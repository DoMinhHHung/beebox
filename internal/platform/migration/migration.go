package migration

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

var (
	errDeadlineRequired = errors.New("PostgreSQL migration deadline is required")
	errInvalidSources   = errors.New("invalid embedded PostgreSQL migration sources")
	errInitialize       = errors.New("initialize PostgreSQL migration runner")
	errApply            = errors.New("apply PostgreSQL migrations")
	errClose            = errors.New("close PostgreSQL migration adapter")
)

var sourceNamePattern = regexp.MustCompile(`^([0-9]{5})_[a-z0-9_]+\.sql$`)

const (
	lockRetryInterval = 100 * time.Millisecond
	unlockTimeout     = time.Second
)

//go:embed sql/*.sql
var embeddedSQL embed.FS

// Up applies every pending embedded migration in ascending version order. It
// owns and closes db, while the pgx pool behind that adapter remains owned by
// process composition.
func Up(ctx context.Context, db *sql.DB) error {
	sources, err := fs.Sub(embeddedSQL, "sql")
	if err != nil {
		if db != nil {
			_ = db.Close()
		}
		return errInvalidSources
	}

	return upWithSources(ctx, db, sources)
}

func upWithSources(ctx context.Context, db *sql.DB, sources fs.FS) (retErr error) {
	if db == nil {
		return errInitialize
	}
	defer func() {
		if err := db.Close(); err != nil && retErr == nil {
			retErr = errClose
		}
	}()

	if _, ok := ctx.Deadline(); !ok {
		return errDeadlineRequired
	}
	if err := validateSources(sources); err != nil {
		return errInvalidSources
	}

	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		sources,
		goose.WithDisableGlobalRegistry(true),
		goose.WithLogger(goose.NopLogger()),
		goose.WithSessionLocker(advisoryLocker{}),
	)
	if err != nil {
		return errInitialize
	}

	if _, err := provider.Up(ctx); err != nil {
		return errApply
	}

	return nil
}

func validateSources(sources fs.FS) error {
	entries, err := fs.ReadDir(sources, ".")
	if err != nil || len(entries) == 0 {
		return errInvalidSources
	}

	var previousVersion int64
	for _, entry := range entries {
		if entry.IsDir() {
			return errInvalidSources
		}

		matches := sourceNamePattern.FindStringSubmatch(entry.Name())
		if len(matches) != 2 {
			return errInvalidSources
		}

		version, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil || version <= 0 || version <= previousVersion {
			return errInvalidSources
		}
		previousVersion = version

		contents, err := fs.ReadFile(sources, entry.Name())
		if err != nil || !validDirectives(string(contents)) {
			return errInvalidSources
		}
	}

	return nil
}

func validDirectives(contents string) bool {
	return strings.Count(contents, "-- +goose Up") == 1 &&
		!strings.Contains(contents, "-- +goose Down") &&
		!strings.Contains(contents, "-- +goose NO TRANSACTION") &&
		!strings.Contains(contents, "-- +goose ENVSUB")
}

// advisoryLocker uses goose's same-session locking extension. The lock wait
// inherits the caller's migration deadline; unlock receives its own short
// bound because goose deliberately detaches cancellation during cleanup.
type advisoryLocker struct{}

var _ lock.SessionLocker = advisoryLocker{}

func (advisoryLocker) SessionLock(ctx context.Context, conn *sql.Conn) error {
	for {
		var acquired bool
		if err := conn.QueryRowContext(
			ctx,
			"SELECT pg_try_advisory_lock($1)",
			lock.DefaultLockID,
		).Scan(&acquired); err != nil {
			return err
		}
		if acquired {
			return nil
		}

		timer := time.NewTimer(lockRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (advisoryLocker) SessionUnlock(ctx context.Context, conn *sql.Conn) error {
	unlockCtx, cancel := context.WithTimeout(ctx, unlockTimeout)
	defer cancel()

	var released bool
	if err := conn.QueryRowContext(
		unlockCtx,
		"SELECT pg_advisory_unlock($1)",
		lock.DefaultLockID,
	).Scan(&released); err != nil {
		return err
	}
	if !released {
		return errors.New("PostgreSQL migration advisory lock was not held")
	}

	return nil
}
