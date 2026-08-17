//go:build integration

package migration

import (
	"context"
	"database/sql"
	"io/fs"
	"regexp"
	"testing"
	"time"
)

var (
	applicationPublicIDPattern = regexp.MustCompile(`^app_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	userPublicIDPattern        = regexp.MustCompile(`^usr_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func TestMigrationEightBackfillsStablePublicIDs(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_public_id_backfill")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sources, err := fs.Sub(embeddedSQL, "sql")
	if err != nil {
		t.Fatalf("fs.Sub() error = %v", err)
	}
	preEight := omitMigrationFS{
		FS: omitMigrationFS{
			FS: omitMigrationFS{
				FS: omitMigrationFS{
					FS:   sources,
					omit: "00011_password_resets.sql",
				},
				omit: "00010_sessions.sql",
			},
			omit: "00009_public_auth_controls.sql",
		},
		omit: "00008_phase1_public_integration.sql",
	}
	if err := upWithSources(ctx, pool.OpenSQLDB(), preEight); err != nil {
		t.Fatalf("apply pre-00008 migrations error = %v", err)
	}

	db := pool.OpenSQLDB()
	var appID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO application_instances DEFAULT VALUES RETURNING id`).Scan(&appID); err != nil {
		db.Close()
		t.Fatalf("insert legacy application row error = %v", err)
	}
	var userID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO users (application_instance_id) VALUES ($1) RETURNING id`, appID).Scan(&userID); err != nil {
		db.Close()
		t.Fatalf("insert legacy user row error = %v", err)
	}

	migrationEight, err := fs.ReadFile(sources, "00008_phase1_public_integration.sql")
	if err != nil {
		db.Close()
		t.Fatalf("read migration 00008 error = %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		db.Close()
		t.Fatalf("begin migration 00008 transaction error = %v", err)
	}
	if _, err := tx.ExecContext(ctx, string(migrationEight)); err != nil {
		_ = tx.Rollback()
		db.Close()
		t.Fatalf("apply migration 00008 SQL error = %v", err)
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatalf("commit migration 00008 transaction error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close migration adapter error = %v", err)
	}

	appPublicID, userPublicID := readBackfilledPublicIDs(t, ctx, pool, appID, userID)
	if !applicationPublicIDPattern.MatchString(appPublicID) {
		t.Fatalf("backfilled application public ID %q is not app UUIDv4", appPublicID)
	}
	if !userPublicIDPattern.MatchString(userPublicID) {
		t.Fatalf("backfilled user public ID %q is not usr UUIDv4", userPublicID)
	}
}

func readBackfilledPublicIDs(
	t *testing.T,
	ctx context.Context,
	pool interface{ OpenSQLDB() *sql.DB },
	appID int64,
	userID int64,
) (string, string) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var appPublicID string
	if err := db.QueryRowContext(ctx, `SELECT public_id FROM application_instances WHERE id = $1`, appID).Scan(&appPublicID); err != nil {
		t.Fatalf("query application public ID error = %v", err)
	}
	var userPublicID string
	if err := db.QueryRowContext(ctx, `SELECT public_id FROM users WHERE application_instance_id = $1 AND id = $2`, appID, userID).Scan(&userPublicID); err != nil {
		t.Fatalf("query user public ID error = %v", err)
	}
	return appPublicID, userPublicID
}

type omitMigrationFS struct {
	fs.FS
	omit string
}

func (o omitMigrationFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(o.FS, name)
	if err != nil {
		return nil, err
	}
	filtered := make([]fs.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() != o.omit {
			filtered = append(filtered, entry)
		}
	}
	return filtered, nil
}
