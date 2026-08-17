//go:build integration

package migration

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3/lock"
)

func TestMigrationFirstApplyAndRerunAreIdempotent(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_first_apply")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	firstAdapter := pool.OpenSQLDB()
	if err := Up(ctx, firstAdapter); err != nil {
		t.Fatalf("first Up() error = %v", err)
	}
	if err := firstAdapter.PingContext(ctx); err == nil || err.Error() != "sql: database is closed" {
		t.Fatalf("first adapter remained open after Up: %v", err)
	}

	assertMigrationState(t, ctx, pool, 6)

	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("second Up() error = %v", err)
	}
	assertMigrationState(t, ctx, pool, 6)
	assertSchemaTables(t, ctx, pool)
}

func TestConcurrentMigrationRunnersSerializeAndConverge(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_concurrent")
	firstPool := openPool(t, databaseURL)
	secondPool := openPool(t, databaseURL)

	start := make(chan struct{})
	errorsByRunner := make(chan error, 2)
	var runners sync.WaitGroup

	for _, pool := range []*database.Pool{firstPool, secondPool} {
		runners.Add(1)
		go func(pool *database.Pool) {
			defer runners.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			errorsByRunner <- Up(ctx, pool.OpenSQLDB())
		}(pool)
	}

	close(start)
	runners.Wait()
	close(errorsByRunner)

	for err := range errorsByRunner {
		if err != nil {
			t.Fatalf("concurrent Up() error = %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assertMigrationState(t, ctx, firstPool, 6)
	assertSchemaTables(t, ctx, firstPool)
}

func TestMigrationLockWaitHonorsCancellation(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_lock_timeout")
	lockPool := openPool(t, databaseURL)
	runnerPool := openPool(t, databaseURL)

	lockDB := lockPool.OpenSQLDB()
	defer lockDB.Close()

	setupCtx, cancelSetup := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelSetup()
	conn, err := lockDB.Conn(setupCtx)
	if err != nil {
		t.Fatalf("lock connection error = %v", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(
		setupCtx,
		"SELECT pg_advisory_lock($1)",
		lock.DefaultLockID,
	); err != nil {
		t.Fatalf("acquire test lock error = %v", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = conn.ExecContext(
			unlockCtx,
			"SELECT pg_advisory_unlock($1)",
			lock.DefaultLockID,
		)
	}()

	runCtx, cancelRun := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelRun()
	started := time.Now()
	err = Up(runCtx, runnerPool.OpenSQLDB())
	elapsed := time.Since(started)

	if !errors.Is(err, errApply) {
		t.Fatalf("Up() error = %v, want stable apply error", err)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("lock cancellation took %s, want under 2s", elapsed)
	}
}

func TestFailingTransactionalMigrationRollsBackAndIsNotRecorded(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_migration_transaction")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("baseline Up() error = %v", err)
	}

	const secretMarker = "super-secret-provider-dsn"
	failingSources := fstest.MapFS{
		"00001_runtime_baseline.sql":      {Data: []byte(validMigration)},
		"00002_application_instances.sql": {Data: []byte(validMigration)},
		"00003_users.sql":                 {Data: []byte(validMigration)},
		"00004_email_identifiers.sql":     {Data: []byte(validMigration)},
		"00005_password_credentials.sql":  {Data: []byte(validMigration)},
		"00006_audit_events.sql":          {Data: []byte(validMigration)},
		"00007_failure_probe.sql": {Data: []byte(
			"-- +goose Up\n" +
				"-- " + secretMarker + "\n" +
				"CREATE TABLE migration_failure_probe (id bigint PRIMARY KEY);\n" +
				"SELECT missing_column FROM migration_failure_probe;\n",
		)},
	}

	err := upWithSources(ctx, pool.OpenSQLDB(), failingSources)
	if !errors.Is(err, errApply) || err.Error() != "apply PostgreSQL migrations" {
		t.Fatalf("upWithSources() error = %v, want stable apply error", err)
	}
	if strings.Contains(err.Error(), secretMarker) || strings.Contains(err.Error(), "missing_column") {
		t.Fatalf("migration error leaks SQL/provider detail: %q", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var probeTable sql.NullString
	if err := db.QueryRowContext(
		ctx,
		"SELECT to_regclass('migration_failure_probe')::text",
	).Scan(&probeTable); err != nil {
		t.Fatalf("query probe table error = %v", err)
	}
	if probeTable.Valid {
		t.Fatalf("failing migration left probe table %q", probeTable.String)
	}

	var versionSevenCount int
	if err := db.QueryRowContext(
		ctx,
		"SELECT count(*) FROM goose_db_version WHERE version_id = 7 AND is_applied",
	).Scan(&versionSevenCount); err != nil {
		t.Fatalf("query version 7 error = %v", err)
	}
	if versionSevenCount != 0 {
		t.Fatalf("applied version 7 rows = %d, want 0", versionSevenCount)
	}
}

func isolatedDatabaseURL(t *testing.T, schema string) string {
	t.Helper()
	databaseURL := os.Getenv("BEEBOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("BEEBOX_TEST_DATABASE_URL is required for integration tests")
	}

	adminPool := openPool(t, databaseURL)
	adminDB := adminPool.OpenSQLDB()
	quotedSchema := pgx.Identifier{schema}.Sanitize()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := adminDB.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE"); err != nil {
		adminDB.Close()
		t.Fatalf("drop test schema error = %v", err)
	}
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminDB.Close()
		t.Fatalf("create test schema error = %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminDB.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		_ = adminDB.Close()
	})

	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal("BEEBOX_TEST_DATABASE_URL must be a valid URI")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()

	return parsed.String()
}

func openPool(t *testing.T, databaseURL string) *database.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pool.Ping() error = %v", err)
	}
	return pool
}

func assertMigrationState(t *testing.T, ctx context.Context, pool *database.Pool, wantApplied int) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()

	var applied int
	if err := db.QueryRowContext(
		ctx,
		"SELECT count(*) FROM goose_db_version WHERE version_id > 0 AND is_applied",
	).Scan(&applied); err != nil {
		t.Fatalf("query applied migrations error = %v", err)
	}
	if applied != wantApplied {
		t.Fatalf("applied migration rows = %d, want %d", applied, wantApplied)
	}
}

func assertSchemaTables(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()

	rows, err := db.QueryContext(
		ctx,
		`SELECT table_name
		 FROM information_schema.tables
		 WHERE table_schema = current_schema()
		 ORDER BY table_name`,
	)
	if err != nil {
		t.Fatalf("query schema tables error = %v", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatalf("scan schema table error = %v", err)
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema tables error = %v", err)
	}
	if want := []string{"application_instances", "audit_events", "email_identifiers", "goose_db_version", "password_credentials", "users"}; !reflect.DeepEqual(tables, want) {
		t.Fatalf("schema tables = %v, want %v", tables, want)
	}
}
