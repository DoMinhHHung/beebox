//go:build integration

package maintenance

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/jackc/pgx/v5"
)

func cleanupPool(t *testing.T, schema string) (*database.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("BEEBOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("BEEBOX_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	admin, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	adminDB := admin.OpenSQLDB()
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := adminDB.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+quoted+" CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := adminDB.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = adminDB.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quoted+" CASCADE")
		_ = adminDB.Close()
		admin.Close()
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	return pool, ctx
}
