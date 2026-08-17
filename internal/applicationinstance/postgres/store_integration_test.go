//go:build integration

package postgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/jackc/pgx/v5"
)

func TestStoreCreateAndResolveKeepRootScopesDistinct(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_application_instance_store")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	store := New(pool)
	instanceA, err := store.Create(ctx)
	if err != nil {
		t.Fatalf("Create(A) error = %v", err)
	}
	instanceB, err := store.Create(ctx)
	if err != nil {
		t.Fatalf("Create(B) error = %v", err)
	}

	if !instanceA.InternalID.Valid() || !instanceB.InternalID.Valid() {
		t.Fatalf("created internal IDs = %d, %d, want positive", instanceA.InternalID, instanceB.InternalID)
	}
	if instanceA.InternalID == instanceB.InternalID {
		t.Fatalf("created internal IDs are equal: %d", instanceA.InternalID)
	}
	if instanceA.CreatedAt.Location() != time.UTC || instanceB.CreatedAt.Location() != time.UTC {
		t.Fatalf("created timestamps are not normalized to UTC: %v, %v", instanceA.CreatedAt, instanceB.CreatedAt)
	}

	resolvedA, err := store.Resolve(ctx, instanceA.InternalID)
	if err != nil {
		t.Fatalf("Resolve(A) error = %v", err)
	}
	if resolvedA.InternalID != instanceA.InternalID || !resolvedA.CreatedAt.Equal(instanceA.CreatedAt) {
		t.Fatalf("Resolve(A) = %+v, want %+v", resolvedA, instanceA)
	}
	if resolvedA.InternalID == instanceB.InternalID {
		t.Fatalf("Resolve(A) returned B identity %d", instanceB.InternalID)
	}

	resolvedB, err := store.Resolve(ctx, instanceB.InternalID)
	if err != nil {
		t.Fatalf("Resolve(B) error = %v", err)
	}
	if resolvedB.InternalID != instanceB.InternalID || !resolvedB.CreatedAt.Equal(instanceB.CreatedAt) {
		t.Fatalf("Resolve(B) = %+v, want %+v", resolvedB, instanceB)
	}
	if resolvedB.InternalID == instanceA.InternalID {
		t.Fatalf("Resolve(B) returned A identity %d", instanceA.InternalID)
	}

	missingID := instanceA.InternalID + instanceB.InternalID + 1000
	if _, err := store.Resolve(ctx, missingID); !errors.Is(err, applicationinstance.ErrNotFound) {
		t.Fatalf("Resolve(missing) error = %v, want ErrNotFound", err)
	}

	for _, invalidID := range []applicationinstance.InternalID{0, -1} {
		if _, err := store.Resolve(ctx, invalidID); !errors.Is(err, applicationinstance.ErrInvalidInternalID) {
			t.Fatalf("Resolve(%d) error = %v, want ErrInvalidInternalID", invalidID, err)
		}
	}

	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := store.Resolve(cancelledCtx, instanceA.InternalID); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestStoreConcurrentCreateGetsDistinctDatabaseIdentities(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_application_instance_concurrent")
	pool := openPool(t, databaseURL)

	setupCtx, cancelSetup := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelSetup()
	if err := migration.Up(setupCtx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	store := New(pool)
	const creators = 8
	ids := make(chan applicationinstance.InternalID, creators)
	errs := make(chan error, creators)
	var wg sync.WaitGroup

	for range creators {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			instance, err := store.Create(ctx)
			if err != nil {
				errs <- err
				return
			}
			ids <- instance.InternalID
		}()
	}

	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Create() error = %v", err)
	}

	seen := make(map[applicationinstance.InternalID]struct{}, creators)
	for id := range ids {
		if !id.Valid() {
			t.Fatalf("concurrent Create() internal ID = %d, want positive", id)
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate database-generated internal ID = %d", id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != creators {
		t.Fatalf("unique internal IDs = %d, want %d", len(seen), creators)
	}
}

func TestStoreDatabaseFailureUsesStableSafeError(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_application_instance_failure")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, "DROP TABLE application_instances"); err != nil {
		db.Close()
		t.Fatalf("drop application_instances error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close test adapter error = %v", err)
	}

	store := New(pool)
	if _, err := store.Create(ctx); !errors.Is(err, applicationinstance.ErrPersistence) || err.Error() != "application instance persistence failure" {
		t.Fatalf("Create() error = %v, want stable ErrPersistence", err)
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
