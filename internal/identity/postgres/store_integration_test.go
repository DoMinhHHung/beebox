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
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/jackc/pgx/v5"
)

func TestStoreKeepsUsersApplicationScoped(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_identity_store")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	applicationStore := applicationpostgres.New(pool)
	applicationA, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatalf("Create(application A) error = %v", err)
	}
	applicationB, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatalf("Create(application B) error = %v", err)
	}

	store := New(pool)
	userA, err := store.Create(ctx, applicationA.InternalID)
	if err != nil {
		t.Fatalf("Create(user A) error = %v", err)
	}
	userB, err := store.Create(ctx, applicationB.InternalID)
	if err != nil {
		t.Fatalf("Create(user B) error = %v", err)
	}

	if !userA.InternalID.Valid() || !userB.InternalID.Valid() {
		t.Fatalf("created user IDs = %d, %d, want positive", userA.InternalID, userB.InternalID)
	}
	if userA.InternalID == userB.InternalID {
		t.Fatalf("created user IDs are equal: %d", userA.InternalID)
	}
	if userA.ApplicationInstanceID != applicationA.InternalID || userB.ApplicationInstanceID != applicationB.InternalID {
		t.Fatalf("created scopes = %d, %d; want %d, %d", userA.ApplicationInstanceID, userB.ApplicationInstanceID, applicationA.InternalID, applicationB.InternalID)
	}
	if userA.CreatedAt.Location() != time.UTC || userB.CreatedAt.Location() != time.UTC {
		t.Fatalf("created timestamps are not UTC: %v, %v", userA.CreatedAt, userB.CreatedAt)
	}

	assertResolves(t, ctx, store, applicationA.InternalID, userA)
	assertResolves(t, ctx, store, applicationB.InternalID, userB)

	if _, err := store.Resolve(ctx, applicationB.InternalID, userA.InternalID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("Resolve(B, userA) error = %v, want ErrNotFound", err)
	}
	if _, err := store.Resolve(ctx, applicationA.InternalID, userB.InternalID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("Resolve(A, userB) error = %v, want ErrNotFound", err)
	}

	missingID := userA.InternalID + userB.InternalID + 1000
	if _, err := store.Resolve(ctx, applicationA.InternalID, missingID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("Resolve(A, missing) error = %v, want ErrNotFound", err)
	}

	for _, invalidUserID := range []identity.InternalID{0, -1} {
		if _, err := store.Resolve(ctx, applicationA.InternalID, invalidUserID); !errors.Is(err, identity.ErrInvalidInternalID) {
			t.Fatalf("Resolve(A, %d) error = %v, want ErrInvalidInternalID", invalidUserID, err)
		}
	}
	for _, invalidScope := range []applicationinstance.InternalID{0, -1} {
		if _, err := store.Resolve(ctx, invalidScope, userA.InternalID); !errors.Is(err, identity.ErrInvalidApplicationInstanceScope) {
			t.Fatalf("Resolve(%d, userA) error = %v, want ErrInvalidApplicationInstanceScope", invalidScope, err)
		}
		if _, err := store.Create(ctx, invalidScope); !errors.Is(err, identity.ErrInvalidApplicationInstanceScope) {
			t.Fatalf("Create(%d) error = %v, want ErrInvalidApplicationInstanceScope", invalidScope, err)
		}
	}

	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := store.Resolve(cancelledCtx, applicationA.InternalID, userA.InternalID); !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestStoreForeignKeyPreventsOrphanUser(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_identity_fk")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	store := New(pool)
	if _, err := store.Create(ctx, applicationinstance.InternalID(999999)); !errors.Is(err, identity.ErrPersistence) || err.Error() != "user persistence failure" {
		t.Fatalf("Create(nonexistent scope) error = %v, want stable ErrPersistence", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil {
		t.Fatalf("count users error = %v", err)
	}
	if count != 0 {
		t.Fatalf("orphan prevention user count = %d, want 0", count)
	}
}

func TestConcurrentCreatesReceiveDistinctDatabaseIdentities(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_identity_concurrent")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	applicationRoot, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(application) error = %v", err)
	}

	store := New(pool)
	const creates = 8
	start := make(chan struct{})
	users := make(chan identity.User, creates)
	errs := make(chan error, creates)
	var wg sync.WaitGroup
	for range creates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			user, err := store.Create(ctx, applicationRoot.InternalID)
			if err != nil {
				errs <- err
				return
			}
			users <- user
		}()
	}
	close(start)
	wg.Wait()
	close(users)
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent Create() error = %v", err)
	}
	seen := make(map[identity.InternalID]struct{}, creates)
	for user := range users {
		if !user.InternalID.Valid() {
			t.Fatalf("concurrent user ID = %d, want positive", user.InternalID)
		}
		if user.ApplicationInstanceID != applicationRoot.InternalID {
			t.Fatalf("concurrent user scope = %d, want %d", user.ApplicationInstanceID, applicationRoot.InternalID)
		}
		if _, exists := seen[user.InternalID]; exists {
			t.Fatalf("duplicate concurrent user ID = %d", user.InternalID)
		}
		seen[user.InternalID] = struct{}{}
	}
	if len(seen) != creates {
		t.Fatalf("distinct concurrent user IDs = %d, want %d", len(seen), creates)
	}
}

func TestStoreDatabaseFailureUsesStableSafeError(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_identity_failure")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	applicationRoot, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(application) error = %v", err)
	}

	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, "DROP TABLE users"); err != nil {
		db.Close()
		t.Fatalf("drop users error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close test adapter error = %v", err)
	}

	store := New(pool)
	if _, err := store.Create(ctx, applicationRoot.InternalID); !errors.Is(err, identity.ErrPersistence) || err.Error() != "user persistence failure" {
		t.Fatalf("Create() error = %v, want stable ErrPersistence", err)
	}
}

func assertResolves(t *testing.T, ctx context.Context, store *Store, scope applicationinstance.InternalID, want identity.User) {
	t.Helper()
	got, err := store.Resolve(ctx, scope, want.InternalID)
	if err != nil {
		t.Fatalf("Resolve(%d, %d) error = %v", scope, want.InternalID, err)
	}
	if got.InternalID != want.InternalID || got.ApplicationInstanceID != scope || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("Resolve(%d, %d) = %+v, want %+v", scope, want.InternalID, got, want)
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
