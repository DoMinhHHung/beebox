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

func TestEmailIdentifierCreateResolveAndScopeIsolation(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_email_create_resolve")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	appStore := applicationpostgres.New(pool)
	appA, err := appStore.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	appB, err := appStore.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app B) error = %v", err)
	}
	store := New(pool)
	userA, err := store.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatalf("Create(user A) error = %v", err)
	}
	userB, err := store.Create(ctx, appB.InternalID)
	if err != nil {
		t.Fatalf("Create(user B) error = %v", err)
	}

	identifier, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA.InternalID, " Alice@Example.TEST ")
	if err != nil {
		t.Fatalf("CreateEmailIdentifier() error = %v", err)
	}
	assertEmailIdentifier(t, identifier, appA.InternalID, userA.InternalID, "Alice@Example.TEST", "alice@example.test")
	if identifier.VerifiedAt != nil {
		t.Fatalf("new identifier VerifiedAt = %v, want nil", identifier.VerifiedAt)
	}

	resolved, err := store.ResolveEmailIdentifier(ctx, appA.InternalID, identifier.InternalID)
	if err != nil {
		t.Fatalf("ResolveEmailIdentifier() error = %v", err)
	}
	assertEmailIdentifier(t, resolved, appA.InternalID, userA.InternalID, "Alice@Example.TEST", "alice@example.test")

	if _, err := store.ResolveEmailIdentifier(ctx, appB.InternalID, identifier.InternalID); !errors.Is(err, identity.ErrEmailNotFound) {
		t.Fatalf("ResolveEmailIdentifier(foreign scope) error = %v, want ErrEmailNotFound", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, appB.InternalID, userA.InternalID, "cross@example.test"); !errors.Is(err, identity.ErrEmailPersistence) {
		t.Fatalf("CreateEmailIdentifier(cross scope) error = %v, want ErrEmailPersistence", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, appB.InternalID, userB.InternalID, "alice@example.test"); err != nil {
		t.Fatalf("CreateEmailIdentifier(same email other app) error = %v", err)
	}
}

func TestEmailIdentifierDuplicateNormalizedEmailConflictsWithoutReassignment(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_email_duplicate")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	store := New(pool)
	firstUser, err := store.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(first user) error = %v", err)
	}
	secondUser, err := store.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(second user) error = %v", err)
	}
	created, err := store.CreateEmailIdentifier(ctx, app.InternalID, firstUser.InternalID, "Alice@Example.TEST")
	if err != nil {
		t.Fatalf("CreateEmailIdentifier(first) error = %v", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, app.InternalID, secondUser.InternalID, " alice@example.test "); !errors.Is(err, identity.ErrEmailConflict) {
		t.Fatalf("CreateEmailIdentifier(duplicate) error = %v, want ErrEmailConflict", err)
	}
	resolved, err := store.ResolveEmailIdentifier(ctx, app.InternalID, created.InternalID)
	if err != nil {
		t.Fatalf("ResolveEmailIdentifier() error = %v", err)
	}
	if resolved.UserID != firstUser.InternalID {
		t.Fatalf("duplicate email reassigned owner to %d, want %d", resolved.UserID, firstUser.InternalID)
	}
}

func TestEmailIdentifierConcurrentDuplicateHasSingleOwner(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_email_concurrent")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	store := New(pool)
	user, err := store.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user) error = %v", err)
	}

	const attempts = 8
	start := make(chan struct{})
	errorsByAttempt := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.CreateEmailIdentifier(ctx, app.InternalID, user.InternalID, "Race@Example.TEST")
			errorsByAttempt <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errorsByAttempt)
	var successes int
	for err := range errorsByAttempt {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, identity.ErrEmailConflict) {
			t.Fatalf("concurrent CreateEmailIdentifier() error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successes = %d, want 1", successes)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var count int
	var storedUserID int64
	if err := db.QueryRowContext(ctx, `SELECT count(*), min(user_id) FROM email_identifiers WHERE application_instance_id=$1 AND normalized_email='race@example.test'`, int64(app.InternalID)).Scan(&count, &storedUserID); err != nil {
		t.Fatalf("query concurrent state error = %v", err)
	}
	if count != 1 || storedUserID != int64(user.InternalID) {
		t.Fatalf("concurrent persisted state count=%d user=%d, want count=1 user=%d", count, storedUserID, user.InternalID)
	}
}

func TestEmailIdentifierDatabaseFailureUsesStableSafeError(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_email_failure")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	store := New(pool)
	user, err := store.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user) error = %v", err)
	}

	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, "DROP TABLE password_reset_challenges"); err != nil {
		db.Close()
		t.Fatalf("drop password_reset_challenges error = %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE email_verification_challenges"); err != nil {
		db.Close()
		t.Fatalf("drop email_verification_challenges error = %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE email_identifiers"); err != nil {
		db.Close()
		t.Fatalf("drop email_identifiers error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close test adapter error = %v", err)
	}

	if _, err := store.CreateEmailIdentifier(ctx, app.InternalID, user.InternalID, "safe-error@example.test"); !errors.Is(err, identity.ErrEmailPersistence) || err.Error() != "email identifier persistence failure" {
		t.Fatalf("CreateEmailIdentifier() error = %v, want stable ErrEmailPersistence", err)
	}
}

func assertEmailIdentifier(
	t *testing.T,
	identifier identity.EmailIdentifier,
	appID applicationinstance.InternalID,
	userID identity.InternalID,
	wantAddress string,
	wantNormalized string,
) {
	t.Helper()
	if !identifier.InternalID.Valid() {
		t.Fatalf("email identifier internal ID = %d, want positive", identifier.InternalID)
	}
	if identifier.ApplicationInstanceID != appID || identifier.UserID != userID {
		t.Fatalf("email identifier scope/owner = %d/%d, want %d/%d", identifier.ApplicationInstanceID, identifier.UserID, appID, userID)
	}
	if identifier.EmailAddress != wantAddress || identifier.NormalizedEmail != wantNormalized {
		t.Fatalf("email identifier address/normalized = %q/%q, want %q/%q", identifier.EmailAddress, identifier.NormalizedEmail, wantAddress, wantNormalized)
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
