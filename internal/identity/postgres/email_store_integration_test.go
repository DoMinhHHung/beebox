//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
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

func TestEmailIdentifierPersistsApplicationScopeAndVerification(t *testing.T) {
	pool, ctx := resetEmailTestDatabase(t, "beebox_email_identifier_scope")
	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	appB, err := apps.Create(ctx)
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

	identifierA, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA.InternalID, "User@Example.com")
	if err != nil {
		t.Fatalf("CreateEmailIdentifier(app A) error = %v", err)
	}
	identifierB, err := store.CreateEmailIdentifier(ctx, appB.InternalID, userB.InternalID, "User@example.com")
	if err != nil {
		t.Fatalf("CreateEmailIdentifier(app B) error = %v", err)
	}
	assertEmailIdentifier(t, identifierA, appA.InternalID, userA.InternalID, "User@Example.com", "User@example.com", false)
	assertEmailIdentifier(t, identifierB, appB.InternalID, userB.InternalID, "User@example.com", "User@example.com", false)

	verifiedA, err := store.MarkEmailVerified(ctx, appA.InternalID, identifierA.InternalID)
	if err != nil {
		t.Fatalf("MarkEmailVerified() error = %v", err)
	}
	if verifiedA.VerifiedAt == nil || !verifiedA.VerifiedAt.Equal(verifiedA.VerifiedAt.UTC()) {
		t.Fatalf("VerifiedAt = %v, want UTC value", verifiedA.VerifiedAt)
	}
	resolvedA, err := store.ResolveEmailIdentifier(ctx, appA.InternalID, "User@Example.com")
	if err != nil {
		t.Fatalf("ResolveEmailIdentifier(app A) error = %v", err)
	}
	if resolvedA.VerifiedAt == nil {
		t.Fatal("ResolveEmailIdentifier(app A) lost verified state")
	}
	resolvedB, err := store.ResolveEmailIdentifier(ctx, appB.InternalID, "User@example.com")
	if err != nil {
		t.Fatalf("ResolveEmailIdentifier(app B) error = %v", err)
	}
	if resolvedB.VerifiedAt != nil {
		t.Fatalf("app B identifier unexpectedly verified at %v", resolvedB.VerifiedAt)
	}
}

func TestEmailIdentifierRejectsCrossApplicationOwnership(t *testing.T) {
	pool, ctx := resetEmailTestDatabase(t, "beebox_email_identifier_cross_app")
	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app B) error = %v", err)
	}
	store := New(pool)
	userA, err := store.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatalf("Create(user A) error = %v", err)
	}

	if _, err := store.CreateEmailIdentifier(ctx, appB.InternalID, userA.InternalID, "cross@example.com"); !errors.Is(err, identity.ErrEmailPersistence) {
		t.Fatalf("CreateEmailIdentifier(cross app) error = %v, want ErrEmailPersistence", err)
	}
}

func TestEmailIdentifierRejectsDuplicateWithinApplication(t *testing.T) {
	pool, ctx := resetEmailTestDatabase(t, "beebox_email_identifier_duplicate")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	store := New(pool)
	userA, err := store.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user A) error = %v", err)
	}
	userB, err := store.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user B) error = %v", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, app.InternalID, userA.InternalID, "Duplicate@Example.com"); err != nil {
		t.Fatalf("first CreateEmailIdentifier() error = %v", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, app.InternalID, userB.InternalID, "Duplicate@example.com"); !errors.Is(err, identity.ErrEmailConflict) {
		t.Fatalf("second CreateEmailIdentifier() error = %v, want ErrEmailConflict", err)
	}
}

func TestEmailIdentifierConcurrentDuplicateConvergesToOneOwner(t *testing.T) {
	pool, ctx := resetEmailTestDatabase(t, "beebox_email_identifier_race")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	store := New(pool)
	userA, err := store.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user A) error = %v", err)
	}
	userB, err := store.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user B) error = %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, userID := range []identity.InternalID{userA.InternalID, userB.InternalID} {
		wg.Add(1)
		go func(userID identity.InternalID) {
			defer wg.Done()
			<-start
			_, err := store.CreateEmailIdentifier(ctx, app.InternalID, userID, "Race@Example.com")
			results <- err
		}(userID)
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	conflicts := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, identity.ErrEmailConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent CreateEmailIdentifier() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
}

func TestEmailIdentifierDatabaseFailureUsesStableSafeError(t *testing.T) {
	pool, ctx := resetEmailTestDatabase(t, "beebox_email_identifier_safe_error")
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
	for _, table := range []string{"password_reset_challenges", "email_otp_signin_challenges", "email_verification_challenges", "email_identifiers"} {
		if _, err := db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			db.Close()
			t.Fatalf("drop %s error = %v", table, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close test adapter error = %v", err)
	}

	if _, err := store.CreateEmailIdentifier(ctx, app.InternalID, user.InternalID, "safe-error@example.test"); !errors.Is(err, identity.ErrEmailPersistence) || err.Error() != "email identifier persistence failure" {
		t.Fatalf("CreateEmailIdentifier() error = %v, want stable ErrEmailPersistence", err)
	}
}

func assertEmailIdentifier(t *testing.T, identifier identity.EmailIdentifier, appID applicationinstance.InternalID, userID identity.InternalID, address, normalized string, verified bool) {
	t.Helper()
	if identifier.ApplicationInstanceID != appID || identifier.UserID != userID || identifier.EmailAddress != address || identifier.NormalizedEmail != normalized {
		t.Fatalf("identifier = %#v", identifier)
	}
	if (identifier.VerifiedAt != nil) != verified {
		t.Fatalf("identifier VerifiedAt = %v, want verified=%v", identifier.VerifiedAt, verified)
	}
	if identifier.CreatedAt.IsZero() || !identifier.CreatedAt.Equal(identifier.CreatedAt.UTC()) {
		t.Fatalf("CreatedAt = %v", identifier.CreatedAt)
	}
}

func resetEmailTestDatabase(t *testing.T, schema string) (*database.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("BEEBOX_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("BEEBOX_TEST_DATABASE_URL is required")
	}
	adminCtx, cancelAdmin := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancelAdmin)
	adminPool, err := database.Open(adminCtx, databaseURL)
	if err != nil {
		t.Fatalf("database.Open(admin) error = %v", err)
	}
	t.Cleanup(adminPool.Close)
	adminDB := adminPool.OpenSQLDB()
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := adminDB.ExecContext(adminCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE"); err != nil {
		adminDB.Close()
		t.Fatalf("drop schema error = %v", err)
	}
	if _, err := adminDB.ExecContext(adminCtx, "CREATE SCHEMA "+quotedSchema); err != nil {
		adminDB.Close()
		t.Fatalf("create schema error = %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = adminDB.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		_ = adminDB.Close()
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL error = %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := database.Open(adminCtx, parsed.String())
	if err != nil {
		t.Fatalf("database.Open(test schema) error = %v", err)
	}
	t.Cleanup(pool.Close)
	if err := migration.Up(adminCtx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	return pool, adminCtx
}

func ExampleEmailConflictIsApplicationScoped() {
	fmt.Println("email equality is scoped by application_instance")
	// Output: email equality is scoped by application_instance
}
