//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

func TestEmailIdentifiersAreApplicationScopedAndUnverified(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_email_scope")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	applicationStore := applicationpostgres.New(pool)
	appA, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	appB, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatalf("Create(app B) error = %v", err)
	}

	store := New(pool)
	userA, err := store.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatalf("Create(user A) error = %v", err)
	}
	userA2, err := store.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatalf("Create(user A2) error = %v", err)
	}
	userB, err := store.Create(ctx, appB.InternalID)
	if err != nil {
		t.Fatalf("Create(user B) error = %v", err)
	}

	emailA, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA.InternalID, "  Alice+Tag@Example.TEST  ")
	if err != nil {
		t.Fatalf("CreateEmailIdentifier(A) error = %v", err)
	}
	assertEmailIdentifier(t, emailA, appA.InternalID, userA.InternalID, "Alice+Tag@Example.TEST", "alice+tag@example.test")

	resolvedA, err := store.ResolveEmailIdentifierByAddress(ctx, appA.InternalID, "alice+tag@example.test")
	if err != nil {
		t.Fatalf("ResolveEmailIdentifierByAddress(A) error = %v", err)
	}
	assertEmailIdentifier(t, resolvedA, appA.InternalID, userA.InternalID, "Alice+Tag@Example.TEST", "alice+tag@example.test")

	if _, err := store.ResolveEmailIdentifierByAddress(ctx, appB.InternalID, "ALICE+TAG@example.test"); !errors.Is(err, identity.ErrEmailIdentifierNotFound) {
		t.Fatalf("ResolveEmailIdentifierByAddress(B) error = %v, want not found", err)
	}

	emailB, err := store.CreateEmailIdentifier(ctx, appB.InternalID, userB.InternalID, "alice+tag@example.test")
	if err != nil {
		t.Fatalf("CreateEmailIdentifier(B) error = %v", err)
	}
	assertEmailIdentifier(t, emailB, appB.InternalID, userB.InternalID, "alice+tag@example.test", "alice+tag@example.test")

	if _, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA2.InternalID, "ALICE+TAG@EXAMPLE.TEST"); !errors.Is(err, identity.ErrEmailConflict) {
		t.Fatalf("same-app duplicate email error = %v, want conflict", err)
	}

	if _, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA.InternalID, "Alice+Tag@Example.TEST"); !errors.Is(err, identity.ErrEmailConflict) {
		t.Fatalf("same-owner duplicate email error = %v, want conflict", err)
	}

	if _, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userB.InternalID, "scope-mismatch@example.test"); !errors.Is(err, identity.ErrEmailPersistence) {
		t.Fatalf("cross-app owner error = %v, want persistence failure", err)
	}
}

func TestEmailIdentifierValidationRejectsUnsafeInputs(t *testing.T) {
	store := New(nil)
	ctx := context.Background()
	if _, err := store.CreateEmailIdentifier(ctx, 0, 1, "alice@example.test"); !errors.Is(err, identity.ErrInvalidApplicationInstanceScope) {
		t.Fatalf("invalid app scope error = %v", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, 1, 0, "alice@example.test"); !errors.Is(err, identity.ErrInvalidInternalID) {
		t.Fatalf("invalid user ID error = %v", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, 1, 1, "not-an-email"); !errors.Is(err, identity.ErrInvalidEmail) {
		t.Fatalf("invalid email error = %v", err)
	}
}

func TestEmailIdentifierConcurrentCreateConvergesOnDatabaseUniqueness(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_email_concurrent")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.CreateEmailIdentifier(ctx, app.InternalID, user.InternalID, "race@example.test")
			results <- err
		}()
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
			t.Fatalf("concurrent CreateEmailIdentifier() error = %v", err)
		}
	}
	if successes != 1 || conflicts != attempts-1 {
		t.Fatalf("concurrent results successes=%d conflicts=%d, want 1/%d", successes, conflicts, attempts-1)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var count int
	var storedUserID int64
	if err := db.QueryRowContext(
		ctx,
		`SELECT count(*), min(user_id)
		 FROM email_identifiers
		 WHERE application_instance_id = $1 AND normalized_email = $2`,
		int64(app.InternalID), "race@example.test",
	).Scan(&count, &storedUserID); err != nil {
		t.Fatalf("query concurrent email state error = %v", err)
	}
	if count != 1 || identity.InternalID(storedUserID) != user.InternalID {
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
	if identifier.ApplicationInstanceID != appID || identifier.UserID != userID {
		t.Fatalf("identifier scope/owner = %d/%d, want %d/%d", identifier.ApplicationInstanceID, identifier.UserID, appID, userID)
	}
	if identifier.EmailAddress != wantAddress || identifier.NormalizedEmail != wantNormalized {
		t.Fatalf("identifier email state = %q/%q, want %q/%q", identifier.EmailAddress, identifier.NormalizedEmail, wantAddress, wantNormalized)
	}
	if identifier.VerifiedAt != nil {
		t.Fatalf("new identifier VerifiedAt = %v, want nil", identifier.VerifiedAt)
	}
	if identifier.CreatedAt.Location() != time.UTC {
		t.Fatalf("identifier CreatedAt location = %v, want UTC", identifier.CreatedAt.Location())
	}
}
