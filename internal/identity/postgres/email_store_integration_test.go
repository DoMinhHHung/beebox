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

func TestEmailIdentifiersAreScopedUniqueUnverifiedAndNeverAutoLink(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_email_scope")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	identifierA, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA.InternalID, "Alice@Example.TEST")
	if err != nil {
		t.Fatalf("CreateEmailIdentifier(A) error = %v", err)
	}
	assertEmailIdentifier(t, identifierA, appA.InternalID, userA.InternalID, "Alice@Example.TEST", "alice@example.test")

	if _, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA2.InternalID, "alice@example.test"); !errors.Is(err, identity.ErrEmailConflict) {
		t.Fatalf("same-app different-owner duplicate error = %v, want ErrEmailConflict", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA.InternalID, "  ALICE@EXAMPLE.TEST  "); !errors.Is(err, identity.ErrEmailConflict) {
		t.Fatalf("same-user normalized duplicate error = %v, want ErrEmailConflict", err)
	}

	identifierB, err := store.CreateEmailIdentifier(ctx, appB.InternalID, userB.InternalID, "alice@example.test")
	if err != nil {
		t.Fatalf("CreateEmailIdentifier(B) error = %v", err)
	}
	assertEmailIdentifier(t, identifierB, appB.InternalID, userB.InternalID, "alice@example.test", "alice@example.test")
	if identifierA.InternalID == identifierB.InternalID {
		t.Fatalf("cross-app identifiers share internal ID %d", identifierA.InternalID)
	}

	resolvedA, err := store.ResolveEmailIdentifierByAddress(ctx, appA.InternalID, " ALICE@Example.Test ")
	if err != nil {
		t.Fatalf("ResolveEmailIdentifierByAddress(A) error = %v", err)
	}
	assertEmailIdentifier(t, resolvedA, appA.InternalID, userA.InternalID, "Alice@Example.TEST", "alice@example.test")
	if resolvedA.InternalID != identifierA.InternalID {
		t.Fatalf("ResolveEmailIdentifierByAddress(A) internal ID = %d, want %d", resolvedA.InternalID, identifierA.InternalID)
	}

	resolvedB, err := store.ResolveEmailIdentifierByAddress(ctx, appB.InternalID, "Alice@Example.TEST")
	if err != nil {
		t.Fatalf("ResolveEmailIdentifierByAddress(B) error = %v", err)
	}
	assertEmailIdentifier(t, resolvedB, appB.InternalID, userB.InternalID, "alice@example.test", "alice@example.test")
	if resolvedB.InternalID != identifierB.InternalID {
		t.Fatalf("ResolveEmailIdentifierByAddress(B) internal ID = %d, want %d", resolvedB.InternalID, identifierB.InternalID)
	}

	if _, err := store.ResolveEmailIdentifierByAddress(ctx, appA.InternalID, "missing@example.test"); !errors.Is(err, identity.ErrEmailIdentifierNotFound) {
		t.Fatalf("ResolveEmailIdentifierByAddress(missing) error = %v, want ErrEmailIdentifierNotFound", err)
	}
	if _, err := store.ResolveEmailIdentifierByAddress(ctx, applicationinstance.InternalID(0), "alice@example.test"); !errors.Is(err, identity.ErrInvalidApplicationInstanceScope) {
		t.Fatalf("ResolveEmailIdentifierByAddress(invalid scope) error = %v, want ErrInvalidApplicationInstanceScope", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, appA.InternalID, identity.InternalID(0), "other@example.test"); !errors.Is(err, identity.ErrInvalidInternalID) {
		t.Fatalf("CreateEmailIdentifier(invalid user) error = %v, want ErrInvalidInternalID", err)
	}
	if _, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userA.InternalID, "not-an-email"); !errors.Is(err, identity.ErrInvalidEmail) {
		t.Fatalf("CreateEmailIdentifier(invalid email) error = %v, want ErrInvalidEmail", err)
	}

	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := store.ResolveEmailIdentifierByAddress(cancelledCtx, appA.InternalID, "alice@example.test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveEmailIdentifierByAddress(cancelled) error = %v, want context.Canceled", err)
	}
}

func TestEmailIdentifierCompositeForeignKeyRejectsCrossApplicationOwner(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_email_fk")
	pool := openPool(t, databaseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	userB, err := store.Create(ctx, appB.InternalID)
	if err != nil {
		t.Fatalf("Create(user B) error = %v", err)
	}

	if _, err := store.CreateEmailIdentifier(ctx, appA.InternalID, userB.InternalID, "cross-scope@example.test"); !errors.Is(err, identity.ErrEmailPersistence) {
		t.Fatalf("cross-app owner CreateEmailIdentifier() error = %v, want ErrEmailPersistence", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_identifiers`).Scan(&count); err != nil {
		t.Fatalf("count email identifiers error = %v", err)
	}
	if count != 0 {
		t.Fatalf("cross-app FK failure left %d identifier rows, want 0", count)
	}
}

func TestConcurrentNormalizedEmailDuplicatesCommitExactlyOnce(t *testing.T) {
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

	variants := []string{
		"Race@Example.TEST",
		" race@example.test ",
		"RACE@example.test",
		"Race@EXAMPLE.TEST",
		"  race@Example.Test  ",
		"rAcE@example.test",
		"RACE@EXAMPLE.TEST",
		"race@example.test",
	}
	start := make(chan struct{})
	results := make(chan error, len(variants))
	var wg sync.WaitGroup
	for _, raw := range variants {
		raw := raw
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.CreateEmailIdentifier(ctx, app.InternalID, user.InternalID, raw)
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
			t.Fatalf("concurrent CreateEmailIdentifier() error = %v, want nil or ErrEmailConflict", err)
		}
	}
	if successes != 1 || conflicts != len(variants)-1 {
		t.Fatalf("concurrent results successes=%d conflicts=%d, want 1/%d", successes, conflicts, len(variants)-1)
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
		int64(app.InternalID),
		"race@example.test",
	).Scan(&count, &storedUserID); err != nil {
		t.Fatalf("query concurrent identifier state error = %v", err)
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
	if _, err := db.ExecContext(ctx, "DROP TABLE password_reset_challenges"); err != nil {
		db.Close()
		t.Fatalf("drop password_reset_challenges error = %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE email_otp_signin_challenges"); err != nil {
		db.Close()
		t.Fatalf("drop email_otp_signin_challenges error = %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE email_verification_challenges"); err != nil {
		db.Close()
		t.Fatalf("drop email_verification_challenges error = %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE email_signin_links"); err != nil {
		db.Close()
		t.Fatalf("drop email_signin_links error = %v", err)
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
		t.Fatalf("email identifier address/key = %q/%q, want %q/%q", identifier.EmailAddress, identifier.NormalizedEmail, wantAddress, wantNormalized)
	}
	if identifier.VerifiedAt != nil {
		t.Fatalf("email identifier VerifiedAt = %v, want nil", identifier.VerifiedAt)
	}
	if identifier.CreatedAt.Location() != time.UTC {
		t.Fatalf("email identifier CreatedAt location = %v, want UTC", identifier.CreatedAt.Location())
	}
}
