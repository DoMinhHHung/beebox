//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

type publicSignupDelivery struct {
	mu          sync.Mutex
	calls       int
	destination string
	code        string
	err         error
}

func (d *publicSignupDelivery) DeliverVerificationCode(_ context.Context, destination, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	d.destination = destination
	d.code = code
	return d.err
}

func (d *publicSignupDelivery) snapshot() (int, string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, d.destination, d.code
}

func TestPublicSignupIdempotencyDuplicateAndVerificationLifecycle(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_public_signup")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(application) error = %v", err)
	}
	delivery := &publicSignupDelivery{}
	store := New(pool)
	signup := authentication.NewPublicSignupService(store, delivery)

	const email = "User@Example.COM"
	const password = "correct horse battery staple"
	if err := signup.SignUp(ctx, app.InternalID, email, password, "signup-one"); err != nil {
		t.Fatalf("first SignUp() error = %v", err)
	}
	calls, destination, code := delivery.snapshot()
	if calls != 1 || destination != email || len(code) != 6 {
		t.Fatalf("delivery calls/destination/code = %d/%q/%q", calls, destination, code)
	}
	assertPublicSignupCounts(t, ctx, pool, app.InternalID, 1, 1, 1, 1)

	if err := signup.SignUp(ctx, app.InternalID, email, password, "signup-one"); err != nil {
		t.Fatalf("idempotent replay SignUp() error = %v", err)
	}
	calls, _, _ = delivery.snapshot()
	if calls != 1 {
		t.Fatalf("idempotent replay delivery calls = %d, want 1", calls)
	}
	assertPublicSignupCounts(t, ctx, pool, app.InternalID, 1, 1, 1, 1)

	if err := signup.SignUp(ctx, app.InternalID, email, "different correct horse battery staple", "signup-one"); !errors.Is(err, authentication.ErrPublicIdempotencyConflict) {
		t.Fatalf("conflicting idempotency error = %v", err)
	}
	assertPublicSignupCounts(t, ctx, pool, app.InternalID, 1, 1, 1, 1)

	if err := signup.SignUp(ctx, app.InternalID, email, "another correct horse battery staple", "signup-two"); err != nil {
		t.Fatalf("duplicate signup generic error = %v", err)
	}
	calls, _, _ = delivery.snapshot()
	if calls != 1 {
		t.Fatalf("duplicate existing account delivery calls = %d, want 1", calls)
	}
	assertPublicSignupCounts(t, ctx, pool, app.InternalID, 1, 1, 1, 1)

	verification := authentication.NewPublicVerificationService(
		identitypostgres.New(pool),
		store,
		authentication.NewEmailVerificationService(store, delivery),
	)
	if err := verification.Confirm(ctx, app.InternalID, email, code); err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	identifier, err := identitypostgres.New(pool).ResolveEmailIdentifierByAddress(ctx, app.InternalID, email)
	if err != nil || identifier.VerifiedAt == nil {
		t.Fatalf("verified identifier = %+v error=%v", identifier, err)
	}
	if err := verification.Confirm(ctx, app.InternalID, email, code); err == nil {
		t.Fatal("verification replay unexpectedly succeeded")
	}
}

func TestPublicSignupConcurrentIdempotencyHasOneLogicalExecution(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_public_signup_concurrent")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &publicSignupDelivery{}
	signup := authentication.NewPublicSignupService(New(pool), delivery)

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- signup.SignUp(ctx, app.InternalID, "race@example.com", "correct horse battery staple", "same-key")
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent SignUp() error = %v", err)
		}
	}
	calls, _, _ := delivery.snapshot()
	if calls != 1 {
		t.Fatalf("concurrent delivery calls = %d, want 1", calls)
	}
	assertPublicSignupCounts(t, ctx, pool, app.InternalID, 1, 1, 1, 1)
}

func TestPublicSignupProviderFailureDoesNotEraseCommittedState(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_public_signup_delivery_failure")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &publicSignupDelivery{err: errors.New("synthetic provider secret detail")}
	signup := authentication.NewPublicSignupService(New(pool), delivery)
	if err := signup.SignUp(ctx, app.InternalID, "delivery@example.com", "correct horse battery staple", "delivery-key"); !errors.Is(err, authentication.ErrEmailVerificationDelivery) {
		t.Fatalf("SignUp() delivery error = %v", err)
	}
	assertPublicSignupCounts(t, ctx, pool, app.InternalID, 1, 1, 1, 1)

	db := pool.OpenSQLDB()
	defer db.Close()
	var audits int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_events WHERE application_instance_id = $1
		 AND action IN ('authentication.email_password.register','authentication.email_verification.challenge_issued')`,
		int64(app.InternalID),
	).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 2 {
		t.Fatalf("committed signup/verification audits = %d, want 2", audits)
	}
}

func TestPublicSignupSameEmailIsApplicationScoped(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_public_signup_cross_app")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &publicSignupDelivery{}
	signup := authentication.NewPublicSignupService(New(pool), delivery)
	for _, appID := range []applicationinstance.InternalID{appA.InternalID, appB.InternalID} {
		if err := signup.SignUp(ctx, appID, "shared@example.com", "correct horse battery staple", "same-client-key"); err != nil {
			t.Fatalf("SignUp(app=%d) error = %v", appID, err)
		}
		assertPublicSignupCounts(t, ctx, pool, appID, 1, 1, 1, 1)
	}
	calls, _, _ := delivery.snapshot()
	if calls != 2 {
		t.Fatalf("cross-app delivery calls = %d, want 2", calls)
	}
}

func assertPublicSignupCounts(
	t *testing.T,
	ctx context.Context,
	pool interface{ OpenSQLDB() *sql.DB },
	appID applicationinstance.InternalID,
	users int,
	emails int,
	passwords int,
	challenges int,
) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	checks := []struct {
		query string
		want  int
	}{
		{`SELECT count(*) FROM users WHERE application_instance_id = $1`, users},
		{`SELECT count(*) FROM email_identifiers WHERE application_instance_id = $1`, emails},
		{`SELECT count(*) FROM password_credentials WHERE application_instance_id = $1`, passwords},
		{`SELECT count(*) FROM email_verification_challenges WHERE application_instance_id = $1`, challenges},
	}
	for _, check := range checks {
		var got int
		if err := db.QueryRowContext(ctx, check.query, int64(appID)).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != check.want {
			t.Fatalf("query %q count = %d, want %d", check.query, got, check.want)
		}
	}
}
