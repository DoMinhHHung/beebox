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
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

func TestRegistrationCommitsCompleteScopedBundle(t *testing.T) {
	pool, ctx := registrationDatabase(t, "beebox_registration_success")
	appA, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	appB, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app B) error = %v", err)
	}

	registrar := authentication.NewRegistrar(New(pool))
	resultA, err := registrar.RegisterEmailPassword(ctx, appA.InternalID, "  Alice@Example.TEST  ", []byte(" synthetic registration password "))
	if err != nil {
		t.Fatalf("RegisterEmailPassword(A) error = %v", err)
	}
	if resultA.EmailIdentifier.EmailAddress != "Alice@Example.TEST" || resultA.EmailIdentifier.NormalizedEmail != "alice@example.test" || resultA.EmailIdentifier.VerifiedAt != nil {
		t.Fatalf("registered email state = %#v", resultA.EmailIdentifier)
	}

	credential, err := New(pool).ResolvePasswordCredential(ctx, appA.InternalID, resultA.User.InternalID)
	if err != nil {
		t.Fatalf("ResolvePasswordCredential(A) error = %v", err)
	}
	if err := authentication.VerifyPassword(credential.PasswordHash, []byte(" synthetic registration password ")); err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}

	resultB, err := registrar.RegisterEmailPassword(ctx, appB.InternalID, "alice@example.test", []byte("second synthetic password"))
	if err != nil {
		t.Fatalf("RegisterEmailPassword(B) error = %v", err)
	}
	if resultA.User.InternalID == resultB.User.InternalID && resultA.User.ApplicationInstanceID == resultB.User.ApplicationInstanceID {
		t.Fatal("cross-application registrations collapsed into one scoped user")
	}

	assertRegistrationCounts(t, ctx, pool.OpenSQLDB(), appA.InternalID, 1, 1, 1, 1)
	assertRegistrationCounts(t, ctx, pool.OpenSQLDB(), appB.InternalID, 1, 1, 1, 1)

	db := pool.OpenSQLDB()
	defer db.Close()
	var actorKind, action, resource, outcome, source string
	var subjectUserID int64
	var correlationLength int
	if err := db.QueryRowContext(
		ctx,
		`SELECT actor_kind, subject_user_id, action, resource_category, outcome, source, octet_length(correlation_id)
		 FROM audit_events WHERE application_instance_id = $1`,
		int64(appA.InternalID),
	).Scan(&actorKind, &subjectUserID, &action, &resource, &outcome, &source, &correlationLength); err != nil {
		t.Fatalf("query audit event error = %v", err)
	}
	if actorKind != audit.ActorKindAnonymousRegistration || identity.InternalID(subjectUserID) != resultA.User.InternalID || action != audit.ActionEmailPasswordRegistration || resource != audit.ResourceCategoryUserRegistration || outcome != audit.OutcomeSuccess || source != audit.SourceInternalRegistration || correlationLength != audit.CorrelationIDBytes {
		t.Fatalf("unexpected registration audit fact: actor=%q subject=%d action=%q resource=%q outcome=%q source=%q correlation=%d", actorKind, subjectUserID, action, resource, outcome, source, correlationLength)
	}
}

func TestRegistrationDuplicateEmailRollsBackLoser(t *testing.T) {
	pool, ctx := registrationDatabase(t, "beebox_registration_duplicate")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	store := New(pool)
	hash, err := authentication.HashPassword([]byte("prehashed duplicate fixture"))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	first := registrationWrite(t, app.InternalID, "Alice@Example.TEST", hash)
	if _, err := store.PersistRegistration(ctx, first); err != nil {
		t.Fatalf("first PersistRegistration() error = %v", err)
	}
	second := registrationWrite(t, app.InternalID, " alice@example.test ", hash)
	if _, err := store.PersistRegistration(ctx, second); !errors.Is(err, authentication.ErrRegistrationConflict) {
		t.Fatalf("duplicate PersistRegistration() error = %v, want conflict", err)
	}
	assertRegistrationCounts(t, ctx, pool.OpenSQLDB(), app.InternalID, 1, 1, 1, 1)
}

func TestRegistrationConcurrentDuplicateCommitsOneBundle(t *testing.T) {
	pool, ctx := registrationDatabase(t, "beebox_registration_concurrent")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	hash, err := authentication.HashPassword([]byte("prehashed concurrency fixture"))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	const attempts = 8
	variants := []string{"Alice@Example.TEST", " alice@example.test ", "ALICE@example.test", "Alice@EXAMPLE.TEST"}
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		write := registrationWrite(t, app.InternalID, variants[i%len(variants)], hash)
		wg.Add(1)
		go func(write authentication.RegistrationWrite) {
			defer wg.Done()
			<-start
			_, err := New(pool).PersistRegistration(ctx, write)
			results <- err
		}(write)
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
		case errors.Is(err, authentication.ErrRegistrationConflict):
			conflicts++
		default:
			t.Fatalf("concurrent registration error = %v", err)
		}
	}
	if successes != 1 || conflicts != attempts-1 {
		t.Fatalf("concurrent results success=%d conflict=%d, want 1/%d", successes, conflicts, attempts-1)
	}
	assertRegistrationCounts(t, ctx, pool.OpenSQLDB(), app.InternalID, 1, 1, 1, 1)
}

func TestRegistrationRollsBackPasswordAndAuditFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		table      string
		function   string
		trigger    string
	}{
		{name: "password", table: "password_credentials", function: "fail_registration_password", trigger: "fail_registration_password"},
		{name: "audit", table: "audit_events", function: "fail_registration_audit", trigger: "fail_registration_audit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, ctx := registrationDatabase(t, "beebox_registration_fail_"+tc.name)
			app, err := applicationpostgres.New(pool).Create(ctx)
			if err != nil {
				t.Fatalf("Create(app) error = %v", err)
			}
			db := pool.OpenSQLDB()
			functionSQL := "CREATE FUNCTION " + tc.function + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic registration write failure'; END $$"
			if _, err := db.ExecContext(ctx, functionSQL); err != nil {
				db.Close()
				t.Fatalf("create failure function error = %v", err)
			}
			triggerSQL := "CREATE TRIGGER " + tc.trigger + " BEFORE INSERT ON " + tc.table + " FOR EACH ROW EXECUTE FUNCTION " + tc.function + "()"
			if _, err := db.ExecContext(ctx, triggerSQL); err != nil {
				db.Close()
				t.Fatalf("create failure trigger error = %v", err)
			}
			_ = db.Close()

			hash, err := authentication.HashPassword([]byte("forced failure fixture"))
			if err != nil {
				t.Fatalf("HashPassword() error = %v", err)
			}
			_, err = New(pool).PersistRegistration(ctx, registrationWrite(t, app.InternalID, "failure@example.test", hash))
			if !errors.Is(err, authentication.ErrRegistrationPersistence) {
				t.Fatalf("PersistRegistration() error = %v, want stable persistence failure", err)
			}
			assertRegistrationCounts(t, ctx, pool.OpenSQLDB(), app.InternalID, 0, 0, 0, 0)
		})
	}
}

func TestRegistrationRejectsMissingApplicationAndCancellationWithoutPartialState(t *testing.T) {
	pool, ctx := registrationDatabase(t, "beebox_registration_boundary")
	hash, err := authentication.HashPassword([]byte("boundary fixture"))
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if _, err := New(pool).PersistRegistration(ctx, registrationWrite(t, applicationinstance.InternalID(999999), "missing-app@example.test", hash)); !errors.Is(err, authentication.ErrRegistrationPersistence) {
		t.Fatalf("missing application error = %v", err)
	}

	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := New(pool).PersistRegistration(canceled, registrationWrite(t, app.InternalID, "cancel@example.test", hash)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled registration error = %v", err)
	}
	assertRegistrationCounts(t, ctx, pool.OpenSQLDB(), app.InternalID, 0, 0, 0, 0)
}

func TestAuditScopedUserReferencesRejectForeignApplication(t *testing.T) {
	pool, ctx := registrationDatabase(t, "beebox_audit_scope")
	appA, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app A) error = %v", err)
	}
	appB, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app B) error = %v", err)
	}
	registered, err := authentication.NewRegistrar(New(pool)).RegisterEmailPassword(ctx, appB.InternalID, "subject@example.test", []byte("scope fixture"))
	if err != nil {
		t.Fatalf("register app B subject error = %v", err)
	}
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatalf("NewCorrelationID() error = %v", err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO audit_events (application_instance_id, actor_kind, subject_user_id, action, resource_category, outcome, correlation_id, source)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		int64(appA.InternalID),
		audit.ActorKindAnonymousRegistration,
		int64(registered.User.InternalID),
		audit.ActionEmailPasswordRegistration,
		audit.ResourceCategoryUserRegistration,
		audit.OutcomeSuccess,
		correlationID[:],
		audit.SourceInternalRegistration,
	)
	if err == nil {
		t.Fatal("cross-application audit subject insert unexpectedly succeeded")
	}
}

func registrationDatabase(t *testing.T, schema string) (*database.Pool, context.Context) {
	t.Helper()
	pool := openPool(t, isolatedDatabaseURL(t, schema))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	return pool, ctx
}

func registrationWrite(t *testing.T, appID applicationinstance.InternalID, rawEmail string, hash authentication.PasswordHash) authentication.RegistrationWrite {
	t.Helper()
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		t.Fatalf("NormalizeEmail(%q) error = %v", rawEmail, err)
	}
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatalf("NewCorrelationID() error = %v", err)
	}
	return authentication.RegistrationWrite{
		ApplicationInstanceID: appID,
		Email:                  email,
		PasswordHash:           hash,
		CorrelationID:          correlationID,
	}
}

func assertRegistrationCounts(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	appID applicationinstance.InternalID,
	users int,
	emails int,
	credentials int,
	audits int,
) {
	t.Helper()
	defer db.Close()
	for _, item := range []struct {
		table string
		want  int
	}{
		{table: "users", want: users},
		{table: "email_identifiers", want: emails},
		{table: "password_credentials", want: credentials},
		{table: "audit_events", want: audits},
	} {
		var got int
		query := "SELECT count(*) FROM " + item.table + " WHERE application_instance_id = $1"
		if err := db.QueryRowContext(ctx, query, int64(appID)).Scan(&got); err != nil {
			t.Fatalf("count %s error = %v", item.table, err)
		}
		if got != item.want {
			t.Fatalf("%s rows = %d, want %d", item.table, got, item.want)
		}
	}
}
