//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestAccountIdentifierConcurrentRemovalCannotStrandUser(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "account_identifier_remove_race")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()

	var firstID, secondID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at)
		VALUES($1,$2,'first@example.test','first@example.test',CURRENT_TIMESTAMP) RETURNING public_id`,
		int64(app.InternalID), int64(user.InternalID)).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `
		INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at)
		VALUES($1,$2,'second@example.test','second@example.test',CURRENT_TIMESTAMP) RETURNING public_id`,
		int64(app.InternalID), int64(user.InternalID)).Scan(&secondID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO password_credentials(application_instance_id,user_id,password_hash) VALUES($1,$2,'hash')`, int64(app.InternalID), int64(user.InternalID)); err != nil {
		t.Fatal(err)
	}

	current := authentication.AccountManagementSession{ApplicationInstanceID: app.InternalID, UserID: user.InternalID}
	store := New(pool)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, publicID := range []string{firstID, secondID} {
		publicID := publicID
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			correlation, err := audit.NewCorrelationID()
			if err != nil {
				results <- err
				return
			}
			results <- store.RemoveManagedEmail(context.Background(), current, publicID, correlation)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	succeeded, protected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, authentication.ErrLastAuthenticationMethod):
			protected++
		default:
			t.Fatalf("concurrent removal error=%v", err)
		}
	}
	if succeeded != 1 || protected != 1 {
		t.Fatalf("succeeded=%d protected=%d, want one removal and one last-method denial", succeeded, protected)
	}
	var remaining, primary int
	if err := db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER (WHERE is_primary) FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&remaining, &primary); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 || primary != 1 {
		t.Fatalf("remaining=%d primary=%d, want one usable primary identifier", remaining, primary)
	}
}

func TestAccountIdentifierMutationIsTenantScopedAndNonEnumerating(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "account_identifier_scope")
	apps := applicationpostgres.New(pool)
	appA, _ := apps.Create(ctx)
	appB, _ := apps.Create(ctx)
	identities := identitypostgres.New(pool)
	userA, _ := identities.Create(ctx, appA.InternalID)
	userB, _ := identities.Create(ctx, appB.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	var emailA, emailB string
	if err := db.QueryRowContext(ctx, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,'a@example.test','a@example.test',CURRENT_TIMESTAMP) RETURNING public_id`, int64(appA.InternalID), int64(userA.InternalID)).Scan(&emailA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,'b@example.test','b@example.test',CURRENT_TIMESTAMP) RETURNING public_id`, int64(appB.InternalID), int64(userB.InternalID)).Scan(&emailB); err != nil {
		t.Fatal(err)
	}

	currentA := authentication.AccountManagementSession{ApplicationInstanceID: appA.InternalID, UserID: userA.InternalID}
	correlation, _ := audit.NewCorrelationID()
	store := New(pool)
	if err := store.RemoveManagedEmail(ctx, currentA, emailB, correlation); err != nil {
		t.Fatalf("cross-tenant removal should be non-enumerating idempotent success, got %v", err)
	}
	correlation, _ = audit.NewCorrelationID()
	if err := store.SetPrimaryManagedEmail(ctx, currentA, emailB, correlation); !errors.Is(err, authentication.ErrAccountIdentifierNotFound) {
		t.Fatalf("cross-tenant primary change error=%v, want not found", err)
	}
	var otherCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3`, int64(appB.InternalID), int64(userB.InternalID), emailB).Scan(&otherCount); err != nil {
		t.Fatal(err)
	}
	if otherCount != 1 {
		t.Fatalf("cross-tenant identifier count=%d, want preserved", otherCount)
	}
	page, err := store.ListManagedEmails(ctx, appA.InternalID, userA.InternalID, 10, nil)
	if err != nil || len(page) != 1 || page[0].PublicID != emailA {
		t.Fatalf("tenant A list=%#v err=%v", page, err)
	}
}

func TestAccountIdentifierRemovalAuditFailureRollsBackMutation(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "account_identifier_audit_rollback")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	var targetID string
	if err := db.QueryRowContext(ctx, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,'target@example.test','target@example.test',CURRENT_TIMESTAMP) RETURNING public_id`, int64(app.InternalID), int64(user.InternalID)).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,'backup@example.test','backup@example.test',CURRENT_TIMESTAMP)`, int64(app.InternalID), int64(user.InternalID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO password_credentials(application_instance_id,user_id,password_hash) VALUES($1,$2,'hash')`, int64(app.InternalID), int64(user.InternalID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_account_management CHECK (source <> 'internal_account_management')`); err != nil {
		t.Fatal(err)
	}

	correlation, _ := audit.NewCorrelationID()
	current := authentication.AccountManagementSession{ApplicationInstanceID: app.InternalID, UserID: user.InternalID}
	if err := New(pool).RemoveManagedEmail(ctx, current, targetID, correlation); !errors.Is(err, authentication.ErrAccountManagementPersistence) {
		t.Fatalf("audit failure error=%v, want account management persistence failure", err)
	}
	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3`, int64(app.InternalID), int64(user.InternalID), targetID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("identifier count after audit failure=%d, want rollback", remaining)
	}
}
