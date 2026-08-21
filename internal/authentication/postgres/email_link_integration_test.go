//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

type emailLinkFixture struct {
	store      *Store
	ctx        context.Context
	appID      int64
	userID     int64
	emailID    int64
	challenge  string
	completion string
	generation int64
}

func newEmailLinkFixture(t *testing.T, schema, challenge string) emailLinkFixture {
	t.Helper()
	pool, ctx := socialAccountManagementDatabase(t, schema)
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
	var emailID int64
	if err := db.QueryRowContext(ctx, `
		INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at)
		VALUES($1,$2,'user@example.test','user@example.test',CURRENT_TIMESTAMP) RETURNING id`,
		int64(app.InternalID), int64(user.InternalID)).Scan(&emailID); err != nil {
		t.Fatal(err)
	}
	correlation, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	secretHash := [32]byte{1, 2, 3, 4}
	store := New(pool)
	completion := "https://app.example/return"
	result, err := store.IssueEmailLink(ctx, authentication.EmailLinkIssue{
		ApplicationInstanceID: app.InternalID,
		NormalizedEmail:       "user@example.test",
		ChallengePublicID:     challenge,
		SecretHash:            secretHash,
		CompletionURL:         completion,
		CorrelationID:         correlation,
	})
	if err != nil || !result.ShouldSend {
		t.Fatalf("issue result=%#v err=%v", result, err)
	}
	snapshot, err := store.LoadEmailLink(ctx, app.InternalID, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return emailLinkFixture{store: store, ctx: ctx, appID: int64(app.InternalID), userID: int64(user.InternalID), emailID: emailID, challenge: challenge, completion: completion, generation: snapshot.ChallengeGeneration}
}

func (f emailLinkFixture) finalize(t *testing.T, matched bool, sessionID string) authentication.EmailLinkFinalize {
	t.Helper()
	correlation, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	return authentication.EmailLinkFinalize{
		ApplicationInstanceID: authenticationAppID(f.appID),
		EmailIdentifierID:     authenticationEmailID(f.emailID),
		UserID:                authenticationUserID(f.userID),
		ChallengePublicID:     f.challenge,
		ChallengeGeneration:   f.generation,
		CompletionURL:         f.completion,
		Matched:               matched,
		SessionPublicID:       sessionID,
		RefreshVerifier:       [32]byte{9, 8, 7, 6},
		IdleExpiresAt:         now.Add(time.Hour),
		ExpiresAt:             now.Add(2 * time.Hour),
		PendingMFA: authentication.PendingMFAWrite{
			PublicID:       "mfp_123e4567-e89b-42d3-a456-426614174210",
			TokenHash:      [32]byte{5, 4, 3, 2},
			PrimaryMethod:  authentication.PrimaryMethodEmailLink,
			PrimaryContext: f.challenge,
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Minute),
		},
		CorrelationID: correlation,
	}
}

func TestEmailLinkConcurrentConsumeCreatesAtMostOneSession(t *testing.T) {
	f := newEmailLinkFixture(t, "email_link_consume_race", "eln_123e4567-e89b-42d3-a456-426614174201")
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			final := f.finalize(t, true, "ses_123e4567-e89b-42d3-a456-426614174202")
			_, err := f.store.FinalizeEmailLink(context.Background(), final)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	success, stale := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, authentication.ErrEmailLinkStale), errors.Is(err, authentication.ErrEmailLinkInvalid):
			stale++
		default:
			t.Fatalf("concurrent finalize error=%v", err)
		}
	}
	if success != 1 || stale != 1 {
		t.Fatalf("success=%d stale=%d", success, stale)
	}
	db := f.store.pool.OpenSQLDB()
	defer db.Close()
	var sessions, consumed int
	if err := db.QueryRowContext(f.ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND user_id=$2`, f.appID, f.userID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(f.ctx, `SELECT count(*) FROM email_signin_links WHERE application_instance_id=$1 AND public_id=$2 AND consumed_at IS NOT NULL AND secret_hash IS NULL`, f.appID, f.challenge).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || consumed != 1 {
		t.Fatalf("sessions=%d consumed=%d want 1/1", sessions, consumed)
	}
}

func TestEmailLinkFailureBudgetAndCrossApplicationIsolation(t *testing.T) {
	f := newEmailLinkFixture(t, "email_link_failure_budget", "eln_123e4567-e89b-42d3-a456-426614174203")
	otherApp, err := applicationpostgres.New(f.store.pool).Create(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.LoadEmailLink(f.ctx, otherApp.InternalID, f.challenge); !errors.Is(err, authentication.ErrEmailLinkInvalid) {
		t.Fatalf("cross-app load error=%v", err)
	}
	for i := 0; i < authentication.EmailLinkMaxAttempts; i++ {
		final := f.finalize(t, false, "")
		if _, err := f.store.FinalizeEmailLink(f.ctx, final); !errors.Is(err, authentication.ErrEmailLinkInvalid) {
			t.Fatalf("failure %d error=%v", i+1, err)
		}
	}
	if _, err := f.store.LoadEmailLink(f.ctx, authenticationAppID(f.appID), f.challenge); !errors.Is(err, authentication.ErrEmailLinkInvalid) {
		t.Fatalf("exhausted link load error=%v", err)
	}
	db := f.store.pool.OpenSQLDB()
	defer db.Close()
	var failures int
	if err := db.QueryRowContext(f.ctx, `SELECT failed_attempts FROM email_signin_links WHERE application_instance_id=$1 AND public_id=$2`, f.appID, f.challenge).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != authentication.EmailLinkMaxAttempts {
		t.Fatalf("failed_attempts=%d", failures)
	}
}

func TestEmailLinkAuditFailureRollsBackConsumptionAndSession(t *testing.T) {
	f := newEmailLinkFixture(t, "email_link_audit_rollback", "eln_123e4567-e89b-42d3-a456-426614174204")
	db := f.store.pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(f.ctx, `ALTER TABLE audit_events ADD CONSTRAINT audit_events_test_reject_email_link CHECK (source <> 'internal_email_link')`); err != nil {
		t.Fatal(err)
	}
	_, err := f.store.FinalizeEmailLink(f.ctx, f.finalize(t, true, "ses_123e4567-e89b-42d3-a456-426614174205"))
	if !errors.Is(err, authentication.ErrEmailLinkPersistence) {
		t.Fatalf("finalize error=%v", err)
	}
	var active, sessions int
	if err := db.QueryRowContext(f.ctx, `SELECT count(*) FROM email_signin_links WHERE application_instance_id=$1 AND public_id=$2 AND consumed_at IS NULL AND secret_hash IS NOT NULL`, f.appID, f.challenge).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(f.ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND user_id=$2`, f.appID, f.userID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if active != 1 || sessions != 0 {
		t.Fatalf("active=%d sessions=%d want 1/0", active, sessions)
	}
}

func TestEmailLinkWithActiveTOTPCreatesPendingMFAWithoutSession(t *testing.T) {
	f := newEmailLinkFixture(t, "email_link_totp_gate", "eln_123e4567-e89b-42d3-a456-426614174206")
	db := f.store.pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(f.ctx, `
		INSERT INTO totp_credentials(application_instance_id,user_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret)
		VALUES($1,$2,1,'test-key',decode(repeat('aa',12),'hex'),decode(repeat('bb',17),'hex'))`, f.appID, f.userID); err != nil {
		t.Fatal(err)
	}
	result, err := f.store.FinalizeEmailLink(f.ctx, f.finalize(t, true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !result.MFARequired || result.PendingMFAPublicID == "" {
		t.Fatalf("result=%#v", result)
	}
	var sessions, pending int
	if err := db.QueryRowContext(f.ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND user_id=$2`, f.appID, f.userID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(f.ctx, `SELECT count(*) FROM pending_mfa_authentications WHERE application_instance_id=$1 AND user_id=$2 AND primary_method='email_link' AND primary_context=$3 AND consumed_at IS NULL`, f.appID, f.userID, f.challenge).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || pending != 1 {
		t.Fatalf("sessions=%d pending=%d want 0/1", sessions, pending)
	}
}

// Narrow conversion helpers keep fixtures explicit without leaking SQL ints into
// production APIs.
func authenticationAppID(id int64) applicationinstance.InternalID {
	return applicationinstance.InternalID(id)
}
func authenticationUserID(id int64) identity.InternalID { return identity.InternalID(id) }
func authenticationEmailID(id int64) identity.EmailIdentifierInternalID {
	return identity.EmailIdentifierInternalID(id)
}
