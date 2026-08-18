//go:build integration

package postgres

import (
	"context"
	cryptosha256 "crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func TestSocialExternalIdentityConvergesPerApplicationAndIgnoresEmailCollision(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_identity")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}

	applicationStore := applicationpostgres.New(pool)
	appA, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}

	identityStore := identitypostgres.New(pool)
	existing, err := identityStore.Create(ctx, appA.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	emailIdentifier, err := identityStore.CreateEmailIdentifier(ctx, appA.InternalID, existing.InternalID, "user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `UPDATE email_identifiers SET verified_at=CURRENT_TIMESTAMP WHERE id=$1`, int64(emailIdentifier.InternalID)); err != nil {
		t.Fatal(err)
	}

	store := New(pool)
	challenge, _ := authentication.S256Challenge(strings.Repeat("v", 43))
	correlation, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatal(err)
	}
	final := authentication.SocialProofFinalize{
		ApplicationInstanceID: appA.InternalID,
		Provider:              authentication.ProviderGitHub,
		ProviderSubject:       "stable-provider-subject",
		ClientCodeChallenge:   challenge,
		CompletionCodeHash:    cryptosha256.Sum256([]byte("fake-completion-a")),
		CompletionExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
		CorrelationID:         correlation,
	}
	if err := store.FinalizeSocialProof(ctx, final); err != nil {
		t.Fatalf("FinalizeSocialProof() error = %v", err)
	}

	var socialUserID int64
	if err := db.QueryRowContext(ctx, `SELECT user_id FROM external_identities WHERE application_instance_id=$1 AND provider='github' AND provider_subject=$2`, int64(appA.InternalID), final.ProviderSubject).Scan(&socialUserID); err != nil {
		t.Fatal(err)
	}
	if socialUserID == int64(existing.InternalID) {
		t.Fatal("provider subject attached to existing email principal")
	}
	var emailRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_identifiers WHERE application_instance_id=$1`, int64(appA.InternalID)).Scan(&emailRows); err != nil {
		t.Fatal(err)
	}
	if emailRows != 1 {
		t.Fatalf("email identifiers = %d, want existing row only", emailRows)
	}
	var socialUserEmailRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2`, int64(appA.InternalID), socialUserID).Scan(&socialUserEmailRows); err != nil {
		t.Fatal(err)
	}
	if socialUserEmailRows != 0 {
		t.Fatalf("provider-first user gained %d email identifiers", socialUserEmailRows)
	}

	secondCorrelation, _ := audit.NewCorrelationID()
	second := final
	second.CompletionCodeHash = cryptosha256.Sum256([]byte("fake-completion-b"))
	second.CorrelationID = secondCorrelation
	if err := store.FinalizeSocialProof(ctx, second); err != nil {
		t.Fatalf("existing subject finalize error = %v", err)
	}
	var usersForSubject int
	if err := db.QueryRowContext(ctx, `SELECT count(DISTINCT user_id) FROM external_identities WHERE application_instance_id=$1 AND provider='github' AND provider_subject=$2`, int64(appA.InternalID), final.ProviderSubject).Scan(&usersForSubject); err != nil {
		t.Fatal(err)
	}
	if usersForSubject != 1 {
		t.Fatalf("existing subject resolved to %d users", usersForSubject)
	}

	crossCorrelation, _ := audit.NewCorrelationID()
	cross := final
	cross.ApplicationInstanceID = appB.InternalID
	cross.CompletionCodeHash = cryptosha256.Sum256([]byte("fake-completion-cross-app"))
	cross.CorrelationID = crossCorrelation
	if err := store.FinalizeSocialProof(ctx, cross); err != nil {
		t.Fatalf("cross-app finalize error = %v", err)
	}
	var crossUserID int64
	if err := db.QueryRowContext(ctx, `SELECT user_id FROM external_identities WHERE application_instance_id=$1 AND provider='github' AND provider_subject=$2`, int64(appB.InternalID), final.ProviderSubject).Scan(&crossUserID); err != nil {
		t.Fatal(err)
	}
	if crossUserID == socialUserID {
		t.Fatal("identical provider subject shared a user across applications")
	}
}

func TestConcurrentFirstSocialProofCreatesOnePrincipalAndNoOrphan(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_concurrency")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	challenge, _ := authentication.S256Challenge(strings.Repeat("c", 43))

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			correlation, err := audit.NewCorrelationID()
			if err != nil {
				errs <- err
				return
			}
			errs <- store.FinalizeSocialProof(ctx, authentication.SocialProofFinalize{
				ApplicationInstanceID: app.InternalID,
				Provider:              authentication.ProviderGoogle,
				ProviderSubject:       "same-concurrent-subject",
				ClientCodeChallenge:   challenge,
				CompletionCodeHash:    cryptosha256.Sum256([]byte{byte(i + 1)}),
				CompletionExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
				CorrelationID:         correlation,
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent finalize error = %v", err)
		}
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var identities, users, grants int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM external_identities WHERE application_instance_id=$1 AND provider='google' AND provider_subject='same-concurrent-subject'`, int64(app.InternalID)).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM social_auth_completion_grants WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if identities != 1 || users != 1 || grants != 2 {
		t.Fatalf("identities=%d users=%d grants=%d, want 1/1/2", identities, users, grants)
	}
}

func TestSocialAttemptAndCompletionAreOneTimeAndApplicationScoped(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_grants")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	applicationStore := applicationpostgres.New(pool)
	appA, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := applicationStore.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	challenge, _ := authentication.S256Challenge(strings.Repeat("p", 43))
	stateHash := cryptosha256.Sum256([]byte("fake-state-material"))
	if err := store.CreateSocialAttempt(ctx, authentication.SocialAttemptWrite{
		ApplicationInstanceID: appA.InternalID,
		Provider:              authentication.ProviderDiscord,
		CanonicalRedirectURL:  "https://app.example.test/auth/callback",
		StateHash:             stateHash,
		ClientCodeChallenge:   challenge,
		ExpiresAt:             time.Now().UTC().Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeSocialAttempt(ctx, stateHash, authentication.ProviderGitHub); !errors.Is(err, authentication.ErrSocialInvalidState) {
		t.Fatalf("wrong provider error = %v", err)
	}
	if _, err := store.ConsumeSocialAttempt(ctx, stateHash, authentication.ProviderDiscord); err != nil {
		t.Fatalf("consume attempt error = %v", err)
	}
	if _, err := store.ConsumeSocialAttempt(ctx, stateHash, authentication.ProviderDiscord); !errors.Is(err, authentication.ErrSocialInvalidState) {
		t.Fatalf("replayed state error = %v", err)
	}

	correlation, _ := audit.NewCorrelationID()
	completionHash := cryptosha256.Sum256([]byte("fake-one-time-completion"))
	if err := store.FinalizeSocialProof(ctx, authentication.SocialProofFinalize{
		ApplicationInstanceID: appA.InternalID,
		Provider:              authentication.ProviderDiscord,
		ProviderSubject:       "discord-stable-id",
		ClientCodeChallenge:   challenge,
		CompletionCodeHash:    completionHash,
		CompletionExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
		CorrelationID:         correlation,
	}); err != nil {
		t.Fatal(err)
	}
	wrongAppCorrelation, _ := audit.NewCorrelationID()
	wrongAppSession, _ := session.NewPublicID()
	_, err = store.ExchangeSocialCompletion(ctx, authentication.SocialCompletionFinalize{
		ApplicationInstanceID: appB.InternalID,
		CompletionCodeHash:    completionHash,
		ClientCodeChallenge:   challenge,
		SessionPublicID:       wrongAppSession,
		RefreshVerifier:       cryptosha256.Sum256([]byte("fake-refresh-wrong-app")),
		IdleExpiresAt:         time.Now().UTC().Add(time.Hour),
		ExpiresAt:             time.Now().UTC().Add(24 * time.Hour),
		CorrelationID:         wrongAppCorrelation,
	})
	if !errors.Is(err, authentication.ErrSocialCompletionInvalid) {
		t.Fatalf("cross-app completion error = %v", err)
	}

	sessionID, _ := session.NewPublicID()
	exchangeCorrelation, _ := audit.NewCorrelationID()
	result, err := store.ExchangeSocialCompletion(ctx, authentication.SocialCompletionFinalize{
		ApplicationInstanceID: appA.InternalID,
		CompletionCodeHash:    completionHash,
		ClientCodeChallenge:   challenge,
		SessionPublicID:       sessionID,
		RefreshVerifier:       cryptosha256.Sum256([]byte("fake-refresh")),
		IdleExpiresAt:         time.Now().UTC().Add(time.Hour),
		ExpiresAt:             time.Now().UTC().Add(24 * time.Hour),
		CorrelationID:         exchangeCorrelation,
	})
	if err != nil {
		t.Fatalf("exchange error = %v", err)
	}
	if result.UserPublicID == "" || result.ApplicationPublicID != string(appA.PublicID) {
		t.Fatalf("exchange result = %#v", result)
	}
	replaySession, _ := session.NewPublicID()
	replayCorrelation, _ := audit.NewCorrelationID()
	_, err = store.ExchangeSocialCompletion(ctx, authentication.SocialCompletionFinalize{
		ApplicationInstanceID: appA.InternalID,
		CompletionCodeHash:    completionHash,
		ClientCodeChallenge:   challenge,
		SessionPublicID:       replaySession,
		RefreshVerifier:       cryptosha256.Sum256([]byte("fake-refresh-replay")),
		IdleExpiresAt:         time.Now().UTC().Add(time.Hour),
		ExpiresAt:             time.Now().UTC().Add(24 * time.Hour),
		CorrelationID:         replayCorrelation,
	})
	if !errors.Is(err, authentication.ErrSocialCompletionInvalid) {
		t.Fatalf("completion replay error = %v", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var sessionRows, refreshRows, successAudits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND public_id=$2`, int64(appA.InternalID), sessionID).Scan(&sessionRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM session_refresh_credentials r JOIN sessions s ON s.id=r.session_id WHERE s.application_instance_id=$1 AND s.public_id=$2`, int64(appA.InternalID), sessionID).Scan(&refreshRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND action=$2 AND resource_reference=$3 AND outcome='success'`, int64(appA.InternalID), audit.ActionSocialSessionIssued, "session:"+sessionID).Scan(&successAudits); err != nil {
		t.Fatal(err)
	}
	if sessionRows != 1 || refreshRows != 1 || successAudits != 1 {
		t.Fatalf("session=%d refresh=%d audit=%d, want 1/1/1", sessionRows, refreshRows, successAudits)
	}
}

func TestSocialCompletionAuditFailureRollsBackSessionAndGrantConsumption(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_rollback")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	challenge, _ := authentication.S256Challenge(strings.Repeat("r", 43))
	completionHash := cryptosha256.Sum256([]byte("fake-rollback-completion"))
	correlation, _ := audit.NewCorrelationID()
	if err := store.FinalizeSocialProof(ctx, authentication.SocialProofFinalize{
		ApplicationInstanceID: app.InternalID,
		Provider:              authentication.ProviderGitLab,
		ProviderSubject:       "gitlab-stable-id",
		ClientCodeChallenge:   challenge,
		CompletionCodeHash:    completionHash,
		CompletionExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
		CorrelationID:         correlation,
	}); err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD CONSTRAINT social_test_force_audit_failure CHECK (action <> 'authentication.social.session_issued')`); err != nil {
		t.Fatal(err)
	}
	sessionID, _ := session.NewPublicID()
	exchangeCorrelation, _ := audit.NewCorrelationID()
	_, err = store.ExchangeSocialCompletion(ctx, authentication.SocialCompletionFinalize{
		ApplicationInstanceID: app.InternalID,
		CompletionCodeHash:    completionHash,
		ClientCodeChallenge:   challenge,
		SessionPublicID:       sessionID,
		RefreshVerifier:       cryptosha256.Sum256([]byte("fake-refresh-rollback")),
		IdleExpiresAt:         time.Now().UTC().Add(time.Hour),
		ExpiresAt:             time.Now().UTC().Add(24 * time.Hour),
		CorrelationID:         exchangeCorrelation,
	})
	if !errors.Is(err, authentication.ErrSocialPersistence) {
		t.Fatalf("exchange audit failure = %v", err)
	}
	var sessions, consumed int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND public_id=$2`, int64(app.InternalID), sessionID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM social_auth_completion_grants WHERE application_instance_id=$1 AND code_hash=$2 AND consumed_at IS NOT NULL`, int64(app.InternalID), completionHash[:]).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || consumed != 0 {
		t.Fatalf("rollback sessions=%d consumed=%d, want 0/0", sessions, consumed)
	}
}
