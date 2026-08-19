//go:build integration

package postgres

import (
	"context"
	cryptosha256 "crypto/sha256"
	"errors"
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

func TestSocialLinkOwnershipRulesAndNoPrincipalOrSessionCreation(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_link_ownership")
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
	identityStore := identitypostgres.New(pool)
	userA, err := identityStore.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	userB, err := identityStore.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()

	// A verified email on B intentionally collides with a provider fixture notionally
	// carrying the same address. Social link persistence receives no email at all.
	emailB, err := identityStore.CreateEmailIdentifier(ctx, app.InternalID, userB.InternalID, "collision@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE email_identifiers SET verified_at=CURRENT_TIMESTAMP WHERE id=$1`, int64(emailB.InternalID)); err != nil {
		t.Fatal(err)
	}

	sessionA, createdA := insertSocialLinkSession(t, ctx, db, app.InternalID, userA.InternalID, time.Minute)
	sessionB, createdB := insertSocialLinkSession(t, ctx, db, app.InternalID, userB.InternalID, time.Minute)
	store := New(pool)

	attemptA := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, userA.InternalID, sessionA, createdA, authentication.ProviderGitHub, "ownership-a")
	correlationA, _ := audit.NewCorrelationID()
	if err := store.FinalizeSocialLink(ctx, authentication.SocialLinkFinalize{AttemptID: attemptA.AttemptID, ProviderSubject: "shared-subject", CorrelationID: correlationA}); err != nil {
		t.Fatalf("first link error = %v", err)
	}
	assertExternalIdentityOwner(t, ctx, db, app.InternalID, authentication.ProviderGitHub, "shared-subject", userA.InternalID)

	// Exact same owner is a logical idempotent success and must not duplicate ownership.
	attemptSame := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, userA.InternalID, sessionA, createdA, authentication.ProviderGitHub, "ownership-same")
	correlationSame, _ := audit.NewCorrelationID()
	if err := store.FinalizeSocialLink(ctx, authentication.SocialLinkFinalize{AttemptID: attemptSame.AttemptID, ProviderSubject: "shared-subject", CorrelationID: correlationSame}); err != nil {
		t.Fatalf("same-owner link error = %v", err)
	}
	var identityRows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM external_identities WHERE application_instance_id=$1 AND provider='github' AND provider_subject='shared-subject'`, int64(app.InternalID)).Scan(&identityRows); err != nil {
		t.Fatal(err)
	}
	if identityRows != 1 {
		t.Fatalf("same-owner identity rows = %d, want 1", identityRows)
	}

	// A different bound user is denied without transfer or merge.
	attemptB := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, userB.InternalID, sessionB, createdB, authentication.ProviderGitHub, "ownership-b")
	correlationB, _ := audit.NewCorrelationID()
	err = store.FinalizeSocialLink(ctx, authentication.SocialLinkFinalize{AttemptID: attemptB.AttemptID, ProviderSubject: "shared-subject", CorrelationID: correlationB})
	if !errors.Is(err, authentication.ErrSocialLinkDenied) {
		t.Fatalf("other-owner link error = %v, want denied", err)
	}
	assertExternalIdentityOwner(t, ctx, db, app.InternalID, authentication.ProviderGitHub, "shared-subject", userA.InternalID)

	var users, sessions, grants, emailRows, successAudits, deniedAudits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM social_auth_completion_grants WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM email_identifiers WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&emailRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND action=$2 AND outcome='success'`, int64(app.InternalID), audit.ActionSocialLinkSucceeded).Scan(&successAudits); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND action=$2 AND outcome='denied'`, int64(app.InternalID), audit.ActionSocialLinkDenied).Scan(&deniedAudits); err != nil {
		t.Fatal(err)
	}
	if users != 2 || sessions != 2 || grants != 0 || emailRows != 1 || successAudits != 2 || deniedAudits != 1 {
		t.Fatalf("users=%d sessions=%d grants=%d emails=%d success_audits=%d denied_audits=%d, want 2/2/0/1/2/1", users, sessions, grants, emailRows, successAudits, deniedAudits)
	}
}

func TestConcurrentSocialLinkClaimsConvergeToOneBoundOwner(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_link_concurrent")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	app, _ := applicationpostgres.New(pool).Create(ctx)
	identityStore := identitypostgres.New(pool)
	userA, _ := identityStore.Create(ctx, app.InternalID)
	userB, _ := identityStore.Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionA, createdA := insertSocialLinkSession(t, ctx, db, app.InternalID, userA.InternalID, time.Minute)
	sessionB, createdB := insertSocialLinkSession(t, ctx, db, app.InternalID, userB.InternalID, time.Minute)
	store := New(pool)
	attemptA := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, userA.InternalID, sessionA, createdA, authentication.ProviderGoogle, "race-a")
	attemptB := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, userB.InternalID, sessionB, createdB, authentication.ProviderGoogle, "race-b")

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, attempt := range []authentication.SocialLinkAttemptSnapshot{attemptA, attemptB} {
		attempt := attempt
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			correlation, _ := audit.NewCorrelationID()
			errs <- store.FinalizeSocialLink(ctx, authentication.SocialLinkFinalize{AttemptID: attempt.AttemptID, ProviderSubject: "one-subject", CorrelationID: correlation})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	var succeeded, denied int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, authentication.ErrSocialLinkDenied):
			denied++
		default:
			t.Fatalf("concurrent finalization error = %v", err)
		}
	}
	if succeeded != 1 || denied != 1 {
		t.Fatalf("concurrent outcomes success=%d denied=%d, want 1/1", succeeded, denied)
	}
	var rows, owners int
	if err := db.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT user_id) FROM external_identities WHERE application_instance_id=$1 AND provider='google' AND provider_subject='one-subject'`, int64(app.InternalID)).Scan(&rows, &owners); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || owners != 1 {
		t.Fatalf("concurrent identity rows=%d owners=%d, want 1/1", rows, owners)
	}
}

func TestSocialLinkFinalizationFailsClosedWhenBoundSessionChanges(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_link_session")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	store := New(pool)

	for _, tc := range []struct {
		name   string
		mutate func(string)
	}{
		{name: "revoked", mutate: func(publicID string) {
			if _, err := db.ExecContext(ctx, `UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE public_id=$1`, publicID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "expired", mutate: func(publicID string) {
			if _, err := db.ExecContext(ctx, `UPDATE sessions SET idle_expires_at=CURRENT_TIMESTAMP - INTERVAL '1 second', expires_at=CURRENT_TIMESTAMP WHERE public_id=$1`, publicID); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicID, createdAt := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
			attempt := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, user.InternalID, publicID, createdAt, authentication.ProviderDiscord, "session-"+tc.name)
			tc.mutate(publicID)
			correlation, _ := audit.NewCorrelationID()
			err := store.FinalizeSocialLink(ctx, authentication.SocialLinkFinalize{AttemptID: attempt.AttemptID, ProviderSubject: "subject-" + tc.name, CorrelationID: correlation})
			if !errors.Is(err, authentication.ErrSocialLinkDenied) {
				t.Fatalf("finalize error = %v, want denied", err)
			}
			var rows int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM external_identities WHERE application_instance_id=$1 AND provider='discord' AND provider_subject=$2`, int64(app.InternalID), "subject-"+tc.name).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != 0 {
				t.Fatalf("identity rows after %s session = %d", tc.name, rows)
			}
		})
	}
}

func TestSocialLinkAuditFailureRollsBackNewExternalIdentity(t *testing.T) {
	databaseURL := isolatedDatabaseURL(t, "beebox_social_link_audit_rollback")
	pool := openPool(t, databaseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	publicID, createdAt := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	store := New(pool)
	attempt := createConsumedSocialLinkAttempt(t, ctx, store, app.InternalID, user.InternalID, publicID, createdAt, authentication.ProviderSlack, "audit-rollback")

	if _, err := db.ExecContext(ctx, `
		CREATE FUNCTION reject_social_link_success_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'authentication.social.link_succeeded' THEN
				RAISE EXCEPTION 'reject social link success audit';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_social_link_success_audit_trigger
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_social_link_success_audit();`); err != nil {
		t.Fatal(err)
	}
	correlation, _ := audit.NewCorrelationID()
	err := store.FinalizeSocialLink(ctx, authentication.SocialLinkFinalize{AttemptID: attempt.AttemptID, ProviderSubject: "rollback-subject", CorrelationID: correlation})
	if !errors.Is(err, authentication.ErrSocialLinkPersistence) {
		t.Fatalf("finalize error = %v, want persistence failure", err)
	}
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM external_identities WHERE application_instance_id=$1 AND provider='slack' AND provider_subject='rollback-subject'`, int64(app.InternalID)).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("external identity survived failed audit: rows=%d", rows)
	}
}

func insertSocialLinkSession(t *testing.T, ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, appID applicationinstance.InternalID, userID identity.InternalID, age time.Duration) (string, time.Time) {
	t.Helper()
	publicID, err := session.NewPublicID()
	if err != nil {
		t.Fatal(err)
	}
	var createdAt time.Time
	if err := db.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,created_at,last_seen_at,idle_expires_at,expires_at)
		VALUES($1,$2,$3,CURRENT_TIMESTAMP-$4::interval,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '30 minutes',CURRENT_TIMESTAMP+INTERVAL '1 hour')
		RETURNING created_at`, publicID, int64(appID), int64(userID), age.String()).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	return publicID, createdAt.UTC()
}

func createConsumedSocialLinkAttempt(t *testing.T, ctx context.Context, store *Store, appID applicationinstance.InternalID, userID identity.InternalID, sessionPublicID string, recentAuthAt time.Time, provider authentication.Provider, stateMaterial string) authentication.SocialLinkAttemptSnapshot {
	t.Helper()
	stateHash := cryptosha256.Sum256([]byte(stateMaterial))
	createdAt := time.Now().UTC()
	expiresAt := recentAuthAt.Add(authentication.SocialLinkFreshness)
	if max := createdAt.Add(authentication.SocialLinkAttemptTTL); max.Before(expiresAt) {
		expiresAt = max
	}
	if err := store.CreateSocialLinkAttempt(ctx, authentication.SocialLinkAttemptWrite{
		ApplicationInstanceID: appID,
		UserID:                userID,
		SessionPublicID:       sessionPublicID,
		Provider:              provider,
		CanonicalRedirectURL:  "https://app.example.test/link-complete",
		StateHash:             stateHash,
		RecentAuthAt:          recentAuthAt,
		CreatedAt:             createdAt,
		ExpiresAt:             expiresAt,
	}); err != nil {
		t.Fatalf("CreateSocialLinkAttempt() error = %v", err)
	}
	snapshot, err := store.ConsumeSocialLinkAttempt(ctx, stateHash, provider)
	if err != nil {
		t.Fatalf("ConsumeSocialLinkAttempt() error = %v", err)
	}
	return snapshot
}
