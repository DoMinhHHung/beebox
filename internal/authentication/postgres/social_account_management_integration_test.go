//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

type socialAvailabilityRegistry struct {
	app       applicationinstance.PublicID
	providers map[authentication.Provider]bool
}

func (r socialAvailabilityRegistry) Resolve(app applicationinstance.PublicID, provider authentication.Provider) (authentication.SocialProvider, bool) {
	return nil, app == r.app && r.providers[provider]
}

func TestSocialAccountListingIsScopedBoundedAndStable(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "listing")
	appA, _ := applicationpostgres.New(pool).Create(ctx)
	appB, _ := applicationpostgres.New(pool).Create(ctx)
	identities := identitypostgres.New(pool)
	userA, _ := identities.Create(ctx, appA.InternalID)
	otherA, _ := identities.Create(ctx, appA.InternalID)
	userB, _ := identities.Create(ctx, appB.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()

	insertExternalIdentity(t, ctx, db, appA.InternalID, userA.InternalID, "github", "subject-1", time.Unix(10, 0).UTC())
	insertExternalIdentity(t, ctx, db, appA.InternalID, userA.InternalID, "google", "subject-2", time.Unix(20, 0).UTC())
	insertExternalIdentity(t, ctx, db, appA.InternalID, otherA.InternalID, "discord", "other", time.Unix(15, 0).UTC())
	insertExternalIdentity(t, ctx, db, appB.InternalID, userB.InternalID, "github", "cross-app", time.Unix(15, 0).UTC())

	store := New(pool)
	first, err := store.ListSocialAccounts(ctx, appA.InternalID, userA.InternalID, 1, nil)
	if err != nil || len(first) != 1 || first[0].Provider != authentication.ProviderGitHub || !authentication.ValidSocialLinkPublicID(first[0].PublicID) {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	cursor := &authentication.SocialAccountCursor{CreatedAt: first[0].CreatedAt, PublicID: first[0].PublicID}
	second, err := store.ListSocialAccounts(ctx, appA.InternalID, userA.InternalID, 2, cursor)
	if err != nil || len(second) != 1 || second[0].Provider != authentication.ProviderGoogle {
		t.Fatalf("second=%#v err=%v", second, err)
	}
}

func TestSocialUnlinkLastUsableMethodMatrix(t *testing.T) {
	cases := []struct {
		name          string
		setup         func(*testing.T, context.Context, *sql.DB, applicationinstance.InternalID, int64)
		emailOTP      bool
		phoneOTP      bool
		configured   []authentication.Provider
		wantLastOnly bool
	}{
		{name: "social only denied", wantLastOnly: true},
		{name: "configured second social allows", configured: []authentication.Provider{authentication.ProviderGoogle}, setup: addSecondSocial("google", "second")},
		{name: "unconfigured second social denied", setup: addSecondSocial("google", "second"), wantLastOnly: true},
		{name: "password plus verified email allows", setup: func(t *testing.T, ctx context.Context, db *sql.DB, app applicationinstance.InternalID, user int64) {
			mustExec(t, ctx, db, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,'a@example.test','a@example.test',CURRENT_TIMESTAMP)`, int64(app), user)
			mustExec(t, ctx, db, `INSERT INTO password_credentials(application_instance_id,user_id,password_hash) VALUES($1,$2,'hash')`, int64(app), user)
		}},
		{name: "password plus unverified email denied", setup: func(t *testing.T, ctx context.Context, db *sql.DB, app applicationinstance.InternalID, user int64) {
			mustExec(t, ctx, db, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email) VALUES($1,$2,'a@example.test','a@example.test')`, int64(app), user)
			mustExec(t, ctx, db, `INSERT INTO password_credentials(application_instance_id,user_id,password_hash) VALUES($1,$2,'hash')`, int64(app), user)
		}, wantLastOnly: true},
		{name: "verified email SMTP configured allows", emailOTP: true, setup: addVerifiedEmail},
		{name: "verified email SMTP disabled denied", setup: addVerifiedEmail, wantLastOnly: true},
		{name: "verified phone SMS enabled allows", phoneOTP: true, setup: addVerifiedPhone},
		{name: "verified phone SMS disabled denied", setup: addVerifiedPhone, wantLastOnly: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, ctx := socialAccountManagementDatabase(t, "matrix")
			app, _ := applicationpostgres.New(pool).Create(ctx)
			user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
			db := pool.OpenSQLDB()
			defer db.Close()
			sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
			publicID := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "target", time.Now().UTC())
			if tc.setup != nil {
				tc.setup(t, ctx, db, app.InternalID, int64(user.InternalID))
			}
			configured := make(map[authentication.Provider]bool)
			for _, p := range tc.configured {
				configured[p] = true
			}
			availability := authentication.SocialMethodAvailability{EmailOTP: tc.emailOTP, PhoneOTP: tc.phoneOTP, Social: socialAvailabilityRegistry{app: app.PublicID, providers: configured}}
			correlation, _ := audit.NewCorrelationID()
			err := New(pool).UnlinkSocialAccount(ctx, socialAccountSession(app, user.InternalID, sessionID, created), publicID, availability, correlation)
			if tc.wantLastOnly {
				if !errors.Is(err, authentication.ErrLastAuthenticationMethod) {
					t.Fatalf("error=%v want last method", err)
				}
				assertIdentityExists(t, ctx, db, publicID, true)
				var audits int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_reference=$2`, audit.ActionSocialUnlinkDenied, "social_link:"+publicID).Scan(&audits); err != nil || audits != 1 {
					t.Fatalf("denied audit=%d err=%v", audits, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unlink error=%v", err)
				}
				assertIdentityExists(t, ctx, db, publicID, false)
			}
		})
	}
}

func TestSocialUnlinkCancelsPendingSecurityStateAndIsRetrySafe(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "pending")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "target", time.Now().UTC())
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))

	state := sha256.Sum256([]byte("pending-link"))
	mustExec(t, ctx, db, `INSERT INTO social_link_attempts(application_instance_id,user_id,session_id,provider,canonical_redirect_url,state_hash,recent_auth_at,provider_pkce_ciphertext,created_at,expires_at) SELECT $1,$2,id,'github','https://app.example/link',$3,created_at,$4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '5 minutes' FROM sessions WHERE public_id=$5`, int64(app.InternalID), int64(user.InternalID), state[:], []byte("ciphertext"), sessionID)
	code := sha256.Sum256([]byte("completion"))
	mustExec(t, ctx, db, `INSERT INTO social_auth_completion_grants(application_instance_id,user_id,code_hash,client_code_challenge,expires_at) VALUES($1,$2,$3,$4,CURRENT_TIMESTAMP+INTERVAL '5 minutes')`, int64(app.InternalID), int64(user.InternalID), code[:], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	correlation, _ := audit.NewCorrelationID()
	current := socialAccountSession(app, user.InternalID, sessionID, created)
	store := New(pool)
	if err := store.UnlinkSocialAccount(ctx, current, target, authentication.SocialMethodAvailability{EmailOTP: true}, correlation); err != nil {
		t.Fatal(err)
	}
	if err := store.UnlinkSocialAccount(ctx, current, target, authentication.SocialMethodAvailability{EmailOTP: true}, correlation); err != nil {
		t.Fatalf("retry error=%v", err)
	}
	var canceled sql.NullTime
	var ciphertext []byte
	if err := db.QueryRowContext(ctx, `SELECT canceled_at,provider_pkce_ciphertext FROM social_link_attempts WHERE state_hash=$1`, state[:]).Scan(&canceled, &ciphertext); err != nil || !canceled.Valid || len(ciphertext) != 0 {
		t.Fatalf("canceled=%v ciphertext=%x err=%v", canceled, ciphertext, err)
	}
	var consumed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT consumed_at FROM social_auth_completion_grants WHERE code_hash=$1`, code[:]).Scan(&consumed); err != nil || !consumed.Valid {
		t.Fatalf("completion consumed=%v err=%v", consumed, err)
	}
	if _, err := store.ConsumeSocialLinkAttempt(ctx, state, authentication.ProviderGitHub); !errors.Is(err, authentication.ErrSocialLinkInvalidState) {
		t.Fatalf("canceled state consume error=%v", err)
	}
	var successAudits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_reference=$2`, audit.ActionSocialUnlinkSucceeded, "social_link:"+target).Scan(&successAudits); err != nil || successAudits != 1 {
		t.Fatalf("success audits=%d err=%v", successAudits, err)
	}
}

func TestConcurrentUnlinkCannotRemoveLastTwoSocialMethods(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "concurrent-unlink")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	github := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "a", time.Now().UTC())
	google := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "google", "b", time.Now().UTC().Add(time.Second))
	availability := authentication.SocialMethodAvailability{Social: socialAvailabilityRegistry{app: app.PublicID, providers: map[authentication.Provider]bool{authentication.ProviderGitHub: true, authentication.ProviderGoogle: true}}}
	current := socialAccountSession(app, user.InternalID, sessionID, created)
	store := New(pool)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{github, google} {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			correlation, _ := audit.NewCorrelationID()
			errs <- store.UnlinkSocialAccount(ctx, current, id, availability, correlation)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	var success, denied int
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, authentication.ErrLastAuthenticationMethod) {
			denied++
		} else {
			t.Fatalf("concurrent error=%v", err)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("success=%d denied=%d", success, denied)
	}
	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM external_identities WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("remaining=%d err=%v", remaining, err)
	}
}

func socialAccountManagementDatabase(t *testing.T, suffix string) (*database.Pool, context.Context) {
	t.Helper()
	pool := openPool(t, isolatedDatabaseURL(t, "beebox_social_account_"+suffix))
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

func insertExternalIdentity(t *testing.T, ctx context.Context, db *sql.DB, app applicationinstance.InternalID, user identity.InternalID, provider, subject string, created time.Time) string {
	t.Helper()
	var publicID string
	if err := db.QueryRowContext(ctx, `INSERT INTO external_identities(application_instance_id,user_id,provider,provider_subject,created_at) VALUES($1,$2,$3,$4,$5) RETURNING public_id`, int64(app), int64(user), provider, subject, created).Scan(&publicID); err != nil {
		t.Fatal(err)
	}
	return publicID
}

func socialAccountSession(app applicationinstance.Instance, user identity.InternalID, sessionID string, created time.Time) authentication.SocialAccountSession {
	return authentication.SocialAccountSession{ApplicationInstanceID: app.InternalID, ApplicationPublicID: app.PublicID, UserID: user, SessionPublicID: sessionID, CreatedAt: created, IdleExpiresAt: time.Now().UTC().Add(time.Hour), ExpiresAt: time.Now().UTC().Add(2 * time.Hour)}
}

func addSecondSocial(provider, subject string) func(*testing.T, context.Context, *sql.DB, applicationinstance.InternalID, int64) {
	return func(t *testing.T, ctx context.Context, db *sql.DB, app applicationinstance.InternalID, user int64) {
		mustExec(t, ctx, db, `INSERT INTO external_identities(application_instance_id,user_id,provider,provider_subject) VALUES($1,$2,$3,$4)`, int64(app), user, provider, subject)
	}
}

func addVerifiedEmail(t *testing.T, ctx context.Context, db *sql.DB, app applicationinstance.InternalID, user int64) {
	mustExec(t, ctx, db, `INSERT INTO email_identifiers(application_instance_id,user_id,email_address,normalized_email,verified_at) VALUES($1,$2,'a@example.test','a@example.test',CURRENT_TIMESTAMP)`, int64(app), user)
}

func addVerifiedPhone(t *testing.T, ctx context.Context, db *sql.DB, app applicationinstance.InternalID, user int64) {
	mustExec(t, ctx, db, `INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at) VALUES($1,$2,'+84901234567',CURRENT_TIMESTAMP)`, int64(app), user)
}

func mustExec(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func assertIdentityExists(t *testing.T, ctx context.Context, db *sql.DB, publicID string, want bool) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM external_identities WHERE public_id=$1`, publicID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if (count == 1) != want {
		t.Fatalf("identity %s count=%d want=%v", publicID, count, want)
	}
}
