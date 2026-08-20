//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestSocialUnlinkTreatsOnlySamePrincipalPasskeyAsUsableMethod(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "social-passkey-method")
	apps := applicationpostgres.New(pool)
	app, _ := apps.Create(ctx)
	otherApp, _ := apps.Create(ctx)
	identities := identitypostgres.New(pool)
	user, _ := identities.Create(ctx, app.InternalID)
	otherUser, _ := identities.Create(ctx, otherApp.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	target := insertExternalIdentity(t, ctx, db, app.InternalID, user.InternalID, "github", "target", time.Now().UTC())

	if _, err := db.ExecContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json) VALUES($1,$2,'other.example',$3,$4::jsonb)`, int64(otherApp.InternalID), int64(otherUser.InternalID), []byte("cross-app-passkey"), string(json.RawMessage(`{"id":"cross-app-passkey"}`))); err != nil {
		t.Fatal(err)
	}
	correlation, _ := audit.NewCorrelationID()
	current := socialAccountSession(app, user.InternalID, sessionID, created)
	if err := New(pool).UnlinkSocialAccount(ctx, current, target, authentication.SocialMethodAvailability{}, correlation); !errors.Is(err, authentication.ErrLastAuthenticationMethod) {
		t.Fatalf("cross-app passkey counted as usable method: %v", err)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json) VALUES($1,$2,'app.example',$3,$4::jsonb)`, int64(app.InternalID), int64(user.InternalID), []byte("same-user-passkey"), string(json.RawMessage(`{"id":"same-user-passkey"}`))); err != nil {
		t.Fatal(err)
	}
	correlation, _ = audit.NewCorrelationID()
	if err := New(pool).UnlinkSocialAccount(ctx, current, target, authentication.SocialMethodAvailability{}, correlation); err != nil {
		t.Fatalf("same-principal passkey did not allow social unlink: %v", err)
	}
}

func TestPasskeyRemovalAllowsPasswordVerifiedEmailOrConfiguredSocial(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, context.Context, *Store, authentication.PasskeySession, string)
	}{
		{
			name: "password with verified email",
			setup: func(t *testing.T, ctx context.Context, store *Store, current authentication.PasskeySession, _ string) {
				db := store.pool.OpenSQLDB()
				defer db.Close()
				addVerifiedEmail(t, ctx, db, current.ApplicationInstanceID, int64(current.UserID))
				if _, err := db.ExecContext(ctx, `INSERT INTO password_credentials(application_instance_id,user_id,password_hash) VALUES($1,$2,'synthetic-hash')`, int64(current.ApplicationInstanceID), int64(current.UserID)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "configured social identity",
			setup: func(t *testing.T, ctx context.Context, store *Store, current authentication.PasskeySession, _ string) {
				db := store.pool.OpenSQLDB()
				defer db.Close()
				insertExternalIdentity(t, ctx, db, current.ApplicationInstanceID, current.UserID, "github", "fallback", time.Now().UTC())
				store.SetMethodAvailability(authentication.SocialMethodAvailability{Social: socialAvailabilityRegistry{app: current.ApplicationPublicID, providers: map[authentication.Provider]bool{authentication.ProviderGitHub: true}}})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, ctx := socialAccountManagementDatabase(t, "passkey-remove-method")
			app, _ := applicationpostgres.New(pool).Create(ctx)
			user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
			db := pool.OpenSQLDB()
			sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
			var publicID string
			if err := db.QueryRowContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json) VALUES($1,$2,'app.example',$3,'{"id":"credential"}'::jsonb) RETURNING public_id`, int64(app.InternalID), int64(user.InternalID), []byte("credential")).Scan(&publicID); err != nil {
				db.Close()
				t.Fatal(err)
			}
			db.Close()
			current := authentication.PasskeySession{ApplicationInstanceID: app.InternalID, ApplicationPublicID: app.PublicID, UserID: user.InternalID, UserPublicID: user.PublicID, SessionPublicID: sessionID, CreatedAt: created, IdleExpiresAt: created.Add(time.Hour), ExpiresAt: created.Add(2 * time.Hour)}
			store := New(pool)
			tc.setup(t, ctx, store, current, publicID)
			correlation, _ := audit.NewCorrelationID()
			if err := store.RemovePasskeyCredential(ctx, current, publicID, correlation); err != nil {
				t.Fatalf("remove with alternate method: %v", err)
			}
		})
	}
}
