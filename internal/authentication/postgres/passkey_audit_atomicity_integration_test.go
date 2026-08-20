//go:build integration

package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
)

func TestPasskeyRegistrationAuditFailureRollsBackCredential(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "passkey-audit-register")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	store := New(pool)
	challenge := sha256.Sum256([]byte("audit-register"))
	attemptID, err := store.CreatePasskeyAttempt(ctx, authentication.PasskeyAttemptWrite{
		ApplicationInstanceID: app.InternalID, UserID: user.InternalID, SessionPublicID: sessionID,
		Purpose: "registration", Origin: "https://app.example", RPID: "app.example",
		SessionData: json.RawMessage(`{"challenge":"audit"}`), ChallengeHash: challenge,
		CreatedAt: created.Add(time.Minute), ExpiresAt: created.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := store.ConsumePasskeyAttempt(ctx, app.InternalID, attemptID, "registration", "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	forcePasskeyAuditFailure(t, ctx, db)
	correlation, _ := audit.NewCorrelationID()
	_, err = store.CreatePasskeyCredential(ctx, attempt, authentication.PasskeyCredential{
		RPID: "app.example", CredentialID: []byte("audit-register-credential"), CredentialJSON: json.RawMessage(`{"id":"must-not-commit"}`),
	}, correlation)
	if !errors.Is(err, authentication.ErrPasskeyPersistence) {
		t.Fatalf("registration audit failure=%v", err)
	}
	var credentials int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(user.InternalID)).Scan(&credentials); err != nil || credentials != 0 {
		t.Fatalf("credentials=%d err=%v", credentials, err)
	}
}

func TestPasskeyAuthenticationAuditFailureRollsBackSessionAndCredentialState(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "passkey-audit-auth")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	oldJSON := `{"id":"credential","authenticator":{"signCount":1}}`
	credentialID := []byte("audit-auth-credential")
	if _, err := db.ExecContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json) VALUES($1,$2,'app.example',$3,$4::jsonb)`, int64(app.InternalID), int64(user.InternalID), credentialID, oldJSON); err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	now := time.Now().UTC()
	challenge := sha256.Sum256([]byte("audit-auth"))
	attemptID, err := store.CreatePasskeyAttempt(ctx, authentication.PasskeyAttemptWrite{
		ApplicationInstanceID: app.InternalID, Purpose: "authentication", Origin: "https://app.example", RPID: "app.example",
		SessionData: json.RawMessage(`{"challenge":"audit"}`), ChallengeHash: challenge,
		CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumePasskeyAttempt(ctx, app.InternalID, attemptID, "authentication", "https://app.example"); err != nil {
		t.Fatal(err)
	}
	forcePasskeyAuditFailure(t, ctx, db)
	correlation, _ := audit.NewCorrelationID()
	refresh := sha256.Sum256([]byte("refresh-verifier"))
	newJSON := json.RawMessage(`{"id":"credential","authenticator":{"signCount":2}}`)
	_, err = store.FinalizePasskeyAuthentication(ctx, authentication.PasskeyAuthFinalize{
		AttemptPublicID: attemptID, UserID: user.InternalID,
		Credential: authentication.PasskeyCredential{RPID: "app.example", CredentialID: credentialID, CredentialJSON: newJSON},
		SessionPublicID: "ses_123e4567-e89b-42d3-a456-426614174099", RefreshVerifier: refresh,
		IdleExpiresAt: now.Add(time.Hour), ExpiresAt: now.Add(24 * time.Hour), CorrelationID: correlation,
	})
	if !errors.Is(err, authentication.ErrPasskeyPersistence) {
		t.Fatalf("authentication audit failure=%v", err)
	}
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE public_id='ses_123e4567-e89b-42d3-a456-426614174099'`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions=%d err=%v", sessions, err)
	}
	var signCount int
	if err := db.QueryRowContext(ctx, `SELECT (credential_json->'authenticator'->>'signCount')::int FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2 AND credential_id=$3`, int64(app.InternalID), int64(user.InternalID), credentialID).Scan(&signCount); err != nil || signCount != 1 {
		t.Fatalf("signCount=%d err=%v", signCount, err)
	}
}

func TestPasskeyRemovalAuditFailureRollsBackDeletion(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "passkey-audit-remove")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	if _, err := db.ExecContext(ctx, `INSERT INTO password_credentials(application_instance_id,user_id,password_hash) VALUES($1,$2,'synthetic-hash')`, int64(app.InternalID), int64(user.InternalID)); err != nil {
		t.Fatal(err)
	}
	var publicID string
	if err := db.QueryRowContext(ctx, `INSERT INTO passkey_credentials(application_instance_id,user_id,rp_id,credential_id,credential_json) VALUES($1,$2,'app.example',$3,'{"id":"audit-remove"}'::jsonb) RETURNING public_id`, int64(app.InternalID), int64(user.InternalID), []byte("audit-remove-credential")).Scan(&publicID); err != nil {
		t.Fatal(err)
	}
	forcePasskeyAuditFailure(t, ctx, db)
	correlation, _ := audit.NewCorrelationID()
	current := authentication.PasskeySession{ApplicationInstanceID: app.InternalID, ApplicationPublicID: app.PublicID, UserID: user.InternalID, UserPublicID: user.PublicID, SessionPublicID: sessionID, CreatedAt: created, IdleExpiresAt: created.Add(time.Hour), ExpiresAt: created.Add(2 * time.Hour)}
	err := New(pool).RemovePasskeyCredential(ctx, current, publicID, correlation)
	if !errors.Is(err, authentication.ErrPasskeyPersistence) {
		t.Fatalf("removal audit failure=%v", err)
	}
	var credentials int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM passkey_credentials WHERE public_id=$1`, publicID).Scan(&credentials); err != nil || credentials != 1 {
		t.Fatalf("credential rows=%d err=%v", credentials, err)
	}
}

func TestPasskeyAuditStoresOnlyOpaqueResourceReference(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "passkey-audit-minimal")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	store := New(pool)
	challenge := sha256.Sum256([]byte("secret-challenge-never-audit"))
	attemptID, err := store.CreatePasskeyAttempt(ctx, authentication.PasskeyAttemptWrite{
		ApplicationInstanceID: app.InternalID, UserID: user.InternalID, SessionPublicID: sessionID,
		Purpose: "registration", Origin: "https://app.example", RPID: "app.example",
		SessionData: json.RawMessage(`{"challenge":"raw-browser-data-never-audit"}`), ChallengeHash: challenge,
		CreatedAt: created.Add(time.Minute), ExpiresAt: created.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := store.ConsumePasskeyAttempt(ctx, app.InternalID, attemptID, "registration", "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	correlation, _ := audit.NewCorrelationID()
	credential, err := store.CreatePasskeyCredential(ctx, attempt, authentication.PasskeyCredential{
		RPID: "app.example", CredentialID: []byte("credential-secret-never-audit"), CredentialJSON: json.RawMessage(`{"publicKey":"credential-public-material-never-audit"}`),
	}, correlation)
	if err != nil {
		t.Fatal(err)
	}
	var resource, action, source string
	if err := db.QueryRowContext(ctx, `SELECT resource_reference,action,source FROM audit_events WHERE application_instance_id=$1 AND action=$2`, int64(app.InternalID), audit.ActionPasskeyRegistered).Scan(&resource, &action, &source); err != nil {
		t.Fatal(err)
	}
	if resource != "passkey:"+credential.PublicID || action != audit.ActionPasskeyRegistered || source != audit.SourceInternalPasskey {
		t.Fatalf("audit resource=%q action=%q source=%q", resource, action, source)
	}
	for _, forbidden := range []string{"credential-secret-never-audit", "credential-public-material-never-audit", "raw-browser-data-never-audit", "secret-challenge-never-audit"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND row_to_json(audit_events)::text LIKE '%' || $2 || '%'`, int64(app.InternalID), forbidden).Scan(&count); err != nil || count != 0 {
			t.Fatalf("audit leaked %q count=%d err=%v", forbidden, count, err)
		}
	}
}

func forcePasskeyAuditFailure(t *testing.T, ctx interface{ Done() <-chan struct{} }, db interface {
	ExecContext(interface{ Done() <-chan struct{} }, string, ...any) (interface{}, error)
}) {
	// This declaration is intentionally replaced below by the concrete helper;
	// keeping the helper local to this integration file avoids production hooks.
}
