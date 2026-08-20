//go:build integration

package postgres

import (
	"context"
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

func TestPasskeyStoreCeremonyScopeReplayAndAuditAtomicity(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "passkey")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	otherApp, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identities := identitypostgres.New(pool)
	user, err := identities.Create(ctx, app.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := identities.Create(ctx, otherApp.InternalID)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, created := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	now := created.Add(time.Minute)
	store := New(pool)
	challenge := sha256.Sum256([]byte("registration-one"))
	attemptID, err := store.CreatePasskeyAttempt(ctx, authentication.PasskeyAttemptWrite{
		ApplicationInstanceID: app.InternalID, UserID: user.InternalID, SessionPublicID: sessionID,
		Purpose: "registration", Origin: "https://app.example", RPID: "app.example",
		SessionData: json.RawMessage(`{"challenge":"one"}`), ChallengeHash: challenge,
		CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create attempt: %v", err)
	}
	attempt, err := store.ConsumePasskeyAttempt(ctx, app.InternalID, attemptID, "registration", "https://app.example")
	if err != nil {
		t.Fatalf("consume attempt: %v", err)
	}
	if _, err := store.ConsumePasskeyAttempt(ctx, app.InternalID, attemptID, "registration", "https://app.example"); !errors.Is(err, authentication.ErrPasskeyInvalidAttempt) {
		t.Fatalf("replay error=%v", err)
	}
	if _, err := store.ConsumePasskeyAttempt(ctx, otherApp.InternalID, attemptID, "registration", "https://app.example"); !errors.Is(err, authentication.ErrPasskeyInvalidAttempt) {
		t.Fatalf("cross-app consume error=%v", err)
	}

	correlation, _ := audit.NewCorrelationID()
	credential := authentication.PasskeyCredential{RPID: "app.example", CredentialID: []byte("credential-one"), CredentialJSON: json.RawMessage(`{"id":"credential-one","authenticator":{"signCount":0}}`), Name: "Laptop"}
	createdCredential, err := store.CreatePasskeyCredential(ctx, attempt, credential, correlation)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if !authentication.ValidPasskeyPublicID(createdCredential.PublicID) {
		t.Fatalf("public id=%q", createdCredential.PublicID)
	}
	listed, err := store.ListPasskeyCredentials(ctx, app.InternalID, user.InternalID)
	if err != nil || len(listed) != 1 || listed[0].PublicID != createdCredential.PublicID {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	if cross, err := store.ListPasskeyCredentials(ctx, otherApp.InternalID, otherUser.InternalID); err != nil || len(cross) != 0 {
		t.Fatalf("cross-app list=%#v err=%v", cross, err)
	}

	secondChallenge := sha256.Sum256([]byte("registration-two"))
	secondID, err := store.CreatePasskeyAttempt(ctx, authentication.PasskeyAttemptWrite{
		ApplicationInstanceID: app.InternalID, UserID: user.InternalID, SessionPublicID: sessionID,
		Purpose: "registration", Origin: "https://app.example", RPID: "app.example",
		SessionData: json.RawMessage(`{"challenge":"two"}`), ChallengeHash: secondChallenge,
		CreatedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	secondAttempt, err := store.ConsumePasskeyAttempt(ctx, app.InternalID, secondID, "registration", "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	secondCorrelation, _ := audit.NewCorrelationID()
	if _, err := store.CreatePasskeyCredential(ctx, secondAttempt, credential, secondCorrelation); err == nil {
		t.Fatal("duplicate credential accepted")
	}
	var registeredAudits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND action=$2`, int64(app.InternalID), audit.ActionPasskeyRegistered).Scan(&registeredAudits); err != nil || registeredAudits != 1 {
		t.Fatalf("registered audits=%d err=%v", registeredAudits, err)
	}

	current := authentication.PasskeySession{ApplicationInstanceID: app.InternalID, ApplicationPublicID: app.PublicID, UserID: user.InternalID, UserPublicID: user.PublicID, SessionPublicID: sessionID, CreatedAt: created, IdleExpiresAt: created.Add(time.Hour), ExpiresAt: created.Add(2 * time.Hour)}
	removeCorrelation, _ := audit.NewCorrelationID()
	if err := store.RemovePasskeyCredential(ctx, current, createdCredential.PublicID, removeCorrelation); !errors.Is(err, authentication.ErrLastAuthenticationMethod) {
		t.Fatalf("last-method removal error=%v", err)
	}
	var stillPresent int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM passkey_credentials WHERE public_id=$1`, createdCredential.PublicID).Scan(&stillPresent); err != nil || stillPresent != 1 {
		t.Fatalf("still present=%d err=%v", stillPresent, err)
	}

	addVerifiedEmail(t, ctx, db, app.InternalID, int64(user.InternalID))
	store.SetMethodAvailability(authentication.SocialMethodAvailability{EmailOTP: true})
	successCorrelation, _ := audit.NewCorrelationID()
	if err := store.RemovePasskeyCredential(ctx, current, createdCredential.PublicID, successCorrelation); err != nil {
		t.Fatalf("remove with fallback: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM passkey_credentials WHERE public_id=$1`, createdCredential.PublicID).Scan(&stillPresent); err != nil || stillPresent != 0 {
		t.Fatalf("remaining=%d err=%v", stillPresent, err)
	}
	var removedAudits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND action=$2`, int64(app.InternalID), audit.ActionPasskeyRemoved).Scan(&removedAudits); err != nil || removedAudits != 1 {
		t.Fatalf("removed audits=%d err=%v", removedAudits, err)
	}
}

func TestPasskeyAttemptExpiryFailsClosed(t *testing.T) {
	pool, ctx := socialAccountManagementDatabase(t, "passkey-expiry")
	app, _ := applicationpostgres.New(pool).Create(ctx)
	user, _ := identitypostgres.New(pool).Create(ctx, app.InternalID)
	db := pool.OpenSQLDB()
	defer db.Close()
	sessionID, _ := insertSocialLinkSession(t, ctx, db, app.InternalID, user.InternalID, time.Minute)
	challenge := sha256.Sum256([]byte("expired"))
	var attemptID string
	if err := db.QueryRowContext(ctx, `INSERT INTO passkey_attempts(application_instance_id,user_id,session_public_id,purpose,origin,rp_id,session_data,challenge_hash,created_at,expires_at) VALUES($1,$2,$3,'registration','https://app.example','app.example','{}'::jsonb,$4,CURRENT_TIMESTAMP-INTERVAL '5 minutes',CURRENT_TIMESTAMP-INTERVAL '1 second') RETURNING public_id`, int64(app.InternalID), int64(user.InternalID), sessionID, challenge[:]).Scan(&attemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := New(pool).ConsumePasskeyAttempt(context.Background(), app.InternalID, attemptID, "registration", "https://app.example"); !errors.Is(err, authentication.ErrPasskeyInvalidAttempt) {
		t.Fatalf("expired consume=%v", err)
	}
}
