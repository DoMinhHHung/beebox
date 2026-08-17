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
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/migration"
)

type resetDelivery struct {
	mu               sync.Mutex
	verificationCode string
	resetCode        string
	resetCalls       int
	resetErr         error
}

func (d *resetDelivery) DeliverVerificationCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.verificationCode = code
	return nil
}

func (d *resetDelivery) DeliverPasswordResetCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resetCalls++
	d.resetCode = code
	return d.resetErr
}

func (d *resetDelivery) codes() (string, string, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.verificationCode, d.resetCode, d.resetCalls
}

func TestPasswordResetChangesCredentialRevokesSessionsAndRejectsReplay(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_password_reset_success")
	app, email, oldPassword, delivery, store := createVerifiedResetUser(t, ctx, pool)

	userID := resetUserID(t, ctx, pool, app.InternalID, email)
	createResetSession(t, ctx, pool, app.InternalID, userID)
	reset := authentication.NewPasswordResetService(store, delivery)
	correlationID, _ := audit.NewCorrelationID()
	if err := reset.RequestWithCorrelation(ctx, app.InternalID, email, correlationID); err != nil {
		t.Fatalf("RequestWithCorrelation() error = %v", err)
	}
	_, code, calls := delivery.codes()
	if calls != 1 || len(code) != 8 {
		t.Fatalf("reset delivery calls/code = %d/%q", calls, code)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var encoded string
	if err := db.QueryRowContext(ctx, `SELECT code_hash FROM password_reset_challenges WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(userID)).Scan(&encoded); err != nil {
		t.Fatalf("query reset hash error = %v", err)
	}
	if encoded == code || encoded == "" {
		t.Fatal("database contains plaintext or empty reset verifier")
	}
	var auditLeakCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND (action LIKE '%' || $2 || '%' OR source LIKE '%' || $2 || '%')`, int64(app.InternalID), code).Scan(&auditLeakCount); err != nil {
		t.Fatalf("query audit leak error = %v", err)
	}
	if auditLeakCount != 0 {
		t.Fatal("reset code leaked into audit")
	}

	newPassword := "new correct horse battery staple"
	confirmCorrelation, _ := audit.NewCorrelationID()
	if err := reset.ConfirmWithCorrelation(ctx, app.InternalID, email, code, newPassword, confirmCorrelation); err != nil {
		t.Fatalf("ConfirmWithCorrelation() error = %v", err)
	}
	credential, err := store.ResolvePasswordCredential(ctx, app.InternalID, userID)
	if err != nil {
		t.Fatalf("ResolvePasswordCredential() error = %v", err)
	}
	if authentication.VerifyPassword(credential.PasswordHash, []byte(oldPassword)) == nil {
		t.Fatal("old password still verifies after reset")
	}
	prepared, err := authentication.PreparePublicPassword(newPassword)
	if err != nil || authentication.VerifyPassword(credential.PasswordHash, prepared) != nil {
		t.Fatalf("new password does not verify: prepare=%v", err)
	}
	var revokedCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND user_id=$2 AND revoked_at IS NOT NULL`, int64(app.InternalID), int64(userID)).Scan(&revokedCount); err != nil {
		t.Fatalf("query revoked sessions error = %v", err)
	}
	if revokedCount != 1 {
		t.Fatalf("revoked sessions = %d, want 1", revokedCount)
	}
	var consumed bool
	var cleared bool
	if err := db.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL, code_hash IS NULL FROM password_reset_challenges WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(userID)).Scan(&consumed, &cleared); err != nil {
		t.Fatalf("query reset consume state error = %v", err)
	}
	if !consumed || !cleared {
		t.Fatal("successful reset did not consume challenge and clear verifier")
	}
	replayCorrelation, _ := audit.NewCorrelationID()
	if err := reset.ConfirmWithCorrelation(ctx, app.InternalID, email, code, "another correct horse battery staple", replayCorrelation); !errors.Is(err, authentication.ErrPasswordResetFailed) {
		t.Fatalf("reset replay error = %v", err)
	}
}

func TestPasswordResetUnknownAndUnverifiedRequestsDoNotRevealOrDeliver(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_password_reset_enumeration")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	delivery := &resetDelivery{}
	reset := authentication.NewPasswordResetService(New(pool), delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := reset.RequestWithCorrelation(ctx, app.InternalID, "unknown@example.test", correlation); err != nil {
		t.Fatalf("unknown RequestWithCorrelation() error = %v", err)
	}
	_, _, calls := delivery.codes()
	if calls != 0 {
		t.Fatalf("unknown account reset delivery calls = %d", calls)
	}
}

func TestPasswordResetWrongAttemptsExhaustBudget(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_password_reset_attempts")
	app, email, _, delivery, store := createVerifiedResetUser(t, ctx, pool)
	reset := authentication.NewPasswordResetService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := reset.RequestWithCorrelation(ctx, app.InternalID, email, correlation); err != nil {
		t.Fatalf("request reset error = %v", err)
	}
	_, code, _ := delivery.codes()
	wrong := "00000000"
	if wrong == code {
		wrong = "99999999"
	}
	for i := 0; i < authentication.PasswordResetMaxAttempts; i++ {
		attemptCorrelation, _ := audit.NewCorrelationID()
		err := reset.ConfirmWithCorrelation(ctx, app.InternalID, email, wrong, "new correct horse battery staple", attemptCorrelation)
		if !errors.Is(err, authentication.ErrPasswordResetFailed) {
			t.Fatalf("wrong reset attempt %d error = %v", i+1, err)
		}
	}
	correctCorrelation, _ := audit.NewCorrelationID()
	if err := reset.ConfirmWithCorrelation(ctx, app.InternalID, email, code, "new correct horse battery staple", correctCorrelation); !errors.Is(err, authentication.ErrPasswordResetFailed) {
		t.Fatalf("correct code after attempt exhaustion error = %v", err)
	}
}

func TestPasswordResetIsApplicationScoped(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_password_reset_cross_app")
	appA, email, _, delivery, store := createVerifiedResetUser(t, ctx, pool)
	appB, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app B) error = %v", err)
	}
	reset := authentication.NewPasswordResetService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := reset.RequestWithCorrelation(ctx, appB.InternalID, email, correlation); err != nil {
		t.Fatalf("foreign-app reset request error = %v", err)
	}
	_, _, calls := delivery.codes()
	if calls != 0 {
		t.Fatalf("foreign-app reset deliveries = %d", calls)
	}
	var count int
	db := pool.OpenSQLDB()
	defer db.Close()
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM password_reset_challenges WHERE application_instance_id=$1`, int64(appA.InternalID)).Scan(&count); err != nil {
		t.Fatalf("count app A challenges error = %v", err)
	}
	if count != 0 {
		t.Fatalf("foreign reset created app A challenge count=%d", count)
	}
}

func resetTestDatabase(t *testing.T, schema string) (*database.Pool, context.Context) {
	t.Helper()
	pool := openPool(t, isolatedDatabaseURL(t, schema))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	if err := migration.Up(ctx, pool.OpenSQLDB()); err != nil {
		t.Fatalf("migration.Up() error = %v", err)
	}
	return pool, ctx
}

func createVerifiedResetUser(t *testing.T, ctx context.Context, pool *database.Pool) (applicationinstance.Instance, string, string, *resetDelivery, *Store) {
	t.Helper()
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	delivery := &resetDelivery{}
	store := New(pool)
	signup := authentication.NewPublicSignupService(store, delivery)
	email := "reset@example.test"
	password := "correct horse battery staple"
	if err := signup.SignUp(ctx, app.InternalID, email, password, "reset-signup"); err != nil {
		t.Fatalf("SignUp() error = %v", err)
	}
	verificationCode, _, _ := delivery.codes()
	verification := authentication.NewPublicVerificationService(identitypostgres.New(pool), store, authentication.NewEmailVerificationService(store, delivery))
	if err := verification.Confirm(ctx, app.InternalID, email, verificationCode); err != nil {
		t.Fatalf("Confirm verification error = %v", err)
	}
	return app, email, password, delivery, store
}

func resetUserID(t *testing.T, ctx context.Context, pool *database.Pool, appID applicationinstance.InternalID, email string) identity.InternalID {
	t.Helper()
	identifier, err := identitypostgres.New(pool).ResolveEmailIdentifierByAddress(ctx, appID, email)
	if err != nil {
		t.Fatalf("ResolveEmailIdentifierByAddress() error = %v", err)
	}
	return identifier.UserID
}

func createResetSession(t *testing.T, ctx context.Context, pool *database.Pool, appID applicationinstance.InternalID, userID identity.InternalID) {
	t.Helper()
	db := pool.OpenSQLDB()
	defer db.Close()
	var sessionID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO sessions (public_id, application_instance_id, user_id, idle_expires_at, expires_at) VALUES ('ses_11111111-1111-4111-8111-111111111111',$1,$2,CURRENT_TIMESTAMP+INTERVAL '1 day',CURRENT_TIMESTAMP+INTERVAL '2 days') RETURNING id`, int64(appID), int64(userID)).Scan(&sessionID); err != nil {
		t.Fatalf("insert session error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO session_refresh_credentials (session_id, verifier_hash) VALUES ($1, decode(repeat('ab',32),'hex'))`, sessionID); err != nil {
		t.Fatalf("insert refresh credential error = %v", err)
	}
}

var _ = sql.ErrNoRows
