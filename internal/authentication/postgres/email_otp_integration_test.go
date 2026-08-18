//go:build integration

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

type otpDelivery struct {
	mu    sync.Mutex
	codes []string
}

func (d *otpDelivery) DeliverSignInCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.codes = append(d.codes, code)
	return nil
}

func (d *otpDelivery) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.codes...)
}

func TestEmailOTPSignInVerifiedUserWithoutPasswordCreatesOneSession(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_email_otp_success")
	app, email, _, _, store := createVerifiedResetUser(t, ctx, pool)
	userID := resetUserID(t, ctx, pool, app.InternalID, email)
	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, `DELETE FROM password_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(userID)); err != nil {
		db.Close()
		t.Fatalf("delete password credential error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db error = %v", err)
	}

	delivery := &otpDelivery{}
	issuer := authentication.NewEmailOTPService(store, delivery)
	issueCorrelation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, email, issueCorrelation); err != nil {
		t.Fatalf("issue error = %v", err)
	}
	codes := delivery.snapshot()
	if len(codes) != 1 || len(codes[0]) != 6 {
		t.Fatalf("delivered codes = %v", codes)
	}

	db = pool.OpenSQLDB()
	var encoded string
	var generation int64
	var ttlSeconds int
	if err := db.QueryRowContext(ctx, `
		SELECT c.code_hash,c.generation,EXTRACT(EPOCH FROM (c.expires_at-c.last_issued_at))::int
		FROM email_otp_signin_challenges c
		JOIN email_identifiers e ON e.application_instance_id=c.application_instance_id AND e.id=c.email_identifier_id
		WHERE e.application_instance_id=$1 AND e.user_id=$2`, int64(app.InternalID), int64(userID)).Scan(&encoded, &generation, &ttlSeconds); err != nil {
		db.Close()
		t.Fatalf("query challenge error = %v", err)
	}
	if encoded == codes[0] || encoded == "" || generation != 1 || ttlSeconds != 600 {
		db.Close()
		t.Fatalf("challenge persistence leaked/invalid: generation=%d ttl=%d hash=%q", generation, ttlSeconds, encoded)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db error = %v", err)
	}

	confirmer := session.NewEmailOTPService(store, testEmailOTPKeyRing(t))
	confirmCorrelation, _ := audit.NewCorrelationID()
	pair, err := confirmer.Confirm(ctx, app.InternalID, email, codes[0], confirmCorrelation)
	if err != nil {
		t.Fatalf("confirm error = %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || !session.ValidPublicID(pair.SessionID) {
		t.Fatalf("token pair incomplete: %+v", pair)
	}

	db = pool.OpenSQLDB()
	defer db.Close()
	var sessions, refreshRows, successAudits int
	var consumed, cleared bool
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1 AND user_id=$2`, int64(app.InternalID), int64(userID)).Scan(&sessions); err != nil {
		t.Fatalf("count sessions error = %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM session_refresh_credentials r JOIN sessions s ON s.id=r.session_id WHERE s.application_instance_id=$1 AND s.user_id=$2 AND octet_length(r.verifier_hash)=32`, int64(app.InternalID), int64(userID)).Scan(&refreshRows); err != nil {
		t.Fatalf("count refresh rows error = %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL, code_hash IS NULL FROM email_otp_signin_challenges c JOIN email_identifiers e ON e.application_instance_id=c.application_instance_id AND e.id=c.email_identifier_id WHERE e.application_instance_id=$1 AND e.user_id=$2`, int64(app.InternalID), int64(userID)).Scan(&consumed, &cleared); err != nil {
		t.Fatalf("query consumed state error = %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND subject_user_id=$2 AND action='authentication.email_otp.confirm' AND outcome='success'`, int64(app.InternalID), int64(userID)).Scan(&successAudits); err != nil {
		t.Fatalf("count OTP audit error = %v", err)
	}
	if sessions != 1 || refreshRows != 1 || !consumed || !cleared || successAudits != 1 {
		t.Fatalf("atomic result sessions=%d refresh=%d consumed=%v cleared=%v audits=%d", sessions, refreshRows, consumed, cleared, successAudits)
	}

	replayCorrelation, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, email, codes[0], replayCorrelation); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestEmailOTPIssueIsGenericForUnknownUnverifiedAndCooldown(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_email_otp_issue_generic")
	verifiedApp, email, _, _, store := createVerifiedResetUser(t, ctx, pool)
	unverifiedApp, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unverifiedDelivery := &resetDelivery{}
	signup := authentication.NewPublicSignupService(store, unverifiedDelivery)
	if err := signup.SignUp(ctx, unverifiedApp.InternalID, "pending@example.test", "correct horse battery staple", "otp-unverified"); err != nil {
		t.Fatalf("unverified signup error = %v", err)
	}

	delivery := &otpDelivery{}
	issuer := authentication.NewEmailOTPService(store, delivery)
	for _, tc := range []struct {
		app   applicationinstance.InternalID
		email string
	}{
		{verifiedApp.InternalID, "unknown@example.test"},
		{unverifiedApp.InternalID, "pending@example.test"},
	} {
		correlation, _ := audit.NewCorrelationID()
		if err := issuer.RequestWithCorrelation(ctx, tc.app, tc.email, correlation); err != nil {
			t.Fatalf("generic issue %q error = %v", tc.email, err)
		}
	}
	if got := len(delivery.snapshot()); got != 0 {
		t.Fatalf("ineligible delivery count = %d", got)
	}
	firstCorrelation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, verifiedApp.InternalID, email, firstCorrelation); err != nil {
		t.Fatal(err)
	}
	secondCorrelation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, verifiedApp.InternalID, email, secondCorrelation); err != nil {
		t.Fatal(err)
	}
	if got := len(delivery.snapshot()); got != 1 {
		t.Fatalf("cooldown delivery count = %d, want 1", got)
	}
}

func TestEmailOTPResendRotatesGenerationAndInvalidatesOldCode(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_email_otp_rotation")
	app, email, _, _, store := createVerifiedResetUser(t, ctx, pool)
	delivery := &otpDelivery{}
	issuer := authentication.NewEmailOTPService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, email, correlation); err != nil {
		t.Fatal(err)
	}
	oldCode := delivery.snapshot()[0]
	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, `UPDATE email_otp_signin_challenges SET last_issued_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds' WHERE application_instance_id=$1`, int64(app.InternalID)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	_ = db.Close()
	correlation, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, email, correlation); err != nil {
		t.Fatal(err)
	}
	codes := delivery.snapshot()
	if len(codes) != 2 || codes[1] == oldCode {
		t.Fatalf("rotated codes = %v", codes)
	}
	confirmer := session.NewEmailOTPService(store, testEmailOTPKeyRing(t))
	oldCorrelation, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, email, oldCode, oldCorrelation); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("old code error = %v", err)
	}
	newCorrelation, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, email, codes[1], newCorrelation); err != nil {
		t.Fatalf("new code error = %v", err)
	}
}

func TestEmailOTPConcurrentRedeemCreatesAtMostOneSession(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_email_otp_concurrent")
	app, email, _, _, store := createVerifiedResetUser(t, ctx, pool)
	delivery := &otpDelivery{}
	issuer := authentication.NewEmailOTPService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, email, correlation); err != nil {
		t.Fatal(err)
	}
	code := delivery.snapshot()[0]
	confirmer := session.NewEmailOTPService(store, testEmailOTPKeyRing(t))
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, _ := audit.NewCorrelationID()
			_, err := confirmer.Confirm(ctx, app.InternalID, email, code, c)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, session.ErrInvalidCredentials) {
			t.Fatalf("unexpected concurrent error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successes = %d, want 1", successes)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("session count = %d, want 1", count)
	}
}

func TestEmailOTPWrongAppAndAttemptExhaustionFailClosed(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_email_otp_failures")
	appA, email, _, _, store := createVerifiedResetUser(t, ctx, pool)
	appB, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &otpDelivery{}
	issuer := authentication.NewEmailOTPService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, appA.InternalID, email, correlation); err != nil {
		t.Fatal(err)
	}
	code := delivery.snapshot()[0]
	confirmer := session.NewEmailOTPService(store, testEmailOTPKeyRing(t))
	foreignCorrelation, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, appB.InternalID, email, code, foreignCorrelation); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("cross-app confirmation error = %v", err)
	}
	wrong := "000000"
	if wrong == code {
		wrong = "999999"
	}
	for i := 0; i < authentication.EmailOTPMaxAttempts; i++ {
		c, _ := audit.NewCorrelationID()
		if _, err := confirmer.Confirm(ctx, appA.InternalID, email, wrong, c); !errors.Is(err, session.ErrInvalidCredentials) {
			t.Fatalf("wrong attempt %d error = %v", i+1, err)
		}
	}
	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, `DELETE FROM public_auth_rate_limits WHERE application_instance_id=$1 AND operation IN ('email_otp_confirm_global','email_otp_confirm_identifier')`, int64(appA.InternalID)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	_ = db.Close()
	c, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, appA.InternalID, email, code, c); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("correct code after attempt exhaustion error = %v", err)
	}
}

func testEmailOTPKeyRing(t *testing.T) *session.KeyRing {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := session.NewKeyRing("https://issuer.example.test", "active", private, map[string]ed25519.PublicKey{"active": public})
	if err != nil {
		t.Fatal(err)
	}
	return ring
}
