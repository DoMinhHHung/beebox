//go:build integration

package postgres

import (
	"context"
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

type phoneTestDelivery struct {
	mu      sync.Mutex
	signups []string
	signins []string
}

func (d *phoneTestDelivery) DeliverPhoneSignupCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signups = append(d.signups, code)
	return nil
}

func (d *phoneTestDelivery) DeliverPhoneSignInCode(_ context.Context, _ string, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signins = append(d.signins, code)
	return nil
}

func (d *phoneTestDelivery) signupCodes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.signups...)
}

func (d *phoneTestDelivery) signinCodes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.signins...)
}

func TestPhoneSignupCreatesNothingUntilProofThenCommitsPrincipalSessionAndAudit(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_phone_signup_success")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	delivery := &phoneTestDelivery{}
	issuer := authentication.NewPhoneSignupService(store, delivery)
	phone := "+84901234567"
	correlation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, correlation); err != nil {
		t.Fatalf("signup issue error = %v", err)
	}
	codes := delivery.signupCodes()
	if len(codes) != 1 || len(codes[0]) != 6 {
		t.Fatalf("signup codes = %v", codes)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var users, phones, rawPhoneColumns, fingerprintBytes, generation, ttlSeconds int
	var encoded string
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM phone_identifiers WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&phones); err != nil {
		t.Fatal(err)
	}
	if users != 0 || phones != 0 {
		t.Fatalf("pre-proof state users=%d phones=%d, want 0/0", users, phones)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='phone_signup_challenges' AND column_name IN ('phone','phone_e164')`).Scan(&rawPhoneColumns); err != nil {
		t.Fatal(err)
	}
	if rawPhoneColumns != 0 {
		t.Fatalf("signup challenge has %d raw-phone columns", rawPhoneColumns)
	}
	if err := db.QueryRowContext(ctx, `SELECT octet_length(phone_fingerprint),code_hash,generation,EXTRACT(EPOCH FROM (expires_at-last_issued_at))::int FROM phone_signup_challenges WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&fingerprintBytes, &encoded, &generation, &ttlSeconds); err != nil {
		t.Fatal(err)
	}
	if fingerprintBytes != 32 || encoded == "" || encoded == codes[0] || generation != 1 || ttlSeconds != 600 {
		t.Fatalf("challenge fingerprint=%d generation=%d ttl=%d hash=%q", fingerprintBytes, generation, ttlSeconds, encoded)
	}

	confirmer := session.NewPhoneSignupService(store, testEmailOTPKeyRing(t))
	confirmCorrelation, _ := audit.NewCorrelationID()
	pair, err := confirmer.Confirm(ctx, app.InternalID, phone, codes[0], confirmCorrelation)
	if err != nil {
		t.Fatalf("signup confirm error = %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || !session.ValidPublicID(pair.SessionID) {
		t.Fatalf("token pair incomplete: %+v", pair)
	}

	var verifiedPhones, sessions, refreshRows, audits, passwords int
	var consumed, cleared bool
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM phone_identifiers WHERE application_instance_id=$1 AND phone_e164=$2 AND verified_at IS NOT NULL`, int64(app.InternalID), phone).Scan(&verifiedPhones); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM session_refresh_credentials r JOIN sessions s ON s.id=r.session_id WHERE s.application_instance_id=$1 AND octet_length(r.verifier_hash)=32`, int64(app.InternalID)).Scan(&refreshRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND action='authentication.phone_signup.confirm' AND outcome='success'`, int64(app.InternalID)).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL,code_hash IS NULL FROM phone_signup_challenges WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&consumed, &cleared); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM password_credentials p JOIN users u ON u.id=p.user_id AND u.application_instance_id=p.application_instance_id WHERE u.application_instance_id=$1`, int64(app.InternalID)).Scan(&passwords); err != nil {
		t.Fatal(err)
	}
	if users != 1 || verifiedPhones != 1 || sessions != 1 || refreshRows != 1 || audits != 1 || !consumed || !cleared || passwords != 0 {
		t.Fatalf("committed state users=%d phones=%d sessions=%d refresh=%d audits=%d consumed=%v cleared=%v passwords=%d", users, verifiedPhones, sessions, refreshRows, audits, consumed, cleared, passwords)
	}

	replayCorrelation, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, phone, codes[0], replayCorrelation); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("signup replay error = %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if users != 1 || sessions != 1 {
		t.Fatalf("replay changed state users=%d sessions=%d", users, sessions)
	}
}

func TestPhoneSignupConcurrencyAndExistingOwnershipAreOnePrincipalAndNoResend(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_phone_signup_concurrency")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	delivery := &phoneTestDelivery{}
	issuer := authentication.NewPhoneSignupService(store, delivery)
	phone := "+15551234567"
	correlation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, correlation); err != nil {
		t.Fatal(err)
	}
	code := delivery.signupCodes()[0]
	confirmer := session.NewPhoneSignupService(store, testEmailOTPKeyRing(t))
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, _ := audit.NewCorrelationID()
			_, err := confirmer.Confirm(ctx, app.InternalID, phone, code, c)
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
			continue
		}
		if !errors.Is(err, session.ErrInvalidCredentials) {
			t.Fatalf("concurrent signup error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent signup successes = %d, want 1", successes)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	var users, phones, sessions int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&users)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM phone_identifiers WHERE application_instance_id=$1 AND phone_e164=$2 AND verified_at IS NOT NULL`, int64(app.InternalID), phone).Scan(&phones)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&sessions)
	if users != 1 || phones != 1 || sessions != 1 {
		t.Fatalf("concurrent state users=%d phones=%d sessions=%d", users, phones, sessions)
	}
	before := len(delivery.signupCodes())
	c, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, c); err != nil {
		t.Fatalf("owned phone issue leaked error = %v", err)
	}
	if got := len(delivery.signupCodes()); got != before {
		t.Fatalf("owned phone sent signup SMS: before=%d after=%d", before, got)
	}
}

func TestPhoneSignupAttemptsRotationWindowAndCrossApplicationIndependence(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_phone_signup_limits")
	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	delivery := &phoneTestDelivery{}
	issuer := authentication.NewPhoneSignupService(store, delivery)
	phone := "+447700900123"
	c, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, appA.InternalID, phone, c); err != nil {
		t.Fatal(err)
	}
	first := delivery.signupCodes()[0]
	c, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, appA.InternalID, phone, c); err != nil {
		t.Fatal(err)
	}
	if got := len(delivery.signupCodes()); got != 1 {
		t.Fatalf("cooldown deliveries = %d", got)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	for issue := 2; issue <= authentication.PhoneOTPMaxIssues; issue++ {
		if _, err := db.ExecContext(ctx, `UPDATE phone_signup_challenges SET issue_window_started_at=LEAST(issue_window_started_at,CURRENT_TIMESTAMP-INTERVAL '61 seconds'),last_issued_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds' WHERE application_instance_id=$1`, int64(appA.InternalID)); err != nil {
			t.Fatal(err)
		}
		c, _ = audit.NewCorrelationID()
		if err := issuer.RequestWithCorrelation(ctx, appA.InternalID, phone, c); err != nil {
			t.Fatal(err)
		}
	}
	codes := delivery.signupCodes()
	if len(codes) != authentication.PhoneOTPMaxIssues || codes[1] == first {
		t.Fatalf("rotation deliveries=%d codes=%v", len(codes), codes)
	}
	if _, err := db.ExecContext(ctx, `UPDATE phone_signup_challenges SET issue_window_started_at=LEAST(issue_window_started_at,CURRENT_TIMESTAMP-INTERVAL '61 seconds'),last_issued_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds' WHERE application_instance_id=$1`, int64(appA.InternalID)); err != nil {
		t.Fatal(err)
	}
	c, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, appA.InternalID, phone, c); err != nil {
		t.Fatal(err)
	}
	if got := len(delivery.signupCodes()); got != authentication.PhoneOTPMaxIssues {
		t.Fatalf("fourth issue delivered: %d", got)
	}

	c, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, appB.InternalID, phone, c); err != nil {
		t.Fatal(err)
	}
	appBCode := delivery.signupCodes()[len(delivery.signupCodes())-1]
	confirmer := session.NewPhoneSignupService(store, testEmailOTPKeyRing(t))
	confirmB, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, appB.InternalID, phone, appBCode, confirmB); err != nil {
		t.Fatalf("cross-app independent signup error = %v", err)
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM phone_signup_challenges WHERE application_instance_id=$1`, int64(appA.InternalID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM public_auth_rate_limits WHERE application_instance_id=$1 AND operation LIKE 'phone_signup_%'`, int64(appA.InternalID)); err != nil {
		t.Fatal(err)
	}
	c, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, appA.InternalID, phone, c); err != nil {
		t.Fatal(err)
	}
	correct := delivery.signupCodes()[len(delivery.signupCodes())-1]
	wrong := "000000"
	if wrong == correct {
		wrong = "999999"
	}
	for i := 0; i < authentication.PhoneOTPMaxAttempts; i++ {
		attempt, _ := audit.NewCorrelationID()
		if _, err := confirmer.Confirm(ctx, appA.InternalID, phone, wrong, attempt); !errors.Is(err, session.ErrInvalidCredentials) {
			t.Fatalf("wrong signup attempt %d error = %v", i+1, err)
		}
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM public_auth_rate_limits WHERE application_instance_id=$1 AND operation IN ('phone_signup_confirm_global','phone_signup_confirm_identifier')`, int64(appA.InternalID)); err != nil {
		t.Fatal(err)
	}
	attempt, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, appA.InternalID, phone, correct, attempt); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("correct code after exhaustion error = %v", err)
	}
}

func TestPhoneOTPSignInVerifiedOnlyReplayCrossAppAndConcurrency(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_phone_otp_signin")
	apps := applicationpostgres.New(pool)
	appA, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := apps.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	phone := "+33612345678"
	delivery := &phoneTestDelivery{}
	signupIssuer := authentication.NewPhoneSignupService(store, delivery)
	c, _ := audit.NewCorrelationID()
	if err := signupIssuer.RequestWithCorrelation(ctx, appA.InternalID, phone, c); err != nil {
		t.Fatal(err)
	}
	signupConfirmer := session.NewPhoneSignupService(store, testEmailOTPKeyRing(t))
	c, _ = audit.NewCorrelationID()
	if _, err := signupConfirmer.Confirm(ctx, appA.InternalID, phone, delivery.signupCodes()[0], c); err != nil {
		t.Fatal(err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var userB int64
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, int64(appB.InternalID)).Scan(&userB); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164) VALUES($1,$2,$3)`, int64(appB.InternalID), userB, phone); err != nil {
		t.Fatal(err)
	}
	signinIssuer := authentication.NewPhoneOTPService(store, delivery)
	for _, tc := range []struct {
		app   int64
		phone string
	}{{int64(appB.InternalID), phone}, {int64(appA.InternalID), "+33699999999"}} {
		issue, _ := audit.NewCorrelationID()
		if err := signinIssuer.RequestWithCorrelation(ctx, applicationID(tc.app), tc.phone, issue); err != nil {
			t.Fatalf("generic signin issue error = %v", err)
		}
	}
	if got := len(delivery.signinCodes()); got != 0 {
		t.Fatalf("ineligible signin deliveries = %d", got)
	}

	issue, _ := audit.NewCorrelationID()
	if err := signinIssuer.RequestWithCorrelation(ctx, appA.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	code := delivery.signinCodes()[0]
	confirmer := session.NewPhoneOTPService(store, testEmailOTPKeyRing(t))
	foreign, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, appB.InternalID, phone, code, foreign); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("cross-app signin confirm error = %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			confirm, _ := audit.NewCorrelationID()
			_, err := confirmer.Confirm(ctx, appA.InternalID, phone, code, confirm)
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
			continue
		}
		if !errors.Is(err, session.ErrInvalidCredentials) {
			t.Fatalf("concurrent signin error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("signin successes = %d, want 1", successes)
	}
	var sessions, audits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(appA.InternalID)).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE application_instance_id=$1 AND action='authentication.phone_otp.confirm' AND outcome='success'`, int64(appA.InternalID)).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if sessions != 2 || audits != 1 {
		t.Fatalf("phone auth state sessions=%d (signup+signin want 2) signinAudits=%d", sessions, audits)
	}
	replay, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, appA.InternalID, phone, code, replay); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("signin replay error = %v", err)
	}
}

func applicationID(value int64) applicationinstance.InternalID {
	return applicationinstance.InternalID(value)
}
