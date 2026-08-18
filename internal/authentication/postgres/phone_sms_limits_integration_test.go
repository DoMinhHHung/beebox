//go:build integration

package postgres

import (
	"errors"
	"testing"

	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func TestPhoneSignupResendInvalidatesOldCodeAndExpiryCreatesNoPrincipal(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_phone_signup_rotation_expiry")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	delivery := &phoneTestDelivery{}
	issuer := authentication.NewPhoneSignupService(store, delivery)
	phone := "+819012345678"
	issue, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	oldCode := delivery.signupCodes()[0]
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		UPDATE phone_signup_challenges
		SET issue_window_started_at=LEAST(issue_window_started_at,CURRENT_TIMESTAMP-INTERVAL '61 seconds'),
		    last_issued_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds',updated_at=CURRENT_TIMESTAMP
		WHERE application_instance_id=$1`, int64(app.InternalID)); err != nil {
		t.Fatal(err)
	}
	issue, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	codes := delivery.signupCodes()
	if len(codes) != 2 || codes[1] == oldCode {
		t.Fatalf("signup resend codes = %v", codes)
	}
	confirmer := session.NewPhoneSignupService(store, testEmailOTPKeyRing(t))
	oldAttempt, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, phone, oldCode, oldAttempt); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("old signup code error = %v", err)
	}
	newAttempt, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, phone, codes[1], newAttempt); err != nil {
		t.Fatalf("rotated signup code error = %v", err)
	}

	// A separate application proves expiry does not create partial identity/session state.
	expiredApp, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expiredPhone := "+819012345679"
	issue, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, expiredApp.InternalID, expiredPhone, issue); err != nil {
		t.Fatal(err)
	}
	expiredCode := delivery.signupCodes()[len(delivery.signupCodes())-1]
	if _, err := db.ExecContext(ctx, `
		UPDATE phone_signup_challenges
		SET issue_window_started_at=CURRENT_TIMESTAMP-INTERVAL '3 minutes',
		    last_issued_at=CURRENT_TIMESTAMP-INTERVAL '2 minutes',
		    expires_at=CURRENT_TIMESTAMP-INTERVAL '1 minute',updated_at=CURRENT_TIMESTAMP
		WHERE application_instance_id=$1`, int64(expiredApp.InternalID)); err != nil {
		t.Fatal(err)
	}
	expiredAttempt, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, expiredApp.InternalID, expiredPhone, expiredCode, expiredAttempt); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("expired signup confirmation error = %v", err)
	}
	var users, phones, sessions int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(expiredApp.InternalID)).Scan(&users)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM phone_identifiers WHERE application_instance_id=$1`, int64(expiredApp.InternalID)).Scan(&phones)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(expiredApp.InternalID)).Scan(&sessions)
	if users != 0 || phones != 0 || sessions != 0 {
		t.Fatalf("expired signup created state users=%d phones=%d sessions=%d", users, phones, sessions)
	}
}

func TestPhoneOTPSignInCooldownRotationWindowAttemptsAndExpiry(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_phone_otp_limits")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	var userID, phoneID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, int64(app.InternalID)).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	phone := "+61412345678"
	if err := db.QueryRowContext(ctx, `INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at) VALUES($1,$2,$3,CURRENT_TIMESTAMP) RETURNING id`, int64(app.InternalID), userID, phone).Scan(&phoneID); err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	delivery := &phoneTestDelivery{}
	issuer := authentication.NewPhoneOTPService(store, delivery)
	issue, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	first := delivery.signinCodes()[0]
	issue, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	if len(delivery.signinCodes()) != 1 {
		t.Fatalf("signin cooldown deliveries = %d", len(delivery.signinCodes()))
	}

	for allowed := 2; allowed <= authentication.PhoneOTPMaxIssues; allowed++ {
		if _, err := db.ExecContext(ctx, `
			UPDATE phone_otp_signin_challenges
			SET issue_window_started_at=LEAST(issue_window_started_at,CURRENT_TIMESTAMP-INTERVAL '61 seconds'),
			    last_issued_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds',updated_at=CURRENT_TIMESTAMP
			WHERE application_instance_id=$1 AND phone_identifier_id=$2`, int64(app.InternalID), phoneID); err != nil {
			t.Fatal(err)
		}
		issue, _ = audit.NewCorrelationID()
		if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
			t.Fatal(err)
		}
	}
	codes := delivery.signinCodes()
	if len(codes) != authentication.PhoneOTPMaxIssues || codes[1] == first {
		t.Fatalf("signin rotation codes = %v", codes)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE phone_otp_signin_challenges
		SET issue_window_started_at=LEAST(issue_window_started_at,CURRENT_TIMESTAMP-INTERVAL '61 seconds'),
		    last_issued_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds',updated_at=CURRENT_TIMESTAMP
		WHERE application_instance_id=$1 AND phone_identifier_id=$2`, int64(app.InternalID), phoneID); err != nil {
		t.Fatal(err)
	}
	issue, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	if len(delivery.signinCodes()) != authentication.PhoneOTPMaxIssues {
		t.Fatalf("fourth signin issue delivered: %d", len(delivery.signinCodes()))
	}

	confirmer := session.NewPhoneOTPService(store, testEmailOTPKeyRing(t))
	oldAttempt, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, phone, first, oldAttempt); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("old signin code error = %v", err)
	}

	// Reset issue and admission state so attempt exhaustion is isolated from the issue window.
	if _, err := db.ExecContext(ctx, `DELETE FROM phone_otp_signin_challenges WHERE application_instance_id=$1`, int64(app.InternalID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM public_auth_rate_limits WHERE application_instance_id=$1 AND operation LIKE 'phone_otp_%'`, int64(app.InternalID)); err != nil {
		t.Fatal(err)
	}
	issue, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	correct := delivery.signinCodes()[len(delivery.signinCodes())-1]
	wrong := "000000"
	if wrong == correct {
		wrong = "999999"
	}
	for attemptNumber := 0; attemptNumber < authentication.PhoneOTPMaxAttempts; attemptNumber++ {
		attempt, _ := audit.NewCorrelationID()
		if _, err := confirmer.Confirm(ctx, app.InternalID, phone, wrong, attempt); !errors.Is(err, session.ErrInvalidCredentials) {
			t.Fatalf("wrong signin attempt %d error = %v", attemptNumber+1, err)
		}
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM public_auth_rate_limits WHERE application_instance_id=$1 AND operation IN ('phone_otp_confirm_global','phone_otp_confirm_identifier')`, int64(app.InternalID)); err != nil {
		t.Fatal(err)
	}
	attempt, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, phone, correct, attempt); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("correct signin code after exhaustion error = %v", err)
	}

	// Fresh challenge then force a constraint-valid expired timestamp ordering.
	if _, err := db.ExecContext(ctx, `DELETE FROM phone_otp_signin_challenges WHERE application_instance_id=$1`, int64(app.InternalID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM public_auth_rate_limits WHERE application_instance_id=$1 AND operation LIKE 'phone_otp_%'`, int64(app.InternalID)); err != nil {
		t.Fatal(err)
	}
	issue, _ = audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	expiredCode := delivery.signinCodes()[len(delivery.signinCodes())-1]
	if _, err := db.ExecContext(ctx, `
		UPDATE phone_otp_signin_challenges
		SET issue_window_started_at=CURRENT_TIMESTAMP-INTERVAL '3 minutes',
		    last_issued_at=CURRENT_TIMESTAMP-INTERVAL '2 minutes',
		    expires_at=CURRENT_TIMESTAMP-INTERVAL '1 minute',updated_at=CURRENT_TIMESTAMP
		WHERE application_instance_id=$1 AND phone_identifier_id=$2`, int64(app.InternalID), phoneID); err != nil {
		t.Fatal(err)
	}
	expiredAttempt, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, phone, expiredCode, expiredAttempt); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("expired signin code error = %v", err)
	}
	var sessions int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("failed phone signin created %d sessions", sessions)
	}
}

func TestPhoneSignupAuditFailureRollsBackUserPhoneSessionAndChallengeConsumption(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_phone_signup_atomic_failure")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	delivery := &phoneTestDelivery{}
	issuer := authentication.NewPhoneSignupService(store, delivery)
	phone := "+498912345678"
	issue, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	code := delivery.signupCodes()[0]
	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(ctx, `
		CREATE FUNCTION fail_phone_signup_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action='authentication.phone_signup.confirm' THEN RAISE EXCEPTION 'synthetic phone signup audit failure'; END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER fail_phone_signup_audit_trigger BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_phone_signup_audit();`); err != nil {
		t.Fatal(err)
	}
	confirmer := session.NewPhoneSignupService(store, testEmailOTPKeyRing(t))
	confirm, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, phone, code, confirm); !errors.Is(err, session.ErrSessionUnavailable) {
		t.Fatalf("signup audit failure error = %v", err)
	}
	var users, phones, sessions int
	var consumed bool
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&users)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM phone_identifiers WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&phones)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&sessions)
	_ = db.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL FROM phone_signup_challenges WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&consumed)
	if users != 0 || phones != 0 || sessions != 0 || consumed {
		t.Fatalf("signup rollback users=%d phones=%d sessions=%d consumed=%v", users, phones, sessions, consumed)
	}
}

func TestPhoneOTPAuditFailureRollsBackSessionAndChallengeConsumption(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_phone_otp_atomic_failure")
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	var userID int64
	if err := db.QueryRowContext(ctx, `INSERT INTO users(application_instance_id) VALUES($1) RETURNING id`, int64(app.InternalID)).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	phone := "+33123456789"
	if _, err := db.ExecContext(ctx, `INSERT INTO phone_identifiers(application_instance_id,user_id,phone_e164,verified_at) VALUES($1,$2,$3,CURRENT_TIMESTAMP)`, int64(app.InternalID), userID, phone); err != nil {
		t.Fatal(err)
	}
	store := New(pool)
	delivery := &phoneTestDelivery{}
	issuer := authentication.NewPhoneOTPService(store, delivery)
	issue, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, phone, issue); err != nil {
		t.Fatal(err)
	}
	code := delivery.signinCodes()[0]
	if _, err := db.ExecContext(ctx, `
		CREATE FUNCTION fail_phone_otp_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action='authentication.phone_otp.confirm' AND NEW.outcome='success' THEN RAISE EXCEPTION 'synthetic phone otp audit failure'; END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER fail_phone_otp_audit_trigger BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_phone_otp_audit();`); err != nil {
		t.Fatal(err)
	}
	confirmer := session.NewPhoneOTPService(store, testEmailOTPKeyRing(t))
	confirm, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, phone, code, confirm); !errors.Is(err, session.ErrSessionUnavailable) {
		t.Fatalf("signin audit failure error = %v", err)
	}
	var sessions int
	var consumed, cleared bool
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&sessions)
	_ = db.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL,code_hash IS NULL FROM phone_otp_signin_challenges WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&consumed, &cleared)
	if sessions != 0 || consumed || cleared {
		t.Fatalf("signin rollback sessions=%d consumed=%v cleared=%v", sessions, consumed, cleared)
	}
}
