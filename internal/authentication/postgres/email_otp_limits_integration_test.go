//go:build integration

package postgres

import (
	"errors"
	"testing"

	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func TestEmailOTPIssueWindowAllowsThreeAndSuppressesFourth(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_email_otp_issue_window")
	app, email, _, _, store := createVerifiedResetUser(t, ctx, pool)
	delivery := &otpDelivery{}
	issuer := authentication.NewEmailOTPService(store, delivery)

	for issue := 1; issue <= authentication.EmailOTPMaxIssues; issue++ {
		correlation, _ := audit.NewCorrelationID()
		if err := issuer.RequestWithCorrelation(ctx, app.InternalID, email, correlation); err != nil {
			t.Fatalf("issue %d error = %v", issue, err)
		}
		if issue < authentication.EmailOTPMaxIssues {
			db := pool.OpenSQLDB()
			_, err := db.ExecContext(ctx, `UPDATE email_otp_signin_challenges
				SET issue_window_started_at=LEAST(issue_window_started_at,CURRENT_TIMESTAMP-INTERVAL '61 seconds'),
				    last_issued_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds'
				WHERE application_instance_id=$1`, int64(app.InternalID))
			_ = db.Close()
			if err != nil {
				t.Fatalf("advance cooldown after issue %d: %v", issue, err)
			}
		}
	}
	if got := len(delivery.snapshot()); got != authentication.EmailOTPMaxIssues {
		t.Fatalf("deliveries after allowed issues = %d, want %d", got, authentication.EmailOTPMaxIssues)
	}

	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, `UPDATE email_otp_signin_challenges
		SET issue_window_started_at=LEAST(issue_window_started_at,CURRENT_TIMESTAMP-INTERVAL '61 seconds'),
		    last_issued_at=CURRENT_TIMESTAMP-INTERVAL '61 seconds'
		WHERE application_instance_id=$1`, int64(app.InternalID)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	_ = db.Close()
	correlation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, email, correlation); err != nil {
		t.Fatalf("suppressed fourth issue leaked error = %v", err)
	}
	if got := len(delivery.snapshot()); got != authentication.EmailOTPMaxIssues {
		t.Fatalf("fourth issue delivered code: deliveries=%d", got)
	}
}

func TestEmailOTPExpiredChallengeFailsWithoutSession(t *testing.T) {
	pool, ctx := resetTestDatabase(t, "beebox_email_otp_expired")
	app, email, _, _, store := createVerifiedResetUser(t, ctx, pool)
	delivery := &otpDelivery{}
	issuer := authentication.NewEmailOTPService(store, delivery)
	correlation, _ := audit.NewCorrelationID()
	if err := issuer.RequestWithCorrelation(ctx, app.InternalID, email, correlation); err != nil {
		t.Fatal(err)
	}
	code := delivery.snapshot()[0]

	db := pool.OpenSQLDB()
	if _, err := db.ExecContext(ctx, `UPDATE email_otp_signin_challenges
		SET issue_window_started_at=LEAST(issue_window_started_at,CURRENT_TIMESTAMP-INTERVAL '2 minutes'),
		    last_issued_at=CURRENT_TIMESTAMP-INTERVAL '2 minutes',
		    expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second'
		WHERE application_instance_id=$1`, int64(app.InternalID)); err != nil {
		db.Close()
		t.Fatal(err)
	}
	_ = db.Close()

	confirmer := session.NewEmailOTPService(store, testEmailOTPKeyRing(t))
	confirmCorrelation, _ := audit.NewCorrelationID()
	if _, err := confirmer.Confirm(ctx, app.InternalID, email, code, confirmCorrelation); !errors.Is(err, session.ErrInvalidCredentials) {
		t.Fatalf("expired confirmation error = %v", err)
	}
	db = pool.OpenSQLDB()
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE application_instance_id=$1`, int64(app.InternalID)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired challenge created %d sessions", count)
	}
}
