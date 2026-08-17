//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	applicationpostgres "github.com/DoMinhHHung/beebox/internal/applicationinstance/postgres"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	identitypostgres "github.com/DoMinhHHung/beebox/internal/identity/postgres"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
)

type verificationDeliveryRecorder struct {
	code        string
	destination string
	expiresAt   time.Time
	err         error
}

func (d *verificationDeliveryRecorder) DeliverVerificationCode(_ context.Context, destination string, code string, expiresAt time.Time) error {
	d.destination = destination
	d.code = code
	d.expiresAt = expiresAt
	return d.err
}

func TestEmailVerificationIssueAndSuccessLifecycle(t *testing.T) {
	pool, ctx, appID, email := verificationIdentity(t, "beebox_email_verify_success", "Alice@Example.TEST")
	delivery := &verificationDeliveryRecorder{}
	service := authentication.NewEmailVerificationService(New(pool), delivery)

	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("IssueEmailVerification() error = %v", err)
	}
	if delivery.destination != email.EmailAddress || len(delivery.code) != 6 {
		t.Fatal("issue did not deliver to the stored scoped email destination")
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var storedHash string
	var generation int64
	var failedAttempts int
	var issueCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT code_hash, generation, failed_attempts, issue_count
		 FROM email_verification_challenges
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appID), int64(email.InternalID),
	).Scan(&storedHash, &generation, &failedAttempts, &issueCount); err != nil {
		t.Fatalf("query challenge error = %v", err)
	}
	if storedHash == delivery.code || strings.Contains(storedHash, delivery.code) {
		t.Fatal("database challenge contains plaintext verification code")
	}
	if _, err := authentication.ParseVerificationCodeHash(storedHash); err != nil {
		t.Fatalf("stored verification code hash invalid: %v", err)
	}
	if generation != 1 || failedAttempts != 0 || issueCount != 1 {
		t.Fatalf("initial challenge state generation=%d failed=%d issues=%d", generation, failedAttempts, issueCount)
	}

	result, err := service.VerifyEmailCode(ctx, appID, email.InternalID, delivery.code)
	if err != nil {
		t.Fatalf("VerifyEmailCode() error = %v", err)
	}
	if result.EmailIdentifier.VerifiedAt == nil {
		t.Fatal("successful verification did not set verified_at")
	}

	var consumedAt sql.NullTime
	var clearedHash sql.NullString
	if err := db.QueryRowContext(
		ctx,
		`SELECT consumed_at, code_hash
		 FROM email_verification_challenges
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appID), int64(email.InternalID),
	).Scan(&consumedAt, &clearedHash); err != nil {
		t.Fatalf("query consumed challenge error = %v", err)
	}
	if !consumedAt.Valid || clearedHash.Valid {
		t.Fatal("successful verification did not consume challenge and clear verifier material")
	}
	if got := auditCount(t, ctx, db, appID, audit.ActionEmailVerificationChallengeIssued, audit.OutcomeSuccess); got != 1 {
		t.Fatalf("issuance success audits = %d, want 1", got)
	}
	if got := auditCount(t, ctx, db, appID, audit.ActionEmailVerificationVerify, audit.OutcomeSuccess); got != 1 {
		t.Fatalf("verification success audits = %d, want 1", got)
	}
	if _, err := service.VerifyEmailCode(ctx, appID, email.InternalID, delivery.code); !errors.Is(err, authentication.ErrEmailVerificationAlreadyCompleted) {
		t.Fatalf("verification replay error = %v, want already completed", err)
	}
}

func TestEmailVerificationWrongAttemptsBudgetAndResendLimits(t *testing.T) {
	pool, ctx, appID, email := verificationIdentity(t, "beebox_email_verify_attempts", "attempts@example.test")
	delivery := &verificationDeliveryRecorder{}
	service := authentication.NewEmailVerificationService(New(pool), delivery)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("initial issue error = %v", err)
	}

	for i := 0; i < authentication.EmailVerificationMaxAttempts; i++ {
		if _, err := service.VerifyEmailCode(ctx, appID, email.InternalID, "999999"); !errors.Is(err, authentication.ErrEmailVerificationMismatch) {
			t.Fatalf("wrong attempt %d error = %v, want mismatch", i+1, err)
		}
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var failedAttempts int
	if err := db.QueryRowContext(
		ctx,
		`SELECT failed_attempts FROM email_verification_challenges
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appID), int64(email.InternalID),
	).Scan(&failedAttempts); err != nil {
		t.Fatalf("query failed attempts error = %v", err)
	}
	if failedAttempts != authentication.EmailVerificationMaxAttempts {
		t.Fatalf("failed attempts = %d, want %d", failedAttempts, authentication.EmailVerificationMaxAttempts)
	}
	if got := auditCount(t, ctx, db, appID, audit.ActionEmailVerificationVerify, audit.OutcomeDenied); got != authentication.EmailVerificationMaxAttempts {
		t.Fatalf("denied audits = %d, want %d", got, authentication.EmailVerificationMaxAttempts)
	}

	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); !errors.Is(err, authentication.ErrEmailVerificationResendCooldown) {
		t.Fatalf("immediate resend error = %v, want cooldown", err)
	}
	advanceResendCooldown(t, ctx, db, appID, email.InternalID)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("second issue error = %v", err)
	}
	newCode := delivery.code
	if err := db.QueryRowContext(
		ctx,
		`SELECT failed_attempts FROM email_verification_challenges
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appID), int64(email.InternalID),
	).Scan(&failedAttempts); err != nil {
		t.Fatalf("query failed attempts after resend error = %v", err)
	}
	if failedAttempts != authentication.EmailVerificationMaxAttempts {
		t.Fatalf("resend reset failed attempts to %d", failedAttempts)
	}
	if _, err := service.VerifyEmailCode(ctx, appID, email.InternalID, newCode); !errors.Is(err, authentication.ErrEmailVerificationAttemptLimit) {
		t.Fatalf("correct code after exhausted attempts error = %v, want attempt limit", err)
	}

	advanceResendCooldown(t, ctx, db, appID, email.InternalID)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("third issue error = %v", err)
	}
	advanceResendCooldown(t, ctx, db, appID, email.InternalID)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); !errors.Is(err, authentication.ErrEmailVerificationIssueLimit) {
		t.Fatalf("fourth issue error = %v, want issue limit", err)
	}
}

func TestEmailVerificationNewIssueWindowResetsCountersAndRotatesCode(t *testing.T) {
	pool, ctx, appID, email := verificationIdentity(t, "beebox_email_verify_window", "window@example.test")
	delivery := &verificationDeliveryRecorder{}
	service := authentication.NewEmailVerificationService(New(pool), delivery)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("initial issue error = %v", err)
	}
	oldCode := delivery.code
	if _, err := service.VerifyEmailCode(ctx, appID, email.InternalID, "999999"); !errors.Is(err, authentication.ErrEmailVerificationMismatch) {
		t.Fatalf("wrong attempt error = %v", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(
		ctx,
		`UPDATE email_verification_challenges
		 SET issue_window_started_at = CURRENT_TIMESTAMP - INTERVAL '16 minutes',
		     last_issued_at = CURRENT_TIMESTAMP - INTERVAL '61 seconds'
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appID), int64(email.InternalID),
	); err != nil {
		t.Fatalf("age challenge window error = %v", err)
	}
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("new-window issue error = %v", err)
	}
	newCode := delivery.code
	if newCode == oldCode {
		t.Fatal("resend did not rotate verification code")
	}

	var generation int64
	var failedAttempts int
	var issueCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT generation, failed_attempts, issue_count
		 FROM email_verification_challenges
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appID), int64(email.InternalID),
	).Scan(&generation, &failedAttempts, &issueCount); err != nil {
		t.Fatalf("query new-window challenge error = %v", err)
	}
	if generation != 2 || failedAttempts != 0 || issueCount != 1 {
		t.Fatalf("new-window state generation=%d failed=%d issues=%d", generation, failedAttempts, issueCount)
	}
	if _, err := service.VerifyEmailCode(ctx, appID, email.InternalID, oldCode); !errors.Is(err, authentication.ErrEmailVerificationMismatch) {
		t.Fatalf("old rotated code error = %v, want mismatch", err)
	}
	if _, err := service.VerifyEmailCode(ctx, appID, email.InternalID, newCode); err != nil {
		t.Fatalf("new rotated code verification error = %v", err)
	}
}

func TestEmailVerificationDeliveryFailureKeepsCommittedChallengeAndAudit(t *testing.T) {
	pool, ctx, appID, email := verificationIdentity(t, "beebox_email_verify_delivery", "delivery@example.test")
	delivery := &verificationDeliveryRecorder{err: errors.New("synthetic provider failure")}
	service := authentication.NewEmailVerificationService(New(pool), delivery)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); !errors.Is(err, authentication.ErrEmailVerificationDelivery) {
		t.Fatalf("delivery failure = %v, want stable delivery error", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var challengeCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT count(*) FROM email_verification_challenges
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appID), int64(email.InternalID),
	).Scan(&challengeCount); err != nil {
		t.Fatalf("query challenge count error = %v", err)
	}
	if challengeCount != 1 || auditCount(t, ctx, db, appID, audit.ActionEmailVerificationChallengeIssued, audit.OutcomeSuccess) != 1 {
		t.Fatal("delivery failure erased committed challenge or issuance audit")
	}
	if _, err := service.VerifyEmailCode(ctx, appID, email.InternalID, delivery.code); err != nil {
		t.Fatalf("committed challenge after delivery failure did not remain valid: %v", err)
	}
}

func TestEmailVerificationExpiryAndCrossApplicationIsolation(t *testing.T) {
	pool, ctx := registrationDatabase(t, "beebox_email_verify_scope")
	appA, emailA := createVerificationIdentity(t, ctx, pool, "a@example.test")
	appB, emailB := createVerificationIdentity(t, ctx, pool, "b@example.test")

	delivery := &verificationDeliveryRecorder{}
	service := authentication.NewEmailVerificationService(New(pool), delivery)
	if err := service.IssueEmailVerification(ctx, appA, emailA.InternalID); err != nil {
		t.Fatalf("issue app A error = %v", err)
	}
	codeA := delivery.code
	if err := service.IssueEmailVerification(ctx, appA, emailB.InternalID); !errors.Is(err, authentication.ErrEmailVerificationChallengeNotFound) {
		t.Fatalf("cross-app issue error = %v, want not found", err)
	}
	if _, err := service.VerifyEmailCode(ctx, appA, emailB.InternalID, "123456"); !errors.Is(err, authentication.ErrEmailVerificationChallengeNotFound) {
		t.Fatalf("cross-app verify error = %v, want not found", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	if _, err := db.ExecContext(
		ctx,
		`UPDATE email_verification_challenges
		 SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appA), int64(emailA.InternalID),
	); err != nil {
		t.Fatalf("expire challenge error = %v", err)
	}
	if _, err := service.VerifyEmailCode(ctx, appA, emailA.InternalID, codeA); !errors.Is(err, authentication.ErrEmailVerificationExpired) {
		t.Fatalf("expired verification error = %v, want expired", err)
	}
	var verifiedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT verified_at FROM email_identifiers WHERE application_instance_id = $1 AND id = $2`, int64(appA), int64(emailA.InternalID)).Scan(&verifiedAt); err != nil {
		t.Fatalf("query verified_at error = %v", err)
	}
	if verifiedAt.Valid {
		t.Fatal("expired verification changed verified_at")
	}

	hash, err := authentication.HashVerificationCode("123456")
	if err != nil {
		t.Fatalf("HashVerificationCode() error = %v", err)
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO email_verification_challenges (
			application_instance_id, email_identifier_id, generation, code_hash,
			expires_at, failed_attempts, issue_count, issue_window_started_at, last_issued_at
		 ) VALUES ($1,$2,1,$3,CURRENT_TIMESTAMP + INTERVAL '10 minutes',0,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		int64(appA), int64(emailB.InternalID), hash.StorageEncoding(),
	)
	if err == nil {
		t.Fatal("cross-application challenge foreign key unexpectedly succeeded")
	}
	_ = appB
}

func TestEmailVerificationConcurrentSuccessAndResendGenerationRace(t *testing.T) {
	pool, ctx, appID, email := verificationIdentity(t, "beebox_email_verify_races", "races@example.test")
	delivery := &verificationDeliveryRecorder{}
	service := authentication.NewEmailVerificationService(New(pool), delivery)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("initial issue error = %v", err)
	}
	store := New(pool)
	snapshot, err := store.LoadEmailVerificationChallenge(ctx, appID, email.InternalID)
	if err != nil {
		t.Fatalf("LoadEmailVerificationChallenge() error = %v", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	advanceResendCooldown(t, ctx, db, appID, email.InternalID)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("resend error = %v", err)
	}
	correlationID, err := audit.NewCorrelationID()
	if err != nil {
		t.Fatalf("NewCorrelationID() error = %v", err)
	}
	_, err = store.FinalizeEmailVerification(ctx, authentication.EmailVerificationAttempt{
		ApplicationInstanceID: appID,
		EmailIdentifierID:     email.InternalID,
		Generation:            snapshot.Generation,
		Matched:               true,
		CorrelationID:         correlationID,
	})
	if !errors.Is(err, authentication.ErrEmailVerificationStaleChallenge) {
		t.Fatalf("stale generation finalization error = %v, want stale", err)
	}

	current, err := store.LoadEmailVerificationChallenge(ctx, appID, email.InternalID)
	if err != nil {
		t.Fatalf("load rotated challenge error = %v", err)
	}
	const attempts = 4
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		correlationID, err := audit.NewCorrelationID()
		if err != nil {
			t.Fatalf("NewCorrelationID() error = %v", err)
		}
		wg.Add(1)
		go func(correlationID audit.CorrelationID) {
			defer wg.Done()
			<-start
			_, err := store.FinalizeEmailVerification(ctx, authentication.EmailVerificationAttempt{
				ApplicationInstanceID: appID,
				EmailIdentifierID:     email.InternalID,
				Generation:            current.Generation,
				Matched:               true,
				CorrelationID:         correlationID,
			})
			results <- err
		}(correlationID)
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	replays := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, authentication.ErrEmailVerificationAlreadyCompleted):
			replays++
		default:
			t.Fatalf("concurrent finalization error = %v", err)
		}
	}
	if successes != 1 || replays != attempts-1 {
		t.Fatalf("concurrent verify results success=%d replay=%d, want 1/%d", successes, replays, attempts-1)
	}
	if got := auditCount(t, ctx, db, appID, audit.ActionEmailVerificationVerify, audit.OutcomeSuccess); got != 1 {
		t.Fatalf("concurrent success audits = %d, want 1", got)
	}
}

func TestEmailVerificationCancellationHasNoPartialMutation(t *testing.T) {
	pool, ctx, appID, email := verificationIdentity(t, "beebox_email_verify_cancel", "cancel@example.test")
	delivery := &verificationDeliveryRecorder{}
	service := authentication.NewEmailVerificationService(New(pool), delivery)
	if err := service.IssueEmailVerification(ctx, appID, email.InternalID); err != nil {
		t.Fatalf("issue error = %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.VerifyEmailCode(canceled, appID, email.InternalID, delivery.code); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verify error = %v, want context cancellation", err)
	}

	db := pool.OpenSQLDB()
	defer db.Close()
	var failedAttempts int
	var verifiedAt sql.NullTime
	if err := db.QueryRowContext(
		ctx,
		`SELECT c.failed_attempts, e.verified_at
		 FROM email_verification_challenges c
		 JOIN email_identifiers e ON e.application_instance_id = c.application_instance_id AND e.id = c.email_identifier_id
		 WHERE c.application_instance_id = $1 AND c.email_identifier_id = $2`,
		int64(appID), int64(email.InternalID),
	).Scan(&failedAttempts, &verifiedAt); err != nil {
		t.Fatalf("query canceled state error = %v", err)
	}
	if failedAttempts != 0 || verifiedAt.Valid {
		t.Fatal("canceled verification mutated challenge or verified state")
	}
}

func verificationIdentity(t *testing.T, schema string, rawEmail string) (*database.Pool, context.Context, applicationinstance.InternalID, identity.EmailIdentifier) {
	t.Helper()
	pool, ctx := registrationDatabase(t, schema)
	appID, email := createVerificationIdentity(t, ctx, pool, rawEmail)
	return pool, ctx, appID, email
}

func createVerificationIdentity(t *testing.T, ctx context.Context, pool *database.Pool, rawEmail string) (applicationinstance.InternalID, identity.EmailIdentifier) {
	t.Helper()
	app, err := applicationpostgres.New(pool).Create(ctx)
	if err != nil {
		t.Fatalf("Create(app) error = %v", err)
	}
	user, err := identitypostgres.New(pool).Create(ctx, app.InternalID)
	if err != nil {
		t.Fatalf("Create(user) error = %v", err)
	}
	email, err := identitypostgres.New(pool).CreateEmailIdentifier(ctx, app.InternalID, user.InternalID, rawEmail)
	if err != nil {
		t.Fatalf("CreateEmailIdentifier() error = %v", err)
	}
	return app.InternalID, email
}

func advanceResendCooldown(t *testing.T, ctx context.Context, db *sql.DB, appID applicationinstance.InternalID, emailID identity.EmailIdentifierInternalID) {
	t.Helper()
	if _, err := db.ExecContext(
		ctx,
		`UPDATE email_verification_challenges
		 SET last_issued_at = CURRENT_TIMESTAMP - INTERVAL '61 seconds'
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(appID), int64(emailID),
	); err != nil {
		t.Fatalf("advance resend cooldown error = %v", err)
	}
}

func auditCount(t *testing.T, ctx context.Context, db *sql.DB, appID applicationinstance.InternalID, action string, outcome string) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT count(*) FROM audit_events
		 WHERE application_instance_id = $1 AND action = $2 AND outcome = $3`,
		int64(appID), action, outcome,
	).Scan(&count); err != nil {
		t.Fatalf("query audit count error = %v", err)
	}
	return count
}
