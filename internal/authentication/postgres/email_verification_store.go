package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func (s *Store) IssueEmailVerification(
	ctx context.Context,
	issue authentication.EmailVerificationIssue,
) (authentication.EmailVerificationIssueResult, error) {
	if !issue.ApplicationInstanceID.Valid() {
		return authentication.EmailVerificationIssueResult{}, authentication.ErrInvalidApplicationInstanceScope
	}
	if !issue.EmailIdentifierID.Valid() {
		return authentication.EmailVerificationIssueResult{}, authentication.ErrInvalidEmailIdentifierInternalID
	}
	if !issue.CodeHash.Valid() {
		return authentication.EmailVerificationIssueResult{}, authentication.ErrInvalidVerificationCodeHash
	}
	if err := ctx.Err(); err != nil {
		return authentication.EmailVerificationIssueResult{}, err
	}
	if s == nil || s.pool == nil {
		return authentication.EmailVerificationIssueResult{}, authentication.ErrEmailVerificationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.EmailVerificationIssueResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var userID int64
	var destination string
	var verifiedAt sql.NullTime
	err = tx.QueryRowContext(
		ctx,
		`SELECT user_id, email_address, verified_at
		 FROM email_identifiers
		 WHERE application_instance_id = $1 AND id = $2
		 FOR UPDATE`,
		int64(issue.ApplicationInstanceID),
		int64(issue.EmailIdentifierID),
	).Scan(&userID, &destination, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.EmailVerificationIssueResult{}, authentication.ErrEmailVerificationChallengeNotFound
	}
	if err != nil {
		return authentication.EmailVerificationIssueResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	if verifiedAt.Valid {
		return authentication.EmailVerificationIssueResult{}, authentication.ErrEmailVerificationAlreadyCompleted
	}

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.EmailVerificationIssueResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	now = now.UTC()
	expiresAt := now.Add(authentication.EmailVerificationCodeTTL)

	var generation int64
	var failedAttempts int
	var issueCount int
	var windowStartedAt time.Time
	var lastIssuedAt time.Time
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(
		ctx,
		`SELECT generation, failed_attempts, issue_count, issue_window_started_at,
		        last_issued_at, consumed_at
		 FROM email_verification_challenges
		 WHERE application_instance_id = $1 AND email_identifier_id = $2
		 FOR UPDATE`,
		int64(issue.ApplicationInstanceID),
		int64(issue.EmailIdentifierID),
	).Scan(&generation, &failedAttempts, &issueCount, &windowStartedAt, &lastIssuedAt, &consumedAt)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		generation = 1
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO email_verification_challenges (
				application_instance_id, email_identifier_id, generation, code_hash,
				expires_at, failed_attempts, issue_count, issue_window_started_at,
				last_issued_at, consumed_at, updated_at
			 ) VALUES ($1,$2,$3,$4,$5,0,1,$6,$6,NULL,$6)`,
			int64(issue.ApplicationInstanceID),
			int64(issue.EmailIdentifierID),
			generation,
			issue.CodeHash.StorageEncoding(),
			expiresAt,
			now,
		); err != nil {
			return authentication.EmailVerificationIssueResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
	case err != nil:
		return authentication.EmailVerificationIssueResult{}, classifyEmailVerificationPersistence(ctx, err)
	default:
		if consumedAt.Valid {
			return authentication.EmailVerificationIssueResult{}, authentication.ErrEmailVerificationAlreadyCompleted
		}
		windowStartedAt = windowStartedAt.UTC()
		lastIssuedAt = lastIssuedAt.UTC()
		generation++
		if !now.Before(windowStartedAt.Add(authentication.EmailVerificationIssueWindow)) {
			failedAttempts = 0
			issueCount = 1
			windowStartedAt = now
		} else {
			if now.Before(lastIssuedAt.Add(authentication.EmailVerificationResendCooldown)) {
				return authentication.EmailVerificationIssueResult{}, authentication.ErrEmailVerificationResendCooldown
			}
			if issueCount >= authentication.EmailVerificationMaxIssues {
				return authentication.EmailVerificationIssueResult{}, authentication.ErrEmailVerificationIssueLimit
			}
			issueCount++
		}

		if _, err := tx.ExecContext(
			ctx,
			`UPDATE email_verification_challenges
			 SET generation = $3, code_hash = $4, expires_at = $5,
			     failed_attempts = $6, issue_count = $7,
			     issue_window_started_at = $8, last_issued_at = $9,
			     consumed_at = NULL, updated_at = $9
			 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
			int64(issue.ApplicationInstanceID),
			int64(issue.EmailIdentifierID),
			generation,
			issue.CodeHash.StorageEncoding(),
			expiresAt,
			failedAttempts,
			issueCount,
			windowStartedAt,
			now,
		); err != nil {
			return authentication.EmailVerificationIssueResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
	}

	if err := insertEmailVerificationAudit(
		ctx,
		tx,
		issue.ApplicationInstanceID,
		identity.InternalID(userID),
		audit.ActionEmailVerificationChallengeIssued,
		audit.OutcomeSuccess,
		issue.CorrelationID,
	); err != nil {
		return authentication.EmailVerificationIssueResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.EmailVerificationIssueResult{}, classifyEmailVerificationPersistence(ctx, err)
	}

	return authentication.EmailVerificationIssueResult{Destination: destination, ExpiresAt: expiresAt}, nil
}

func (s *Store) LoadEmailVerificationChallenge(
	ctx context.Context,
	applicationInstanceID applicationinstance.InternalID,
	emailIdentifierID identity.EmailIdentifierInternalID,
) (authentication.EmailVerificationChallengeSnapshot, error) {
	if !applicationInstanceID.Valid() {
		return authentication.EmailVerificationChallengeSnapshot{}, authentication.ErrInvalidApplicationInstanceScope
	}
	if !emailIdentifierID.Valid() {
		return authentication.EmailVerificationChallengeSnapshot{}, authentication.ErrInvalidEmailIdentifierInternalID
	}
	if err := ctx.Err(); err != nil {
		return authentication.EmailVerificationChallengeSnapshot{}, err
	}
	if s == nil || s.pool == nil {
		return authentication.EmailVerificationChallengeSnapshot{}, authentication.ErrEmailVerificationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	var snapshot authentication.EmailVerificationChallengeSnapshot
	var encoded sql.NullString
	var consumedAt sql.NullTime
	var verifiedAt sql.NullTime
	err := db.QueryRowContext(
		ctx,
		`SELECT c.generation, c.code_hash, c.expires_at, c.failed_attempts,
		        c.consumed_at, e.verified_at
		 FROM email_verification_challenges c
		 JOIN email_identifiers e
		   ON e.application_instance_id = c.application_instance_id
		  AND e.id = c.email_identifier_id
		 WHERE c.application_instance_id = $1 AND c.email_identifier_id = $2`,
		int64(applicationInstanceID),
		int64(emailIdentifierID),
	).Scan(&snapshot.Generation, &encoded, &snapshot.ExpiresAt, &snapshot.FailedAttempts, &consumedAt, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.EmailVerificationChallengeSnapshot{}, authentication.ErrEmailVerificationChallengeNotFound
	}
	if err != nil {
		return authentication.EmailVerificationChallengeSnapshot{}, classifyEmailVerificationPersistence(ctx, err)
	}
	if verifiedAt.Valid || consumedAt.Valid {
		return authentication.EmailVerificationChallengeSnapshot{}, authentication.ErrEmailVerificationAlreadyCompleted
	}
	if !encoded.Valid {
		return authentication.EmailVerificationChallengeSnapshot{}, authentication.ErrEmailVerificationPersistence
	}
	parsed, err := authentication.ParseVerificationCodeHash(encoded.String)
	if err != nil {
		return authentication.EmailVerificationChallengeSnapshot{}, authentication.ErrEmailVerificationPersistence
	}
	snapshot.CodeHash = parsed
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	return snapshot, nil
}

func (s *Store) FinalizeEmailVerification(
	ctx context.Context,
	attempt authentication.EmailVerificationAttempt,
) (authentication.VerifiedEmailResult, error) {
	if !attempt.ApplicationInstanceID.Valid() {
		return authentication.VerifiedEmailResult{}, authentication.ErrInvalidApplicationInstanceScope
	}
	if !attempt.EmailIdentifierID.Valid() {
		return authentication.VerifiedEmailResult{}, authentication.ErrInvalidEmailIdentifierInternalID
	}
	if attempt.Generation <= 0 {
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationStaleChallenge
	}
	if err := ctx.Err(); err != nil {
		return authentication.VerifiedEmailResult{}, err
	}
	if s == nil || s.pool == nil {
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var email identity.EmailIdentifier
	var emailID int64
	var appID int64
	var userID int64
	var verifiedAt sql.NullTime
	err = tx.QueryRowContext(
		ctx,
		`SELECT id, application_instance_id, user_id, email_address,
		        normalized_email, verified_at, created_at
		 FROM email_identifiers
		 WHERE application_instance_id = $1 AND id = $2
		 FOR UPDATE`,
		int64(attempt.ApplicationInstanceID),
		int64(attempt.EmailIdentifierID),
	).Scan(
		&emailID,
		&appID,
		&userID,
		&email.EmailAddress,
		&email.NormalizedEmail,
		&verifiedAt,
		&email.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationChallengeNotFound
	}
	if err != nil {
		return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
	}

	var generation int64
	var encoded sql.NullString
	var expiresAt time.Time
	var failedAttempts int
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(
		ctx,
		`SELECT generation, code_hash, expires_at, failed_attempts, consumed_at
		 FROM email_verification_challenges
		 WHERE application_instance_id = $1 AND email_identifier_id = $2
		 FOR UPDATE`,
		int64(attempt.ApplicationInstanceID),
		int64(attempt.EmailIdentifierID),
	).Scan(&generation, &encoded, &expiresAt, &failedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationChallengeNotFound
	}
	if err != nil {
		return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	if generation != attempt.Generation {
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationStaleChallenge
	}
	if verifiedAt.Valid || consumedAt.Valid {
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationAlreadyCompleted
	}
	if !encoded.Valid {
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationPersistence
	}

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	now = now.UTC()
	expiresAt = expiresAt.UTC()

	if !now.Before(expiresAt) {
		if err := insertEmailVerificationAudit(ctx, tx, attempt.ApplicationInstanceID, identity.InternalID(userID), audit.ActionEmailVerificationVerify, audit.OutcomeDenied, attempt.CorrelationID); err != nil {
			return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
		if err := tx.Commit(); err != nil {
			return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationExpired
	}
	if failedAttempts >= authentication.EmailVerificationMaxAttempts {
		if err := insertEmailVerificationAudit(ctx, tx, attempt.ApplicationInstanceID, identity.InternalID(userID), audit.ActionEmailVerificationVerify, audit.OutcomeDenied, attempt.CorrelationID); err != nil {
			return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
		if err := tx.Commit(); err != nil {
			return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationAttemptLimit
	}
	if !attempt.Matched {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE email_verification_challenges
			 SET failed_attempts = failed_attempts + 1, updated_at = $3
			 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
			int64(attempt.ApplicationInstanceID),
			int64(attempt.EmailIdentifierID),
			now,
		); err != nil {
			return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
		if err := insertEmailVerificationAudit(ctx, tx, attempt.ApplicationInstanceID, identity.InternalID(userID), audit.ActionEmailVerificationVerify, audit.OutcomeDenied, attempt.CorrelationID); err != nil {
			return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
		if err := tx.Commit(); err != nil {
			return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
		}
		return authentication.VerifiedEmailResult{}, authentication.ErrEmailVerificationMismatch
	}

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE email_identifiers
		 SET verified_at = $3
		 WHERE application_instance_id = $1 AND id = $2 AND verified_at IS NULL`,
		int64(attempt.ApplicationInstanceID),
		int64(attempt.EmailIdentifierID),
		now,
	); err != nil {
		return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE email_verification_challenges
		 SET consumed_at = $3, code_hash = NULL, updated_at = $3
		 WHERE application_instance_id = $1 AND email_identifier_id = $2`,
		int64(attempt.ApplicationInstanceID),
		int64(attempt.EmailIdentifierID),
		now,
	); err != nil {
		return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	if err := insertEmailVerificationAudit(ctx, tx, attempt.ApplicationInstanceID, identity.InternalID(userID), audit.ActionEmailVerificationVerify, audit.OutcomeSuccess, attempt.CorrelationID); err != nil {
		return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.VerifiedEmailResult{}, classifyEmailVerificationPersistence(ctx, err)
	}

	verifiedUTC := now
	email.InternalID = identity.EmailIdentifierInternalID(emailID)
	email.ApplicationInstanceID = applicationinstance.InternalID(appID)
	email.UserID = identity.InternalID(userID)
	email.VerifiedAt = &verifiedUTC
	email.CreatedAt = email.CreatedAt.UTC()
	return authentication.VerifiedEmailResult{EmailIdentifier: email}, nil
}

func insertEmailVerificationAudit(
	ctx context.Context,
	tx *sql.Tx,
	applicationInstanceID applicationinstance.InternalID,
	subjectUserID identity.InternalID,
	action string,
	outcome string,
	correlationID audit.CorrelationID,
) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO audit_events (
			application_instance_id, actor_kind, subject_user_id, action,
			resource_category, outcome, correlation_id, source
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		int64(applicationInstanceID),
		audit.ActorKindAnonymousEmailVerification,
		int64(subjectUserID),
		action,
		audit.ResourceCategoryEmailIdentifier,
		outcome,
		correlationID[:],
		audit.SourceInternalEmailVerification,
	)
	return err
}

func classifyEmailVerificationPersistence(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return authentication.ErrEmailVerificationPersistence
}
