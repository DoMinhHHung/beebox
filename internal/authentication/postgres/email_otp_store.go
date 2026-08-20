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

func (s *Store) IssueEmailOTP(ctx context.Context, issue authentication.EmailOTPIssue) (authentication.EmailOTPIssueResult, error) {
	if s == nil || s.pool == nil || !issue.ApplicationInstanceID.Valid() || issue.NormalizedEmail == "" || !issue.CodeHash.Valid() || issue.CorrelationID == (audit.CorrelationID{}) {
		return authentication.EmailOTPIssueResult{}, authentication.ErrEmailOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var emailID, userID int64
	var destination string
	var verifiedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT id, user_id, email_address, verified_at
		FROM email_identifiers
		WHERE application_instance_id=$1 AND normalized_email=$2
		FOR UPDATE`, int64(issue.ApplicationInstanceID), issue.NormalizedEmail,
	).Scan(&emailID, &userID, &destination, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !verifiedAt.Valid) {
		if err := tx.Commit(); err != nil {
			return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
		}
		return authentication.EmailOTPIssueResult{}, nil
	}
	if err != nil {
		return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
	}

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
	}
	now = now.UTC()
	expiresAt := now.Add(authentication.EmailOTPCodeTTL)

	var generation int64
	var issueCount int
	var windowStartedAt, lastIssuedAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT generation, issue_count, issue_window_started_at, last_issued_at
		FROM email_otp_signin_challenges
		WHERE application_instance_id=$1 AND email_identifier_id=$2
		FOR UPDATE`, int64(issue.ApplicationInstanceID), emailID,
	).Scan(&generation, &issueCount, &windowStartedAt, &lastIssuedAt)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		generation = 1
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO email_otp_signin_challenges (
				application_instance_id,email_identifier_id,generation,code_hash,
				expires_at,failed_attempts,issue_count,issue_window_started_at,
				last_issued_at,consumed_at,updated_at
			) VALUES ($1,$2,1,$3,$4,0,1,$5,$5,NULL,$5)`,
			int64(issue.ApplicationInstanceID), emailID, issue.CodeHash.StorageEncoding(), expiresAt, now,
		); err != nil {
			return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
		}
	case err != nil:
		return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
	default:
		windowStartedAt = windowStartedAt.UTC()
		lastIssuedAt = lastIssuedAt.UTC()
		if now.Before(lastIssuedAt.Add(authentication.EmailOTPResendCooldown)) {
			if err := tx.Commit(); err != nil {
				return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
			}
			return authentication.EmailOTPIssueResult{}, nil
		}
		if !now.Before(windowStartedAt.Add(authentication.EmailOTPIssueWindow)) {
			issueCount = 1
			windowStartedAt = now
		} else {
			if issueCount >= authentication.EmailOTPMaxIssues {
				if err := tx.Commit(); err != nil {
					return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
				}
				return authentication.EmailOTPIssueResult{}, nil
			}
			issueCount++
		}
		generation++
		if _, err := tx.ExecContext(ctx, `
			UPDATE email_otp_signin_challenges
			SET generation=$3, code_hash=$4, expires_at=$5, failed_attempts=0,
			    issue_count=$6, issue_window_started_at=$7, last_issued_at=$8,
			    consumed_at=NULL, updated_at=$8
			WHERE application_instance_id=$1 AND email_identifier_id=$2`,
			int64(issue.ApplicationInstanceID), emailID, generation, issue.CodeHash.StorageEncoding(), expiresAt, issueCount, windowStartedAt, now,
		); err != nil {
			return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
		}
	}

	if err := insertEmailOTPAudit(ctx, tx, issue.ApplicationInstanceID, identity.InternalID(userID), "authentication.email_otp.challenge_issued", "success", issue.CorrelationID, "email_otp_challenge"); err != nil {
		return authentication.EmailOTPIssueResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.EmailOTPIssueResult{}, classifyEmailOTP(ctx, err)
	}
	return authentication.EmailOTPIssueResult{ShouldSend: true, Destination: destination, ExpiresAt: expiresAt}, nil
}

func (s *Store) LoadEmailOTP(ctx context.Context, appID applicationinstance.InternalID, normalizedEmail string) (authentication.EmailOTPChallengeSnapshot, error) {
	if s == nil || s.pool == nil || !appID.Valid() || normalizedEmail == "" {
		return authentication.EmailOTPChallengeSnapshot{}, authentication.ErrEmailOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var snapshot authentication.EmailOTPChallengeSnapshot
	var userID, emailID int64
	var encoded sql.NullString
	var consumedAt sql.NullTime
	var verifiedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT e.user_id,e.id,e.verified_at,c.generation,c.code_hash,c.expires_at,c.failed_attempts,c.consumed_at
		FROM email_identifiers e
		JOIN email_otp_signin_challenges c
		  ON c.application_instance_id=e.application_instance_id AND c.email_identifier_id=e.id
		WHERE e.application_instance_id=$1 AND e.normalized_email=$2`, int64(appID), normalizedEmail,
	).Scan(&userID, &emailID, &verifiedAt, &snapshot.ChallengeGeneration, &encoded, &snapshot.ExpiresAt, &snapshot.FailedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.EmailOTPChallengeSnapshot{}, authentication.ErrEmailOTPInvalid
	}
	if err != nil {
		return authentication.EmailOTPChallengeSnapshot{}, classifyEmailOTP(ctx, err)
	}
	if !verifiedAt.Valid || consumedAt.Valid || !encoded.Valid || snapshot.FailedAttempts >= authentication.EmailOTPMaxAttempts {
		return authentication.EmailOTPChallengeSnapshot{}, authentication.ErrEmailOTPInvalid
	}
	hash, err := authentication.ParseVerificationCodeHash(encoded.String)
	if err != nil {
		return authentication.EmailOTPChallengeSnapshot{}, authentication.ErrEmailOTPPersistence
	}
	snapshot.UserID = identity.InternalID(userID)
	snapshot.EmailIdentifierID = identity.EmailIdentifierInternalID(emailID)
	snapshot.CodeHash = hash
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	return snapshot, nil
}

func (s *Store) FinalizeEmailOTP(ctx context.Context, finalize authentication.EmailOTPFinalize) (authentication.EmailOTPFinalizeResult, error) {
	if s == nil || s.pool == nil || !finalize.ApplicationInstanceID.Valid() || !finalize.EmailIdentifierID.Valid() || !finalize.UserID.Valid() || finalize.ChallengeGeneration <= 0 || finalize.CorrelationID == (audit.CorrelationID{}) {
		return authentication.EmailOTPFinalizeResult{}, authentication.ErrEmailOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var verifiedAt sql.NullTime
	var currentUserID int64
	err = tx.QueryRowContext(ctx, `
		SELECT user_id, verified_at
		FROM email_identifiers
		WHERE application_instance_id=$1 AND id=$2
		FOR UPDATE`, int64(finalize.ApplicationInstanceID), int64(finalize.EmailIdentifierID),
	).Scan(&currentUserID, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (!verifiedAt.Valid || currentUserID != int64(finalize.UserID))) {
		return authentication.EmailOTPFinalizeResult{}, authentication.ErrEmailOTPStale
	}
	if err != nil {
		return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
	}

	var generation int64
	var encoded sql.NullString
	var expiresAt time.Time
	var failedAttempts int
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT generation,code_hash,expires_at,failed_attempts,consumed_at
		FROM email_otp_signin_challenges
		WHERE application_instance_id=$1 AND email_identifier_id=$2
		FOR UPDATE`, int64(finalize.ApplicationInstanceID), int64(finalize.EmailIdentifierID),
	).Scan(&generation, &encoded, &expiresAt, &failedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.EmailOTPFinalizeResult{}, authentication.ErrEmailOTPInvalid
	}
	if err != nil {
		return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
	}
	if generation != finalize.ChallengeGeneration || consumedAt.Valid || !encoded.Valid {
		return authentication.EmailOTPFinalizeResult{}, authentication.ErrEmailOTPStale
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
	}
	now = now.UTC()
	if !now.Before(expiresAt.UTC()) || failedAttempts >= authentication.EmailOTPMaxAttempts {
		if err := insertEmailOTPAudit(ctx, tx, finalize.ApplicationInstanceID, finalize.UserID, "authentication.email_otp.confirm", "denied", finalize.CorrelationID, "email_otp_challenge"); err != nil {
			return authentication.EmailOTPFinalizeResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
		}
		return authentication.EmailOTPFinalizeResult{}, authentication.ErrEmailOTPInvalid
	}
	if !finalize.Matched {
		if _, err := tx.ExecContext(ctx, `
			UPDATE email_otp_signin_challenges
			SET failed_attempts=failed_attempts+1,updated_at=$3
			WHERE application_instance_id=$1 AND email_identifier_id=$2`, int64(finalize.ApplicationInstanceID), int64(finalize.EmailIdentifierID), now,
		); err != nil {
			return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
		}
		if err := insertEmailOTPAudit(ctx, tx, finalize.ApplicationInstanceID, finalize.UserID, "authentication.email_otp.confirm", "denied", finalize.CorrelationID, "email_otp_challenge"); err != nil {
			return authentication.EmailOTPFinalizeResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
		}
		return authentication.EmailOTPFinalizeResult{}, authentication.ErrEmailOTPInvalid
	}
	if !finalize.PendingMFA.Valid() || finalize.PendingMFA.PrimaryMethod != authentication.PrimaryMethodEmailOTP {
		return authentication.EmailOTPFinalizeResult{}, authentication.ErrEmailOTPPersistence
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE email_otp_signin_challenges
		SET consumed_at=$4,code_hash=NULL,updated_at=$4
		WHERE application_instance_id=$1 AND email_identifier_id=$2 AND generation=$3 AND consumed_at IS NULL`,
		int64(finalize.ApplicationInstanceID), int64(finalize.EmailIdentifierID), finalize.ChallengeGeneration, now,
	); err != nil {
		return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
	}
	assurance, err := finalizePrimaryAssurance(ctx, tx, finalize.ApplicationInstanceID, finalize.UserID, primarySessionMaterial{
		PublicID:       finalize.SessionPublicID,
		RefreshHash:    finalize.RefreshVerifier,
		IdleExpiresAt:  finalize.IdleExpiresAt,
		ExpiresAt:      finalize.ExpiresAt,
		Pending:        finalize.PendingMFA,
		ExpectedMethod: authentication.PrimaryMethodEmailOTP,
	})
	if err != nil {
		return authentication.EmailOTPFinalizeResult{}, authentication.ErrEmailOTPPersistence
	}
	resource := "session"
	if assurance.MFARequired {
		resource = "pending_mfa"
	}
	if err := insertEmailOTPAudit(ctx, tx, finalize.ApplicationInstanceID, finalize.UserID, "authentication.email_otp.confirm", "success", finalize.CorrelationID, resource); err != nil {
		return authentication.EmailOTPFinalizeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.EmailOTPFinalizeResult{}, classifyEmailOTP(ctx, err)
	}
	return authentication.EmailOTPFinalizeResult{
		UserPublicID:          assurance.UserPublicID,
		ApplicationPublicID:   assurance.ApplicationPublicID,
		MFARequired:           assurance.MFARequired,
		PendingMFAPublicID:    assurance.PendingMFAPublicID,
		PendingMFAExpiresAt:   assurance.PendingMFAExpiresAt,
		RecoveryCodeAvailable: assurance.RecoveryCodeAvailable,
	}, nil
}

func insertEmailOTPAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, action, outcome string, correlationID audit.CorrelationID, resource string) error {
	actorKind := "anonymous_email_otp"
	var actorUser any
	if outcome == "success" && action == "authentication.email_otp.confirm" {
		actorKind = "user"
		actorUser = int64(userID)
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,outcome,correlation_id,source)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'internal_email_otp')`,
		int64(appID), actorKind, actorUser, int64(userID), action, resource, outcome, correlationID[:],
	)
	return classifyEmailOTP(ctx, err)
}

func classifyEmailOTP(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return authentication.ErrEmailOTPPersistence
}
