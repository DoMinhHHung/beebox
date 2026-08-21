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

func (s *Store) IssueEmailLink(ctx context.Context, issue authentication.EmailLinkIssue) (authentication.EmailLinkIssueResult, error) {
	if s == nil || s.pool == nil || !issue.ApplicationInstanceID.Valid() || issue.NormalizedEmail == "" || !authentication.ValidEmailLinkChallengeID(issue.ChallengePublicID) || issue.SecretHash == ([32]byte{}) || issue.CompletionURL == "" || issue.CorrelationID == (audit.CorrelationID{}) {
		return authentication.EmailLinkIssueResult{}, authentication.ErrEmailLinkPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var emailID, userID int64
	var destination string
	var verifiedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT id,user_id,email_address,verified_at
		FROM email_identifiers
		WHERE application_instance_id=$1 AND normalized_email=$2
		FOR UPDATE`, int64(issue.ApplicationInstanceID), issue.NormalizedEmail,
	).Scan(&emailID, &userID, &destination, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !verifiedAt.Valid) {
		if err := tx.Commit(); err != nil {
			return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
		}
		return authentication.EmailLinkIssueResult{}, nil
	}
	if err != nil {
		return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
	}

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
	}
	now = now.UTC()
	expiresAt := now.Add(authentication.EmailLinkTTL)

	var generation int64
	var issueCount int
	var windowStartedAt, lastIssuedAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT generation,issue_count,issue_window_started_at,last_issued_at
		FROM email_signin_links
		WHERE application_instance_id=$1 AND email_identifier_id=$2
		FOR UPDATE`, int64(issue.ApplicationInstanceID), emailID,
	).Scan(&generation, &issueCount, &windowStartedAt, &lastIssuedAt)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		generation = 1
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO email_signin_links(
				application_instance_id,email_identifier_id,public_id,purpose,secret_hash,
				completion_url,generation,expires_at,failed_attempts,issue_count,
				issue_window_started_at,last_issued_at,consumed_at,updated_at
			) VALUES($1,$2,$3,'sign_in',$4,$5,1,$6,0,1,$7,$7,NULL,$7)`,
			int64(issue.ApplicationInstanceID), emailID, issue.ChallengePublicID, issue.SecretHash[:], issue.CompletionURL, expiresAt, now,
		); err != nil {
			return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
		}
	case err != nil:
		return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
	default:
		windowStartedAt = windowStartedAt.UTC()
		lastIssuedAt = lastIssuedAt.UTC()
		if now.Before(lastIssuedAt.Add(authentication.EmailLinkResendCooldown)) {
			if err := tx.Commit(); err != nil {
				return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
			}
			return authentication.EmailLinkIssueResult{}, nil
		}
		if !now.Before(windowStartedAt.Add(authentication.EmailLinkIssueWindow)) {
			issueCount = 1
			windowStartedAt = now
		} else {
			if issueCount >= authentication.EmailLinkMaxIssues {
				if err := tx.Commit(); err != nil {
					return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
				}
				return authentication.EmailLinkIssueResult{}, nil
			}
			issueCount++
		}
		generation++
		if _, err := tx.ExecContext(ctx, `
			UPDATE email_signin_links
			SET public_id=$3,secret_hash=$4,completion_url=$5,generation=$6,expires_at=$7,
			    failed_attempts=0,issue_count=$8,issue_window_started_at=$9,last_issued_at=$10,
			    consumed_at=NULL,updated_at=$10
			WHERE application_instance_id=$1 AND email_identifier_id=$2`,
			int64(issue.ApplicationInstanceID), emailID, issue.ChallengePublicID, issue.SecretHash[:], issue.CompletionURL,
			generation, expiresAt, issueCount, windowStartedAt, now,
		); err != nil {
			return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
		}
	}

	if err := insertEmailLinkAudit(ctx, tx, issue.ApplicationInstanceID, identity.InternalID(userID), "authentication.email_link.challenge_issued", "success", issue.CorrelationID, "email_link_challenge"); err != nil {
		return authentication.EmailLinkIssueResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.EmailLinkIssueResult{}, classifyEmailLink(ctx, err)
	}
	return authentication.EmailLinkIssueResult{ShouldSend: true, Destination: destination, ExpiresAt: expiresAt}, nil
}

func (s *Store) LoadEmailLink(ctx context.Context, appID applicationinstance.InternalID, challengeID string) (authentication.EmailLinkChallengeSnapshot, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !authentication.ValidEmailLinkChallengeID(challengeID) {
		return authentication.EmailLinkChallengeSnapshot{}, authentication.ErrEmailLinkInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var snapshot authentication.EmailLinkChallengeSnapshot
	var userID, emailID int64
	var secretHash []byte
	var consumedAt sql.NullTime
	var verifiedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT e.user_id,e.id,e.verified_at,l.public_id,l.generation,l.secret_hash,l.completion_url,l.expires_at,l.failed_attempts,l.consumed_at
		FROM email_identifiers e
		JOIN email_signin_links l
		  ON l.application_instance_id=e.application_instance_id AND l.email_identifier_id=e.id
		WHERE l.application_instance_id=$1 AND l.public_id=$2`, int64(appID), challengeID,
	).Scan(&userID, &emailID, &verifiedAt, &snapshot.ChallengePublicID, &snapshot.ChallengeGeneration, &secretHash, &snapshot.CompletionURL, &snapshot.ExpiresAt, &snapshot.FailedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.EmailLinkChallengeSnapshot{}, authentication.ErrEmailLinkInvalid
	}
	if err != nil {
		return authentication.EmailLinkChallengeSnapshot{}, classifyEmailLink(ctx, err)
	}
	if !verifiedAt.Valid || consumedAt.Valid || len(secretHash) != 32 || snapshot.FailedAttempts >= authentication.EmailLinkMaxAttempts {
		return authentication.EmailLinkChallengeSnapshot{}, authentication.ErrEmailLinkInvalid
	}
	snapshot.UserID = identity.InternalID(userID)
	snapshot.EmailIdentifierID = identity.EmailIdentifierInternalID(emailID)
	copy(snapshot.SecretHash[:], secretHash)
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	return snapshot, nil
}

func (s *Store) FinalizeEmailLink(ctx context.Context, finalize authentication.EmailLinkFinalize) (authentication.EmailLinkFinalizeResult, error) {
	if s == nil || s.pool == nil || !finalize.ApplicationInstanceID.Valid() || !finalize.EmailIdentifierID.Valid() || !finalize.UserID.Valid() || !authentication.ValidEmailLinkChallengeID(finalize.ChallengePublicID) || finalize.ChallengeGeneration <= 0 || finalize.CompletionURL == "" || finalize.CorrelationID == (audit.CorrelationID{}) {
		return authentication.EmailLinkFinalizeResult{}, authentication.ErrEmailLinkPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var verifiedAt sql.NullTime
	var currentUserID int64
	err = tx.QueryRowContext(ctx, `
		SELECT user_id,verified_at FROM email_identifiers
		WHERE application_instance_id=$1 AND id=$2 FOR UPDATE`,
		int64(finalize.ApplicationInstanceID), int64(finalize.EmailIdentifierID),
	).Scan(&currentUserID, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (!verifiedAt.Valid || currentUserID != int64(finalize.UserID))) {
		return authentication.EmailLinkFinalizeResult{}, authentication.ErrEmailLinkStale
	}
	if err != nil {
		return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
	}

	var generation int64
	var storedCompletion string
	var secretHash []byte
	var expiresAt time.Time
	var failedAttempts int
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT generation,completion_url,secret_hash,expires_at,failed_attempts,consumed_at
		FROM email_signin_links
		WHERE application_instance_id=$1 AND email_identifier_id=$2 AND public_id=$3
		FOR UPDATE`, int64(finalize.ApplicationInstanceID), int64(finalize.EmailIdentifierID), finalize.ChallengePublicID,
	).Scan(&generation, &storedCompletion, &secretHash, &expiresAt, &failedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.EmailLinkFinalizeResult{}, authentication.ErrEmailLinkInvalid
	}
	if err != nil {
		return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
	}
	if generation != finalize.ChallengeGeneration || storedCompletion != finalize.CompletionURL || consumedAt.Valid || len(secretHash) != 32 {
		return authentication.EmailLinkFinalizeResult{}, authentication.ErrEmailLinkStale
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
	}
	now = now.UTC()
	if !now.Before(expiresAt.UTC()) || failedAttempts >= authentication.EmailLinkMaxAttempts {
		if err := insertEmailLinkAudit(ctx, tx, finalize.ApplicationInstanceID, finalize.UserID, "authentication.email_link.confirm", "denied", finalize.CorrelationID, "email_link_challenge"); err != nil {
			return authentication.EmailLinkFinalizeResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
		}
		return authentication.EmailLinkFinalizeResult{}, authentication.ErrEmailLinkInvalid
	}
	if !finalize.Matched {
		if _, err := tx.ExecContext(ctx, `
			UPDATE email_signin_links SET failed_attempts=failed_attempts+1,updated_at=$4
			WHERE application_instance_id=$1 AND email_identifier_id=$2 AND public_id=$3`,
			int64(finalize.ApplicationInstanceID), int64(finalize.EmailIdentifierID), finalize.ChallengePublicID, now,
		); err != nil {
			return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
		}
		if err := insertEmailLinkAudit(ctx, tx, finalize.ApplicationInstanceID, finalize.UserID, "authentication.email_link.confirm", "denied", finalize.CorrelationID, "email_link_challenge"); err != nil {
			return authentication.EmailLinkFinalizeResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
		}
		return authentication.EmailLinkFinalizeResult{}, authentication.ErrEmailLinkInvalid
	}
	if !finalize.PendingMFA.Valid() || finalize.PendingMFA.PrimaryMethod != authentication.PrimaryMethodEmailLink {
		return authentication.EmailLinkFinalizeResult{}, authentication.ErrEmailLinkPersistence
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE email_signin_links SET consumed_at=$4,secret_hash=NULL,updated_at=$4
		WHERE application_instance_id=$1 AND email_identifier_id=$2 AND public_id=$3 AND consumed_at IS NULL`,
		int64(finalize.ApplicationInstanceID), int64(finalize.EmailIdentifierID), finalize.ChallengePublicID, now,
	); err != nil {
		return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
	}
	assurance, err := finalizePrimaryAssurance(ctx, tx, finalize.ApplicationInstanceID, finalize.UserID, primarySessionMaterial{
		PublicID:       finalize.SessionPublicID,
		RefreshHash:    finalize.RefreshVerifier,
		IdleExpiresAt:  finalize.IdleExpiresAt,
		ExpiresAt:      finalize.ExpiresAt,
		Pending:        finalize.PendingMFA,
		ExpectedMethod: authentication.PrimaryMethodEmailLink,
	})
	if err != nil {
		return authentication.EmailLinkFinalizeResult{}, authentication.ErrEmailLinkPersistence
	}
	resource := "session"
	if assurance.MFARequired {
		resource = "pending_mfa"
	}
	if err := insertEmailLinkAudit(ctx, tx, finalize.ApplicationInstanceID, finalize.UserID, "authentication.email_link.confirm", "success", finalize.CorrelationID, resource); err != nil {
		return authentication.EmailLinkFinalizeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.EmailLinkFinalizeResult{}, classifyEmailLink(ctx, err)
	}
	return authentication.EmailLinkFinalizeResult{
		UserPublicID:          assurance.UserPublicID,
		ApplicationPublicID:   assurance.ApplicationPublicID,
		MFARequired:           assurance.MFARequired,
		PendingMFAPublicID:    assurance.PendingMFAPublicID,
		PendingMFAExpiresAt:   assurance.PendingMFAExpiresAt,
		RecoveryCodeAvailable: assurance.RecoveryCodeAvailable,
	}, nil
}

func insertEmailLinkAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, action, outcome string, correlationID audit.CorrelationID, resource string) error {
	actorKind := "anonymous_email_link"
	var actorUser any
	if outcome == "success" && action == "authentication.email_link.confirm" {
		actorKind = "user"
		actorUser = int64(userID)
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,outcome,correlation_id,source)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'internal_email_link')`,
		int64(appID), actorKind, actorUser, int64(userID), action, resource, outcome, correlationID[:],
	)
	return classifyEmailLink(ctx, err)
}

func classifyEmailLink(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return authentication.ErrEmailLinkPersistence
}
