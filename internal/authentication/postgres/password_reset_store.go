package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func (s *Store) IssuePasswordReset(ctx context.Context, issue authentication.PasswordResetIssue) (authentication.PasswordResetIssueResult, error) {
	if s == nil || s.pool == nil || !issue.ApplicationInstanceID.Valid() || !issue.CodeHash.Valid() || issue.NormalizedEmail == "" {
		return authentication.PasswordResetIssueResult{}, authentication.ErrPasswordResetPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
	}
	now = now.UTC()
	identifierHash := resetIdentifierHash(issue.NormalizedEmail)
	globalLimited, err := incrementResetRate(ctx, tx, issue.ApplicationInstanceID, "password_reset_global", [32]byte{1}, 100, time.Minute, now)
	if err != nil {
		return authentication.PasswordResetIssueResult{}, err
	}
	identifierLimited, err := incrementResetRate(ctx, tx, issue.ApplicationInstanceID, "password_reset_identifier", identifierHash, 5, 15*time.Minute, now)
	if err != nil {
		return authentication.PasswordResetIssueResult{}, err
	}
	if globalLimited || identifierLimited {
		if err := tx.Commit(); err != nil {
			return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
		}
		return authentication.PasswordResetIssueResult{}, authentication.ErrPasswordResetRateLimited
	}

	var emailID, userID int64
	var destination string
	err = tx.QueryRowContext(ctx, `
		SELECT e.id, e.user_id, e.email_address
		FROM email_identifiers e
		JOIN password_credentials p ON p.application_instance_id = e.application_instance_id AND p.user_id = e.user_id
		WHERE e.application_instance_id = $1 AND e.normalized_email = $2 AND e.verified_at IS NOT NULL`,
		int64(issue.ApplicationInstanceID), issue.NormalizedEmail,
	).Scan(&emailID, &userID, &destination)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
		}
		return authentication.PasswordResetIssueResult{}, nil
	}
	if err != nil {
		return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
	}

	var generation int64
	var failedAttempts, issueCount int
	var windowStarted, lastIssued time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT generation, failed_attempts, issue_count, issue_window_started_at, last_issued_at
		FROM password_reset_challenges
		WHERE application_instance_id = $1 AND user_id = $2
		FOR UPDATE`, int64(issue.ApplicationInstanceID), userID,
	).Scan(&generation, &failedAttempts, &issueCount, &windowStarted, &lastIssued)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
	}
	newWindow := errors.Is(err, sql.ErrNoRows) || !windowStarted.Add(authentication.PasswordResetIssueWindow).After(now)
	if !newWindow {
		if lastIssued.Add(authentication.PasswordResetResendCooldown).After(now) || issueCount >= authentication.PasswordResetMaxIssues {
			if err := tx.Commit(); err != nil {
				return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
			}
			return authentication.PasswordResetIssueResult{}, authentication.ErrPasswordResetRateLimited
		}
		generation++
		issueCount++
	} else {
		if generation <= 0 {
			generation = 1
		} else {
			generation++
		}
		failedAttempts = 0
		issueCount = 1
		windowStarted = now
	}
	expiresAt := now.Add(authentication.PasswordResetCodeTTL)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO password_reset_challenges (
			application_instance_id, user_id, email_identifier_id, generation, code_hash,
			expires_at, failed_attempts, issue_count, issue_window_started_at, last_issued_at,
			consumed_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$10)
		ON CONFLICT (application_instance_id, user_id) DO UPDATE SET
			email_identifier_id = EXCLUDED.email_identifier_id,
			generation = EXCLUDED.generation,
			code_hash = EXCLUDED.code_hash,
			expires_at = EXCLUDED.expires_at,
			failed_attempts = EXCLUDED.failed_attempts,
			issue_count = EXCLUDED.issue_count,
			issue_window_started_at = EXCLUDED.issue_window_started_at,
			last_issued_at = EXCLUDED.last_issued_at,
			consumed_at = NULL,
			updated_at = EXCLUDED.updated_at`,
		int64(issue.ApplicationInstanceID), userID, emailID, generation, issue.CodeHash.StorageEncoding(), expiresAt,
		failedAttempts, issueCount, windowStarted, now,
	)
	if err != nil {
		return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
	}
	if err := insertResetAudit(ctx, tx, issue.ApplicationInstanceID, identity.InternalID(userID), "authentication.password_reset.issued", "success", issue.CorrelationID[:]); err != nil {
		return authentication.PasswordResetIssueResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.PasswordResetIssueResult{}, resetClassify(ctx, err)
	}
	return authentication.PasswordResetIssueResult{ShouldSend: true, Destination: destination, ExpiresAt: expiresAt}, nil
}

func (s *Store) LoadPasswordReset(ctx context.Context, appID applicationinstance.InternalID, normalizedEmail string) (authentication.PasswordResetSnapshot, error) {
	if s == nil || s.pool == nil || !appID.Valid() || normalizedEmail == "" {
		return authentication.PasswordResetSnapshot{}, authentication.ErrPasswordResetPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var snapshot authentication.PasswordResetSnapshot
	var userID, emailID int64
	var encoded string
	err := db.QueryRowContext(ctx, `
		SELECT c.user_id, c.email_identifier_id, c.generation, p.generation, c.code_hash, c.expires_at, c.failed_attempts
		FROM password_reset_challenges c
		JOIN email_identifiers e ON e.application_instance_id = c.application_instance_id AND e.id = c.email_identifier_id
		JOIN password_credentials p ON p.application_instance_id = c.application_instance_id AND p.user_id = c.user_id
		WHERE c.application_instance_id = $1 AND e.normalized_email = $2 AND e.verified_at IS NOT NULL
		  AND c.consumed_at IS NULL AND c.code_hash IS NOT NULL`, int64(appID), normalizedEmail,
	).Scan(&userID, &emailID, &snapshot.ChallengeGeneration, &snapshot.CredentialGeneration, &encoded, &snapshot.ExpiresAt, &snapshot.FailedAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PasswordResetSnapshot{}, authentication.ErrPasswordResetFailed
	}
	if err != nil {
		return authentication.PasswordResetSnapshot{}, resetClassify(ctx, err)
	}
	hash, err := authentication.ParsePasswordResetCodeHash(encoded)
	if err != nil {
		return authentication.PasswordResetSnapshot{}, authentication.ErrPasswordResetPersistence
	}
	snapshot.UserID = identity.InternalID(userID)
	snapshot.EmailIdentifierID = identity.EmailIdentifierInternalID(emailID)
	snapshot.CodeHash = hash
	snapshot.ExpiresAt = snapshot.ExpiresAt.UTC()
	return snapshot, nil
}

func (s *Store) FinalizePasswordReset(ctx context.Context, final authentication.PasswordResetFinalize) error {
	if s == nil || s.pool == nil || !final.ApplicationInstanceID.Valid() || !final.UserID.Valid() || !final.EmailIdentifierID.Valid() || final.CorrelationID == ([16]byte{}) {
		return authentication.ErrPasswordResetPersistence
	}
	if final.Matched && !final.NewPasswordHash.Valid() {
		return authentication.ErrPasswordResetPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return resetClassify(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var generation, credentialGeneration int64
	var failedAttempts int
	var expiresAt time.Time
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT c.generation, c.failed_attempts, c.expires_at, c.consumed_at, p.generation
		FROM password_reset_challenges c
		JOIN password_credentials p ON p.application_instance_id = c.application_instance_id AND p.user_id = c.user_id
		JOIN email_identifiers e ON e.application_instance_id = c.application_instance_id AND e.id = c.email_identifier_id
		WHERE c.application_instance_id = $1 AND c.user_id = $2 AND c.email_identifier_id = $3 AND e.verified_at IS NOT NULL
		FOR UPDATE OF c, p`, int64(final.ApplicationInstanceID), int64(final.UserID), int64(final.EmailIdentifierID),
	).Scan(&generation, &failedAttempts, &expiresAt, &consumedAt, &credentialGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrPasswordResetFailed
	}
	if err != nil {
		return resetClassify(ctx, err)
	}
	if generation != final.ChallengeGeneration || credentialGeneration != final.CredentialGeneration {
		return authentication.ErrPasswordResetStale
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return resetClassify(ctx, err)
	}
	now = now.UTC()
	if consumedAt.Valid || !expiresAt.After(now) || failedAttempts >= authentication.PasswordResetMaxAttempts {
		return authentication.ErrPasswordResetFailed
	}
	if !final.Matched {
		if _, err := tx.ExecContext(ctx, `UPDATE password_reset_challenges SET failed_attempts = failed_attempts + 1, updated_at = $4 WHERE application_instance_id = $1 AND user_id = $2 AND generation = $3`, int64(final.ApplicationInstanceID), int64(final.UserID), generation, now); err != nil {
			return resetClassify(ctx, err)
		}
		if err := insertResetAudit(ctx, tx, final.ApplicationInstanceID, final.UserID, "authentication.password_reset.confirm", "denied", final.CorrelationID[:]); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return resetClassify(ctx, err)
		}
		return nil
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE password_credentials
		SET password_hash = $4, generation = generation + 1, updated_at = $5
		WHERE application_instance_id = $1 AND user_id = $2 AND generation = $3`,
		int64(final.ApplicationInstanceID), int64(final.UserID), final.CredentialGeneration, final.NewPasswordHash.StorageEncoding(), now,
	)
	if err != nil {
		return resetClassify(ctx, err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return authentication.ErrPasswordResetStale
	}
	if _, err := tx.ExecContext(ctx, `UPDATE password_reset_challenges SET consumed_at = $4, code_hash = NULL, updated_at = $4 WHERE application_instance_id = $1 AND user_id = $2 AND generation = $3`, int64(final.ApplicationInstanceID), int64(final.UserID), generation, now); err != nil {
		return resetClassify(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at,$3) WHERE application_instance_id = $1 AND user_id = $2`, int64(final.ApplicationInstanceID), int64(final.UserID), now); err != nil {
		return resetClassify(ctx, err)
	}
	if err := insertResetAudit(ctx, tx, final.ApplicationInstanceID, final.UserID, "authentication.password_reset.confirm", "success", final.CorrelationID[:]); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return resetClassify(ctx, err)
	}
	return nil
}

func incrementResetRate(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, operation string, subjectHash [32]byte, limit int, window time.Duration, now time.Time) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO public_auth_rate_limits (application_instance_id, operation, subject_hash, window_started_at, request_count, expires_at)
		VALUES ($1,$2,$3,$4,1,$5)
		ON CONFLICT (application_instance_id, operation, subject_hash) DO UPDATE SET
			window_started_at = CASE WHEN public_auth_rate_limits.expires_at <= EXCLUDED.window_started_at THEN EXCLUDED.window_started_at ELSE public_auth_rate_limits.window_started_at END,
			request_count = CASE WHEN public_auth_rate_limits.expires_at <= EXCLUDED.window_started_at THEN 1 ELSE public_auth_rate_limits.request_count + 1 END,
			expires_at = CASE WHEN public_auth_rate_limits.expires_at <= EXCLUDED.window_started_at THEN EXCLUDED.expires_at ELSE public_auth_rate_limits.expires_at END
		RETURNING request_count`, int64(appID), operation, subjectHash[:], now, now.Add(window)).Scan(&count); err != nil {
		return false, resetClassify(ctx, err)
	}
	return count > limit, nil
}

func resetIdentifierHash(normalizedEmail string) [32]byte {
	return sha256Sum("password-reset-email\x00" + normalizedEmail)
}

func sha256Sum(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func insertResetAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, action, outcome string, correlation []byte) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (application_instance_id, actor_kind, subject_user_id, action, resource_category, outcome, correlation_id, source)
		VALUES ($1,'anonymous_password_reset',$2,$3,'user',$4,$5,'internal_password_reset')`, int64(appID), int64(userID), action, outcome, correlation)
	return resetClassify(ctx, err)
}

func resetClassify(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return authentication.ErrPasswordResetPersistence
}
