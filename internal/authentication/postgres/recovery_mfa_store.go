package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
	"github.com/DoMinhHHung/beebox/internal/session"
)

func (s *Store) LoadPendingRecoveryAuthentication(ctx context.Context, pendingPublicID string, tokenHash [32]byte) (authentication.PendingRecoveryAuthenticationSnapshot, error) {
	if s == nil || s.pool == nil || !publicid.IsUUIDv4(pendingPublicID, "mfp") || tokenHash == ([32]byte{}) {
		return authentication.PendingRecoveryAuthenticationSnapshot{}, authentication.ErrRecoveryInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var out authentication.PendingRecoveryAuthenticationSnapshot
	var appID, userID int64
	var storedTokenHash []byte
	err := db.QueryRowContext(ctx, `
		SELECT p.public_id,p.token_hash,p.application_instance_id,p.user_id,p.primary_method,p.primary_context,
		       p.failed_attempts,p.expires_at,s.id,s.public_id
		FROM pending_mfa_authentications p
		JOIN recovery_code_sets s ON s.application_instance_id=p.application_instance_id AND s.user_id=p.user_id
		WHERE p.public_id=$1 AND p.token_hash=$2 AND p.purpose='authentication' AND p.required_factor='totp'
		  AND p.consumed_at IS NULL AND p.expires_at>CURRENT_TIMESTAMP AND p.failed_attempts<5
		  AND s.invalidated_at IS NULL
		  AND EXISTS(SELECT 1 FROM recovery_codes c WHERE c.recovery_set_id=s.id AND c.consumed_at IS NULL)`,
		pendingPublicID, tokenHash[:]).Scan(
		&out.PendingPublicID, &storedTokenHash, &appID, &userID, &out.PrimaryMethod, &out.PrimaryContext,
		&out.FailedAttempts, &out.ExpiresAt, &out.RecoverySetID, &out.RecoverySetPublicID)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PendingRecoveryAuthenticationSnapshot{}, authentication.ErrRecoveryInvalid
	}
	if err != nil {
		return authentication.PendingRecoveryAuthenticationSnapshot{}, classifyRecoveryError(ctx, err)
	}
	if !copyFixedHash32(&out.TokenHash, storedTokenHash) || out.TokenHash != tokenHash {
		return authentication.PendingRecoveryAuthenticationSnapshot{}, authentication.ErrRecoveryInvalid
	}
	out.ApplicationInstanceID = applicationinstance.InternalID(appID)
	out.UserID = identity.InternalID(userID)
	out.ExpiresAt = out.ExpiresAt.UTC()
	return out, nil
}

func (s *Store) FinalizePendingRecoveryAuthentication(ctx context.Context, final authentication.RecoveryAuthenticationFinalize) (authentication.RecoveryAuthenticationResult, error) {
	snapshot := final.Snapshot
	if s == nil || s.pool == nil || !publicid.IsUUIDv4(snapshot.PendingPublicID, "mfp") || snapshot.TokenHash == ([32]byte{}) || final.CodeHash == ([32]byte{}) || !session.ValidPublicID(final.SessionPublicID) || final.RefreshVerifier == ([32]byte{}) || final.IdleExpiresAt.IsZero() || final.ExpiresAt.IsZero() || !final.IdleExpiresAt.Before(final.ExpiresAt) || final.CorrelationID == (audit.CorrelationID{}) {
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var appID, userID int64
	var purpose, factor, primaryMethod, primaryContext string
	var failedAttempts int
	var expiresAt sql.NullTime
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT application_instance_id,user_id,purpose,required_factor,primary_method,primary_context,
		       failed_attempts,expires_at,consumed_at
		FROM pending_mfa_authentications
		WHERE public_id=$1 AND token_hash=$2 FOR UPDATE`, snapshot.PendingPublicID, snapshot.TokenHash[:]).Scan(
		&appID, &userID, &purpose, &factor, &primaryMethod, &primaryContext, &failedAttempts, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) || consumedAt.Valid || !expiresAt.Valid {
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryReplay
	}
	if err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	var now sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil || !now.Valid {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	if !now.Time.UTC().Before(expiresAt.Time.UTC()) || failedAttempts >= 5 {
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryInvalid
	}
	if appID != int64(snapshot.ApplicationInstanceID) || userID != int64(snapshot.UserID) || purpose != "authentication" || factor != "totp" || primaryMethod != snapshot.PrimaryMethod || primaryContext != snapshot.PrimaryContext {
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryInvalid
	}
	var setPublicID string
	var invalidatedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT public_id,invalidated_at FROM recovery_code_sets
		WHERE id=$1 AND application_instance_id=$2 AND user_id=$3 FOR UPDATE`,
		snapshot.RecoverySetID, appID, userID).Scan(&setPublicID, &invalidatedAt)
	if errors.Is(err, sql.ErrNoRows) || invalidatedAt.Valid || setPublicID != snapshot.RecoverySetPublicID {
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryInvalid
	}
	if err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	var codeID int64
	var codeConsumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT id,consumed_at FROM recovery_codes
		WHERE recovery_set_id=$1 AND code_hash=$2 FOR UPDATE`, snapshot.RecoverySetID, final.CodeHash[:]).Scan(&codeID, &codeConsumedAt)
	if errors.Is(err, sql.ErrNoRows) || codeConsumedAt.Valid {
		result, updateErr := tx.ExecContext(ctx, `
			UPDATE pending_mfa_authentications SET failed_attempts=failed_attempts+1
			WHERE public_id=$1 AND token_hash=$2 AND consumed_at IS NULL AND failed_attempts<5`,
			snapshot.PendingPublicID, snapshot.TokenHash[:])
		if updateErr != nil {
			return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, updateErr)
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil || rows != 1 {
			return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryReplay
		}
		if auditErr := insertRecoveryAudit(ctx, tx, snapshot.ApplicationInstanceID, snapshot.UserID, audit.ActionRecoveryCodeDenied, audit.OutcomeDenied, "recovery_set:"+snapshot.RecoverySetPublicID, final.CorrelationID); auditErr != nil {
			return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryPersistence
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, commitErr)
		}
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryInvalid
	}
	if err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	consumeCode, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL`, codeID, now.Time.UTC())
	if err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	consumedRows, err := consumeCode.RowsAffected()
	if err != nil || consumedRows != 1 {
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryReplay
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE pending_mfa_authentications SET consumed_at=$3
		WHERE public_id=$1 AND token_hash=$2 AND consumed_at IS NULL`, snapshot.PendingPublicID, snapshot.TokenHash[:], now.Time.UTC())
	if err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryReplay
	}
	var sessionID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at,mfa_method)
		VALUES($1,$2,$3,$4,$5,'recovery_code') RETURNING id`, final.SessionPublicID, appID, userID, final.IdleExpiresAt.UTC(), final.ExpiresAt.UTC()).Scan(&sessionID); err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) VALUES($1,$2)`, sessionID, final.RefreshVerifier[:]); err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	if err := insertRecoveryAudit(ctx, tx, snapshot.ApplicationInstanceID, snapshot.UserID, audit.ActionRecoveryCodeAuthenticated, audit.OutcomeSuccess, "recovery_set:"+snapshot.RecoverySetPublicID, final.CorrelationID); err != nil {
		return authentication.RecoveryAuthenticationResult{}, authentication.ErrRecoveryPersistence
	}
	var out authentication.RecoveryAuthenticationResult
	if err := tx.QueryRowContext(ctx, `
		SELECT u.public_id,a.public_id FROM users u
		JOIN application_instances a ON a.id=u.application_instance_id
		WHERE u.application_instance_id=$1 AND u.id=$2`, appID, userID).Scan(&out.UserPublicID, &out.ApplicationPublicID); err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.RecoveryAuthenticationResult{}, classifyRecoveryError(ctx, err)
	}
	return out, nil
}
