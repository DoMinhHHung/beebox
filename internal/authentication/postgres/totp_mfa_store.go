package postgres

import (
	"bytes"
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

func (s *Store) LoadPendingTOTPAuthentication(ctx context.Context, pendingPublicID string, tokenHash [32]byte) (authentication.PendingTOTPAuthenticationSnapshot, error) {
	if s == nil || s.pool == nil || !publicid.IsUUIDv4(pendingPublicID, "mfp") || tokenHash == ([32]byte{}) {
		return authentication.PendingTOTPAuthenticationSnapshot{}, authentication.ErrPendingMFAInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var out authentication.PendingTOTPAuthenticationSnapshot
	var appID, userID int64
	var version int
	var keyID, credentialID string
	var nonce, ciphertext []byte
	var last sql.NullInt64
	err := db.QueryRowContext(ctx, `
		SELECT p.public_id,p.token_hash,p.application_instance_id,p.user_id,p.primary_method,p.primary_context,p.expires_at,
		       c.public_id,c.encryption_version,c.encryption_key_id,c.encryption_nonce,c.encrypted_secret,c.last_accepted_timestep
		FROM pending_mfa_authentications p
		JOIN totp_credentials c ON c.application_instance_id=p.application_instance_id AND c.user_id=p.user_id
		WHERE p.public_id=$1 AND p.token_hash=$2 AND p.purpose='authentication' AND p.required_factor='totp'
		  AND p.consumed_at IS NULL AND p.expires_at>CURRENT_TIMESTAMP`, pendingPublicID, tokenHash[:],
	).Scan(&out.PendingPublicID, &out.TokenHash, &appID, &userID, &out.PrimaryMethod, &out.PrimaryContext, &out.ExpiresAt,
		&credentialID, &version, &keyID, &nonce, &ciphertext, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PendingTOTPAuthenticationSnapshot{}, authentication.ErrPendingMFAInvalid
	}
	if err != nil {
		return authentication.PendingTOTPAuthenticationSnapshot{}, classifyTOTPError(ctx, err)
	}
	out.ApplicationInstanceID = applicationinstance.InternalID(appID)
	out.UserID = identity.InternalID(userID)
	out.CredentialID = credentialID
	out.Envelope = authentication.TOTPSecretEnvelope{Version: version, KeyID: keyID, Nonce: append([]byte(nil), nonce...), Ciphertext: append([]byte(nil), ciphertext...)}
	if last.Valid {
		value := last.Int64
		out.LastAcceptedTimestep = &value
	}
	out.ExpiresAt = out.ExpiresAt.UTC()
	return out, nil
}

func (s *Store) FinalizePendingTOTPAuthentication(ctx context.Context, final authentication.TOTPAuthenticationFinalize) (authentication.TOTPAuthenticationResult, error) {
	if s == nil || s.pool == nil || !publicid.IsUUIDv4(final.PendingPublicID, "mfp") || final.TokenHash == ([32]byte{}) || final.Timestep < 0 || !session.ValidPublicID(final.SessionPublicID) || final.RefreshVerifier == ([32]byte{}) || final.IdleExpiresAt.IsZero() || final.ExpiresAt.IsZero() || !final.IdleExpiresAt.Before(final.ExpiresAt) || final.CorrelationID == (audit.CorrelationID{}) {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrPendingMFAInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var appID, userID int64
	var primaryMethod, primaryContext, purpose, factor string
	var expiresAt sql.NullTime
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT application_instance_id,user_id,purpose,primary_method,primary_context,required_factor,expires_at,consumed_at
		FROM pending_mfa_authentications
		WHERE public_id=$1 AND token_hash=$2
		FOR UPDATE`, final.PendingPublicID, final.TokenHash[:],
	).Scan(&appID, &userID, &purpose, &primaryMethod, &primaryContext, &factor, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) || consumedAt.Valid || !expiresAt.Valid {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrPendingMFAInvalid
	}
	if err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	var now sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil || !now.Valid {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	if !now.Time.UTC().Before(expiresAt.Time.UTC()) {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrPendingMFAExpired
	}
	snapshot := final.Snapshot
	if purpose != "authentication" || factor != "totp" || appID != int64(snapshot.ApplicationInstanceID) || userID != int64(snapshot.UserID) || primaryMethod != snapshot.PrimaryMethod || primaryContext != snapshot.PrimaryContext || snapshot.PendingPublicID != final.PendingPublicID || snapshot.TokenHash != final.TokenHash {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrPendingMFAInvalid
	}

	var credentialID, keyID string
	var version int
	var nonce, ciphertext []byte
	var last sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT public_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,last_accepted_timestep
		FROM totp_credentials
		WHERE application_instance_id=$1 AND user_id=$2
		FOR UPDATE`, appID, userID,
	).Scan(&credentialID, &version, &keyID, &nonce, &ciphertext, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrPendingMFAInvalid
	}
	if err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	if credentialID != snapshot.CredentialID || version != snapshot.Envelope.Version || keyID != snapshot.Envelope.KeyID || !bytes.Equal(nonce, snapshot.Envelope.Nonce) || !bytes.Equal(ciphertext, snapshot.Envelope.Ciphertext) {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrPendingMFAInvalid
	}
	if last.Valid && final.Timestep <= last.Int64 {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrTOTPReplay
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE totp_credentials SET last_accepted_timestep=$3,updated_at=$4
		WHERE application_instance_id=$1 AND user_id=$2`, appID, userID, final.Timestep, now.Time.UTC()); err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE pending_mfa_authentications SET consumed_at=$3
		WHERE public_id=$1 AND token_hash=$2 AND consumed_at IS NULL`, final.PendingPublicID, final.TokenHash[:], now.Time.UTC())
	if err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrPendingMFAReplay
	}
	var sessionID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sessions(public_id,application_instance_id,user_id,idle_expires_at,expires_at)
		VALUES($1,$2,$3,$4,$5) RETURNING id`, final.SessionPublicID, appID, userID, final.IdleExpiresAt.UTC(), final.ExpiresAt.UTC()).Scan(&sessionID); err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_refresh_credentials(session_id,verifier_hash) VALUES($1,$2)`, sessionID, final.RefreshVerifier[:]); err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	if err := insertTOTPAudit(ctx, tx, snapshot.ApplicationInstanceID, snapshot.UserID, audit.ActionTOTPAuthenticated, audit.OutcomeSuccess, "totp:"+credentialID, final.CorrelationID); err != nil {
		return authentication.TOTPAuthenticationResult{}, authentication.ErrTOTPPersistence
	}
	var out authentication.TOTPAuthenticationResult
	if err := tx.QueryRowContext(ctx, `
		SELECT u.public_id,a.public_id FROM users u
		JOIN application_instances a ON a.id=u.application_instance_id
		WHERE u.application_instance_id=$1 AND u.id=$2`, appID, userID).Scan(&out.UserPublicID, &out.ApplicationPublicID); err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return authentication.TOTPAuthenticationResult{}, classifyTOTPError(ctx, err)
	}
	return out, nil
}
