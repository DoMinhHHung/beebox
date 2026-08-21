package postgres

import (
	"context"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

// FinalizePasskeyAuthenticationWithAssurance persists the verified authenticator
// state and atomically chooses pending TOTP or an ordinary BeeBox session.
func (s *Store) FinalizePasskeyAuthenticationWithAssurance(
	ctx context.Context,
	final authentication.PasskeyAuthFinalize,
	pending authentication.PendingMFAWrite,
) (authentication.PasskeyAuthResult, authentication.PrimaryAssuranceResult, error) {
	if s == nil || s.pool == nil || !authentication.ValidPasskeyAttemptPublicID(final.AttemptPublicID) || !final.UserID.Valid() || len(final.Credential.CredentialID) == 0 || len(final.Credential.CredentialJSON) == 0 || final.Credential.RPID == "" || correlationZero(final.CorrelationID) || !pending.Valid() || pending.PrimaryMethod != authentication.PrimaryMethodPasskey {
		return authentication.PasskeyAuthResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPasskeyPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PasskeyAuthResult{}, authentication.PrimaryAssuranceResult{}, classifyPasskeyError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var appID int64
	var appPublic, userPublic string
	err = tx.QueryRowContext(ctx, `
		SELECT p.application_instance_id,a.public_id,u.public_id
		FROM passkey_attempts p
		JOIN application_instances a ON a.id=p.application_instance_id
		JOIN users u ON u.application_instance_id=p.application_instance_id AND u.id=$2
		WHERE p.public_id=$1 AND p.purpose='authentication' AND p.consumed_at IS NOT NULL AND p.expires_at>CURRENT_TIMESTAMP
		FOR SHARE OF p`, final.AttemptPublicID, int64(final.UserID)).Scan(&appID, &appPublic, &userPublic)
	if err != nil {
		return authentication.PasskeyAuthResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPasskeyInvalidAttempt
	}
	var credentialPublic string
	err = tx.QueryRowContext(ctx, `
		SELECT public_id FROM passkey_credentials
		WHERE application_instance_id=$1 AND user_id=$2 AND rp_id=$3 AND credential_id=$4
		FOR UPDATE`, appID, int64(final.UserID), final.Credential.RPID, final.Credential.CredentialID).Scan(&credentialPublic)
	if err != nil {
		return authentication.PasskeyAuthResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPasskeyProof
	}
	if _, err = tx.ExecContext(ctx, `
		UPDATE passkey_credentials SET credential_json=$1::jsonb,updated_at=CURRENT_TIMESTAMP
		WHERE application_instance_id=$2 AND user_id=$3 AND public_id=$4`,
		string(final.Credential.CredentialJSON), appID, int64(final.UserID), credentialPublic); err != nil {
		return authentication.PasskeyAuthResult{}, authentication.PrimaryAssuranceResult{}, classifyPasskeyError(ctx, err)
	}

	assurance, err := finalizePrimaryAssurance(ctx, tx, applicationinstance.InternalID(appID), final.UserID, primarySessionMaterial{
		PublicID:       final.SessionPublicID,
		RefreshHash:    final.RefreshVerifier,
		IdleExpiresAt:  final.IdleExpiresAt,
		ExpiresAt:      final.ExpiresAt,
		Pending:        pending,
		ExpectedMethod: authentication.PrimaryMethodPasskey,
	})
	if err != nil {
		return authentication.PasskeyAuthResult{}, authentication.PrimaryAssuranceResult{}, classifyPasskeyError(ctx, err)
	}
	if err = insertPasskeyAudit(ctx, tx, applicationinstance.InternalID(appID), final.UserID, audit.ActionPasskeyAuthenticated, audit.OutcomeSuccess, "passkey:"+credentialPublic, final.CorrelationID); err != nil {
		return authentication.PasskeyAuthResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPasskeyPersistence
	}
	if err = tx.Commit(); err != nil {
		return authentication.PasskeyAuthResult{}, authentication.PrimaryAssuranceResult{}, classifyPasskeyError(ctx, err)
	}
	return authentication.PasskeyAuthResult{
		UserPublicID:        identity.PublicID(userPublic),
		ApplicationPublicID: applicationinstance.PublicID(appPublic),
	}, assurance, nil
}
