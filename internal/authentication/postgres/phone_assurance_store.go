package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

// FinalizePhoneOTPWithAssurance consumes a proven phone OTP and atomically
// chooses between pending TOTP assurance and an ordinary BeeBox session.
func (s *Store) FinalizePhoneOTPWithAssurance(
	ctx context.Context,
	final authentication.PhoneOTPFinalize,
	pending authentication.PendingMFAWrite,
) (authentication.PhoneOTPFinalizeResult, authentication.PrimaryAssuranceResult, error) {
	if s == nil || s.pool == nil || !final.ApplicationInstanceID.Valid() || !final.PhoneIdentifierID.Valid() || !final.UserID.Valid() || final.ChallengeGeneration <= 0 || final.CorrelationID == (audit.CorrelationID{}) || !pending.Valid() || pending.PrimaryMethod != authentication.PrimaryMethodPhoneOTP {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPhoneOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var verifiedAt sql.NullTime
	var currentUserID int64
	err = tx.QueryRowContext(ctx, `
		SELECT user_id,verified_at FROM phone_identifiers
		WHERE application_instance_id=$1 AND id=$2
		FOR UPDATE`, int64(final.ApplicationInstanceID), int64(final.PhoneIdentifierID),
	).Scan(&currentUserID, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (!verifiedAt.Valid || currentUserID != int64(final.UserID))) {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPhoneOTPStale
	}
	if err != nil {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
	}

	var generation int64
	var encoded sql.NullString
	var expiresAt time.Time
	var failedAttempts int
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT generation,code_hash,expires_at,failed_attempts,consumed_at
		FROM phone_otp_signin_challenges
		WHERE application_instance_id=$1 AND phone_identifier_id=$2
		FOR UPDATE`, int64(final.ApplicationInstanceID), int64(final.PhoneIdentifierID),
	).Scan(&generation, &encoded, &expiresAt, &failedAttempts, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPhoneOTPInvalid
	}
	if err != nil {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
	}
	if generation != final.ChallengeGeneration || consumedAt.Valid || !encoded.Valid {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPhoneOTPStale
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
	}
	now = now.UTC()
	if !now.Before(expiresAt.UTC()) || failedAttempts >= authentication.PhoneOTPMaxAttempts {
		if err := insertPhoneOTPAudit(ctx, tx, final.ApplicationInstanceID, final.UserID, "authentication.phone_otp.confirm", "denied", final.CorrelationID, "phone_identifier"); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
		}
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPhoneOTPInvalid
	}
	if !final.Matched {
		if _, err := tx.ExecContext(ctx, `
			UPDATE phone_otp_signin_challenges
			SET failed_attempts=failed_attempts+1,updated_at=$3
			WHERE application_instance_id=$1 AND phone_identifier_id=$2`, int64(final.ApplicationInstanceID), int64(final.PhoneIdentifierID), now,
		); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
		}
		if err := insertPhoneOTPAudit(ctx, tx, final.ApplicationInstanceID, final.UserID, "authentication.phone_otp.confirm", "denied", final.CorrelationID, "phone_identifier"); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
		}
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, authentication.ErrPhoneOTPInvalid
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE phone_otp_signin_challenges
		SET consumed_at=$4,code_hash=NULL,updated_at=$4
		WHERE application_instance_id=$1 AND phone_identifier_id=$2 AND generation=$3 AND consumed_at IS NULL`,
		int64(final.ApplicationInstanceID), int64(final.PhoneIdentifierID), final.ChallengeGeneration, now,
	); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
	}

	assurance, err := finalizePrimaryAssurance(ctx, tx, final.ApplicationInstanceID, final.UserID, primarySessionMaterial{
		PublicID:       final.SessionPublicID,
		RefreshHash:    final.RefreshVerifier,
		IdleExpiresAt:  final.IdleExpiresAt,
		ExpiresAt:      final.ExpiresAt,
		Pending:        pending,
		ExpectedMethod: authentication.PrimaryMethodPhoneOTP,
	})
	if err != nil {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
	}
	resource := "session"
	if assurance.MFARequired {
		resource = "pending_mfa"
	}
	if err := insertPhoneOTPAudit(ctx, tx, final.ApplicationInstanceID, final.UserID, "authentication.phone_otp.confirm", "success", final.CorrelationID, resource); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.PhoneOTPFinalizeResult{}, authentication.PrimaryAssuranceResult{}, classifyPhoneOTP(ctx, err)
	}
	return authentication.PhoneOTPFinalizeResult{
		UserPublicID:        assurance.UserPublicID,
		ApplicationPublicID: assurance.ApplicationPublicID,
	}, assurance, nil
}
