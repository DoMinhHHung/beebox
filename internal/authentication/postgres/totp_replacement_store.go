package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

func (s *Store) LoadTOTPReplacementRecoverySet(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID) (authentication.TOTPReplacementRecoverySet, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return authentication.TOTPReplacementRecoverySet{}, authentication.ErrRecoveryUnavailable
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var out authentication.TOTPReplacementRecoverySet
	err := db.QueryRowContext(ctx, `
		SELECT s.id,s.public_id FROM recovery_code_sets s
		JOIN totp_credentials t ON t.id=s.totp_credential_id
		WHERE s.application_instance_id=$1 AND s.user_id=$2 AND s.invalidated_at IS NULL
		  AND t.application_instance_id=$1 AND t.user_id=$2
		  AND EXISTS(SELECT 1 FROM recovery_codes c WHERE c.recovery_set_id=s.id AND c.consumed_at IS NULL)`, int64(appID), int64(userID)).Scan(&out.ID, &out.PublicID)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.TOTPReplacementRecoverySet{}, authentication.ErrRecoveryInvalid
	}
	if err != nil {
		return authentication.TOTPReplacementRecoverySet{}, classifyRecoveryError(ctx, err)
	}
	return out, nil
}

func (s *Store) CreateTOTPReplacement(ctx context.Context, current authentication.TOTPSession, write authentication.TOTPReplacementWrite) error {
	enrollment := write.Enrollment
	if s == nil || s.pool == nil || !publicid.IsUUIDv4(enrollment.EnrollmentID, "mfe") || !publicid.IsUUIDv4(enrollment.CredentialID, "mfc") || !validTOTPEnvelope(enrollment.Envelope) || write.RecoverySetID <= 0 || write.CodeHash == ([32]byte{}) || enrollment.ApplicationInstanceID != current.ApplicationInstanceID || enrollment.UserID != current.UserID || enrollment.SessionPublicID != current.SessionPublicID || enrollment.CorrelationID == (audit.CorrelationID{}) {
		return authentication.ErrRecoveryInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyRecoveryError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateFreshTOTPSessionTx(ctx, tx, current.ApplicationInstanceID, current.UserID, current.SessionPublicID); err != nil {
		return authentication.ErrRecoveryReverification
	}
	var credentialID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&credentialID); errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrRecoveryInvalid
	} else if err != nil {
		return classifyRecoveryError(ctx, err)
	}
	var setPublicID string
	var invalidatedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT public_id,invalidated_at FROM recovery_code_sets WHERE id=$1 AND application_instance_id=$2 AND user_id=$3 AND totp_credential_id=$4 FOR UPDATE`, write.RecoverySetID, int64(current.ApplicationInstanceID), int64(current.UserID), credentialID).Scan(&setPublicID, &invalidatedAt)
	if errors.Is(err, sql.ErrNoRows) || invalidatedAt.Valid {
		return authentication.ErrRecoveryInvalid
	}
	if err != nil {
		return classifyRecoveryError(ctx, err)
	}
	var codeID int64
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id,consumed_at FROM recovery_codes WHERE recovery_set_id=$1 AND code_hash=$2 FOR UPDATE`, write.RecoverySetID, write.CodeHash[:]).Scan(&codeID, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) || consumedAt.Valid {
		return authentication.ErrRecoveryInvalid
	}
	if err != nil {
		return classifyRecoveryError(ctx, err)
	}
	if err := admitSensitiveInitiationTx(ctx, tx, current.ApplicationInstanceID, current.UserID, current.SessionPublicID, "totp_enrollment_start"); err != nil {
		return err
	}
	consumeCode, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET consumed_at=CURRENT_TIMESTAMP WHERE id=$1 AND consumed_at IS NULL`, codeID)
	if err != nil {
		return classifyRecoveryError(ctx, err)
	}
	if rows, rowsErr := consumeCode.RowsAffected(); rowsErr != nil || rows != 1 {
		return authentication.ErrRecoveryReplay
	}
	if _, err := tx.ExecContext(ctx, `UPDATE totp_enrollments SET consumed_at=CURRENT_TIMESTAMP WHERE application_instance_id=$1 AND user_id=$2 AND consumed_at IS NULL`, int64(current.ApplicationInstanceID), int64(current.UserID)); err != nil {
		return classifyRecoveryError(ctx, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO totp_enrollments(
			public_id,credential_public_id,application_instance_id,user_id,session_public_id,
			encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,created_at,expires_at,
			purpose,replacement_recovery_set_id
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'replacement',$12)`,
		enrollment.EnrollmentID, enrollment.CredentialID, int64(current.ApplicationInstanceID), int64(current.UserID), current.SessionPublicID,
		enrollment.Envelope.Version, enrollment.Envelope.KeyID, enrollment.Envelope.Nonce, enrollment.Envelope.Ciphertext,
		enrollment.CreatedAt.UTC(), enrollment.ExpiresAt.UTC(), write.RecoverySetID); err != nil {
		return classifyRecoveryError(ctx, err)
	}
	if err := insertRecoveryAudit(ctx, tx, current.ApplicationInstanceID, current.UserID, audit.ActionTOTPReplacementStarted, audit.OutcomeSuccess, "recovery_set:"+setPublicID, enrollment.CorrelationID); err != nil {
		return authentication.ErrRecoveryPersistence
	}
	if err := tx.Commit(); err != nil {
		return classifyRecoveryError(ctx, err)
	}
	return nil
}

func (s *Store) LoadTOTPReplacement(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, enrollmentID string) (authentication.TOTPReplacementSnapshot, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || !publicid.IsUUIDv4(enrollmentID, "mfe") {
		return authentication.TOTPReplacementSnapshot{}, authentication.ErrTOTPEnrollmentInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var out authentication.TOTPReplacementSnapshot
	var version int
	var keyID string
	var nonce, ciphertext []byte
	err := db.QueryRowContext(ctx, `
		SELECT public_id,credential_public_id,application_instance_id,user_id,session_public_id,
		       encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,created_at,expires_at,replacement_recovery_set_id
		FROM totp_enrollments
		WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 AND purpose='replacement'
		  AND consumed_at IS NULL AND expires_at>CURRENT_TIMESTAMP`, int64(appID), int64(userID), enrollmentID).Scan(
		&out.EnrollmentID, &out.CredentialID, &out.ApplicationInstanceID, &out.UserID, &out.SessionPublicID,
		&version, &keyID, &nonce, &ciphertext, &out.CreatedAt, &out.ExpiresAt, &out.RecoverySetID)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.TOTPReplacementSnapshot{}, authentication.ErrTOTPEnrollmentInvalid
	}
	if err != nil {
		return authentication.TOTPReplacementSnapshot{}, classifyTOTPError(ctx, err)
	}
	out.Envelope = authentication.TOTPSecretEnvelope{Version: version, KeyID: keyID, Nonce: append([]byte(nil), nonce...), Ciphertext: append([]byte(nil), ciphertext...)}
	out.CreatedAt = out.CreatedAt.UTC()
	out.ExpiresAt = out.ExpiresAt.UTC()
	return out, nil
}

func (s *Store) ActivateTOTPReplacement(ctx context.Context, current authentication.TOTPSession, snapshot authentication.TOTPReplacementSnapshot, timestep int64, newSet authentication.RecoveryCodeSetWrite, correlationID audit.CorrelationID) (authentication.TOTPCredentialView, error) {
	if s == nil || s.pool == nil || snapshot.RecoverySetID <= 0 || timestep < 0 || !newSet.Valid() || newSet.Reason != "replacement" || newSet.ApplicationInstanceID != current.ApplicationInstanceID || newSet.UserID != current.UserID || newSet.SessionPublicID != current.SessionPublicID || correlationID == (audit.CorrelationID{}) {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPEnrollmentInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var credentialPublicID, sessionID, keyID string
	var version int
	var nonce, ciphertext []byte
	var expiresAt time.Time
	var recoverySetID int64
	err = tx.QueryRowContext(ctx, `
		SELECT credential_public_id,session_public_id,encryption_version,encryption_key_id,encryption_nonce,
		       encrypted_secret,expires_at,replacement_recovery_set_id
		FROM totp_enrollments
		WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 AND purpose='replacement' AND consumed_at IS NULL
		FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID), snapshot.EnrollmentID).Scan(
		&credentialPublicID, &sessionID, &version, &keyID, &nonce, &ciphertext, &expiresAt, &recoverySetID)
	if err != nil || credentialPublicID != snapshot.CredentialID || sessionID != snapshot.SessionPublicID || version != snapshot.Envelope.Version || keyID != snapshot.Envelope.KeyID || !bytes.Equal(nonce, snapshot.Envelope.Nonce) || !bytes.Equal(ciphertext, snapshot.Envelope.Ciphertext) || recoverySetID != snapshot.RecoverySetID {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPEnrollmentInvalid
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil || !now.Before(expiresAt) {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPEnrollmentInvalid
	}
	if err := validateFreshTOTPSessionTx(ctx, tx, current.ApplicationInstanceID, current.UserID, current.SessionPublicID); err != nil {
		return authentication.TOTPCredentialView{}, err
	}
	var credentialID int64
	if err := tx.QueryRowContext(ctx, `
		UPDATE totp_credentials SET public_id=$3,encryption_version=$4,encryption_key_id=$5,
		       encryption_nonce=$6,encrypted_secret=$7,last_accepted_timestep=$8,updated_at=$9
		WHERE application_instance_id=$1 AND user_id=$2
		RETURNING id`, int64(current.ApplicationInstanceID), int64(current.UserID), snapshot.CredentialID,
		version, keyID, nonce, ciphertext, timestep, now.UTC()).Scan(&credentialID); err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	invalidateSet, err := tx.ExecContext(ctx, `UPDATE recovery_code_sets SET invalidated_at=$4 WHERE application_instance_id=$1 AND user_id=$2 AND id=$3 AND invalidated_at IS NULL`, int64(current.ApplicationInstanceID), int64(current.UserID), snapshot.RecoverySetID, now.UTC())
	if err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	if rows, rowsErr := invalidateSet.RowsAffected(); rowsErr != nil || rows != 1 {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPEnrollmentInvalid
	}
	var newSetID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO recovery_code_sets(
			public_id,application_instance_id,user_id,totp_credential_id,created_by_session_public_id,reason,created_at
		) VALUES($1,$2,$3,$4,$5,'replacement',$6) RETURNING id`, newSet.PublicID, int64(current.ApplicationInstanceID), int64(current.UserID), credentialID, current.SessionPublicID, newSet.CreatedAt.UTC()).Scan(&newSetID); err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	for _, codeHash := range newSet.CodeHashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(recovery_set_id,code_hash) VALUES($1,$2)`, newSetID, codeHash[:]); err != nil {
			return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
		}
	}
	consumeEnrollment, err := tx.ExecContext(ctx, `UPDATE totp_enrollments SET consumed_at=$2 WHERE public_id=$1 AND consumed_at IS NULL`, snapshot.EnrollmentID, now.UTC())
	if err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	if rows, rowsErr := consumeEnrollment.RowsAffected(); rowsErr != nil || rows != 1 {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPReplay
	}
	if err := insertRecoveryAudit(ctx, tx, current.ApplicationInstanceID, current.UserID, audit.ActionTOTPReplacementCompleted, audit.OutcomeSuccess, "recovery_set:"+newSet.PublicID, correlationID); err != nil {
		return authentication.TOTPCredentialView{}, authentication.ErrRecoveryPersistence
	}
	if err := insertRecoveryAudit(ctx, tx, current.ApplicationInstanceID, current.UserID, audit.ActionRecoveryCodesGenerated, audit.OutcomeSuccess, "recovery_set:"+newSet.PublicID, correlationID); err != nil {
		return authentication.TOTPCredentialView{}, authentication.ErrRecoveryPersistence
	}
	if err := tx.Commit(); err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	return authentication.TOTPCredentialView{ID: snapshot.CredentialID, CreatedAt: now.UTC()}, nil
}
