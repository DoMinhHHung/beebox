package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
	"github.com/DoMinhHHung/beebox/internal/platform/publicid"
)

type SecretEncryptionReference struct {
	Version int
	KeyID   string
}

func (s *Store) TOTPSecretEncryptionReferences(ctx context.Context) ([]SecretEncryptionReference, error) {
	if s == nil || s.pool == nil {
		return nil, authentication.ErrTOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT encryption_version,encryption_key_id FROM (
			SELECT encryption_version,encryption_key_id FROM totp_credentials
			UNION ALL
			SELECT encryption_version,encryption_key_id FROM totp_enrollments WHERE consumed_at IS NULL
		) refs ORDER BY encryption_version,encryption_key_id`)
	if err != nil {
		return nil, classifyTOTPError(ctx, err)
	}
	defer rows.Close()
	var out []SecretEncryptionReference
	for rows.Next() {
		var ref SecretEncryptionReference
		if err := rows.Scan(&ref.Version, &ref.KeyID); err != nil {
			return nil, authentication.ErrTOTPPersistence
		}
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, authentication.ErrTOTPPersistence
	}
	return out, nil
}

func (s *Store) HasActiveTOTP(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID) (bool, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return false, authentication.ErrTOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2)`, int64(appID), int64(userID)).Scan(&exists); err != nil {
		return false, classifyTOTPError(ctx, err)
	}
	return exists, nil
}

func (s *Store) CreateTOTPEnrollment(ctx context.Context, write authentication.TOTPEnrollmentWrite) error {
	if s == nil || s.pool == nil || !write.ApplicationInstanceID.Valid() || !write.UserID.Valid() || !publicid.IsUUIDv4(write.EnrollmentID, "mfe") || !publicid.IsUUIDv4(write.CredentialID, "mfc") || write.SessionPublicID == "" || !validTOTPEnvelope(write.Envelope) || !write.ExpiresAt.After(write.CreatedAt) || write.CorrelationID == (audit.CorrelationID{}) {
		return authentication.ErrTOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyTOTPError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := validateFreshTOTPSessionTx(ctx, tx, write.ApplicationInstanceID, write.UserID, write.SessionPublicID); err != nil {
		return err
	}
	if err := admitSensitiveInitiationTx(ctx, tx, write.ApplicationInstanceID, write.UserID, write.SessionPublicID, "totp_enrollment_start"); err != nil {
		if errors.Is(err, authentication.ErrRecoveryRateLimited) {
			return authentication.ErrTOTPEnrollmentRateLimited
		}
		return authentication.ErrTOTPPersistence
	}
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2)`, int64(write.ApplicationInstanceID), int64(write.UserID)).Scan(&active); err != nil {
		return classifyTOTPError(ctx, err)
	}
	if active {
		return authentication.ErrTOTPAlreadyActive
	}
	if _, err := tx.ExecContext(ctx, `UPDATE totp_enrollments SET consumed_at=CURRENT_TIMESTAMP WHERE application_instance_id=$1 AND user_id=$2 AND consumed_at IS NULL AND CURRENT_TIMESTAMP<=expires_at`, int64(write.ApplicationInstanceID), int64(write.UserID)); err != nil {
		return classifyTOTPError(ctx, err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO totp_enrollments(public_id,credential_public_id,application_instance_id,user_id,session_public_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, write.EnrollmentID, write.CredentialID, int64(write.ApplicationInstanceID), int64(write.UserID), write.SessionPublicID, write.Envelope.Version, write.Envelope.KeyID, write.Envelope.Nonce, write.Envelope.Ciphertext, write.CreatedAt.UTC(), write.ExpiresAt.UTC())
	if err != nil {
		return classifyTOTPError(ctx, err)
	}
	if err := insertTOTPAudit(ctx, tx, write.ApplicationInstanceID, write.UserID, audit.ActionTOTPEnrollmentStarted, audit.OutcomeSuccess, "totp:"+write.CredentialID, write.CorrelationID); err != nil {
		return authentication.ErrTOTPPersistence
	}
	if err := tx.Commit(); err != nil {
		return classifyTOTPError(ctx, err)
	}
	return nil
}

func (s *Store) LoadTOTPEnrollment(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID, enrollmentID string) (authentication.TOTPEnrollmentSnapshot, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() || !publicid.IsUUIDv4(enrollmentID, "mfe") {
		return authentication.TOTPEnrollmentSnapshot{}, authentication.ErrTOTPEnrollmentInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var out authentication.TOTPEnrollmentSnapshot
	var version int
	var keyID string
	var nonce, ciphertext []byte
	err := db.QueryRowContext(ctx, `SELECT public_id,credential_public_id,application_instance_id,user_id,session_public_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,created_at,expires_at FROM totp_enrollments WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 AND consumed_at IS NULL AND expires_at>CURRENT_TIMESTAMP`, int64(appID), int64(userID), enrollmentID).Scan(&out.EnrollmentID, &out.CredentialID, &out.ApplicationInstanceID, &out.UserID, &out.SessionPublicID, &version, &keyID, &nonce, &ciphertext, &out.CreatedAt, &out.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.TOTPEnrollmentSnapshot{}, authentication.ErrTOTPEnrollmentInvalid
	}
	if err != nil {
		return authentication.TOTPEnrollmentSnapshot{}, classifyTOTPError(ctx, err)
	}
	out.Envelope = authentication.TOTPSecretEnvelope{Version: version, KeyID: keyID, Nonce: append([]byte(nil), nonce...), Ciphertext: append([]byte(nil), ciphertext...)}
	out.CreatedAt = out.CreatedAt.UTC()
	out.ExpiresAt = out.ExpiresAt.UTC()
	return out, nil
}

func (s *Store) ActivateTOTPEnrollment(ctx context.Context, snapshot authentication.TOTPEnrollmentSnapshot, timestep int64, recoverySet authentication.RecoveryCodeSetWrite, correlationID audit.CorrelationID) (authentication.TOTPCredentialView, error) {
	if s == nil || s.pool == nil || !snapshot.ApplicationInstanceID.Valid() || !snapshot.UserID.Valid() || !publicid.IsUUIDv4(snapshot.EnrollmentID, "mfe") || !publicid.IsUUIDv4(snapshot.CredentialID, "mfc") || timestep < 0 || !recoverySet.Valid() || recoverySet.ApplicationInstanceID != snapshot.ApplicationInstanceID || recoverySet.UserID != snapshot.UserID || recoverySet.SessionPublicID != snapshot.SessionPublicID || recoverySet.Reason != "activation" || correlationID == (audit.CorrelationID{}) {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPEnrollmentInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var credentialID, sessionID, keyID string
	var version int
	var nonce, ciphertext []byte
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT credential_public_id,session_public_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,expires_at FROM totp_enrollments WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3 AND consumed_at IS NULL FOR UPDATE`, int64(snapshot.ApplicationInstanceID), int64(snapshot.UserID), snapshot.EnrollmentID).Scan(&credentialID, &sessionID, &version, &keyID, &nonce, &ciphertext, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPEnrollmentInvalid
	}
	if err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	if !now.Before(expiresAt) || credentialID != snapshot.CredentialID || sessionID != snapshot.SessionPublicID || version != snapshot.Envelope.Version || keyID != snapshot.Envelope.KeyID || !bytes.Equal(nonce, snapshot.Envelope.Nonce) || !bytes.Equal(ciphertext, snapshot.Envelope.Ciphertext) {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPEnrollmentInvalid
	}
	if err := validateFreshTOTPSessionTx(ctx, tx, snapshot.ApplicationInstanceID, snapshot.UserID, sessionID); err != nil {
		return authentication.TOTPCredentialView{}, err
	}
	var out authentication.TOTPCredentialView
	err = tx.QueryRowContext(ctx, `INSERT INTO totp_credentials(public_id,application_instance_id,user_id,encryption_version,encryption_key_id,encryption_nonce,encrypted_secret,last_accepted_timestep) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING public_id,created_at`, credentialID, int64(snapshot.ApplicationInstanceID), int64(snapshot.UserID), version, keyID, nonce, ciphertext, timestep).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	var recoverySetID int64
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO recovery_code_sets(
			public_id,application_instance_id,user_id,totp_credential_id,created_by_session_public_id,reason,created_at
		) SELECT $1,$2,$3,id,$4,'activation',$5 FROM totp_credentials
		WHERE application_instance_id=$2 AND user_id=$3 AND public_id=$6
		RETURNING id`, recoverySet.PublicID, int64(snapshot.ApplicationInstanceID), int64(snapshot.UserID), recoverySet.SessionPublicID, recoverySet.CreatedAt.UTC(), out.ID).Scan(&recoverySetID); err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	for _, codeHash := range recoverySet.CodeHashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(recovery_set_id,code_hash) VALUES($1,$2)`, recoverySetID, codeHash[:]); err != nil {
			return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE totp_enrollments SET consumed_at=CURRENT_TIMESTAMP WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3`, int64(snapshot.ApplicationInstanceID), int64(snapshot.UserID), snapshot.EnrollmentID); err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	if err := insertTOTPAudit(ctx, tx, snapshot.ApplicationInstanceID, snapshot.UserID, audit.ActionTOTPActivated, audit.OutcomeSuccess, "totp:"+out.ID, correlationID); err != nil {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPPersistence
	}
	if err := insertRecoveryAudit(ctx, tx, snapshot.ApplicationInstanceID, snapshot.UserID, audit.ActionRecoveryCodesGenerated, audit.OutcomeSuccess, "recovery_set:"+recoverySet.PublicID, correlationID); err != nil {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPPersistence
	}
	if err := tx.Commit(); err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	out.CreatedAt = out.CreatedAt.UTC()
	return out, nil
}

func (s *Store) GetTOTPCredential(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID) (authentication.TOTPCredentialView, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var out authentication.TOTPCredentialView
	err := db.QueryRowContext(ctx, `SELECT public_id,created_at FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(appID), int64(userID)).Scan(&out.ID, &out.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.TOTPCredentialView{}, authentication.ErrTOTPEnrollmentInvalid
	}
	if err != nil {
		return authentication.TOTPCredentialView{}, classifyTOTPError(ctx, err)
	}
	out.CreatedAt = out.CreatedAt.UTC()
	return out, nil
}

func (s *Store) RemoveTOTPCredential(ctx context.Context, current authentication.TOTPSession, correlationID audit.CorrelationID) error {
	if s == nil || s.pool == nil || !current.ApplicationInstanceID.Valid() || !current.UserID.Valid() || current.SessionPublicID == "" || correlationID == (audit.CorrelationID{}) {
		return authentication.ErrTOTPPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyTOTPError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateFreshTOTPSessionTx(ctx, tx, current.ApplicationInstanceID, current.UserID, current.SessionPublicID); err != nil {
		return err
	}
	var publicID string
	err = tx.QueryRowContext(ctx, `SELECT public_id FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2 FOR UPDATE`, int64(current.ApplicationInstanceID), int64(current.UserID)).Scan(&publicID)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return classifyTOTPError(ctx, err)
	}
	usable, err := s.hasUsablePrimaryMethod(ctx, tx, current.ApplicationInstanceID, current.ApplicationPublicID, current.UserID)
	if err != nil {
		return err
	}
	if !usable {
		if err := insertTOTPAudit(ctx, tx, current.ApplicationInstanceID, current.UserID, audit.ActionTOTPRemoveDenied, audit.OutcomeDenied, "totp:"+publicID, correlationID); err != nil {
			return authentication.ErrTOTPPersistence
		}
		if err := tx.Commit(); err != nil {
			return authentication.ErrTOTPPersistence
		}
		return authentication.ErrLastAuthenticationMethod
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(current.ApplicationInstanceID), int64(current.UserID)); err != nil {
		return classifyTOTPError(ctx, err)
	}
	if err := insertTOTPAudit(ctx, tx, current.ApplicationInstanceID, current.UserID, audit.ActionTOTPRemoved, audit.OutcomeSuccess, "totp:"+publicID, correlationID); err != nil {
		return authentication.ErrTOTPPersistence
	}
	if err := tx.Commit(); err != nil {
		return classifyTOTPError(ctx, err)
	}
	return nil
}

func (s *Store) hasUsablePrimaryMethod(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, appPublic applicationinstance.PublicID, userID identity.InternalID) (bool, error) {
	var verifiedEmails, passwords, passkeys, verifiedPhones int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL`, int64(appID), int64(userID)).Scan(&verifiedEmails); err != nil {
		return false, authentication.ErrTOTPPersistence
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM password_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(appID), int64(userID)).Scan(&passwords); err != nil {
		return false, authentication.ErrTOTPPersistence
	}
	if passwords > 0 && verifiedEmails > 0 {
		return true, nil
	}
	if s.availability.EmailOTP && verifiedEmails > 0 {
		return true, nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM phone_identifiers WHERE application_instance_id=$1 AND user_id=$2 AND verified_at IS NOT NULL`, int64(appID), int64(userID)).Scan(&verifiedPhones); err != nil {
		return false, authentication.ErrTOTPPersistence
	}
	if s.availability.PhoneOTP && verifiedPhones > 0 {
		return true, nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkey_credentials WHERE application_instance_id=$1 AND user_id=$2`, int64(appID), int64(userID)).Scan(&passkeys); err != nil {
		return false, authentication.ErrTOTPPersistence
	}
	if passkeys > 0 {
		return true, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT provider FROM external_identities WHERE application_instance_id=$1 AND user_id=$2`, int64(appID), int64(userID))
	if err != nil {
		return false, authentication.ErrTOTPPersistence
	}
	defer rows.Close()
	for rows.Next() {
		var provider string
		if err := rows.Scan(&provider); err != nil {
			return false, authentication.ErrTOTPPersistence
		}
		if s.availability.Social != nil {
			if _, ok := s.availability.Social.Resolve(appPublic, authentication.Provider(provider)); ok {
				return true, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, authentication.ErrTOTPPersistence
	}
	return false, nil
}

func validateFreshTOTPSessionTx(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, sessionPublicID string) error {
	var app, user int64
	var created, idle, expires, now time.Time
	var revoked sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT application_instance_id,user_id,created_at,idle_expires_at,expires_at,revoked_at,CURRENT_TIMESTAMP FROM sessions WHERE public_id=$1 FOR UPDATE`, sessionPublicID).Scan(&app, &user, &created, &idle, &expires, &revoked, &now)
	if err != nil || app != int64(appID) || user != int64(userID) || revoked.Valid || !now.Before(idle) || !now.Before(expires) {
		return authentication.ErrTOTPInvalidSession
	}
	if !now.Before(created.Add(authentication.SocialLinkFreshness)) {
		return authentication.ErrTOTPReverificationRequired
	}
	return nil
}

func validTOTPEnvelope(env authentication.TOTPSecretEnvelope) bool {
	return env.Version == 1 && len(env.KeyID) >= 1 && len(env.KeyID) <= 32 && len(env.Nonce) == 12 && len(env.Ciphertext) >= 17
}

func insertTOTPAudit(ctx context.Context, tx *sql.Tx, appID applicationinstance.InternalID, userID identity.InternalID, action, outcome, resource string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(application_instance_id,actor_kind,actor_user_id,subject_user_id,action,resource_category,resource_reference,outcome,correlation_id,source) VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)`, int64(appID), audit.ActorKindSocialUser, int64(userID), action, audit.ResourceCategoryTOTP, resource, outcome, correlationID[:], audit.SourceInternalTOTP)
	return err
}

func classifyTOTPError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return authentication.ErrTOTPAlreadyActive
	}
	return authentication.ErrTOTPPersistence
}
