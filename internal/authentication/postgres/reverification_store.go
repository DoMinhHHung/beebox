package postgres

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
	"github.com/DoMinhHHung/beebox/internal/identity"
)

func (s *Store) ReverificationRequiresTOTP(ctx context.Context, appID applicationinstance.InternalID, userID identity.InternalID) (bool, error) {
	if s == nil || s.pool == nil || !appID.Valid() || !userID.Valid() {
		return false, authentication.ErrReverificationInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	var required bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM totp_credentials
			WHERE application_instance_id=$1 AND user_id=$2
		)`, int64(appID), int64(userID)).Scan(&required); err != nil {
		return false, classifyReverification(ctx, err)
	}
	return required, nil
}

type reverificationSessionRow struct {
	appID, userID                       int64
	createdAt, idleExpiresAt, expiresAt time.Time
	revokedAt                           sql.NullTime
	mfaMethod                           sql.NullString
}

func loadReverificationSession(ctx context.Context, tx *sql.Tx, publicID string) (reverificationSessionRow, error) {
	var out reverificationSessionRow
	err := tx.QueryRowContext(ctx, `
		SELECT application_instance_id,user_id,created_at,idle_expires_at,expires_at,revoked_at,mfa_method
		FROM sessions
		WHERE public_id=$1
		FOR SHARE`, publicID,
	).Scan(&out.appID, &out.userID, &out.createdAt, &out.idleExpiresAt, &out.expiresAt, &out.revokedAt, &out.mfaMethod)
	return out, err
}

func activeReverificationSessionRow(row reverificationSessionRow, expectedAppID, expectedUserID int64, now time.Time) bool {
	return row.appID == expectedAppID && row.userID == expectedUserID && !row.revokedAt.Valid && now.Before(row.idleExpiresAt.UTC()) && now.Before(row.expiresAt.UTC())
}

func ensureReverificationAssurance(ctx context.Context, tx *sql.Tx, appID, userID int64, proof reverificationSessionRow) error {
	var requiresTOTP bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM totp_credentials
			WHERE application_instance_id=$1 AND user_id=$2
		)`, appID, userID).Scan(&requiresTOTP); err != nil {
		return classifyReverification(ctx, err)
	}
	if !requiresTOTP {
		return nil
	}
	if proof.mfaMethod.Valid && proof.mfaMethod.String == "totp" {
		return nil
	}
	if proof.mfaMethod.Valid && proof.mfaMethod.String == "recovery_code" {
		return authentication.ErrReverificationRecovery
	}
	return authentication.ErrReverificationInvalid
}

func (s *Store) CreateReverificationGrant(ctx context.Context, write authentication.ReverificationGrantWrite) (time.Time, error) {
	if s == nil || s.pool == nil || !write.ApplicationInstanceID.Valid() || !write.UserID.Valid() ||
		write.PublicID == "" || write.VerifierHash == ([32]byte{}) || write.TargetSessionPublicID == "" ||
		write.ProofSessionPublicID == "" || !authentication.ValidReverificationPurpose(write.Purpose) ||
		write.CorrelationID == (audit.CorrelationID{}) || write.CreatedAt.IsZero() || write.ExpiresAt.IsZero() {
		return time.Time{}, authentication.ErrReverificationInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, classifyReverification(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return time.Time{}, classifyReverification(ctx, err)
	}
	now = now.UTC()
	target, err := loadReverificationSession(ctx, tx, write.TargetSessionPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, authentication.ErrReverificationInvalid
		}
		return time.Time{}, classifyReverification(ctx, err)
	}
	proof, err := loadReverificationSession(ctx, tx, write.ProofSessionPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, authentication.ErrReverificationInvalid
		}
		return time.Time{}, classifyReverification(ctx, err)
	}
	expectedAppID, expectedUserID := int64(write.ApplicationInstanceID), int64(write.UserID)
	if !activeReverificationSessionRow(target, expectedAppID, expectedUserID, now) || !activeReverificationSessionRow(proof, expectedAppID, expectedUserID, now) {
		return time.Time{}, authentication.ErrReverificationInvalid
	}
	proofAt := proof.createdAt.UTC()
	if proofAt.After(now) || !now.Before(proofAt.Add(authentication.ReverificationLifetime)) {
		return time.Time{}, authentication.ErrReverificationExpired
	}
	if err := ensureReverificationAssurance(ctx, tx, expectedAppID, expectedUserID, proof); err != nil {
		return time.Time{}, err
	}
	expiresAt := proofAt.Add(authentication.ReverificationLifetime)
	for _, deadline := range []time.Time{now.Add(authentication.ReverificationLifetime), target.idleExpiresAt.UTC(), target.expiresAt.UTC(), proof.idleExpiresAt.UTC(), proof.expiresAt.UTC(), write.ExpiresAt.UTC()} {
		if deadline.Before(expiresAt) {
			expiresAt = deadline
		}
	}
	if !now.Before(expiresAt) {
		return time.Time{}, authentication.ErrReverificationExpired
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO reverification_grants(
			public_id,verifier_hash,application_instance_id,user_id,target_session_public_id,proof_session_public_id,purpose,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		write.PublicID, write.VerifierHash[:], expectedAppID, expectedUserID, write.TargetSessionPublicID,
		write.ProofSessionPublicID, write.Purpose, now, expiresAt,
	); err != nil {
		return time.Time{}, classifyReverification(ctx, err)
	}
	if err := insertReverificationAudit(ctx, tx, expectedAppID, expectedUserID, "authentication.reverification.issue", write.PublicID, write.CorrelationID); err != nil {
		return time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, classifyReverification(ctx, err)
	}
	return expiresAt, nil
}

func (s *Store) ConsumeReverificationGrant(ctx context.Context, consume authentication.ReverificationGrantConsume) error {
	if s == nil || s.pool == nil || !consume.ApplicationInstanceID.Valid() || !consume.UserID.Valid() ||
		consume.PublicID == "" || consume.VerifierHash == ([32]byte{}) || consume.TargetSessionPublicID == "" ||
		!authentication.ValidReverificationPurpose(consume.Purpose) || consume.CorrelationID == (audit.CorrelationID{}) {
		return authentication.ErrReverificationInvalid
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return classifyReverification(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var storedHash []byte
	var userID int64
	var targetSessionPublicID, proofSessionPublicID, purpose string
	var failed int
	var expiresAt time.Time
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT verifier_hash,user_id,target_session_public_id,proof_session_public_id,purpose,failed_attempts,expires_at,consumed_at
		FROM reverification_grants
		WHERE application_instance_id=$1 AND public_id=$2
		FOR UPDATE`, int64(consume.ApplicationInstanceID), consume.PublicID,
	).Scan(&storedHash, &userID, &targetSessionPublicID, &proofSessionPublicID, &purpose, &failed, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrReverificationInvalid
	}
	if err != nil {
		return classifyReverification(ctx, err)
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return classifyReverification(ctx, err)
	}
	now = now.UTC()
	if consumedAt.Valid {
		return authentication.ErrReverificationReplay
	}
	if !now.Before(expiresAt.UTC()) {
		return authentication.ErrReverificationExpired
	}
	if failed >= authentication.ReverificationMaxFailure {
		return authentication.ErrReverificationInvalid
	}
	bindingMatches := userID == int64(consume.UserID) && targetSessionPublicID == consume.TargetSessionPublicID && purpose == consume.Purpose
	hashMatches := len(storedHash) == 32 && subtle.ConstantTimeCompare(storedHash, consume.VerifierHash[:]) == 1
	if !bindingMatches || !hashMatches {
		if _, err := tx.ExecContext(ctx, `
			UPDATE reverification_grants
			SET failed_attempts=failed_attempts+1
			WHERE application_instance_id=$1 AND public_id=$2 AND consumed_at IS NULL AND failed_attempts<$3`,
			int64(consume.ApplicationInstanceID), consume.PublicID, authentication.ReverificationMaxFailure); err != nil {
			return classifyReverification(ctx, err)
		}
		if err := tx.Commit(); err != nil {
			return classifyReverification(ctx, err)
		}
		return authentication.ErrReverificationInvalid
	}
	expectedAppID, expectedUserID := int64(consume.ApplicationInstanceID), int64(consume.UserID)
	target, err := loadReverificationSession(ctx, tx, targetSessionPublicID)
	if err != nil || !activeReverificationSessionRow(target, expectedAppID, expectedUserID, now) {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return classifyReverification(ctx, err)
		}
		return authentication.ErrReverificationInvalid
	}
	proof, err := loadReverificationSession(ctx, tx, proofSessionPublicID)
	if err != nil || !activeReverificationSessionRow(proof, expectedAppID, expectedUserID, now) {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return classifyReverification(ctx, err)
		}
		return authentication.ErrReverificationInvalid
	}
	proofAt := proof.createdAt.UTC()
	if proofAt.After(now) || !now.Before(proofAt.Add(authentication.ReverificationLifetime)) {
		return authentication.ErrReverificationExpired
	}
	if err := ensureReverificationAssurance(ctx, tx, expectedAppID, expectedUserID, proof); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE reverification_grants SET consumed_at=$3
		WHERE application_instance_id=$1 AND public_id=$2 AND consumed_at IS NULL`,
		expectedAppID, consume.PublicID, now)
	if err != nil {
		return classifyReverification(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return authentication.ErrReverificationReplay
	}
	if err := insertReverificationAudit(ctx, tx, expectedAppID, expectedUserID, "authentication.reverification.consume", consume.PublicID, consume.CorrelationID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return classifyReverification(ctx, err)
	}
	return nil
}

func insertReverificationAudit(ctx context.Context, tx *sql.Tx, appID, userID int64, action, publicID string, correlationID audit.CorrelationID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events(
			application_instance_id,actor_kind,actor_user_id,subject_user_id,action,
			resource_category,resource_reference,outcome,correlation_id,source
		) VALUES($1,'user',$2,$2,$3,'reverification',$4,'success',$5,'internal_reverification')`,
		appID, userID, action, "reverification:"+publicID, correlationID[:])
	return classifyReverification(ctx, err)
}

func classifyReverification(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return authentication.ErrReverificationPersistence
}
