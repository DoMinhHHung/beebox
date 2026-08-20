package postgres

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func (s *Store) CreateReverificationGrant(ctx context.Context, write authentication.ReverificationGrantWrite) (time.Time, error) {
	if s == nil || s.pool == nil || !write.ApplicationInstanceID.Valid() || !write.UserID.Valid() ||
		write.PublicID == "" || write.VerifierHash == ([32]byte{}) || write.TargetSessionPublicID == "" ||
		write.ProofSessionPublicID == "" || !authentication.ValidReverificationPurpose(write.Purpose) ||
		write.CorrelationID == (audit.CorrelationID{}) {
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

	type sessionProof struct {
		userID                              int64
		createdAt, idleExpiresAt, expiresAt time.Time
		revokedAt                           sql.NullTime
		mfaMethod                           sql.NullString
	}
	load := func(publicID string) (sessionProof, error) {
		var out sessionProof
		err := tx.QueryRowContext(ctx, `
			SELECT user_id,created_at,idle_expires_at,expires_at,revoked_at,mfa_method
			FROM sessions
			WHERE application_instance_id=$1 AND public_id=$2
			FOR SHARE`,
			int64(write.ApplicationInstanceID), publicID,
		).Scan(&out.userID, &out.createdAt, &out.idleExpiresAt, &out.expiresAt, &out.revokedAt, &out.mfaMethod)
		return out, err
	}
	target, err := load(write.TargetSessionPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, authentication.ErrReverificationInvalid
		}
		return time.Time{}, classifyReverification(ctx, err)
	}
	proof, err := load(write.ProofSessionPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, authentication.ErrReverificationInvalid
		}
		return time.Time{}, classifyReverification(ctx, err)
	}
	expectedUser := int64(write.UserID)
	if write.TargetSessionPublicID != write.ProofSessionPublicID {
		return time.Time{}, authentication.ErrReverificationInvalid
	}
	active := func(v sessionProof) bool {
		return v.userID == expectedUser && !v.revokedAt.Valid && now.Before(v.idleExpiresAt.UTC()) && now.Before(v.expiresAt.UTC())
	}
	if !active(target) || !active(proof) || proof.createdAt.UTC().Before(now.Add(-authentication.ReverificationLifetime)) || proof.createdAt.UTC().After(now) {
		return time.Time{}, authentication.ErrReverificationInvalid
	}
	var requiresTOTP bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM totp_credentials
			WHERE application_instance_id=$1 AND user_id=$2
		)`, int64(write.ApplicationInstanceID), expectedUser).Scan(&requiresTOTP); err != nil {
		return time.Time{}, classifyReverification(ctx, err)
	}
	if requiresTOTP {
		if !proof.mfaMethod.Valid || proof.mfaMethod.String != "totp" {
			if proof.mfaMethod.Valid && proof.mfaMethod.String == "recovery_code" {
				return time.Time{}, authentication.ErrReverificationRecovery
			}
			return time.Time{}, authentication.ErrReverificationInvalid
		}
	}
	expiresAt := proof.createdAt.UTC().Add(authentication.ReverificationLifetime)
	if target.idleExpiresAt.UTC().Before(expiresAt) {
		expiresAt = target.idleExpiresAt.UTC()
	}
	if target.expiresAt.UTC().Before(expiresAt) {
		expiresAt = target.expiresAt.UTC()
	}
	if !now.Before(expiresAt) {
		return time.Time{}, authentication.ErrReverificationExpired
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO reverification_grants(
			public_id,verifier_hash,application_instance_id,user_id,session_public_id,purpose,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		write.PublicID, write.VerifierHash[:], int64(write.ApplicationInstanceID), expectedUser,
		write.TargetSessionPublicID, write.Purpose, now, expiresAt,
	); err != nil {
		return time.Time{}, classifyReverification(ctx, err)
	}
	if err := insertReverificationAudit(ctx, tx, int64(write.ApplicationInstanceID), expectedUser, "authentication.reverification.issue", write.PublicID, write.CorrelationID); err != nil {
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
	var sessionPublicID, purpose string
	var failed int
	var expiresAt time.Time
	var consumedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT verifier_hash,user_id,session_public_id,purpose,failed_attempts,expires_at,consumed_at
		FROM reverification_grants
		WHERE application_instance_id=$1 AND public_id=$2
		FOR UPDATE`, int64(consume.ApplicationInstanceID), consume.PublicID,
	).Scan(&storedHash, &userID, &sessionPublicID, &purpose, &failed, &expiresAt, &consumedAt)
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
	bindingMatches := userID == int64(consume.UserID) && sessionPublicID == consume.TargetSessionPublicID && purpose == consume.Purpose
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
	var active bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM sessions
			WHERE application_instance_id=$1 AND user_id=$2 AND public_id=$3
			  AND revoked_at IS NULL AND idle_expires_at>$4 AND expires_at>$4
		)`, int64(consume.ApplicationInstanceID), int64(consume.UserID), consume.TargetSessionPublicID, now).Scan(&active); err != nil {
		return classifyReverification(ctx, err)
	}
	if !active {
		return authentication.ErrReverificationInvalid
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE reverification_grants SET consumed_at=$3
		WHERE application_instance_id=$1 AND public_id=$2 AND consumed_at IS NULL`,
		int64(consume.ApplicationInstanceID), consume.PublicID, now)
	if err != nil {
		return classifyReverification(ctx, err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return authentication.ErrReverificationReplay
	}
	if err := insertReverificationAudit(ctx, tx, int64(consume.ApplicationInstanceID), int64(consume.UserID), "authentication.reverification.consume", consume.PublicID, consume.CorrelationID); err != nil {
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
