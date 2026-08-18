package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func (s *Store) AdmitPublicSignup(ctx context.Context, appID applicationinstance.InternalID, keyHash, requestFingerprint, identifierFingerprint [32]byte) (bool, error) {
	if s == nil || s.pool == nil || !appID.Valid() {
		return false, authentication.ErrPublicSignupPersistence
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, classifyPublicSignupError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return false, classifyPublicSignupError(ctx, err)
	}
	now = now.UTC()

	var existing []byte
	var status sql.NullString
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT request_fingerprint, result_status, expires_at FROM public_auth_idempotency WHERE application_instance_id=$1 AND operation='signup' AND key_hash=$2 FOR UPDATE`, int64(appID), keyHash[:]).Scan(&existing, &status, &expires)
	if err == nil {
		if expires.After(now) {
			if !equal32(existing, requestFingerprint) {
				return false, authentication.ErrPublicIdempotencyConflict
			}
			if status.Valid && status.String == "verification_pending" {
				if err := tx.Commit(); err != nil {
					return false, classifyPublicSignupError(ctx, err)
				}
				return true, nil
			}
			return false, authentication.ErrPublicSignupPersistence
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM public_auth_idempotency WHERE application_instance_id=$1 AND operation='signup' AND key_hash=$2`, int64(appID), keyHash[:]); err != nil {
			return false, classifyPublicSignupError(ctx, err)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, classifyPublicSignupError(ctx, err)
	}

	if err := enforceAtomicPublicRateLimit(ctx, tx, appID, "signup_pre_kdf_global", [32]byte{11}, authentication.PublicSignupGlobalLimit, authentication.PublicSignupGlobalWindow, now, authentication.ErrPublicSignupPersistence); err != nil {
		return false, err
	}
	if err := enforceAtomicPublicRateLimit(ctx, tx, appID, "signup_pre_kdf_identifier", identifierFingerprint, authentication.PublicSignupIdentifierLimit, authentication.PublicSignupIdentifierWindow, now, authentication.ErrPublicSignupPersistence); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, classifyPublicSignupError(ctx, err)
	}
	return false, nil
}

func (s *Store) AllowPublicVerificationConfirm(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "verification_confirm_global", [32]byte{12}, authentication.PublicVerificationGlobalLimit, authentication.PublicVerificationGlobalWindow, "verification_confirm_identifier", fingerprint, authentication.PublicVerificationIdentifierLimit, authentication.PublicVerificationIdentifierWindow, authentication.ErrEmailVerificationPersistence)
}

func (s *Store) AllowPasswordResetIssue(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "password_reset_issue_pre_kdf_global", [32]byte{13}, 100, time.Minute, "password_reset_issue_pre_kdf_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrPasswordResetPersistence)
}

func (s *Store) AllowPasswordResetConfirm(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "password_reset_confirm_global", [32]byte{14}, 100, time.Minute, "password_reset_confirm_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrPasswordResetPersistence)
}

func (s *Store) AllowEmailOTPIssue(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "email_otp_issue_global", [32]byte{15}, 100, time.Minute, "email_otp_issue_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrEmailOTPPersistence)
}

func (s *Store) AllowEmailOTPConfirm(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "email_otp_confirm_global", [32]byte{16}, 100, time.Minute, "email_otp_confirm_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrEmailOTPPersistence)
}

func (s *Store) AllowPhoneSignupIssue(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "phone_signup_issue_global", [32]byte{17}, 100, time.Minute, "phone_signup_issue_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrPhoneSignupPersistence)
}

func (s *Store) AllowPhoneSignupConfirm(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "phone_signup_confirm_global", [32]byte{18}, 100, time.Minute, "phone_signup_confirm_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrPhoneSignupPersistence)
}

func (s *Store) AllowPhoneOTPIssue(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "phone_otp_issue_global", [32]byte{19}, 100, time.Minute, "phone_otp_issue_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrPhoneOTPPersistence)
}

func (s *Store) AllowPhoneOTPConfirm(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "phone_otp_confirm_global", [32]byte{20}, 100, time.Minute, "phone_otp_confirm_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrPhoneOTPPersistence)
}

func (s *Store) allowPublicPair(ctx context.Context, appID applicationinstance.InternalID, globalOp string, globalHash [32]byte, globalLimit int, globalWindow time.Duration, identifierOp string, identifierHash [32]byte, identifierLimit int, identifierWindow time.Duration, persistenceErr error) error {
	if s == nil || s.pool == nil || !appID.Valid() {
		return persistenceErr
	}
	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return persistenceErr
	}
	defer func() { _ = tx.Rollback() }()
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return persistenceErr
	}
	now = now.UTC()
	if err := enforceAtomicPublicRateLimit(ctx, tx, appID, globalOp, globalHash, globalLimit, globalWindow, now, persistenceErr); err != nil {
		return err
	}
	// Keep this ordering: global denial must not create or update identifier state.
	if err := enforceAtomicPublicRateLimit(ctx, tx, appID, identifierOp, identifierHash, identifierLimit, identifierWindow, now, persistenceErr); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return persistenceErr
	}
	return nil
}

// enforceAtomicPublicRateLimit performs first-row creation, active-window
// increment, and expired-window reset as one PostgreSQL UPSERT. The unique key
// arbitrates concurrent first use; no missing-row SELECT/FOR UPDATE gap exists.
func enforceAtomicPublicRateLimit(
	ctx context.Context,
	tx *sql.Tx,
	appID applicationinstance.InternalID,
	operation string,
	subjectHash [32]byte,
	limit int,
	window time.Duration,
	now time.Time,
	persistenceErr error,
) error {
	var requestCount int
	err := tx.QueryRowContext(ctx, `
		INSERT INTO public_auth_rate_limits (
			application_instance_id, operation, subject_hash,
			window_started_at, request_count, expires_at
		) VALUES ($1,$2,$3,$4,1,$5)
		ON CONFLICT (application_instance_id, operation, subject_hash)
		DO UPDATE SET
			window_started_at = CASE
				WHEN public_auth_rate_limits.expires_at <= $4 THEN $4
				ELSE public_auth_rate_limits.window_started_at
			END,
			request_count = CASE
				WHEN public_auth_rate_limits.expires_at <= $4 THEN 1
				ELSE public_auth_rate_limits.request_count + 1
			END,
			expires_at = CASE
				WHEN public_auth_rate_limits.expires_at <= $4 THEN $5
				ELSE public_auth_rate_limits.expires_at
			END
		WHERE public_auth_rate_limits.expires_at <= $4
		   OR public_auth_rate_limits.request_count < $6
		RETURNING request_count`,
		int64(appID), operation, subjectHash[:], now, now.Add(window), limit,
	).Scan(&requestCount)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.ErrPublicRateLimited
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return persistenceErr
	}
	if requestCount < 1 || requestCount > limit {
		return persistenceErr
	}
	return nil
}
