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

	if err := enforcePublicRateLimit(ctx, tx, appID, "signup_global", [32]byte{1}, authentication.PublicSignupGlobalLimit, authentication.PublicSignupGlobalWindow, now); err != nil {
		return false, err
	}
	if err := enforcePublicRateLimit(ctx, tx, appID, "signup_identifier", identifierFingerprint, authentication.PublicSignupIdentifierLimit, authentication.PublicSignupIdentifierWindow, now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, classifyPublicSignupError(ctx, err)
	}
	return false, nil
}

func (s *Store) AllowPublicVerificationConfirm(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "verification_confirm_global", [32]byte{3}, authentication.PublicVerificationGlobalLimit, authentication.PublicVerificationGlobalWindow, "verification_confirm_identifier", fingerprint, authentication.PublicVerificationIdentifierLimit, authentication.PublicVerificationIdentifierWindow, authentication.ErrEmailVerificationPersistence)
}

func (s *Store) AllowPasswordResetIssue(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "password_reset_global", [32]byte{4}, 100, time.Minute, "password_reset_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrPasswordResetPersistence)
}

func (s *Store) AllowPasswordResetConfirm(ctx context.Context, appID applicationinstance.InternalID, fingerprint [32]byte) error {
	return s.allowPublicPair(ctx, appID, "password_reset_confirm_global", [32]byte{5}, 100, time.Minute, "password_reset_confirm_identifier", fingerprint, 5, 15*time.Minute, authentication.ErrPasswordResetPersistence)
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
	if err := enforcePublicRateLimit(ctx, tx, appID, globalOp, globalHash, globalLimit, globalWindow, now); err != nil {
		return err
	}
	if err := enforcePublicRateLimit(ctx, tx, appID, identifierOp, identifierHash, identifierLimit, identifierWindow, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return persistenceErr
	}
	return nil
}
