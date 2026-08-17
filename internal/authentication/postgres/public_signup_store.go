package postgres

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"time"

	"github.com/DoMinhHHung/beebox/internal/applicationinstance"
	"github.com/DoMinhHHung/beebox/internal/audit"
	"github.com/DoMinhHHung/beebox/internal/authentication"
)

func (s *Store) PersistPublicSignup(ctx context.Context, write authentication.PublicSignupWrite) (authentication.PublicSignupPersistenceResult, error) {
	if !write.ApplicationInstanceID.Valid() || !write.PasswordHash.Valid() || !write.VerificationCodeHash.Valid() {
		return authentication.PublicSignupPersistenceResult{}, authentication.ErrPublicSignupPersistence
	}
	if err := ctx.Err(); err != nil {
		return authentication.PublicSignupPersistenceResult{}, err
	}
	if s == nil || s.pool == nil {
		return authentication.PublicSignupPersistenceResult{}, authentication.ErrPublicSignupPersistence
	}

	db := s.pool.OpenSQLDB()
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}
	now = now.UTC()

	replay, err := reserveSignupIdempotency(ctx, tx, write, now)
	if err != nil {
		return authentication.PublicSignupPersistenceResult{}, err
	}
	if replay {
		if err := tx.Commit(); err != nil {
			return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
		}
		return authentication.PublicSignupPersistenceResult{Replay: true}, nil
	}

	globalFingerprint := [32]byte{1}
	if err := enforcePublicRateLimit(ctx, tx, write.ApplicationInstanceID, "signup_global", globalFingerprint, authentication.PublicSignupGlobalLimit, authentication.PublicSignupGlobalWindow, now); err != nil {
		return authentication.PublicSignupPersistenceResult{}, err
	}
	if err := enforcePublicRateLimit(ctx, tx, write.ApplicationInstanceID, "signup_identifier", write.IdentifierFingerprint, authentication.PublicSignupIdentifierLimit, authentication.PublicSignupIdentifierWindow, now); err != nil {
		return authentication.PublicSignupPersistenceResult{}, err
	}

	lockKey := int64(binary.BigEndian.Uint64(write.IdentifierFingerprint[:8]))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}

	var existingEmailID int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM email_identifiers
		 WHERE application_instance_id = $1 AND normalized_email = $2`,
		int64(write.ApplicationInstanceID), write.Email.ComparisonKey,
	).Scan(&existingEmailID)
	if err == nil {
		if err := completeSignupIdempotency(ctx, tx, write); err != nil {
			return authentication.PublicSignupPersistenceResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
		}
		return authentication.PublicSignupPersistenceResult{}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}

	var userID int64
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO users (application_instance_id) VALUES ($1) RETURNING id`,
		int64(write.ApplicationInstanceID),
	).Scan(&userID); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}

	var emailID int64
	var destination string
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO email_identifiers (application_instance_id, user_id, email_address, normalized_email)
		 VALUES ($1, $2, $3, $4) RETURNING id, email_address`,
		int64(write.ApplicationInstanceID), userID, write.Email.EmailAddress, write.Email.ComparisonKey,
	).Scan(&emailID, &destination); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO password_credentials (application_instance_id, user_id, password_hash)
		 VALUES ($1, $2, $3)`,
		int64(write.ApplicationInstanceID), userID, write.PasswordHash.StorageEncoding(),
	); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_events (
			application_instance_id, actor_kind, subject_user_id, action,
			resource_category, outcome, correlation_id, source
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		int64(write.ApplicationInstanceID), audit.ActorKindAnonymousRegistration, userID,
		audit.ActionEmailPasswordRegistration, audit.ResourceCategoryUserRegistration,
		audit.OutcomeSuccess, write.RegistrationAuditID[:], audit.SourceInternalRegistration,
	); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}

	expiresAt := now.Add(authentication.EmailVerificationCodeTTL)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO email_verification_challenges (
			application_instance_id, email_identifier_id, generation, code_hash,
			expires_at, failed_attempts, issue_count, issue_window_started_at,
			last_issued_at, consumed_at, updated_at
		 ) VALUES ($1,$2,1,$3,$4,0,1,$5,$5,NULL,$5)`,
		int64(write.ApplicationInstanceID), emailID,
		write.VerificationCodeHash.StorageEncoding(), expiresAt, now,
	); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_events (
			application_instance_id, actor_kind, subject_user_id, action,
			resource_category, outcome, correlation_id, source
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		int64(write.ApplicationInstanceID), audit.ActorKindAnonymousEmailVerification, userID,
		audit.ActionEmailVerificationChallengeIssued, audit.ResourceCategoryEmailIdentifier,
		audit.OutcomeSuccess, write.VerificationAuditID[:], audit.SourceInternalEmailVerification,
	); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}

	if err := completeSignupIdempotency(ctx, tx, write); err != nil {
		return authentication.PublicSignupPersistenceResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return authentication.PublicSignupPersistenceResult{}, classifyPublicSignupError(ctx, err)
	}
	return authentication.PublicSignupPersistenceResult{
		ShouldSend:  true,
		Destination: destination,
		ExpiresAt:   expiresAt,
	}, nil
}

func reserveSignupIdempotency(ctx context.Context, tx *sql.Tx, write authentication.PublicSignupWrite, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx,
		`INSERT INTO public_auth_idempotency (
			application_instance_id, operation, key_hash, request_fingerprint, result_status, expires_at
		 ) VALUES ($1, 'signup', $2, $3, NULL, $4)
		 ON CONFLICT DO NOTHING`,
		int64(write.ApplicationInstanceID), write.IdempotencyKeyHash[:], write.RequestFingerprint[:],
		now.Add(authentication.PublicSignupIdempotencyRetention),
	)
	if err != nil {
		return false, classifyPublicSignupError(ctx, err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, authentication.ErrPublicSignupPersistence
	}
	if inserted == 1 {
		return false, nil
	}

	var fingerprint []byte
	var status sql.NullString
	var expiresAt time.Time
	if err := tx.QueryRowContext(ctx,
		`SELECT request_fingerprint, result_status, expires_at
		 FROM public_auth_idempotency
		 WHERE application_instance_id = $1 AND operation = 'signup' AND key_hash = $2
		 FOR UPDATE`,
		int64(write.ApplicationInstanceID), write.IdempotencyKeyHash[:],
	).Scan(&fingerprint, &status, &expiresAt); err != nil {
		return false, classifyPublicSignupError(ctx, err)
	}
	if !expiresAt.After(now) {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM public_auth_idempotency
			 WHERE application_instance_id = $1 AND operation = 'signup' AND key_hash = $2`,
			int64(write.ApplicationInstanceID), write.IdempotencyKeyHash[:],
		); err != nil {
			return false, classifyPublicSignupError(ctx, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO public_auth_idempotency (
				application_instance_id, operation, key_hash, request_fingerprint, result_status, expires_at
			 ) VALUES ($1, 'signup', $2, $3, NULL, $4)`,
			int64(write.ApplicationInstanceID), write.IdempotencyKeyHash[:], write.RequestFingerprint[:],
			now.Add(authentication.PublicSignupIdempotencyRetention),
		); err != nil {
			return false, classifyPublicSignupError(ctx, err)
		}
		return false, nil
	}
	if !equal32(fingerprint, write.RequestFingerprint) {
		return false, authentication.ErrPublicIdempotencyConflict
	}
	if !status.Valid || status.String != "verification_pending" {
		return false, authentication.ErrPublicSignupPersistence
	}
	return true, nil
}

func completeSignupIdempotency(ctx context.Context, tx *sql.Tx, write authentication.PublicSignupWrite) error {
	result, err := tx.ExecContext(ctx,
		`UPDATE public_auth_idempotency SET result_status = 'verification_pending'
		 WHERE application_instance_id = $1 AND operation = 'signup' AND key_hash = $2`,
		int64(write.ApplicationInstanceID), write.IdempotencyKeyHash[:],
	)
	if err != nil {
		return classifyPublicSignupError(ctx, err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return authentication.ErrPublicSignupPersistence
	}
	return nil
}

func enforcePublicRateLimit(
	ctx context.Context,
	tx *sql.Tx,
	applicationInstanceID applicationinstance.InternalID,
	operation string,
	subjectHash [32]byte,
	limit int,
	window time.Duration,
	now time.Time,
) error {
	appID := int64(applicationInstanceID)
	var count int
	var expiresAt time.Time
	err := tx.QueryRowContext(ctx,
		`SELECT request_count, expires_at
		 FROM public_auth_rate_limits
		 WHERE application_instance_id = $1 AND operation = $2 AND subject_hash = $3
		 FOR UPDATE`,
		appID, operation, subjectHash[:],
	).Scan(&count, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO public_auth_rate_limits (
				application_instance_id, operation, subject_hash, window_started_at, request_count, expires_at
			 ) VALUES ($1,$2,$3,$4,1,$5)`,
			appID, operation, subjectHash[:], now, now.Add(window),
		)
		return classifyPublicSignupError(ctx, err)
	}
	if err != nil {
		return classifyPublicSignupError(ctx, err)
	}
	if !expiresAt.After(now) {
		_, err = tx.ExecContext(ctx,
			`UPDATE public_auth_rate_limits
			 SET window_started_at = $4, request_count = 1, expires_at = $5
			 WHERE application_instance_id = $1 AND operation = $2 AND subject_hash = $3`,
			appID, operation, subjectHash[:], now, now.Add(window),
		)
		return classifyPublicSignupError(ctx, err)
	}
	if count >= limit {
		return authentication.ErrPublicRateLimited
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE public_auth_rate_limits SET request_count = request_count + 1
		 WHERE application_instance_id = $1 AND operation = $2 AND subject_hash = $3`,
		appID, operation, subjectHash[:],
	)
	return classifyPublicSignupError(ctx, err)
}

func equal32(value []byte, expected [32]byte) bool {
	if len(value) != len(expected) {
		return false
	}
	var diff byte
	for i := range expected {
		diff |= value[i] ^ expected[i]
	}
	return diff == 0
}

func classifyPublicSignupError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return authentication.ErrPublicSignupPersistence
}
