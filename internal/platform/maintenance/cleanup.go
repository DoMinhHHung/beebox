package maintenance

import (
	"context"
	"database/sql"
	"errors"
)

const DefaultBatchSize = 500

var ErrInvalidBatchSize = errors.New("invalid cleanup batch size")

type Result struct {
	RateLimits              int64
	Idempotency             int64
	EmailChallenges         int64
	EmailOTPChallenges      int64
	PasswordResetChallenges int64
	PhoneSignupChallenges   int64
	PhoneOTPChallenges      int64
	SocialAuthAttempts      int64
	SocialLinkAttempts      int64
	SocialCompletionGrants  int64
	PasskeyAttempts         int64
	TOTPEnrollments         int64
	PendingMFA              int64
	RecoveryCodeSets        int64
	SensitiveAdmission      int64
}

// CleanupSecurityState removes only operational rows whose security lifetime
// has ended. Each table is bounded by batchSize. Audit events, sessions, phone
// identifiers, external identities, passkey credentials, TOTP credentials, and
// refresh credentials are deliberately outside this primitive. Correctness never
// depends on this cleanup: proof paths still enforce expiry and one-time
// consumption themselves.
func CleanupSecurityState(ctx context.Context, db *sql.DB, batchSize int) (Result, error) {
	if db == nil || batchSize <= 0 || batchSize > 10_000 {
		return Result{}, ErrInvalidBatchSize
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	var result Result
	queries := []struct {
		destination *int64
		query       string
	}{
		{&result.RateLimits, `WITH doomed AS (
			SELECT ctid FROM public_auth_rate_limits
			WHERE expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM public_auth_rate_limits p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.Idempotency, `WITH doomed AS (
			SELECT ctid FROM public_auth_idempotency
			WHERE expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM public_auth_idempotency p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.EmailChallenges, `WITH doomed AS (
			SELECT ctid FROM email_verification_challenges
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM email_verification_challenges p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.EmailOTPChallenges, `WITH doomed AS (
			SELECT ctid FROM email_otp_signin_challenges
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM email_otp_signin_challenges p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.PasswordResetChallenges, `WITH doomed AS (
			SELECT ctid FROM password_reset_challenges
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM password_reset_challenges p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.PhoneSignupChallenges, `WITH doomed AS (
			SELECT ctid FROM phone_signup_challenges
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM phone_signup_challenges p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.PhoneOTPChallenges, `WITH doomed AS (
			SELECT ctid FROM phone_otp_signin_challenges
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM phone_otp_signin_challenges p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.SocialAuthAttempts, `WITH doomed AS (
			SELECT ctid FROM social_auth_attempts
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM social_auth_attempts p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.SocialLinkAttempts, `WITH doomed AS (
			SELECT ctid FROM social_link_attempts
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM social_link_attempts p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.SocialCompletionGrants, `WITH doomed AS (
			SELECT ctid FROM social_auth_completion_grants
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM social_auth_completion_grants p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.PasskeyAttempts, `WITH doomed AS (
			SELECT ctid FROM passkey_attempts
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM passkey_attempts p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.TOTPEnrollments, `WITH doomed AS (
			SELECT ctid FROM totp_enrollments
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM totp_enrollments p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.PendingMFA, `WITH doomed AS (
			SELECT ctid FROM pending_mfa_authentications
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM pending_mfa_authentications p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.RecoveryCodeSets, `WITH doomed AS (
			SELECT s.ctid FROM recovery_code_sets s
			WHERE s.invalidated_at IS NOT NULL
			  AND NOT EXISTS(SELECT 1 FROM totp_enrollments e WHERE e.replacement_recovery_set_id=s.id)
			ORDER BY s.invalidated_at
			LIMIT $1
		) DELETE FROM recovery_code_sets p USING doomed d WHERE p.ctid = d.ctid`},
		{&result.SensitiveAdmission, `WITH doomed AS (
			SELECT ctid FROM sensitive_operation_admission
			WHERE expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM sensitive_operation_admission p USING doomed d WHERE p.ctid = d.ctid`},
	}
	for _, cleanup := range queries {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		execResult, err := db.ExecContext(ctx, cleanup.query, batchSize)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return result, ctxErr
			}
			return result, errors.New("cleanup security state")
		}
		rows, err := execResult.RowsAffected()
		if err != nil {
			return result, errors.New("cleanup security state")
		}
		*cleanup.destination = rows
	}
	return result, nil
}
