package maintenance

import (
	"context"
	"database/sql"
	"errors"
)

const DefaultBatchSize = 500

var ErrInvalidBatchSize = errors.New("invalid cleanup batch size")

type Result struct {
	RateLimits             int64
	Idempotency            int64
	EmailChallenges        int64
	PasswordResetChallenges int64
}

// CleanupSecurityState removes only operational rows whose security lifetime
// has ended. Each table is bounded by batchSize. Audit events, sessions, and
// refresh credentials are deliberately outside this primitive.
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
		{&result.PasswordResetChallenges, `WITH doomed AS (
			SELECT ctid FROM password_reset_challenges
			WHERE consumed_at IS NOT NULL OR expires_at <= CURRENT_TIMESTAMP
			ORDER BY expires_at
			LIMIT $1
		) DELETE FROM password_reset_challenges p USING doomed d WHERE p.ctid = d.ctid`},
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
