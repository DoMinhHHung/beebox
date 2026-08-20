package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/DoMinhHHung/beebox/internal/platform/config"
	"github.com/DoMinhHHung/beebox/internal/platform/database"
	"github.com/DoMinhHHung/beebox/internal/platform/maintenance"
)

func runCleanupOperator(ctx context.Context, lookup config.LookupEnv, output io.Writer) error {
	cfg, err := config.LoadMigration(lookup)
	if err != nil {
		return fmt.Errorf("load operator configuration: %w", err)
	}
	operatorCtx, cancel := context.WithTimeout(ctx, cfg.DatabaseMigrationTimeout)
	defer cancel()
	pool, err := database.Open(operatorCtx, cfg.DatabaseURL)
	if err != nil {
		return errors.New("initialize PostgreSQL pool")
	}
	defer pool.Close()
	if err := pool.Ping(operatorCtx); err != nil {
		return errors.New("verify PostgreSQL connectivity")
	}
	db := pool.OpenSQLDB()
	defer db.Close()
	result, err := maintenance.CleanupSecurityState(operatorCtx, db, maintenance.DefaultBatchSize)
	if err != nil {
		return errors.New("cleanup security state")
	}
	_, err = fmt.Fprintf(output,
		"rate_limits=%d\nidempotency=%d\nemail_verification_challenges=%d\nemail_otp_challenges=%d\npassword_reset_challenges=%d\nphone_signup_challenges=%d\nphone_otp_challenges=%d\nsocial_auth_attempts=%d\nsocial_link_attempts=%d\nsocial_completion_grants=%d\npasskey_attempts=%d\ntotp_enrollments=%d\npending_mfa=%d\n",
		result.RateLimits,
		result.Idempotency,
		result.EmailChallenges,
		result.EmailOTPChallenges,
		result.PasswordResetChallenges,
		result.PhoneSignupChallenges,
		result.PhoneOTPChallenges,
		result.SocialAuthAttempts,
		result.SocialLinkAttempts,
		result.SocialCompletionGrants,
		result.PasskeyAttempts,
		result.TOTPEnrollments,
		result.PendingMFA,
	)
	return err
}
