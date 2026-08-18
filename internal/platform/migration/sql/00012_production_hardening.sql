-- +goose Up
ALTER TABLE public_auth_rate_limits
    DROP CONSTRAINT public_auth_rate_limits_operation_check;
ALTER TABLE public_auth_rate_limits
    ADD CONSTRAINT public_auth_rate_limits_operation_check
    CHECK (operation IN (
        'signup_global',
        'signup_identifier',
        'verification_issue_global',
        'verification_issue_identifier',
        'signin_global',
        'signin_identifier',
        'password_reset_global',
        'password_reset_identifier',
        'signup_pre_kdf_global',
        'signup_pre_kdf_identifier',
        'verification_confirm_global',
        'verification_confirm_identifier',
        'password_reset_issue_pre_kdf_global',
        'password_reset_issue_pre_kdf_identifier',
        'password_reset_confirm_global',
        'password_reset_confirm_identifier'
    ));

CREATE INDEX email_verification_challenges_expiry_idx
    ON email_verification_challenges (expires_at);

CREATE INDEX password_reset_challenges_expiry_idx
    ON password_reset_challenges (expires_at);
