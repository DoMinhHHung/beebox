-- +goose Up
CREATE TABLE email_otp_signin_challenges (
    application_instance_id BIGINT NOT NULL,
    email_identifier_id BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    code_hash TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    issue_count INTEGER NOT NULL,
    issue_window_started_at TIMESTAMPTZ NOT NULL,
    last_issued_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (application_instance_id, email_identifier_id),
    CONSTRAINT email_otp_signin_challenges_email_scope_fk
        FOREIGN KEY (application_instance_id, email_identifier_id)
        REFERENCES email_identifiers(application_instance_id, id),
    CONSTRAINT email_otp_signin_challenges_generation_check
        CHECK (generation > 0),
    CONSTRAINT email_otp_signin_challenges_failed_attempts_check
        CHECK (failed_attempts >= 0 AND failed_attempts <= 5),
    CONSTRAINT email_otp_signin_challenges_issue_count_check
        CHECK (issue_count >= 1 AND issue_count <= 3),
    CONSTRAINT email_otp_signin_challenges_active_code_check
        CHECK ((consumed_at IS NULL AND code_hash IS NOT NULL) OR
               (consumed_at IS NOT NULL AND code_hash IS NULL)),
    CONSTRAINT email_otp_signin_challenges_time_check
        CHECK (issue_window_started_at <= last_issued_at AND
               last_issued_at < expires_at AND
               created_at <= updated_at)
);

CREATE INDEX email_otp_signin_challenges_expiry_idx
    ON email_otp_signin_challenges (expires_at);

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
        'password_reset_confirm_identifier',
        'email_otp_issue_global',
        'email_otp_issue_identifier',
        'email_otp_confirm_global',
        'email_otp_confirm_identifier'
    ));
