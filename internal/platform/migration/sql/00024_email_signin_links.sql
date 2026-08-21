-- +goose Up
CREATE TABLE email_signin_links (
    application_instance_id BIGINT NOT NULL,
    email_identifier_id BIGINT NOT NULL,
    public_id TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT 'sign_in',
    secret_hash BYTEA NULL,
    completion_url TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0 AND failed_attempts <= 5),
    issue_count INTEGER NOT NULL CHECK (issue_count >= 1 AND issue_count <= 3),
    issue_window_started_at TIMESTAMPTZ NOT NULL,
    last_issued_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (application_instance_id, email_identifier_id),
    CONSTRAINT email_signin_links_email_scope_fk
        FOREIGN KEY (application_instance_id, email_identifier_id)
        REFERENCES email_identifiers(application_instance_id, id)
        ON DELETE CASCADE,
    CONSTRAINT email_signin_links_public_id_key UNIQUE (public_id),
    CONSTRAINT email_signin_links_public_id_check CHECK (
        public_id ~ '^eln_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT email_signin_links_purpose_check CHECK (purpose = 'sign_in'),
    CONSTRAINT email_signin_links_secret_hash_check CHECK (secret_hash IS NULL OR octet_length(secret_hash) = 32),
    CONSTRAINT email_signin_links_completion_url_check CHECK (char_length(completion_url) BETWEEN 1 AND 2048),
    CONSTRAINT email_signin_links_active_secret_check CHECK (
        (consumed_at IS NULL AND secret_hash IS NOT NULL) OR
        (consumed_at IS NOT NULL AND secret_hash IS NULL)
    ),
    CONSTRAINT email_signin_links_time_check CHECK (
        issue_window_started_at <= last_issued_at AND
        last_issued_at < expires_at AND
        created_at <= updated_at
    )
);

CREATE INDEX email_signin_links_expiry_idx
    ON email_signin_links(expires_at, application_instance_id, email_identifier_id);

ALTER TABLE public_auth_rate_limits
    DROP CONSTRAINT public_auth_rate_limits_operation_check;
ALTER TABLE public_auth_rate_limits
    ADD CONSTRAINT public_auth_rate_limits_operation_check CHECK (operation IN (
        'signup_global','signup_identifier','verification_issue_global','verification_issue_identifier','signin_global','signin_identifier',
        'password_reset_global','password_reset_identifier','signup_pre_kdf_global','signup_pre_kdf_identifier','verification_confirm_global','verification_confirm_identifier',
        'password_reset_issue_pre_kdf_global','password_reset_issue_pre_kdf_identifier','password_reset_confirm_global','password_reset_confirm_identifier',
        'email_otp_issue_global','email_otp_issue_identifier','email_otp_confirm_global','email_otp_confirm_identifier',
        'phone_signup_issue_global','phone_signup_issue_identifier','phone_signup_confirm_global','phone_signup_confirm_identifier',
        'phone_otp_issue_global','phone_otp_issue_identifier','phone_otp_confirm_global','phone_otp_confirm_identifier',
        'email_link_issue_global','email_link_issue_identifier','email_link_confirm_global','email_link_confirm_identifier'
    ));
