-- +goose Up
ALTER TABLE sessions
    ADD CONSTRAINT sessions_application_user_id_key UNIQUE (application_instance_id, user_id, id);

CREATE TABLE social_link_attempts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    session_id BIGINT NOT NULL,
    provider TEXT NOT NULL,
    canonical_redirect_url TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT 'social_link',
    state_hash BYTEA NOT NULL,
    recent_auth_at TIMESTAMPTZ NOT NULL,
    oidc_nonce_hash BYTEA,
    provider_pkce_ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT social_link_attempts_user_scope_fk
        FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT social_link_attempts_session_scope_fk
        FOREIGN KEY (application_instance_id, user_id, session_id)
        REFERENCES sessions(application_instance_id, user_id, id),
    CONSTRAINT social_link_attempts_provider_check CHECK (provider IN ('google','apple','microsoft','github','gitlab','facebook','slack','discord','linkedin','x','tiktok')),
    CONSTRAINT social_link_attempts_purpose_check CHECK (purpose = 'social_link'),
    CONSTRAINT social_link_attempts_state_hash_check CHECK (octet_length(state_hash) = 32),
    CONSTRAINT social_link_attempts_state_hash_key UNIQUE (state_hash),
    CONSTRAINT social_link_attempts_nonce_hash_check CHECK (oidc_nonce_hash IS NULL OR octet_length(oidc_nonce_hash) = 32),
    CONSTRAINT social_link_attempts_redirect_length_check CHECK (char_length(canonical_redirect_url) BETWEEN 1 AND 2048),
    CONSTRAINT social_link_attempts_time_check CHECK (
        recent_auth_at <= created_at
        AND created_at < expires_at
        AND expires_at <= created_at + INTERVAL '10 minutes'
        AND expires_at <= recent_auth_at + INTERVAL '10 minutes'
        AND (consumed_at IS NULL OR (created_at <= consumed_at AND consumed_at <= expires_at))
    )
);
CREATE INDEX social_link_attempts_expiry_idx ON social_link_attempts(expires_at);
CREATE INDEX social_link_attempts_application_user_provider_idx ON social_link_attempts(application_instance_id, user_id, provider);

ALTER TABLE public_auth_rate_limits DROP CONSTRAINT public_auth_rate_limits_operation_check;
ALTER TABLE public_auth_rate_limits ADD CONSTRAINT public_auth_rate_limits_operation_check CHECK (operation IN (
    'signup_global','signup_identifier','verification_issue_global','verification_issue_identifier','signin_global','signin_identifier',
    'password_reset_global','password_reset_identifier','signup_pre_kdf_global','signup_pre_kdf_identifier','verification_confirm_global','verification_confirm_identifier',
    'password_reset_issue_pre_kdf_global','password_reset_issue_pre_kdf_identifier','password_reset_confirm_global','password_reset_confirm_identifier',
    'email_otp_issue_global','email_otp_issue_identifier','email_otp_confirm_global','email_otp_confirm_identifier',
    'phone_signup_issue_global','phone_signup_issue_identifier','phone_signup_confirm_global','phone_signup_confirm_identifier',
    'phone_otp_issue_global','phone_otp_issue_identifier','phone_otp_confirm_global','phone_otp_confirm_identifier',
    'social_attempt_global','social_attempt_application_provider','social_exchange_global','social_exchange_application',
    'social_link_attempt_global','social_link_attempt_user_provider'
));
