-- +goose Up
ALTER TABLE audit_events
    ADD COLUMN resource_reference TEXT,
    ADD CONSTRAINT audit_events_resource_reference_check
        CHECK (resource_reference IS NULL OR char_length(resource_reference) BETWEEN 1 AND 256);

CREATE TABLE application_redirect_urls (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    canonical_redirect_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT application_redirect_urls_application_url_key UNIQUE (application_instance_id, canonical_redirect_url),
    CONSTRAINT application_redirect_urls_length_check CHECK (char_length(canonical_redirect_url) BETWEEN 1 AND 2048)
);
CREATE INDEX application_redirect_urls_application_idx ON application_redirect_urls(application_instance_id);

CREATE TABLE external_identities (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT external_identities_user_scope_fk FOREIGN KEY (application_instance_id, user_id) REFERENCES users(application_instance_id, id),
    CONSTRAINT external_identities_application_instance_id_id_key UNIQUE (application_instance_id, id),
    CONSTRAINT external_identities_provider_check CHECK (provider IN ('google','apple','microsoft','github','gitlab','facebook','slack','discord','linkedin','x','tiktok')),
    CONSTRAINT external_identities_subject_check CHECK (char_length(provider_subject) BETWEEN 1 AND 512),
    CONSTRAINT external_identities_subject_owner_key UNIQUE (application_instance_id, provider, provider_subject)
);
CREATE INDEX external_identities_application_user_idx ON external_identities(application_instance_id, user_id);

CREATE TABLE social_auth_attempts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    provider TEXT NOT NULL,
    canonical_redirect_url TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT 'social_auth',
    state_hash BYTEA NOT NULL,
    client_code_challenge TEXT NOT NULL,
    oidc_nonce_hash BYTEA,
    provider_pkce_ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT social_auth_attempts_provider_check CHECK (provider IN ('google','apple','microsoft','github','gitlab','facebook','slack','discord','linkedin','x','tiktok')),
    CONSTRAINT social_auth_attempts_purpose_check CHECK (purpose = 'social_auth'),
    CONSTRAINT social_auth_attempts_state_hash_check CHECK (octet_length(state_hash) = 32),
    CONSTRAINT social_auth_attempts_state_hash_key UNIQUE (state_hash),
    CONSTRAINT social_auth_attempts_client_challenge_check CHECK (client_code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT social_auth_attempts_nonce_hash_check CHECK (oidc_nonce_hash IS NULL OR octet_length(oidc_nonce_hash) = 32),
    CONSTRAINT social_auth_attempts_redirect_length_check CHECK (char_length(canonical_redirect_url) BETWEEN 1 AND 2048),
    CONSTRAINT social_auth_attempts_time_check CHECK (created_at < expires_at AND (consumed_at IS NULL OR created_at <= consumed_at))
);
CREATE INDEX social_auth_attempts_expiry_idx ON social_auth_attempts(expires_at);
CREATE INDEX social_auth_attempts_application_idx ON social_auth_attempts(application_instance_id, provider);

CREATE TABLE social_auth_completion_grants (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    code_hash BYTEA NOT NULL,
    client_code_challenge TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT social_auth_completion_grants_user_scope_fk FOREIGN KEY (application_instance_id, user_id) REFERENCES users(application_instance_id, id),
    CONSTRAINT social_auth_completion_grants_code_hash_check CHECK (octet_length(code_hash) = 32),
    CONSTRAINT social_auth_completion_grants_code_hash_key UNIQUE (code_hash),
    CONSTRAINT social_auth_completion_grants_client_challenge_check CHECK (client_code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT social_auth_completion_grants_time_check CHECK (created_at < expires_at AND (consumed_at IS NULL OR created_at <= consumed_at))
);
CREATE INDEX social_auth_completion_grants_expiry_idx ON social_auth_completion_grants(expires_at);
CREATE INDEX social_auth_completion_grants_application_user_idx ON social_auth_completion_grants(application_instance_id, user_id);

ALTER TABLE public_auth_rate_limits DROP CONSTRAINT public_auth_rate_limits_operation_check;
ALTER TABLE public_auth_rate_limits ADD CONSTRAINT public_auth_rate_limits_operation_check CHECK (operation IN (
    'signup_global','signup_identifier','verification_issue_global','verification_issue_identifier','signin_global','signin_identifier',
    'password_reset_global','password_reset_identifier','signup_pre_kdf_global','signup_pre_kdf_identifier','verification_confirm_global','verification_confirm_identifier',
    'password_reset_issue_pre_kdf_global','password_reset_issue_pre_kdf_identifier','password_reset_confirm_global','password_reset_confirm_identifier',
    'email_otp_issue_global','email_otp_issue_identifier','email_otp_confirm_global','email_otp_confirm_identifier',
    'phone_signup_issue_global','phone_signup_issue_identifier','phone_signup_confirm_global','phone_signup_confirm_identifier',
    'phone_otp_issue_global','phone_otp_issue_identifier','phone_otp_confirm_global','phone_otp_confirm_identifier',
    'social_attempt_global','social_attempt_application_provider','social_exchange_global','social_exchange_application'
));