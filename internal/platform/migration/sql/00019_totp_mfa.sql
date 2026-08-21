-- +goose Up
CREATE TABLE totp_credentials (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL DEFAULT ('mfc_' || gen_random_uuid()::text) UNIQUE,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    encryption_version SMALLINT NOT NULL,
    encryption_key_id TEXT NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    encrypted_secret BYTEA NOT NULL,
    last_accepted_timestep BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT totp_credentials_public_id_check CHECK (
        public_id ~ '^mfc_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT totp_credentials_user_scope_fk FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT totp_credentials_application_user_key UNIQUE (application_instance_id, user_id),
    CONSTRAINT totp_credentials_encryption_version_check CHECK (encryption_version = 1),
    CONSTRAINT totp_credentials_key_id_check CHECK (
        char_length(encryption_key_id) BETWEEN 1 AND 32
        AND encryption_key_id ~ '^[A-Za-z0-9._-]+$'
    ),
    CONSTRAINT totp_credentials_nonce_check CHECK (octet_length(encryption_nonce) = 12),
    CONSTRAINT totp_credentials_ciphertext_check CHECK (octet_length(encrypted_secret) >= 17),
    CONSTRAINT totp_credentials_timestep_check CHECK (last_accepted_timestep IS NULL OR last_accepted_timestep >= 0)
);

CREATE INDEX totp_credentials_key_reference_idx
    ON totp_credentials(encryption_key_id, encryption_version);

CREATE TABLE totp_enrollments (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL DEFAULT ('mfe_' || gen_random_uuid()::text) UNIQUE,
    credential_public_id TEXT NOT NULL DEFAULT ('mfc_' || gen_random_uuid()::text) UNIQUE,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    session_public_id TEXT NOT NULL,
    encryption_version SMALLINT NOT NULL,
    encryption_key_id TEXT NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    encrypted_secret BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT totp_enrollments_public_id_check CHECK (
        public_id ~ '^mfe_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT totp_enrollments_credential_public_id_check CHECK (
        credential_public_id ~ '^mfc_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT totp_enrollments_session_scope_fk FOREIGN KEY (application_instance_id, user_id, session_public_id)
        REFERENCES sessions(application_instance_id, user_id, public_id),
    CONSTRAINT totp_enrollments_encryption_version_check CHECK (encryption_version = 1),
    CONSTRAINT totp_enrollments_key_id_check CHECK (
        char_length(encryption_key_id) BETWEEN 1 AND 32
        AND encryption_key_id ~ '^[A-Za-z0-9._-]+$'
    ),
    CONSTRAINT totp_enrollments_nonce_check CHECK (octet_length(encryption_nonce) = 12),
    CONSTRAINT totp_enrollments_ciphertext_check CHECK (octet_length(encrypted_secret) >= 17),
    CONSTRAINT totp_enrollments_time_check CHECK (
        created_at < expires_at
        AND expires_at <= created_at + INTERVAL '10 minutes'
        AND (consumed_at IS NULL OR (created_at <= consumed_at AND consumed_at <= expires_at))
    )
);

CREATE UNIQUE INDEX totp_enrollments_application_user_pending_key
    ON totp_enrollments(application_instance_id, user_id)
    WHERE consumed_at IS NULL;
CREATE INDEX totp_enrollments_expiry_idx
    ON totp_enrollments(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX totp_enrollments_cleanup_idx
    ON totp_enrollments(expires_at, consumed_at);
CREATE INDEX totp_enrollments_key_reference_idx
    ON totp_enrollments(encryption_key_id, encryption_version) WHERE consumed_at IS NULL;

CREATE TABLE pending_mfa_authentications (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL DEFAULT ('mfp_' || gen_random_uuid()::text) UNIQUE,
    token_hash BYTEA NOT NULL UNIQUE,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    purpose TEXT NOT NULL DEFAULT 'authentication',
    primary_method TEXT NOT NULL,
    primary_context TEXT NOT NULL,
    required_factor TEXT NOT NULL,
    failed_attempts SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT pending_mfa_authentications_public_id_check CHECK (
        public_id ~ '^mfp_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT pending_mfa_authentications_token_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT pending_mfa_authentications_user_scope_fk FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT pending_mfa_authentications_purpose_check CHECK (purpose = 'authentication'),
    CONSTRAINT pending_mfa_authentications_primary_method_check CHECK (
        primary_method IN ('password','email_otp','phone_otp','social','passkey')
    ),
    CONSTRAINT pending_mfa_authentications_primary_context_check CHECK (
        char_length(primary_context) BETWEEN 1 AND 128
    ),
    CONSTRAINT pending_mfa_authentications_required_factor_check CHECK (required_factor = 'totp'),
    CONSTRAINT pending_mfa_authentications_failed_attempts_check CHECK (
        failed_attempts BETWEEN 0 AND 5
    ),
    CONSTRAINT pending_mfa_authentications_time_check CHECK (
        created_at < expires_at
        AND expires_at <= created_at + INTERVAL '5 minutes'
        AND (consumed_at IS NULL OR (created_at <= consumed_at AND consumed_at <= expires_at))
    )
);

CREATE INDEX pending_mfa_authentications_expiry_idx
    ON pending_mfa_authentications(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX pending_mfa_authentications_cleanup_idx
    ON pending_mfa_authentications(expires_at, consumed_at);
CREATE INDEX pending_mfa_authentications_application_user_idx
    ON pending_mfa_authentications(application_instance_id, user_id, created_at);
