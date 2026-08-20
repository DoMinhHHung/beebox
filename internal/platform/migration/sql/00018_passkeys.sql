-- +goose Up
ALTER TABLE sessions
    ADD CONSTRAINT sessions_application_user_public_key
    UNIQUE (application_instance_id, user_id, public_id);

CREATE TABLE passkey_credentials (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL DEFAULT ('pky_' || gen_random_uuid()::text) UNIQUE,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    rp_id TEXT NOT NULL,
    credential_id BYTEA NOT NULL,
    credential_json JSONB NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT passkey_credentials_public_id_check CHECK (
        public_id ~ '^pky_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT passkey_credentials_user_scope_fk FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT passkey_credentials_rp_id_check CHECK (
        rp_id = lower(rp_id) AND char_length(rp_id) BETWEEN 1 AND 253
    ),
    CONSTRAINT passkey_credentials_id_length_check CHECK (
        octet_length(credential_id) BETWEEN 16 AND 1024
    ),
    CONSTRAINT passkey_credentials_name_check CHECK (
        name IS NULL OR char_length(name) BETWEEN 1 AND 64
    ),
    CONSTRAINT passkey_credentials_application_credential_key UNIQUE (
        application_instance_id, credential_id
    )
);

CREATE INDEX passkey_credentials_application_user_created_public_idx
    ON passkey_credentials(application_instance_id, user_id, created_at, public_id);
CREATE INDEX passkey_credentials_application_rp_credential_idx
    ON passkey_credentials(application_instance_id, rp_id, credential_id);

CREATE TABLE passkey_attempts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL DEFAULT ('pka_' || gen_random_uuid()::text) UNIQUE,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT,
    session_public_id TEXT,
    purpose TEXT NOT NULL,
    origin TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    session_data JSONB NOT NULL,
    challenge_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT passkey_attempts_public_id_check CHECK (
        public_id ~ '^pka_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT passkey_attempts_application_fk FOREIGN KEY (application_instance_id)
        REFERENCES application_instances(id),
    CONSTRAINT passkey_attempts_user_scope_fk FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT passkey_attempts_session_scope_fk FOREIGN KEY (application_instance_id, user_id, session_public_id)
        REFERENCES sessions(application_instance_id, user_id, public_id),
    CONSTRAINT passkey_attempts_purpose_check CHECK (purpose IN ('registration','authentication')),
    CONSTRAINT passkey_attempts_binding_check CHECK (
        (purpose = 'registration' AND user_id IS NOT NULL AND session_public_id IS NOT NULL)
        OR
        (purpose = 'authentication' AND user_id IS NULL AND session_public_id IS NULL)
    ),
    CONSTRAINT passkey_attempts_challenge_hash_check CHECK (octet_length(challenge_hash) = 32),
    CONSTRAINT passkey_attempts_origin_check CHECK (char_length(origin) BETWEEN 1 AND 2048),
    CONSTRAINT passkey_attempts_rp_id_check CHECK (
        rp_id = lower(rp_id) AND char_length(rp_id) BETWEEN 1 AND 253
    ),
    CONSTRAINT passkey_attempts_time_check CHECK (
        created_at < expires_at
        AND expires_at <= created_at + INTERVAL '5 minutes'
        AND (consumed_at IS NULL OR (created_at <= consumed_at AND consumed_at <= expires_at))
    )
);

CREATE INDEX passkey_attempts_expiry_idx ON passkey_attempts(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX passkey_attempts_application_user_purpose_idx
    ON passkey_attempts(application_instance_id, user_id, purpose, created_at);
