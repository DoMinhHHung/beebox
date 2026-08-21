-- +goose Up
ALTER TABLE sessions
    ADD COLUMN mfa_method TEXT;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_mfa_method_check CHECK (
        mfa_method IS NULL OR mfa_method IN ('totp', 'recovery_code')
    );
ALTER TABLE sessions
    ADD CONSTRAINT sessions_application_user_public_id_key
        UNIQUE (application_instance_id, user_id, public_id);

CREATE TABLE reverification_grants (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL DEFAULT ('rvg_' || gen_random_uuid()::text) UNIQUE,
    verifier_hash BYTEA NOT NULL,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    target_session_public_id TEXT NOT NULL,
    proof_session_public_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    failed_attempts SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT reverification_grants_public_id_check CHECK (
        public_id ~ '^rvg_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT reverification_grants_verifier_hash_check CHECK (octet_length(verifier_hash) = 32),
    CONSTRAINT reverification_grants_verifier_hash_key UNIQUE (verifier_hash),
    CONSTRAINT reverification_grants_user_scope_fk FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT reverification_grants_target_session_scope_fk FOREIGN KEY (
        application_instance_id, user_id, target_session_public_id
    ) REFERENCES sessions(application_instance_id, user_id, public_id) ON DELETE CASCADE,
    CONSTRAINT reverification_grants_proof_session_scope_fk FOREIGN KEY (
        application_instance_id, user_id, proof_session_public_id
    ) REFERENCES sessions(application_instance_id, user_id, public_id) ON DELETE CASCADE,
    CONSTRAINT reverification_grants_purpose_check CHECK (
        purpose IN (
            'totp_enroll','totp_remove','totp_replace','recovery_regenerate',
            'passkey_register','passkey_remove','social_link','social_unlink',
            'session_revoke','session_revoke_others','sign_out_everywhere',
            'identifier_add','identifier_remove','identifier_primary'
        )
    ),
    CONSTRAINT reverification_grants_failed_attempts_check CHECK (failed_attempts BETWEEN 0 AND 5),
    CONSTRAINT reverification_grants_time_check CHECK (
        created_at < expires_at
        AND expires_at <= created_at + INTERVAL '10 minutes'
        AND (consumed_at IS NULL OR (created_at <= consumed_at AND consumed_at <= expires_at))
    )
);

CREATE INDEX reverification_grants_target_session_idx
    ON reverification_grants(application_instance_id, user_id, target_session_public_id, created_at DESC);
CREATE INDEX reverification_grants_proof_session_idx
    ON reverification_grants(proof_session_public_id, created_at DESC);
CREATE INDEX reverification_grants_expiry_idx
    ON reverification_grants(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX reverification_grants_cleanup_idx
    ON reverification_grants(expires_at, consumed_at);
