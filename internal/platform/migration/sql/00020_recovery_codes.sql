-- +goose Up
ALTER TABLE totp_credentials
    ADD CONSTRAINT totp_credentials_id_user_scope_key UNIQUE (id, application_instance_id, user_id);

CREATE TABLE recovery_code_sets (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL DEFAULT ('rcs_' || gen_random_uuid()::text) UNIQUE,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    totp_credential_id BIGINT NOT NULL,
    created_by_session_public_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    invalidated_at TIMESTAMPTZ,

    CONSTRAINT recovery_code_sets_public_id_check CHECK (
        public_id ~ '^rcs_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    CONSTRAINT recovery_code_sets_user_scope_fk FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT recovery_code_sets_session_scope_fk FOREIGN KEY (
        application_instance_id, user_id, created_by_session_public_id
    ) REFERENCES sessions(application_instance_id, user_id, public_id),
    CONSTRAINT recovery_code_sets_totp_scope_fk FOREIGN KEY (
        totp_credential_id, application_instance_id, user_id
    ) REFERENCES totp_credentials(id, application_instance_id, user_id) ON DELETE CASCADE,
    CONSTRAINT recovery_code_sets_reason_check CHECK (reason IN ('activation','regeneration','replacement')),
    CONSTRAINT recovery_code_sets_time_check CHECK (
        invalidated_at IS NULL OR invalidated_at >= created_at
    ),
    CONSTRAINT recovery_code_sets_id_user_scope_key UNIQUE (id, application_instance_id, user_id)
);

CREATE UNIQUE INDEX recovery_code_sets_application_user_active_key
    ON recovery_code_sets(application_instance_id, user_id)
    WHERE invalidated_at IS NULL;
CREATE INDEX recovery_code_sets_totp_idx ON recovery_code_sets(totp_credential_id);
CREATE INDEX recovery_code_sets_regeneration_admission_idx
    ON recovery_code_sets(application_instance_id, user_id, created_by_session_public_id, created_at)
    WHERE reason = 'regeneration';

CREATE TABLE recovery_codes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recovery_set_id BIGINT NOT NULL REFERENCES recovery_code_sets(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT recovery_codes_set_hash_key UNIQUE (recovery_set_id, code_hash),
    CONSTRAINT recovery_codes_hash_check CHECK (octet_length(code_hash) = 32)
);

CREATE INDEX recovery_codes_unused_idx
    ON recovery_codes(recovery_set_id, code_hash)
    WHERE consumed_at IS NULL;

ALTER TABLE totp_enrollments
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'activation',
    ADD COLUMN replacement_recovery_set_id BIGINT,
    ADD CONSTRAINT totp_enrollments_purpose_check CHECK (purpose IN ('activation','replacement')),
    ADD CONSTRAINT totp_enrollments_replacement_binding_check CHECK (
        (purpose = 'activation' AND replacement_recovery_set_id IS NULL)
        OR (purpose = 'replacement' AND replacement_recovery_set_id IS NOT NULL)
    ),
    ADD CONSTRAINT totp_enrollments_replacement_scope_fk FOREIGN KEY (
        replacement_recovery_set_id, application_instance_id, user_id
    ) REFERENCES recovery_code_sets(id, application_instance_id, user_id);

CREATE INDEX recovery_code_sets_cleanup_idx
    ON recovery_code_sets(invalidated_at) WHERE invalidated_at IS NOT NULL;

CREATE TABLE sensitive_operation_admission (
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    session_public_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL,
    successful_count SMALLINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (application_instance_id, user_id, session_public_id, operation),
    CONSTRAINT sensitive_operation_admission_session_scope_fk FOREIGN KEY (
        application_instance_id, user_id, session_public_id
    ) REFERENCES sessions(application_instance_id, user_id, public_id) ON DELETE CASCADE,
    CONSTRAINT sensitive_operation_admission_operation_check CHECK (
        operation IN ('totp_enrollment_start','recovery_regeneration')
    ),
    CONSTRAINT sensitive_operation_admission_count_check CHECK (successful_count BETWEEN 1 AND 3),
    CONSTRAINT sensitive_operation_admission_time_check CHECK (
        window_started_at < expires_at
        AND expires_at <= window_started_at + INTERVAL '1 hour'
    )
);

CREATE INDEX sensitive_operation_admission_expiry_idx
    ON sensitive_operation_admission(expires_at);
