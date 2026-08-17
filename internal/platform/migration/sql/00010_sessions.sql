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
        'signin_identifier'
    ));

CREATE TABLE sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT sessions_public_id_check CHECK (public_id ~ '^ses_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT sessions_user_scope_fk FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT sessions_lifetime_check CHECK (idle_expires_at <= expires_at)
);

CREATE INDEX sessions_application_user_idx ON sessions(application_instance_id, user_id);

CREATE TABLE session_refresh_credentials (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id BIGINT NOT NULL REFERENCES sessions(id),
    verifier_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(verifier_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX session_refresh_credentials_session_idx ON session_refresh_credentials(session_id);
