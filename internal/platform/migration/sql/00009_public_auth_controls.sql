-- +goose Up
ALTER TABLE audit_events
    DROP CONSTRAINT audit_events_correlation_id_key;

CREATE INDEX audit_events_correlation_id_idx
    ON audit_events (correlation_id);

CREATE TABLE public_auth_idempotency (
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    operation TEXT NOT NULL,
    key_hash BYTEA NOT NULL,
    request_fingerprint BYTEA NOT NULL,
    result_status TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (application_instance_id, operation, key_hash),
    CHECK (octet_length(key_hash) = 32),
    CHECK (octet_length(request_fingerprint) = 32),
    CHECK (operation IN ('signup')),
    CHECK (result_status IS NULL OR result_status IN ('verification_pending')),
    CHECK (expires_at > created_at)
);

CREATE INDEX public_auth_idempotency_expiry_idx
    ON public_auth_idempotency (expires_at);

CREATE TABLE public_auth_rate_limits (
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    operation TEXT NOT NULL,
    subject_hash BYTEA NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (application_instance_id, operation, subject_hash),
    CHECK (octet_length(subject_hash) = 32),
    CHECK (operation IN ('signup_global', 'signup_identifier', 'verification_issue_global', 'verification_issue_identifier')),
    CHECK (request_count > 0),
    CHECK (expires_at > window_started_at)
);

CREATE INDEX public_auth_rate_limits_expiry_idx
    ON public_auth_rate_limits (expires_at);
