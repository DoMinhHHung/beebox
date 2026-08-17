-- +goose Up
ALTER TABLE email_identifiers
    ADD CONSTRAINT email_identifiers_application_instance_id_id_key
    UNIQUE (application_instance_id, id);

CREATE TABLE email_verification_challenges (
    application_instance_id BIGINT NOT NULL,
    email_identifier_id BIGINT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    code_hash TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    failed_attempts INTEGER NOT NULL CHECK (failed_attempts >= 0 AND failed_attempts <= 5),
    issue_count INTEGER NOT NULL CHECK (issue_count > 0 AND issue_count <= 3),
    issue_window_started_at TIMESTAMPTZ NOT NULL,
    last_issued_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (application_instance_id, email_identifier_id),

    CONSTRAINT email_verification_challenges_email_scope_fk
        FOREIGN KEY (application_instance_id, email_identifier_id)
        REFERENCES email_identifiers(application_instance_id, id),

    CONSTRAINT email_verification_challenges_consumption_check
        CHECK ((consumed_at IS NULL AND code_hash IS NOT NULL) OR
               (consumed_at IS NOT NULL AND code_hash IS NULL)),

    CONSTRAINT email_verification_challenges_window_order_check
        CHECK (issue_window_started_at <= last_issued_at)
);
