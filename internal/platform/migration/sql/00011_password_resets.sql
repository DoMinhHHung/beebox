-- +goose Up
ALTER TABLE password_credentials
    ADD COLUMN generation BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD CONSTRAINT password_credentials_generation_check CHECK (generation > 0);

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
        'signin_identifier',
        'password_reset_global',
        'password_reset_identifier'
    ));

CREATE TABLE password_reset_challenges (
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    email_identifier_id BIGINT NOT NULL,
    generation BIGINT NOT NULL DEFAULT 1 CHECK (generation > 0),
    code_hash TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    issue_count INTEGER NOT NULL DEFAULT 1 CHECK (issue_count > 0),
    issue_window_started_at TIMESTAMPTZ NOT NULL,
    last_issued_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (application_instance_id, user_id),
    CONSTRAINT password_reset_challenges_user_scope_fk
        FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT password_reset_challenges_email_scope_fk
        FOREIGN KEY (application_instance_id, email_identifier_id)
        REFERENCES email_identifiers(application_instance_id, id),
    CONSTRAINT password_reset_challenges_code_state_check
        CHECK ((consumed_at IS NULL AND code_hash IS NOT NULL) OR consumed_at IS NOT NULL)
);

CREATE INDEX password_reset_challenges_email_idx
    ON password_reset_challenges(application_instance_id, email_identifier_id);
