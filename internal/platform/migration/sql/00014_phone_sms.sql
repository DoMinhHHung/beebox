-- +goose Up
CREATE TABLE phone_identifiers (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    phone_e164 TEXT NOT NULL,
    verified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT phone_identifiers_user_scope_fk FOREIGN KEY (application_instance_id, user_id) REFERENCES users(application_instance_id, id),
    CONSTRAINT phone_identifiers_application_instance_id_id_key UNIQUE (application_instance_id, id),
    CONSTRAINT phone_identifiers_e164_check CHECK (phone_e164 ~ '^\+[1-9][0-9]{1,14}$'),
    CONSTRAINT phone_identifiers_time_check CHECK (created_at <= updated_at AND (verified_at IS NULL OR created_at <= verified_at))
);
CREATE UNIQUE INDEX phone_identifiers_verified_application_phone_key ON phone_identifiers (application_instance_id, phone_e164) WHERE verified_at IS NOT NULL;
CREATE INDEX phone_identifiers_application_user_idx ON phone_identifiers (application_instance_id, user_id);

CREATE TABLE phone_signup_challenges (
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    phone_fingerprint BYTEA NOT NULL CHECK (octet_length(phone_fingerprint) = 32),
    generation BIGINT NOT NULL,
    code_hash TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    issue_count INTEGER NOT NULL,
    issue_window_started_at TIMESTAMPTZ NOT NULL,
    last_issued_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (application_instance_id, phone_fingerprint),
    CONSTRAINT phone_signup_challenges_generation_check CHECK (generation > 0),
    CONSTRAINT phone_signup_challenges_failed_attempts_check CHECK (failed_attempts >= 0 AND failed_attempts <= 5),
    CONSTRAINT phone_signup_challenges_issue_count_check CHECK (issue_count >= 1 AND issue_count <= 3),
    CONSTRAINT phone_signup_challenges_active_code_check CHECK ((consumed_at IS NULL AND code_hash IS NOT NULL) OR (consumed_at IS NOT NULL AND code_hash IS NULL)),
    CONSTRAINT phone_signup_challenges_time_check CHECK (issue_window_started_at <= last_issued_at AND last_issued_at < expires_at AND created_at <= updated_at)
);
CREATE INDEX phone_signup_challenges_expiry_idx ON phone_signup_challenges (expires_at);

CREATE TABLE phone_otp_signin_challenges (
    application_instance_id BIGINT NOT NULL,
    phone_identifier_id BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    code_hash TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    issue_count INTEGER NOT NULL,
    issue_window_started_at TIMESTAMPTZ NOT NULL,
    last_issued_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (application_instance_id, phone_identifier_id),
    CONSTRAINT phone_otp_signin_challenges_phone_scope_fk FOREIGN KEY (application_instance_id, phone_identifier_id) REFERENCES phone_identifiers(application_instance_id, id),
    CONSTRAINT phone_otp_signin_challenges_generation_check CHECK (generation > 0),
    CONSTRAINT phone_otp_signin_challenges_failed_attempts_check CHECK (failed_attempts >= 0 AND failed_attempts <= 5),
    CONSTRAINT phone_otp_signin_challenges_issue_count_check CHECK (issue_count >= 1 AND issue_count <= 3),
    CONSTRAINT phone_otp_signin_challenges_active_code_check CHECK ((consumed_at IS NULL AND code_hash IS NOT NULL) OR (consumed_at IS NOT NULL AND code_hash IS NULL)),
    CONSTRAINT phone_otp_signin_challenges_time_check CHECK (issue_window_started_at <= last_issued_at AND last_issued_at < expires_at AND created_at <= updated_at)
);
CREATE INDEX phone_otp_signin_challenges_expiry_idx ON phone_otp_signin_challenges (expires_at);

ALTER TABLE public_auth_rate_limits DROP CONSTRAINT public_auth_rate_limits_operation_check;
ALTER TABLE public_auth_rate_limits ADD CONSTRAINT public_auth_rate_limits_operation_check CHECK (operation IN (
    'signup_global','signup_identifier','verification_issue_global','verification_issue_identifier','signin_global','signin_identifier',
    'password_reset_global','password_reset_identifier','signup_pre_kdf_global','signup_pre_kdf_identifier','verification_confirm_global','verification_confirm_identifier',
    'password_reset_issue_pre_kdf_global','password_reset_issue_pre_kdf_identifier','password_reset_confirm_global','password_reset_confirm_identifier',
    'email_otp_issue_global','email_otp_issue_identifier','email_otp_confirm_global','email_otp_confirm_identifier',
    'phone_signup_issue_global','phone_signup_issue_identifier','phone_signup_confirm_global','phone_signup_confirm_identifier',
    'phone_otp_issue_global','phone_otp_issue_identifier','phone_otp_confirm_global','phone_otp_confirm_identifier'
));
