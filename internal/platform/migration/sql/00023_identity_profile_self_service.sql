-- +goose Up
ALTER TABLE users
    ADD COLUMN display_name TEXT,
    ADD COLUMN given_name TEXT,
    ADD COLUMN family_name TEXT,
    ADD COLUMN locale TEXT,
    ADD CONSTRAINT users_display_name_length_check CHECK (display_name IS NULL OR char_length(display_name) <= 100),
    ADD CONSTRAINT users_given_name_length_check CHECK (given_name IS NULL OR char_length(given_name) <= 100),
    ADD CONSTRAINT users_family_name_length_check CHECK (family_name IS NULL OR char_length(family_name) <= 100),
    ADD CONSTRAINT users_locale_length_check CHECK (locale IS NULL OR octet_length(locale) <= 35);

ALTER TABLE email_identifiers
    ADD COLUMN public_id TEXT,
    ADD COLUMN is_primary BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE email_identifiers
SET public_id = 'eml_' || gen_random_uuid()::text
WHERE public_id IS NULL;

WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY application_instance_id, user_id
               ORDER BY created_at ASC, id ASC
           ) AS position
    FROM email_identifiers
    WHERE verified_at IS NOT NULL
)
UPDATE email_identifiers e
SET is_primary = TRUE
FROM ranked r
WHERE e.id = r.id AND r.position = 1;

ALTER TABLE email_identifiers
    ALTER COLUMN public_id SET DEFAULT ('eml_' || gen_random_uuid()::text),
    ALTER COLUMN public_id SET NOT NULL,
    ADD CONSTRAINT email_identifiers_public_id_key UNIQUE (public_id),
    ADD CONSTRAINT email_identifiers_public_id_check CHECK (
        public_id ~ '^eml_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    ADD CONSTRAINT email_identifiers_primary_verified_check CHECK (NOT is_primary OR verified_at IS NOT NULL);

CREATE UNIQUE INDEX email_identifiers_application_user_primary_key
    ON email_identifiers(application_instance_id, user_id)
    WHERE is_primary;

CREATE INDEX email_identifiers_application_user_created_public_idx
    ON email_identifiers(application_instance_id, user_id, created_at, public_id);

ALTER TABLE phone_identifiers
    ADD COLUMN public_id TEXT,
    ADD COLUMN is_primary BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE phone_identifiers
SET public_id = 'phn_' || gen_random_uuid()::text
WHERE public_id IS NULL;

WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY application_instance_id, user_id
               ORDER BY created_at ASC, id ASC
           ) AS position
    FROM phone_identifiers
    WHERE verified_at IS NOT NULL
)
UPDATE phone_identifiers p
SET is_primary = TRUE
FROM ranked r
WHERE p.id = r.id AND r.position = 1;

ALTER TABLE phone_identifiers
    ALTER COLUMN public_id SET DEFAULT ('phn_' || gen_random_uuid()::text),
    ALTER COLUMN public_id SET NOT NULL,
    ADD CONSTRAINT phone_identifiers_public_id_key UNIQUE (public_id),
    ADD CONSTRAINT phone_identifiers_public_id_check CHECK (
        public_id ~ '^phn_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    ADD CONSTRAINT phone_identifiers_primary_verified_check CHECK (NOT is_primary OR verified_at IS NOT NULL);

CREATE UNIQUE INDEX phone_identifiers_application_phone_key
    ON phone_identifiers(application_instance_id, phone_e164);

CREATE UNIQUE INDEX phone_identifiers_application_user_primary_key
    ON phone_identifiers(application_instance_id, user_id)
    WHERE is_primary;

CREATE INDEX phone_identifiers_application_user_created_public_idx
    ON phone_identifiers(application_instance_id, user_id, created_at, public_id);

CREATE TABLE phone_identifier_verification_challenges (
    application_instance_id BIGINT NOT NULL,
    phone_identifier_id BIGINT NOT NULL,
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

    PRIMARY KEY (application_instance_id, phone_identifier_id),

    CONSTRAINT phone_identifier_verification_challenges_phone_scope_fk
        FOREIGN KEY (application_instance_id, phone_identifier_id)
        REFERENCES phone_identifiers(application_instance_id, id)
        ON DELETE CASCADE,

    CONSTRAINT phone_identifier_verification_challenges_consumption_check
        CHECK ((consumed_at IS NULL AND code_hash IS NOT NULL) OR
               (consumed_at IS NOT NULL AND code_hash IS NULL)),

    CONSTRAINT phone_identifier_verification_challenges_window_order_check
        CHECK (issue_window_started_at <= last_issued_at)
);

CREATE INDEX phone_identifier_verification_challenges_expiry_idx
    ON phone_identifier_verification_challenges(expires_at, application_instance_id, phone_identifier_id);
