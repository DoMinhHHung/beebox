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
    ON email_identifiers(application_instance_id, user_id, created_at DESC, public_id DESC);

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

-- The verified-only application-wide ownership constraint was introduced in
-- 00014 and remains the final concurrency arbiter. Unverified possession claims
-- deliberately do not reserve a phone number across users. A user may not keep
-- duplicate copies of the same canonical number in one application.
CREATE UNIQUE INDEX phone_identifiers_application_user_phone_key
    ON phone_identifiers(application_instance_id, user_id, phone_e164);

CREATE UNIQUE INDEX phone_identifiers_application_user_primary_key
    ON phone_identifiers(application_instance_id, user_id)
    WHERE is_primary;

CREATE INDEX phone_identifiers_application_user_created_public_idx
    ON phone_identifiers(application_instance_id, user_id, created_at DESC, public_id DESC);

-- First-possession verification and primary selection share the same database
-- write boundary. The triggers run only for insertion or verified_at changes,
-- so explicit primary switching is not intercepted. Under concurrent first
-- verification, the partial primary unique indexes serialize the winner and a
-- losing transaction rolls back without exposing a verified primary-less row.
CREATE FUNCTION beebox_assign_first_email_primary() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.verified_at IS NOT NULL
       AND NOT NEW.is_primary
       AND NOT EXISTS (
           SELECT 1
           FROM email_identifiers e
           WHERE e.application_instance_id = NEW.application_instance_id
             AND e.user_id = NEW.user_id
             AND e.is_primary
             AND e.id <> NEW.id
       ) THEN
        NEW.is_primary := TRUE;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER email_identifiers_first_primary_insert
    BEFORE INSERT ON email_identifiers
    FOR EACH ROW EXECUTE FUNCTION beebox_assign_first_email_primary();
CREATE TRIGGER email_identifiers_first_primary_verify
    BEFORE UPDATE OF verified_at ON email_identifiers
    FOR EACH ROW EXECUTE FUNCTION beebox_assign_first_email_primary();

CREATE FUNCTION beebox_assign_first_phone_primary() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.verified_at IS NOT NULL
       AND NOT NEW.is_primary
       AND NOT EXISTS (
           SELECT 1
           FROM phone_identifiers p
           WHERE p.application_instance_id = NEW.application_instance_id
             AND p.user_id = NEW.user_id
             AND p.is_primary
             AND p.id <> NEW.id
       ) THEN
        NEW.is_primary := TRUE;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER phone_identifiers_first_primary_insert
    BEFORE INSERT ON phone_identifiers
    FOR EACH ROW EXECUTE FUNCTION beebox_assign_first_phone_primary();
CREATE TRIGGER phone_identifiers_first_primary_verify
    BEFORE UPDATE OF verified_at ON phone_identifiers
    FOR EACH ROW EXECUTE FUNCTION beebox_assign_first_phone_primary();

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
        CHECK (issue_window_started_at <= last_issued_at),

    CONSTRAINT phone_identifier_verification_challenges_time_check
        CHECK (last_issued_at < expires_at AND created_at <= updated_at)
);

CREATE INDEX phone_identifier_verification_challenges_expiry_idx
    ON phone_identifier_verification_challenges(expires_at, application_instance_id, phone_identifier_id);
