-- +goose Up
ALTER TABLE external_identities
    ADD COLUMN public_id TEXT;

UPDATE external_identities
SET public_id = 'sli_' || gen_random_uuid()::text
WHERE public_id IS NULL;

ALTER TABLE external_identities
    ALTER COLUMN public_id SET DEFAULT ('sli_' || gen_random_uuid()::text),
    ALTER COLUMN public_id SET NOT NULL,
    ADD CONSTRAINT external_identities_public_id_key UNIQUE (public_id),
    ADD CONSTRAINT external_identities_public_id_check CHECK (
        public_id ~ '^sli_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    );

CREATE INDEX external_identities_application_user_created_public_idx
    ON external_identities(application_instance_id, user_id, created_at, public_id);

ALTER TABLE social_link_attempts
    ADD COLUMN canceled_at TIMESTAMPTZ,
    ADD CONSTRAINT social_link_attempts_canceled_time_check CHECK (
        canceled_at IS NULL OR (created_at <= canceled_at AND canceled_at <= expires_at)
    );
