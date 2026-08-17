-- +goose Up
ALTER TABLE application_instances ADD COLUMN public_id TEXT;
UPDATE application_instances SET public_id = 'app_' || gen_random_uuid()::text WHERE public_id IS NULL;
ALTER TABLE application_instances ALTER COLUMN public_id SET DEFAULT ('app_' || gen_random_uuid()::text);
ALTER TABLE application_instances ALTER COLUMN public_id SET NOT NULL;
ALTER TABLE application_instances ADD CONSTRAINT application_instances_public_id_key UNIQUE (public_id);
ALTER TABLE application_instances ADD CONSTRAINT application_instances_public_id_check CHECK (public_id ~ '^app_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

ALTER TABLE users ADD COLUMN public_id TEXT;
UPDATE users SET public_id = 'usr_' || gen_random_uuid()::text WHERE public_id IS NULL;
ALTER TABLE users ALTER COLUMN public_id SET DEFAULT ('usr_' || gen_random_uuid()::text);
ALTER TABLE users ALTER COLUMN public_id SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_public_id_key UNIQUE (public_id);
ALTER TABLE users ADD CONSTRAINT users_public_id_check CHECK (public_id ~ '^usr_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');

CREATE TABLE application_credentials (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    kind TEXT NOT NULL CHECK (kind IN ('publishable', 'secret')),
    publishable_key TEXT UNIQUE,
    secret_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    CONSTRAINT application_credentials_public_id_check CHECK (public_id ~ '^cred_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT application_credentials_kind_value_check CHECK (
        (kind = 'publishable' AND publishable_key IS NOT NULL AND secret_hash IS NULL AND last_used_at IS NULL)
        OR
        (kind = 'secret' AND publishable_key IS NULL AND octet_length(secret_hash) = 32)
    )
);

CREATE INDEX application_credentials_application_idx ON application_credentials(application_instance_id);

CREATE TABLE application_allowed_origins (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    canonical_origin TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (application_instance_id, canonical_origin),
    CHECK (canonical_origin ~ '^https?://[^/?#]+$')
);
