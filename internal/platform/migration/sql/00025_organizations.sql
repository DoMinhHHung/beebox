-- +goose Up
CREATE TABLE organizations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    opaque_id UUID NOT NULL DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT organizations_opaque_id_key UNIQUE (opaque_id),
    CONSTRAINT organizations_application_slug_key UNIQUE (application_instance_id, slug),
    CONSTRAINT organizations_name_check CHECK (
        name = btrim(name)
        AND char_length(name) BETWEEN 1 AND 100
        AND name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT organizations_slug_check CHECK (
        octet_length(slug) BETWEEN 1 AND 63
        AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
    ),
    CONSTRAINT organizations_timestamp_order_check CHECK (updated_at >= created_at)
);

CREATE INDEX organizations_application_opaque_id_idx
    ON organizations(application_instance_id, opaque_id);

CREATE INDEX organizations_application_list_idx
    ON organizations(application_instance_id, created_at, opaque_id);
