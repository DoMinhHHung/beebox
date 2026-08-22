-- +goose Up
ALTER TABLE organizations
    ADD CONSTRAINT organizations_application_instance_id_id_key
    UNIQUE (application_instance_id, id);

CREATE TABLE organization_memberships (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL,
    organization_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    opaque_id UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT organization_memberships_opaque_id_key UNIQUE (opaque_id),
    CONSTRAINT organization_memberships_organization_scope_fk
        FOREIGN KEY (application_instance_id, organization_id)
        REFERENCES organizations(application_instance_id, id),
    CONSTRAINT organization_memberships_user_scope_fk
        FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT organization_memberships_application_organization_user_key
        UNIQUE (application_instance_id, organization_id, user_id)
);

CREATE INDEX organization_memberships_application_opaque_id_idx
    ON organization_memberships(application_instance_id, opaque_id);
