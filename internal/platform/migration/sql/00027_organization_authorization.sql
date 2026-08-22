-- +goose Up
ALTER TABLE organization_memberships
    ADD CONSTRAINT organization_memberships_application_instance_id_id_key
    UNIQUE (application_instance_id, id);

ALTER TABLE audit_events
    ADD COLUMN organization_reference TEXT,
    ADD COLUMN related_resource_reference TEXT,
    ADD CONSTRAINT audit_events_organization_reference_check
        CHECK (organization_reference IS NULL OR char_length(organization_reference) BETWEEN 1 AND 256),
    ADD CONSTRAINT audit_events_related_resource_reference_check
        CHECK (related_resource_reference IS NULL OR char_length(related_resource_reference) BETWEEN 1 AND 256);

CREATE TABLE organization_role_definitions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    opaque_id UUID NOT NULL DEFAULT gen_random_uuid(),
    role_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT organization_role_definitions_opaque_id_key UNIQUE (opaque_id),
    CONSTRAINT organization_role_definitions_application_key_key UNIQUE (application_instance_id, role_key),
    CONSTRAINT organization_role_definitions_application_instance_id_id_key UNIQUE (application_instance_id, id),
    CONSTRAINT organization_role_definitions_role_key_check CHECK (
        octet_length(role_key) BETWEEN 1 AND 63
        AND role_key ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'
    )
);

CREATE INDEX organization_role_definitions_application_opaque_id_idx
    ON organization_role_definitions(application_instance_id, opaque_id);

CREATE TABLE organization_permission_definitions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    opaque_id UUID NOT NULL DEFAULT gen_random_uuid(),
    permission_key TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    action_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT organization_permission_definitions_opaque_id_key UNIQUE (opaque_id),
    CONSTRAINT organization_permission_definitions_application_key_key UNIQUE (application_instance_id, permission_key),
    CONSTRAINT organization_permission_definitions_application_resource_action_key UNIQUE (application_instance_id, resource_key, action_key),
    CONSTRAINT organization_permission_definitions_application_instance_id_id_key UNIQUE (application_instance_id, id),
    CONSTRAINT organization_permission_definitions_permission_key_check CHECK (
        octet_length(permission_key) BETWEEN 1 AND 63
        AND permission_key ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'
    ),
    CONSTRAINT organization_permission_definitions_resource_key_check CHECK (
        octet_length(resource_key) BETWEEN 1 AND 63
        AND resource_key ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'
    ),
    CONSTRAINT organization_permission_definitions_action_key_check CHECK (
        octet_length(action_key) BETWEEN 1 AND 63
        AND action_key ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'
    )
);

CREATE INDEX organization_permission_definitions_application_opaque_id_idx
    ON organization_permission_definitions(application_instance_id, opaque_id);

CREATE TABLE organization_role_permission_grants (
    application_instance_id BIGINT NOT NULL,
    role_definition_id BIGINT NOT NULL,
    permission_definition_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT organization_role_permission_grants_pkey
        PRIMARY KEY (application_instance_id, role_definition_id, permission_definition_id),
    CONSTRAINT organization_role_permission_grants_role_scope_fk
        FOREIGN KEY (application_instance_id, role_definition_id)
        REFERENCES organization_role_definitions(application_instance_id, id),
    CONSTRAINT organization_role_permission_grants_permission_scope_fk
        FOREIGN KEY (application_instance_id, permission_definition_id)
        REFERENCES organization_permission_definitions(application_instance_id, id)
);

CREATE TABLE organization_membership_role_assignments (
    application_instance_id BIGINT NOT NULL,
    membership_id BIGINT NOT NULL,
    role_definition_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT organization_membership_role_assignments_pkey
        PRIMARY KEY (application_instance_id, membership_id),
    CONSTRAINT organization_membership_role_assignments_membership_scope_fk
        FOREIGN KEY (application_instance_id, membership_id)
        REFERENCES organization_memberships(application_instance_id, id),
    CONSTRAINT organization_membership_role_assignments_role_scope_fk
        FOREIGN KEY (application_instance_id, role_definition_id)
        REFERENCES organization_role_definitions(application_instance_id, id),
    CONSTRAINT organization_membership_role_assignments_timestamp_order_check
        CHECK (updated_at >= created_at)
);
