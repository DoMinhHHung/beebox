-- +goose Up
CREATE TABLE audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL REFERENCES application_instances(id),
    actor_kind TEXT NOT NULL CHECK (actor_kind <> ''),
    actor_user_id BIGINT NULL,
    subject_user_id BIGINT NULL,
    action TEXT NOT NULL CHECK (action <> ''),
    resource_category TEXT NOT NULL CHECK (resource_category <> ''),
    outcome TEXT NOT NULL CHECK (outcome <> ''),
    correlation_id BYTEA NOT NULL CHECK (octet_length(correlation_id) = 16),
    source TEXT NOT NULL CHECK (source <> ''),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT audit_events_correlation_id_key UNIQUE (correlation_id),
    CONSTRAINT audit_events_actor_user_scope_fk
        FOREIGN KEY (application_instance_id, actor_user_id)
        REFERENCES users(application_instance_id, id),
    CONSTRAINT audit_events_subject_user_scope_fk
        FOREIGN KEY (application_instance_id, subject_user_id)
        REFERENCES users(application_instance_id, id)
);
