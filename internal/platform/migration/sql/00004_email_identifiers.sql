-- +goose Up
ALTER TABLE users
    ADD CONSTRAINT users_application_instance_id_id_key
    UNIQUE (application_instance_id, id);

CREATE TABLE email_identifiers (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    email_address TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    verified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT email_identifiers_user_scope_fk
        FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id),

    CONSTRAINT email_identifiers_application_normalized_email_key
        UNIQUE (application_instance_id, normalized_email)
);
