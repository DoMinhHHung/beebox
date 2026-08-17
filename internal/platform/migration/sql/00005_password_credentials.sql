-- +goose Up
CREATE TABLE password_credentials (
    application_instance_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (application_instance_id, user_id),

    CONSTRAINT password_credentials_user_scope_fk
        FOREIGN KEY (application_instance_id, user_id)
        REFERENCES users(application_instance_id, id)
);
