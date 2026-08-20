-- +goose Up
CREATE INDEX sessions_self_service_list_idx
    ON sessions(application_instance_id, user_id, created_at DESC, public_id DESC);
