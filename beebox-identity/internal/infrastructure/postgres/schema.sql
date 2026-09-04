CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.users (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL,
  env TEXT NOT NULL CHECK (env IN ('test', 'live')),
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, env, email)
);

CREATE INDEX IF NOT EXISTS users_project_env_email_idx ON identity.users (project_id, env, email);

CREATE TABLE IF NOT EXISTS identity.sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  project_id UUID NOT NULL,
  env TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON identity.sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_token_hash_idx ON identity.sessions (token_hash);
