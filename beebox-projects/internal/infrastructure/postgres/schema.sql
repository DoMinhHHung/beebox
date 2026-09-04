CREATE SCHEMA IF NOT EXISTS project;

CREATE TABLE IF NOT EXISTS project.accounts (
  id          UUID PRIMARY KEY,
  email       TEXT NOT NULL UNIQUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project.projects (
  id          UUID PRIMARY KEY,
  owner_id    UUID NOT NULL REFERENCES project.accounts (id),
  plan_id     UUID NOT NULL,
  plan_slug   TEXT NOT NULL,
  name        TEXT NOT NULL,
  slug        TEXT NOT NULL UNIQUE,
  env         TEXT NOT NULL DEFAULT 'test' CHECK (env IN ('test', 'live')),
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (owner_id, name)
);

CREATE INDEX IF NOT EXISTS projects_owner_id_idx ON project.projects (owner_id);

ALTER TABLE project.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.projects FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS projects_by_owner ON project.projects;
CREATE POLICY projects_by_owner ON project.projects
  USING (owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid)
  WITH CHECK (owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid);
