CREATE SCHEMA IF NOT EXISTS project;

CREATE TABLE IF NOT EXISTS project.accounts (
  id             UUID PRIMARY KEY,
  email          TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE project.accounts
  ADD COLUMN IF NOT EXISTS password_hash TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS project.owner_sessions (
  id          UUID PRIMARY KEY,
  account_id  UUID NOT NULL REFERENCES project.accounts (id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS owner_sessions_account_id_idx ON project.owner_sessions (account_id);

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
  USING (
    owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    OR current_setting('app.internal', true) = 'on'
  )
  WITH CHECK (owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid);

CREATE TABLE IF NOT EXISTS project.api_keys (
  id           UUID PRIMARY KEY,
  project_id   UUID NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,
  prefix       TEXT NOT NULL,
  secret_hash  TEXT NOT NULL,
  kind         TEXT NOT NULL CHECK (kind IN ('publishable', 'secret')),
  env          TEXT NOT NULL CHECK (env IN ('test', 'live')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS api_keys_project_id_idx ON project.api_keys (project_id);
CREATE INDEX IF NOT EXISTS api_keys_secret_hash_idx ON project.api_keys (secret_hash);

ALTER TABLE project.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.api_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS api_keys_by_owner ON project.api_keys;
CREATE POLICY api_keys_by_owner ON project.api_keys
  USING (
    current_setting('app.internal', true) = 'on'
    OR EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = api_keys.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = api_keys.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  );

CREATE TABLE IF NOT EXISTS project.origins (
  id          UUID PRIMARY KEY,
  project_id  UUID NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,
  origin      TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, origin)
);

CREATE INDEX IF NOT EXISTS origins_project_id_idx ON project.origins (project_id);

ALTER TABLE project.origins ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.origins FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS origins_by_owner ON project.origins;
CREATE POLICY origins_by_owner ON project.origins
  USING (
    current_setting('app.internal', true) = 'on'
    OR EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = origins.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = origins.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  );

CREATE TABLE IF NOT EXISTS project.modules (
  project_id  UUID NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  PRIMARY KEY (project_id, name)
);

ALTER TABLE project.modules ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.modules FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS modules_by_owner ON project.modules;
CREATE POLICY modules_by_owner ON project.modules
  USING (
    current_setting('app.internal', true) = 'on'
    OR EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = modules.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = modules.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  );

CREATE TABLE IF NOT EXISTS project.fields (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES project.projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('string', 'number', 'boolean', 'date')),
  required BOOLEAN NOT NULL DEFAULT false,
  unique_per_project BOOLEAN NOT NULL DEFAULT false,
  sort_order INT NOT NULL DEFAULT 0,
  UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS fields_project_id_idx ON project.fields (project_id);

ALTER TABLE project.fields ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.fields FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fields_by_owner ON project.fields;
CREATE POLICY fields_by_owner ON project.fields
  USING (
    current_setting('app.internal', true) = 'on'
    OR EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = fields.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = fields.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  );

CREATE TABLE IF NOT EXISTS project.oauth_providers (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,
  slug TEXT NOT NULL,
  client_id TEXT NOT NULL DEFAULT '',
  client_secret_enc TEXT NOT NULL DEFAULT '',
  extra JSONB NOT NULL DEFAULT '{}'::jsonb,
  redirect_uri TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT false,
  UNIQUE (project_id, slug)
);

CREATE INDEX IF NOT EXISTS oauth_providers_project_id_idx ON project.oauth_providers (project_id);

ALTER TABLE project.oauth_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.oauth_providers FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_providers_by_owner ON project.oauth_providers;
CREATE POLICY oauth_providers_by_owner ON project.oauth_providers
  USING (
    current_setting('app.internal', true) = 'on'
    OR EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = oauth_providers.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = oauth_providers.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  );
