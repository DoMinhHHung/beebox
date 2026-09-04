CREATE TABLE IF NOT EXISTS project.collections (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, slug)
);

CREATE INDEX IF NOT EXISTS collections_project_id_idx ON project.collections (project_id);

ALTER TABLE project.collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.collections FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS collections_by_owner ON project.collections;
CREATE POLICY collections_by_owner ON project.collections
  USING (
    current_setting('app.internal', true) = 'on'
    OR EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = collections.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = collections.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  );

CREATE TABLE IF NOT EXISTS project.documents (
  id UUID PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,
  collection_id UUID NOT NULL REFERENCES project.collections (id) ON DELETE CASCADE,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS documents_collection_id_idx ON project.documents (collection_id);
CREATE INDEX IF NOT EXISTS documents_project_id_idx ON project.documents (project_id);

ALTER TABLE project.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE project.documents FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS documents_by_owner ON project.documents;
CREATE POLICY documents_by_owner ON project.documents
  USING (
    current_setting('app.internal', true) = 'on'
    OR EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = documents.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM project.projects p
      WHERE p.id = documents.project_id
        AND p.owner_id = NULLIF(current_setting('app.current_account', true), '')::uuid
    )
  );
