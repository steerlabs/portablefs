ALTER TABLE commits
  ALTER COLUMN manifest DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS manifest_base_commit_id TEXT REFERENCES commits(id),
  ADD COLUMN IF NOT EXISTS manifest_diff JSONB,
  ADD COLUMN IF NOT EXISTS materialized_manifest BOOLEAN NOT NULL DEFAULT TRUE;

UPDATE commits
SET materialized_manifest = TRUE
WHERE manifest IS NOT NULL;

CREATE INDEX IF NOT EXISTS commits_manifest_base
  ON commits(manifest_base_commit_id);
