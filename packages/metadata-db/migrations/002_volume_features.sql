ALTER TABLE branches
  ADD COLUMN IF NOT EXISTS parent_branch_id TEXT REFERENCES branches(id),
  ADD COLUMN IF NOT EXISTS forked_from_snapshot_id TEXT REFERENCES snapshots(id);

ALTER TABLE attach_sessions
  ADD COLUMN IF NOT EXISTS shared BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS root_path TEXT NOT NULL DEFAULT '';

ALTER TABLE leases
  ADD COLUMN IF NOT EXISTS exclusive BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS path_delegations (
  id TEXT PRIMARY KEY,
  volume_id TEXT NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
  branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  attach_session_id TEXT NOT NULL REFERENCES attach_sessions(id) ON DELETE CASCADE,
  lease_id TEXT NOT NULL REFERENCES leases(id) ON DELETE CASCADE,
  holder_id TEXT NOT NULL,
  path TEXT NOT NULL,
  recursive BOOLEAN NOT NULL DEFAULT TRUE,
  fencing_token BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  released_at BIGINT,
  revoked_at BIGINT
);

CREATE INDEX IF NOT EXISTS path_delegations_active_by_branch
  ON path_delegations(branch_id, released_at, revoked_at, expires_at);

CREATE INDEX IF NOT EXISTS path_delegations_by_session
  ON path_delegations(attach_session_id, released_at, revoked_at);

CREATE UNIQUE INDEX IF NOT EXISTS snapshots_unique_branch_name
  ON snapshots(branch_id, name)
  WHERE name IS NOT NULL;
