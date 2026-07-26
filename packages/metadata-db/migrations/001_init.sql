CREATE TABLE IF NOT EXISTS portablefs_migrations (
  id TEXT PRIMARY KEY,
  applied_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS volumes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  default_branch_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS commits (
  id TEXT PRIMARY KEY,
  volume_id TEXT NOT NULL,
  branch_id TEXT,
  parent_commit_id TEXT REFERENCES commits(id),
  tree_hash TEXT NOT NULL,
  manifest JSONB NOT NULL,
  mutation_count INTEGER NOT NULL,
  byte_count BIGINT NOT NULL,
  created_by_attach_session_id TEXT,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS branches (
  id TEXT PRIMARY KEY,
  volume_id TEXT NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  head_commit_id TEXT NOT NULL REFERENCES commits(id),
  lease_counter BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  UNIQUE(volume_id, name)
);

ALTER TABLE volumes
  ADD CONSTRAINT volumes_default_branch_fk
  FOREIGN KEY (default_branch_id) REFERENCES branches(id);

CREATE TABLE IF NOT EXISTS attach_sessions (
  id TEXT PRIMARY KEY,
  volume_id TEXT NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
  branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('read', 'write')),
  base_commit_id TEXT NOT NULL REFERENCES commits(id),
  holder_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('attached', 'detached')),
  client_info JSONB NOT NULL DEFAULT '{}'::jsonb,
  attached_at BIGINT NOT NULL,
  detached_at BIGINT
);

CREATE TABLE IF NOT EXISTS leases (
  id TEXT PRIMARY KEY,
  volume_id TEXT NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
  branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  attach_session_id TEXT NOT NULL REFERENCES attach_sessions(id) ON DELETE CASCADE,
  holder_id TEXT NOT NULL,
  fencing_token BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  released_at BIGINT
);

CREATE INDEX IF NOT EXISTS leases_active_by_branch
  ON leases(branch_id, released_at, expires_at);

CREATE TABLE IF NOT EXISTS snapshots (
  id TEXT PRIMARY KEY,
  volume_id TEXT NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
  branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  commit_id TEXT NOT NULL REFERENCES commits(id),
  name TEXT,
  created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS snapshots_by_volume_created
  ON snapshots(volume_id, created_at);

CREATE TABLE IF NOT EXISTS blobs (
  digest TEXT PRIMARY KEY,
  size BIGINT NOT NULL,
  storage_key TEXT,
  created_at BIGINT NOT NULL,
  last_verified_at BIGINT
);

CREATE TABLE IF NOT EXISTS packs (
  id TEXT PRIMARY KEY,
  volume_id TEXT NOT NULL REFERENCES volumes(id) ON DELETE CASCADE,
  object_key TEXT NOT NULL,
  blob_count INTEGER NOT NULL,
  byte_count BIGINT NOT NULL,
  created_at BIGINT NOT NULL
);

