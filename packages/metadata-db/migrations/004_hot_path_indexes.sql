CREATE INDEX IF NOT EXISTS commits_by_created
  ON commits(created_at, id);

CREATE INDEX IF NOT EXISTS commits_by_volume_created
  ON commits(volume_id, created_at, id);

CREATE INDEX IF NOT EXISTS commits_by_branch_created
  ON commits(branch_id, created_at, id)
  WHERE branch_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS attach_sessions_by_branch_status
  ON attach_sessions(branch_id, status, attached_at);

CREATE INDEX IF NOT EXISTS blobs_by_created
  ON blobs(created_at, digest);
