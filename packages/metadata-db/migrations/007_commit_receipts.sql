-- Commit receipts: the durable idempotency record for a commit dispatch,
-- keyed by the caller-supplied operation id. Written atomically in the SAME
-- transaction as the commit row it names, so a commit either exists with its
-- receipt or not at all. A retry after a lost response resolves the receipt
-- BEFORE lease/head validation and returns the identical commit; reusing an
-- operation id with a different request body is rejected by comparing the
-- canonical request fingerprint.
CREATE TABLE IF NOT EXISTS commit_receipts (
  operation_id TEXT PRIMARY KEY,
  commit_id TEXT NOT NULL REFERENCES commits(id),
  volume_id TEXT NOT NULL REFERENCES volumes(id),
  branch_id TEXT NOT NULL REFERENCES branches(id),
  request_fingerprint TEXT NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_commit_receipts_commit ON commit_receipts(commit_id);
