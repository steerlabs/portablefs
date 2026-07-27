-- Recovery-only content objects for live checkpoint sidecars. These references
-- are deliberately outside the user manifest/tree hash, but have the same
-- lifetime as the commit that made the sidecar authoritative. The commit row,
-- normalized references, receipt, and branch-head update are written in one
-- transaction by the repository.
ALTER TABLE commit_receipts
  ADD COLUMN IF NOT EXISTS auxiliary_blob_digests_hash TEXT;

CREATE TABLE IF NOT EXISTS commit_auxiliary_blob_refs (
  commit_id TEXT NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
  digest TEXT NOT NULL REFERENCES blobs(digest) ON DELETE RESTRICT,
  PRIMARY KEY (commit_id, digest)
);

CREATE INDEX IF NOT EXISTS commit_auxiliary_blob_refs_by_digest
  ON commit_auxiliary_blob_refs(digest);
