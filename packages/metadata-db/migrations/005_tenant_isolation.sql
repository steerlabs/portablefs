-- Multi-tenant isolation: per-tenant API tokens + per-tenant blob references.

-- A bearer token resolves to a tenant server-side, so tenant identity is derived
-- from the authenticated credential, never trusted from the request body. Only the
-- sha256 of the token is stored.
CREATE TABLE IF NOT EXISTS tenant_tokens (
  token_hash TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  label TEXT,
  created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS tenant_tokens_by_tenant
  ON tenant_tokens(tenant_id);

-- Per-tenant references to globally-deduplicated blobs. A tenant may read a blob
-- only if one of its commits references it (closing the cross-tenant exfiltration
-- oracle: possessing a digest is not authorization). Maintained on commit; the
-- read-authz check is a single primary-key lookup.
CREATE TABLE IF NOT EXISTS blob_refs (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  digest TEXT NOT NULL,
  PRIMARY KEY (tenant_id, digest)
);

CREATE INDEX IF NOT EXISTS blob_refs_by_digest
  ON blob_refs(digest);
