-- Tenant-scoped volume listing (GET /v1/volumes): volumes previously had no
-- tenant_id index, so listing a tenant's volumes was a full table scan.
CREATE INDEX IF NOT EXISTS volumes_by_tenant_created
  ON volumes(tenant_id, created_at, id);
