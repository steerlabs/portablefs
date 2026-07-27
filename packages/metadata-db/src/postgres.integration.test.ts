import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterEach, describe, expect, test } from "vitest";
import {
  computeTreeHash,
  diffManifests,
} from "@portablefs/core";
import { protocolVersion, type TreeEntry, type TreeManifest } from "@portablefs/protocol";
import { PostgresMetadataRepository } from "./postgres.js";

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/portablefs";

const created: Array<{ volumeId: string; tenantId: string }> = [];

// Every attach in this suite targets a legacy_manifest branch, whose
// response always carries the manifest (journal-owned receipted attaches
// are the manifest-free family).
function requireManifest(attached: { manifest?: TreeManifest }): TreeManifest {
  if (!attached.manifest) {
    throw new Error("Expected a manifest on a legacy attach response.");
  }
  return attached.manifest;
}

afterEach(async () => {
  if (!runPostgresTests) {
    return;
  }
  const pool = new pg.Pool({ connectionString: databaseUrl });
  try {
    for (const { volumeId, tenantId } of created.splice(0).reverse()) {
      await cleanupVolume(pool, volumeId, tenantId);
    }
  } finally {
    await pool.end();
  }
});

describePostgres("PostgresMetadataRepository", () => {
  test("bounds diff-backed manifest chains with materialized checkpoints", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });

    try {
      await metadata.applyMigrations();
      const createdVolume = await metadata.createVolume({
        tenantId,
        volumeId,
        branchName: "main",
      });
      const attached = await metadata.attachVolume({
        tenantId,
        volumeId: createdVolume.volume.id,
        branchName: "main",
        mode: "write",
        shared: false,
        rootPath: "",
        holderId: `writer_${randomUUID()}`,
        leaseTtlMs: 600_000,
      });
      if (!attached.session.lease) {
        throw new Error("Expected write lease.");
      }

      let headCommitId = attached.branch.headCommitId;
      let manifest = requireManifest(attached);
      for (let index = 0; index < 40; index += 1) {
        const nextManifest = withFile(manifest, `files/${String(index).padStart(2, "0")}.txt`, `file ${index}\n`);
        const diff = diffManifests(manifest, nextManifest);
        const committed = await metadata.commitDeltaSummary({
          attachSessionId: attached.session.id,
          leaseId: attached.session.lease.id,
          fencingToken: attached.session.lease.fencingToken,
          expectedHeadCommitId: headCommitId,
          targetTreeHash: nextManifest.treeHash,
          diff,
        });
        headCommitId = committed.commit.id;
        manifest = nextManifest;
      }

      const status = await metadata.getStatus({ tenantId, volumeId, branchName: "main" });
      expect(status?.branch.headCommitId).toBe(headCommitId);
      expect(status?.head.manifest.treeHash).toBe(manifest.treeHash);
      expect(status?.head.manifest.entries).toHaveLength(40);

      const storage = await pool.query(
        `SELECT
           COUNT(*) FILTER (WHERE materialized_manifest = FALSE AND manifest IS NULL AND manifest_diff IS NOT NULL) AS diff_commits,
           COUNT(*) FILTER (WHERE materialized_manifest = TRUE AND manifest IS NOT NULL) AS materialized_commits,
           COUNT(*) FILTER (WHERE materialized_manifest = FALSE AND manifest IS NOT NULL) AS inconsistent_diff,
           COUNT(*) FILTER (WHERE materialized_manifest = TRUE AND manifest IS NULL) AS inconsistent_materialized
         FROM commits
         WHERE volume_id = $1`,
        [volumeId]
      );
      expect(Number(storage.rows[0].diff_commits)).toBeGreaterThan(0);
      expect(Number(storage.rows[0].materialized_commits)).toBeGreaterThanOrEqual(2);
      expect(Number(storage.rows[0].inconsistent_diff)).toBe(0);
      expect(Number(storage.rows[0].inconsistent_materialized)).toBe(0);

      const maxChain = await pool.query(
        `WITH RECURSIVE chain AS (
           SELECT id, manifest, manifest_base_commit_id, id AS origin_id, 0 AS depth
           FROM commits
           WHERE volume_id = $1
           UNION ALL
           SELECT commits.id, commits.manifest, commits.manifest_base_commit_id, chain.origin_id, chain.depth + 1
           FROM commits
           JOIN chain ON commits.id = chain.manifest_base_commit_id
           WHERE chain.manifest IS NULL
             AND chain.manifest_base_commit_id IS NOT NULL
             AND chain.depth < 128
         )
         SELECT COALESCE(MAX(diff_depth), 0) AS max_diff_depth
         FROM (
           SELECT origin_id, COUNT(*) FILTER (WHERE manifest IS NULL) AS diff_depth
           FROM chain
           GROUP BY origin_id
         ) depths`,
        [volumeId]
      );
      expect(Number(maxChain.rows[0].max_diff_depth)).toBeLessThanOrEqual(31);
    } finally {
      await metadata.close();
      await pool.end();
    }
  });

  test("waits for branch head changes through Postgres notifications", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });

    try {
      await metadata.applyMigrations();
      const createdVolume = await metadata.createVolume({
        tenantId,
        volumeId,
        branchName: "main",
      });
      const attached = await metadata.attachVolume({
        tenantId,
        volumeId: createdVolume.volume.id,
        branchName: "main",
        mode: "write",
        shared: false,
        rootPath: "",
        holderId: `writer_${randomUUID()}`,
        leaseTtlMs: 600_000,
      });
      if (!attached.session.lease) {
        throw new Error("Expected write lease.");
      }

      const started = Date.now();
      const wait = metadata.waitForHead({
        tenantId,
        volumeId,
        branchName: "main",
        afterCommitId: createdVolume.branch.headCommitId,
        timeoutMs: 5000,
      });
      const baseManifest = requireManifest(attached);
      const nextManifest = withFile(baseManifest, "notified.txt", "wake readers\n");
      const committed = await metadata.commitDeltaSummary({
        attachSessionId: attached.session.id,
        leaseId: attached.session.lease.id,
        fencingToken: attached.session.lease.fencingToken,
        expectedHeadCommitId: attached.branch.headCommitId,
        targetTreeHash: nextManifest.treeHash,
        diff: diffManifests(baseManifest, nextManifest),
      });
      const waited = await wait;

      expect(waited?.branch.headCommitId).toBe(committed.commit.id);
      expect(Date.now() - started).toBeLessThan(1000);
    } finally {
      await metadata.close();
    }
  });

  test("exposes the 017 maintenance read surface to the caller role", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();

      // Both projections execute under the admin DSN (grants from 017) and
      // answer bounded JSONB rows; a fresh database has no backlogged
      // generations and no unreleased pins.
      const generations = await metadata.history.generationsPastThreshold(70);
      expect(Array.isArray(generations)).toBe(true);
      for (const row of generations) {
        expect(typeof row.generationId).toBe("string");
        expect(typeof row.backlogPercent).toBe("number");
        expect(row.backlogPercent).toBeGreaterThanOrEqual(70);
      }
      const pins = await metadata.history.unreleasedServingPins();
      expect(Array.isArray(pins)).toBe(true);

      // Client-side threshold validation fails closed before any query.
      await expect(metadata.history.generationsPastThreshold(0)).rejects.toMatchObject({
        code: "HISTORY_BACKLOG_PERCENT_INVALID",
      });

      // The readiness probe proves connectivity + the complete 001..017 lineage.
      const probe = await metadata.probeControlPlane();
      expect(probe).toMatchObject({
        ok: true,
        migrationLineageComplete: true,
        reachable: true,
      });
    } finally {
      await metadata.close();
    }
  });

  test("applies hot-path indexes for commit and worker scans", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });

    try {
      await metadata.applyMigrations();
      const indexes = await pool.query(
        `SELECT indexname
         FROM pg_indexes
         WHERE schemaname = current_schema()
           AND indexname = ANY($1::text[])`,
        [[
          "commits_by_created",
          "commits_by_tenant_volume_created",
          "commits_by_branch_created",
          "attach_sessions_by_branch_status",
          "blobs_by_created",
        ]]
      );
      expect(new Set(indexes.rows.map((row) => row.indexname))).toEqual(
        new Set([
          "commits_by_created",
          "commits_by_tenant_volume_created",
          "commits_by_branch_created",
          "attach_sessions_by_branch_status",
          "blobs_by_created",
        ])
      );
    } finally {
      await metadata.close();
      await pool.end();
    }
  });

  test("GC mark/sweep primitives: live blobs are referenced, dangling uploads are sweepable", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });

    try {
      await metadata.applyMigrations();
      await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      const attached = await metadata.attachVolume({
        tenantId,
        volumeId,
        branchName: "main",
        mode: "write",
        shared: false,
        rootPath: "",
        holderId: `writer_${randomUUID()}`,
        leaseTtlMs: 600_000,
      });
      if (!attached.session.lease) {
        throw new Error("Expected write lease.");
      }

      // Commit a file referencing a blob digest (live), plus a dangling upload.
      const manifest = withFile(requireManifest(attached), "f.txt", "hi");
      const liveDigest = manifest.entries.find((entry) => entry.path === "f.txt")?.blob?.digest;
      if (!liveDigest) {
        throw new Error("expected a blob digest");
      }
      const dangling = `sha256:${"d".repeat(64)}`;

      await metadata.commitSummary({
        attachSessionId: attached.session.id,
        leaseId: attached.session.lease.id,
        fencingToken: attached.session.lease.fencingToken,
        expectedHeadCommitId: attached.branch.headCommitId,
        manifest,
        mutationCount: 1,
        byteCount: 2,
      });
      await metadata.recordBlobs([
        { digest: liveDigest, size: 2 },
        { digest: dangling, size: 5 },
      ]);

      // Mark: the committed digest is live; the dangling one is not.
      const referenced = await metadata.referencedDigests();
      expect(referenced.has(liveDigest)).toBe(true);
      expect(referenced.has(dangling)).toBe(false);

      // Both are sweep candidates by age; only the dangling one is unreferenced.
      const candidates = await metadata.listBlobsCreatedBefore(Date.now() + 60_000);
      const candidateDigests = new Set(candidates.map((blob) => blob.digest));
      expect(candidateDigests.has(liveDigest)).toBe(true);
      expect(candidateDigests.has(dangling)).toBe(true);

      // Sweep the dangling blob; the live blob is untouched.
      await metadata.deleteBlobRecord(dangling);
      const remaining = new Set((await metadata.listBlobRecords()).map((blob) => blob.digest));
      expect(remaining.has(dangling)).toBe(false);
      expect(remaining.has(liveDigest)).toBe(true);
      // And it is no longer referenced-as-live's complement — still referenced.
      expect((await metadata.referencedDigests()).has(liveDigest)).toBe(true);
    } finally {
      await metadata.close();
    }
  });

  test("scopes a volume id to its tenant while preserving same-tenant conflicts", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const otherTenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    created.push({ volumeId, tenantId: otherTenantId });

    try {
      await metadata.applyMigrations();
      const mine = await metadata.createVolume({
        tenantId,
        volumeId,
        branchName: "main",
      });

      // Same tenant retrying the same id conflicts explicitly.
      await expect(
        metadata.createVolume({ tenantId, volumeId, branchName: "main" })
      ).rejects.toMatchObject({
        name: "MetadataConflictError",
        code: "VOLUME_ALREADY_EXISTS",
        status: 409,
      });

      // The same client-generated id is valid in another tenant. Every
      // volume-qualified read is explicitly tenant-scoped.
      const other = await metadata.createVolume({
        tenantId: otherTenantId,
        volumeId,
        branchName: "main",
      });
      expect(other.volume.id).toBe(volumeId);
      await expect(
        metadata.getStatus({ tenantId, volumeId, branchName: "main" })
      ).resolves.toMatchObject({ volume: { tenantId } });
      await expect(
        metadata.getStatus({ tenantId: otherTenantId, volumeId, branchName: "main" })
      ).resolves.toMatchObject({ volume: { tenantId: otherTenantId } });
      await expect(
        metadata.tenantOwnsVolume({ tenantId, volumeId })
      ).resolves.toBe(true);
      await expect(
        metadata.tenantOwnsVolume({ tenantId: otherTenantId, volumeId })
      ).resolves.toBe(true);

      // The database independently rejects a child that combines tenant A's
      // volume identity with tenant B's branch, even though the public
      // volume id text is identical.
      await expect(
        pool.query(
          `INSERT INTO attach_sessions
           (id, tenant_id, volume_id, branch_id, mode, shared, root_path,
            base_commit_id, holder_id, status, client_info, attached_at)
           VALUES ($1, $2, $3, $4, 'read', FALSE, '', $5, 'cross-tenant',
                   'attached', '{}'::jsonb, $6)`,
          [
            `att_${randomUUID()}`,
            tenantId,
            volumeId,
            other.branch.id,
            mine.head.id,
            Date.now(),
          ]
        )
      ).rejects.toMatchObject({ code: "23503" });
    } finally {
      await metadata.close();
      await pool.end();
    }
  });

  test("lists tenant volumes and walks per-branch commit history", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const otherTenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    const secondVolumeId = `vol_${randomUUID()}`;
    const otherVolumeId = `vol_${randomUUID()}`;

    try {
      await metadata.applyMigrations();
      await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      await metadata.createVolume({ tenantId, volumeId: secondVolumeId, branchName: "main" });
      await metadata.createVolume({ tenantId: otherTenantId, volumeId: otherVolumeId, branchName: "main" });

      const attached = await metadata.attachVolume({
        tenantId,
        volumeId,
        branchName: "main",
        mode: "write",
        shared: false,
        rootPath: "",
        holderId: `writer_${randomUUID()}`,
        leaseTtlMs: 600_000,
      });
      if (!attached.session.lease) {
        throw new Error("Expected write lease.");
      }
      const initialHeadCommitId = attached.branch.headCommitId;
      const firstManifest = withFile(requireManifest(attached), "a.txt", "one\n");
      const firstCommit = await metadata.commitSummary({
        attachSessionId: attached.session.id,
        leaseId: attached.session.lease.id,
        fencingToken: attached.session.lease.fencingToken,
        expectedHeadCommitId: initialHeadCommitId,
        manifest: firstManifest,
        mutationCount: 1,
        byteCount: 4,
      });
      const secondManifest = withFile(firstManifest, "b.txt", "two\n");
      const secondCommit = await metadata.commitSummary({
        attachSessionId: attached.session.id,
        leaseId: attached.session.lease.id,
        fencingToken: attached.session.lease.fencingToken,
        expectedHeadCommitId: firstCommit.commit.id,
        manifest: secondManifest,
        mutationCount: 1,
        byteCount: 4,
      });

      const listed = await metadata.listVolumes({ tenantId, limit: 100 });
      expect(new Set(listed.map((entry) => entry.volume.id))).toEqual(
        new Set([volumeId, secondVolumeId])
      );
      const committedEntry = listed.find((entry) => entry.volume.id === volumeId);
      expect(committedEntry?.branches).toEqual([
        { name: "main", headCommitId: secondCommit.commit.id },
      ]);
      expect(await metadata.listVolumes({ tenantId, limit: 1 })).toHaveLength(1);
      expect(await metadata.listVolumes({ tenantId: `tenant_${randomUUID()}`, limit: 10 })).toEqual([]);

      const history = await metadata.listCommitHistory({
        tenantId,
        volumeId,
        branchName: "main",
        limit: 10,
      });
      expect(history?.map((commit) => commit.id)).toEqual([
        secondCommit.commit.id,
        firstCommit.commit.id,
        initialHeadCommitId,
      ]);
      expect(history?.[0]?.parentCommitId).toBe(firstCommit.commit.id);
      const capped = await metadata.listCommitHistory({
        tenantId,
        volumeId,
        branchName: "main",
        limit: 2,
      });
      expect(capped?.map((commit) => commit.id)).toEqual([
        secondCommit.commit.id,
        firstCommit.commit.id,
      ]);
      await expect(
        metadata.listCommitHistory({ tenantId, volumeId, branchName: "missing", limit: 10 })
      ).resolves.toBeNull();
      await expect(
        metadata.listCommitHistory({
          tenantId,
          volumeId: `vol_${randomUUID()}`,
          branchName: "main",
          limit: 10,
        })
      ).resolves.toBeNull();

      const index = await pool.query(
        `SELECT indexname FROM pg_indexes
         WHERE schemaname = current_schema() AND indexname = 'volumes_by_tenant_created'`
      );
      expect(index.rowCount).toBe(1);
    } finally {
      await pool.query("BEGIN");
      try {
        await cleanupVolumeRows(pool, tenantId, volumeId);
        await cleanupVolumeRows(pool, tenantId, secondVolumeId);
        await cleanupVolumeRows(pool, otherTenantId, otherVolumeId);
        await pool.query(`DELETE FROM tenants WHERE id = ANY($1::text[])`, [
          [tenantId, otherTenantId],
        ]);
        await pool.query("COMMIT");
      } catch (error) {
        await pool.query("ROLLBACK");
        throw error;
      } finally {
        await metadata.close();
        await pool.end();
      }
    }
  });

  test("retires a volume once and fences every ownership resolver", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const otherTenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });

    try {
      await metadata.applyMigrations();
      await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      const attached = await metadata.attachVolume({
        tenantId,
        volumeId,
        branchName: "main",
        mode: "write",
        shared: false,
        rootPath: "",
        holderId: `writer_${randomUUID()}`,
        leaseTtlMs: 600_000,
      });
      const lease = attached.session.lease;
      if (!lease) {
        throw new Error("Expected write lease.");
      }
      const snapshot = await metadata.snapshot({ tenantId, volumeId, branchName: "main" });

      // Live before: every resolver answers the owning tenant.
      await expect(metadata.tenantOwnsVolume({ tenantId, volumeId })).resolves.toBe(true);
      await expect(
        metadata.tenantOwnsVolume({ tenantId: otherTenantId, volumeId })
      ).resolves.toBe(false);
      await expect(metadata.sessionTenant(attached.session.id)).resolves.toBe(tenantId);
      await expect(metadata.leaseTenant(lease.id)).resolves.toBe(tenantId);
      await expect(metadata.snapshotTenant(snapshot.id)).resolves.toBe(tenantId);
      await expect(metadata.commitTenant(attached.branch.headCommitId)).resolves.toBe(tenantId);

      // A foreign tenant or unknown id never flips anything.
      await expect(metadata.retireVolume({ volumeId, tenantId: otherTenantId })).resolves.toBeNull();
      await expect(
        metadata.retireVolume({ volumeId: `vol_${randomUUID()}`, tenantId })
      ).resolves.toBeNull();

      const retiredAtMs = 1_700_000_000_123;
      await expect(metadata.retireVolume({ volumeId, tenantId, now: retiredAtMs })).resolves.toEqual({
        volumeId,
        retiredAtMs,
      });
      // Already retired = null from the flip; the stored receipt is
      // collectable by the owner alone (the route's replay answer), while
      // foreign and unknown ids stay null (non-enumerating 404 upstream).
      await expect(metadata.retireVolume({ volumeId, tenantId })).resolves.toBeNull();
      await expect(metadata.retiredVolumeReceipt({ volumeId, tenantId })).resolves.toEqual({
        volumeId,
        retiredAtMs,
      });
      await expect(
        metadata.retiredVolumeReceipt({ volumeId, tenantId: otherTenantId })
      ).resolves.toBeNull();
      await expect(
        metadata.retiredVolumeReceipt({ volumeId: `vol_${randomUUID()}`, tenantId })
      ).resolves.toBeNull();

      // The volume vanishes from listings and every resolver treats it — and
      // its session, lease, snapshot, and commits — as absent.
      const listed = await metadata.listVolumes({ tenantId, limit: 100 });
      expect(listed.map((entry) => entry.volume.id)).not.toContain(volumeId);
      await expect(metadata.tenantOwnsVolume({ tenantId, volumeId })).resolves.toBe(false);
      await expect(metadata.sessionTenant(attached.session.id)).resolves.toBeNull();
      await expect(metadata.leaseTenant(lease.id)).resolves.toBeNull();
      await expect(metadata.snapshotTenant(snapshot.id)).resolves.toBeNull();
      await expect(metadata.commitTenant(attached.branch.headCommitId)).resolves.toBeNull();

      // Nothing was deleted: the rows are all still there (storage
      // reclamation is deferred; only the route-level guard fences access).
      const status = await metadata.getStatus({ tenantId, volumeId, branchName: "main" });
      expect(status?.branch.headCommitId).toBe(attached.branch.headCommitId);
    } finally {
      await metadata.close();
    }
  });

  test("filters unreferenced blobs per tenant without leaking global existence", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const otherTenantId = `tenant_${randomUUID()}`;
    const mine = `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "3").slice(0, 64)}`;
    const theirs = `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "4").slice(0, 64)}`;
    const unknown = `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "5").slice(0, 64)}`;

    try {
      await metadata.applyMigrations();
      await metadata.createTenant(tenantId);
      await metadata.createTenant(otherTenantId);
      await metadata.addBlobRefs(tenantId, [mine]);
      await metadata.addBlobRefs(otherTenantId, [theirs]);
      // `theirs` exists globally (recorded + referenced by the other tenant), but
      // this tenant holds no reference: the probe must still report it missing.
      await metadata.recordBlobs([
        { digest: mine, size: 1 },
        { digest: theirs, size: 2 },
      ]);

      await expect(
        metadata.filterUnreferencedBlobs(tenantId, [mine, theirs, unknown, theirs])
      ).resolves.toEqual([theirs, unknown]);
      await expect(metadata.filterUnreferencedBlobs(otherTenantId, [theirs])).resolves.toEqual([]);
      await expect(metadata.filterUnreferencedBlobs(tenantId, [])).resolves.toEqual([]);
    } finally {
      await metadata.deleteBlobRecord(mine).catch(() => undefined);
      await metadata.deleteBlobRecord(theirs).catch(() => undefined);
      // Deleting the tenants cascades their blob_refs rows.
      await pool
        .query(`DELETE FROM tenants WHERE id = ANY($1::text[])`, [[tenantId, otherTenantId]])
        .catch(() => undefined);
      await pool.end();
      await metadata.close();
    }
  });

  test("checks blob existence from metadata without object-store calls", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const first = `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "0").slice(0, 64)}`;
    const second = `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "1").slice(0, 64)}`;
    const missing = `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "2").slice(0, 64)}`;

    try {
      await metadata.applyMigrations();
      await metadata.recordBlobs([
        { digest: first, size: 10 },
        { digest: second, size: 20, storageKey: "stored/second" },
      ]);

      await expect(metadata.hasBlobs([first, second, missing, first])).resolves.toEqual(
        new Set([first, second])
      );
    } finally {
      await metadata.deleteBlobRecord(first).catch(() => undefined);
      await metadata.deleteBlobRecord(second).catch(() => undefined);
      await metadata.close();
    }
  });
});

function withFile(previous: TreeManifest, filePath: string, contents: string): TreeManifest {
  const bytes = Buffer.from(contents, "utf8");
  const digest = `sha256:${randomUUID().replaceAll("-", "").padEnd(64, "0").slice(0, 64)}`;
  const entry: TreeEntry = {
    path: filePath,
    kind: "file",
    mode: 0o644,
    size: bytes.byteLength,
    mtimeMs: 0,
    executable: false,
    blob: {
      digest,
      size: bytes.byteLength,
      compression: "none",
      packed: false,
    },
  };
  const entries = [...previous.entries, entry].sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return {
    version: protocolVersion,
    entries,
    treeHash: computeTreeHash(entries),
  };
}

async function cleanupVolume(pool: pg.Pool, volumeId: string, tenantId: string): Promise<void> {
  await pool.query("BEGIN");
  try {
    await cleanupVolumeRows(pool, tenantId, volumeId);
    await pool.query(`DELETE FROM tenants WHERE id = $1`, [tenantId]);
    await pool.query("COMMIT");
  } catch (error) {
    await pool.query("ROLLBACK");
    throw error;
  }
}

async function cleanupVolumeRows(
  pool: pg.Pool,
  tenantId: string,
  volumeId: string
): Promise<void> {
  await pool.query(
    `DELETE FROM path_delegations WHERE tenant_id = $1 AND volume_id = $2`,
    [tenantId, volumeId]
  );
  await pool.query(`DELETE FROM leases WHERE tenant_id = $1 AND volume_id = $2`, [
    tenantId,
    volumeId,
  ]);
  await pool.query(
    `DELETE FROM attach_sessions WHERE tenant_id = $1 AND volume_id = $2`,
    [tenantId, volumeId]
  );
  await pool.query(`DELETE FROM snapshots WHERE tenant_id = $1 AND volume_id = $2`, [
    tenantId,
    volumeId,
  ]);
  await pool.query(
    `UPDATE volumes SET default_branch_id = NULL WHERE tenant_id = $1 AND id = $2`,
    [tenantId, volumeId]
  );
  await pool.query(`DELETE FROM branches WHERE tenant_id = $1 AND volume_id = $2`, [
    tenantId,
    volumeId,
  ]);
  await pool.query(`DELETE FROM commits WHERE tenant_id = $1 AND volume_id = $2`, [
    tenantId,
    volumeId,
  ]);
  await pool.query(`DELETE FROM volumes WHERE tenant_id = $1 AND id = $2`, [
    tenantId,
    volumeId,
  ]);
}
