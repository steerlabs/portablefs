import { createHash, randomUUID } from "node:crypto";
import pg from "pg";
import { describe, expect, test } from "vitest";
import { MetadataConflictError } from "./types.js";
import { PostgresMetadataRepository } from "./postgres.js";

// ---------------------------------------------------------------------------
// PostgreSQL integration for migration 018_managed_volume_fork: the full
// lineage applies with 018; forking a ready journal-era cut births a managed
// destination volume on the copied PFT2 root with the GC-pinning fork
// consumer, the immutable provenance row, and a serving proof the first
// authority claim can open; refusals are typed and roll back entirely; a
// replayed operationId answers exactly-once.
//
// Each test runs in its own throwaway database created from the admin URL
// (VOLUME_DATABASE_URL), so no shared state survives a run.
// ---------------------------------------------------------------------------

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/portablefs";

const zeroDigest = "0".repeat(64);

async function withTemporaryDatabase<T>(
  run: (metadata: PostgresMetadataRepository, pool: pg.Pool) => Promise<T>
): Promise<T> {
  const name = `portablefs_fork_${randomUUID().replaceAll("-", "")}`;
  const quoted = `"${name.replaceAll('"', '""')}"`;
  const target = new URL(databaseUrl);
  target.pathname = `/${name}`;
  const admin = new pg.Pool({ connectionString: databaseUrl });
  await admin.query(`CREATE DATABASE ${quoted}`);
  const metadata = new PostgresMetadataRepository(target.toString());
  const pool = new pg.Pool({ connectionString: target.toString() });
  try {
    await metadata.applyMigrations();
    return await run(metadata, pool);
  } finally {
    // Both pools are fully closed before the drop; a plain DROP (no FORCE)
    // never fires a FATAL into a client mid-teardown. Socket close can lag
    // pool.end() by a moment, so 55006 ("being accessed") retries briefly.
    await pool.end();
    await metadata.close();
    try {
      for (let attempt = 0; ; attempt += 1) {
        try {
          await admin.query(`DROP DATABASE IF EXISTS ${quoted}`);
          break;
        } catch (error) {
          if ((error as { code?: string }).code === "55006" && attempt < 50) {
            await new Promise((resolve) => setTimeout(resolve, 100));
            continue;
          }
          throw error;
        }
      }
    } finally {
      await admin.end();
    }
  }
}

interface ReadyCutFixture {
  cutId: string;
  /** The cut's canonical PFT2 result commit (the fork's copied base). */
  commitId: string;
  rootDigest: string;
  maxInoSeen: string;
  objectBytes: string;
  sourceBranchId: string;
}

// Builds one source volume with a cut in the requested state. A ready cut
// represents the already-verified worker settlement — result commit,
// canonical PFT2 provenance, live root object — exactly what
// pfh.volume_fork_from_cut and its installer re-prove. The rows are written
// directly (the gated suite runs as the database owner, the same posture as
// the other integration suites); no history worker runs here.
async function cutFixture(
  pool: pg.Pool,
  metadata: PostgresMetadataRepository,
  tenantId: string,
  volumeId: string,
  options: { state?: "ready" | "pending" } = {}
): Promise<ReadyCutFixture> {
  const state = options.state ?? "ready";
  const suffix = randomUUID().replaceAll("-", "");
  const created = await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
  const sourceBranchId = created.branch.id;
  const cutId = `hcut_${suffix}`;
  const commitId = `cpft2src_${suffix}`;
  const rootDigest = createHash("sha256").update(`root-${suffix}`).digest("hex");
  const maxInoSeen = "21474836481"; // compose(5, 1): a namespaced source root
  const objectBytes = "4096";
  if (state === "ready") {
    await pool.query(
      `INSERT INTO commits (
         id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,
         mutation_count, byte_count, created_at, materialized_manifest, commit_kind)
       VALUES ($1, $2, $3, $4, $5, $6, NULL, 0, $7, 1, FALSE, 'pft2')`,
      [
        commitId,
        tenantId,
        volumeId,
        sourceBranchId,
        created.head.id,
        `pft2:${rootDigest}`,
        objectBytes,
      ]
    );
  }
  await pool.query(
    `INSERT INTO pfh.history_cuts (
       id, tenant_id, volume_id, branch_id, branch_name, kind, source_kind,
       source_head_commit_id, materializer_version, replication_policy,
       dedup_key, request_fingerprint, op_tenant_id, op_domain, op_operation_id,
       state, result_commit_id, recovery_anchor_id,
       created_db_ms, updated_db_ms, ready_db_ms)
     VALUES ($1, $2, $3, $4, 'main', 'user', 'legacy_manifest',
       $5, 'pfm-test', '{"v":"1","requiredFailureDomains":["dom-a"],"policyEpoch":"1"}'::jsonb,
       $6, $7, $2, 'history-cut', $8,
       $9, $10, $11, 1, 1, $12)`,
    [
      cutId,
      tenantId,
      volumeId,
      sourceBranchId,
      created.head.id,
      `fixture\u0001${suffix}`,
      "f".repeat(64),
      `op_fixture_${suffix}`,
      state,
      state === "ready" ? commitId : null,
      state === "ready" ? `hanch_fixture_${suffix}` : null,
      state === "ready" ? 1 : null,
    ]
  );
  if (state === "ready") {
    await pool.query(
      `INSERT INTO pfh.pft2_commits (
         commit_id, cut_id, tenant_id, root_digest, root_size, max_ino_seen,
         object_count, object_bytes, created_db_ms)
       VALUES ($1, $2, $3, $4, 64, $5, 3, $6, 1)`,
      [commitId, cutId, tenantId, rootDigest, maxInoSeen, objectBytes]
    );
    await pool.query(
      `INSERT INTO pfh.objects (
         tenant_id, kind, digest, size, incarnation, state, created_db_ms, updated_db_ms)
       VALUES ($1, 'pft2', $2, 64, 1, 'live', 1, 1)`,
      [tenantId, `sha256:${rootDigest}`]
    );
  }
  return { cutId, commitId, rootDigest, maxInoSeen, objectBytes, sourceBranchId };
}

// Installs a LIVE fixture journal generation for the fork destination — the
// exact fresh seq-0 origin the first authority claim would create — so the
// serving proof can be exercised without a running authority. The 012 guard
// trigger admits it because the destination branch is born managed_journal.
async function installDestinationGeneration(
  pool: pg.Pool,
  tenantId: string,
  volumeId: string,
  branchId: string,
  baseCommitId: string
): Promise<string> {
  const generationId = `gen_${randomUUID().replaceAll("-", "")}`;
  await pool.query(
    `INSERT INTO pfj.journal_generations (
       id, tenant_id, volume_id, branch_id, epoch, record_codec, control_codec,
       base_commit_id, base_seq, base_digest, next_seq, tip_digest,
       physical_trimmed_seq, status, backlog_bytes, backlog_records,
       quota_backlog_bytes, quota_backlog_records, created_at, updated_at)
     VALUES ($1, $2, $3, $4, 1, 'pfj3', 'pfc2', $5, 0, $6, 0, $6,
       0, 'active', 0, 0, 1000000, 1000000, 1, 1)`,
    [generationId, tenantId, volumeId, branchId, baseCommitId, zeroDigest]
  );
  return generationId;
}

describePostgres("018 managed cross-volume fork (PostgreSQL)", () => {
  test("the full lineage applies with 018 and the fork surface exists", async () => {
    await withTemporaryDatabase(async (metadata, pool) => {
      // applyMigrations already ran; a second run is a no-op.
      await metadata.applyMigrations();
      const probe = await metadata.probeControlPlane();
      expect(probe).toMatchObject({ ok: true, migrationLineageComplete: true });
      const receipt = await pool.query(
        `SELECT id FROM portablefs_migrations WHERE id = '018_managed_volume_fork'`
      );
      expect(receipt.rowCount).toBe(1);
      const surface = await pool.query(
        `SELECT to_regclass('pfh.pft2_fork_commits') AS provenance,
                to_regprocedure('pfh.volume_fork_from_cut(text,text,text,text,text,text)') AS fork,
                to_regprocedure('pfh.pft2_fork_commit_install(text,text,text,text,text,text)') AS install`
      );
      expect(surface.rows[0]?.provenance).toBe("pfh.pft2_fork_commits");
      expect(surface.rows[0]?.fork).not.toBeNull();
      expect(surface.rows[0]?.install).not.toBeNull();
    });
  }, 240_000);

  test("forks a ready cut into a managed destination with GC pin, provenance, serving proof, and exact-once replay", async () => {
    await withTemporaryDatabase(async (metadata, pool) => {
      const tenantId = `tenant_${randomUUID()}`;
      const sourceVolumeId = `vol_${randomUUID()}`;
      const cut = await cutFixture(pool, metadata, tenantId, sourceVolumeId);

      const fork = await metadata.forkVolumeFromCut({
        cutId: cut.cutId,
        tenantId,
        branchName: "forked",
        operationId: "op-fork-1",
      });
      expect(fork.replayed).toBe(false);
      expect(fork.operationId).toBe("op-fork-1");
      expect(fork.commitKind).toBe("pft2");
      expect(fork.volume.tenantId).toBe(tenantId);
      expect(fork.volume.defaultBranchId).toBe(fork.branch.id);
      expect(fork.branch.name).toBe("forked");
      expect(fork.branch.headCommitId).toBe(fork.head.id);
      expect(fork.head.treeHash).toBe(`pft2:${cut.rootDigest}`);
      expect(fork.head.parentCommitId).toBe(cut.commitId);
      expect(fork.head.byteCount).toBe(Number(cut.objectBytes));

      // The destination branch is born managed (journal-native).
      const branchRow = await pool.query(
        `SELECT branch_mode, head_commit_id FROM branches WHERE id = $1`,
        [fork.branch.id]
      );
      expect(branchRow.rows[0]).toEqual({
        branch_mode: "managed_journal",
        head_commit_id: fork.head.id,
      });
      // The fork-point commit carries the copied identity and no manifest.
      const commitRow = await pool.query(
        `SELECT parent_commit_id, tree_hash, commit_kind, byte_count::TEXT AS byte_count, manifest
         FROM commits WHERE id = $1`,
        [fork.head.id]
      );
      expect(commitRow.rows[0]).toEqual({
        parent_commit_id: cut.commitId,
        tree_hash: `pft2:${cut.rootDigest}`,
        commit_kind: "pft2",
        byte_count: cut.objectBytes,
        manifest: null,
      });
      // The ACTIVE fork consumer is the durable GC root of the shared cut.
      const consumer = await pool.query(
        `SELECT cut_id, released_db_ms FROM pfh.cut_consumers
         WHERE consumer_kind = 'fork' AND consumer_id = $1`,
        [fork.branch.id]
      );
      expect(consumer.rows).toEqual([{ cut_id: cut.cutId, released_db_ms: null }]);
      // The immutable provenance row binds the exact copied facts.
      const provenance = await pool.query(
        `SELECT branch_id, tenant_id, volume_id, source_cut_id, source_commit_id, root_digest,
                root_size::TEXT AS root_size, max_ino_seen::TEXT AS max_ino_seen,
                object_count::TEXT AS object_count, object_bytes::TEXT AS object_bytes
         FROM pfh.pft2_fork_commits WHERE commit_id = $1`,
        [fork.head.id]
      );
      expect(provenance.rows[0]).toEqual({
        branch_id: fork.branch.id,
        tenant_id: tenantId,
        volume_id: fork.volume.id,
        source_cut_id: cut.cutId,
        source_commit_id: cut.commitId,
        root_digest: cut.rootDigest,
        root_size: "64",
        max_ino_seen: cut.maxInoSeen,
        object_count: "3",
        object_bytes: cut.objectBytes,
      });
      // Provenance rows are immutable (freeze trigger).
      await expect(
        pool.query(`DELETE FROM pfh.pft2_fork_commits WHERE commit_id = $1`, [fork.head.id])
      ).rejects.toMatchObject({ code: "PF001" });
      // Fresh never-reused destination allocator; ZERO inherited recovery
      // provenance (a fork starts with default PFC2 state).
      const namespace = await pool.query(
        `SELECT namespace::TEXT AS namespace, purpose FROM pfh.inode_namespaces WHERE branch_id = $1`,
        [fork.branch.id]
      );
      expect(namespace.rows[0]?.purpose).toBe("branch");
      const inherited = await pool.query(
        `SELECT
           (SELECT COUNT(*) FROM pfh.pft2_commits WHERE commit_id = $1)::INT AS cut_provenance,
           (SELECT COUNT(*) FROM pfh.recovery_anchors WHERE commit_id = $1)::INT AS anchors`,
        [fork.head.id]
      );
      expect(inherited.rows[0]).toEqual({ cut_provenance: 0, anchors: 0 });

      // Exact-once: the same operationId replays the recorded destination;
      // no second volume is created.
      const replay = await metadata.forkVolumeFromCut({
        cutId: cut.cutId,
        tenantId,
        branchName: "forked",
        operationId: "op-fork-1",
      });
      expect(replay.replayed).toBe(true);
      expect(replay.volume.id).toBe(fork.volume.id);
      expect(replay.branch.id).toBe(fork.branch.id);
      expect(replay.head.id).toBe(fork.head.id);
      const volumes = await pool.query(
        `SELECT COUNT(*)::INT AS n FROM volumes WHERE tenant_id = $1`,
        [tenantId]
      );
      expect(volumes.rows[0]?.n).toBe(2); // source + one destination
      // The same operationId with a CHANGED payload is a typed conflict.
      await expect(
        metadata.forkVolumeFromCut({
          cutId: cut.cutId,
          tenantId,
          branchName: "other-branch",
          operationId: "op-fork-1",
        })
      ).rejects.toSatisfy(
        (error: unknown) =>
          error instanceof MetadataConflictError && error.code === "HISTORY_FORK_REJECTED"
      );

      // A second fork of the SAME cut (fresh minted operationId) gets a
      // distinct destination and a distinct never-reused namespace.
      const second = await metadata.forkVolumeFromCut({
        cutId: cut.cutId,
        tenantId,
        branchName: "forked-2",
      });
      expect(second.volume.id).not.toBe(fork.volume.id);
      expect(second.operationId.startsWith("volfork_")).toBe(true);
      const secondNamespace = await pool.query(
        `SELECT namespace::TEXT AS namespace FROM pfh.inode_namespaces WHERE branch_id = $1`,
        [second.branch.id]
      );
      expect(secondNamespace.rows[0]?.namespace).not.toBe(namespace.rows[0]?.namespace);

      // The serving proof opens the fork destination: fresh seq-0 origin,
      // baseMode 'fork', the copied root, and the DESTINATION allocator.
      const generationId = await installDestinationGeneration(
        pool,
        tenantId,
        fork.volume.id,
        fork.branch.id,
        fork.head.id
      );
      const proof = await metadata.history.servingBaseProof({
        tenantId,
        commitId: fork.head.id,
        generationId,
        baseSeq: "0",
        baseDigest: zeroDigest,
        recordCodec: "pfj3",
        controlCodec: "pfc2",
      });
      expect(proof).toMatchObject({
        kind: "pft2",
        baseMode: "fork",
        commitId: fork.head.id,
        volumeId: fork.volume.id,
        branchId: fork.branch.id,
        root: {
          digest: cut.rootDigest,
          size: "64",
          maxInoSeen: cut.maxInoSeen,
        },
        allocator: {
          inodeNamespace: namespace.rows[0]?.namespace,
          nextLocal: "1",
        },
      });
      expect((proof as { anchor?: unknown }).anchor).toBeUndefined();

      // The destination's own NEXT cut sees a positive 'fork' base mode with
      // the provenance-table root facts (the worker fails closed without it).
      const nextCutId = `hcut_next_${randomUUID().replaceAll("-", "")}`;
      await pool.query(
        `INSERT INTO pfh.history_cuts (
           id, tenant_id, volume_id, branch_id, branch_name, kind, source_kind,
           generation_id, journal_epoch, record_codec, control_codec,
           source_base_commit_id, source_base_seq, source_base_digest,
           cut_seq_exclusive, cut_digest, cut_backlog_bytes, cut_backlog_records,
           materializer_version, replication_policy, dedup_key,
           request_fingerprint, op_tenant_id, op_domain, op_operation_id,
           state, created_db_ms, updated_db_ms)
         VALUES ($1, $2, $3, $4, 'forked', 'user', 'managed_journal',
           $5, 1, 'pfj3', 'pfc2',
           $6, 0, $7, 0, $7, 0, 0,
           'pfm-test', '{"v":"1","requiredFailureDomains":["dom-a"],"policyEpoch":"1"}'::jsonb, $8,
           $9, $2, 'history-cut', $10,
           'pending', 1, 1)`,
        [
          nextCutId,
          tenantId,
          fork.volume.id,
          fork.branch.id,
          generationId,
          fork.head.id,
          zeroDigest,
          `next\u0001${nextCutId}`,
          "e".repeat(64),
          `op_next_${nextCutId}`,
        ]
      );
      const nextStatus = await metadata.history.cutStatus(tenantId, nextCutId);
      expect(nextStatus?.baseCommit).toMatchObject({
        commitId: fork.head.id,
        commitKind: "pft2",
        baseMode: "fork",
        rootDigest: cut.rootDigest,
        rootSize: "64",
        maxInoSeen: cut.maxInoSeen,
      });
    });
  }, 240_000);

  test("refuses a not-ready cut and a destination collision typed, with full rollback", async () => {
    await withTemporaryDatabase(async (metadata, pool) => {
      const tenantId = `tenant_${randomUUID()}`;
      const pendingVolumeId = `vol_${randomUUID()}`;
      const pendingCut = await cutFixture(pool, metadata, tenantId, pendingVolumeId, {
        state: "pending",
      });
      await expect(
        metadata.forkVolumeFromCut({
          cutId: pendingCut.cutId,
          tenantId,
          branchName: "forked",
          operationId: "op-fork-pending",
        })
      ).rejects.toSatisfy(
        (error: unknown) =>
          error instanceof MetadataConflictError &&
          error.code === "HISTORY_FORK_REJECTED" &&
          error.status === 409
      );

      const readyVolumeId = `vol_${randomUUID()}`;
      const readyCut = await cutFixture(pool, metadata, tenantId, readyVolumeId);
      // Destination id collision (the CAS: the destination must not exist).
      await expect(
        metadata.forkVolumeFromCut({
          cutId: readyCut.cutId,
          tenantId,
          branchName: "forked",
          volumeId: readyVolumeId,
          operationId: "op-fork-collision",
        })
      ).rejects.toSatisfy(
        (error: unknown) =>
          error instanceof MetadataConflictError && error.code === "HISTORY_FORK_REJECTED"
      );

      // Full rollback: no volume, branch, namespace, consumer, provenance,
      // or ledger row of the refused attempts survives.
      const leftovers = await pool.query(
        `SELECT
           (SELECT COUNT(*) FROM volumes WHERE tenant_id = $1)::INT AS volumes,
           (SELECT COUNT(*) FROM pfh.pft2_fork_commits WHERE tenant_id = $1)::INT AS provenance,
           (SELECT COUNT(*) FROM pfh.cut_consumers WHERE tenant_id = $1 AND consumer_kind = 'fork')::INT AS consumers,
           (SELECT COUNT(*) FROM pfh.inode_namespaces WHERE tenant_id = $1)::INT AS namespaces,
           (SELECT COUNT(*) FROM pfh.resource_operations WHERE tenant_id = $1 AND domain = 'volume-fork')::INT AS operations`,
        [tenantId]
      );
      expect(leftovers.rows[0]).toEqual({
        volumes: 2, // the two source volumes only
        provenance: 0,
        consumers: 0,
        namespaces: 0,
        operations: 0,
      });

      // A refusal is not a permanent receipt: the SAME operationId succeeds
      // once the source is usable (here: against the ready cut).
      const retried = await metadata.forkVolumeFromCut({
        cutId: readyCut.cutId,
        tenantId,
        branchName: "forked",
        operationId: "op-fork-pending",
      });
      expect(retried.replayed).toBe(false);
      expect(retried.commitKind).toBe("pft2");
    });
  }, 240_000);

  test("forks into a tenant-local id already used by another tenant without mutating it", async () => {
    await withTemporaryDatabase(async (metadata, pool) => {
      const tenantA = `tenant_a_${randomUUID()}`;
      const tenantB = `tenant_b_${randomUUID()}`;
      const source = await cutFixture(
        pool,
        metadata,
        tenantA,
        `source_${randomUUID()}`
      );
      const sharedDestinationId = `shared_${randomUUID()}`;
      const other = await metadata.createVolume({
        tenantId: tenantB,
        volumeId: sharedDestinationId,
        branchName: "other-main",
      });

      const fork = await metadata.forkVolumeFromCut({
        cutId: source.cutId,
        tenantId: tenantA,
        branchName: "fork-main",
        volumeId: sharedDestinationId,
        operationId: `op_${randomUUID()}`,
      });
      expect(fork.volume.id).toBe(sharedDestinationId);
      expect(fork.volume.tenantId).toBe(tenantA);

      const rows = await pool.query(
        `SELECT tenant_id, default_branch_id
         FROM volumes
         WHERE id = $1
         ORDER BY tenant_id`,
        [sharedDestinationId]
      );
      expect(rows.rowCount).toBe(2);
      expect(
        rows.rows.find((row) => row.tenant_id === tenantA)?.default_branch_id
      ).toBe(fork.branch.id);
      expect(
        rows.rows.find((row) => row.tenant_id === tenantB)?.default_branch_id
      ).toBe(other.branch.id);
    });
  }, 240_000);

  test("a foreign tenant's ready cut is indistinguishable from a missing cut", async () => {
    await withTemporaryDatabase(async (metadata, pool) => {
      const tenantA = `tenant_a_${randomUUID()}`;
      const tenantB = `tenant_b_${randomUUID()}`;
      await metadata.createTenant(tenantA);
      const foreignVolumeId = `vol_${randomUUID()}`;
      const foreignCut = await cutFixture(pool, metadata, tenantB, foreignVolumeId);

      const refusal = async (cutId: string): Promise<MetadataConflictError> => {
        try {
          await metadata.forkVolumeFromCut({
            cutId,
            tenantId: tenantA,
            branchName: "forked",
            operationId: `op_${randomUUID()}`,
          });
        } catch (error) {
          expect(error).toBeInstanceOf(MetadataConflictError);
          return error as MetadataConflictError;
        }
        throw new Error("the fork must refuse");
      };

      const foreign = await refusal(foreignCut.cutId);
      const missing = await refusal("hcut_does_not_exist");
      expect(foreign.code).toBe("HISTORY_FORK_REJECTED");
      expect(missing.code).toBe(foreign.code);
      expect(missing.status).toBe(foreign.status);
      // Identical shape modulo the presented id: cross-tenant probing
      // learns nothing.
      expect(missing.message.replace("hcut_does_not_exist", foreignCut.cutId)).toBe(
        foreign.message
      );
      const forks = await pool.query(
        `SELECT COUNT(*)::INT AS n FROM pfh.pft2_fork_commits WHERE tenant_id IN ($1, $2)`,
        [tenantA, tenantB]
      );
      expect(forks.rows[0]?.n).toBe(0);
    });
  }, 240_000);
});
