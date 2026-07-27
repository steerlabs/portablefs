import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterEach, describe, expect, test } from "vitest";
import { MetadataConflictError, type AttachVolumeInput } from "./types.js";
import { PostgresMetadataRepository } from "./postgres.js";

// ---------------------------------------------------------------------------
// Journal-era metadata surface against real Postgres (the full migration
// lineage): receipted attach exact-once semantics and its manifest-free
// journal-branch resolution (including PFT2 heads with PFT2 parents — the
// fork/branch mount chain), born-ready manifest snapshots through the cut
// surface, cut snapshot labels (migration 019), PFT2 commit-row handling
// (listCommits/GC skip, typed manifest refusal), and journal-owned branch
// mode enforcement.
// ---------------------------------------------------------------------------

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/portablefs";

const zeroDigest = "0".repeat(64);

const created: Array<{ volumeId: string; tenantId: string }> = [];

// The singleton pfh policy cut_create requires; the shared dev database may
// already carry one from an earlier run (the CAS refuses a second epoch-0
// install), so install only when absent.
async function ensureHistoryPolicy(
  pool: pg.Pool,
  metadata: PostgresMetadataRepository
): Promise<void> {
  const existing = await pool.query(
    `SELECT policy_epoch FROM pfh.history_policies WHERE singleton_key = 'history'`
  );
  if ((existing.rowCount ?? 0) > 0) {
    return;
  }
  await metadata.history.installHistoryPolicy(
    JSON.stringify({
      v: "1",
      requiredFailureDomains: ["dom-a"],
      maxLastVerifiedAgeMs: 3_600_000,
      maxWorkerHeartbeatAgeMs: 60_000,
    }),
    "0"
  );
}

// A LIVE fixture journal generation — the fresh seq-0 origin a first
// authority claim would create — so cut capture and attach-base resolution
// can be exercised without a running authority. The 012 guard trigger
// admits it because the branch is managed_journal.
async function liveGenerationFixture(
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
       0, 'active', 0, 0, 1000000, 1000000, $7, $7)`,
    [generationId, tenantId, volumeId, branchId, baseCommitId, zeroDigest, Date.now()]
  );
  return generationId;
}

// One pft2 commit row exactly as the cut/fork planes insert it: no manifest
// of any shape, tree_hash = the content-addressed root identity.
async function insertPft2Commit(
  pool: pg.Pool | pg.PoolClient,
  input: {
    tenantId: string;
    commitId: string;
    volumeId: string;
    branchId: string;
    parentCommitId: string | null;
    rootHex: string;
  }
): Promise<void> {
  await pool.query(
    `INSERT INTO commits
     (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, manifest_base_commit_id, manifest_diff, materialized_manifest, mutation_count, byte_count, created_at, commit_kind)
     VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, FALSE, 0, 0, $7, 'pft2')`,
    [
      input.commitId,
      input.tenantId,
      input.volumeId,
      input.branchId,
      input.parentCommitId,
      `pft2:${input.rootHex}`,
      Date.now(),
    ]
  );
}

// The fork / branch-from-cut branch shape the repro chain produces: a branch
// born managed_journal whose head is a PFT2 commit (cpft2f_...) and whose
// PARENT is ALSO a PFT2 commit (the source branch's activation-cut commit,
// cpft2_...). Pre-fix, attach-base resolution failed this chain closed with
// VOLUME_COMMIT_PFT2_NO_MANIFEST and every fork/branch mount broke.
async function pft2ChainBranchFixture(
  pool: pg.Pool,
  input: {
    tenantId: string;
    volumeId: string;
    sourceBranchId: string;
    sourceHeadCommitId: string;
  }
): Promise<{ branchId: string; headCommitId: string; parentCommitId: string }> {
  const suffix = randomUUID().replaceAll("-", "");
  const parentCommitId = `cpft2_${suffix}`;
  const headCommitId = `cpft2f_${suffix}`;
  const branchId = `br_${suffix}`;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await insertPft2Commit(client, {
      tenantId: input.tenantId,
      commitId: parentCommitId,
      volumeId: input.volumeId,
      branchId: input.sourceBranchId,
      parentCommitId: input.sourceHeadCommitId,
      rootHex: "b".repeat(64),
    });
    await insertPft2Commit(client, {
      tenantId: input.tenantId,
      commitId: headCommitId,
      volumeId: input.volumeId,
      branchId,
      parentCommitId,
      rootHex: "c".repeat(64),
    });
    await client.query(
      `INSERT INTO branches
       (id, tenant_id, volume_id, name, head_commit_id, branch_mode, created_at, updated_at)
       VALUES ($1, $2, $3, 'forked', $4, 'managed_journal', $5, $5)`,
      [branchId, input.tenantId, input.volumeId, headCommitId, Date.now()]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  return { branchId, headCommitId, parentCommitId };
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

describePostgres("journal-era PostgresMetadataRepository", () => {
  test("receipted attach is exact-once: identical retries replay, different bodies conflict", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      // The receipted (exact-once) attach is the MANAGED authority's
      // admission and requires a journal-owned branch; birth it managed.
      await metadata.createVolume({ tenantId, volumeId, branchName: "main", managed: true });
      const operationId = `op_${randomUUID()}`;
      const request = {
        volumeId,
        branchName: "main",
        mode: "write" as const,
        shared: false,
        rootPath: "",
        holderId: "holder-1",
        leaseTtlMs: 600_000,
        tenantId,
        operationId,
      };

      const first = await metadata.attachVolume(request);
      expect(first.receipt).toMatchObject({ operationId, replayed: false });
      expect(first.current?.branch.id).toBe(first.branch.id);
      // Journal-owned attaches are manifest-free: the child binds the head
      // commit id and proves its base through pfh.serving_base_prove.
      expect(first.manifest).toBeUndefined();

      const replay = await metadata.attachVolume(request);
      expect(replay.receipt).toMatchObject({ operationId, replayed: true });
      expect(replay.session.id).toBe(first.session.id);
      expect(replay.branch.headCommitId).toBe(first.branch.headCommitId);
      expect(replay.manifest).toBeUndefined();

      await expect(
        metadata.attachVolume({ ...request, holderId: "different-holder" })
      ).rejects.toMatchObject({ code: "VOLUME_ATTACH_OPERATION_CONFLICT" });
    } finally {
      await metadata.close();
    }
  });

  test("receipted attach serves a PFT2 head with a PFT2 parent manifest-free (fork/branch mounts)", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      const volume = await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      const chain = await pft2ChainBranchFixture(pool, {
        tenantId,
        volumeId,
        sourceBranchId: volume.branch.id,
        sourceHeadCommitId: volume.head.id,
      });

      const request = {
        volumeId,
        branchName: "forked",
        mode: "write" as const,
        shared: false,
        rootPath: "",
        holderId: "authority-fork-1",
        leaseTtlMs: 600_000,
        tenantId,
        operationId: `op_${randomUUID()}`,
      };
      const attached = await metadata.attachVolume(request);
      // The attach identity names the REAL PFT2 head — no manifest is
      // hydrated or borrowed from any parent-chain shape.
      expect(attached.branch.headCommitId).toBe(chain.headCommitId);
      expect(attached.session.baseCommitId).toBe(chain.headCommitId);
      expect(attached.manifest).toBeUndefined();
      expect(attached.receipt?.replayed).toBe(false);
      const lease = attached.session.lease;
      if (!lease) {
        throw new Error("Expected an exclusive write lease.");
      }
      expect(lease.fencingToken).toBeGreaterThan(0);

      // The exact-once replay resolves the PFT2 base summary-only (the
      // pre-fix replay path hydrated the base manifest and failed typed).
      const replay = await metadata.attachVolume(request);
      expect(replay.receipt?.replayed).toBe(true);
      expect(replay.session.id).toBe(attached.session.id);
      expect(replay.branch.headCommitId).toBe(chain.headCommitId);
      expect(replay.manifest).toBeUndefined();

      // Once a live generation exists, the attach base is the GENERATION's
      // base commit (journal recovery = immutable base + suffix), not the
      // branch head — still manifest-free for a pft2 base.
      await metadata.detach({ attachSessionId: attached.session.id, releaseLease: true });
      const adoptedBaseId = `cpft2a_${randomUUID().replaceAll("-", "")}`;
      await insertPft2Commit(pool, {
        tenantId,
        commitId: adoptedBaseId,
        volumeId,
        branchId: chain.branchId,
        parentCommitId: chain.headCommitId,
        rootHex: "d".repeat(64),
      });
      await liveGenerationFixture(pool, tenantId, volumeId, chain.branchId, adoptedBaseId);
      const generationAttach = await metadata.attachVolume({
        ...request,
        operationId: `op_${randomUUID()}`,
      });
      expect(generationAttach.branch.headCommitId).toBe(adoptedBaseId);
      expect(generationAttach.session.baseCommitId).toBe(adoptedBaseId);
      expect(generationAttach.manifest).toBeUndefined();
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("receipted attach refuses rootPath on a journal-owned branch typed", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      await metadata.createVolume({ tenantId, volumeId, branchName: "main", managed: true });
      await expect(
        metadata.attachVolume({
          tenantId,
          volumeId,
          branchName: "main",
          mode: "write",
          shared: false,
          rootPath: "src",
          holderId: "authority-1",
          leaseTtlMs: 60_000,
          operationId: `op_${randomUUID()}`,
        })
      ).rejects.toMatchObject({ code: "VOLUME_ROOT_PATH_UNSUPPORTED", status: 409 });
    } finally {
      await metadata.close();
    }
  });

  test("legacy attach keeps its manifest and rootPath semantics", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      const volume = await metadata.createVolume({ tenantId, volumeId, branchName: "main" });

      // rootPath still validates against the head manifest on legacy branches.
      await expect(
        metadata.attachVolume({
          tenantId,
          volumeId,
          branchName: "main",
          mode: "read",
          shared: false,
          rootPath: "missing",
          holderId: "reader-1",
          leaseTtlMs: 60_000,
        })
      ).rejects.toMatchObject({ code: "VOLUME_ROOT_PATH_NOT_FOUND", status: 404 });

      const attached = await metadata.attachVolume({
        tenantId,
        volumeId,
        branchName: "main",
        mode: "write",
        shared: false,
        rootPath: "",
        holderId: "writer-1",
        leaseTtlMs: 60_000,
      });
      expect(attached.manifest?.treeHash).toBe(volume.head.manifest.treeHash);
      expect(attached.branch.headCommitId).toBe(volume.head.id);
    } finally {
      await metadata.close();
    }
  });

  test("snapshotCut on a manifest-headed branch is born ready, listed, and resolvable", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      await metadata.createVolume({ tenantId, volumeId, branchName: "main" });

      const record = await metadata.snapshotCut({
        volumeId,
        branchName: "main",
        tenantId,
        name: "base",
      });
      expect(record.state).toBe("ready");
      expect(record.name).toBe("base");
      expect(record.cutId).toBeUndefined();

      const listed = await metadata.listSnapshotRecords({ tenantId, volumeId });
      expect(listed.map((entry) => entry.id)).toContain(record.id);
      expect(listed.find((entry) => entry.id === record.id)?.state).toBe("ready");

      const source = await metadata.resolveSnapshotSource(record.id);
      expect(source?.kind).toBe("snapshot");

      // Ready commit-pinned records keep branching exactly as before.
      const branch = await metadata.createBranch({
        tenantId,
        volumeId,
        branchName: "from-snap",
        fromSnapshotId: record.id,
        fromBranch: "main",
      });
      expect(branch.branch.name).toBe("from-snap");
    } finally {
      await metadata.close();
    }
  });

  test("snapshot name persists on journal cut records through create, replay, and listing", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      const volume = await metadata.createVolume({
        tenantId,
        volumeId,
        branchName: "main",
        managed: true,
      });
      await ensureHistoryPolicy(pool, metadata);
      await liveGenerationFixture(pool, tenantId, volumeId, volume.branch.id, volume.head.id);

      const operationId = `op_${randomUUID()}`;
      const record = await metadata.snapshotCut({
        volumeId,
        branchName: "main",
        tenantId,
        name: "milestone",
        operationId,
      });
      expect(record.state).toBe("pending");
      expect(record.name).toBe("milestone");
      const cutId = record.cutId;
      if (!cutId) {
        throw new Error("Expected a cut-backed snapshot record.");
      }
      const stored = await pool.query(
        `SELECT user_label FROM pfh.history_cuts WHERE id = $1`,
        [cutId]
      );
      expect(stored.rows[0]?.user_label).toBe("milestone");

      // The exact-once replay resolves the pending operation to the SAME
      // named record.
      const replay = await metadata.snapshotCut({
        volumeId,
        branchName: "main",
        tenantId,
        name: "milestone",
        operationId,
      });
      expect(replay.id).toBe(record.id);
      expect(replay.state).toBe("pending");
      expect(replay.name).toBe("milestone");

      const listedPending = await metadata.listSnapshotRecords({ tenantId, volumeId });
      const pendingEntry = listedPending.find((entry) => entry.id === record.id);
      expect(pendingEntry?.state).toBe("pending");
      expect(pendingEntry?.name).toBe("milestone");

      // Worker settlement (materialized out of process in production): the
      // record keeps its name once ready.
      const resultCommitId = `cpft2_${randomUUID().replaceAll("-", "")}`;
      await insertPft2Commit(pool, {
        tenantId,
        commitId: resultCommitId,
        volumeId,
        branchId: volume.branch.id,
        parentCommitId: volume.head.id,
        rootHex: "e".repeat(64),
      });
      await pool.query(
        `UPDATE pfh.history_cuts
         SET state = 'ready', result_commit_id = $2, recovery_anchor_id = $3,
             ready_db_ms = $4, updated_db_ms = $4
         WHERE id = $1`,
        [cutId, resultCommitId, `hanch_${randomUUID().replaceAll("-", "")}`, Date.now()]
      );
      const listedReady = await metadata.listSnapshotRecords({ tenantId, volumeId });
      const readyEntry = listedReady.find((entry) => entry.id === record.id);
      expect(readyEntry?.state).toBe("ready");
      expect(readyEntry?.name).toBe("milestone");
      expect(readyEntry?.resultCommitId).toBe(resultCommitId);

      const status = await metadata.history.cutStatus(tenantId, cutId);
      expect(status?.userLabel).toBe("milestone");
      const source = await metadata.resolveSnapshotSource(cutId);
      expect(source?.kind).toBe("cut");
      expect(source?.kind === "cut" ? source.record.name : undefined).toBe("milestone");
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("an unnamed journal cut stays unnamed through create and listing", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      const volume = await metadata.createVolume({
        tenantId,
        volumeId,
        branchName: "main",
        managed: true,
      });
      await ensureHistoryPolicy(pool, metadata);
      await liveGenerationFixture(pool, tenantId, volumeId, volume.branch.id, volume.head.id);

      const record = await metadata.snapshotCut({ volumeId, branchName: "main", tenantId });
      expect(record.state).toBe("pending");
      expect(record.name).toBeUndefined();
      const cutId = record.cutId;
      if (!cutId) {
        throw new Error("Expected a cut-backed snapshot record.");
      }

      const resultCommitId = `cpft2_${randomUUID().replaceAll("-", "")}`;
      await insertPft2Commit(pool, {
        tenantId,
        commitId: resultCommitId,
        volumeId,
        branchId: volume.branch.id,
        parentCommitId: volume.head.id,
        rootHex: "f".repeat(64),
      });
      await pool.query(
        `UPDATE pfh.history_cuts
         SET state = 'ready', result_commit_id = $2, recovery_anchor_id = $3,
             ready_db_ms = $4, updated_db_ms = $4
         WHERE id = $1`,
        [cutId, resultCommitId, `hanch_${randomUUID().replaceAll("-", "")}`, Date.now()]
      );
      const listed = await metadata.listSnapshotRecords({ tenantId, volumeId });
      const entry = listed.find((item) => item.id === record.id);
      expect(entry?.state).toBe("ready");
      expect(entry?.name).toBeUndefined();
      expect(await metadata.history.cutStatus(tenantId, cutId)).not.toHaveProperty(
        "userLabel"
      );
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("PFT2 commit rows are skipped by listCommits/referencedDigests and refuse manifest reads typed", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      const volume = await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      const pft2CommitId = `cpft2_${randomUUID()}`;
      // A published cut commit as pfh.cut_mark_ready inserts it: pft2 kind,
      // no manifest of any shape, tree_hash = the content-addressed root.
      await pool.query(
        `INSERT INTO commits
         (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, manifest_base_commit_id, manifest_diff, materialized_manifest, mutation_count, byte_count, created_at, commit_kind)
         VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, FALSE, 0, 0, $7, 'pft2')`,
        [
          pft2CommitId,
          tenantId,
          volumeId,
          volume.branch.id,
          volume.head.id,
          `pft2:${"a".repeat(64)}`,
          Date.now(),
        ]
      );

      const commits = await metadata.listCommits();
      expect(commits.some((commit) => commit.id === pft2CommitId)).toBe(false);
      expect(commits.some((commit) => commit.id === volume.head.id)).toBe(true);

      const digests = await metadata.referencedDigests();
      expect(digests).toBeInstanceOf(Set);

      await expect(metadata.getCommit(pft2CommitId)).rejects.toMatchObject({
        code: "VOLUME_COMMIT_PFT2_NO_MANIFEST",
      });
      expect(await metadata.commitKind(pft2CommitId)).toBe("pft2");
      expect(await metadata.commitKind(volume.head.id)).toBe("manifest_v1");
      const summary = await metadata.getCommitSummary(pft2CommitId);
      expect(summary?.treeHash).toBe(`pft2:${"a".repeat(64)}`);

      // The cut-history probe tolerates branches with no cuts.
      const history = await metadata.listCommitHistory({
        tenantId,
        volumeId,
        branchName: "main",
        limit: 10,
      });
      expect(history?.map((commit) => commit.id)).toEqual([volume.head.id]);
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("journal-owned branches refuse manifest mutations typed while receipted attach serves them", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      const volume = await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      // A branch BORN managed (the only conversion-free journal birth the
      // schema admits): INSERT with the mode; the guard constrains UPDATEs.
      const managedBranchId = `br_${randomUUID()}`;
      await pool.query(
        `INSERT INTO branches
         (id, tenant_id, volume_id, name, head_commit_id, branch_mode, created_at, updated_at)
         VALUES ($1, $2, $3, 'managed', $4, 'managed_journal', $5, $5)`,
        [managedBranchId, tenantId, volumeId, volume.head.id, Date.now()]
      );

      expect(await metadata.branchMode({ tenantId, volumeId, branchName: "managed" })).toBe(
        "managed_journal"
      );
      expect(await metadata.branchMode({ tenantId, volumeId, branchName: "main" })).toBe(
        "legacy_manifest"
      );
      expect(
        await metadata.journalBinding({ tenantId, volumeId, branchName: "managed" })
      ).toBeNull();

      // Plain manifest attach refuses; the stale-head snapshot pin refuses.
      await expect(
        metadata.attachVolume({
          tenantId,
          volumeId,
          branchName: "managed",
          mode: "write",
          shared: false,
          rootPath: "",
          holderId: "legacy-holder",
          leaseTtlMs: 60_000,
        })
      ).rejects.toMatchObject({ code: "VOLUME_BRANCH_MODE_CONFLICT" });
      await expect(
        metadata.snapshot({ tenantId, volumeId, branchName: "managed" })
      ).rejects.toMatchObject({ code: "VOLUME_BRANCH_MODE_CONFLICT" });

      // The receipted attach serves the journal-owned branch: with no live
      // generation yet, the base is the branch head (the committed base the
      // first claim will bind).
      const receipted = await metadata.attachVolume({
        volumeId,
        branchName: "managed",
        mode: "write",
        shared: false,
        rootPath: "",
        holderId: "authority-1",
        leaseTtlMs: 60_000,
        tenantId,
        operationId: `op_${randomUUID()}`,
      });
      expect(receipted.branch.headCommitId).toBe(volume.head.id);
      expect(receipted.session.baseCommitId).toBe(volume.head.id);
      expect(receipted.receipt?.replayed).toBe(false);

      // The DATABASE guard independently refuses a manifest head move.
      await expect(
        pool.query(`UPDATE branches SET head_commit_id = $1 WHERE id = $2`, [
          volume.head.id,
          managedBranchId,
        ])
      ).resolves.toBeDefined(); // same head: no distinct-from change, allowed
      const otherCommit = `cmt_${randomUUID()}`;
      await pool.query(
        `INSERT INTO commits
         (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, mutation_count, byte_count, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0, 0, $8)`,
        [
          otherCommit,
          tenantId,
          volumeId,
          managedBranchId,
          volume.head.id,
          volume.head.treeHash,
          JSON.stringify(volume.head.manifest),
          Date.now(),
        ]
      );
      await expect(
        pool.query(`UPDATE branches SET head_commit_id = $1 WHERE id = $2`, [
          otherCommit,
          managedBranchId,
        ])
      ).rejects.toMatchObject({ code: "PF001" });
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("wait-head releases the LISTEN connection when the signal aborts", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      const volume = await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      const controller = new AbortController();
      const wait = metadata.waitForHead({
        tenantId,
        volumeId,
        branchName: "main",
        afterCommitId: volume.head.id,
        timeoutMs: 30_000,
        signal: controller.signal,
      });
      setTimeout(() => controller.abort(), 100);
      await expect(wait).rejects.toMatchObject({ name: "AbortError" });
    } finally {
      await metadata.close();
    }
  });

  test("snapshotCut replays converge through an explicit operation id on journal branches only", async () => {
    // Manifest-headed branches take the born-ready path where the exact-once
    // identity is the snapshot row itself; the pfh operation ledger applies
    // once a live generation exists. This test pins the boundary: no journal
    // generation means no pfh cut row is ever created.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      const record = await metadata.snapshotCut({
        volumeId,
        branchName: "main",
        tenantId,
        operationId: `op_${randomUUID()}`,
      });
      expect(record.state).toBe("ready");
      const cuts = await pool.query(`SELECT id FROM pfh.history_cuts WHERE volume_id = $1`, [
        volumeId,
      ]);
      expect(cuts.rowCount).toBe(0);
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("MetadataConflictError carries typed codes through the journal-era surface", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const tenantId = `tenant_${randomUUID()}`;
    const volumeId = `vol_${randomUUID()}`;
    created.push({ volumeId, tenantId });
    try {
      await metadata.applyMigrations();
      await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
      // Receipted attach without a tenant identity is a typed 403.
      await expect(
        metadata.attachVolume(
          {
            volumeId,
            branchName: "main",
            mode: "read",
            shared: false,
            rootPath: "",
            holderId: "h",
            leaseTtlMs: 60_000,
            operationId: "op-1",
          } as unknown as AttachVolumeInput
        )
      ).rejects.toSatisfy(
        (error: unknown) =>
          error instanceof MetadataConflictError && error.code === "VOLUME_TENANT_REQUIRED"
      );
    } finally {
      await metadata.close();
    }
  });
});

async function cleanupVolume(pool: pg.Pool, volumeId: string, tenantId: string): Promise<void> {
  await pool.query("BEGIN");
  try {
    await pool.query(
      `DELETE FROM pfh.history_cuts WHERE tenant_id = $1 AND volume_id = $2`,
      [tenantId, volumeId]
    );
    // Cut capture issues the branch's durable inode namespace and settles a
    // permanent resource operation; both are tenant/volume-scoped fixtures
    // here (no FK holds them).
    await pool.query(
      `DELETE FROM pfh.inode_namespaces WHERE tenant_id = $1 AND volume_id = $2`,
      [tenantId, volumeId]
    );
    await pool.query(`DELETE FROM pfh.resource_operations WHERE tenant_id = $1`, [tenantId]);
    await pool.query(`DELETE FROM attach_receipts WHERE tenant_id = $1`, [tenantId]);
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
    // Branch rows forked from a snapshot reference it; release the FK
    // before the snapshot rows go.
    await pool.query(
      `UPDATE branches SET forked_from_snapshot_id = NULL
       WHERE tenant_id = $1 AND volume_id = $2`,
      [tenantId, volumeId]
    );
    await pool.query(
      `DELETE FROM snapshots WHERE tenant_id = $1 AND volume_id = $2`,
      [tenantId, volumeId]
    );
    await pool.query(
      `UPDATE volumes SET default_branch_id = NULL
       WHERE tenant_id = $1 AND id = $2`,
      [tenantId, volumeId]
    );
    await pool.query(
      `DELETE FROM branches WHERE tenant_id = $1 AND volume_id = $2`,
      [tenantId, volumeId]
    );
    await pool.query(
      `DELETE FROM commits WHERE tenant_id = $1 AND volume_id = $2`,
      [tenantId, volumeId]
    );
    await pool.query(`DELETE FROM volumes WHERE tenant_id = $1 AND id = $2`, [
      tenantId,
      volumeId,
    ]);
    await pool.query(`DELETE FROM tenants WHERE id = $1`, [tenantId]);
    await pool.query("COMMIT");
  } catch (error) {
    await pool.query("ROLLBACK");
    throw error;
  }
}
