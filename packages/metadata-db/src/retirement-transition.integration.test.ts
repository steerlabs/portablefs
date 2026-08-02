import { createHash, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";

// ---------------------------------------------------------------------------
// ROUND 17c / FINDING 5, against real Postgres on the full lineage.
//
// (a) THE RETAINED TAIL. Round 16's DELETE route called
//     pfj.journal_retire_for_volume inline, caught any failure, LOGGED it and
//     answered success. Nothing was written down, and the maintenance loop
//     could not recover the work from rows: it only reclaims BELOW an
//     existing horizon, and a live generation's horizon is its own base_seq,
//     so a never-retired generation offers zero reclaimable records and never
//     appears in pfj.journal_reclaim_candidates. Without a client replay the
//     tail was retained forever.
//
// (b) THE PENDING-CUT CLAMP. pfh.volume_retire_cleanup and
//     pfj.journal_retire_for_volume were separate transactions with no common
//     lock, and pfh.cut_create never looked at volumes.retired_at. A cut
//     created after cleanup committed and before journal retirement locked
//     the generation clamps journal_reclaim_horizon to its source_base_seq —
//     forever, because cleanup has already run, the maintenance loop only
//     CREATES cuts, and the volume is gone so no client will settle it.
//
// Migration 033 closes both: the obligation is enqueued in the retirement
// flip's own transaction, the transition runs cleanup + journal retirement in
// ONE transaction under every branch advisory lock of the volume, and
// cut_create refuses a retired volume.
// ---------------------------------------------------------------------------

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/portablefs";

const zeroDigest = "0".repeat(64);
const pools: pg.Pool[] = [];

afterAll(async () => {
  await Promise.all(pools.splice(0).map((pool) => pool.end()));
});

function newPool(): pg.Pool {
  const pool = new pg.Pool({ connectionString: databaseUrl });
  pools.push(pool);
  return pool;
}

function hexOf(seed: string): string {
  return createHash("sha256").update(seed, "utf8").digest("hex");
}

interface Fixture {
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  generationId: string;
}

async function ensureHistoryPolicy(
  pool: pg.Pool,
  metadata: PostgresMetadataRepository
): Promise<void> {
  const existing = await pool.query(
    `SELECT 1 FROM pfh.history_policies WHERE singleton_key = 'history'`
  );
  if ((existing.rowCount ?? 0) > 0) {
    return;
  }
  await metadata.history.installHistoryPolicy(
    JSON.stringify({
      v: "1",
      requiredFailureDomains: ["itest-a", "itest-b", "itest-c"],
      maxLastVerifiedAgeMs: 3_600_000,
      maxWorkerHeartbeatAgeMs: 60_000,
    }),
    "0"
  );
}

/** A managed volume with a pfj3 generation carrying `records` real records. */
async function managedFixture(
  pool: pg.Pool,
  metadata: PostgresMetadataRepository,
  records: number
): Promise<Fixture> {
  const tenantId = `tenant_${randomUUID()}`;
  const volumeId = `vol_${randomUUID()}`;
  const branchName = "main";
  await metadata.createVolume({ tenantId, volumeId, branchName, managed: true });
  const branch = await pool.query(
    `SELECT id, head_commit_id FROM branches WHERE tenant_id=$1 AND volume_id=$2 AND name=$3`,
    [tenantId, volumeId, branchName]
  );
  const branchId = String(branch.rows[0].id);
  const bornCommitId = String(branch.rows[0].head_commit_id);
  const generationId = `gen_${randomUUID().replaceAll("-", "")}`;
  await pool.query(
    `INSERT INTO pfj.journal_generations (
       id, tenant_id, volume_id, branch_id, epoch, record_codec, control_codec,
       base_commit_id, base_seq, base_digest, next_seq, tip_digest,
       physical_trimmed_seq, status, backlog_bytes, backlog_records,
       quota_backlog_bytes, quota_backlog_records, created_at, updated_at)
     VALUES ($1, $2, $3, $4, 1, 'pfj3', 'pfc2', $5, 0, $6, $7, $6,
       0, 'active', $8, $7, 4294967296, 1048576, $9, $9)`,
    [
      generationId,
      tenantId,
      volumeId,
      branchId,
      bornCommitId,
      zeroDigest,
      records,
      records * 64,
      Date.now(),
    ]
  );
  // Real journal records: the BYTEA payloads that were never released.
  for (let seq = 0; seq < records; seq += 1) {
    const payload = Buffer.concat([
      Buffer.from([0x50, 0x46, 0x4a, 0x33]),
      Buffer.alloc(60, seq % 251),
    ]);
    await pool.query(
      `INSERT INTO pfj.journal_records
         (generation_id, seq, payload, payload_bytes, record_hash, chain_digest, created_at, record_codec)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'pfj3')`,
      [
        generationId,
        seq,
        payload,
        payload.length,
        hexOf(`${generationId}-${seq}`),
        hexOf(`${generationId}-chain-${seq}`),
        Date.now(),
      ]
    );
  }
  return { tenantId, volumeId, branchId, branchName, generationId };
}

async function horizonOf(pool: pg.Pool, generationId: string): Promise<number> {
  const { rows } = await pool.query(`SELECT pfj.journal_reclaim_horizon($1) AS seq`, [
    generationId,
  ]);
  return Number(rows[0].seq);
}

async function recordCount(pool: pg.Pool, generationId: string): Promise<number> {
  const { rows } = await pool.query(
    `SELECT count(*)::int AS n FROM pfj.journal_records WHERE generation_id=$1`,
    [generationId]
  );
  return rows[0].n as number;
}

async function candidateFor(
  metadata: PostgresMetadataRepository,
  generationId: string
): Promise<{ reclaimableRecords: string } | undefined> {
  const candidates = await metadata.history.journalReclaimCandidates(256);
  return candidates.find((candidate) => candidate.generationId === generationId);
}

describePostgres("volume retirement transition (migration 033)", () => {
  test("a retirement whose transition fails leaves a DURABLE, claimable obligation", async () => {
    const pool = newPool();
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await ensureHistoryPolicy(pool, metadata);
    const fixture = await managedFixture(pool, metadata, 40);

    const receipt = await metadata.retireVolume({
      tenantId: fixture.tenantId,
      volumeId: fixture.volumeId,
    });
    expect(receipt).not.toBeNull();

    // THE OBLIGATION IS PART OF THE RECEIPT'S TRANSACTION. Before 033 there
    // was no queue at all: a failed inline release was a log line.
    const task = await pool.query(
      `SELECT tenant_id, attempts, completed_at_ms
         FROM public.portablefs_volume_retirement_tasks WHERE volume_id=$1`,
      [fixture.volumeId]
    );
    expect(task.rowCount).toBe(1);
    expect(task.rows[0].completed_at_ms).toBeNull();

    // THE RETAINED TAIL, exactly as it was permanent before 033: the
    // generation is still live, so its horizon is its own base_seq (0) and
    // NOTHING is reclaimable...
    expect(await horizonOf(pool, fixture.generationId)).toBe(0);
    expect(await recordCount(pool, fixture.generationId)).toBe(40);
    // ...and the maintenance loop can never derive the work from rows: an
    // un-retired generation is not a reclaim candidate.
    expect(await candidateFor(metadata, fixture.generationId)).toBeUndefined();

    // The drain claims it (bounded, with backoff) and the transition runs.
    const claimed = await metadata.claimVolumeRetirementTasks({ limit: 64, backoffMs: 1_000 });
    expect(claimed.map((entry) => entry.volumeId)).toContain(fixture.volumeId);
    await metadata.finishVolumeRetirement({
      tenantId: fixture.tenantId,
      volumeId: fixture.volumeId,
    });

    // The whole journal is now below the horizon and physically reclaimable.
    expect(await horizonOf(pool, fixture.generationId)).toBe(40);
    const candidate = await candidateFor(metadata, fixture.generationId);
    expect(candidate?.reclaimableRecords).toBe("40");
    await metadata.history.reclaimJournalRecords({
      generationId: fixture.generationId,
      maxRows: 4096,
    });
    expect(await recordCount(pool, fixture.generationId)).toBe(0);

    const done = await pool.query(
      `SELECT completed_at_ms FROM public.portablefs_volume_retirement_tasks WHERE volume_id=$1`,
      [fixture.volumeId]
    );
    expect(done.rows[0].completed_at_ms).not.toBeNull();
    // A completed obligation is not re-claimed.
    const again = await metadata.claimVolumeRetirementTasks({ limit: 64 });
    expect(again.map((entry) => entry.volumeId)).not.toContain(fixture.volumeId);
    await metadata.close();
  });

  test("cut_create transactionally REFUSES a retired volume", async () => {
    const pool = newPool();
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await ensureHistoryPolicy(pool, metadata);
    const fixture = await managedFixture(pool, metadata, 8);

    // Live: a cut is admitted, so the refusal below is caused by retirement.
    const live = await metadata.history.createCut({
      tenantId: fixture.tenantId,
      volumeId: fixture.volumeId,
      branchName: fixture.branchName,
      kind: "recovery",
      operationId: `itest_${randomUUID()}`,
      requestCanonicalJson: JSON.stringify({ itest: randomUUID() }),
      materializerVersion: "pfm-itest-1",
    });
    expect(live.state).toBe("pending");

    await metadata.retireVolume({ tenantId: fixture.tenantId, volumeId: fixture.volumeId });

    await expect(
      metadata.history.createCut({
        tenantId: fixture.tenantId,
        volumeId: fixture.volumeId,
        branchName: fixture.branchName,
        kind: "recovery",
        operationId: `itest_${randomUUID()}`,
        requestCanonicalJson: JSON.stringify({ itest: randomUUID() }),
        materializerVersion: "pfm-itest-1",
      })
    ).rejects.toMatchObject({ code: "PF001" });
    await metadata.close();
  });

  test("the transition cancels the clamping cut and retires the journal in ONE transaction", async () => {
    const pool = newPool();
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await ensureHistoryPolicy(pool, metadata);
    const fixture = await managedFixture(pool, metadata, 24);

    // A pending cut whose window starts at the generation's base: exactly the
    // row that clamps journal_reclaim_horizon (rule 2).
    const cut = await metadata.history.createCut({
      tenantId: fixture.tenantId,
      volumeId: fixture.volumeId,
      branchName: fixture.branchName,
      kind: "recovery",
      operationId: `itest_${randomUUID()}`,
      requestCanonicalJson: JSON.stringify({ itest: randomUUID() }),
      materializerVersion: "pfm-itest-1",
    });
    expect(cut.state).toBe("pending");

    await metadata.retireVolume({ tenantId: fixture.tenantId, volumeId: fixture.volumeId });

    // Round 16's shape, reproduced: journal retirement WITHOUT the cleanup in
    // the same transaction. The generation goes terminal and its base moves
    // to the tip, yet the pending cut clamps the horizon back to 0 — nothing
    // is reclaimable, and no later pass would ever cancel that cut.
    await metadata.history.retireVolumeJournals({
      tenantId: fixture.tenantId,
      volumeId: fixture.volumeId,
    });
    expect(await horizonOf(pool, fixture.generationId)).toBe(0);
    expect(await candidateFor(metadata, fixture.generationId)).toBeUndefined();

    // 033's transition runs cleanup AND journal retirement together, so the
    // clamping cut is canceled in the same transaction that retires the
    // generation. The horizon reaches the tip.
    await metadata.finishVolumeRetirement({
      tenantId: fixture.tenantId,
      volumeId: fixture.volumeId,
    });
    const state = await pool.query(`SELECT state FROM pfh.history_cuts WHERE id=$1`, [cut.cutId]);
    expect(state.rows[0].state).toBe("canceled");
    expect(await horizonOf(pool, fixture.generationId)).toBe(24);
    await metadata.close();
  });

  test("the transition serializes against an in-flight cut_create on the same branch", async () => {
    const pool = newPool();
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await ensureHistoryPolicy(pool, metadata);
    const fixture = await managedFixture(pool, metadata, 16);

    // T1 opens a cut_create transaction and holds the branch advisory lock.
    const t1 = await newPool().connect();
    await t1.query("BEGIN");
    const created = await t1.query(`SELECT pfh.cut_create($1,$2,$3,'recovery',$4,$5,$6,'{}'::jsonb,NULL) AS out`, [
      fixture.tenantId,
      fixture.volumeId,
      fixture.branchName,
      `itest_${randomUUID()}`,
      hexOf(`fingerprint-${randomUUID()}`),
      "pfm-itest-1",
    ]);
    const inflightCutId = (created.rows[0].out as { cutId: string }).cutId;

    // T2 retires and starts the transition. It MUST block on the branch lock
    // T1 holds: this is the window in which round 16 lost the cut.
    await metadata.retireVolume({ tenantId: fixture.tenantId, volumeId: fixture.volumeId });
    let finished = false;
    const transition = metadata
      .finishVolumeRetirement({ tenantId: fixture.tenantId, volumeId: fixture.volumeId })
      .then((result) => {
        finished = true;
        return result;
      });
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(finished, "the transition must wait for the in-flight cut_create").toBe(false);

    // T1 commits its pending cut INTO a volume that is already retired.
    await t1.query("COMMIT");
    t1.release();
    await transition;

    // The transition saw it and canceled it, because it ran strictly after
    // T1's commit under the same lock. The horizon reaches the tip.
    const state = await pool.query(`SELECT state FROM pfh.history_cuts WHERE id=$1`, [
      inflightCutId,
    ]);
    expect(state.rows[0].state).toBe("canceled");
    expect(await horizonOf(pool, fixture.generationId)).toBe(16);
    await metadata.close();
  });
});
