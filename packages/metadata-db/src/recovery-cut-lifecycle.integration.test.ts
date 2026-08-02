import { randomUUID } from "node:crypto";
import pg from "pg";
import { describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";
import type { HistoryCutStatus } from "./history.js";

// ---------------------------------------------------------------------------
// Terminal recovery cuts (migration 035) against real Postgres.
//
// THE LIVE DEFECT THIS PINS. Production logged, once a minute for days:
//
//   "recovery cut hcut_f6c19bfeb58148138c86d3ea54ea0eb5 for generation
//    jgen_c6c2ed9f537c42a884edbffe2bfdddcc is failed; adoption is blocked
//    until an operator intervenes"
//
// The cut row carried the reason the whole time —
//   {"kind":"corrupt","message":"historycut: source corruption: journal page
//    at seq 0 is empty below the cut 32"}
// — and nothing could read it: pfj.journal_generations and the terminal rows
// of pfh.history_cuts are owner-private, and every projection the maintenance
// loop had was blind to cut STATE.
//
// These tests hold two things: the survey names the stuck generation with
// everything an operator needs, and — the safety argument for letting a
// terminally failed cut go — the reclamation horizon clamps on cuts that
// might STILL MATERIALIZE and never on ones that cannot.
//
// The suite drives the pfh/pfj surface directly as the test role over fixture
// generations. Fixtures use random ids and are designed for a disposable
// database.
// ---------------------------------------------------------------------------

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/portablefs";

const zeroDigest = "0".repeat(64);

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

interface Fixture {
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  generationId: string;
}

async function managedFixture(
  pool: pg.Pool,
  metadata: PostgresMetadataRepository,
  baseSeq = 0
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
  const generationId = `gen_${randomUUID().replaceAll("-", "")}`;
  await pool.query(
    `INSERT INTO pfj.journal_generations (
       id, tenant_id, volume_id, branch_id, epoch, record_codec, control_codec,
       base_commit_id, base_seq, base_digest, next_seq, tip_digest,
       physical_trimmed_seq, status, backlog_bytes, backlog_records,
       quota_backlog_bytes, quota_backlog_records, created_at, updated_at)
     VALUES ($1, $2, $3, $4, 1, 'pfj3', 'pfc2', $5, $8, $6, 32, $6,
       0, 'active', 10906, 32, 4294967296, 1048576, $7, $7)`,
    [
      generationId,
      tenantId,
      volumeId,
      branchId,
      String(branch.rows[0].head_commit_id),
      zeroDigest,
      Date.now(),
      baseSeq,
    ]
  );
  return { tenantId, volumeId, branchId, branchName, generationId };
}

async function createRecoveryCut(
  metadata: PostgresMetadataRepository,
  fixture: Fixture
): Promise<HistoryCutStatus> {
  return metadata.history.createCut({
    tenantId: fixture.tenantId,
    volumeId: fixture.volumeId,
    branchName: fixture.branchName,
    kind: "recovery",
    operationId: `itest_${randomUUID()}`,
    requestCanonicalJson: JSON.stringify({ itest: randomUUID() }),
    materializerVersion: "pfm-itest-1",
  });
}

/**
 * Settle one cut 'failed' through the REAL pfh.cut_fail path.
 *
 * The claim is installed directly rather than through pfh.cut_claim, which is
 * fleet-wide by design: it hands out the oldest claimable cuts in the whole
 * database, so a suite that used it would both steal other suites' work items
 * and starve waiting for its own. The claim columns written here are exactly
 * what cut_claim writes; cut_fail then verifies the live claim and performs
 * the terminal settlement (including the atomic operation finish) unmodified.
 */
async function failCut(pool: pg.Pool, cutId: string, error: unknown): Promise<void> {
  const { rows } = await pool.query(
    `UPDATE pfh.history_cuts
        SET state='materializing',
            claim_worker_id='itest-worker',
            claim_epoch=claim_epoch+1,
            lease_expires_db_ms=$2,
            attempt_count=attempt_count+1,
            updated_db_ms=$3
      WHERE id=$1
      RETURNING claim_epoch`,
    [cutId, Date.now() + 60_000, Date.now()]
  );
  if (rows.length !== 1) {
    throw new Error(`cut ${cutId} could not be claimed for the test`);
  }
  await pool.query(`SELECT pfh.cut_fail($1, $2, $3::jsonb) AS out`, [
    cutId,
    String(rows[0].claim_epoch),
    JSON.stringify(error),
  ]);
}

async function horizon(pool: pg.Pool, generationId: string): Promise<number> {
  const { rows } = await pool.query(`SELECT pfj.journal_reclaim_horizon($1) AS seq`, [
    generationId,
  ]);
  return Number(rows[0].seq);
}

describePostgres("terminal recovery cuts (migration 035)", () => {
  test("the survey names the stuck generation, its failure and its age", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedFixture(pool, metadata);

      // A healthy pending cut is NOT an operator's problem.
      const cut = await createRecoveryCut(metadata, fixture);
      expect(
        (await metadata.history.stuckRecoveryGenerations(256)).map((row) => row.generationId)
      ).not.toContain(fixture.generationId);

      // The exact production failure.
      await failCut(pool, cut.cutId, {
        kind: "corrupt",
        message:
          "historycut: source corruption: journal page at seq 0 is empty below the cut 32",
      });

      const stuck = (await metadata.history.stuckRecoveryGenerations(256)).find(
        (row) => row.generationId === fixture.generationId
      );
      expect(stuck).toBeDefined();
      // Everything `cutsFailed: 1` never carried.
      expect(stuck!.tenantId).toBe(fixture.tenantId);
      expect(stuck!.volumeId).toBe(fixture.volumeId);
      expect(stuck!.branchName).toBe(fixture.branchName);
      expect(stuck!.cutId).toBe(cut.cutId);
      expect(stuck!.cutState).toBe("failed");
      expect(stuck!.cutKind).toBe("recovery");
      expect(stuck!.dedupRevision).toBe("1");
      expect(stuck!.failureKind).toBe("corrupt");
      expect(stuck!.failureMessage).toContain("journal page at seq 0 is empty");
      expect(stuck!.baseSeq).toBe("0");
      expect(stuck!.nextSeq).toBe("32");
      expect(stuck!.cutSeqExclusive).toBe("32");
      expect(stuck!.terminalCuts).toBe("1");
      expect(Number(stuck!.stuckAgeMs)).toBeGreaterThanOrEqual(0);
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("a re-cut under the next revision clears the generation from the survey", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedFixture(pool, metadata);

      const first = await createRecoveryCut(metadata, fixture);
      await failCut(pool, first.cutId, { kind: "transient", message: "worker unreachable" });
      expect(
        (await metadata.history.stuckRecoveryGenerations(256)).map((row) => row.generationId)
      ).toContain(fixture.generationId);

      // The lifecycle's re-cut: a NEW operation at the SAME boundary. 029's
      // cut_create mints a fresh dedup revision after a definite failure —
      // which is what makes the loop's bounded retry possible at all.
      const second = await createRecoveryCut(metadata, fixture);
      expect(second.cutId).not.toBe(first.cutId);
      expect(second.dedupRevision).toBe("2");
      expect(second.state).toBe("pending");

      // Live work in flight: no longer an operator obligation.
      expect(
        (await metadata.history.stuckRecoveryGenerations(256)).map((row) => row.generationId)
      ).not.toContain(fixture.generationId);

      // And when THAT one dies too, the survey reports the newest revision.
      await failCut(pool, second.cutId, { kind: "transient", message: "worker unreachable" });
      const stuck = (await metadata.history.stuckRecoveryGenerations(256)).find(
        (row) => row.generationId === fixture.generationId
      );
      expect(stuck!.cutId).toBe(second.cutId);
      expect(stuck!.dedupRevision).toBe("2");
      expect(stuck!.terminalCuts).toBe("2");
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("a dead letter is flattened onto the error that exhausted the budget", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedFixture(pool, metadata);

      const cut = await createRecoveryCut(metadata, fixture);
      await failCut(pool, cut.cutId, {
        kind: "dead_letter",
        message: "cut exhausted its attempt budget",
        attempts: 16,
        lastError: { kind: "transient", message: "history worker object store unreachable" },
      });

      const stuck = (await metadata.history.stuckRecoveryGenerations(256)).find(
        (row) => row.generationId === fixture.generationId
      );
      // "dead_letter" alone says only that 013's counter ran out. The retry
      // policy needs the WRAPPED kind: sixteen transient failures are still a
      // transient story, and a fresh cut later can succeed.
      expect(stuck!.failureKind).toBe("dead_letter/transient");
      expect(stuck!.failureMessage).toContain("object store unreachable");
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  // ── the horizon safety argument ──────────────────────────────────────────
  //
  // A cut that MIGHT STILL MATERIALIZE keeps its read window pinned: deleting
  // records under a live fold would corrupt it. A terminally failed one must
  // NOT, because it can never produce the recovery anchor that gives its
  // window meaning — clamping on it would pin the prefix on a proof that will
  // never arrive, which is exactly how one dead cut would hold a generation's
  // journal hostage forever.
  test("a pending cut clamps the reclamation horizon and a failed one does not", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      // base_seq=16 gives the horizon somewhere to be clamped FROM: base_seq
      // is its upper bound.
      const fixture = await managedFixture(pool, metadata, 16);

      const insertCut = async (
        state: string,
        sourceBaseSeq: number,
        cutSeqExclusive: number,
        ready: boolean
      ): Promise<string> => {
        const id = `hcut_${randomUUID().replaceAll("-", "")}`;
        await pool.query(
          `INSERT INTO pfh.history_cuts (
             id, tenant_id, volume_id, branch_id, branch_name, kind, source_kind,
             generation_id, journal_epoch, record_codec, control_codec,
             source_base_commit_id, source_base_seq, source_base_digest,
             cut_seq_exclusive, cut_digest, cut_backlog_bytes, cut_backlog_records,
             materializer_version, replication_policy, dedup_key, dedup_revision,
             request_fingerprint, op_tenant_id, op_domain, op_operation_id,
             state, result_commit_id, recovery_anchor_id,
             created_db_ms, updated_db_ms, ready_db_ms)
           VALUES ($1,$2,$3,$4,'main','recovery','managed_journal',$5,1,'pfj3','pfc2',
             NULL,$10,$6,$11,$6,0,0,'pfm-itest-1',
             '{"v":"1","requiredFailureDomains":[],"policyEpoch":"1"}'::jsonb,
             $7,1,$8,$2,'history-cut',$16,$12,$13,$14,$9,$9,$15)`,
          [
            id,
            fixture.tenantId,
            fixture.volumeId,
            fixture.branchId,
            fixture.generationId,
            zeroDigest,
            `itest-dedup-${randomUUID()}`,
            zeroDigest,
            Date.now(),
            sourceBaseSeq,
            cutSeqExclusive,
            state,
            ready ? `cpft2_${randomUUID().replaceAll("-", "")}` : null,
            ready ? `hanchor_${randomUUID().replaceAll("-", "")}` : null,
            ready ? Date.now() : null,
            `itest-op-${randomUUID()}`,
          ]
        );
        return id;
      };

      // A READY cut whose anchor covers the base: 031 rule (3) is satisfied,
      // so reclamation is permitted up to base_seq.
      await insertCut("ready", 0, 16, true);
      expect(await horizon(pool, fixture.generationId)).toBe(16);

      // A PENDING cut captured from seq 0 — a fold an adoption raced ahead
      // of. It MIGHT still materialize, so its read window is pinned and the
      // horizon collapses to its own start. Deleting under a live fold would
      // corrupt it; this clamp is load-bearing.
      const pending = await insertCut("pending", 0, 32, false);
      expect(await horizon(pool, fixture.generationId)).toBe(0);

      // The SAME row, failed. It can never produce the recovery anchor that
      // gives its window meaning, so clamping on it would pin the prefix on
      // a proof that will never arrive — one dead cut holding a generation's
      // journal hostage forever. The clamp is released.
      await pool.query(
        `UPDATE pfh.history_cuts SET state='failed', last_error='{"kind":"corrupt"}'::jsonb
         WHERE id=$1`,
        [pending]
      );
      expect(await horizon(pool, fixture.generationId)).toBe(16);

      // An operator's cancel behaves identically: also terminal, also unable
      // to produce an anchor.
      await pool.query(`UPDATE pfh.history_cuts SET state='canceled' WHERE id=$1`, [pending]);
      expect(await horizon(pool, fixture.generationId)).toBe(16);

      // ...and a 'materializing' cut clamps again: this is a state test, not
      // a one-off exemption for 'pending'.
      await pool.query(`UPDATE pfh.history_cuts SET state='materializing' WHERE id=$1`, [pending]);
      expect(await horizon(pool, fixture.generationId)).toBe(0);
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("a retired volume's generations are not reported as an operator's problem", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedFixture(pool, metadata);

      const cut = await createRecoveryCut(metadata, fixture);
      await failCut(pool, cut.cutId, { kind: "corrupt", message: "source corruption" });
      expect(
        (await metadata.history.stuckRecoveryGenerations(256)).map((row) => row.generationId)
      ).toContain(fixture.generationId);

      // 022 cancels a retired volume's cuts by design, and 033's drain — not
      // an operator — owns their release. Reporting them would guarantee a
      // permanently non-empty list.
      await pool.query(`UPDATE public.volumes SET retired_at=now() WHERE id=$1 AND tenant_id=$2`, [
        fixture.volumeId,
        fixture.tenantId,
      ]);
      expect(
        (await metadata.history.stuckRecoveryGenerations(256)).map((row) => row.generationId)
      ).not.toContain(fixture.generationId);
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  // The 031 header names this trap by measurement: a parameter inside an
  // inequality estimates so badly under a GENERIC plan that the planner
  // sequential-scans, and a single EXPLAIN never shows it because the first
  // five calls still get CUSTOM plans. The survey's only parameter is the
  // LIMIT — every cut lookup inside it is a generation_id EQUALITY, which a
  // generic plan resolves against the 035 partial index every time. This
  // asserts the index exists and that the newest-terminal-cut lookup rides
  // it past the generic-plan threshold rather than scanning the cut table.
  test("the terminal-cut lookup keeps its index plan past the generic-plan threshold", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const client = await pool.connect();
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedFixture(pool, metadata);
      const cut = await createRecoveryCut(metadata, fixture);
      await failCut(pool, cut.cutId, { kind: "corrupt", message: "source corruption" });

      // A plan assertion on a near-empty table asserts nothing: a sequential
      // scan of 28 rows IS the right plan. Seed enough terminal cuts that an
      // index is genuinely the cheaper answer, then measure.
      await client.query(
        `INSERT INTO pfh.history_cuts (
           id, tenant_id, volume_id, branch_id, branch_name, kind, source_kind,
           generation_id, journal_epoch, record_codec, control_codec,
           source_base_seq, source_base_digest, cut_seq_exclusive, cut_digest,
           cut_backlog_bytes, cut_backlog_records, materializer_version,
           replication_policy, dedup_key, dedup_revision, request_fingerprint,
           op_tenant_id, op_domain, op_operation_id, state, created_db_ms, updated_db_ms)
         SELECT 'planfill_'||$1||'_'||n, $2, $3, $4, 'main', 'recovery', 'managed_journal',
                'planfillgen_'||$1||'_'||(n % 100), 1, 'pfj3', 'pfc2',
                0, repeat('0',64), n, repeat('0',64), 0, 0, 'pfm-itest-1',
                '{"v":"1","requiredFailureDomains":[],"policyEpoch":"1"}'::jsonb,
                'planfilldedup_'||$1||'_'||n, 1, repeat('0',64),
                $2, 'history-cut', 'planfillop_'||$1||'_'||n, 'failed', n, n
           FROM generate_series(1, 4000) n`,
        [randomUUID().replaceAll("-", ""), fixture.tenantId, fixture.volumeId, fixture.branchId]
      );
      await client.query(`VACUUM ANALYZE pfh.history_cuts`);

      const index = await client.query(
        `SELECT indexdef FROM pg_indexes
          WHERE schemaname='pfh' AND indexname='history_cuts_terminal_by_generation'`
      );
      expect(index.rowCount).toBe(1);
      expect(String(index.rows[0].indexdef)).toContain("cut_seq_exclusive DESC");

      await client.query(
        `PREPARE terminal_probe(text) AS
           SELECT c.id FROM pfh.history_cuts c
            WHERE c.generation_id = $1
              AND c.source_kind = 'managed_journal'
              AND c.state IN ('failed','canceled')
            ORDER BY c.cut_seq_exclusive DESC, c.dedup_revision DESC, c.id DESC
            LIMIT 1`
      );
      // Five custom plans, then the generic one PREPARE promotes to. EXPLAIN
      // once would only ever have shown the custom plan.
      // Simple-protocol EXECUTE: the extended protocol would re-plan per
      // bind and never reach the generic plan this is here to observe.
      const execute = `EXECUTE terminal_probe('planfillgen_x_7')`;
      for (let call = 0; call < 6; call += 1) {
        await client.query(execute);
      }
      const explained = await client.query(`EXPLAIN ${execute}`);
      const plan = explained.rows.map((row) => row["QUERY PLAN"] as string).join("\n");
      expect(plan).toContain("history_cuts_terminal_by_generation");
      expect(plan).not.toMatch(/Seq Scan on history_cuts/i);
    } finally {
      client.release();
      await pool.end();
      await metadata.close();
    }
  });
});
