import { randomUUID } from "node:crypto";
import pg from "pg";
import { describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";

// ---------------------------------------------------------------------------
// The history plane's liveness beat must never queue behind its own work
// (migration 036).
//
// WHAT WAS MEASURED. During the append flood that killed every mount, the lock
// sampler caught pfh.worker_beat, pfh.cut_claim, pfh.repair_claim and
// pfh.sweep_claim blocked on each other for 1 to 4.5 seconds, against the 5s
// lock_timeout pfh.require_txn_settings pins. It looks like workers fighting
// over work items. It was not: every work-item claim already distributes with
// FOR UPDATE SKIP LOCKED (cuts, sweeps) or a conditional lease upsert
// (repairs). The contention was entirely on pfh.worker_heartbeats — every
// claim opened by upserting ITS kind's row and held it to COMMIT, and
// pfh.worker_beat wrote ALL FOUR kinds' rows in one transaction, so the beat
// queued behind whichever claim was running while holding the rows the other
// claims needed.
//
// Production confirms the shape: ONE worker id ('railway-history-1') with four
// heartbeat rows, and pfh.repair_claim sampled live mid-transaction.
//
// FAILING-FIRST. Against the pre-036 schema this file's first test measured
// the chain with pg_blocking_pids —
//     cut_claim (pid 702) <- worker_beat (700) <- repair_claim (699)
// with the beat taking 913 ms and the cut claim 708 ms. After 036 the blocking
// graph is empty and both take single-digit milliseconds.
// ---------------------------------------------------------------------------

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/portablefs";

describePostgres("history worker liveness beat (migration 036)", () => {
  test("a beat does not queue behind an open claim, and neither does another claim", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await metadata.close();

    const worker = `itest-convoy-${randomUUID()}`;
    const claimer = new pg.Client({ connectionString: databaseUrl });
    const beater = new pg.Client({ connectionString: databaseUrl });
    const observer = new pg.Client({ connectionString: databaseUrl });
    await claimer.connect();
    await beater.connect();
    await observer.connect();
    try {
      await ensurePolicy(observer);
      // Steady state: this worker's heartbeat rows already exist and are
      // committed. A worker's FIRST-EVER beat is a one-time speculative-insert
      // race, documented in 036, and is not what the fleet spends its life
      // doing — measuring it instead would measure the wrong thing.
      await observer.query(`SELECT pfh.worker_beat($1, $2, '{}'::jsonb)`, [
        worker,
        ["materializer", "scrub", "repair", "gc"],
      ]);

      // A claim transaction left open the way a real one is while the worker
      // is still inside its scan. It holds ('repair', worker) to COMMIT.
      await claimer.query("BEGIN");
      // A claim that ERRORS aborts its transaction and holds no lock at all,
      // which would make every timing below pass for the wrong reason.
      await claimer.query(`SELECT * FROM pfh.repair_claim($1, 16, 900000)`, [worker]);

      const beatStarted = Date.now();
      const beat = await beater.query(`SELECT pfh.worker_beat($1, $2, '{}'::jsonb) AS out`, [
        worker,
        ["materializer", "scrub", "repair", "gc"],
      ]);
      const beatMs = Date.now() - beatStarted;

      // A different claim kind, which used to queue behind the beat. Wrapped
      // in a rolled-back transaction: pfh.cut_claim is fleet-wide by design,
      // so a committed claim here would steal work items from every other
      // suite sharing this database.
      const cutStarted = Date.now();
      await cutter(beater, worker);
      const cutMs = Date.now() - cutStarted;

      // Scoped to THIS test's connections: other suites share the database
      // and their own waits are none of this assertion's business.
      const mine = [claimer, beater].map((client) => (client as unknown as { processID: number }).processID);
      const { rows: blocked } = await observer.query(
        `SELECT pid FROM pg_stat_activity
          WHERE pid = ANY($1::int[]) AND cardinality(pg_blocking_pids(pid)) > 0`,
        [mine]
      );
      expect(blocked).toHaveLength(0);
      // Generous by three orders of magnitude against the 913 ms / 708 ms the
      // pre-036 schema measured, so this asserts the absence of a lock wait
      // and not a machine's speed.
      expect(beatMs).toBeLessThan(300);
      expect(cutMs).toBeLessThan(300);

      // The beat reports what it skipped rather than waiting for it: the
      // 'repair' row was held by the open claim, which is itself beating.
      expect(Number((beat.rows[0].out as { skippedKinds: number }).skippedKinds)).toBe(1);

      await claimer.query("COMMIT");
    } finally {
      await claimer.end();
      await beater.end();
      await observer.end();
    }
  });

  test("a skipped beat never moves a worker's liveness backwards", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await metadata.close();

    const worker = `itest-monotone-${randomUUID()}`;
    const client = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    try {
      await client.query(`SELECT pfh.worker_touch('gc', $1, 5000, NULL)`, [worker]);
      // A late beat carrying an older clock reading must not regress the row.
      const stale = await client.query(`SELECT pfh.worker_touch('gc', $1, 1000, NULL) AS out`, [
        worker,
      ]);
      expect(stale.rows[0].out).toBe(true);
      const { rows } = await client.query(
        `SELECT last_beat_db_ms FROM pfh.worker_heartbeats WHERE worker_kind='gc' AND worker_id=$1`,
        [worker]
      );
      expect(Number(rows[0].last_beat_db_ms)).toBe(5000);
    } finally {
      await client.end();
    }
  });

  test("the touch skips a locked row instead of waiting for it", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await metadata.close();

    const worker = `itest-skip-${randomUUID()}`;
    const holder = new pg.Client({ connectionString: databaseUrl });
    const other = new pg.Client({ connectionString: databaseUrl });
    await holder.connect();
    await other.connect();
    try {
      await other.query(`SELECT pfh.worker_touch('scrub', $1, 1000, NULL)`, [worker]);
      await holder.query("BEGIN");
      await holder.query(`SELECT pfh.worker_touch('scrub', $1, 2000, NULL)`, [worker]);

      const started = Date.now();
      const skipped = await other.query(`SELECT pfh.worker_touch('scrub', $1, 3000, NULL) AS out`, [
        worker,
      ]);
      // FALSE, immediately — not TRUE after a wait. The holder is the same
      // (kind, worker) and is writing a fresh beat of its own, so skipping
      // loses no liveness.
      expect(skipped.rows[0].out).toBe(false);
      expect(Date.now() - started).toBeLessThan(300);
      await holder.query("COMMIT");
    } finally {
      await holder.end();
      await other.end();
    }
  });
});

async function cutter(client: pg.Client, worker: string): Promise<void> {
  await client.query("BEGIN");
  try {
    await client.query(`SELECT * FROM pfh.cut_claim($1, 1, 60000)`, [worker]);
  } finally {
    await client.query("ROLLBACK");
  }
}

/** pfh.repair_claim refuses without an installed policy; a refused claim
 *  aborts its transaction and holds no lock, which would silently invert
 *  what this suite measures. */
async function ensurePolicy(client: pg.Client): Promise<void> {
  const existing = await client.query(
    `SELECT 1 FROM pfh.history_policies WHERE singleton_key='history'`
  );
  if ((existing.rowCount ?? 0) > 0) {
    return;
  }
  await client.query(`SELECT pfh.install_history_policy($1, 0)`, [
    JSON.stringify({
      v: "1",
      requiredFailureDomains: ["itest-a", "itest-b", "itest-c"],
      maxLastVerifiedAgeMs: 3_600_000,
      maxWorkerHeartbeatAgeMs: 60_000,
    }),
  ]);
}
