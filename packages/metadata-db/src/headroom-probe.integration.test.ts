import pg from "pg";
import { afterAll, describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";

// ---------------------------------------------------------------------------
// ROUND 17c / FINDING 4, against real Postgres on the full lineage.
//
// 030's readiness write probe was a fixed 16-slot ring of in-place UPDATEs.
// Its own migration concedes the hole — such an update "must take a free page
// from the FSM or extend" — and only the extend arm proves headroom. After
// the first vacuum of the ring's own dead versions, the FSM arm is the one
// that always runs. Measured on postgres:18 with the ring in a 100%-full
// tablespace and a writable WAL volume: 40/40 probes SUCCEEDED, the relation
// grew 0 bytes, and a journal-class insert in the same session failed 53100.
//
// The 032 probe cannot degrade that way, and these tests pin the reason
// rather than the symptom: the probe relation is INSERT-ONLY, so it never has
// a dead tuple, so vacuum can never hand a page back to the FSM; and every
// row is larger than half a page, so no page that holds one can take another.
// Every probe must therefore take NEW space from the filesystem. A
// full-tablespace run is the other half of the evidence and lives outside the
// suite (it needs a filesystem with real ENOSPC semantics, not a tmpfs);
// what is guarded here is the invariant that makes it true.
// ---------------------------------------------------------------------------

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/portablefs";

const pools: pg.Pool[] = [];
afterAll(async () => {
  await Promise.all(pools.splice(0).map((pool) => pool.end()));
});

function newPool(): pg.Pool {
  const pool = new pg.Pool({ connectionString: databaseUrl });
  pools.push(pool);
  return pool;
}

async function heapBytes(pool: pg.Pool): Promise<number> {
  const { rows } = await pool.query(
    `SELECT pg_relation_size('public.portablefs_control_headroom_probes')::bigint AS n`
  );
  return Number(rows[0].n);
}

describePostgres("readiness headroom probe (migration 032)", () => {
  test("every probe ALLOCATES, including across vacuums of the probe relations", async () => {
    const pool = newPool();
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();

    // Start from a known floor so the run never crosses the reset cap.
    await pool.query(`TRUNCATE public.portablefs_control_headroom_probes`);

    let previous = await heapBytes(pool);
    let extended = 0;
    const probes = 30;
    for (let i = 0; i < probes; i += 1) {
      const result = await metadata.probeControlPlane();
      expect(result.ok).toBe(true);
      expect(result.writable).toBe(true);
      const now = await heapBytes(pool);
      if (now > previous) {
        extended += 1;
      }
      previous = now;
      // VACUUM between probes is exactly what turned the 030 ring into a
      // no-allocation probe: it recycles the ring's dead row versions into
      // FSM-reusable pages. It can do nothing here.
      if (i % 5 === 4) {
        await pool.query(`VACUUM (ANALYZE) public.portablefs_control_headroom_probes`);
        await pool.query(`VACUUM (ANALYZE) public.portablefs_control_write_probes`);
      }
    }
    expect(extended, "every readiness probe must take NEW space").toBe(probes);

    // The invariant behind it: no dead tuples, ever, so vacuum has nothing to
    // give back to the FSM. (The 030 ring, by contrast, manufactures one dead
    // tuple per probe — that is the machine that produced the reusable pages.)
    const stats = await pool.query(
      `SELECT relname, n_dead_tup::int AS dead FROM pg_stat_user_tables
        WHERE relname IN ('portablefs_control_headroom_probes','portablefs_control_write_probes')`
    );
    const dead = new Map(stats.rows.map((row) => [row.relname as string, row.dead as number]));
    expect(dead.get("portablefs_control_headroom_probes")).toBe(0);
    await metadata.close();
  });

  test("no page that holds a probe row can ever take another", async () => {
    const pool = newPool();
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await pool.query(`TRUNCATE public.portablefs_control_headroom_probes`);

    await metadata.probeControlPlane();
    const oneRow = await heapBytes(pool);
    expect(oneRow).toBe(8192);
    // One row per 8 KiB page: the row is bigger than the largest hole a
    // vacuumed page could ever offer while still holding a live row.
    const { rows } = await pool.query(
      `SELECT octet_length(filler)::int AS n FROM public.portablefs_control_headroom_probes LIMIT 1`
    );
    expect(rows[0].n).toBeGreaterThan(4096);

    await metadata.probeControlPlane();
    expect(await heapBytes(pool)).toBe(16384);
    await metadata.close();
  });

  test("the probe relation is BOUNDED: the reset refills from the floor", async () => {
    const pool = newPool();
    const metadata = new PostgresMetadataRepository(databaseUrl);
    await metadata.applyMigrations();
    await pool.query(`TRUNCATE public.portablefs_control_headroom_probes`);

    const capBytes = 128 * 8192;
    let sawReset = false;
    for (let i = 0; i < 160; i += 1) {
      const before = await heapBytes(pool);
      await metadata.probeControlPlane();
      const after = await heapBytes(pool);
      expect(after).toBeLessThanOrEqual(capBytes);
      if (after < before) {
        sawReset = true;
        // The reset TRUNCATEs and refills the floor IN ONE TRANSACTION, so
        // the refill must allocate that floor while the old file is still on
        // disk — it can never truncate its way to a green answer on a full
        // volume.
        expect(after).toBe(8 * 8192);
      }
    }
    expect(sawReset, "the probe relation must reset before exceeding its cap").toBe(true);
    await metadata.close();
  });
});
