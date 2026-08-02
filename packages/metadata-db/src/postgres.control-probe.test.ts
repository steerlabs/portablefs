import { describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";

// ---------------------------------------------------------------------------
// The control-plane readiness probe must exercise WRITE capability.
//
// Incident: the control-store Postgres filled its disk, every journal/lease
// write failed, and readiness stayed green because the probe was a catalog
// READ (SELECT count(*) FROM portablefs_migrations). An out-of-disk primary
// answers catalog reads perfectly — it takes no row lock, allocates no
// tuple, extends no relation and writes no WAL.
//
// These tests pin the probe to a real durable write by simulating exactly
// that failure mode: reads succeed, writes raise 53100 (disk_full).
// ---------------------------------------------------------------------------

interface RecordedQuery {
  text: string;
  values: unknown[];
}

class DiskFullPool {
  readonly calls: RecordedQuery[] = [];
  constructor(private readonly failWrites = true) {}

  async query(text: string, values: unknown[] = []): Promise<{ rows: unknown[] }> {
    this.calls.push({ text, values });
    if (/INSERT|UPDATE|DELETE|headroom_probe/i.test(text)) {
      if (this.failWrites) {
        const error = new Error(
          'could not extend file "base/16384/24576": No space left on device'
        ) as Error & { code?: string };
        error.code = "53100";
        throw error;
      }
      return {
        rows: [
          {
            probe: {
              ok: true,
              slot: 3,
              probeSeq: "12",
              allocatedBytes: "8192",
              probeRelationBytes: "65536",
              reset: false,
              dbTimeMs: "1783710000000",
            },
          },
        ],
      };
    }
    // Every read the probe can issue answers happily, exactly like a real
    // out-of-disk primary does. The lineage read is echoed back complete
    // (one applied row per expected migration id) so this fixture never
    // needs updating when the lineage grows.
    const expected = Array.isArray(values[0]) ? (values[0] as unknown[]).length : 0;
    return { rows: [{ applied: String(expected) }] };
  }

  async end(): Promise<void> {}
  on(): void {}
}

function withPool(pool: DiskFullPool): PostgresMetadataRepository {
  const repository = new PostgresMetadataRepository("postgres://user@localhost:5432/db");
  (repository as unknown as { pool: unknown }).pool = pool;
  return repository;
}

describe("probeControlPlane write capability", () => {
  test("an out-of-disk control store that still answers reads is NOT ready", async () => {
    const pool = new DiskFullPool(true);
    const repository = withPool(pool);

    const result = await repository.probeControlPlane();

    // The lineage read succeeded — this is precisely the state that shipped a
    // "healthy" deploy while every lease write was failing.
    expect(result.migrationLineageComplete).toBe(true);
    expect(result.reachable).toBe(true);
    // ...and readiness must still fail, because writes do not work.
    expect(result.writable).toBe(false);
    expect(result.ok).toBe(false);
  });

  test("the probe issues a real durable write against the bounded probe ring", async () => {
    const pool = new DiskFullPool(false);
    const repository = withPool(pool);

    const result = await repository.probeControlPlane();

    expect(result.ok).toBe(true);
    expect(result.writable).toBe(true);
    const write = pool.calls.find((call) => /headroom_probe/i.test(call.text));
    expect(write, "probeControlPlane must issue a write, not only reads").toBeDefined();
    // Bounded: the slot is drawn from a fixed ring so the durable-transition
    // leg can never accumulate rows across restarts or replicas.
    expect(typeof write!.values[0]).toBe("number");
    expect(write!.values[0] as number).toBeGreaterThanOrEqual(0);
    expect(write!.values[0] as number).toBeLessThan(16);
  });

  // ROUND 17c / FINDING 4. The 030 write leg was `INSERT ... ON CONFLICT DO
  // UPDATE` on a fixed 16-slot ring. Such an update is satisfied EITHER by
  // extending the relation OR by an FSM page, and after the first vacuum of
  // the ring's own dead versions the FSM arm is the one that always runs.
  // Measured on postgres:18, ring in a 100%-full tablespace with a writable
  // WAL volume: 40/40 probes SUCCEEDED, the relation grew 0 bytes, and a
  // journal-class insert in the same session failed 53100. /readyz was green
  // on a control store that could not accept a byte.
  //
  // The write leg must therefore be the 032 headroom probe, which allocates
  // from an INSERT-ONLY relation (no dead tuples => no FSM reuse => every
  // probe must extend) and verifies the extension inside its transaction.
  test("the write leg PROVES an allocation, not merely a fixed-row update", async () => {
    const pool = new DiskFullPool(false);
    const repository = withPool(pool);

    await repository.probeControlPlane();

    const write = pool.calls.find((call) => /headroom_probe/i.test(call.text));
    expect(
      write,
      "the readiness write leg must be the 032 allocation probe"
    ).toBeDefined();
    expect(write!.text).toContain("portablefs_control_headroom_probe");
    expect(
      pool.calls.some(
        (call) =>
          /INSERT INTO portablefs_control_write_probes/i.test(call.text) &&
          !/headroom_probe/i.test(call.text)
      ),
      "readiness must not rest on the bare 030 fixed-ring update: it answers healthy from FSM-reused pages on a full data volume"
    ).toBe(false);
  });

  test("an unreachable store reports neither lineage nor write capability", async () => {
    const pool = {
      calls: [] as RecordedQuery[],
      async query(): Promise<{ rows: unknown[] }> {
        throw new Error("connection refused: postgres://user:secret@db/x");
      },
      async end(): Promise<void> {},
      on(): void {},
    };
    const repository = withPool(pool as unknown as DiskFullPool);

    const result = await repository.probeControlPlane();

    expect(result.ok).toBe(false);
    expect(result.reachable).toBe(false);
    expect(result.writable).toBe(false);
  });
});
