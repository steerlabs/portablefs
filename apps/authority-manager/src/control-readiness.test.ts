import { describe, expect, test } from "vitest";
import { ManagerControlReadiness } from "./control-readiness.js";
import { ManagerMetrics } from "./manager-metrics.js";
import { createManagerMetricsEndpoint } from "./metrics-endpoint.js";
import { PostgresManagerControlStore, type ManagerControlPool } from "./manager-control-store.js";

// ---------------------------------------------------------------------------
// /readyz must reflect the ability to perform a DURABLE CONTROL TRANSITION.
//
// Recorded incident: the control-store Postgres filled its disk, every lease
// write failed, and readiness stayed green — the control-store leg was
// `SELECT to_regproc('pfm.manager_renew') IS NOT NULL`, a catalog read that
// an out-of-disk primary answers perfectly. The deploy gate
// (railway/authority-manager.railway.json healthcheckPath=/readyz) therefore
// declared the release healthy.
//
// The pool below reproduces that state EXACTLY: every read succeeds, every
// write raises 53100 disk_full.
// ---------------------------------------------------------------------------

interface Recorded {
  text: string;
  values: unknown[];
}

class OutOfDiskPool implements ManagerControlPool {
  readonly calls: Recorded[] = [];
  constructor(private readonly failWrites = true) {}

  async query(text: string, values: unknown[]): Promise<{ rows: unknown[] }> {
    this.calls.push({ text, values });
    // The WRITE call, not the lineage read that merely names the function.
    if (text.includes("SELECT pfm.control_headroom_probe(")) {
      if (this.failWrites) {
        throw Object.assign(
          new Error('could not extend file "base/16384/24576": No space left on device'),
          { code: "53100" }
        );
      }
      return { rows: [{ r: { ok: true, slot: 3, probeSeq: "41", dbTimeMs: "1783710000000" } }] };
    }
    if (text.includes("control_store_usage")) {
      return {
        rows: [
          {
            r: {
              databaseBytes: "21474836480",
              planeBytes: { pfj: "20401094656", pfm: "1048576", pfh: "4194304" },
              dbTimeMs: "1783710000000",
            },
          },
        ],
      };
    }
    // The lineage read: a full disk answers catalog reads perfectly.
    return { rows: [{ lineage: true }] };
  }

  async end(): Promise<void> {}
}

describe("manager control-store readiness", () => {
  test("an out-of-disk control store that still answers reads is NOT healthy", async () => {
    const pool = new OutOfDiskPool(true);
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });

    const probe = await store.healthProbe();

    // Reads work; lineage is current. This is exactly the state that shipped.
    expect(probe.lineageComplete).toBe(true);
    // And readiness must still fail, because a lease write would fail.
    expect(probe.writable).toBe(false);
    expect(probe.ok).toBe(false);
    expect(probe.code).toBe("not_writable");
  });

  test("the probe issues a real durable write, not only catalog reads", async () => {
    const pool = new OutOfDiskPool(false);
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });

    const probe = await store.healthProbe();

    expect(probe).toEqual({ ok: true, lineageComplete: true, writable: true });
    const write = pool.calls.find((call) =>
      call.text.includes("SELECT pfm.control_headroom_probe(")
    );
    expect(write, "healthProbe must exercise write capability").toBeDefined();
    // Bounded: the write targets a fixed ring slot, so proving readiness can
    // never grow the control store that this fix exists to stop filling.
    expect(typeof write!.values[0]).toBe("number");
    expect(write!.values[0] as number).toBeGreaterThanOrEqual(0);
    expect(write!.values[0] as number).toBeLessThan(16);
  });

  // ROUND 17c / FINDING 4. The 030 probe (pfm.control_write_probe) is a fixed
  // 16-slot ring of in-place UPDATEs. Its own migration concedes such an
  // update "must take a free page from the FSM or extend", and after vacuum
  // recycles the ring's own dead versions the FSM arm is the one that always
  // runs: measured on postgres:18 with the ring in a 100%-full tablespace
  // (WAL writable), 40/40 probes answered HEALTHY, the relation grew 0 bytes,
  // and a journal-class insert in the same session failed 53100.
  //
  // Readiness must therefore call the probe that PROVES AN ALLOCATION
  // (pfm.control_headroom_probe, migration 032), and the lineage predicate
  // must name it so a store without 032 reads as incomplete rather than
  // getting a green answer out of the weaker probe.
  test("readiness proves ALLOCATION headroom, not merely a fixed-row update", async () => {
    const pool = new OutOfDiskPool(false);
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });

    await store.healthProbe();

    const lineage = pool.calls[0]!;
    expect(
      lineage.text,
      "the lineage gate must name the 032 headroom probe, so a pre-032 store fails closed"
    ).toContain("pfm.control_headroom_probe(int)");
    const probes = pool.calls.filter((call) => call.text.includes("SELECT pfm."));
    expect(
      probes.some((call) => call.text.includes("pfm.control_headroom_probe(")),
      "healthProbe must exercise the allocation probe"
    ).toBe(true);
    expect(
      probes.some(
        (call) =>
          call.text.includes("pfm.control_write_probe(") &&
          !call.text.includes("pfm.control_headroom_probe(")
      ),
      "readiness must NOT rest on the 030 fixed-ring probe: it answers healthy from FSM-reused pages on a full data volume"
    ).toBe(false);
  });

  test("a control store missing the probe surface is lineage-incomplete, never optimistically ready", async () => {
    const pool: ManagerControlPool = {
      async query() {
        return { rows: [{ lineage: false }] };
      },
      async end() {},
    };
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });

    const probe = await store.healthProbe();

    expect(probe).toEqual({
      ok: false,
      lineageComplete: false,
      writable: false,
      code: "lineage_incomplete",
    });
  });

  test("usageProbe reports exact control-store consumption for operator accounting", async () => {
    const pool = new OutOfDiskPool(false);
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });

    const usage = await store.usageProbe();

    expect(usage.databaseBytes).toBe("21474836480");
    expect(usage.planeBytes.pfj).toBe("20401094656");
  });

  test("/readyz answers not_writable — never ok — when the store refuses writes", async () => {
    const readiness = new ManagerControlReadiness({
      components: () => true,
      controlProbe: async () => ({
        ok: false,
        lineageComplete: true,
        writable: false,
        code: "not_writable" as const,
      }),
    });

    expect(await readiness.evaluate()).toEqual({ ok: false, code: "not_writable" });
  });

  test("a probe that claims ok without proving a write is not trusted", async () => {
    const readiness = new ManagerControlReadiness({
      components: () => true,
      // The pre-fix shape: ok because a catalog read succeeded.
      controlProbe: async () => ({ ok: true, lineageComplete: true, writable: false }),
    });

    expect((await readiness.evaluate()).ok).toBe(false);
  });

  test("down components answer before the control store is ever touched", async () => {
    let probes = 0;
    const readiness = new ManagerControlReadiness({
      components: () => false,
      controlProbe: async () => {
        probes += 1;
        return { ok: true, lineageComplete: true, writable: true };
      },
    });

    expect(await readiness.evaluate()).toEqual({ ok: false, code: "components_unavailable" });
    expect(probes).toBe(0);
  });

  test("bounds a hung probe and never leaks database text", async () => {
    const readiness = new ManagerControlReadiness({
      components: () => true,
      controlProbe: () => new Promise(() => undefined),
      probeTimeoutMs: 20,
    });

    const body = await readiness.evaluate();

    expect(body).toEqual({ ok: false, code: "timeout" });
  });

  test("a thrown probe fails closed as unreachable with no error text", async () => {
    const readiness = new ManagerControlReadiness({
      components: () => true,
      controlProbe: async () => {
        throw new Error("connection refused: postgres://user:secret@db/x");
      },
    });

    const body = await readiness.evaluate();

    expect(body).toEqual({ ok: false, code: "unreachable" });
    expect(JSON.stringify(body)).not.toContain("secret");
  });

  test("control-store consumption renders as fixed-name /metrics gauges", async () => {
    const metrics = new ManagerMetrics();
    const endpoint = createManagerMetricsEndpoint({
      metrics,
      controlStoreUsage: async () => ({
        databaseBytes: "21474836480",
        planeBytes: { pfj: "20401094656", pfm: "1048576", nonsense: "1", bad: "not-a-number" },
      }),
    });

    const body = await endpoint();

    expect(body).toContain("pfm_control_store_database_bytes 21474836480");
    expect(body).toContain("pfm_control_store_pfj_bytes 20401094656");
    // Closed plane allowlist: an unexpected plane never mints a new series.
    expect(body).not.toContain("nonsense");
    expect(body).not.toContain("bad");
  });

  test("a failing usage probe never takes the rest of the scrape down", async () => {
    const metrics = new ManagerMetrics();
    metrics.setGauge("pfm_manager_claimed", 1);
    const endpoint = createManagerMetricsEndpoint({
      metrics,
      controlStoreUsage: async () => {
        throw new Error("statement timeout");
      },
    });

    const body = await endpoint();

    // The operator watching a filling control store needs the REST of these
    // numbers most of all.
    expect(body).toContain("pfm_manager_claimed 1");
    expect(body).not.toContain("pfm_control_store_database_bytes");
  });

  test("caches the verdict and keeps at most one write probe outstanding", async () => {
    let probes = 0;
    const readiness = new ManagerControlReadiness({
      components: () => true,
      controlProbe: async () => {
        probes += 1;
        return { ok: true, lineageComplete: true, writable: true };
      },
      cacheTtlMs: 60_000,
    });

    await Promise.all([readiness.evaluate(), readiness.evaluate(), readiness.evaluate()]);
    await readiness.evaluate();

    // Readiness traffic must not map one-to-one onto control-store writes.
    expect(probes).toBe(1);
  });
});
