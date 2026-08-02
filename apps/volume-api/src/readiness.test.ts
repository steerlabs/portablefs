import { describe, expect, test } from "vitest";
import type { ControlPlaneProbeResult } from "@portablefs/metadata-db";
import { ControlReadiness } from "./readiness.js";
import type { ServingPhase } from "./runtime.js";

function readiness(options: {
  phase?: ServingPhase;
  probe: (options: { signal: AbortSignal }) => Promise<ControlPlaneProbeResult>;
  probeTimeoutMs?: number;
  cacheTtlMs?: number;
}): ControlReadiness {
  return new ControlReadiness({
    phase: () => options.phase ?? "serving",
    controlProbe: options.probe,
    ...(options.probeTimeoutMs !== undefined ? { probeTimeoutMs: options.probeTimeoutMs } : {}),
    ...(options.cacheTtlMs !== undefined ? { cacheTtlMs: options.cacheTtlMs } : {}),
  });
}

describe("ControlReadiness", () => {
  test("answers 200 when the metadata probe is healthy and lineage is current", async () => {
    const probe = readiness({
      probe: async () => ({ ok: true, migrationLineageComplete: true, reachable: true }),
    });

    const report = await probe.evaluate();

    expect(report.status).toBe(200);
    expect(report.body).toEqual({
      ok: true,
      phase: "serving",
      control: { ok: true, migrationLineageComplete: true },
    });
  });

  test("fails closed with 503 when the probe throws, without leaking error text", async () => {
    const probe = readiness({
      probe: async () => {
        throw new Error("connection refused: postgres://user:secret@db/x");
      },
    });

    const report = await probe.evaluate();

    expect(report.status).toBe(503);
    expect(report.body.control).toEqual({
      ok: false,
      migrationLineageComplete: false,
      code: "unreachable",
    });
    expect(JSON.stringify(report.body)).not.toContain("secret");
  });

  test("reports an incomplete migration lineage as its own coarse code", async () => {
    const probe = readiness({
      probe: async () => ({
        ok: false,
        migrationLineageComplete: false,
        reachable: true,
        error: "applied 12 of 17 expected migrations",
      }),
    });

    const report = await probe.evaluate();

    expect(report.status).toBe(503);
    expect(report.body.control.code).toBe("migration_lineage_incomplete");
    expect(JSON.stringify(report.body)).not.toContain("applied 12");
  });

  test("a control store that reads fine but cannot WRITE is unready by its own code", async () => {
    // The recorded outage exactly: disk full, every read answered, every
    // durable write refused. `unreachable` would be a lie and `ok` was the
    // lie that shipped a healthy deploy.
    const probe = readiness({
      probe: async () => ({
        ok: false,
        migrationLineageComplete: true,
        reachable: true,
        writable: false,
        error: 'could not extend file "base/16384/24576": No space left on device',
      }),
    });

    const report = await probe.evaluate();

    expect(report.status).toBe(503);
    expect(report.body.control.code).toBe("not_writable");
    expect(JSON.stringify(report.body)).not.toContain("base/16384");
  });

  test("bounds a hung probe with a timeout answer", async () => {
    const probe = readiness({
      probe: () => new Promise<ControlPlaneProbeResult>(() => undefined),
      probeTimeoutMs: 20,
    });

    const report = await probe.evaluate();

    expect(report.status).toBe(503);
    expect(report.body.control.code).toBe("timeout");
  });

  test("is unready while draining even when the probe is healthy", async () => {
    const probe = readiness({
      phase: "draining",
      probe: async () => ({ ok: true, migrationLineageComplete: true, reachable: true }),
    });

    const report = await probe.evaluate();

    expect(report.status).toBe(503);
    expect(report.body.phase).toBe("draining");
  });

  test("caches the probe result and never overlaps underlying probes", async () => {
    let calls = 0;
    const probe = readiness({
      probe: async () => {
        calls += 1;
        return { ok: true, migrationLineageComplete: true, reachable: true };
      },
      cacheTtlMs: 60_000,
    });

    await Promise.all([probe.evaluate(), probe.evaluate(), probe.evaluate()]);
    await probe.evaluate();

    expect(calls).toBe(1);
  });
});
