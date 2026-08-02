import type { ControlPlaneProbeResult } from "@portablefs/metadata-db";
import type { ServingPhase } from "./runtime.js";

// ---------------------------------------------------------------------------
// Control readiness for /readyz.
//
//   /healthz   dependency-free process liveness. Always 200 while the event
//              loop runs — INCLUDING while draining (the orchestrator must
//              not kill a draining process early). Unchanged by this module.
//   /readyz    CONTROL readiness: serving phase + bounded metadata probe
//              (connectivity + migration lineage current). Blob stores are
//              NEVER touched: managed live writes bypass this service, so a
//              dead or noncooperative blob store must not add one
//              millisecond of latency — or one connection of load — to
//              control readiness. Deploy gates (Railway) poll this.
//
// Probe discipline: AT MOST ONE outstanding underlying probe, ever. A caller
// waits at most probeTimeoutMs for it; on timeout the caller reports
// `timeout` but the underlying probe stays registered until it actually
// settles — a noncooperative database can never accumulate overlapping
// background probes. Results are cached for cacheTtlMs.
//
// This endpoint is UNAUTHENTICATED: the payload carries only stable coarse
// codes (`timeout`, `unreachable`, `migration_lineage_incomplete`). Raw
// database or exception text never appears. Everything fails CLOSED: a
// thrown probe, a timeout, or an incomplete lineage is 503.
// ---------------------------------------------------------------------------

interface ControlStatus {
  ok: boolean;
  migrationLineageComplete: boolean;
  code?: "timeout" | "unreachable" | "migration_lineage_incomplete" | "not_writable";
}

export interface ReadinessReport {
  ok: boolean;
  status: number;
  body: {
    ok: boolean;
    phase: ServingPhase;
    control: ControlStatus;
  };
}

export interface ControlReadinessOptions {
  phase: () => ServingPhase;
  controlProbe: (options: { signal: AbortSignal }) => Promise<ControlPlaneProbeResult>;
  probeTimeoutMs?: number;
  cacheTtlMs?: number;
  now?: () => number;
}

export class ControlReadiness {
  private readonly probeTimeoutMs: number;
  private readonly cacheTtlMs: number;
  private readonly now: () => number;
  private cached: { at: number; value: ControlStatus } | undefined;
  private underlying: Promise<ControlStatus> | undefined;

  constructor(private readonly options: ControlReadinessOptions) {
    this.probeTimeoutMs = validatedPositiveInt(options.probeTimeoutMs ?? 2_000, "probeTimeoutMs");
    this.cacheTtlMs = validatedPositiveInt(options.cacheTtlMs ?? 5_000, "cacheTtlMs");
    this.now = options.now ?? Date.now;
  }

  async evaluate(): Promise<ReadinessReport> {
    const phase = this.options.phase();
    const control = await this.readControl();
    // Draining/closed is always unready — the orchestrator must route new
    // work elsewhere while liveness stays green.
    const ok = phase === "serving" && control.ok;
    return {
      ok,
      status: ok ? 200 : 503,
      body: { ok, phase, control },
    };
  }

  private async readControl(): Promise<ControlStatus> {
    if (this.cached && this.now() - this.cached.at < this.cacheTtlMs) {
      return this.cached.value;
    }
    if (!this.underlying) {
      const controller = new AbortController();
      const abortTimer = setTimeout(() => controller.abort(), this.probeTimeoutMs);
      abortTimer.unref?.();
      const flight: Promise<ControlStatus> = Promise.resolve()
        .then(() => this.options.controlProbe({ signal: controller.signal }))
        .then(
          (result) => toControlStatus(result),
          // The raw error is deliberately dropped: nothing beyond the coarse
          // outcome may survive to an unauthenticated payload.
          (): ControlStatus => ({ ok: false, migrationLineageComplete: false, code: "unreachable" })
        )
        .then((value) => {
          clearTimeout(abortTimer);
          this.cached = { at: this.now(), value };
          // Only the flight that is still current clears the slot; a stale
          // settle after replacement must not clobber a newer flight.
          if (this.underlying === flight) {
            this.underlying = undefined;
          }
          return value;
        });
      this.underlying = flight;
    }
    return this.boundedWait(this.underlying);
  }

  private boundedWait(work: Promise<ControlStatus>): Promise<ControlStatus> {
    return new Promise<ControlStatus>((resolve) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          resolve({ ok: false, migrationLineageComplete: false, code: "timeout" });
        }
      }, this.probeTimeoutMs);
      timer.unref?.();
      work.then(
        (value) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve(value);
          }
        },
        () => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve({ ok: false, migrationLineageComplete: false, code: "timeout" });
          }
        }
      );
    });
  }
}

function toControlStatus(result: ControlPlaneProbeResult): ControlStatus {
  if (result.ok) {
    return { ok: true, migrationLineageComplete: result.migrationLineageComplete };
  }
  // Coarse classification only: lineage and write capability are booleans the
  // probe already computed; everything else collapses to "unreachable".
  //
  // `not_writable` is the code the out-of-disk outage needed and did not
  // have: the store answered every read, so "unreachable" would have been a
  // lie and "ok" was the lie that actually shipped.
  return {
    ok: false,
    migrationLineageComplete: result.migrationLineageComplete,
    code: coarseFailureCode(result),
  };
}

function coarseFailureCode(
  result: ControlPlaneProbeResult
): "unreachable" | "migration_lineage_incomplete" | "not_writable" {
  if (result.reachable !== true) {
    return "unreachable";
  }
  if (result.migrationLineageComplete === false) {
    return "migration_lineage_incomplete";
  }
  if (result.writable === false) {
    return "not_writable";
  }
  return "unreachable";
}

function validatedPositiveInt(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`ControlReadiness ${name} must be a positive safe integer.`);
  }
  return value;
}
