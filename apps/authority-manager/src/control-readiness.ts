import type { ManagerControlProbe, ManagerControlProbeCode } from "./manager-control-store.js";

// ---------------------------------------------------------------------------
// Manager readiness for /readyz.
//
//   /healthz, /livez  dependency-free process LIVENESS. 200 while the event
//                     loop runs. An orchestrator must not kill a manager
//                     whose database is sick — restarting it fixes nothing
//                     and throws away the epoch claim.
//   /readyz           READINESS: can this manager perform a durable control
//                     transition right now? Process components (router
//                     listening, lease service healthy, live epoch claim)
//                     AND a bounded DURABLE WRITE against the control store.
//                     Railway gates deploys on this path.
//
// WHY A WRITE. The control-store leg used to be
// `SELECT to_regproc('pfm.manager_renew') IS NOT NULL`. During a total
// control-store outage — Postgres disk full, every lease write failing —
// that read answered perfectly, /readyz answered 200, and the deploy was
// declared healthy. A read-only probe cannot distinguish a serving control
// store from one that cannot accept another byte, because a catalog read
// takes no row lock, allocates no tuple, extends no relation and writes no
// WAL. So the probe writes.
//
// PROBE DISCIPLINE (mirrors the volume-api coordinator): AT MOST ONE
// outstanding underlying probe, ever. A caller waits at most probeTimeoutMs
// for it; on timeout the caller reports `timeout` while the underlying probe
// stays registered until it actually settles, so a noncooperative database
// can never accumulate overlapping probes — and, because the probe now
// WRITES, can never accumulate overlapping writes either. Results are cached
// for cacheTtlMs, which is what keeps a bounded write probe cheap: readiness
// traffic no longer maps one-to-one onto control-store transactions.
//
// This endpoint is UNAUTHENTICATED. The payload carries only the stable
// coarse codes below. Raw database or exception text never appears, and
// usage/capacity numbers never appear — those are operator data and live on
// the authenticated /metrics endpoint.
// ---------------------------------------------------------------------------

export type ManagerReadinessCode =
  | ManagerControlProbeCode
  | "timeout"
  // A process component is down (router not listening, lease service
  // unhealthy, or the singleton epoch claim is not live). Named separately
  // so an operator can tell "this manager" apart from "the control store".
  | "components_unavailable";

export interface ManagerReadinessBody {
  ok: boolean;
  code?: ManagerReadinessCode;
}

export interface ManagerControlReadinessOptions {
  // Process-local components. Synchronous and allocation-free: a dead
  // component must answer before the control store is ever touched.
  components: () => boolean;
  controlProbe: (options: { signal: AbortSignal }) => Promise<ManagerControlProbe>;
  probeTimeoutMs?: number;
  cacheTtlMs?: number;
  now?: () => number;
}

// The coarse verdict this coordinator carries internally. It is deliberately
// narrower than ManagerControlProbe: nothing but ok + a stable code may reach
// an unauthenticated payload, so nothing else is retained past the probe.
interface ProbeVerdict {
  ok: boolean;
  code?: ManagerReadinessCode;
}

const unreachable: ProbeVerdict = { ok: false, code: "unreachable" };

export class ManagerControlReadiness {
  private readonly probeTimeoutMs: number;
  private readonly cacheTtlMs: number;
  private readonly now: () => number;
  private cached: { at: number; value: ProbeVerdict } | undefined;
  private underlying: Promise<ProbeVerdict> | undefined;

  constructor(private readonly options: ManagerControlReadinessOptions) {
    this.probeTimeoutMs = validatedPositiveInt(options.probeTimeoutMs ?? 2_000, "probeTimeoutMs");
    this.cacheTtlMs = validatedPositiveInt(options.cacheTtlMs ?? 5_000, "cacheTtlMs");
    this.now = options.now ?? Date.now;
  }

  async evaluate(): Promise<ManagerReadinessBody> {
    // Components first: a manager that is not listening, has lost its epoch,
    // or has an unhealthy lease service is unready no matter how healthy the
    // database is — and asking the database would be pure waste.
    if (!this.options.components()) {
      return { ok: false, code: "components_unavailable" };
    }
    const control = await this.readControl();
    if (control.ok) {
      return { ok: true };
    }
    return { ok: false, code: control.code ?? "unreachable" };
  }

  private async readControl(): Promise<ProbeVerdict> {
    if (this.cached && this.now() - this.cached.at < this.cacheTtlMs) {
      return this.cached.value;
    }
    if (!this.underlying) {
      const controller = new AbortController();
      const abortTimer = setTimeout(() => controller.abort(), this.probeTimeoutMs);
      abortTimer.unref?.();
      const flight: Promise<ProbeVerdict> = Promise.resolve()
        .then(() => this.options.controlProbe({ signal: controller.signal }))
        // The raw error is deliberately dropped: nothing beyond the coarse
        // outcome may survive to an unauthenticated payload.
        .then((result) => toVerdict(result), () => unreachable)
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

  private boundedWait(work: Promise<ProbeVerdict>): Promise<ProbeVerdict> {
    return new Promise<ProbeVerdict>((resolve) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          resolve({ ok: false, code: "timeout" });
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
            resolve({ ok: false, code: "timeout" });
          }
        }
      );
    });
  }
}

// A probe that claims ok WITHOUT proving a write is not ok. Readiness is the
// ability to perform a durable control transition; a store that answered
// reads while refusing every lease write is the exact incident this module
// exists for, so `writable` is checked here rather than trusted from `ok`.
function toVerdict(result: ManagerControlProbe): ProbeVerdict {
  if (result.ok && result.writable && result.lineageComplete) {
    return { ok: true };
  }
  return { ok: false, code: result.code ?? "not_writable" };
}

function validatedPositiveInt(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`ManagerControlReadiness ${name} must be a positive safe integer.`);
  }
  return value;
}
