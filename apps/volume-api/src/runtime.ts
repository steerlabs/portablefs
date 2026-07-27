import type { Server } from "node:http";
import type { VolumeApiTelemetry } from "./telemetry.js";

// ---------------------------------------------------------------------------
// Process lifecycle for the Volume API.
//
// ARCHITECTURE INVARIANT: this service is metadata/control/history serving
// only. Live writes bypass it entirely (authority -> fenced PostgreSQL
// journal), so process shutdown here is purely local: it must NEVER
// checkpoint, HistoryCut, freeze, drain, suspend, or otherwise signal an
// already-live authority. The only external effect of shutting this process
// down is that new control/history requests go elsewhere.
//
// Drain sequence (idempotent; the first signal wins):
//   t=0    phase=draining: server.close() stops accepting sockets and
//          closeIdleConnections() drops keepalive idlers; NEW requests on
//          surviving keepalive connections are refused with 503 +
//          Connection: close.
//   t<=20s settle grace: dispatched durable effects (exact attach, commit,
//          blob record) usually finish here.
//   t=20s  read-only work is aborted through drainSignal: head waits, blob
//          reads and grep/history scans. Dispatched mutations are NOT
//          cancelled.
//   t=25s  surviving client sockets are force-closed. This kills transport
//          only — already-dispatched exact mutations keep running.
//   then   the runtime KEEPS WAITING until every tracked durable effect has
//          settled. metadata.close() runs strictly after the last effect —
//          a dispatched mutation can never observe a closing repository.
//          Then the process exits 0.
//   t=30s  hard deadline: if effects (or anything else) still have not
//          settled, exit nonzero WITHOUT closing metadata — process death is
//          the only thing allowed to interrupt a dispatched mutation.
// ---------------------------------------------------------------------------

export type ServingPhase = "starting" | "serving" | "draining" | "closed";

export interface VolumeApiRuntimeOptions {
  telemetry?: VolumeApiTelemetry;
  /** Grace for dispatched durable effects to settle. */
  drainEffectsGraceMs?: number;
  /** When surviving sockets are destroyed (measured from the signal). */
  forceCloseConnectionsMs?: number;
  /** Hard nonzero-exit deadline (measured from the signal). */
  hardExitMs?: number;
  exit?: (code: number) => void;
  log?: (message: string) => void;
  /** Injectable monotonic clock (milliseconds). */
  now?: () => number;
}

export class VolumeApiRuntime {
  private currentPhase: ServingPhase = "starting";
  private readonly drainController = new AbortController();
  private readonly effects = new Set<Promise<unknown>>();
  private activeRequests = 0;
  private shutdownRun: Promise<void> | undefined;
  private server: Server | undefined;
  private metadataClose: (() => Promise<void>) | undefined;

  private readonly telemetry: VolumeApiTelemetry | undefined;
  private readonly drainEffectsGraceMs: number;
  private readonly forceCloseConnectionsMs: number;
  private readonly hardExitMs: number;
  private readonly exit: (code: number) => void;
  private readonly log: (message: string) => void;
  private readonly now: () => number;

  constructor(options: VolumeApiRuntimeOptions = {}) {
    this.telemetry = options.telemetry;
    this.drainEffectsGraceMs = validatedTimeoutMs(
      options.drainEffectsGraceMs ?? 20_000,
      "drainEffectsGraceMs"
    );
    this.forceCloseConnectionsMs = validatedTimeoutMs(
      options.forceCloseConnectionsMs ?? 25_000,
      "forceCloseConnectionsMs"
    );
    this.hardExitMs = validatedTimeoutMs(options.hardExitMs ?? 30_000, "hardExitMs");
    // The phases only make sense strictly ordered: settle grace, then socket
    // force-close, then the hard process deadline.
    if (
      this.drainEffectsGraceMs > this.forceCloseConnectionsMs ||
      this.forceCloseConnectionsMs > this.hardExitMs
    ) {
      throw new Error(
        "VolumeApiRuntime timeouts must satisfy drainEffectsGraceMs <= forceCloseConnectionsMs <= hardExitMs."
      );
    }
    this.exit = options.exit ?? ((code) => process.exit(code));
    this.log = options.log ?? ((message) => console.log(message));
    this.now = options.now ?? Date.now;
  }

  get phase(): ServingPhase {
    return this.currentPhase;
  }

  /**
   * Aborted 20s into a drain. Read-only waits (wait-head), blob transfers,
   * grep and history scans must chain onto it.
   */
  get drainSignal(): AbortSignal {
    return this.drainController.signal;
  }

  isDraining(): boolean {
    return this.currentPhase === "draining" || this.currentPhase === "closed";
  }

  attachServer(server: Server): void {
    this.server = server;
  }

  attachMetadataClose(close: () => Promise<void>): void {
    this.metadataClose = close;
  }

  markServing(): void {
    if (this.currentPhase === "starting") {
      this.currentPhase = "serving";
    }
  }

  /**
   * Truthful active-request accounting: the returned function must be called
   * when HANDLER WORK finishes — not when the response socket closes. A lost
   * client whose durable work is still running still counts as active.
   */
  requestStarted(): () => void {
    this.activeRequests += 1;
    let done = false;
    return () => {
      if (done) {
        return;
      }
      done = true;
      this.activeRequests -= 1;
    };
  }

  get activeRequestCount(): number {
    return this.activeRequests;
  }

  /**
   * Registers a request whose durable effect is ALREADY DISPATCHED (an exact
   * attach or commit in flight, a blob about to be recorded). Draining waits
   * for these — a lost client must not turn a dispatched commit into a
   * stranded one. The registration must wrap only the dispatch itself, not
   * client I/O.
   */
  trackEffect<T>(work: Promise<T>): Promise<T> {
    const sentinel: Promise<void> = work
      .then(
        () => undefined,
        () => undefined
      )
      .then(() => {
        this.effects.delete(sentinel);
      });
    this.effects.add(sentinel);
    return work;
  }

  get pendingEffects(): number {
    return this.effects.size;
  }

  /** Idempotent: the first signal starts the drain; later signals join it. */
  shutdown(reason: string): Promise<void> {
    if (!this.shutdownRun) {
      this.shutdownRun = this.runShutdown(reason);
    }
    return this.shutdownRun;
  }

  private async runShutdown(reason: string): Promise<void> {
    this.currentPhase = "draining";
    this.log(`PortableFS volume API draining after ${reason}.`);
    this.emitShutdown("draining");

    const hardTimer = setTimeout(() => {
      this.emitShutdown("hard_timeout");
      this.log(
        `PortableFS volume API shutdown hard deadline with ${this.effects.size} unsettled effect(s); exiting nonzero without closing metadata.`
      );
      this.exit(1);
    }, this.hardExitMs);
    hardTimer.unref?.();

    const forceTimer = setTimeout(() => {
      // Transport-only: sockets die, dispatched exact mutations keep running
      // against a still-open repository.
      this.emitShutdown("forcing_connections");
      this.server?.closeAllConnections();
    }, this.forceCloseConnectionsMs);
    forceTimer.unref?.();

    // Stop accepting new sockets; drop idle keepalive connections. In-flight
    // requests (and non-idle keepalive sockets) survive until they finish or
    // are force-closed.
    const serverClosed = new Promise<void>((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close(() => resolve());
      this.server.closeIdleConnections();
    });

    // Settle grace for dispatched durable effects. effects_settled is only
    // ever emitted truthfully — when nothing is pending.
    let settledEmitted = false;
    await this.waitForEffects(this.drainEffectsGraceMs);
    if (this.effects.size === 0) {
      settledEmitted = true;
      this.emitShutdown("effects_settled");
    }

    // Abort read-only waits: wait-head long polls, blob streams, grep scans,
    // history reads. These hold sockets/connections but have no durable
    // effect to lose.
    this.emitShutdown("aborting_reads");
    this.drainController.abort();

    await serverClosed;
    clearTimeout(forceTimer);

    // DURABILITY ORDER: metadata must outlive every dispatched effect. If an
    // effect never settles, the hard deadline above exits nonzero and this
    // line is never reached — process death, not repository close, is what
    // interrupts it.
    while (this.effects.size > 0) {
      await Promise.allSettled([...this.effects]);
    }
    if (!settledEmitted) {
      this.emitShutdown("effects_settled");
    }
    if (this.metadataClose) {
      await this.metadataClose().catch(() => undefined);
    }

    this.currentPhase = "closed";
    this.emitShutdown("closed");
    clearTimeout(hardTimer);
    this.log("PortableFS volume API shutdown complete.");
    this.exit(0);
  }

  private async waitForEffects(graceMs: number): Promise<void> {
    const deadline = this.now() + graceMs;
    while (this.effects.size > 0 && this.now() < deadline) {
      const pending = [...this.effects];
      const remaining = deadline - this.now();
      await Promise.race([
        Promise.allSettled(pending),
        new Promise((resolve) => {
          const timer = setTimeout(resolve, Math.max(1, remaining));
          timer.unref?.();
        }),
      ]);
    }
  }

  private emitShutdown(
    phase:
      | "draining"
      | "effects_settled"
      | "aborting_reads"
      | "forcing_connections"
      | "closed"
      | "hard_timeout"
  ): void {
    this.telemetry?.emit({
      type: "shutdown",
      phase,
      pendingEffects: this.effects.size,
      activeRequests: this.activeRequests,
    });
  }
}

function validatedTimeoutMs(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`VolumeApiRuntime ${name} must be a positive safe integer of milliseconds.`);
  }
  return value;
}

/** Installs SIGTERM/SIGINT handlers routing into the idempotent shutdown. */
export function installSignalHandlers(runtime: VolumeApiRuntime): void {
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.once(signal, () => {
      void runtime.shutdown(signal);
    });
  }
}
