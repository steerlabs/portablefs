import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import type {
  ClaimHeartbeatMessage,
  ClaimHeartbeatWorkerData,
} from "./claim-heartbeat-worker.js";
import type { ManagerIdentity } from "./manager-control-store.js";

// ---------------------------------------------------------------------------
// The singleton claim's liveness channel (main-thread half).
//
// THE INVARIANT: the manager's claim renewal must not share ANY resource with
// data-plane or bulk control-plane load. It is the fencing authority — if its
// renewal starves, the manager fences ITSELF and strands every client, which
// is the exact incident this seam exists to make structurally impossible.
//
// Two resources used to be shared and are now both isolated:
//
//   1. THE EVENT LOOP. The manager process also runs the data-plane router
//      (every tunnel byte is a socket callback on its loop), the control HTTP
//      server, the child metrics scraper and every child's heartbeat pipe.
//      Renewal now runs on a dedicated worker_thread that carries none of it.
//   2. THE DATABASE CONNECTION. Renewal used to queue in the same bounded
//      pg Pool as every client-driven lease/runtime call; a saturated pool
//      rejects the queued renewal after connectionTimeoutMillis, so bulk
//      traffic alone could starve liveness without the database ever being
//      unhealthy. The worker holds its own reserved connection.
//
// SAFETY IS NOT WEAKENED. The main thread still owns the deadline and the
// fence. It moves the deadline ONLY on a renewal the database actually
// confirmed, anchored at the instant BEFORE the statement was issued. A
// worker that is slow, wedged, crashed or gone simply stops posting
// successes, and the unchanged deadline watchdog fences on schedule. Every
// failure mode of this channel is silence, and silence fences.
// ---------------------------------------------------------------------------

export interface ClaimRenewalFacts {
  /** Local monotonic instant captured BEFORE the renewal statement was issued. */
  anchorLocalMs: number;
  dbTimeMs: number;
  claimExpiresAtDbMs: number;
}

export interface ClaimHeartbeatListeners {
  onRenewed(facts: ClaimRenewalFacts): void;
  /** The claim is provably gone (PF001): fence NOW, do not wait for the deadline. */
  onSuperseded(message: string): void;
  /** An ambiguous attempt. NEVER extends the deadline; the watchdog still rules. */
  onFailure(message: string): void;
}

export interface ClaimHeartbeatStartArgs {
  identity: ManagerIdentity;
  ttlMs: number;
  intervalMs: number;
  /** The registry's own monotonic clock; the isolation proof is taken against it. */
  now: () => number;
  listeners: ClaimHeartbeatListeners;
}

export interface ClaimHeartbeat {
  /**
   * Proves isolation and starts renewing. Rejecting is fail-closed: the
   * manager never reaches readiness with an unproven liveness channel.
   */
  start(args: ClaimHeartbeatStartArgs): Promise<void>;
  stop(): void;
  /**
   * The latest claim deadline this channel has confirmed, in local monotonic
   * milliseconds, or null if it has confirmed none yet. Read SYNCHRONOUSLY by
   * the fencing watchdog: a renewal must be visible the instant the database
   * confirms it, not once the main event loop gets around to draining a
   * message queue that a data-plane flood is competing with.
   */
  publishedDeadlineLocalMs(): number | null;
  /**
   * True when renewals are issued off the main event loop on a reserved
   * database connection. The production composition asserts this.
   */
  readonly isolated: boolean;
}

/** SQLSTATE raised by pfm when the caller is no longer the live manager. */
const EPOCH_SUPERSEDED_SQLSTATE = "PF001";

// ---------------------------------------------------------------------------
// In-process heartbeat.
//
// Renews on the CALLER'S event loop through the caller's store. It is the
// correct shape for an in-memory control store (there is no connection to
// reserve and no data plane to be starved by), and it is NOT isolated —
// `isolated` is false, and the production composition refuses it.
// ---------------------------------------------------------------------------

export class InProcessClaimHeartbeat implements ClaimHeartbeat {
  readonly isolated = false;

  private timer: NodeJS.Timeout | null = null;
  private stopped = false;
  private deadlineLocalMs: number | null = null;

  publishedDeadlineLocalMs(): number | null {
    return this.deadlineLocalMs;
  }

  constructor(
    private readonly renew: (args: {
      identity: ManagerIdentity;
      ttlMs: number;
    }) => Promise<{ dbTimeMs: number; claimExpiresAtDbMs: number }>
  ) {}

  async start(args: ClaimHeartbeatStartArgs): Promise<void> {
    const attempt = async () => {
      if (this.stopped) {
        return;
      }
      const anchorLocalMs = args.now();
      try {
        const renewal = await this.renew({ identity: args.identity, ttlMs: args.ttlMs });
        if (this.stopped) {
          return;
        }
        const deadline =
          anchorLocalMs + (renewal.claimExpiresAtDbMs - renewal.dbTimeMs);
        if (this.deadlineLocalMs === null || deadline > this.deadlineLocalMs) {
          this.deadlineLocalMs = deadline;
        }
        args.listeners.onRenewed({
          anchorLocalMs,
          dbTimeMs: renewal.dbTimeMs,
          claimExpiresAtDbMs: renewal.claimExpiresAtDbMs,
        });
      } catch (error) {
        if (this.stopped) {
          return;
        }
        const message = error instanceof Error ? error.message : String(error);
        if (isEpochSupersededError(error)) {
          args.listeners.onSuperseded(message);
          return;
        }
        args.listeners.onFailure(message);
      }
    };
    this.timer = setInterval(() => void attempt(), args.intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

// A ManagerEpochSupersededError carries the durable proof that this manager
// lost the claim. Recognised structurally (name + sqlstate) so this module
// stays free of an import cycle with the control store.
function isEpochSupersededError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const candidate = error as { name?: unknown; code?: unknown };
  return (
    candidate.name === "ManagerEpochSupersededError" ||
    candidate.code === EPOCH_SUPERSEDED_SQLSTATE
  );
}

// ---------------------------------------------------------------------------
// Worker-thread heartbeat (production).
// ---------------------------------------------------------------------------

/** The subset of worker_threads.Worker this module uses; tests supply a double. */
export interface ClaimHeartbeatWorkerHandle {
  readonly threadId: number;
  on(event: "message", listener: (message: ClaimHeartbeatMessage) => void): unknown;
  on(event: "error", listener: (error: Error) => void): unknown;
  on(event: "exit", listener: (code: number) => void): unknown;
  postMessage(message: unknown): void;
  terminate(): Promise<number>;
  unref?(): void;
}

export interface WorkerClaimHeartbeatOptions {
  connectionString: string;
  /** Builds the exact pfm renewal statement; the control store owns the SQL. */
  renewalStatement(args: {
    identity: ManagerIdentity;
    ttlMs: number;
  }): { sql: string; values: unknown[] };
  connectTimeoutMs: number;
  statementTimeoutMs: number;
  /** Test seam: production spawns the real worker module. */
  spawnWorker?(data: ClaimHeartbeatWorkerData): ClaimHeartbeatWorkerHandle;
  /** Bound on the worker's isolation handshake. */
  helloTimeoutMs?: number;
}

const DEFAULT_HELLO_TIMEOUT_MS = 10_000;

export class WorkerClaimHeartbeat implements ClaimHeartbeat {
  readonly isolated = true;

  private worker: ClaimHeartbeatWorkerHandle | null = null;
  private stopped = false;
  // One BigInt64 cell shared with the liveness thread. It carries the current
  // claim deadline in local monotonic milliseconds; 0 means "none confirmed
  // yet". The main thread only ever LOADS it, so there is no lock, no queue,
  // and nothing on the main event loop between a confirmed renewal and the
  // watchdog seeing it.
  private readonly deadlineCell = new SharedArrayBuffer(8);
  private readonly deadlineView = new BigInt64Array(this.deadlineCell);

  constructor(private readonly options: WorkerClaimHeartbeatOptions) {}

  publishedDeadlineLocalMs(): number | null {
    const value = Atomics.load(this.deadlineView, 0);
    return value === 0n ? null : Number(value);
  }

  async start(args: ClaimHeartbeatStartArgs): Promise<void> {
    const statement = this.options.renewalStatement({
      identity: args.identity,
      ttlMs: args.ttlMs,
    });
    const data: ClaimHeartbeatWorkerData = {
      connectionString: this.options.connectionString,
      sql: statement.sql,
      values: statement.values,
      intervalMs: args.intervalMs,
      connectTimeoutMs: this.options.connectTimeoutMs,
      statementTimeoutMs: this.options.statementTimeoutMs,
      deadlineCell: this.deadlineCell,
    };
    // The clock bracket is captured around the worker's whole boot: the hello
    // frame's clock reading must fall inside it, which proves both threads
    // read ONE monotonic clock. Without that proof the anchors the worker
    // sends would be meaningless on this thread, so a failure is fatal.
    const clockBefore = args.now();
    const worker = (this.options.spawnWorker ?? spawnClaimHeartbeatWorker)(data);
    this.worker = worker;
    // The heartbeat must never be the reason the process stays alive; the
    // registry stops it explicitly on shutdown.
    worker.unref?.();

    const hello = await new Promise<{ threadId: number; isMainThread: boolean; clockMs: number }>(
      (resolve, reject) => {
        const timer = setTimeout(() => {
          reject(
            new Error(
              `The manager claim heartbeat worker did not report within ${
                this.options.helloTimeoutMs ?? DEFAULT_HELLO_TIMEOUT_MS
              }ms; refusing to run without a proven liveness thread.`
            )
          );
        }, this.options.helloTimeoutMs ?? DEFAULT_HELLO_TIMEOUT_MS);
        timer.unref?.();
        worker.on("message", (message) => {
          if (message.type === "hello") {
            clearTimeout(timer);
            resolve(message);
          }
        });
        worker.on("error", (error) => {
          clearTimeout(timer);
          reject(error);
        });
        worker.on("exit", (code) => {
          clearTimeout(timer);
          reject(
            new Error(`The manager claim heartbeat worker exited with code ${code} during startup.`)
          );
        });
      }
    );
    const clockAfter = args.now();
    if (hello.isMainThread) {
      throw new Error(
        "The manager claim heartbeat reported that it runs on the main thread; the singleton claim's liveness must not share the event loop that carries data-plane traffic."
      );
    }
    if (!(hello.clockMs >= clockBefore && hello.clockMs <= clockAfter)) {
      throw new Error(
        `The manager claim heartbeat worker does not share this thread's monotonic clock (${hello.clockMs} outside [${clockBefore}, ${clockAfter}]); its renewal anchors cannot be projected onto the local claim deadline.`
      );
    }

    worker.on("message", (message) => {
      if (this.stopped) {
        return;
      }
      if (message.type === "renewed") {
        args.listeners.onRenewed({
          anchorLocalMs: message.anchorLocalMs,
          dbTimeMs: message.dbTimeMs,
          claimExpiresAtDbMs: message.claimExpiresAtDbMs,
        });
        return;
      }
      if (message.type === "failed") {
        if (message.code === EPOCH_SUPERSEDED_SQLSTATE) {
          args.listeners.onSuperseded(message.message);
          return;
        }
        args.listeners.onFailure(message.message);
      }
    });
    // A worker that dies is a liveness channel that is gone. It is reported
    // once and never restarted: the deadline watchdog owns what happens next,
    // and it fences on schedule. Restarting here would be a second, racing
    // opinion about who holds the claim.
    worker.on("error", (error) => {
      if (!this.stopped) {
        args.listeners.onFailure(
          `the manager claim heartbeat thread failed: ${error.message}; this manager will fence at its claim deadline`
        );
      }
    });
    worker.on("exit", (code) => {
      if (!this.stopped) {
        args.listeners.onFailure(
          `the manager claim heartbeat thread exited (code ${code}); this manager will fence at its claim deadline`
        );
      }
    });
  }

  stop(): void {
    this.stopped = true;
    const worker = this.worker;
    this.worker = null;
    if (!worker) {
      return;
    }
    try {
      worker.postMessage({ type: "stop" });
    } catch {
      // The thread is already gone.
    }
    void worker.terminate().catch(() => undefined);
  }
}

/**
 * Resolves the worker entry sitting next to THIS module, in whichever form
 * this module itself was loaded: the compiled `.js` in a built deployment, the
 * `.ts` when the manager is run straight from source (`pnpm dev`, vitest).
 * This is module layout, not policy — there is no in-process fallback. When
 * neither sibling exists the deployment is broken and startup fails closed.
 */
export function claimHeartbeatWorkerEntryUrl(): URL {
  const compiled = new URL("./claim-heartbeat-worker.js", import.meta.url);
  if (existsSync(fileURLToPath(compiled))) {
    return compiled;
  }
  const source = new URL("./claim-heartbeat-worker.ts", import.meta.url);
  if (existsSync(fileURLToPath(source))) {
    return source;
  }
  throw new Error(
    `The manager claim heartbeat worker entry is missing next to ${import.meta.url}; this build cannot renew its singleton claim in isolation.`
  );
}

function spawnClaimHeartbeatWorker(
  data: ClaimHeartbeatWorkerData
): ClaimHeartbeatWorkerHandle {
  return new Worker(claimHeartbeatWorkerEntryUrl(), {
    workerData: data,
    // The liveness thread never inherits stdio pressure from the main thread.
    stdin: false,
  }) as unknown as ClaimHeartbeatWorkerHandle;
}
