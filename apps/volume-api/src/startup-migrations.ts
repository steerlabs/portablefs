import { intEnv } from "./config.js";

// ---------------------------------------------------------------------------
// The startup migration gate.
//
// applyMigrations is the FIRST thing this process does, and it runs before
// anything listens. A single throw there kills the process at boot.
//
// The recorded incident: PostgreSQL was in crash recovery when a deploy rolled.
// It answered `57P03 the database system is starting up` — a state it leaves on
// its own, usually in seconds. The API took that transient answer as a verdict,
// died, and stayed dead.
//
// This gate makes the distinction the process was missing:
//
//   TRANSIENT  — the database is not ACCEPTING work yet (crash recovery,
//                starting up, shutting down, connection refused/reset, DNS not
//                resolving yet, connection budget momentarily exhausted). The
//                answer says nothing about the migrations. Retry until the
//                budget runs out.
//   DEFINITIVE — the database answered ABOUT the work: a bad migration, a
//                permission problem, a lineage conflict. Retrying cannot change
//                it. Fail the deploy now, with the original error.
//
// The budget is bounded on both ends: it never gives up on a database that is
// merely slow to come back, and it never retries forever either. When it
// expires the process exits non-zero with the last transient error attached, so
// the deploy fails DEFINITIVELY and visibly instead of a container flapping.
// ---------------------------------------------------------------------------

// SQLSTATEs that describe the SERVER'S availability, never the migration.
//   57P03 cannot_connect_now  — starting up / in recovery / shutting down
//   57P01 admin_shutdown      — the backend was terminated
//   57P02 crash_shutdown      — the backend crashed and the cluster is recovering
//   53300 too_many_connections
//   08xxx connection exceptions (refused, reset, failure to establish)
const TRANSIENT_SQLSTATES = new Set([
  "57P01",
  "57P02",
  "57P03",
  "53300",
  "08000",
  "08001",
  "08003",
  "08004",
  "08006",
  "08007",
  "08P01",
]);

// Socket/DNS level failures: the database was never reached, so nothing was
// learned about the migrations.
const TRANSIENT_SYSCALL_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "EPIPE",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENOTFOUND",
  "EAI_AGAIN",
]);

// pg's pool raises this as a plain Error when every connection is checked out
// or a new one could not be established inside connectionTimeoutMillis.
const TRANSIENT_MESSAGE_PATTERNS = [
  /timeout exceeded when trying to connect/i,
  /Connection terminated unexpectedly/i,
  /the database system is (?:starting up|shutting down|in recovery)/i,
];

/**
 * True when the error describes the database's AVAILABILITY rather than the
 * migrations themselves. Everything else is definitive by default: an unknown
 * error must fail the deploy, never be retried into a timeout.
 */
export function isTransientStartupError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const candidate = error as { code?: unknown; message?: unknown };
  if (typeof candidate.code === "string") {
    if (TRANSIENT_SQLSTATES.has(candidate.code) || TRANSIENT_SYSCALL_CODES.has(candidate.code)) {
      return true;
    }
    // A definitive SQLSTATE (a broken migration, a permission denial) must not
    // be rescued by the message patterns below.
    if (/^[0-9A-Z]{5}$/u.test(candidate.code)) {
      return false;
    }
  }
  const message = typeof candidate.message === "string" ? candidate.message : "";
  return TRANSIENT_MESSAGE_PATTERNS.some((pattern) => pattern.test(message));
}

export interface StartupMigrationBudget {
  /** Total wall time the gate will keep retrying a NOT-YET-READY database. */
  totalBudgetMs: number;
  /** Delay before the first retry; doubles up to maxBackoffMs. */
  initialBackoffMs: number;
  maxBackoffMs: number;
}

export const DEFAULT_STARTUP_MIGRATION_BUDGET: StartupMigrationBudget = {
  // Long enough to outlast a real PostgreSQL crash recovery on a managed
  // instance, short enough that a genuinely unreachable database fails the
  // deploy inside one deploy window.
  totalBudgetMs: 300_000,
  initialBackoffMs: 1_000,
  maxBackoffMs: 15_000,
};

export function startupMigrationBudgetFromEnv(
  env: NodeJS.ProcessEnv
): StartupMigrationBudget {
  const budget: StartupMigrationBudget = {
    totalBudgetMs: intEnv(
      env,
      "VOLUME_MIGRATION_READY_BUDGET_MS",
      DEFAULT_STARTUP_MIGRATION_BUDGET.totalBudgetMs,
      1_000,
      3_600_000
    ),
    initialBackoffMs: intEnv(
      env,
      "VOLUME_MIGRATION_RETRY_INITIAL_BACKOFF_MS",
      DEFAULT_STARTUP_MIGRATION_BUDGET.initialBackoffMs,
      10,
      60_000
    ),
    maxBackoffMs: intEnv(
      env,
      "VOLUME_MIGRATION_RETRY_MAX_BACKOFF_MS",
      DEFAULT_STARTUP_MIGRATION_BUDGET.maxBackoffMs,
      10,
      120_000
    ),
  };
  if (budget.initialBackoffMs > budget.maxBackoffMs) {
    throw new Error(
      "VOLUME_MIGRATION_RETRY_INITIAL_BACKOFF_MS must not exceed VOLUME_MIGRATION_RETRY_MAX_BACKOFF_MS."
    );
  }
  return budget;
}

/** Raised when the budget expired with the database still not accepting work. */
export class StartupMigrationsNotReadyError extends Error {
  constructor(
    readonly attempts: number,
    readonly elapsedMs: number,
    readonly lastError: unknown
  ) {
    super(
      `The metadata database did not become ready for migrations within ${elapsedMs}ms (${attempts} attempts). ` +
        "This deployment is failing DEFINITIVELY rather than starting without its schema lineage. " +
        `Last transient error: ${lastError instanceof Error ? lastError.message : String(lastError)}`
    );
    this.name = "StartupMigrationsNotReadyError";
  }
}

export interface ApplyMigrationsUntilReadyDeps {
  budget?: StartupMigrationBudget;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  log?: (message: string) => void;
}

/**
 * Applies migrations, retrying ONLY while the database is not yet accepting
 * work. A definitive failure propagates on the first attempt; an exhausted
 * budget throws StartupMigrationsNotReadyError. Either way the caller's boot
 * fails — this never starts an API without its schema lineage.
 */
export async function applyMigrationsUntilReady(
  apply: () => Promise<void>,
  deps: ApplyMigrationsUntilReadyDeps = {}
): Promise<void> {
  const budget = deps.budget ?? DEFAULT_STARTUP_MIGRATION_BUDGET;
  const now = deps.now ?? (() => Date.now());
  const sleep =
    deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const log = deps.log ?? ((message: string) => console.warn(message));

  const startedAt = now();
  const deadline = startedAt + budget.totalBudgetMs;
  let backoffMs = budget.initialBackoffMs;
  let attempts = 0;
  let lastError: unknown;

  for (;;) {
    attempts += 1;
    try {
      await apply();
      if (attempts > 1) {
        log(
          `PortableFS API metadata migrations applied after ${attempts} attempts (${
            now() - startedAt
          }ms waiting for the database to accept work).`
        );
      }
      return;
    } catch (error) {
      if (!isTransientStartupError(error)) {
        // The database answered ABOUT the migrations. No amount of waiting
        // changes that answer.
        throw error;
      }
      lastError = error;
      const remainingMs = deadline - now();
      if (remainingMs <= 0) {
        throw new StartupMigrationsNotReadyError(attempts, now() - startedAt, error);
      }
      const waitMs = Math.min(backoffMs, remainingMs);
      log(
        `PortableFS API metadata database is not accepting work yet (attempt ${attempts}: ${
          error instanceof Error ? error.message : String(error)
        }); retrying in ${waitMs}ms, ${remainingMs}ms of budget left.`
      );
      await sleep(waitMs);
      backoffMs = Math.min(backoffMs * 2, budget.maxBackoffMs);
    }
  }
}
