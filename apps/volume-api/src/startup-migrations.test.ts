import { describe, expect, test } from "vitest";
import {
  applyMigrationsUntilReady,
  isTransientStartupError,
  startupMigrationBudgetFromEnv,
  StartupMigrationsNotReadyError,
  type StartupMigrationBudget,
} from "./startup-migrations.js";

function pgError(code: string, message = "pg error"): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}

// A deterministic clock: every sleep advances it exactly, so budgets and
// backoff are asserted by arithmetic instead of by waiting.
function fakeClock(): {
  now(): number;
  sleep(ms: number): Promise<void>;
  slept: number[];
} {
  let current = 1_000_000;
  const slept: number[] = [];
  return {
    now: () => current,
    sleep: async (ms: number) => {
      slept.push(ms);
      current += ms;
    },
    slept,
  };
}

const budget: StartupMigrationBudget = {
  totalBudgetMs: 10_000,
  initialBackoffMs: 100,
  maxBackoffMs: 800,
};

describe("isTransientStartupError", () => {
  test("a database that is not accepting work yet is transient", () => {
    // The recorded incident: PostgreSQL in crash recovery during a deploy.
    expect(
      isTransientStartupError(pgError("57P03", "the database system is starting up"))
    ).toBe(true);
    expect(isTransientStartupError(pgError("57P02"))).toBe(true);
    expect(isTransientStartupError(pgError("53300"))).toBe(true);
    expect(isTransientStartupError(pgError("08006"))).toBe(true);
    expect(isTransientStartupError(pgError("ECONNREFUSED"))).toBe(true);
    expect(isTransientStartupError(pgError("EAI_AGAIN"))).toBe(true);
    expect(isTransientStartupError(new Error("timeout exceeded when trying to connect"))).toBe(
      true
    );
  });

  test("a database that answered ABOUT the migrations is definitive", () => {
    expect(isTransientStartupError(pgError("42601", "syntax error at or near"))).toBe(false);
    expect(isTransientStartupError(pgError("42501", "permission denied for schema"))).toBe(false);
    expect(isTransientStartupError(pgError("23505", "duplicate key value"))).toBe(false);
    // Unknown shapes are definitive: an unrecognised failure must fail the
    // deploy, never be retried into a timeout.
    expect(isTransientStartupError(new Error("migration 017 checksum mismatch"))).toBe(false);
    expect(isTransientStartupError("not an error")).toBe(false);
    expect(isTransientStartupError(null)).toBe(false);
  });

  test("a definitive SQLSTATE is not rescued by a transient-looking message", () => {
    expect(
      isTransientStartupError(pgError("42601", "timeout exceeded when trying to connect"))
    ).toBe(false);
  });
});

describe("applyMigrationsUntilReady", () => {
  test("a database in crash recovery is waited out, and migrations then apply", async () => {
    const clock = fakeClock();
    let attempts = 0;
    await applyMigrationsUntilReady(
      async () => {
        attempts += 1;
        if (attempts < 4) {
          throw pgError("57P03", "the database system is starting up");
        }
      },
      { budget, now: clock.now, sleep: clock.sleep, log: () => {} }
    );
    expect(attempts).toBe(4);
    // Exponential backoff, capped.
    expect(clock.slept).toEqual([100, 200, 400]);
  });

  test("a REAL migration failure fails the deploy on the first attempt", async () => {
    const clock = fakeClock();
    let attempts = 0;
    await expect(
      applyMigrationsUntilReady(
        async () => {
          attempts += 1;
          throw pgError("42601", "syntax error at or near \"CRAETE\"");
        },
        { budget, now: clock.now, sleep: clock.sleep, log: () => {} }
      )
    ).rejects.toThrow(/syntax error/);
    expect(attempts).toBe(1);
    expect(clock.slept).toEqual([]);
  });

  test("an exhausted budget fails the deploy DEFINITIVELY rather than starting without the schema", async () => {
    const clock = fakeClock();
    let attempts = 0;
    const error = await applyMigrationsUntilReady(
      async () => {
        attempts += 1;
        throw pgError("ECONNREFUSED", "connect ECONNREFUSED 10.0.0.5:5432");
      },
      { budget, now: clock.now, sleep: clock.sleep, log: () => {} }
    ).catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(StartupMigrationsNotReadyError);
    const notReady = error as StartupMigrationsNotReadyError;
    expect(notReady.elapsedMs).toBeGreaterThanOrEqual(budget.totalBudgetMs);
    expect(notReady.attempts).toBe(attempts);
    expect(notReady.message).toContain("ECONNREFUSED");
    // Never an unbounded retry loop.
    expect(attempts).toBeLessThan(100);
  });

  test("the final wait never overruns the budget", async () => {
    const clock = fakeClock();
    await applyMigrationsUntilReady(
      async () => {
        throw pgError("57P03");
      },
      {
        budget: { totalBudgetMs: 250, initialBackoffMs: 200, maxBackoffMs: 200 },
        now: clock.now,
        sleep: clock.sleep,
        log: () => {},
      }
    ).catch(() => undefined);
    expect(clock.slept).toEqual([200, 50]);
  });

  test("a database that is ready immediately applies once and waits for nothing", async () => {
    const clock = fakeClock();
    let attempts = 0;
    await applyMigrationsUntilReady(
      async () => {
        attempts += 1;
      },
      { budget, now: clock.now, sleep: clock.sleep, log: () => {} }
    );
    expect(attempts).toBe(1);
    expect(clock.slept).toEqual([]);
  });
});

describe("startupMigrationBudgetFromEnv", () => {
  test("defaults outlast a real crash recovery and are bounded", () => {
    const resolved = startupMigrationBudgetFromEnv({});
    expect(resolved.totalBudgetMs).toBe(300_000);
    expect(resolved.initialBackoffMs).toBe(1_000);
    expect(resolved.maxBackoffMs).toBe(15_000);
  });

  test("tuning is strictly validated", () => {
    expect(
      startupMigrationBudgetFromEnv({ VOLUME_MIGRATION_READY_BUDGET_MS: "60000" }).totalBudgetMs
    ).toBe(60_000);
    expect(() => startupMigrationBudgetFromEnv({ VOLUME_MIGRATION_READY_BUDGET_MS: "0" })).toThrow();
    expect(() =>
      startupMigrationBudgetFromEnv({ VOLUME_MIGRATION_READY_BUDGET_MS: "forever" })
    ).toThrow();
    expect(() =>
      startupMigrationBudgetFromEnv({
        VOLUME_MIGRATION_RETRY_INITIAL_BACKOFF_MS: "30000",
        VOLUME_MIGRATION_RETRY_MAX_BACKOFF_MS: "1000",
      })
    ).toThrow(/must not exceed/);
  });
});
