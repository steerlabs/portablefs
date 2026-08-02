import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { parseManagerEpoch } from "@portablefs/protocol";
import { afterEach, describe, expect, test } from "vitest";
import {
  claimHeartbeatWorkerEntryUrl,
  InProcessClaimHeartbeat,
  WorkerClaimHeartbeat,
  type ClaimHeartbeatListeners,
  type ClaimHeartbeatWorkerHandle,
  type ClaimRenewalFacts,
} from "./claim-heartbeat.js";
import {
  projectRenewal,
  runClaimHeartbeatWorker as runClaimHeartbeatWorkerForTest,
  type ClaimHeartbeatMessage,
  type ClaimHeartbeatWorkerData,
} from "./claim-heartbeat-worker.js";
import type { ManagerIdentity } from "./manager-control-store.js";

const identity: ManagerIdentity = {
  managerEpoch: parseManagerEpoch("7"),
  managerRuntimeId: "pfmgr_test",
  managerCapability: "pfmcap_test",
};

function collector(): {
  listeners: ClaimHeartbeatListeners;
  renewed: ClaimRenewalFacts[];
  superseded: string[];
  failures: string[];
} {
  const renewed: ClaimRenewalFacts[] = [];
  const superseded: string[] = [];
  const failures: string[] = [];
  return {
    renewed,
    superseded,
    failures,
    listeners: {
      onRenewed: (facts) => renewed.push(facts),
      onSuperseded: (message) => superseded.push(message),
      onFailure: (message) => failures.push(message),
    },
  };
}

// A worker double: the main thread's half of the protocol is exercised
// without a database, a thread, or a clock race.
class FakeWorker implements ClaimHeartbeatWorkerHandle {
  readonly threadId = 3;
  readonly posted: unknown[] = [];
  terminated = 0;
  private readonly messageListeners: Array<(message: ClaimHeartbeatMessage) => void> = [];
  private readonly errorListeners: Array<(error: Error) => void> = [];
  private readonly exitListeners: Array<(code: number) => void> = [];

  constructor(readonly data: ClaimHeartbeatWorkerData) {}

  on(event: "message" | "error" | "exit", listener: (arg: never) => unknown): this {
    if (event === "message") {
      this.messageListeners.push(listener as (message: ClaimHeartbeatMessage) => void);
    } else if (event === "error") {
      this.errorListeners.push(listener as unknown as (error: Error) => void);
    } else {
      this.exitListeners.push(listener as unknown as (code: number) => void);
    }
    return this;
  }

  postMessage(message: unknown): void {
    this.posted.push(message);
  }

  async terminate(): Promise<number> {
    this.terminated += 1;
    return 0;
  }

  emit(message: ClaimHeartbeatMessage): void {
    for (const listener of [...this.messageListeners]) {
      listener(message);
    }
  }

  emitError(error: Error): void {
    for (const listener of [...this.errorListeners]) {
      listener(error);
    }
  }

  emitExit(code: number): void {
    for (const listener of [...this.exitListeners]) {
      listener(code);
    }
  }
}

async function startWithFakeWorker(options: {
  hello?: Partial<{ threadId: number; isMainThread: boolean; clockMs: number }>;
  now?: () => number;
} = {}): Promise<{
  heartbeat: WorkerClaimHeartbeat;
  worker: FakeWorker;
  collected: ReturnType<typeof collector>;
}> {
  let worker: FakeWorker | undefined;
  const collected = collector();
  const heartbeat = new WorkerClaimHeartbeat({
    connectionString: "postgres://control/manager",
    renewalStatement: (args) => ({
      sql: "SELECT pfm.manager_renew($1,$2,$3,$4) AS r",
      values: [args.identity.managerEpoch, args.identity.managerRuntimeId, args.identity.managerCapability, args.ttlMs],
    }),
    connectTimeoutMs: 5_000,
    statementTimeoutMs: 10_000,
    helloTimeoutMs: 1_000,
    spawnWorker: (data) => {
      worker = new FakeWorker(data);
      // The hello frame lands on the next turn, exactly as a real thread's does.
      setImmediate(() =>
        worker!.emit({
          type: "hello",
          threadId: options.hello?.threadId ?? 3,
          isMainThread: options.hello?.isMainThread ?? false,
          clockMs: options.hello?.clockMs ?? performance.now(),
        })
      );
      return worker;
    },
  });
  await heartbeat.start({
    identity,
    ttlMs: 30_000,
    intervalMs: 10_000,
    now: options.now ?? (() => performance.now()),
    listeners: collected.listeners,
  });
  return { heartbeat, worker: worker!, collected };
}

describe("WorkerClaimHeartbeat: the isolated liveness channel", () => {
  test("reports isolated=true and hands the worker the exact renewal statement", async () => {
    const { heartbeat, worker } = await startWithFakeWorker();
    expect(heartbeat.isolated).toBe(true);
    expect(worker.data.sql).toBe("SELECT pfm.manager_renew($1,$2,$3,$4) AS r");
    expect(worker.data.values).toEqual(["7", "pfmgr_test", "pfmcap_test", 30_000]);
    // The per-attempt bound IS the cadence: two attempts can never overlap and
    // therefore can never add up past the TTL.
    expect(worker.data.intervalMs).toBe(10_000);
    heartbeat.stop();
  });

  test("no deadline is published before the first confirmed renewal", async () => {
    const { heartbeat } = await startWithFakeWorker();
    expect(heartbeat.publishedDeadlineLocalMs()).toBeNull();
    heartbeat.stop();
  });

  test("a confirmed renewal is forwarded with the worker's PRE-CALL anchor", async () => {
    const { heartbeat, worker, collected } = await startWithFakeWorker();
    worker.emit({
      type: "renewed",
      anchorLocalMs: 1_000,
      dbTimeMs: 5_000_000,
      claimExpiresAtDbMs: 5_030_000,
    });
    expect(collected.renewed).toEqual([
      { anchorLocalMs: 1_000, dbTimeMs: 5_000_000, claimExpiresAtDbMs: 5_030_000 },
    ]);
    heartbeat.stop();
  });

  test("PF001 is supersession, every other failure is ambiguous", async () => {
    const { heartbeat, worker, collected } = await startWithFakeWorker();
    worker.emit({ type: "failed", anchorLocalMs: 1, code: "PF001", message: "epoch superseded" });
    worker.emit({ type: "failed", anchorLocalMs: 2, code: "57P03", message: "starting up" });
    worker.emit({ type: "failed", anchorLocalMs: 3, code: null, message: "timeout exceeded" });
    expect(collected.superseded).toEqual(["epoch superseded"]);
    expect(collected.failures).toEqual(["starting up", "timeout exceeded"]);
    heartbeat.stop();
  });

  test("a dead liveness thread is a renewal FAILURE, never a silent success", async () => {
    const { heartbeat, worker, collected } = await startWithFakeWorker();
    worker.emitError(new Error("worker blew up"));
    worker.emitExit(7);
    expect(collected.renewed).toEqual([]);
    expect(collected.failures).toHaveLength(2);
    expect(collected.failures[0]).toContain("will fence at its claim deadline");
    expect(collected.failures[1]).toContain("exited (code 7)");
    heartbeat.stop();
  });

  test("FAIL CLOSED: a heartbeat that reports it runs on the main thread is refused", async () => {
    await expect(startWithFakeWorker({ hello: { isMainThread: true } })).rejects.toThrow(
      /must not share the event loop/
    );
  });

  test("FAIL CLOSED: a heartbeat that does not share this thread's monotonic clock is refused", async () => {
    // Its anchors would be meaningless when projected onto the local deadline.
    await expect(startWithFakeWorker({ hello: { clockMs: -1 } })).rejects.toThrow(
      /does not share this thread's monotonic clock/
    );
  });

  test("FAIL CLOSED: a heartbeat that never reports is refused rather than assumed alive", async () => {
    const heartbeat = new WorkerClaimHeartbeat({
      connectionString: "postgres://control/manager",
      renewalStatement: () => ({ sql: "SELECT 1", values: [] }),
      connectTimeoutMs: 1_000,
      statementTimeoutMs: 1_000,
      helloTimeoutMs: 50,
      spawnWorker: (data) => new FakeWorker(data),
    });
    await expect(
      heartbeat.start({
        identity,
        ttlMs: 30_000,
        intervalMs: 10_000,
        now: () => performance.now(),
        listeners: collector().listeners,
      })
    ).rejects.toThrow(/did not report within 50ms/);
  });

  test("stop asks the thread to stop and then terminates it", async () => {
    const { heartbeat, worker, collected } = await startWithFakeWorker();
    heartbeat.stop();
    expect(worker.posted).toEqual([{ type: "stop" }]);
    expect(worker.terminated).toBe(1);
    // Post-stop noise never moves the deadline.
    worker.emit({ type: "renewed", anchorLocalMs: 1, dbTimeMs: 1, claimExpiresAtDbMs: 2 });
    expect(collected.renewed).toEqual([]);
  });
});

describe("projectRenewal: the liveness thread's response projection", () => {
  test("anchors the deadline at the PRE-CALL instant, never at the response", () => {
    // A renewal issued at local 1_000 that granted 30s of database time is
    // good until local 31_000 — even if the response took 5s to arrive.
    expect(projectRenewal(1_000, { dbTimeMs: "5000000", expiresAtDbMs: "5030000" })).toEqual({
      dbTimeMs: 5_000_000,
      claimExpiresAtDbMs: 5_030_000,
      deadlineLocalMs: 31_000,
    });
  });

  test("refuses any response shape that is not pfm's canonical decimal strings", () => {
    // pfm renders 64-bit millisecond timestamps as decimal strings; anything
    // else would let a malformed response move a fencing deadline.
    expect(() => projectRenewal(0, { dbTimeMs: 1, expiresAtDbMs: "2" })).toThrow(
      /dbTimeMs is not a canonical decimal string/
    );
    expect(() => projectRenewal(0, { dbTimeMs: "01", expiresAtDbMs: "2" })).toThrow();
    expect(() => projectRenewal(0, { dbTimeMs: "-1", expiresAtDbMs: "2" })).toThrow();
    expect(() => projectRenewal(0, { dbTimeMs: "1" })).toThrow(/expiresAtDbMs/);
    expect(() => projectRenewal(0, { dbTimeMs: "1", expiresAtDbMs: "99999999999999999999" })).toThrow(
      /safe timestamp boundary/
    );
    expect(() => projectRenewal(0, null)).toThrow(/unexpected row shape/);
    expect(() => projectRenewal(0, [])).toThrow(/unexpected row shape/);
  });
});

describe("InProcessClaimHeartbeat", () => {
  test("reports isolated=false: it renews on the CALLER'S event loop", () => {
    expect(new InProcessClaimHeartbeat(async () => ({ dbTimeMs: 0, claimExpiresAtDbMs: 0 })).isolated).toBe(
      false
    );
  });

  test("forwards renewals, supersession and failures", async () => {
    const collected = collector();
    const outcomes: Array<"ok" | "superseded" | "boom"> = ["ok", "superseded", "boom"];
    let index = 0;
    const heartbeat = new InProcessClaimHeartbeat(async () => {
      const outcome = outcomes[index++];
      if (outcome === "superseded") {
        const error = new Error("PF001 superseded") as Error & { name: string };
        error.name = "ManagerEpochSupersededError";
        throw error;
      }
      if (outcome === "boom") {
        throw new Error("store unavailable");
      }
      return { dbTimeMs: 1_000, claimExpiresAtDbMs: 31_000 };
    });
    await heartbeat.start({
      identity,
      ttlMs: 30_000,
      intervalMs: 1,
      now: () => 500,
      listeners: collected.listeners,
    });
    const deadline = Date.now() + 2_000;
    while (index < 3 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    heartbeat.stop();
    expect(collected.renewed[0]).toEqual({
      anchorLocalMs: 500,
      dbTimeMs: 1_000,
      claimExpiresAtDbMs: 31_000,
    });
    expect(collected.superseded).toEqual(["PF001 superseded"]);
    expect(collected.failures).toEqual(["store unavailable"]);
  });
});

// ---------------------------------------------------------------------------
// THE ROOT-CAUSE TEST (D2).
//
// The incident: a manager under full-speed client write load fenced ITSELF.
// The renewal loop lived on the same event loop as the data-plane router, so
// it could not run while that loop was busy — and the claim's deadline does
// not pause for a busy loop.
//
// This is a DETERMINISTIC loop-blocking harness, not a load test: the main
// thread is held in a hard synchronous busy loop for longer than a whole
// claim TTL. Nothing on the main event loop can run during it, by definition
// — that is a stronger statement than any flood could make. The assertion is
// then structural: renewal attempts were issued DURING the block, by wall
// position, on the process-wide monotonic clock.
//
// The control assertion in the same test shows the old shape failing: a
// renewal loop scheduled on the blocked thread issues ZERO attempts.
// ---------------------------------------------------------------------------

const workerEntry = claimHeartbeatWorkerEntryUrl();

function blockMainThreadFor(ms: number): { startedAt: number; endedAt: number } {
  const startedAt = performance.now();
  // A hard synchronous spin: no timer, no microtask, no I/O callback on this
  // thread can run until it returns.
  while (performance.now() - startedAt < ms) {
    // busy
  }
  return { startedAt, endedAt: performance.now() };
}

describe("the claim heartbeat survives a fully blocked main event loop", () => {
  const workers: Worker[] = [];
  afterEach(async () => {
    await Promise.allSettled(workers.splice(0).map((worker) => worker.terminate()));
  });

  test("the REAL heartbeat worker issues renewal attempts while the main thread is blocked past a whole claim TTL", async () => {
    // The entry under test is the one production resolves, in whichever form
    // this run loaded the module.
    expect(existsSync(fileURLToPath(workerEntry))).toBe(true);

    const intervalMs = 200;
    const claimTtlMs = intervalMs * 3;
    // No database is reachable at this address, so every attempt FAILS — which
    // is exactly what this test needs. What is under test is whether the
    // attempt is issued at all while the main loop is blocked, and a failed
    // attempt proves that as well as a successful one (and proves the real
    // outage path stays honest rather than silent).
    const worker = new Worker(workerEntry, {
      workerData: {
        connectionString: "postgres://pfs:pfs@127.0.0.1:1/pfs_control_unreachable",
        sql: "SELECT pfm.manager_renew($1,$2,$3,$4) AS r",
        values: ["7", "pfmgr_test", "pfmcap_test", claimTtlMs],
        intervalMs,
        connectTimeoutMs: 50,
        statementTimeoutMs: 50,
        deadlineCell: new SharedArrayBuffer(8),
      } satisfies ClaimHeartbeatWorkerData,
    });
    workers.push(worker);

    const messages: ClaimHeartbeatMessage[] = [];
    worker.on("message", (message: ClaimHeartbeatMessage) => messages.push(message));

    // A control loop of the OLD shape: renewal scheduled on the main thread.
    const mainThreadAttempts: number[] = [];
    const mainThreadLoop = setInterval(() => mainThreadAttempts.push(performance.now()), intervalMs);

    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(messages.some((message) => message.type === "hello")).toBe(true);
    const attemptsBeforeBlock = messages.filter((message) => message.type !== "hello").length;
    const mainAttemptsBeforeBlock = mainThreadAttempts.length;

    // Hold the main event loop for longer than a whole claim TTL.
    const block = blockMainThreadFor(claimTtlMs + intervalMs);
    clearInterval(mainThreadLoop);

    // Drain the port: the worker's messages were produced during the block and
    // are only delivered now.
    await new Promise((resolve) => setTimeout(resolve, 50));

    const attemptAnchors = messages
      .filter((message): message is Exclude<ClaimHeartbeatMessage, { type: "hello" }> =>
        message.type !== "hello"
      )
      .map((message) => message.anchorLocalMs);
    const duringBlock = attemptAnchors.filter(
      (anchor) => anchor > block.startedAt && anchor < block.endedAt
    );

    // THE INVARIANT: liveness kept its cadence through a total main-loop
    // block that is longer than the claim's whole lifetime. Three intervals
    // fit inside a TTL; allow for the first tick landing just outside.
    expect(duringBlock.length).toBeGreaterThanOrEqual(3);
    expect(attemptAnchors.length).toBeGreaterThan(attemptsBeforeBlock);

    // THE CONTROL: the shape this replaced — a renewal loop on the manager's
    // own event loop — issued nothing at all across the same window, which is
    // precisely how a healthy manager used to run out its own claim.
    expect(mainThreadAttempts.length).toBe(mainAttemptsBeforeBlock);
  }, 20_000);

  test("the deadline reaches the main thread through SHARED MEMORY, not through a message the loop must drain", async () => {
    // The worker publishes into the shared cell before it posts anything, so
    // the fencing watchdog observes a confirmed renewal with a plain atomic
    // load — never behind a queue that a data-plane flood competes with.
    const cell = new SharedArrayBuffer(8);
    const view = new BigInt64Array(cell);
    const posted: ClaimHeartbeatMessage[] = [];
    const handle = runClaimHeartbeatWorkerForTest(
      {
        connectionString: "postgres://pfs:pfs@127.0.0.1:1/pfs_control_unreachable",
        sql: "SELECT pfm.manager_renew($1,$2,$3,$4) AS r",
        values: [],
        intervalMs: 50,
        connectTimeoutMs: 25,
        statementTimeoutMs: 25,
        deadlineCell: cell,
      },
      (message) => posted.push(message)
    );
    try {
      // Every attempt fails (nothing listens): a failed attempt must NEVER
      // move the published deadline.
      const deadline = Date.now() + 3_000;
      while (posted.filter((message) => message.type === "failed").length < 2 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      expect(posted.some((message) => message.type === "failed")).toBe(true);
      expect(Atomics.load(view, 0)).toBe(0n);
    } finally {
      handle.stop();
    }
  }, 20_000);

  test("BY CONSTRUCTION: the production worker entry reports a non-main thread and the main thread's own monotonic clock", async () => {
    const before = performance.now();
    const worker = new Worker(workerEntry, {
      workerData: {
        connectionString: "postgres://pfs:pfs@127.0.0.1:1/pfs_control_unreachable",
        sql: "SELECT 1 AS r",
        values: [],
        intervalMs: 60_000,
        connectTimeoutMs: 50,
        statementTimeoutMs: 50,
        deadlineCell: new SharedArrayBuffer(8),
      } satisfies ClaimHeartbeatWorkerData,
    });
    workers.push(worker);
    const hello = await new Promise<ClaimHeartbeatMessage>((resolve, reject) => {
      worker.once("message", resolve);
      worker.once("error", reject);
    });
    const after = performance.now();
    expect(hello.type).toBe("hello");
    if (hello.type !== "hello") {
      throw new Error("unreachable");
    }
    expect(hello.isMainThread).toBe(false);
    expect(hello.threadId).toBeGreaterThan(0);
    expect(hello.clockMs).toBeGreaterThanOrEqual(before);
    expect(hello.clockMs).toBeLessThanOrEqual(after);
  }, 20_000);

  test("a real database outage still surfaces as an explicit failure, never as silence", async () => {
    const worker = new Worker(workerEntry, {
      workerData: {
        connectionString: "postgres://pfs:pfs@127.0.0.1:1/pfs_control_unreachable",
        sql: "SELECT pfm.manager_renew($1,$2,$3,$4) AS r",
        values: ["7", "pfmgr_test", "pfmcap_test", 30_000],
        intervalMs: 200,
        connectTimeoutMs: 50,
        statementTimeoutMs: 50,
        deadlineCell: new SharedArrayBuffer(8),
      } satisfies ClaimHeartbeatWorkerData,
    });
    workers.push(worker);
    const failure = await new Promise<ClaimHeartbeatMessage>((resolve, reject) => {
      worker.on("message", (message: ClaimHeartbeatMessage) => {
        if (message.type === "failed") {
          resolve(message);
        }
      });
      worker.once("error", reject);
      setTimeout(() => reject(new Error("no failure reported")), 10_000).unref?.();
    });
    expect(failure.type).toBe("failed");
    if (failure.type !== "failed") {
      throw new Error("unreachable");
    }
    expect(failure.message.length).toBeGreaterThan(0);
    // Not PF001: an unreachable database is ambiguous, not proof of loss.
    expect(failure.code).not.toBe("PF001");
  }, 20_000);
});
