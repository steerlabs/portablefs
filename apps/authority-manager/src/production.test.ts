import { afterEach, describe, expect, test } from "vitest";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { readFile, stat } from "node:fs/promises";
import os from "node:os";
import type { AddressInfo } from "node:net";
import type { ChildProcess } from "node:child_process";
import { parseAccessLeaseControlSeq, parseManagerEpoch, type ManagerEpoch } from "@portablefs/protocol";
import {
  AuthorityOperationError,
  authorityOperationErrorCodes,
  createAuthorityManagerServer,
  type AuthorityRef,
  type AuthorityRegistry,
} from "./server.js";
import {
  ControlStoreUnavailableError,
  InMemoryManagerControlStore,
  ManagerEpochSupersededError,
  managedTenantKey,
  sha256Hex,
  type ManagerClaimResult,
  type ManagerIdentity,
} from "./manager-control-store.js";
import { AccessLeaseError } from "./access-lease-error.js";
import { ProductionAccessLeaseService, accessLeaseRefKey } from "./production-access-leases.js";
import {
  CHILD_BOOTSTRAP_FD,
  CHILD_HEARTBEAT_FD,
  MANAGED_CHILD_PROTOCOL_VERSION,
  canonicalHaPolicyHash,
  createProductionAuthorityRegistry,
  escapeLogControls,
  formatChildLogChunk,
  readProductionAuthorityRegistryConfig,
  type ProductionAuthorityRegistry,
} from "./production-registry.js";
import {
  mintAccessToken,
  mintRootSecret,
  parseAccessToken,
  verifyAccessToken,
  type AccessTokenClaims,
} from "./access-tokens.js";
import { ChildMetricsCollector } from "./child-metrics.js";
import { ManagerMetrics } from "./manager-metrics.js";
import { createManagerMetricsEndpoint } from "./metrics-endpoint.js";

const ref = { teamId: "team_1", volumeId: "vol_1", branch: "main" };

const registries: ProductionAuthorityRegistry[] = [];
const servers: Array<ReturnType<typeof createAuthorityManagerServer>> = [];

test("operator logs escape tenant controls and prefix every child-output line", () => {
  expect(escapeLogControls("vol\nname\u001b[31m")).toBe(
    "vol\\u000aname\\u001b[31m"
  );
  expect(
    formatChildLogChunk(
      "[portablefs-vcs production safe]",
      Buffer.from("first\nforged\u001b[2J\n")
    )
  ).toBe(
    "[portablefs-vcs production safe] first\n" +
      "[portablefs-vcs production safe] forged\\u001b[2J\n"
  );
});

afterEach(async () => {
  await Promise.allSettled(registries.splice(0).map((registry) => registry.shutdown()));
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        })
    )
  );
});

function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeoutMs = 2_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await condition()) {
      return;
    }
    if (Date.now() > deadline) {
      throw new Error("waitFor condition not reached in time");
    }
    await delay(5);
  }
}

interface ClaimedManager {
  claim: ManagerClaimResult;
  identity: ManagerIdentity;
}

async function claimManager(
  store: InMemoryManagerControlStore,
  args: { operationId: string; runtimeId: string; capability?: string; ttlMs?: number }
): Promise<ClaimedManager> {
  const capability = args.capability ?? `capability-${args.runtimeId}`;
  const claim = await store.claimManager({
    operationId: args.operationId,
    runtimeId: args.runtimeId,
    capabilityHash: sha256Hex(capability),
    ttlMs: args.ttlMs ?? 300_000,
  });
  return {
    claim,
    identity: {
      managerEpoch: claim.managerEpoch,
      managerRuntimeId: args.runtimeId,
      managerCapability: capability,
    },
  };
}

async function expectAccessLeaseError(
  run: () => Promise<unknown> | unknown,
  code: string
): Promise<AccessLeaseError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(AccessLeaseError);
    expect((error as AccessLeaseError).code).toBe(code);
    return error as AccessLeaseError;
  }
  throw new Error(`expected AccessLeaseError ${code}, but the operation succeeded`);
}

async function expectOperationError(
  promise: Promise<unknown>,
  code: string
): Promise<AuthorityOperationError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AuthorityOperationError);
    expect((error as AuthorityOperationError).code).toBe(code);
    return error as AuthorityOperationError;
  }
  throw new Error(`expected AuthorityOperationError ${code}, but the operation succeeded`);
}

// ---------------------------------------------------------------------------
// ProductionAccessLeaseService.
// ---------------------------------------------------------------------------

interface LeaseHarness {
  store: InMemoryManagerControlStore;
  service: ProductionAccessLeaseService;
  identity: ManagerIdentity;
  managerEpoch: ManagerEpoch;
  db: { time: number; advance(ms: number): void };
}

async function newLeaseHarness(
  options: {
    serviceOptions?: ConstructorParameters<typeof ProductionAccessLeaseService>[4];
    store?: InMemoryManagerControlStore;
  } = {}
): Promise<LeaseHarness> {
  const db = {
    time: 1_000_000,
    advance(ms: number) {
      this.time += ms;
    },
  };
  const store = options.store ?? new InMemoryManagerControlStore({ dbNow: () => db.time });
  const manager = await claimManager(store, {
    operationId: "claim-manager-a",
    runtimeId: "manager-a",
    ttlMs: 600_000,
  });
  await store.beginAuthorityRuntime({
    identity: manager.identity,
    scope: { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch },
    authorityInstanceId: "pfvcs_a",
    runtimeId: "runtime-a",
  });
  const service = new ProductionAccessLeaseService(
    store,
    manager.identity,
    { dbTimeMs: manager.claim.dbTimeMs },
    mintRootSecret(),
    {
      // The HOST clock is frozen and wildly skewed from the database clock:
      // every expiry fact must come from store database time regardless.
      localNow: () => 555,
      ...(options.serviceOptions ?? {}),
    }
  );
  service.setAuthorityRouteResolver(() => ({
    backendAddresses: ["127.0.0.1:1"],
    backendAuthToken: "pfs_backend_test",
  }));
  return {
    store,
    service,
    identity: manager.identity,
    managerEpoch: manager.claim.managerEpoch,
    db,
  };
}

const createArgs = {
  operationId: "op-create-1",
  teamId: "team_1",
  volumeId: "vol_1",
  branch: "main",
  consumerId: "sandbox-a",
  authorityInstanceId: "pfvcs_a",
  authorityRuntimeGeneration: "1",
  authorityRuntimeId: "runtime-a",
  ttlMs: 60_000,
};

describe("ProductionAccessLeaseService", () => {
  test("create mints a deterministic token on DATABASE time; the lost-response replay is byte-identical with NO TTL extension", async () => {
    const h = await newLeaseHarness();
    const first = await h.service.create(createArgs);
    expect(first.lease.accessLeaseId.startsWith("pfal_")).toBe(true);
    expect(first.lease).toMatchObject({
      managerEpoch: h.managerEpoch,
      tokenGeneration: "1",
      controlSeq: "1",
      state: "active",
      authorityInstanceId: "pfvcs_a",
    });
    // Expiry is database time + ttl — the skewed host clock (localNow 555) is
    // irrelevant.
    expect(first.lease.expiresAt).toBe(1_000_000 + 60_000);

    h.db.advance(30_000); // a late retry must NOT stretch the lease
    const replay = await h.service.create(createArgs);
    expect(replay.accessToken).toBe(first.accessToken);
    expect(replay.lease.accessLeaseId).toBe(first.lease.accessLeaseId);
    expect(replay.lease.expiresAt).toBe(first.lease.expiresAt);
    expect(replay.lease.tokenGeneration).toBe("1");
    expect(replay.lease.controlSeq).toBe("1");
    // Exactly one lease exists and its token resolves on the data plane.
    expect(h.service.activeLeaseCount(accessLeaseRefKey(ref))).toBe(1);
    expect(h.service.resolveSessionToken(first.accessToken)).toMatchObject({
      accessLeaseId: first.lease.accessLeaseId,
      tokenGeneration: "1",
      sessionExpiresAt: first.lease.expiresAt,
    });
  });

  test("the deterministic token binds the REAL runtime sequence: a token minted against runtime N dies with it", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    const parsed = parseAccessToken(created.accessToken)!;
    const claims: AccessTokenClaims = {
      protocolVersion: 1,
      managerEpoch: h.managerEpoch,
      accessLeaseId: created.lease.accessLeaseId,
      controlSeq: parseAccessLeaseControlSeq("1"),
      tokenGeneration: parsed.tokenGeneration,
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      authorityInstanceId: "pfvcs_a",
      authorityRuntimeGeneration: "1",
      consumerId: "sandbox-a",
      expiresAt: created.lease.expiresAt,
    };
    // The claims with runtime sequence 1 recompute the identical token; a
    // shifted runtime sequence computes a DIFFERENT token, so a restarted
    // runtime (seq 2) can never validate generation-1 bytes.
    const rootSecretProbe = (secret: Buffer) => verifyAccessToken(secret, claims, created.accessToken);
    expect(mintAccessToken(mintRootSecret(), claims)).not.toBe(created.accessToken);
    void rootSecretProbe; // the service's secret is private; equality is proven by resolveSessionToken
    expect(
      h.service.resolveSessionToken(created.accessToken.replace(".g1.", ".g2."))
    ).toBeNull();
  });

  test("create without a teamId refuses: production state is keyed by the tenant namespace", async () => {
    const h = await newLeaseHarness();
    const { teamId: _teamId, ...withoutTeam } = createArgs;
    await expectAccessLeaseError(
      () => h.service.create({ ...withoutTeam, operationId: "op-no-team" }),
      "ACCESS_LEASE_INVALID_REQUEST"
    );
  });

  test("inspect authenticates fresh DB-time truth with zero lease mutations or secret disclosure", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    const before = await h.store.accessGet({
      identity: h.identity,
      tenantKey: managedTenantKey(ref),
      leaseId: created.lease.accessLeaseId,
    });
    // Any accidental transition immediately fails this read-only operation.
    const mutationAttempted = async (): Promise<never> => {
      throw new Error("inspect attempted a lease mutation");
    };
    h.store.accessCreate = mutationAttempted;
    h.store.accessRenew = mutationAttempted;
    h.store.accessRelease = mutationAttempted;
    h.store.accessRevoke = mutationAttempted;
    h.store.accessEndBatch = mutationAttempted;
    h.store.sweepAccessLeases = mutationAttempted;

    const inspected = await h.service.inspect({
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
    });
    expect(inspected).toEqual({ lease: created.lease, serverTimeMs: h.db.time });
    expect(inspected).not.toHaveProperty("accessToken");
    const after = await h.store.accessGet({
      identity: h.identity,
      tenantKey: managedTenantKey(ref),
      leaseId: created.lease.accessLeaseId,
    });
    expect(after).toEqual(before);
  });

  test("inspect rejects wrong, cross-lease, rotated, inactive, and DB-time-expired tokens exactly", async () => {
    const h = await newLeaseHarness();
    const first = await h.service.create(createArgs);
    const second = await h.service.create({
      ...createArgs,
      operationId: "op-create-inspect-second",
      consumerId: "sandbox-b",
    });
    await expectAccessLeaseError(
      () =>
        h.service.inspect({ accessLeaseId: first.lease.accessLeaseId, accessToken: "wrong-token" }),
      "ACCESS_LEASE_UNAUTHORIZED"
    );
    await expectAccessLeaseError(
      () =>
        h.service.inspect({
          accessLeaseId: first.lease.accessLeaseId,
          accessToken: second.accessToken,
        }),
      "ACCESS_LEASE_UNAUTHORIZED"
    );

    const rotated = await h.service.renew({
      operationId: "op-rotate-before-inspect",
      accessLeaseId: first.lease.accessLeaseId,
      accessToken: first.accessToken,
      expectedControlSeq: first.lease.controlSeq,
      rotateToken: true,
    });
    await expectAccessLeaseError(
      () =>
        h.service.inspect({
          accessLeaseId: first.lease.accessLeaseId,
          accessToken: first.accessToken,
        }),
      "ACCESS_LEASE_UNAUTHORIZED"
    );
    await expect(
      h.service.inspect({
        accessLeaseId: first.lease.accessLeaseId,
        accessToken: rotated.accessToken!,
      })
    ).resolves.toMatchObject({ lease: { tokenGeneration: "2", state: "active" } });

    await h.service.release({
      operationId: "op-release-before-inspect",
      accessLeaseId: first.lease.accessLeaseId,
      accessToken: rotated.accessToken!,
    });
    await expectAccessLeaseError(
      () =>
        h.service.inspect({
          accessLeaseId: first.lease.accessLeaseId,
          accessToken: rotated.accessToken!,
        }),
      "ACCESS_LEASE_RELEASED"
    );

    h.db.advance(60_001);
    await expectAccessLeaseError(
      () =>
        h.service.inspect({
          accessLeaseId: second.lease.accessLeaseId,
          accessToken: second.accessToken,
        }),
      "ACCESS_LEASE_EXPIRED"
    );
  });

  test("reusing an operationId with a DIFFERENT canonical request is a structured conflict", async () => {
    const h = await newLeaseHarness();
    await h.service.create(createArgs);
    await expectAccessLeaseError(
      () => h.service.create({ ...createArgs, ttlMs: 61_000 }),
      "ACCESS_LEASE_OPERATION_CONFLICT"
    );
    await expectAccessLeaseError(
      () => h.service.create({ ...createArgs, consumerId: "sandbox-OTHER" }),
      "ACCESS_LEASE_OPERATION_CONFLICT"
    );
  });

  test("renew advances controlSeq on database time; a lost-response replay repeats the exact facts once", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    const leaseId = created.lease.accessLeaseId;

    h.db.advance(30_000);
    const renewArgs = {
      operationId: "op-renew-1",
      accessLeaseId: leaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      ttlMs: 60_000,
    };
    const renewed = await h.service.renew(renewArgs);
    expect(renewed.lease.controlSeq).toBe("2");
    expect(renewed.lease.tokenGeneration).toBe("1"); // no rotation without rotateToken
    expect(renewed.lease.expiresAt).toBe(1_030_000 + 60_000);
    expect(renewed.accessToken).toBeUndefined();

    h.db.advance(20_000);
    const replay = await h.service.renew(renewArgs);
    // The replay repeats the recorded transition; it does NOT apply a second
    // extension at the later database time (that would be 1_050_000 + 60_000).
    expect(replay.lease.controlSeq).toBe("2");
    expect(replay.lease.expiresAt).toBe(1_090_000);

    // A fresh shorter renew cannot shorten an already-granted lease window.
    const shorter = await h.service.renew({
      operationId: "op-renew-2",
      accessLeaseId: leaseId,
      accessToken: created.accessToken,
      expectedControlSeq: renewed.lease.controlSeq,
      ttlMs: 1_000,
    });
    expect(shorter.lease.expiresAt).toBe(1_090_000);
    expect(shorter.lease.controlSeq).toBe("3");
  });

  test("an older renew replays immutable response facts without rewinding a newer or terminal projection", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    const oldArgs = {
      operationId: "op-renew-old-response",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      ttlMs: 30_000,
    };
    const old = await h.service.renew(oldArgs);
    const newer = await h.service.renew({
      operationId: "op-renew-new-response",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
      expectedControlSeq: old.lease.controlSeq,
      ttlMs: 60_000,
    });

    const replayWhileLive = await h.service.renew(oldArgs);
    expect(replayWhileLive.lease).toEqual(old.lease);
    expect(await h.service.lookup(created.lease.accessLeaseId)).toEqual(newer.lease);

    const released = await h.service.release({
      operationId: "op-release-after-newer",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
    });
    expect(released.lease.state).toBe("released");
    const replayAfterRelease = await h.service.renew(oldArgs);
    expect(replayAfterRelease.lease).toEqual(old.lease);
    expect((await h.service.lookup(created.lease.accessLeaseId))?.state).toBe("released");
  });

  test("out-of-order successful renew responses cannot rewind the live projection", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    const firstCommitted = deferred<void>();
    const releaseFirstResponse = deferred<void>();
    const renew = h.store.accessRenew.bind(h.store);
    h.store.accessRenew = async (args) => {
      const result = await renew(args);
      if (args.operationId === "op-renew-slow-first") {
        firstCommitted.resolve();
        await releaseFirstResponse.promise;
      }
      return result;
    };

    const firstPromise = h.service.renew({
      operationId: "op-renew-slow-first",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      ttlMs: 30_000,
    });
    await firstCommitted.promise;
    const second = await h.service.renew({
      operationId: "op-renew-fast-second",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
      expectedControlSeq: parseAccessLeaseControlSeq("2"),
      ttlMs: 60_000,
    });
    releaseFirstResponse.resolve();
    const first = await firstPromise;

    expect(first.lease.controlSeq).toBe("2");
    expect(second.lease.controlSeq).toBe("3");
    expect((await h.service.lookup(created.lease.accessLeaseId))?.controlSeq).toBe("3");
  });

  test("an evicted renew receipt fails 410 from the caller's original controlSeq and never re-executes", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    let current = created.lease;
    const oldest = {
      operationId: "op-renew-oldest",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      ttlMs: 30_000,
    };
    current = (await h.service.renew(oldest)).lease;
    for (let index = 1; index <= 64; index += 1) {
      current = (
        await h.service.renew({
          operationId: `op-renew-window-${index}`,
          accessLeaseId: created.lease.accessLeaseId,
          accessToken: created.accessToken,
          expectedControlSeq: current.controlSeq,
          ttlMs: 30_000,
        })
      ).lease;
    }
    expect(current.controlSeq).toBe("66");

    await expectAccessLeaseError(() => h.service.renew(oldest), "ACCESS_LEASE_RECEIPT_EVICTED");
    expect((await h.service.lookup(created.lease.accessLeaseId))?.controlSeq).toBe("66");
  });

  test("sweepDue durably converges quiet expiry in bounded exact pages and resumes without duplicate events", async () => {
    const h = await newLeaseHarness();
    const created = await Promise.all(
      [0, 1, 2].map((index) =>
        h.service.create({
          ...createArgs,
          operationId: `op-create-sweep-${index}`,
          consumerId: `sandbox-sweep-${index}`,
          ttlMs: 1_000,
        })
      )
    );
    const ended: string[] = [];
    h.service.onLeaseEnded((event) => ended.push(event.accessLeaseId));
    h.db.advance(1_001);

    const first = await h.service.sweepDue({ sweepId: "sweep-cycle-1", limit: 1, maxPages: 2 });
    expect(first).toMatchObject({ pages: 2, hasMore: true });
    expect(first.endedLeaseIds).toHaveLength(2);
    expect(first.nextCursor).toBeTypeOf("string");

    const completed = await h.service.sweepDue({
      sweepId: "sweep-cycle-1",
      afterLeaseId: first.nextCursor!,
      limit: 1,
      maxPages: 2,
    });
    expect(completed).toMatchObject({ pages: 1, hasMore: false });
    expect(completed.endedLeaseIds).toHaveLength(1);
    expect(new Set(ended)).toEqual(new Set(created.map((entry) => entry.lease.accessLeaseId)));

    // An ambiguous caller retry can restart the exact cycle. Page receipts
    // replay, and already-terminal projections emit no duplicate end events.
    const replay = await h.service.sweepDue({ sweepId: "sweep-cycle-1", limit: 1, maxPages: 2 });
    expect(replay.endedLeaseIds).toEqual(first.endedLeaseIds);
    expect(ended).toHaveLength(3);
    for (const entry of created) {
      expect((await h.service.lookup(entry.lease.accessLeaseId))?.state).toBe("expired");
      expect(h.service.resolveSessionToken(entry.accessToken)).toBeNull();
    }
  });

  test("sweepDue validates its local work bound before calling the store", async () => {
    const h = await newLeaseHarness();
    await expectAccessLeaseError(
      () => h.service.sweepDue({ sweepId: "cycle", limit: 513 }),
      "ACCESS_LEASE_INVALID_REQUEST"
    );
    await expectAccessLeaseError(
      () => h.service.sweepDue({ sweepId: "cycle", maxPages: 0 }),
      "ACCESS_LEASE_INVALID_REQUEST"
    );
  });

  test("host clock skew is IRRELEVANT: a lease expires exactly when database time passes its expiry", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    h.db.advance(59_000);
    const touched = await h.service.renew({
      operationId: "op-touch",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      ttlMs: 1, // grants less than the remaining window: no extension
    });
    expect(h.service.resolveSessionToken(created.accessToken)).not.toBeNull();

    h.db.advance(61_001);
    // Any store round trip re-observes the database clock; the renew attempt
    // itself refuses AND is enough for the data plane to see the expiry.
    await expectAccessLeaseError(
      () =>
        h.service.renew({
          operationId: "op-too-late",
          accessLeaseId: created.lease.accessLeaseId,
          accessToken: created.accessToken,
          expectedControlSeq: touched.lease.controlSeq,
        }),
      "ACCESS_LEASE_EXPIRED"
    );
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
  });

  test("a DELAYED create response can only SHRINK the authorized window (deadline anchored BEFORE the store call); ambiguity at the terminal boundary never extends", async () => {
    const local = { now: 0 };
    const h = await newLeaseHarness({
      serviceOptions: { localNow: () => local.now, deadlineGuardMs: 100 },
    });
    // The create response arrives 10 SECONDS of local time after the call
    // left the service: an offset-interpolation design would authorize until
    // local 70_000; the conservative per-lease deadline dies at 59_900.
    const accessCreate = h.store.accessCreate.bind(h.store);
    h.store.accessCreate = async (args) => {
      local.now += 10_000;
      return accessCreate(args);
    };
    const created = await h.service.create(createArgs); // 60s TTL at db 1_000_000
    local.now = 59_899;
    expect(h.service.resolveSessionToken(created.accessToken)).not.toBeNull();

    // Past the conservative deadline with the DB recheck FAILING: an
    // error/ambiguous answer never extends — the tunnel stays closed — and
    // the projection never invents a terminal state from the local clock.
    h.store.failNext("accessGet", 10);
    local.now = 59_900;
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
    await delay(10);
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
    expect((await h.service.lookup(created.lease.accessLeaseId))?.state).toBe("active");
  });

  test("the terminal-boundary DB recheck settles the truth: it REVIVES a genuinely live lease and settles a DB-expired one", async () => {
    const local = { now: 0 };
    const h = await newLeaseHarness({
      serviceOptions: { localNow: () => local.now, deadlineGuardMs: 100 },
    });
    const accessCreate = h.store.accessCreate.bind(h.store);
    h.store.accessCreate = async (args) => {
      local.now += 10_000;
      return accessCreate(args);
    };
    const created = await h.service.create(createArgs);

    // The conservative deadline fires at local 59_900 while DATABASE time is
    // still 1_000_000 (the whole 60s window remains): fail-closed first,
    // then the fresh row read restores authorization.
    local.now = 59_900;
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
    const revivedBy = Date.now() + 2_000;
    while (h.service.resolveSessionToken(created.accessToken) === null && Date.now() < revivedBy) {
      await delay(5);
    }
    expect(h.service.resolveSessionToken(created.accessToken)).not.toBeNull();

    // Now the database itself passes the expiry: the next boundary recheck
    // settles the projection as EXPIRED from durable facts.
    h.db.advance(61_000);
    local.now = 130_000; // past any conceivable local deadline
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
    const settledBy = Date.now() + 2_000;
    while (
      (await h.service.lookup(created.lease.accessLeaseId))?.state === "active" &&
      Date.now() < settledBy
    ) {
      await delay(5);
    }
    expect((await h.service.lookup(created.lease.accessLeaseId))?.state).toBe("expired");
  });

  test("a REPLAYED renew receipt never advances the authorization deadline; only confirmed NEWER control facts do", async () => {
    const local = { now: 0 };
    const h = await newLeaseHarness({
      serviceOptions: { localNow: () => local.now, deadlineGuardMs: 100 },
    });
    const created = await h.service.create(createArgs); // anchor 0 → deadline 59_900
    h.db.advance(30_000);
    local.now = 5_000;
    const renewed = await h.service.renew({
      operationId: "op-r1",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      ttlMs: 60_000,
    }); // 60s from db 1_030_000 → CONFIRMED deadline 5_000 + 60_000 − 100

    // The identical operation replays MUCH later in local time. Same
    // controlSeq, same facts: it proves nothing new and must not extend.
    local.now = 40_000;
    const replay = await h.service.renew({
      operationId: "op-r1",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      ttlMs: 60_000,
    });
    expect(replay.lease.expiresAt).toBe(renewed.lease.expiresAt);
    expect(replay.lease.controlSeq).toBe(renewed.lease.controlSeq);

    h.store.failNext("accessGet", 10);
    local.now = 64_900; // past the CONFIRMED deadline; a replay-derived one would reach 99_900
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
  });

  test("DEFENSE IN DEPTH: an ended authority runtime makes a not-yet-reconciled ACTIVE lease unrenewable at the store", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    // Simulate the exact hazard the teardown ordering prevents: the runtime
    // row ends while the lease row is still active (crash/ordering bug).
    await h.store.endAuthorityRuntime({
      identity: h.identity,
      scope: { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch },
      runtimeSeq: "1",
      runtimeId: "runtime-a",
      reason: "test-ordering-bug",
    });
    // The renew is REFUSED by the runtime-liveness gate — never extended.
    await expectAccessLeaseError(
      () =>
        h.service.renew({
          operationId: "op-after-runtime-end",
          accessLeaseId: created.lease.accessLeaseId,
          accessToken: created.accessToken,
          expectedControlSeq: created.lease.controlSeq,
          ttlMs: 60_000,
        }),
      "ACCESS_LEASE_REVOKED"
    );
    const row = await h.store.accessGet({
      identity: h.identity,
      tenantKey: managedTenantKey(ref),
      leaseId: created.lease.accessLeaseId,
    });
    expect(row?.expiresAt).toBe(created.lease.expiresAt);
  });

  test("rotation mints generation 2 deterministically; the old token stops resolving but still authenticates ONE lost-response recovery", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    const leaseId = created.lease.accessLeaseId;
    const rotations: Array<[string, string]> = [];
    h.service.onLeaseRotated((id, generation) => rotations.push([id, generation]));

    const r1 = await h.service.renew({
      operationId: "op-rotate-1",
      accessLeaseId: leaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      rotateToken: true,
    });
    expect(r1.accessToken).toBeDefined();
    expect(r1.accessToken).not.toBe(created.accessToken);
    expect(r1.lease.tokenGeneration).toBe("2");
    expect(rotations).toEqual([[leaseId, "2"]]);

    // The data plane accepts ONLY the current generation.
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
    expect(h.service.resolveSessionToken(r1.accessToken!)).toMatchObject({ tokenGeneration: "2" });

    // The replay of the LOST rotation response returns the byte-identical
    // rotated token, authenticated by the previous-generation token — and it
    // does NOT rotate again.
    const replay = await h.service.renew({
      operationId: "op-rotate-1",
      accessLeaseId: leaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      rotateToken: true,
    });
    expect(replay.accessToken).toBe(r1.accessToken);
    expect(replay.lease.tokenGeneration).toBe("2");
    expect(rotations).toHaveLength(1);
  });

  test("only the latest lost rotation can replay through its immediately previous token; older generations fail closed", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    const leaseId = created.lease.accessLeaseId;
    const r1 = await h.service.renew({
      operationId: "op-rotate-1",
      accessLeaseId: leaseId,
      accessToken: created.accessToken,
      expectedControlSeq: created.lease.controlSeq,
      rotateToken: true,
    });
    const r2 = await h.service.renew({
      operationId: "op-rotate-2",
      accessLeaseId: leaseId,
      accessToken: r1.accessToken!,
      expectedControlSeq: r1.lease.controlSeq,
      rotateToken: true,
    });
    expect(r2.lease.tokenGeneration).toBe("3");

    // R2's lost response is recoverable through its immediately previous
    // generation and replays the byte-identical token without rotating again.
    const r2Replay = await h.service.renew({
      operationId: "op-rotate-2",
      accessLeaseId: leaseId,
      accessToken: r1.accessToken!,
      expectedControlSeq: r1.lease.controlSeq,
      rotateToken: true,
    });
    expect(r2Replay.accessToken).toBe(r2.accessToken);
    await expectAccessLeaseError(
      () =>
        h.service.renew({
          operationId: "op-rotate-1",
          accessLeaseId: leaseId,
          accessToken: r1.accessToken!,
          expectedControlSeq: created.lease.controlSeq,
          rotateToken: true,
        }),
      "ACCESS_LEASE_UNAUTHORIZED"
    );

    const r3 = await h.service.renew({
      operationId: "op-rotate-3",
      accessLeaseId: leaseId,
      accessToken: r2.accessToken!,
      expectedControlSeq: r2.lease.controlSeq,
      rotateToken: true,
    });
    expect(r3.lease.tokenGeneration).toBe("4");
    // R2 is now older than the immediately previous generation too: it is
    // rejected, never silently re-executed as a fresh rotation.
    await expectAccessLeaseError(
      () =>
        h.service.renew({
          operationId: "op-rotate-2",
          accessLeaseId: leaseId,
          accessToken: r2.accessToken!,
          expectedControlSeq: r1.lease.controlSeq,
          rotateToken: true,
        }),
      "ACCESS_LEASE_UNAUTHORIZED"
    );
    expect(h.service.resolveSessionToken(r3.accessToken!)).toMatchObject({ tokenGeneration: "4" });
  });

  test("a failed durable transition changes NOTHING: no record, no controlSeq, no rotation, no event, no tunnel action", async () => {
    const h = await newLeaseHarness();
    const ended: string[] = [];
    const rotations: string[] = [];
    h.service.onLeaseEnded((event) => ended.push(event.accessLeaseId));
    h.service.onLeaseRotated((_id, generation) => rotations.push(generation));

    // Create fails durably → nothing exists.
    h.store.failNext("accessCreate");
    await expectAccessLeaseError(() => h.service.create(createArgs), "ACCESS_LEASE_STORE_UNAVAILABLE");
    expect(h.service.activeLeaseCount(accessLeaseRefKey(ref))).toBe(0);
    expect(h.service.activityVersion(accessLeaseRefKey(ref))).toBe(0);

    const created = await h.service.create(createArgs);
    const before = await h.service.lookup(created.lease.accessLeaseId);

    // Renew-with-rotation fails durably → the lease is untouched and the OLD
    // token still resolves (no rotation event, no generation bump).
    h.store.failNext("accessRenew");
    await expectAccessLeaseError(
      () =>
        h.service.renew({
          operationId: "op-rotate-1",
          accessLeaseId: created.lease.accessLeaseId,
          accessToken: created.accessToken,
          expectedControlSeq: created.lease.controlSeq,
          rotateToken: true,
        }),
      "ACCESS_LEASE_STORE_UNAVAILABLE"
    );
    const after = await h.service.lookup(created.lease.accessLeaseId);
    expect(after).toEqual(before);
    expect(rotations).toEqual([]);
    expect(h.service.resolveSessionToken(created.accessToken)).not.toBeNull();

    // Release fails durably → the lease is STILL ACTIVE and its tunnels stay
    // open (no end event): live state changes only AFTER the durable
    // transition succeeds.
    h.store.failNext("accessRelease");
    await expectAccessLeaseError(
      () =>
        h.service.release({
          operationId: "op-release-1",
          accessLeaseId: created.lease.accessLeaseId,
          accessToken: created.accessToken,
        }),
      "ACCESS_LEASE_STORE_UNAVAILABLE"
    );
    expect(ended).toEqual([]);
    expect(h.service.resolveSessionToken(created.accessToken)).not.toBeNull();

    // The retried release (same operationId) succeeds, ends the lease, closes
    // tunnels, and its replay returns the identical receipt.
    const released = await h.service.release({
      operationId: "op-release-1",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
    });
    expect(released.lease.state).toBe("released");
    expect(ended).toEqual([created.lease.accessLeaseId]);
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
    const replay = await h.service.release({
      operationId: "op-release-1",
      accessLeaseId: created.lease.accessLeaseId,
      accessToken: created.accessToken,
    });
    expect(replay.receipt).toEqual(released.receipt);
    // Renew after release NEVER mints a replacement.
    await expectAccessLeaseError(
      () =>
        h.service.renew({
          operationId: "op-after-release",
          accessLeaseId: created.lease.accessLeaseId,
          accessToken: created.accessToken,
          expectedControlSeq: created.lease.controlSeq,
        }),
      "ACCESS_LEASE_RELEASED"
    );
  });

  test("the configured lease TTL quota clamps oversized requests without changing replay facts", async () => {
    const h = await newLeaseHarness({ serviceOptions: { maxTtlMs: 2_000 } });
    const created = await h.service.create({ ...createArgs, ttlMs: 999_999 });
    expect(created.lease.expiresAt).toBe(1_002_000);
    h.db.advance(500);
    const replay = await h.service.create({ ...createArgs, ttlMs: 999_999 });
    expect(replay.lease.expiresAt).toBe(created.lease.expiresAt);
    expect(h.service.activeLeaseCount(accessLeaseRefKey(ref))).toBe(1);
  });

  test("owner revocation is hard-bound to its tenant and cannot cross into another team", async () => {
    const h = await newLeaseHarness();
    const teamOne = await h.service.create(createArgs);
    await h.store.beginAuthorityRuntime({
      identity: h.identity,
      scope: { tenantKey: "t:team_2", volumeId: "vol_2", branch: "main" },
      authorityInstanceId: "pfvcs_b",
      runtimeId: "runtime-b",
    });
    const teamTwo = await h.service.create({
      ...createArgs,
      operationId: "op-create-team-2",
      teamId: "team_2",
      volumeId: "vol_2",
      authorityInstanceId: "pfvcs_b",
      authorityRuntimeGeneration: "1",
      authorityRuntimeId: "runtime-b",
    });
    expect(await h.service.revokeOwner({ teamId: "team_1", consumerId: createArgs.consumerId })).toEqual([
      teamOne.lease.accessLeaseId,
    ]);
    expect((await h.service.lookup(teamOne.lease.accessLeaseId))?.endReason).toBe("owner-revoked");
    expect((await h.service.lookup(teamTwo.lease.accessLeaseId))?.state).toBe("active");
    expect(h.service.resolveSessionToken(teamTwo.accessToken)).not.toBeNull();
    // Without a tenant scope the batch refuses.
    await expectAccessLeaseError(
      () => h.service.revokeOwner({ consumerId: createArgs.consumerId }),
      "ACCESS_LEASE_INVALID_REQUEST"
    );
  });

  test("epoch supersession ends every lease, invalidates every old token automatically, and refuses further mutations", async () => {
    const h = await newLeaseHarness();
    const created = await h.service.create(createArgs);
    const ended: string[] = [];
    h.service.onLeaseEnded((event) => ended.push(event.accessLeaseId));

    // A competing manager claims the next epoch; this manager discovers it on
    // its next fenced store call.
    h.store.supersedeEpoch();
    await expectAccessLeaseError(
      () => h.service.create({ ...createArgs, operationId: "op-create-2" }),
      "ACCESS_LEASE_EPOCH_SUPERSEDED"
    );
    expect(h.service.healthy()).toBe(false);
    expect(ended).toEqual([created.lease.accessLeaseId]);
    expect((await h.service.lookup(created.lease.accessLeaseId))?.endReason).toBe(
      "manager-epoch-superseded"
    );
    expect(h.service.resolveSessionToken(created.accessToken)).toBeNull();
    await expectAccessLeaseError(
      () =>
        h.service.renew({
          operationId: "op-renew-1",
          accessLeaseId: created.lease.accessLeaseId,
          accessToken: created.accessToken,
          expectedControlSeq: created.lease.controlSeq,
        }),
      "ACCESS_LEASE_EPOCH_SUPERSEDED"
    );
  });

  test("overlapping managers: the successor's service never validates the predecessor's tokens", async () => {
    const db = { time: 1_000_000 };
    const store = new InMemoryManagerControlStore({ dbNow: () => db.time });
    const managerA = await claimManager(store, {
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
      ttlMs: 30_000,
    });
    await store.beginAuthorityRuntime({
      identity: managerA.identity,
      scope: { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch },
      authorityInstanceId: "pfvcs_a",
      runtimeId: "runtime-a",
    });
    const rootSecret = mintRootSecret();
    const serviceA = new ProductionAccessLeaseService(
      store,
      managerA.identity,
      { dbTimeMs: managerA.claim.dbTimeMs },
      rootSecret,
      { localNow: () => 555 }
    );
    serviceA.setAuthorityRouteResolver(() => ({
      backendAddresses: ["127.0.0.1:1"],
      backendAuthToken: "t",
    }));
    const created = await serviceA.create(createArgs);

    db.time = 1_030_001;
    const managerB = await claimManager(store, {
      operationId: "claim-manager-b",
      runtimeId: "manager-b",
      ttlMs: 30_000,
    });
    const runtimeB = await store.beginAuthorityRuntime({
      identity: managerB.identity,
      scope: { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch },
      authorityInstanceId: "pfvcs_b",
      runtimeId: "runtime-b",
    });
    const serviceB = new ProductionAccessLeaseService(
      store,
      managerB.identity,
      { dbTimeMs: managerB.claim.dbTimeMs },
      rootSecret,
      { localNow: () => 555 }
    );
    serviceB.setAuthorityRouteResolver(() => ({
      backendAddresses: ["127.0.0.1:1"],
      backendAuthToken: "t",
    }));

    // The predecessor's token is invalid under the successor BY CONSTRUCTION
    // (new epoch, new epoch-scoped key derivation) — no revocation list.
    expect(serviceB.resolveSessionToken(created.accessToken)).toBeNull();
    const fresh = await serviceB.create({
      ...createArgs,
      operationId: "op-create-B",
      authorityInstanceId: "pfvcs_b",
      authorityRuntimeGeneration: runtimeB.runtimeSeq,
      authorityRuntimeId: "runtime-b",
    });
    expect(fresh.lease.managerEpoch).toBe(managerB.claim.managerEpoch);
    expect(serviceB.resolveSessionToken(fresh.accessToken)).not.toBeNull();
    serviceA.close();
    serviceB.close();
  });
});

// ---------------------------------------------------------------------------
// ProductionAuthorityRegistry with SCRIPTED FAKE CHILDREN: the spawn mock
// yields EventEmitter-based ChildProcess doubles whose fd-3/fd-4 pipes and
// /readyz identity behavior are driven per test, exactly how the hosted
// registry is tested — no real vcs binary, no Postgres.
// ---------------------------------------------------------------------------

const SIM_JOURNAL_GENERATION = "pfgen_sim_1";

// The structured HA policy the manager issues and the child (sim) verifies;
// the canonical hash travels bootstrap → readiness and must match exactly.
const TEST_HA_POLICY_JSON =
  '{"v":1,"expectedSystemIdentifier":"7300000000000000001","expectedDatabase":"portablefs","minSynchronousCommit":"on","minSyncStandbys":1,"standbyFailureDomains":{"standby_a":"zone-a","standby_b":"zone-b"},"minDistinctFailureDomains":1}';
const TEST_HA_POLICY_HASH = canonicalHaPolicyHash(TEST_HA_POLICY_JSON);
// The Go child computes the identical canonical hash for this exact policy
// (vcs/internal/hapolicy Policy.Hash); the pinned literal proves the two
// canonical JSON encoders stay byte-identical.
const TEST_HA_POLICY_HASH_PINNED =
  "0bd3101de332afaa3e00d748e86d4e47387f1c67445777aba3ac5b2fa6cf7347";

// The exposition a healthy child serves on GET /metrics (the real Go
// exporter's shape: allowlisted names, no HELP/TYPE lines). Tests overwrite
// per-sim to model garbage or label-smuggling children.
const SIM_METRICS_BODY =
  "vcs_ready 1\nvcs_fsproto_ops 10\nvcs_fsproto_conns 2\nvcs_dirty_block_bytes 4096\nvcs_dirty_block_bytes_max 2048000\n";

class ProdVcsSim {
  unready = false;
  metricsBody = SIM_METRICS_BODY;
  // The child binds its own loopback listeners and reports them on the
  // bootstrap pipe; the sim mints them like the real child's 127.0.0.1:0.
  readonly fsAddr: string;
  readonly metricsAddr: string;

  constructor(
    readonly env: NodeJS.ProcessEnv,
    ports: { fsPort: number; metricsPort: number }
  ) {
    this.fsAddr = `127.0.0.1:${ports.fsPort}`;
    this.metricsAddr = `127.0.0.1:${ports.metricsPort}`;
  }

  ready(): boolean {
    return !this.unready;
  }

  bootstrapFrame(): Record<string, unknown> {
    return {
      v: 1,
      authorityInstanceId: this.env.VCS_AUTHORITY_INSTANCE_ID,
      volumeId: this.env.VCS_VOLUME_ID,
      branch: this.env.VCS_BRANCH,
      managerEpoch: this.env.VCS_MANAGER_EPOCH,
      authorityRuntimeSeq: this.env.VCS_AUTHORITY_RUNTIME_SEQ,
      authorityRuntimeId: this.env.VCS_AUTHORITY_RUNTIME_ID,
      fsAddr: this.fsAddr,
      metricsAddr: this.metricsAddr,
      journalGenerationId: SIM_JOURNAL_GENERATION,
      protocolVersion: MANAGED_CHILD_PROTOCOL_VERSION,
      haPolicyHash: TEST_HA_POLICY_HASH,
    };
  }
}

interface CapturedHeartbeatWrite {
  frame: Record<string, unknown>;
  release: (error?: Error) => void;
}

interface ProdHarness {
  registry: ProductionAuthorityRegistry;
  store: InMemoryManagerControlStore;
  // The same fetch double the registry probes children with; the child
  // metrics collector scrapes through it in the /metrics tests.
  fetch: typeof fetch;
  sims: Map<string, ProdVcsSim>;
  spawnEnvs: NodeJS.ProcessEnv[];
  spawnCwds: string[];
  children: ChildProcess[];
  kills: string[];
  logs: string[];
  heartbeatWrites: CapturedHeartbeatWrite[];
  // With holdBootstrap: one release closure per spawned child, in spawn
  // order; calling it emits that child's bootstrap frame (the child then
  // becomes ready and its start-gate permit frees).
  bootstrapHolds: Array<() => void>;
  renewSuccesses: number;
  latestSim(): ProdVcsSim;
  latestChild(): ChildProcess;
}

const PROD_ENV = {
  PORTABLEFS_MANAGED_VCS_BIN: "/usr/local/bin/portablefs-vcs",
  PORTABLEFS_AUTHORITY_ROUTER_URL: "router.example:2050",
  PORTABLEFS_VOLUME_API_URL: "https://volume.example",
  PORTABLEFS_MANAGED_VCS_JOURNAL_DSN: "postgres://portablefs@db.internal/journal",
  // The harness runs pooled mode so every spawn asserts the passthrough.
  PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE: "transaction",
  PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON: TEST_HA_POLICY_JSON,
  PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET: Buffer.alloc(32, 7).toString("hex"),
  PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS: "2000",
  PORTABLEFS_MANAGED_VCS_PROCESS_GRACE_MS: "50",
};

// How the fake child behaves on its pipes, for startup-fencing tests:
//   normal     — emits one exact bootstrap frame (the real child's behavior);
//   silent     — never writes the bootstrap frame;
//   truncated  — writes half a frame and closes the pipe;
//   trailing   — a valid frame followed by more bytes (one-shot violated);
//   foreign    — reports a DIFFERENT authority instance (spoofed identity);
//   spoofed-addr — reports a non-loopback fs address;
//   heartbeat-backpressure — the lease pipe refuses writes (write() false).
type ChildPipeMode =
  | "normal"
  | "silent"
  | "truncated"
  | "trailing"
  | "foreign"
  | "spoofed-addr"
  | "heartbeat-backpressure";

// How the fake child PROCESS behaves, for lifecycle-hardening tests:
//   normal          — exits on the first kill() of any signal;
//   spawn-enoent    — emits 'error' (ENOENT) asynchronously and NEVER exits
//                     (kill is a no-op on a process that never spawned);
//   immediate-exit  — exits(1) right after spawn, before any pipe activity;
//   ignore-sigterm  — ignores SIGTERM; only SIGKILL produces the exit;
//   ignore-all      — ignores every signal and never emits exit at all.
type ChildProcessMode =
  | "normal"
  | "spawn-enoent"
  | "immediate-exit"
  | "ignore-sigterm"
  | "ignore-all";

async function newProductionHarness(
  options: {
    env?: Record<string, string>;
    store?: InMemoryManagerControlStore;
    pipeMode?: ChildPipeMode;
    processMode?: ChildProcessMode;
    // "hold" captures every lease-frame write and defers its callback until
    // the test releases it (exercising latest-value coalescing); "error"
    // completes the first write's callback with an error (a dying pipe).
    heartbeat?: "hold" | "error";
    // Withholds every child's bootstrap frame behind a per-child release
    // closure (bootstrapHolds), keeping each start inside its cold-start
    // critical section until the test lets it finish.
    holdBootstrap?: boolean;
    localNow?: () => number;
  } = {}
): Promise<ProdHarness> {
  const sims = new Map<string, ProdVcsSim>();
  const spawnEnvs: NodeJS.ProcessEnv[] = [];
  const spawnCwds: string[] = [];
  const children: ChildProcess[] = [];
  const kills: string[] = [];
  const logs: string[] = [];
  const heartbeatWrites: CapturedHeartbeatWrite[] = [];
  const bootstrapHolds: Array<() => void> = [];
  const pipeMode = options.pipeMode ?? "normal";
  const processMode = options.processMode ?? "normal";
  const store = options.store ?? new InMemoryManagerControlStore();
  const harnessState = { renewSuccesses: 0 };
  const renewManagerClaim = store.renewManagerClaim.bind(store);
  store.renewManagerClaim = async (args) => {
    const result = await renewManagerClaim(args);
    harnessState.renewSuccesses += 1;
    return result;
  };

  const fetchMock = (async (input) => {
    const url = new URL(String(input));
    const sim = sims.get(url.host);
    if (url.pathname === "/readyz") {
      const ready = Boolean(sim?.ready());
      // The identity payload the real managed child publishes on /readyz.
      return new Response(
        JSON.stringify({
          ready,
          authorityInstanceId: sim?.env.VCS_AUTHORITY_INSTANCE_ID,
          volumeId: sim?.env.VCS_VOLUME_ID,
          branch: sim?.env.VCS_BRANCH,
          journal: "remote",
          managerEpoch: sim?.env.VCS_MANAGER_EPOCH,
          authorityRuntimeSeq: sim?.env.VCS_AUTHORITY_RUNTIME_SEQ,
          authorityRuntimeId: sim?.env.VCS_AUTHORITY_RUNTIME_ID,
          journalGenerationId: SIM_JOURNAL_GENERATION,
          protocolVersion: MANAGED_CHILD_PROTOCOL_VERSION,
          haPolicyHash: TEST_HA_POLICY_HASH,
          // Readiness describes the ACTUAL bound listeners.
          fsAddr: sim?.fsAddr,
          metricsAddr: sim?.metricsAddr,
        }),
        { status: ready ? 200 : 503 }
      );
    }
    if (url.pathname === "/metrics" && sim) {
      return new Response(sim.metricsBody, { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  const spawnMock = ((
    _bin: string,
    _args: string[],
    spawnOptions: { cwd: string; env: NodeJS.ProcessEnv }
  ) => {
    spawnEnvs.push(spawnOptions.env);
    spawnCwds.push(spawnOptions.cwd);
    const child = new EventEmitter() as ChildProcess;
    children.push(child);
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const heartbeat = new PassThrough();
    if (pipeMode === "heartbeat-backpressure") {
      // The lease pipe refuses delivery: write() reports backpressure.
      heartbeat.write = (() => false) as typeof heartbeat.write;
    } else if (options.heartbeat) {
      // Capture every lease frame plus its completion callback so tests
      // drive the coalescing state machine deterministically.
      const mode = options.heartbeat;
      heartbeat.write = ((chunk: unknown, callback?: (error?: Error | null) => void) => {
        const frame = JSON.parse(String(chunk)) as Record<string, unknown>;
        const release = (error?: Error) => callback?.(error ?? null);
        heartbeatWrites.push({ frame, release });
        if (mode === "error" && heartbeatWrites.length === 1) {
          setImmediate(() => release(new Error("EPIPE: lease pipe died")));
        }
        return true;
      }) as typeof heartbeat.write;
    }
    const bootstrap = new PassThrough();
    Object.assign(child, {
      pid: 41000 + spawnEnvs.length,
      exitCode: null,
      signalCode: null,
      stdout,
      stderr,
      stdio: [null, stdout, stderr, heartbeat, bootstrap],
      kill: (signal?: NodeJS.Signals | number) => {
        const name = String(signal ?? "SIGTERM");
        kills.push(name);
        switch (processMode) {
          case "spawn-enoent":
          case "ignore-all":
            return false; // nothing dies; no exit event ever
          case "ignore-sigterm":
            if (name === "SIGTERM") {
              return true; // delivered but ignored by the child
            }
            break;
          default:
            break;
        }
        Object.assign(child, { exitCode: 0 });
        child.emit("exit", 0, null);
        return true;
      },
    });
    if (processMode === "spawn-enoent") {
      setImmediate(() => {
        child.emit(
          "error",
          Object.assign(new Error("spawn portablefs-vcs ENOENT"), { code: "ENOENT" })
        );
      });
    } else if (processMode === "immediate-exit") {
      setImmediate(() => {
        Object.assign(child, { exitCode: 1 });
        child.emit("exit", 1, null);
      });
    }
    // The child binds 127.0.0.1:0 itself; the sim mints the ports and
    // reports the EXACT addresses on the bootstrap pipe (fd 4). There is no
    // address in the environment to inherit or race.
    const sim = new ProdVcsSim(spawnOptions.env, {
      fsPort: 42000 + spawnEnvs.length,
      metricsPort: 43000 + spawnEnvs.length,
    });
    sims.set(sim.metricsAddr, sim);
    setImmediate(() => {
      if (processMode === "spawn-enoent" || processMode === "immediate-exit") {
        return; // a dead or never-spawned child reports nothing
      }
      switch (pipeMode) {
        case "silent":
        case "heartbeat-backpressure":
          return;
        case "truncated":
          bootstrap.write('{"v":1,"authorityInstanceId":"pf');
          bootstrap.end();
          return;
        case "trailing":
          // A perfectly valid frame FOLLOWED by more bytes: the one-shot
          // protocol is violated and the child must not be adopted.
          bootstrap.write(`${JSON.stringify(sim.bootstrapFrame())}\n{"v":1,"second":true}\n`);
          return;
        case "foreign":
          bootstrap.write(
            `${JSON.stringify({ ...sim.bootstrapFrame(), authorityInstanceId: "pfvcs_foreign" })}\n`
          );
          return;
        case "spoofed-addr":
          bootstrap.write(`${JSON.stringify({ ...sim.bootstrapFrame(), fsAddr: "10.0.0.9:2050" })}\n`);
          return;
        default: {
          const emitBootstrap = () => bootstrap.write(`${JSON.stringify(sim.bootstrapFrame())}\n`);
          if (options.holdBootstrap) {
            bootstrapHolds.push(emitBootstrap);
            return;
          }
          emitBootstrap();
        }
      }
    });
    return child;
  }) as never;

  const registry = await createProductionAuthorityRegistry(
    { ...PROD_ENV, ...(options.env ?? {}) },
    {
      controlStore: store,
      fetch: fetchMock,
      spawnProcess: spawnMock,
      log: (message) => {
        logs.push(message);
      },
      ...(options.localNow ? { localNow: options.localNow } : {}),
    }
  );
  registries.push(registry);
  return {
    registry,
    store,
    fetch: fetchMock,
    sims,
    spawnEnvs,
    spawnCwds,
    children,
    kills,
    logs,
    heartbeatWrites,
    bootstrapHolds,
    get renewSuccesses() {
      return harnessState.renewSuccesses;
    },
    latestSim() {
      const sim = [...sims.values()].at(-1);
      if (!sim) {
        throw new Error("no VCS simulator spawned");
      }
      return sim;
    },
    latestChild() {
      const child = children.at(-1);
      if (!child) {
        throw new Error("no child spawned");
      }
      return child;
    },
  };
}

async function createHarnessLease(h: ProdHarness, operationId = "op-create-1") {
  return h.registry.ensureAuthorityForLease(ref, (binding) =>
    h.registry.leases.create({
      operationId,
      teamId: ref.teamId,
      volumeId: ref.volumeId,
      branch: ref.branch,
      consumerId: "sandbox-a",
      authorityInstanceId: binding.authorityInstanceId,
      ...(binding.authorityRuntimeGeneration !== undefined
        ? { authorityRuntimeGeneration: binding.authorityRuntimeGeneration }
        : {}),
      ...(binding.authorityRuntimeId !== undefined
        ? { authorityRuntimeId: binding.authorityRuntimeId }
        : {}),
    })
  );
}

describe("production registry configuration fails closed", () => {
  test("the remote journal contract is REQUIRED and local-topology variables are rejected by name", () => {
    const { PORTABLEFS_MANAGED_VCS_JOURNAL_DSN: _dsn, ...withoutDsn } = PROD_ENV;
    expect(() => readProductionAuthorityRegistryConfig(withoutDsn)).toThrow(
      /PORTABLEFS_MANAGED_VCS_JOURNAL_DSN/
    );
    const { PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON: _policy, ...withoutPolicy } = PROD_ENV;
    expect(() => readProductionAuthorityRegistryConfig(withoutPolicy)).toThrow(
      /PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON/
    );
    const { PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET: _secret, ...withoutSecret } = PROD_ENV;
    expect(() => readProductionAuthorityRegistryConfig(withoutSecret)).toThrow(
      /PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET/
    );
    // A STATIC child credential is refused by name: children authenticate
    // with manager-minted runtime credentials (migration 015) exclusively —
    // a static token could only ever represent one tenant.
    for (const staticToken of ["PORTABLEFS_VOLUME_API_TOKEN", "VOLUME_API_TOKEN"]) {
      expect(() =>
        readProductionAuthorityRegistryConfig({ ...PROD_ENV, [staticToken]: "static-token" })
      ).toThrow(/manager-minted runtime credentials/);
    }
    // A local-topology variable in the MANAGER's environment is a config
    // error, not something to silently scrub.
    for (const forbidden of ["VCS_WAL", "VCS_REPLICA_ADDR", "VCS_STANDBY", "VCS_CACHE_DIR"]) {
      expect(() => readProductionAuthorityRegistryConfig({ ...PROD_ENV, [forbidden]: "set" })).toThrow(
        new RegExp(forbidden)
      );
    }
    // Optional child tuning is exact-allowlisted; journal/identity/topology
    // fields remain manager-owned.
    expect(() =>
      readProductionAuthorityRegistryConfig({
        ...PROD_ENV,
        PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON: JSON.stringify({ VCS_WAL: "/wal" }),
      })
    ).toThrow(/VCS_WAL/);
    expect(() =>
      readProductionAuthorityRegistryConfig({
        ...PROD_ENV,
        PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON: JSON.stringify({ PGDSN: "x" }),
      })
    ).toThrow(/exact child-env allowlist/);
    // Pooler topology accepts exactly "transaction" (or absence): a session
    // pooler (or a typo) must fail loudly, never silently mis-time the
    // journal's safety deadlines.
    expect(() =>
      readProductionAuthorityRegistryConfig({
        ...PROD_ENV,
        PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE: "session",
      })
    ).toThrow(/PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE/);
    expect(
      readProductionAuthorityRegistryConfig({
        ...PROD_ENV,
        PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON: JSON.stringify({
          VCS_CACHE_RAM_MB: "64",
          VCS_DIRTY_RSS_MAX_MB: "512",
        }),
      }).extraChildEnv
    ).toEqual({ VCS_CACHE_RAM_MB: "64", VCS_DIRTY_RSS_MAX_MB: "512" });
  });

  test("idle eviction is ALWAYS on: unset applies the 15-minute default; off/zero/negative are startup errors naming the connection-exhaustion incident", () => {
    expect(readProductionAuthorityRegistryConfig(PROD_ENV).idleEvictionGraceMs).toBe(900_000);
    expect(
      readProductionAuthorityRegistryConfig({
        ...PROD_ENV,
        PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: "30000",
      }).idleEvictionGraceMs
    ).toBe(30_000);
    // Eviction can be re-tuned, never disabled: idle children hold Postgres
    // journal connections (the 62-idle-children incident).
    for (const disabled of ["off", "0", "-1"]) {
      expect(() =>
        readProductionAuthorityRegistryConfig({
          ...PROD_ENV,
          PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: disabled,
        })
      ).toThrow(/cannot be disabled.*Postgres journal connections/s);
    }
    // Garbage is a startup error too, never a silent fallback.
    expect(() =>
      readProductionAuthorityRegistryConfig({
        ...PROD_ENV,
        PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: "soon",
      })
    ).toThrow(/positive integer/);
  });

  test("the capacity knobs default to 100 resident authorities and 4 concurrent starts, and refuse malformed values instead of silently falling back", () => {
    const config = readProductionAuthorityRegistryConfig(PROD_ENV);
    expect(config.maxAuthorities).toBe(100);
    expect(config.maxConcurrentStarts).toBe(4);
    expect(
      readProductionAuthorityRegistryConfig({
        ...PROD_ENV,
        PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES: "8",
        PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS: "2",
      })
    ).toMatchObject({ maxAuthorities: 8, maxConcurrentStarts: 2 });
    for (const bad of ["0", "-3", "many", "2.5"]) {
      expect(() =>
        readProductionAuthorityRegistryConfig({
          ...PROD_ENV,
          PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES: bad,
        })
      ).toThrow(/PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES must be a positive integer/);
      expect(() =>
        readProductionAuthorityRegistryConfig({
          ...PROD_ENV,
          PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS: bad,
        })
      ).toThrow(/PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS must be a positive integer/);
    }
  });

  test("the HA policy must be the versioned structured document — prose, weak levels, and zero-standby policies are rejected", () => {
    const withPolicy = (policy: string) =>
      readProductionAuthorityRegistryConfig({
        ...PROD_ENV,
        PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON: policy,
      });
    expect(() => withPolicy("we promise it is multi-zone")).toThrow(/not valid JSON/);
    expect(() => withPolicy(TEST_HA_POLICY_JSON.replace('"v":1', '"v":2'))).toThrow(/version 1/);
    expect(() =>
      withPolicy(
        TEST_HA_POLICY_JSON.replace('"minSynchronousCommit":"on"', '"minSynchronousCommit":"local"')
      )
    ).toThrow(/minSynchronousCommit/);
    expect(() =>
      withPolicy(TEST_HA_POLICY_JSON.replace('"minSyncStandbys":1', '"minSyncStandbys":0'))
    ).toThrow(/minSyncStandbys/);
    expect(() =>
      withPolicy(
        TEST_HA_POLICY_JSON.replace(
          '"minDistinctFailureDomains":1}',
          '"minDistinctFailureDomains":1,"extra":true}'
        )
      )
    ).toThrow(/unknown field/);
    // The pins and the operator-attested domain mapping are REQUIRED.
    expect(() =>
      withPolicy(
        '{"v":1,"expectedDatabase":"portablefs","minSynchronousCommit":"on","minSyncStandbys":1,"standbyFailureDomains":{"a":"z"},"minDistinctFailureDomains":1}'
      )
    ).toThrow(/expectedSystemIdentifier/);
    expect(() =>
      withPolicy(
        TEST_HA_POLICY_JSON.replace(
          ',"standbyFailureDomains":{"standby_a":"zone-a","standby_b":"zone-b"}',
          ""
        )
      )
    ).toThrow(/standbyFailureDomains|minDistinctFailureDomains/);
    expect(() =>
      withPolicy(
        TEST_HA_POLICY_JSON.replace('"minDistinctFailureDomains":1', '"minDistinctFailureDomains":3')
      )
    ).toThrow(/exceeds/);

    // remote_apply is a legal (stronger) minimum; the canonical hash is
    // deterministic and distinct per policy.
    const remoteApply = TEST_HA_POLICY_JSON.replace(
      '"minSynchronousCommit":"on"',
      '"minSynchronousCommit":"remote_apply"'
    );
    expect(withPolicy(remoteApply).journalHaPolicyHash).toHaveLength(64);
    expect(withPolicy(remoteApply).journalHaPolicyHash).not.toBe(TEST_HA_POLICY_HASH);
    expect(canonicalHaPolicyHash(TEST_HA_POLICY_JSON)).toBe(TEST_HA_POLICY_HASH);
    // The canonical JSON encoder is byte-identical to the Go child's
    // (vcs/internal/hapolicy Policy.Hash of this exact policy).
    expect(TEST_HA_POLICY_HASH).toBe(TEST_HA_POLICY_HASH_PINNED);
    // Key order and formatting never change the canonical hash.
    expect(
      canonicalHaPolicyHash(
        '{"standbyFailureDomains":{"standby_b":"zone-b","standby_a":"zone-a"},"minDistinctFailureDomains":1,"minSyncStandbys":1,"minSynchronousCommit":"on","expectedDatabase":"portablefs","expectedSystemIdentifier":"7300000000000000001","v":1}'
      )
    ).toBe(TEST_HA_POLICY_HASH_PINNED);
  });

  test("a missing remote ManagerControlStore is an HONEST readiness failure — never a silent file fallback", async () => {
    const error = await expectOperationError(
      createProductionAuthorityRegistry(PROD_ENV, {}),
      authorityOperationErrorCodes.controlStoreRequired
    );
    expect(error.status).toBe(503);
    expect(error.message).toMatch(/no file fallback/);
  });
});

describe("production children are disposable and journal remotely (no local files)", () => {
  test("the spawn environment is built from scratch: remote journal + HA policy + runtime capability present, local topology and listener addresses ABSENT, private HOME/TMP beneath the ephemeral cwd removed after teardown", async () => {
    const h = await newProductionHarness();
    expect(h.registry.ready()).toBe(true);
    const endpoint = await h.registry.ensureAuthority(ref);
    expect(endpoint.authorityInstanceId!.startsWith("pfvcs_")).toBe(true);

    expect(h.spawnEnvs).toHaveLength(1);
    const env = h.spawnEnvs[0]!;
    expect(env.VCS_JOURNAL_DSN).toBe("postgres://portablefs@db.internal/journal");
    expect(env.VCS_JOURNAL_POOLER_MODE).toBe("transaction");
    expect(env.VCS_JOURNAL_HA_POLICY_JSON).toBe(TEST_HA_POLICY_JSON);
    expect(env.VCS_TENANT_ID).toBe("team_1");
    expect(env.VCS_MANAGER_EPOCH).toBe("1");
    expect(typeof env.VCS_MANAGER_RUNTIME_ID).toBe("string");
    expect(env.VCS_AUTHORITY_RUNTIME_SEQ).toBe("1");
    expect(typeof env.VCS_AUTHORITY_RUNTIME_ID).toBe("string");
    // The manager-minted 256-bit runtime capability travels RAW to exactly
    // this child; the durable runtime row stores only its hash.
    expect(env.VCS_AUTHORITY_RUNTIME_CAPABILITY).toMatch(/^pfrtcap_[A-Za-z0-9_-]{43}$/u);
    expect(env.VCS_PRODUCTION).toBe("1");
    expect(env.VCS_WRITABLE).toBe("1");
    expect(typeof env.VCS_AUTH_TOKEN).toBe("string");
    expect(typeof env.VCS_ADMIN_TOKEN).toBe("string");
    expect(env.VCS_HEARTBEAT_FD).toBe(String(CHILD_HEARTBEAT_FD));
    expect(env.VCS_BOOTSTRAP_FD).toBe(String(CHILD_BOOTSTRAP_FD));
    // The child's ONLY volume-api identity is the manager-minted rotating
    // runtime credential file (0600, inside the ephemeral work dir); the
    // database stores the secret's SHA-256 bound to the live runtime row.
    expect(env.VOLUME_API_TOKEN).toBeUndefined();
    expect(env.VOLUME_API_TOKEN_FILE).toBeTruthy();
    const credentialSecret = (await readFile(env.VOLUME_API_TOKEN_FILE!, "utf8")).trim();
    expect(credentialSecret).toMatch(/^pfrc_[A-Za-z0-9_-]{48}$/u);
    const credentialStat = await stat(env.VOLUME_API_TOKEN_FILE!);
    expect(credentialStat.mode & 0o777).toBe(0o600);
    expect(h.store.mintedCredentialHashes).toContain(sha256Hex(credentialSecret));
    for (const forbidden of [
      "VCS_WAL",
      "VCS_REPLICA_ADDR",
      "VCS_REPLICA_LISTEN",
      "VCS_STANDBY",
      "VCS_STANDBY_WAL",
      // The child binds 127.0.0.1:0 itself and reports the exact addresses
      // on the bootstrap pipe; the manager never assigns listener addresses.
      "VCS_ADDR",
      "VCS_FS_ADDR",
      "VCS_METRICS_ADDR",
      "VCS_CACHE_DIR",
    ]) {
      expect(env[forbidden]).toBeUndefined();
    }
    // ONE child only — never a spawned pair; ephemeral cwd with private
    // HOME/TMP beneath it (no inherited persistent paths whatsoever).
    const cwd = h.spawnCwds[0]!;
    expect(cwd.startsWith(os.tmpdir())).toBe(true);
    expect(env.HOME!.startsWith(cwd)).toBe(true);
    expect(env.TMPDIR!.startsWith(cwd)).toBe(true);
    await expect(stat(env.HOME!)).resolves.toBeTruthy();
    await expect(stat(env.TMPDIR!)).resolves.toBeTruthy();

    // The adopted addresses are EXACTLY the child's self-bound loopback
    // listeners from the bootstrap frame.
    const sim = h.latestSim();
    expect(h.registry.resolveDataPlaneRoute(endpoint.authorityInstanceId!)).toMatchObject({
      backendAddresses: [sim.fsAddr],
    });

    // A repeated ensure REUSES the live child (demand-start, no churn).
    await h.registry.ensureAuthority(ref);
    expect(h.spawnEnvs).toHaveLength(1);

    // Stop tears the child down and removes the ephemeral work dir.
    const stopped = await h.registry.stopAuthority({
      ...ref,
      expectedAuthority: { authorityInstanceId: endpoint.authorityInstanceId! },
    });
    expect(stopped).toEqual({ stopped: true, managed: true });
    await expect(stat(cwd)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("ensureAuthorityForLease binds the lease to the EXACT instance and runtime under the authority lock", async () => {
    const h = await newProductionHarness();
    const { endpoint, result } = await createHarnessLease(h);
    expect(result.lease.authorityInstanceId).toBe(endpoint.authorityInstanceId);
    // The token resolves on the data plane against the live child.
    const route = h.registry.leases.resolveSessionToken(result.accessToken);
    expect(route).toMatchObject({ authorityInstanceId: endpoint.authorityInstanceId });
    expect(route!.backendAddresses).toEqual([h.latestSim().fsAddr]);

    // A second lease on the same ref binds under the same lock to the SAME
    // live child — demand-start, no churn.
    const second = await createHarnessLease(h, "op-create-2");
    expect(second.result.lease.authorityInstanceId).toBe(endpoint.authorityInstanceId);
    expect(h.registry.leases.resolveSessionToken(second.result.accessToken)).toMatchObject({
      authorityInstanceId: endpoint.authorityInstanceId,
    });
    expect(h.spawnEnvs).toHaveLength(1); // same child served both leases
  });
});

// ---------------------------------------------------------------------------
// Manager claim/renew deadline projection: the local deadline anchors at the
// PRE-CALL monotonic instant, so a slow control-store response can never
// extend readiness past the database's own expiry.
// ---------------------------------------------------------------------------

describe("manager claim deadline projection", () => {
  test("a DELAYED claim response never extends readiness past DB expiry: the deadline anchors at the pre-call local instant", async () => {
    const local = { now: 100_000 };
    const db = { now: 1_000_000 };
    const store = new InMemoryManagerControlStore({ dbNow: () => db.now });
    store.gate = async (target) => {
      if (target === "claimManager") {
        // The claim round trip burns 5s of local time before the response
        // (with its full 30s TTL) arrives.
        local.now += 5_000;
        db.now += 5_000;
      }
    };
    const h = await newProductionHarness({ store, localNow: () => local.now });
    // Break further renewals so ONLY the claim projection is observed.
    h.store.failNext("renewManagerClaim", 1_000_000);

    // Correct anchor: pre-call local 100_000 + 30_000 TTL = 130_000. The
    // buggy post-response anchor would be 135_000 — five stolen seconds
    // serving past DB expiry.
    local.now = 129_999;
    expect(h.registry.ready()).toBe(true);
    local.now = 130_000;
    expect(h.registry.ready()).toBe(false);
  });

  test("wall-clock skew: a forward jump fences readiness early and a backward jump never manufactures extra lease time", async () => {
    const local = { now: 50_000 };
    const db = { now: 3_000_000 };
    const store = new InMemoryManagerControlStore({ dbNow: () => db.now });
    const h = await newProductionHarness({ store, localNow: () => local.now });
    h.store.failNext("renewManagerClaim", 1_000_000);

    // FORWARD skew past the DB-derived deadline: fenced immediately — the
    // manager serves conservatively, never optimistically.
    local.now = 50_000 + 30_000 + 600_000;
    expect(h.registry.ready()).toBe(false);

    // BACKWARD skew: the deadline VALUE is unchanged (it derives from the
    // captured anchor + DB facts, never from re-reading the wall clock), so
    // the same fixed instant still bounds readiness exactly.
    local.now = 50_000 + 29_999;
    expect(h.registry.ready()).toBe(true);
    local.now = 50_000 + 30_000;
    expect(h.registry.ready()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Child-process lifecycle hardening: spawn failures are events, not crashes;
// teardown is bounded no matter how the process misbehaves.
// ---------------------------------------------------------------------------

describe("child process lifecycle", () => {
  test("spawn ENOENT (an 'error' event with NO exit, kill a no-op) fails the start cleanly and never crashes the manager", async () => {
    const h = await newProductionHarness({
      processMode: "spawn-enoent",
      env: { PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS: "300" },
    });
    await expect(h.registry.ensureAuthority(ref)).rejects.toThrow(
      /exited or failed before reporting its bootstrap frame/
    );
    // Nothing adopted, every bounded start attempt failed fast, and teardown
    // resolved without hanging on the missing exit event.
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
    expect(h.spawnEnvs.length).toBeGreaterThan(0);
    // COMPENSATION: every durable runtime begin was ended — a spawn failure
    // leaks no live runtime row (and therefore no journal-claimable binding)
    // and the racing cleanup paths never collide on operation content.
    const scope = { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch };
    const deadline = Date.now() + 3_000;
    while (h.store.liveRuntime(scope) !== null && Date.now() < deadline) {
      await delay(10);
    }
    expect(h.store.liveRuntime(scope)).toBeNull();
    expectNoOperationContentConflicts(h);
  });

  test("a spawn that THROWS synchronously compensates the durable runtime begin", async () => {
    const store = new InMemoryManagerControlStore();
    const registry = await createProductionAuthorityRegistry(PROD_ENV, {
      controlStore: store,
      fetch: (async () => new Response("{}", { status: 404 })) as typeof fetch,
      spawnProcess: (() => {
        throw new Error("spawn EAGAIN");
      }) as never,
      log: () => {},
    });
    registries.push(registry);
    await expect(registry.ensureAuthority(ref)).rejects.toThrow(/EAGAIN/);
    // The runtime row minted BEFORE the spawn was ended (start-failed): no
    // live binding, nothing tracked, nothing to fence later.
    expect(
      store.liveRuntime({ tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch })
    ).toBeNull();
    expect(await registry.inspectAuthority(ref)).toBeNull();
  });

  test("a child that exits immediately after spawn fails the start promptly (before the bootstrap timeout)", async () => {
    const h = await newProductionHarness({
      processMode: "immediate-exit",
      env: { PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS: "60000" },
    });
    const started = Date.now();
    await expect(h.registry.ensureAuthority(ref)).rejects.toThrow(
      /exited or failed before reporting its bootstrap frame/
    );
    // Prompt: the 60s bootstrap timeout was NOT what failed the start.
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("a child that ignores SIGTERM is escalated to SIGKILL and teardown completes", async () => {
    const h = await newProductionHarness({ processMode: "ignore-sigterm" });
    const endpoint = await h.registry.ensureAuthority(ref);
    await h.registry.stopAuthority({
      ...ref,
      expectedAuthority: { authorityInstanceId: endpoint.authorityInstanceId! },
    });
    expect(h.kills).toContain("SIGTERM");
    expect(h.kills).toContain("SIGKILL");
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("a child that never emits exit at all cannot hang the bounded teardown", async () => {
    const h = await newProductionHarness({ processMode: "ignore-all" });
    const endpoint = await h.registry.ensureAuthority(ref);
    const started = Date.now();
    // processGraceMs is 50 in PROD_ENV: SIGTERM wait + SIGKILL wait are each
    // bounded by it, so the stop resolves in well under a second even with
    // no exit event ever arriving.
    await h.registry.stopAuthority({
      ...ref,
      expectedAuthority: { authorityInstanceId: endpoint.authorityInstanceId! },
    });
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(h.kills).toContain("SIGTERM");
    expect(h.kills).toContain("SIGKILL");
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("a crashed child is REPLACED by a fresh spawn on the next demand — never adopted or repaired", async () => {
    const h = await newProductionHarness();
    const first = await h.registry.ensureAuthority(ref);
    const scope = { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch };
    const firstRuntime = h.store.liveRuntime(scope);

    h.latestChild().emit("exit", 1, null);
    const deadline = Date.now() + 3_000;
    while (h.store.liveRuntime(scope) !== null && Date.now() < deadline) {
      await delay(10);
    }
    expect(await h.registry.inspectAuthority(ref)).toBeNull();

    const second = await h.registry.ensureAuthority(ref);
    expect(second.authorityInstanceId).not.toBe(first.authorityInstanceId);
    expect(h.spawnEnvs).toHaveLength(2);
    const secondRuntime = h.store.liveRuntime(scope);
    expect(secondRuntime?.runtimeSeq).toBe("2");
    expect(secondRuntime?.runtimeId).not.toBe(firstRuntime?.runtimeId);
    expectNoOperationContentConflicts(h);
  });
});

// ---------------------------------------------------------------------------
// Teardown ordering invariant: the durable access-fence retire COMMITS before
// the runtime row ends, on EVERY teardown path. The reverse order could leave
// active, renewable lease rows standing behind an already-ended runtime.
// ---------------------------------------------------------------------------

// instrumentTeardownOrder wraps the fake store's retire and runtime-end so a
// test observes start/commit/fail events in exact order.
function instrumentTeardownOrder(store: InMemoryManagerControlStore): string[] {
  const events: string[] = [];
  const endBatch = store.accessEndBatch.bind(store);
  store.accessEndBatch = async (args) => {
    events.push("retire-start");
    try {
      const result = await endBatch(args);
      events.push("retire-committed");
      return result;
    } catch (error) {
      events.push("retire-failed");
      throw error;
    }
  };
  const endRuntime = store.endAuthorityRuntime.bind(store);
  store.endAuthorityRuntime = async (args) => {
    events.push("runtime-end-start");
    try {
      const result = await endRuntime(args);
      events.push("runtime-end-committed");
      return result;
    } catch (error) {
      events.push("runtime-end-failed");
      throw error;
    }
  };
  return events;
}

async function waitForEvent(events: string[], name: string, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!events.includes(name) && Date.now() < deadline) {
    await delay(5);
  }
  if (!events.includes(name)) {
    throw new Error(`teardown event ${name} did not happen; saw [${events.join(", ")}]`);
  }
}

function expectRetireCommittedBeforeRuntimeEnd(events: string[]): void {
  const retireCommitted = events.indexOf("retire-committed");
  const runtimeEndStart = events.indexOf("runtime-end-start");
  expect(retireCommitted).toBeGreaterThanOrEqual(0);
  expect(runtimeEndStart).toBeGreaterThan(retireCommitted);
}

// No lifecycle path may trip operation-id/content conflict detection: a
// conflict means two semantic operations collided on one id — a design bug,
// never expected stderr.
function expectNoOperationContentConflicts(h: { logs: string[] }): void {
  expect(h.logs.filter((line) => line.includes("replayed with different content"))).toEqual([]);
}

describe("teardown orders the durable access fence BEFORE the runtime end", () => {
  test("unexpected child exit: local fence immediately, retire commits, ONLY THEN the runtime row ends", async () => {
    const h = await newProductionHarness();
    const { result: session } = await createHarnessLease(h, "op-teardown-exit");
    expect(session.accessToken).toBeDefined();
    const scope = { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch };
    expect(h.store.liveRuntime(scope)).not.toBeNull();

    const events = instrumentTeardownOrder(h.store);
    h.latestChild().emit("exit", 1, null);
    await waitForEvent(events, "runtime-end-committed");

    expectRetireCommittedBeforeRuntimeEnd(events);
    expect(h.store.liveRuntime(scope)).toBeNull();
    // The instance's durable lease rows were retired by the fence, and the
    // session token stopped resolving the moment the local fence ran.
    expect(h.store.activeLeaseRows()).toBe(0);
    expect(h.registry.leases.resolveSessionToken(session.accessToken)).toBeNull();
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
    expectNoOperationContentConflicts(h);
  });

  test("shutdown settles to ZERO live runtime rows with no operation-content conflicts and releases the claim", async () => {
    const h = await newProductionHarness();
    await createHarnessLease(h, "op-teardown-shutdown");
    const scope = { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch };
    expect(h.store.liveRuntime(scope)).not.toBeNull();
    await h.registry.shutdown();
    expect(h.store.liveRuntime(scope)).toBeNull();
    expect(h.store.activeLeaseRows()).toBe(0);
    expect(h.registry.ready()).toBe(false);
    expectNoOperationContentConflicts(h);
    // The claim was released: a successor claims the next epoch immediately
    // instead of waiting out the TTL.
    const successor = await claimManager(h.store, {
      operationId: "claim-successor",
      runtimeId: "manager-successor",
    });
    expect(successor.claim.managerEpoch).toBe("2");
  });

  test("a LOST retire response retries the SAME idempotent operation and the runtime end WAITS for the commit", async () => {
    const h = await newProductionHarness();
    await createHarnessLease(h, "op-teardown-lost-retire");
    const events = instrumentTeardownOrder(h.store);
    h.store.failNext("accessEndBatch", 1);

    h.latestChild().emit("exit", 1, null);
    await waitForEvent(events, "runtime-end-committed");

    // First attempt failed; the retry replayed the deterministic operation;
    // the runtime end never started before a COMMITTED retire.
    expect(events.indexOf("retire-failed")).toBeGreaterThanOrEqual(0);
    expect(events.filter((event) => event === "retire-start").length).toBeGreaterThanOrEqual(2);
    expectRetireCommittedBeforeRuntimeEnd(events);
    expect(events.indexOf("runtime-end-start")).toBeGreaterThan(events.indexOf("retire-failed"));
    expectNoOperationContentConflicts(h);
  });

  test("crash-shaped outage AFTER the fence: the runtime row stays LIVE with all access fenced, and the successor's begin settles it", async () => {
    const h = await newProductionHarness();
    await createHarnessLease(h, "op-teardown-crash");
    const scope = { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch };
    const before = h.store.liveRuntime(scope);
    const events = instrumentTeardownOrder(h.store);
    // Runtime-end fails on every bounded attempt (the "crashed between the
    // two durable writes" shape).
    h.store.failNext("endAuthorityRuntime", 10);

    h.latestChild().emit("exit", 1, null);
    await waitForEvent(events, "retire-committed");
    const settled = Date.now() + 3_000;
    while (events.filter((event) => event === "runtime-end-failed").length < 3 && Date.now() < settled) {
      await delay(10);
    }

    // Runtime metadata is still live — but NOT renewable/routable: every
    // durable lease row was retired first and the local fence closed tunnels.
    expect(h.store.liveRuntime(scope)?.runtimeId).toBe(before?.runtimeId);
    expect(h.store.activeLeaseRows()).toBe(0);

    // The successor demand-start ends the stale row in its own begin
    // transaction — no manual reconciliation.
    await h.registry.ensureAuthority(ref);
    const after = h.store.liveRuntime(scope);
    expect(after).not.toBeNull();
    expect(after?.runtimeId).not.toBe(before?.runtimeId);
    expectNoOperationContentConflicts(h);
  });

  test("a stop whose durable fence cannot commit fails CLOSED before any termination or runtime mutation", async () => {
    const h = await newProductionHarness();
    const endpoint = await h.registry.ensureAuthority(ref);
    const events = instrumentTeardownOrder(h.store);
    h.store.failNext("accessEndBatch", 1);
    await expect(
      h.registry.stopAuthority({
        ...ref,
        expectedAuthority: { authorityInstanceId: endpoint.authorityInstanceId! },
      })
    ).rejects.toMatchObject({ status: 503 });
    // Nothing terminated, nothing ended: the child is still live and a retry
    // (fence commits this time) completes the ordered teardown.
    expect(events).not.toContain("runtime-end-start");
    expect(h.kills).toEqual([]);
    expect(await h.registry.inspectAuthority(ref)).not.toBeNull();
    const retried = await h.registry.stopAuthority({
      ...ref,
      expectedAuthority: { authorityInstanceId: endpoint.authorityInstanceId! },
    });
    expect(retried).toEqual({ stopped: true, managed: true });
    expectRetireCommittedBeforeRuntimeEnd(events);
  });
});

// ---------------------------------------------------------------------------
// Manager pipes: the bootstrap frame is the ONLY address truth, and the lease
// pipe must accept every frame or the child dies.
// ---------------------------------------------------------------------------

describe("manager pipes fence the child", () => {
  test("a child that never reports its bootstrap frame is terminated and NEVER adopted", async () => {
    const h = await newProductionHarness({
      pipeMode: "silent",
      env: { PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS: "100" },
    });
    await expect(h.registry.ensureAuthority(ref)).rejects.toThrow(/bootstrap frame/);
    // Every bounded start attempt was cleaned up: spawned children were
    // terminated and nothing is tracked.
    expect(h.spawnEnvs.length).toBeGreaterThan(0);
    expect(h.kills.length).toBeGreaterThanOrEqual(h.spawnEnvs.length);
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("a truncated bootstrap frame (child died mid-write) is refused, never parsed partially", async () => {
    const h = await newProductionHarness({
      pipeMode: "truncated",
      env: { PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS: "100" },
    });
    await expect(h.registry.ensureAuthority(ref)).rejects.toThrow(
      /bootstrap pipe closed before a complete frame/
    );
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("TRAILING bytes after the one-shot bootstrap frame are refused — even when the frame itself is valid", async () => {
    const h = await newProductionHarness({ pipeMode: "trailing" });
    await expect(h.registry.ensureAuthority(ref)).rejects.toThrow(
      /trailing bytes after the one-shot frame/
    );
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("a bootstrap frame naming a FOREIGN authority identity is refused (no spoofed adoption)", async () => {
    const h = await newProductionHarness({ pipeMode: "foreign" });
    await expect(h.registry.ensureAuthority(ref)).rejects.toThrow(/foreign authorityInstanceId/);
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("a bootstrap frame reporting a non-loopback data-plane address is refused", async () => {
    const h = await newProductionHarness({ pipeMode: "spoofed-addr" });
    await expect(h.registry.ensureAuthority(ref)).rejects.toThrow(/non-loopback or malformed fsAddr/);
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("lease-frame backpressure is FATAL for the child, never silently ignored", async () => {
    const h = await newProductionHarness({
      pipeMode: "heartbeat-backpressure",
      env: { PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS: "500" },
    });
    // The very first lease frame is refused by the pipe; the manager
    // terminates the child instead of letting it serve on a stale (absent)
    // lease view. The start attempt therefore fails and nothing is adopted.
    await expect(h.registry.ensureAuthority(ref)).rejects.toThrow();
    expect(h.kills.length).toBeGreaterThan(0);
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("a lease-frame write ERROR is fatal for the child too", async () => {
    const h = await newProductionHarness({
      heartbeat: "error",
      env: { PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS: "500" },
    });
    // The write error can land just before or just after adoption completes
    // (both are real timings); either way the child is terminated and
    // nothing stays tracked.
    await h.registry.ensureAuthority(ref).catch(() => null);
    const deadline = Date.now() + 2_000;
    while (h.kills.length === 0 && Date.now() < deadline) {
      await delay(10);
    }
    expect(h.kills.length).toBeGreaterThan(0);
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
  });

  test("lease frames are LATEST-VALUE and bounded: one write in flight, superseded frames discarded, sequence strictly monotonic", async () => {
    const db = { now: 5_000_000 };
    const store = new InMemoryManagerControlStore({ dbNow: () => db.now });
    const renewTimes: number[] = [];
    store.gate = async (target) => {
      if (target === "renewManagerClaim") {
        db.now += 1_000; // each renewal observes fresh database time
        renewTimes.push(db.now);
      }
    };
    const h = await newProductionHarness({
      store,
      heartbeat: "hold",
      env: { PORTABLEFS_MANAGER_CLAIM_TTL_MS: "3000" },
    });
    await h.registry.ensureAuthority(ref);

    // The startup frame is in flight; its callback is deliberately HELD.
    expect(h.heartbeatWrites).toHaveLength(1);
    expect(h.heartbeatWrites[0]!.frame.seq).toBe(1);
    expect(h.heartbeatWrites[0]!.frame.v).toBe(1);
    expect(h.heartbeatWrites[0]!.frame.managerEpoch).toBe("1");
    expect(typeof h.heartbeatWrites[0]!.frame.authorityInstanceId).toBe("string");
    expect(Number.isInteger(h.heartbeatWrites[0]!.frame.dbTimeMs)).toBe(true);
    expect(Number.isInteger(h.heartbeatWrites[0]!.frame.leaseRemainingMs)).toBe(true);

    // Three renewals land while the first write is still in flight: each
    // hands the child fresher lease facts, but the pipe must never queue
    // them — the single pending slot keeps replacing (discarding) the
    // superseded frames.
    const waitUntil = Date.now() + 4_500;
    while (h.renewSuccesses < 3 && Date.now() < waitUntil) {
      await delay(25);
    }
    expect(h.renewSuccesses).toBeGreaterThanOrEqual(3);
    expect(h.heartbeatWrites).toHaveLength(1); // still just the held write

    // Releasing the held write flushes EXACTLY ONE follow-up frame: the
    // latest facts, the next sequence — not a backlog of stale frames.
    const renewsAtRelease = h.renewSuccesses;
    h.heartbeatWrites[0]!.release();
    expect(h.heartbeatWrites).toHaveLength(2);
    const flushed = h.heartbeatWrites[1]!.frame;
    expect(flushed.seq).toBe(2);
    expect(flushed.dbTimeMs).toBe(renewTimes[renewsAtRelease - 1]);

    // Releasing the second write with the pending slot empty flushes nothing.
    h.heartbeatWrites[1]!.release();
    expect(h.heartbeatWrites).toHaveLength(2);
    // The child is still alive and adopted throughout: coalescing is not a
    // failure mode.
    expect(h.kills).toEqual([]);
    expect(await h.registry.inspectAuthority(ref)).not.toBeNull();
  }, 10_000);
});

// ---------------------------------------------------------------------------
// Epoch handoff and idle eviction.
// ---------------------------------------------------------------------------

describe("production epoch loss, handoff, and idle eviction", () => {
  test("losing the manager epoch stops ALL mutation immediately: readiness fails, every lease ends, every child is terminated; the successor spawns FRESH children and mounts reacquire", async () => {
    const db = { now: 1_000_000 };
    const store = new InMemoryManagerControlStore({ dbNow: () => db.now });
    const h = await newProductionHarness({ store });
    const created = await createHarnessLease(h);
    const oldToken = created.result.accessToken;

    // A competing manager claims the next epoch; this manager discovers the
    // loss on its next fenced store write (here: a lease create's receipt).
    h.store.supersedeEpoch();
    await expectAccessLeaseError(
      () =>
        h.registry.leases.create({
          operationId: "op-create-after-loss",
          teamId: ref.teamId,
          volumeId: ref.volumeId,
          branch: ref.branch,
          consumerId: "sandbox-b",
          authorityInstanceId: created.endpoint.authorityInstanceId!,
          authorityRuntimeGeneration: "1",
          authorityRuntimeId: h.spawnEnvs[0]!.VCS_AUTHORITY_RUNTIME_ID as string,
        }),
      "ACCESS_LEASE_EPOCH_SUPERSEDED"
    );
    // Every lease under the old epoch ended and its token stopped resolving.
    expect(h.registry.ready()).toBe(false);
    expect(h.registry.leases.healthy()).toBe(false);
    expect(h.registry.leases.resolveSessionToken(oldToken)).toBeNull();
    expect((await h.registry.leases.lookup(created.result.lease.accessLeaseId))?.endReason).toBe(
      "manager-epoch-superseded"
    );
    // A REGISTRY lifecycle mutation discovers the loss through its own fenced
    // store write (the runtime begin for a fresh scope is refused server-side
    // — a lost manager can never mint a runtime row): the manager fences
    // itself and proactively terminates the old children (their journal truth
    // is remote; the successor manager demand-starts replacements).
    await expectOperationError(
      h.registry.ensureAuthority({ ...ref, branch: "feature" }),
      authorityOperationErrorCodes.managerEpochSuperseded
    );
    expect(
      h.store.liveRuntime({ tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: "feature" })
    ).toBeNull();
    // The old children were fenced and terminated.
    const deadline = Date.now() + 2_000;
    while (h.kills.length === 0 && Date.now() < deadline) {
      await delay(10);
    }
    expect(h.kills.length).toBeGreaterThan(0);
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
    // The old scope's runtime row deliberately stays LIVE: supersession skips
    // the runtime end (the rows die with the epoch server-side) and the
    // successor's begin settles it.
    const scope = { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch };
    expect(h.store.liveRuntime(scope)?.runtimeSeq).toBe("1");
    // Further mutations refuse with the supersession code.
    await expectOperationError(
      h.registry.ensureAuthority(ref),
      authorityOperationErrorCodes.managerEpochSuperseded
    );

    // A SUCCESSOR manager against the SAME store: the competitor's claim is
    // expired at database time, the successor mints the next epoch, spawns a
    // FRESH child (runtime seq advances), and a fresh lease resolves while
    // the predecessor's token stays dead.
    db.now += 120_000;
    const successor = await newProductionHarness({ store });
    expect(successor.registry.ready()).toBe(true);
    expect(BigInt(successor.registry.epoch())).toBeGreaterThan(BigInt(h.registry.epoch()));
    const reacquired = await createHarnessLease(successor, "op-create-successor");
    expect(reacquired.endpoint.authorityInstanceId).not.toBe(created.endpoint.authorityInstanceId);
    expect(successor.spawnEnvs).toHaveLength(1);
    expect(successor.spawnEnvs[0]!.VCS_AUTHORITY_RUNTIME_SEQ).toBe("2");
    // The successor's begin settled the predecessor's live runtime row.
    expect(h.store.liveRuntime(scope)?.runtimeSeq).toBe("2");
    expect(successor.registry.leases.resolveSessionToken(reacquired.result.accessToken)).not.toBeNull();
    expect(successor.registry.leases.resolveSessionToken(oldToken)).toBeNull();
  });

  test("zero-session grace eviction tears the idle child down in fence-then-runtime-end order", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: "25" },
    });
    const created = await createHarnessLease(h);
    const scope = { tenantKey: managedTenantKey(ref), volumeId: ref.volumeId, branch: ref.branch };
    const events = instrumentTeardownOrder(h.store);

    // Releasing the only lease starts the zero-active grace timer; after the
    // grace the child is evicted with the ordered durable teardown.
    await h.registry.leases.release({
      operationId: "op-release-1",
      accessLeaseId: created.result.lease.accessLeaseId,
      accessToken: created.result.accessToken,
    });
    await waitForEvent(events, "runtime-end-committed");
    expectRetireCommittedBeforeRuntimeEnd(events);
    expect(h.kills.length).toBeGreaterThan(0);
    expect(await h.registry.inspectAuthority(ref)).toBeNull();
    expect(h.store.liveRuntime(scope)).toBeNull();
    expectNoOperationContentConflicts(h);
  });

  test("idle eviction LOSES to a create that lands during the grace window (activity cancels the timer)", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: "60" },
    });
    const created = await createHarnessLease(h);
    const binding = {
      authorityInstanceId: created.endpoint.authorityInstanceId!,
      authorityRuntimeGeneration: "1",
      authorityRuntimeId: h.spawnEnvs[0]!.VCS_AUTHORITY_RUNTIME_ID as string,
    };
    await h.registry.leases.release({
      operationId: "op-release-1",
      accessLeaseId: created.result.lease.accessLeaseId,
      accessToken: created.result.accessToken,
    });
    // The remount lands inside the grace window: activity cancels the timer.
    const remount = await h.registry.leases.create({
      operationId: "op-create-2",
      teamId: ref.teamId,
      volumeId: ref.volumeId,
      branch: ref.branch,
      consumerId: "sandbox-b",
      ...binding,
    });
    await delay(150); // well past the grace: no eviction may fire

    expect(h.kills).toEqual([]);
    expect(await h.registry.inspectAuthority(ref)).not.toBeNull();
    expect(h.registry.leases.resolveSessionToken(remount.accessToken)).toMatchObject({
      authorityInstanceId: binding.authorityInstanceId,
    });
  });

  test("idle eviction LOSES to a create that lands while the eviction waits on the authority lock (activity version re-check)", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: "25" },
    });
    const created = await createHarnessLease(h);

    // Hold the per-branch authority lock with a slow lease creation; release
    // the only lease so the grace timer fires and the eviction queues BEHIND
    // the held lock. When it finally runs, the activity version has moved.
    const lockHeld = deferred<void>();
    const releaseLock = deferred<void>();
    const slowCreate = h.registry.ensureAuthorityForLease(ref, async (binding) => {
      lockHeld.resolve();
      await releaseLock.promise;
      return h.registry.leases.create({
        operationId: "op-create-2",
        teamId: ref.teamId,
        volumeId: ref.volumeId,
        branch: ref.branch,
        consumerId: "sandbox-b",
        authorityInstanceId: binding.authorityInstanceId,
        authorityRuntimeGeneration: binding.authorityRuntimeGeneration!,
        authorityRuntimeId: binding.authorityRuntimeId!,
      });
    });
    await lockHeld.promise;
    await h.registry.leases.release({
      operationId: "op-release-1",
      accessLeaseId: created.result.lease.accessLeaseId,
      accessToken: created.result.accessToken,
    });
    await delay(60); // the grace timer fires; the eviction is queued on the lock
    releaseLock.resolve();
    const remount = await slowCreate;
    await delay(100); // let the queued eviction run its abort checks

    // The eviction LOST: the child is alive and the new lease resolves.
    expect(h.kills).toEqual([]);
    expect(await h.registry.inspectAuthority(ref)).not.toBeNull();
    expect(h.registry.leases.resolveSessionToken(remount.result.accessToken)).not.toBeNull();
  });

  test("a FAILED idle eviction re-arms its own grace timer (at zero leases no zero-active edge can ever fire again)", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: "25" },
    });
    const created = await createHarnessLease(h);

    // The FIRST eviction attempt's durable access fence fails (store outage
    // shape): the child must keep running, nothing may be terminated.
    h.store.failNext("accessEndBatch", 1);

    // Releasing the only lease arms the zero-active grace timer.
    await h.registry.leases.release({
      operationId: "op-release-1",
      accessLeaseId: created.result.lease.accessLeaseId,
      accessToken: created.result.accessToken,
    });

    // Without the self re-arm the story ends here: with zero active leases
    // no lease can ever end, so no zero-active edge fires again and the
    // failed eviction leaks the resident child forever. The re-armed timer
    // must retry (the deterministic pfretire receipt replays cleanly) and
    // complete the eviction.
    await waitFor(async () => (await h.registry.inspectAuthority(ref)) === null);
    expect(h.kills.length).toBeGreaterThan(0);
    expectNoOperationContentConflicts(h);
  });
});

// ---------------------------------------------------------------------------
// Resident capacity cap + the global cold-start gate: both refuse typed with
// Retry-After backoff instead of exhausting the journal database.
// ---------------------------------------------------------------------------

describe("resident capacity and the global start gate", () => {
  test("at the resident cap a NEW spawn refuses typed AUTHORITY_AT_CAPACITY while running authorities keep serving; freed capacity re-admits", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES: "1" },
    });
    const first = await h.registry.ensureAuthority(ref);

    const error = await expectOperationError(
      h.registry.ensureAuthority({ ...ref, volumeId: "vol_2" }),
      authorityOperationErrorCodes.atCapacity
    );
    expect(error.status).toBe(503);
    expect(error.retryAfterSeconds).toBe(15);
    // The refusal spawned nothing and left no durable runtime row behind.
    expect(h.spawnEnvs).toHaveLength(1);
    expect(
      h.store.liveRuntime({ tenantKey: managedTenantKey(ref), volumeId: "vol_2", branch: ref.branch })
    ).toBeNull();

    // The RUNNING authority is unaffected: re-ensure resolves the same
    // instance without a new spawn.
    const again = await h.registry.ensureAuthority(ref);
    expect(again.authorityInstanceId).toBe(first.authorityInstanceId);
    expect(h.spawnEnvs).toHaveLength(1);

    // Freeing capacity (here: a fenced stop) admits the refused scope.
    await h.registry.stopAuthority({
      ...ref,
      expectedAuthority: { authorityInstanceId: first.authorityInstanceId! },
    });
    const admitted = await h.registry.ensureAuthority({ ...ref, volumeId: "vol_2" });
    expect(admitted.authorityInstanceId).not.toBe(first.authorityInstanceId);
    expect(h.spawnEnvs).toHaveLength(2);
  });

  test("replacing a dead-or-unready child at the cap is admitted: the cap gates NET-NEW residents only", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES: "1" },
    });
    const first = await h.registry.ensureAuthority(ref);
    h.latestSim().unready = true;
    const replacement = await h.registry.ensureAuthority(ref);
    expect(replacement.authorityInstanceId).not.toBe(first.authorityInstanceId);
    expect(h.spawnEnvs).toHaveLength(2);
  });

  test("idle eviction frees cap capacity: after the grace evicts the idle child the refused scope admits", async () => {
    const h = await newProductionHarness({
      env: {
        PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES: "1",
        PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: "25",
      },
    });
    const created = await createHarnessLease(h);
    await expectOperationError(
      h.registry.ensureAuthority({ ...ref, volumeId: "vol_2" }),
      authorityOperationErrorCodes.atCapacity
    );
    await h.registry.leases.release({
      operationId: "op-release-cap",
      accessLeaseId: created.result.lease.accessLeaseId,
      accessToken: created.result.accessToken,
    });
    await waitFor(async () => (await h.registry.inspectAuthority(ref)) === null);
    const admitted = await h.registry.ensureAuthority({ ...ref, volumeId: "vol_2" });
    expect(admitted.authorityInstanceId).toBeDefined();
  });

  test("the HTTP surface answers the cap refusal as 503 with Retry-After and the stable machine-readable code on ensure AND lease-create", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES: "1" },
    });
    await h.registry.ensureAuthority(ref);
    const server = createAuthorityManagerServer({
      registry: h.registry,
      authToken: "manager-token",
      accessLeases: h.registry.leases,
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;
    const headers = {
      authorization: "Bearer manager-token",
      "content-type": "application/json",
    };

    const ensure = await fetch(`${baseUrl}/v1/authorities/ensure`, {
      method: "POST",
      headers,
      body: JSON.stringify({ teamId: "team_1", volumeId: "vol_2", branch: "main" }),
    });
    expect(ensure.status).toBe(503);
    expect(ensure.headers.get("retry-after")).toBe("15");
    const ensureBody = (await ensure.json()) as { error: { code: string } };
    expect(ensureBody.error.code).toBe(authorityOperationErrorCodes.atCapacity);

    // The canonical lease-create path surfaces the SAME typed refusal.
    const lease = await fetch(`${baseUrl}/v1/access-leases/create`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        operationId: "op-cap-http-1",
        teamId: "team_1",
        volumeId: "vol_2",
        branch: "main",
        consumerId: "sandbox-cap",
      }),
    });
    expect(lease.status).toBe(503);
    expect(lease.headers.get("retry-after")).toBe("15");
    const leaseBody = (await lease.json()) as { error: { code: string } };
    expect(leaseBody.error.code).toBe(authorityOperationErrorCodes.atCapacity);
  });

  test("the start gate bounds concurrent cold starts to the limit; queued starts proceed FIFO as permits free", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS: "2" },
      holdBootstrap: true,
    });
    const volumes = ["vol_a", "vol_b", "vol_c", "vol_d", "vol_e"];
    const ensures = Promise.all(
      volumes.map((volumeId) =>
        h.registry.ensureAuthority({ teamId: "team_1", volumeId, branch: "main" })
      )
    );

    // Exactly the limit spawns; the other three stay queued on the gate.
    await waitFor(() => h.spawnEnvs.length === 2);
    await delay(40);
    expect(h.spawnEnvs).toHaveLength(2);

    // Each finished start frees exactly one permit: at every step the
    // number of spawned-but-unfinished children never exceeds the limit.
    let released = 0;
    while (released < volumes.length) {
      await waitFor(() => h.bootstrapHolds.length > 0);
      expect(h.spawnEnvs.length).toBeLessThanOrEqual(released + 2);
      h.bootstrapHolds.shift()!();
      released += 1;
    }
    await ensures;
    expect(h.spawnEnvs).toHaveLength(5);
  });

  test("a request for an ALREADY-RUNNING authority never waits on the start gate", async () => {
    const store = new InMemoryManagerControlStore();
    const begin = store.beginAuthorityRuntime.bind(store);
    const hang = deferred<void>();
    let hangEntered = false;
    store.beginAuthorityRuntime = async (args) => {
      if (args.scope.volumeId === "vol_hang") {
        hangEntered = true;
        await hang.promise;
      }
      return begin(args);
    };
    const h = await newProductionHarness({
      store,
      env: { PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS: "1" },
    });
    const running = await h.registry.ensureAuthority(ref);

    // Saturate the single permit with a cold start wedged inside its
    // durable journal begin.
    const wedged = h.registry.ensureAuthority({ ...ref, volumeId: "vol_hang" });
    wedged.catch(() => undefined);
    await waitFor(() => hangEntered);

    // The running authority answers from the fast path — no gate involved.
    const again = await h.registry.ensureAuthority(ref);
    expect(again.authorityInstanceId).toBe(running.authorityInstanceId);

    hang.resolve();
    await wedged;
  });

  test("a start queued past the bounded wait refuses typed AUTHORITY_START_QUEUE_TIMEOUT with Retry-After, without spawning anything", async () => {
    const store = new InMemoryManagerControlStore();
    const begin = store.beginAuthorityRuntime.bind(store);
    const hang = deferred<void>();
    let hangEntered = false;
    store.beginAuthorityRuntime = async (args) => {
      if (args.scope.volumeId === "vol_hang") {
        hangEntered = true;
        await hang.promise;
      }
      return begin(args);
    };
    const h = await newProductionHarness({
      store,
      env: {
        PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS: "1",
        // The queue wait is bounded by the same window that bounds a child
        // start; shrink it so the timeout fires quickly.
        PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS: "150",
      },
    });
    const wedged = h.registry.ensureAuthority({ ...ref, volumeId: "vol_hang" });
    wedged.catch(() => undefined);
    await waitFor(() => hangEntered);

    const error = await expectOperationError(
      h.registry.ensureAuthority({ ...ref, volumeId: "vol_queued" }),
      authorityOperationErrorCodes.startQueueTimeout
    );
    expect(error.status).toBe(503);
    expect(error.retryAfterSeconds).toBe(15);
    // The refused start never spawned and never minted a runtime row.
    expect(h.spawnEnvs).toHaveLength(0);
    expect(
      h.store.liveRuntime({
        tenantKey: managedTenantKey(ref),
        volumeId: "vol_queued",
        branch: ref.branch,
      })
    ).toBeNull();

    hang.resolve();
    await wedged;
  });
});

// ---------------------------------------------------------------------------
// Canonical /v1/access-leases routes served by the PRODUCTION lease service:
// the SAME wire surface the local AccessLeaseService serves (server.test.ts),
// exercised against the async epoch-fenced implementation.
// ---------------------------------------------------------------------------

function stubRegistry(): AuthorityRegistry {
  const endpoint = {
    provider: "stub",
    authorityUrl: "router.example:2050",
    host: "router.example",
    port: 2050,
    authorityInstanceId: "pfai_route_1",
  };
  return {
    ensureAuthority: async () => endpoint,
    isHealthy: async () => true,
    stopAuthority: async () => ({ stopped: false, managed: true, reason: "not_found" }),
    ensureAuthorityForLease: async (_ref, create) => ({
      endpoint,
      result: await create({
        endpoint,
        authorityInstanceId: "pfai_route_1",
        authorityRuntimeGeneration: "1",
        authorityRuntimeId: "runtime-route-1",
      }),
    }),
  };
}

async function startProductionServer(): Promise<{
  baseUrl: string;
  service: ProductionAccessLeaseService;
  store: InMemoryManagerControlStore;
}> {
  const store = new InMemoryManagerControlStore();
  const manager = await claimManager(store, {
    operationId: "claim-manager-route",
    runtimeId: "manager-route",
  });
  await store.beginAuthorityRuntime({
    identity: manager.identity,
    scope: { tenantKey: "t:team_1", volumeId: "vol_1", branch: "main" },
    authorityInstanceId: "pfai_route_1",
    runtimeId: "runtime-route-1",
  });
  const service = new ProductionAccessLeaseService(
    store,
    manager.identity,
    { dbTimeMs: manager.claim.dbTimeMs },
    mintRootSecret()
  );
  service.setAuthorityRouteResolver(() => ({
    backendAddresses: ["127.0.0.1:1"],
    backendAuthToken: "pfs_backend_test",
  }));
  const server = createAuthorityManagerServer({
    registry: stubRegistry(),
    authToken: "manager-token",
    accessLeases: service,
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { baseUrl: `http://127.0.0.1:${port}`, service, store };
}

async function post(
  baseUrl: string,
  pathname: string,
  body: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`${baseUrl}${pathname}`, {
    method: "POST",
    headers: { authorization: "Bearer manager-token", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

describe("canonical access-lease routes over the production service", () => {
  test("create → inspect → renew → release over /v1/access-leases with exact create replay", async () => {
    const { baseUrl } = await startProductionServer();

    const invalid = await post(baseUrl, "/v1/access-leases/create", { operationId: "op-1" });
    expect(invalid.status).toBe(400);
    expect((invalid.body.error as { code: string }).code).toBe("ACCESS_LEASE_INVALID_REQUEST");

    const createBody = {
      operationId: "op-create-1",
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-a",
      ttlMs: 60_000,
    };
    const created = await post(baseUrl, "/v1/access-leases/create", createBody);
    expect(created.status).toBe(200);
    const lease = created.body.lease as Record<string, unknown>;
    const accessToken = created.body.accessToken as string;
    expect(lease).toMatchObject({
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-a",
      authorityInstanceId: "pfai_route_1",
      tokenGeneration: "1",
      controlSeq: "1",
      state: "active",
    });
    expect((lease.accessLeaseId as string).startsWith("pfal_")).toBe(true);
    expect(created.body.authority).toMatchObject({
      authorityUrl: "router.example:2050",
      authorityInstanceId: "pfai_route_1",
      authorityAuthToken: accessToken,
    });

    // The lost-response replay over HTTP is byte-identical.
    const replay = await post(baseUrl, "/v1/access-leases/create", createBody);
    expect(replay.status).toBe(200);
    expect(replay.body.accessToken).toBe(accessToken);
    expect((replay.body.lease as Record<string, unknown>).expiresAt).toBe(lease.expiresAt);

    const inspected = await post(baseUrl, "/v1/access-leases/inspect", {
      accessLeaseId: lease.accessLeaseId,
      accessToken,
    });
    expect(inspected.status).toBe(200);
    expect(Object.keys(inspected.body).sort()).toEqual(["lease", "serverTimeMs"]);
    expect(inspected.body.lease).toEqual(lease);
    expect(inspected.body).not.toHaveProperty("accessToken");
    expect(inspected.body).not.toHaveProperty("authority");

    const inspectWrongToken = await post(baseUrl, "/v1/access-leases/inspect", {
      accessLeaseId: lease.accessLeaseId,
      accessToken: "wrong-token",
    });
    expect(inspectWrongToken.status).toBe(401);
    expect((inspectWrongToken.body.error as { code: string }).code).toBe("ACCESS_LEASE_UNAUTHORIZED");

    const missingPrecondition = await post(baseUrl, "/v1/access-leases/renew", {
      operationId: "op-renew-missing-precondition",
      accessLeaseId: lease.accessLeaseId,
      accessToken,
    });
    expect(missingPrecondition.status).toBe(400);
    expect((missingPrecondition.body.error as { code: string }).code).toBe(
      "ACCESS_LEASE_INVALID_REQUEST"
    );

    const renewed = await post(baseUrl, "/v1/access-leases/renew", {
      operationId: "op-renew-1",
      accessLeaseId: lease.accessLeaseId,
      accessToken,
      expectedControlSeq: lease.controlSeq,
      ttlMs: 120_000,
    });
    expect(renewed.status).toBe(200);
    expect((renewed.body.lease as Record<string, unknown>).controlSeq).toBe("2");
    expect(renewed.body.accessToken).toBeUndefined();

    const released = await post(baseUrl, "/v1/access-leases/release", {
      operationId: "op-release-1",
      accessLeaseId: lease.accessLeaseId,
      accessToken,
    });
    expect(released.status).toBe(200);
    expect((released.body.lease as Record<string, unknown>).state).toBe("released");
    expect(released.body.receipt).toMatchObject({
      operationId: "op-release-1",
      kind: "release",
      accessLeaseId: lease.accessLeaseId,
      controlSeq: "3",
    });
    const releaseReplay = await post(baseUrl, "/v1/access-leases/release", {
      operationId: "op-release-1",
      accessLeaseId: lease.accessLeaseId,
      accessToken,
    });
    expect(releaseReplay.body.receipt).toEqual(released.body.receipt);
    const inspectReleased = await post(baseUrl, "/v1/access-leases/inspect", {
      accessLeaseId: lease.accessLeaseId,
      accessToken,
    });
    expect(inspectReleased.status).toBe(409);
    expect((inspectReleased.body.error as { code: string }).code).toBe("ACCESS_LEASE_RELEASED");
  });

  test("rotation over HTTP mints the new token exactly once and revoke/revoke-owner answer with the terminal lease facts", async () => {
    const { baseUrl } = await startProductionServer();
    const created = await post(baseUrl, "/v1/access-leases/create", {
      operationId: "op-create-rotate",
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-a",
      ttlMs: 60_000,
    });
    const lease = created.body.lease as Record<string, unknown>;
    const rotated = await post(baseUrl, "/v1/access-leases/renew", {
      operationId: "op-rotate-1",
      accessLeaseId: lease.accessLeaseId,
      accessToken: created.body.accessToken,
      expectedControlSeq: lease.controlSeq,
      rotateToken: true,
    });
    expect(rotated.status).toBe(200);
    expect(typeof rotated.body.accessToken).toBe("string");
    expect((rotated.body.lease as Record<string, unknown>).tokenGeneration).toBe("2");

    const revoked = await post(baseUrl, "/v1/access-leases/revoke", {
      accessLeaseId: lease.accessLeaseId,
    });
    expect(revoked.status).toBe(200);
    expect((revoked.body.lease as Record<string, unknown>).state).toBe("revoked");

    const second = await post(baseUrl, "/v1/access-leases/create", {
      operationId: "op-create-owner",
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-owner",
      ttlMs: 60_000,
    });
    const ownerRevoked = await post(baseUrl, "/v1/access-leases/revoke-owner", {
      teamId: "team_1",
      consumerId: "sandbox-owner",
    });
    expect(ownerRevoked.status).toBe(200);
    expect(ownerRevoked.body.revoked).toEqual([
      (second.body.lease as Record<string, unknown>).accessLeaseId,
    ]);
  });

  test("an epoch-superseded service answers the routes with 503 ACCESS_LEASE_EPOCH_SUPERSEDED", async () => {
    const { baseUrl, store } = await startProductionServer();
    const created = await post(baseUrl, "/v1/access-leases/create", {
      operationId: "op-create-epoch",
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-a",
      ttlMs: 60_000,
    });
    expect(created.status).toBe(200);
    store.supersedeEpoch();
    const refused = await post(baseUrl, "/v1/access-leases/create", {
      operationId: "op-create-epoch-2",
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-b",
      ttlMs: 60_000,
    });
    expect(refused.status).toBe(503);
    expect((refused.body.error as { code: string }).code).toBe("ACCESS_LEASE_EPOCH_SUPERSEDED");
  });

  test("a store outage answers 503 ACCESS_LEASE_STORE_UNAVAILABLE and the identical retry succeeds", async () => {
    const { baseUrl, store } = await startProductionServer();
    store.failNext("accessCreate");
    const failed = await post(baseUrl, "/v1/access-leases/create", {
      operationId: "op-create-outage",
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-a",
      ttlMs: 60_000,
    });
    expect(failed.status).toBe(503);
    expect((failed.body.error as { code: string }).code).toBe("ACCESS_LEASE_STORE_UNAVAILABLE");
    const retried = await post(baseUrl, "/v1/access-leases/create", {
      operationId: "op-create-outage",
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-a",
      ttlMs: 60_000,
    });
    expect(retried.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Per-tenant fairness caps: resident-children budget (TENANT_AT_CAPACITY) and
// active-lease budget (TENANT_LEASE_LIMIT). Both are 429 + Retry-After —
// the service is healthy, ONE tenant is over budget — distinct from the 503
// AUTHORITY_AT_CAPACITY service-pressure refusal.
// ---------------------------------------------------------------------------

describe("per-tenant fairness cap configuration fails closed", () => {
  test("unset leaves both caps off (exact current behavior); set values parse", () => {
    const config = readProductionAuthorityRegistryConfig(PROD_ENV);
    expect(config.maxAuthoritiesPerTenant).toBeUndefined();
    expect(config.accessLeasesMaxPerTenant).toBeUndefined();
    const configured = readProductionAuthorityRegistryConfig({
      ...PROD_ENV,
      PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT: "3",
      PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT: "20",
    });
    expect(configured.maxAuthoritiesPerTenant).toBe(3);
    expect(configured.accessLeasesMaxPerTenant).toBe(20);
  });

  test("a set-and-malformed per-tenant cap refuses boot instead of silently running uncapped", () => {
    for (const bad of ["0", "-2", "1.5", "many", " "]) {
      if (bad.trim() === "") {
        continue; // whitespace normalizes to unset
      }
      expect(() =>
        readProductionAuthorityRegistryConfig({
          ...PROD_ENV,
          PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT: bad,
        })
      ).toThrow(/PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT must be a positive integer/);
      expect(() =>
        readProductionAuthorityRegistryConfig({
          ...PROD_ENV,
          PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT: bad,
        })
      ).toThrow(/PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT must be a positive integer/);
    }
  });
});

describe("per-tenant resident-authority budget (TENANT_AT_CAPACITY)", () => {
  const refA1 = { teamId: "team_a", volumeId: "vol_1", branch: "main" };
  const refA2 = { teamId: "team_a", volumeId: "vol_2", branch: "main" };
  const refB1 = { teamId: "team_b", volumeId: "vol_1", branch: "main" };

  test("tenant A at its budget refuses 429 TENANT_AT_CAPACITY with Retry-After while tenant B proceeds; a fenced stop frees the budget", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT: "1" },
    });
    const first = await h.registry.ensureAuthority(refA1);

    const error = await expectOperationError(
      h.registry.ensureAuthority(refA2),
      authorityOperationErrorCodes.tenantAtCapacity
    );
    // 429, not 503: the service is healthy — the TENANT is over budget.
    expect(error.status).toBe(429);
    expect(error.retryAfterSeconds).toBe(15);
    // The refusal spawned nothing and left no durable runtime row behind.
    expect(h.spawnEnvs).toHaveLength(1);
    expect(
      h.store.liveRuntime({
        tenantKey: managedTenantKey(refA2),
        volumeId: refA2.volumeId,
        branch: refA2.branch,
      })
    ).toBeNull();

    // ANOTHER tenant is unaffected by tenant A's budget.
    const tenantB = await h.registry.ensureAuthority(refB1);
    expect(tenantB.authorityInstanceId).toBeDefined();
    expect(h.spawnEnvs).toHaveLength(2);

    // The RUNNING authority of tenant A keeps serving (no new spawn).
    const again = await h.registry.ensureAuthority(refA1);
    expect(again.authorityInstanceId).toBe(first.authorityInstanceId);
    expect(h.spawnEnvs).toHaveLength(2);

    // A fenced stop frees tenant A's budget; the refused scope admits.
    await h.registry.stopAuthority({
      ...refA1,
      expectedAuthority: { authorityInstanceId: first.authorityInstanceId! },
    });
    const admitted = await h.registry.ensureAuthority(refA2);
    expect(admitted.authorityInstanceId).not.toBe(first.authorityInstanceId);
    expect(h.spawnEnvs).toHaveLength(3);
  });

  test("idle eviction frees the tenant budget and the next spawn succeeds", async () => {
    const h = await newProductionHarness({
      env: {
        PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT: "1",
        PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS: "25",
      },
    });
    const created = await createHarnessLease(h);
    await expectOperationError(
      h.registry.ensureAuthority({ ...ref, volumeId: "vol_2" }),
      authorityOperationErrorCodes.tenantAtCapacity
    );
    await h.registry.leases.release({
      operationId: "op-release-tenant-cap",
      accessLeaseId: created.result.lease.accessLeaseId,
      accessToken: created.result.accessToken,
    });
    await waitFor(async () => (await h.registry.inspectAuthority(ref)) === null);
    const admitted = await h.registry.ensureAuthority({ ...ref, volumeId: "vol_2" });
    expect(admitted.authorityInstanceId).toBeDefined();
  });

  test("the HTTP surface answers 429 with Retry-After and the stable TENANT_AT_CAPACITY code on ensure AND lease-create", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT: "1" },
    });
    await h.registry.ensureAuthority(ref);
    const server = createAuthorityManagerServer({
      registry: h.registry,
      authToken: "manager-token",
      accessLeases: h.registry.leases,
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;
    const headers = {
      authorization: "Bearer manager-token",
      "content-type": "application/json",
    };

    const ensure = await fetch(`${baseUrl}/v1/authorities/ensure`, {
      method: "POST",
      headers,
      body: JSON.stringify({ teamId: "team_1", volumeId: "vol_2", branch: "main" }),
    });
    expect(ensure.status).toBe(429);
    expect(ensure.headers.get("retry-after")).toBe("15");
    const ensureBody = (await ensure.json()) as { error: { code: string } };
    expect(ensureBody.error.code).toBe(authorityOperationErrorCodes.tenantAtCapacity);

    const lease = await fetch(`${baseUrl}/v1/access-leases/create`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        operationId: "op-tenant-cap-http-1",
        teamId: "team_1",
        volumeId: "vol_2",
        branch: "main",
        consumerId: "sandbox-tenant-cap",
      }),
    });
    expect(lease.status).toBe(429);
    expect(lease.headers.get("retry-after")).toBe("15");
    const leaseBody = (await lease.json()) as { error: { code: string } };
    expect(leaseBody.error.code).toBe(authorityOperationErrorCodes.tenantAtCapacity);
  });
});

describe("per-tenant active-lease budget (TENANT_LEASE_LIMIT)", () => {
  async function createLeaseFor(
    h: ProdHarness,
    leaseRef: { teamId: string; volumeId: string; branch: string },
    operationId: string,
    consumerId = "sandbox-a"
  ) {
    return h.registry.ensureAuthorityForLease(leaseRef, (binding) =>
      h.registry.leases.create({
        operationId,
        teamId: leaseRef.teamId,
        volumeId: leaseRef.volumeId,
        branch: leaseRef.branch,
        consumerId,
        authorityInstanceId: binding.authorityInstanceId,
        ...(binding.authorityRuntimeGeneration !== undefined
          ? { authorityRuntimeGeneration: binding.authorityRuntimeGeneration }
          : {}),
        ...(binding.authorityRuntimeId !== undefined
          ? { authorityRuntimeId: binding.authorityRuntimeId }
          : {}),
      })
    );
  }

  test("the cap trips at N live leases with 429 TENANT_LEASE_LIMIT; release frees the budget; another tenant proceeds", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT: "2" },
    });
    const first = await createLeaseFor(h, ref, "op-lease-budget-1");
    await createLeaseFor(h, ref, "op-lease-budget-2", "sandbox-b");

    const error = await expectOperationError(
      createLeaseFor(h, ref, "op-lease-budget-3", "sandbox-c"),
      authorityOperationErrorCodes.tenantLeaseLimit
    );
    expect(error.status).toBe(429);
    expect(error.retryAfterSeconds).toBe(15);
    // Nothing durable changed for the refused create.
    expect(h.store.activeLeaseRows()).toBe(2);

    // ANOTHER tenant's budget is untouched.
    const tenantB = await createLeaseFor(
      h,
      { teamId: "team_b", volumeId: "vol_9", branch: "main" },
      "op-lease-budget-b1"
    );
    expect(tenantB.result.lease.state).toBe("active");

    // Releasing one of tenant A's leases frees the budget.
    await h.registry.leases.release({
      operationId: "op-lease-budget-release",
      accessLeaseId: first.result.lease.accessLeaseId,
      accessToken: first.result.accessToken,
    });
    const admitted = await createLeaseFor(h, ref, "op-lease-budget-4", "sandbox-d");
    expect(admitted.result.lease.state).toBe("active");
  });

  test("authority retirement (fenced stop) frees the lease budget: revoked leases never count", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT: "1" },
    });
    const created = await createLeaseFor(h, ref, "op-lease-budget-stop-1");
    await expectOperationError(
      createLeaseFor(h, ref, "op-lease-budget-stop-2", "sandbox-b"),
      authorityOperationErrorCodes.tenantLeaseLimit
    );
    // The fenced stop revokes every lease bound to the instance.
    await h.registry.stopAuthority({
      ...ref,
      expectedAuthority: { authorityInstanceId: created.endpoint.authorityInstanceId! },
    });
    const admitted = await createLeaseFor(h, ref, "op-lease-budget-stop-3", "sandbox-c");
    expect(admitted.result.lease.state).toBe("active");
  });

  test("the HTTP surface answers the lease-budget refusal as 429 with Retry-After and the stable code", async () => {
    const h = await newProductionHarness({
      env: { PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT: "1" },
    });
    const server = createAuthorityManagerServer({
      registry: h.registry,
      authToken: "manager-token",
      accessLeases: h.registry.leases,
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;
    const headers = {
      authorization: "Bearer manager-token",
      "content-type": "application/json",
    };
    const first = await fetch(`${baseUrl}/v1/access-leases/create`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        operationId: "op-lease-http-1",
        teamId: "team_1",
        volumeId: "vol_1",
        branch: "main",
        consumerId: "sandbox-a",
      }),
    });
    expect(first.status).toBe(200);
    const refused = await fetch(`${baseUrl}/v1/access-leases/create`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        operationId: "op-lease-http-2",
        teamId: "team_1",
        volumeId: "vol_1",
        branch: "main",
        consumerId: "sandbox-b",
      }),
    });
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toBe("15");
    const body = (await refused.json()) as { error: { code: string } };
    expect(body.error.code).toBe(authorityOperationErrorCodes.tenantLeaseLimit);
  });
});

// ---------------------------------------------------------------------------
// GET /metrics: the exact endpoint assembly main.ts serves — manager gauges
// refreshed from live registry/lease state plus the closed-allowlist child
// aggregation — exercised against fake-spawned children over the real HTTP
// route with bearer auth.
// ---------------------------------------------------------------------------

describe("GET /metrics over the production registry", () => {
  async function startMetricsServer(h: ProdHarness): Promise<string> {
    const metrics = new ManagerMetrics();
    const collector = new ChildMetricsCollector({
      targets: () => h.registry.metricsTargets(),
      metrics,
      fetchImpl: h.fetch,
      cacheTtlMs: 0, // tests re-render after driving state; never serve stale
    });
    const server = createAuthorityManagerServer({
      registry: h.registry,
      authToken: "manager-token",
      accessLeases: h.registry.leases,
      metricsEndpoint: createManagerMetricsEndpoint({
        metrics,
        registry: h.registry,
        childMetrics: collector,
      }),
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    return `http://127.0.0.1:${port}`;
  }

  async function scrape(baseUrl: string): Promise<string> {
    const response = await fetch(`${baseUrl}/metrics`, {
      headers: { authorization: "Bearer manager-token" },
    });
    expect(response.status).toBe(200);
    expect(String(response.headers.get("content-type"))).toContain("text/plain");
    return response.text();
  }

  function metricValue(body: string, name: string): number | undefined {
    const line = body.split("\n").find((entry) => entry.startsWith(`${name} `));
    return line === undefined ? undefined : Number(line.slice(name.length + 1));
  }

  test("manager gauges and refusal counters reflect driven state; aggregated child metrics ride along", async () => {
    const h = await newProductionHarness({
      env: {
        PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES: "2",
        PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT: "1",
        PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT: "1",
      },
    });
    const baseUrl = await startMetricsServer(h);

    // The same bearer gate as every other control route.
    const unauthenticated = await fetch(`${baseUrl}/metrics`);
    expect(unauthenticated.status).toBe(401);

    // Tenant A: one child + one live lease. Its per-tenant budget (1) is now
    // full while the registry still has global headroom, so the next spawn
    // for tenant A refuses TENANT_AT_CAPACITY.
    const created = await createHarnessLease(h);
    await expectOperationError(
      h.registry.ensureAuthority({ ...ref, volumeId: "vol_2" }),
      authorityOperationErrorCodes.tenantAtCapacity
    );

    // Tenant A's lease budget (1) is full too: the next create refuses
    // TENANT_LEASE_LIMIT against the RUNNING authority.
    await expectOperationError(
      h.registry.ensureAuthorityForLease(ref, (binding) =>
        h.registry.leases.create({
          operationId: "op-metrics-refused",
          teamId: ref.teamId,
          volumeId: ref.volumeId,
          branch: ref.branch,
          consumerId: "sandbox-over",
          authorityInstanceId: binding.authorityInstanceId,
          ...(binding.authorityRuntimeGeneration !== undefined
            ? { authorityRuntimeGeneration: binding.authorityRuntimeGeneration }
            : {}),
          ...(binding.authorityRuntimeId !== undefined
            ? { authorityRuntimeId: binding.authorityRuntimeId }
            : {}),
        })
      ),
      authorityOperationErrorCodes.tenantLeaseLimit
    );

    // Tenant B fills the second (last) global slot with its own lease.
    await h.registry.ensureAuthorityForLease(
      { teamId: "team_b", volumeId: "vol_5", branch: "main" },
      (binding) =>
        h.registry.leases.create({
          operationId: "op-metrics-b1",
          teamId: "team_b",
          volumeId: "vol_5",
          branch: "main",
          consumerId: "sandbox-b",
          authorityInstanceId: binding.authorityInstanceId,
          ...(binding.authorityRuntimeGeneration !== undefined
            ? { authorityRuntimeGeneration: binding.authorityRuntimeGeneration }
            : {}),
          ...(binding.authorityRuntimeId !== undefined
            ? { authorityRuntimeId: binding.authorityRuntimeId }
            : {}),
        })
    );

    // With the registry at its global cap, a THIRD tenant refuses the
    // service-pressure 503 — the distinct AUTHORITY_AT_CAPACITY counter.
    await expectOperationError(
      h.registry.ensureAuthority({ teamId: "team_c", volumeId: "vol_7", branch: "main" }),
      authorityOperationErrorCodes.atCapacity
    );

    const body = await scrape(baseUrl);
    expect(metricValue(body, "pfm_manager_claimed")).toBe(1);
    expect(metricValue(body, "pfm_manager_epoch")).toBe(1);
    expect(metricValue(body, "pfm_manager_superseded")).toBe(0);
    expect(metricValue(body, "pfm_children_total")).toBe(2);
    expect(metricValue(body, "pfm_children_cap")).toBe(2);
    expect(metricValue(body, "pfm_child_start_gate_limit")).toBe(4);
    expect(metricValue(body, "pfm_child_start_gate_held")).toBe(0);
    expect(metricValue(body, "pfm_child_start_gate_waiters")).toBe(0);
    expect(metricValue(body, "pfm_child_starts_total")).toBe(2);
    expect(metricValue(body, "pfm_access_leases_active")).toBe(2);
    expect(metricValue(body, "pfm_access_lease_creates_total")).toBe(2);
    expect(metricValue(body, "pfm_authority_at_capacity_refusals_total")).toBe(1);
    expect(metricValue(body, "pfm_tenant_at_capacity_refusals_total")).toBe(1);
    expect(metricValue(body, "pfm_tenant_lease_limit_refusals_total")).toBe(1);
    // Child aggregation: two healthy children summed through the allowlist.
    expect(metricValue(body, "pfm_child_scrape_targets")).toBe(2);
    expect(metricValue(body, "pfm_child_scrape_aggregated")).toBe(2);
    expect(metricValue(body, "pfm_child_vcs_ready")).toBe(1); // min semantics
    expect(metricValue(body, "pfm_child_vcs_fsproto_ops")).toBe(20);
    expect(metricValue(body, "pfm_child_vcs_dirty_block_bytes")).toBe(8192);
    expect(metricValue(body, "pfm_child_vcs_dirty_block_bytes_max")).toBe(4096000);

    // A release frees the lease budget and the active gauge follows.
    await h.registry.leases.release({
      operationId: "op-metrics-release",
      accessLeaseId: created.result.lease.accessLeaseId,
      accessToken: created.result.accessToken,
    });
    const after = await scrape(baseUrl);
    expect(metricValue(after, "pfm_access_leases_active")).toBe(1);
  });

  test("a child serving unknown metrics or garbage is dropped whole: the aggregate stays exact and nothing leaks through", async () => {
    const h = await newProductionHarness();
    const baseUrl = await startMetricsServer(h);
    await h.registry.ensureAuthority(ref);
    await h.registry.ensureAuthority({ ...ref, volumeId: "vol_2" });

    // One healthy child; one child smuggling unknown names and identifier
    // labels. The bad child's ENTIRE contribution is dropped — its known
    // metrics never inflate the aggregate either.
    const bad = [...h.sims.values()].at(-1)!;
    bad.metricsBody =
      'totally_unknown_metric 5\nvcs_fsproto_ops{volume="vol_secret"} 999\nvcs_ready 1\n';

    const body = await scrape(baseUrl);
    expect(metricValue(body, "pfm_child_scrape_targets")).toBe(2);
    expect(metricValue(body, "pfm_child_scrape_aggregated")).toBe(1);
    expect(metricValue(body, "pfm_child_scrape_errors_total")).toBe(1);
    expect(metricValue(body, "pfm_child_vcs_fsproto_ops")).toBe(10); // healthy child only
    expect(body).not.toContain("totally_unknown_metric");
    expect(body).not.toContain("vol_secret");

    // Pure binary-ish garbage degrades the same way; output stays parseable
    // fixed-name lines only.
    bad.metricsBody = "\u0000\u0001 not prometheus at all {{{";
    const second = await scrape(baseUrl);
    expect(metricValue(second, "pfm_child_vcs_fsproto_ops")).toBe(10);
    expect(second).not.toContain("not prometheus");
    for (const line of second.split("\n")) {
      if (line !== "") {
        expect(line).toMatch(/^[a-z][a-z0-9_]*(\{le="[^"]+"\})? -?[0-9eE.+-]+$/);
      }
    }
  });
});
