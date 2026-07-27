import { describe, expect, test } from "vitest";
import pg from "pg";
import { parseAccessLeaseControlSeq } from "@portablefs/protocol";
import {
  AccessLeaseNotActiveError,
  ControlDurabilityUnavailableError,
  ControlNotFoundError,
  ControlOperationConflictError,
  ControlReceiptEvictedError,
  ControlStoreUnavailableError,
  InMemoryManagerControlStore,
  InvalidControlArgumentError,
  ManagerClaimHeldError,
  ManagerEpochSupersededError,
  PostgresManagerControlStore,
  fingerprintOfCanonicalParts,
  hmacOfCanonicalParts,
  managedTenantKey,
  mapManagerControlError,
  parseAccessLeaseFacts,
  parseAccessSweepResult,
  runtimeEndOperationId,
  sha256Hex,
  validateAccessProjection,
  type ManagerClaimResult,
  type ManagerControlPool,
  type ManagerIdentity,
} from "./manager-control-store.js";

const leaseFacts = {
  leaseId: "pfal_test",
  tenantKey: "t:tenant",
  volumeId: "vol_test",
  branch: "main",
  consumerId: "consumer",
  authorityInstanceId: "authority",
  authorityRuntimeSeq: "9007199254740993",
  authorityRuntimeId: "runtime",
  managerEpoch: "9007199254740995",
  tokenGeneration: "9007199254740997",
  controlSeq: "9007199254740999",
  state: "active",
  expiresAt: "1783719999999",
  createdAtMs: "1783710000000",
} as const;

interface ClaimedManager {
  claim: ManagerClaimResult;
  identity: ManagerIdentity;
}

async function claimManager(
  store: InMemoryManagerControlStore,
  args: {
    operationId: string;
    runtimeId: string;
    capability?: string;
    ttlMs?: number;
  }
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

describe("manager control boundaries", () => {
  test("uses injective fingerprints and domain-separated length-delimited HMACs", () => {
    expect(fingerprintOfCanonicalParts(["ab", "c"])).not.toBe(fingerprintOfCanonicalParts(["a", "bc"]));
    const first = hmacOfCanonicalParts("manager-secret", ["runtime-cap-v1", "ab", "c"]);
    expect(first).toMatch(/^[0-9a-f]{64}$/u);
    expect(first).toBe(hmacOfCanonicalParts("manager-secret", ["runtime-cap-v1", "ab", "c"]));
    expect(first).not.toBe(hmacOfCanonicalParts("manager-secret", ["runtime-cap-v1", "a", "bc"]));
    expect(first).not.toBe(hmacOfCanonicalParts("manager-secret", ["different-domain", "ab", "c"]));
    expect(first).not.toContain("manager-secret");
  });

  test("managedTenantKey is the ONE canonical namespace and refuses a missing tenant", () => {
    expect(managedTenantKey({ teamId: "team_1", volumeId: "vol_1" })).toBe("t:team_1");
    expect(() => managedTenantKey({ volumeId: "vol_1" })).toThrow(InvalidControlArgumentError);
  });

  test("preserves counters beyond 2^53 as canonical decimals and parses only safe decimal times", () => {
    const parsed = parseAccessLeaseFacts(leaseFacts);
    expect(parsed.authorityRuntimeSeq).toBe("9007199254740993");
    expect(parsed.managerEpoch).toBe("9007199254740995");
    expect(parsed.tokenGeneration).toBe("9007199254740997");
    expect(parsed.controlSeq).toBe("9007199254740999");
    expect(parsed.expiresAt).toBe(1_783_719_999_999);

    expect(() => parseAccessLeaseFacts({ ...leaseFacts, controlSeq: 2 })).toThrow(
      /controlSeq is missing/u
    );
    expect(() => parseAccessLeaseFacts({ ...leaseFacts, expiresAt: "9007199254740993" })).toThrow(
      /safe timestamp boundary/u
    );
    expect(() => parseAccessLeaseFacts({ ...leaseFacts, expiresAt: "01" })).toThrow(
      /canonical decimal string/u
    );
    expect(() => parseAccessLeaseFacts({ ...leaseFacts, tenantKey: undefined })).toThrow(
      /tenantKey is missing/u
    );
    expect(() => parseAccessLeaseFacts({ ...leaseFacts, endReason: "expired" })).toThrow(
      /active access lease carries terminal fields/u
    );
    expect(() =>
      parseAccessLeaseFacts({ ...leaseFacts, state: "released", endReason: "revoked" })
    ).toThrow(/incompatible end reason/u);
  });

  test("accepts only forward currentFacts projections of the same immutable access lease", () => {
    const receipted = parseAccessLeaseFacts(leaseFacts);
    const later = parseAccessLeaseFacts({
      ...leaseFacts,
      controlSeq: "9007199254741000",
      tokenGeneration: "9007199254741001",
      expiresAt: "1783720999999",
    });
    expect(() => validateAccessProjection(receipted, later)).not.toThrow();

    const projectedExpired = parseAccessLeaseFacts({
      ...leaseFacts,
      state: "expired",
      endReason: "expired",
    });
    expect(() => validateAccessProjection(receipted, projectedExpired)).not.toThrow();

    expect(() =>
      validateAccessProjection(receipted, parseAccessLeaseFacts({ ...leaseFacts, volumeId: "vol_other" }))
    ).toThrow(/immutable volumeId/u);
    expect(() =>
      validateAccessProjection(
        later,
        parseAccessLeaseFacts({ ...leaseFacts, controlSeq: "9007199254740998" })
      )
    ).toThrow(/regressed the lease control sequence/u);
    expect(() =>
      validateAccessProjection(
        later,
        parseAccessLeaseFacts({
          ...leaseFacts,
          controlSeq: "9007199254741000",
          tokenGeneration: "9007199254741001",
        })
      )
    ).toThrow(/regressed the lease expiry/u);

    const released = parseAccessLeaseFacts({
      ...leaseFacts,
      state: "released",
      endReason: "released",
      endedAtMs: "1783715000000",
    });
    expect(() => validateAccessProjection(released, receipted)).toThrow(
      /resurrected or rewrote a terminal lease/u
    );
  });

  test("maps receipt floors exactly and durability loss as retryable store unavailability", () => {
    const evicted = mapManagerControlError({
      code: "PF014",
      message: "receipt evicted",
      detail: JSON.stringify({ receiptFloorControlSeq: "9007199254740993" }),
    });
    expect(evicted).toBeInstanceOf(ControlReceiptEvictedError);
    expect((evicted as ControlReceiptEvictedError).receiptFloorControlSeq).toBe("9007199254740993");

    const evidence = { ready: false, synchronousStandbyNames: "" };
    const durability = mapManagerControlError({
      code: "PF015",
      message: "durability unavailable",
      detail: JSON.stringify(evidence),
    });
    expect(durability).toBeInstanceOf(ControlDurabilityUnavailableError);
    expect(durability).toBeInstanceOf(ControlStoreUnavailableError);
    expect((durability as ControlDurabilityUnavailableError).evidence).toEqual(evidence);

    const held = mapManagerControlError({
      code: "PF013",
      message: "claim held",
      detail: JSON.stringify({
        expiresAtDbMs: "1783719999999",
        dbTimeMs: "1783710000000",
        currentEpoch: "9007199254740993",
      }),
    });
    expect(held).toBeInstanceOf(ManagerClaimHeldError);
    expect((held as ManagerClaimHeldError).expiresAtDbMs).toBe(1_783_719_999_999);
    expect((held as ManagerClaimHeldError).currentEpoch).toBe("9007199254740993");

    expect(mapManagerControlError({ code: "PF001", message: "fenced" }, "7")).toBeInstanceOf(
      ManagerEpochSupersededError
    );
    expect(mapManagerControlError({ code: "PF007", message: "gone" })).toBeInstanceOf(
      ControlNotFoundError
    );
    expect(mapManagerControlError({ code: "PF012", message: "not active" })).toBeInstanceOf(
      AccessLeaseNotActiveError
    );
    expect(mapManagerControlError({ code: "PF009", message: "content" })).toBeInstanceOf(
      ControlOperationConflictError
    );
    expect(mapManagerControlError({ code: "PF008", message: "bad arg" })).toBeInstanceOf(
      InvalidControlArgumentError
    );
    expect(mapManagerControlError({ code: "ECONNREFUSED", message: "down" })).toBeInstanceOf(
      ControlStoreUnavailableError
    );
  });

  test("rejects malformed or non-monotonic access sweep receipt pages", () => {
    const expected = { operationId: "sweep-1", afterLeaseId: "pfal_a", limit: 2 };
    const valid = {
      operationId: "sweep-1",
      afterLeaseId: "pfal_a",
      limit: "2",
      endedLeaseIds: ["pfal_b", "pfal_c"],
      nextCursor: "pfal_c",
      hasMore: true,
      receiptFingerprint: "a".repeat(64),
      completedAtDbMs: "100",
      replayed: false,
      dbTimeMs: "101",
    };
    expect(parseAccessSweepResult(valid, expected)).toMatchObject({
      endedLeaseIds: ["pfal_b", "pfal_c"],
      nextCursor: "pfal_c",
      limit: 2,
    });

    const malformed: Array<[string, Record<string, unknown>]> = [
      ["duplicate", { ...valid, endedLeaseIds: ["pfal_b", "pfal_b"] }],
      ["unsorted", { ...valid, endedLeaseIds: ["pfal_c", "pfal_b"] }],
      ["before cursor", { ...valid, endedLeaseIds: ["pfal_a", "pfal_c"] }],
      ["over limit", { ...valid, endedLeaseIds: ["pfal_b", "pfal_c", "pfal_d"] }],
      ["cursor without more", { ...valid, hasMore: false }],
      ["more without cursor", { ...valid, nextCursor: null }],
      ["cursor not last", { ...valid, nextCursor: "pfal_b" }],
      ["future completion", { ...valid, completedAtDbMs: "102" }],
      ["missing cursor", { ...valid, nextCursor: undefined }],
    ];
    for (const [, body] of malformed) {
      expect(() => parseAccessSweepResult(body, expected)).toThrow(ControlStoreUnavailableError);
    }
  });
});

describe("runtimeEndOperationId", () => {
  test("one semantic end is deterministic; distinct reasons never collide; ids stay bounded", () => {
    const runtimeId = "pfrt_0b7a4a3e-6a4f-4e6f-9a53-4dd8f6f1c001";
    // Byte-exact for a lost-response retry of the SAME semantic end.
    expect(runtimeEndOperationId(runtimeId, "child-exited")).toBe(
      runtimeEndOperationId(runtimeId, "child-exited")
    );
    // Distinct competing reasons (the spawn-failure/child-exit race) carry
    // DISTINCT ids: no operation-content conflict on a shared id.
    const ids = new Set(
      [
        "child-exited",
        "start-failed",
        "failed-to-become-ready",
        "heartbeat-pipe-fenced",
        "replaced-unready",
        "stopped",
        "idle-evicted",
      ].map((reason) => runtimeEndOperationId(runtimeId, reason))
    );
    expect(ids.size).toBe(7);
    // Free-text reasons stay inside the 256-byte operation-id bound and are
    // slug+hash encoded (deterministic, filesystem/log safe).
    const forced = runtimeEndOperationId(runtimeId, `forced: ${"x".repeat(500)}`);
    expect(forced.length).toBeLessThanOrEqual(256);
    expect(forced.startsWith(`pfare_${runtimeId}_forced-x`)).toBe(true);
    // Reasons differing only past the slug bound still get distinct ids
    // through the content hash.
    expect(runtimeEndOperationId(runtimeId, `forced: ${"x".repeat(500)}y`)).not.toBe(forced);
  });
});

// ---------------------------------------------------------------------------
// InMemoryManagerControlStore: the rigorous fake the production stack is
// tested against (deterministic database clock, epoch fencing, permanent
// exact receipts, and fault injection).
// ---------------------------------------------------------------------------

describe("InMemoryManagerControlStore", () => {
  test("manager claims replay exactly, refuse overlap, and mint the next decimal epoch only after database-time expiry", async () => {
    let dbTime = 1_000_000;
    const store = new InMemoryManagerControlStore({ dbNow: () => dbTime });

    const first = await claimManager(store, {
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
      ttlMs: 30_000,
    });
    expect(first.claim).toMatchObject({
      managerEpoch: "1",
      dbTimeMs: 1_000_000,
      expiresAtDbMs: 1_030_000,
      current: true,
      replayed: false,
    });

    const replay = await store.claimManager({
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
      capabilityHash: sha256Hex("capability-manager-a"),
      ttlMs: 30_000,
    });
    expect(replay).toMatchObject({
      managerEpoch: "1",
      expiresAtDbMs: 1_030_000,
      current: true,
      replayed: true,
    });

    dbTime = 1_005_000;
    await store.renewManagerClaim({ identity: first.identity, ttlMs: 60_000 });
    const replayAfterRenew = await store.claimManager({
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
      capabilityHash: sha256Hex("capability-manager-a"),
      ttlMs: 30_000,
    });
    expect(replayAfterRenew.expiresAtDbMs).toBe(1_065_000);
    await expect(
      store.claimManager({
        operationId: "claim-manager-a",
        runtimeId: "manager-a",
        capabilityHash: sha256Hex("capability-manager-a"),
        ttlMs: 31_000,
      })
    ).rejects.toBeInstanceOf(ControlOperationConflictError);

    await expect(
      claimManager(store, {
        operationId: "claim-manager-b",
        runtimeId: "manager-b",
        ttlMs: 30_000,
      })
    ).rejects.toBeInstanceOf(ManagerClaimHeldError);

    dbTime = 1_065_001;
    const second = await claimManager(store, {
      operationId: "claim-manager-b",
      runtimeId: "manager-b",
      ttlMs: 30_000,
    });
    expect(second.claim.managerEpoch).toBe("2");
    await expect(store.renewManagerClaim({ identity: first.identity, ttlMs: 30_000 })).rejects.toBeInstanceOf(
      ManagerEpochSupersededError
    );
  });

  test("a wrong capability is fenced even under the right epoch and runtime id", async () => {
    const store = new InMemoryManagerControlStore();
    const manager = await claimManager(store, {
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
    });
    await expect(
      store.renewManagerClaim({
        identity: { ...manager.identity, managerCapability: "guessed-capability" },
        ttlMs: 30_000,
      })
    ).rejects.toBeInstanceOf(ManagerEpochSupersededError);
  });

  test("runtime generations are monotonic decimal strings per structured authority scope", async () => {
    const store = new InMemoryManagerControlStore();
    const manager = await claimManager(store, {
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
    });
    const scope = { tenantKey: "t:team_1", volumeId: "vol_1", branch: "main" };
    const first = await store.beginAuthorityRuntime({
      identity: manager.identity,
      scope,
      authorityInstanceId: "pfvcs_a",
      runtimeId: "runtime-a",
    });
    const second = await store.beginAuthorityRuntime({
      identity: manager.identity,
      scope,
      authorityInstanceId: "pfvcs_b",
      runtimeId: "runtime-b",
    });
    const otherScope = await store.beginAuthorityRuntime({
      identity: manager.identity,
      scope: { ...scope, branch: "feature" },
      authorityInstanceId: "pfvcs_c",
      runtimeId: "runtime-c",
    });
    expect(first.runtimeSeq).toBe("1");
    expect(second.runtimeSeq).toBe("2");
    expect(otherScope.runtimeSeq).toBe("1");
    expect(store.liveRuntime(scope)).toEqual({ runtimeSeq: "2", runtimeId: "runtime-b" });
  });

  test("authority runtime end is exactly receipted and keeps the FIRST terminal reason", async () => {
    const store = new InMemoryManagerControlStore();
    const manager = await claimManager(store, {
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
    });
    const scope = { tenantKey: "t:team_1", volumeId: "vol_1", branch: "main" };
    const runtime = await store.beginAuthorityRuntime({
      identity: manager.identity,
      scope,
      authorityInstanceId: "pfvcs_a",
      runtimeId: "runtime-a",
    });
    const ended = await store.endAuthorityRuntime({
      identity: manager.identity,
      scope,
      runtimeSeq: runtime.runtimeSeq,
      runtimeId: "runtime-a",
      reason: "child-exited",
    });
    expect(ended).toMatchObject({ ended: true, endReason: "child-exited", replayed: false });
    // A DIFFERENT semantic end (its own deterministic id) observes the
    // already-ended row and reports the FIRST reason — never a conflict.
    const competing = await store.endAuthorityRuntime({
      identity: manager.identity,
      scope,
      runtimeSeq: runtime.runtimeSeq,
      runtimeId: "runtime-a",
      reason: "failed-to-become-ready",
    });
    expect(competing.endReason).toBe("child-exited");
    // The exact retry of the first end replays.
    const replay = await store.endAuthorityRuntime({
      identity: manager.identity,
      scope,
      runtimeSeq: runtime.runtimeSeq,
      runtimeId: "runtime-a",
      reason: "child-exited",
    });
    expect(replay.replayed).toBe(true);
    expect(store.liveRuntime(scope)).toBeNull();
  });

  test("runtime credential mint binds the LIVE runtime of the exact scope and refuses everything else", async () => {
    const store = new InMemoryManagerControlStore();
    const manager = await claimManager(store, {
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
    });
    const scope = { tenantKey: "t:team_1", volumeId: "vol_1", branch: "main" };
    const runtime = await store.beginAuthorityRuntime({
      identity: manager.identity,
      scope,
      authorityInstanceId: "pfvcs_a",
      runtimeId: "runtime-a",
    });
    const minted = await store.runtimeCredentialMint({
      identity: manager.identity,
      credentialHash: sha256Hex("pfrc_secret"),
      tenantId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      authorityRuntimeSeq: runtime.runtimeSeq,
      authorityRuntimeId: "runtime-a",
      ttlMs: 3_600_000,
    });
    expect(minted).toMatchObject({
      tenantId: "team_1",
      volumeId: "vol_1",
      branchName: "main",
      authEpoch: "1",
      admissionEpoch: "1",
    });
    expect(minted.expiresDbMs - minted.mintedDbMs).toBe(3_600_000);
    expect(store.mintedCredentialHashes).toEqual([sha256Hex("pfrc_secret")]);

    // A stale runtime binding (previous seq, wrong id, or an ended row) can
    // never receive a credential.
    await expect(
      store.runtimeCredentialMint({
        identity: manager.identity,
        credentialHash: sha256Hex("pfrc_other"),
        tenantId: "team_1",
        volumeId: "vol_1",
        branch: "main",
        authorityRuntimeSeq: runtime.runtimeSeq,
        authorityRuntimeId: "runtime-somebody-else",
        ttlMs: 3_600_000,
      })
    ).rejects.toBeInstanceOf(ControlNotFoundError);
    // TTL is bounded 60s..1h like the SQL function.
    await expect(
      store.runtimeCredentialMint({
        identity: manager.identity,
        credentialHash: sha256Hex("pfrc_third"),
        tenantId: "team_1",
        volumeId: "vol_1",
        branch: "main",
        authorityRuntimeSeq: runtime.runtimeSeq,
        authorityRuntimeId: "runtime-a",
        ttlMs: 59_999,
      })
    ).rejects.toBeInstanceOf(InvalidControlArgumentError);
  });

  test("lifecycle receipts are permanent, exact, conflict-detecting, and tenant-isolated", async () => {
    const store = new InMemoryManagerControlStore();
    const manager = await claimManager(store, {
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
    });
    const response = { kind: "evict", operationId: "op-1", checkpointed: false };
    const first = await store.putLifecycleReceipt({
      identity: manager.identity,
      tenantKey: "t:team_1",
      operationId: "op-1",
      response,
    });
    expect(first).toMatchObject({ response, replayed: false });
    const replay = await store.putLifecycleReceipt({
      identity: manager.identity,
      tenantKey: "t:team_1",
      operationId: "op-1",
      response,
    });
    expect(replay).toMatchObject({ response, replayed: true });
    await expect(
      store.putLifecycleReceipt({
        identity: manager.identity,
        tenantKey: "t:team_1",
        operationId: "op-1",
        response: { ...response, checkpointed: true },
      })
    ).rejects.toBeInstanceOf(ControlOperationConflictError);
    expect(
      await store.findLifecycleReceipt({
        identity: manager.identity,
        tenantKey: "t:team_1",
        operationId: "op-1",
      })
    ).toMatchObject({
      kind: "found",
      response,
      fingerprint: expect.stringMatching(/^[0-9a-f]{64}$/u),
    });
    expect(
      await store.findLifecycleReceipt({
        identity: manager.identity,
        tenantKey: "t:team_2",
        operationId: "op-1",
      })
    ).toEqual({ kind: "unknown" });
  });

  test("an injected fault fails the call with ControlStoreUnavailableError and applies NO effects", async () => {
    const store = new InMemoryManagerControlStore();
    store.failNext("claimManager");
    await expect(
      claimManager(store, {
        operationId: "claim-manager-a",
        runtimeId: "manager-a",
        ttlMs: 1_000,
      })
    ).rejects.toBeInstanceOf(ControlStoreUnavailableError);
    expect(store.epoch()).toBe("0");
    // The next call succeeds and mints epoch 1 (the failed claim minted nothing).
    const claimed = await claimManager(store, {
      operationId: "claim-manager-a",
      runtimeId: "manager-a",
      ttlMs: 1_000,
    });
    expect(claimed.claim.managerEpoch).toBe("1");
  });
});

// ---------------------------------------------------------------------------
// PostgresManagerControlStore against a SCRIPTED pool: exact SQL text and
// argument marshalling, canonical-decimal response parsing, SQLSTATE error
// mapping, and fail-closed refusal of malformed rows — no real Postgres.
// ---------------------------------------------------------------------------

interface ScriptedCall {
  text: string;
  values: unknown[];
}

class ScriptedPool implements ManagerControlPool {
  readonly calls: ScriptedCall[] = [];
  private readonly script: Array<{ rows: unknown[] } | Error> = [];
  ended = false;

  reply(payload: unknown): this {
    this.script.push({ rows: [{ r: payload }] });
    return this;
  }

  replyRaw(rows: unknown[]): this {
    this.script.push({ rows });
    return this;
  }

  fail(error: Error): this {
    this.script.push(error);
    return this;
  }

  async query(text: string, values: unknown[]): Promise<{ rows: unknown[] }> {
    this.calls.push({ text, values });
    const next = this.script.shift();
    if (!next) {
      throw new Error(`ScriptedPool has no reply for: ${text}`);
    }
    if (next instanceof Error) {
      throw next;
    }
    return next;
  }

  async end(): Promise<void> {
    this.ended = true;
  }
}

function pgError(code: string, message: string, detail?: unknown): Error {
  return Object.assign(new Error(message), {
    code,
    ...(detail !== undefined ? { detail: JSON.stringify(detail) } : {}),
  });
}

const identity: ManagerIdentity = {
  managerEpoch: "3",
  managerRuntimeId: "pfmgr_x",
  managerCapability: "pfmcap_secret",
} as ManagerIdentity;

describe("PostgresManagerControlStore (scripted pool)", () => {
  test("claimManager invokes pfm.manager_claim with exact arguments and parses decimal-string times", async () => {
    const pool = new ScriptedPool().reply({
      managerEpoch: "7",
      runtimeId: "pfmgr_x",
      operationId: "pfclaim_pfmgr_x",
      claimedAtDbMs: "1000000",
      expiresAtDbMs: "1030000",
      dbTimeMs: "1000000",
      current: true,
      replayed: false,
    });
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });
    const claim = await store.claimManager({
      operationId: "pfclaim_pfmgr_x",
      runtimeId: "pfmgr_x",
      capabilityHash: "a".repeat(64),
      ttlMs: 30_000,
    });
    expect(claim).toMatchObject({
      managerEpoch: "7",
      claimedAtDbMs: 1_000_000,
      expiresAtDbMs: 1_030_000,
      current: true,
    });
    expect(pool.calls[0]!.text).toContain("pfm.manager_claim($1,$2,$3,$4)");
    expect(pool.calls[0]!.values).toEqual(["pfclaim_pfmgr_x", "pfmgr_x", "a".repeat(64), 30_000]);
    await store.close();
    expect(pool.ended).toBe(true);
  });

  test("a replayed live claim answers the row's CURRENT expiry facts", async () => {
    const pool = new ScriptedPool().reply({
      managerEpoch: "7",
      runtimeId: "pfmgr_x",
      operationId: "pfclaim_pfmgr_x",
      claimedAtDbMs: "1000000",
      expiresAtDbMs: "1030000",
      currentExpiresAtDbMs: "1090000",
      currentRenewedAtDbMs: "1060000",
      dbTimeMs: "1061000",
      current: true,
      replayed: true,
    });
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });
    const claim = await store.claimManager({
      operationId: "pfclaim_pfmgr_x",
      runtimeId: "pfmgr_x",
      capabilityHash: "a".repeat(64),
      ttlMs: 30_000,
    });
    expect(claim.expiresAtDbMs).toBe(1_090_000);
    expect(claim.replayed).toBe(true);
  });

  test("renew/release present the full manager identity and map PF001 to ManagerEpochSupersededError with the live epoch", async () => {
    const pool = new ScriptedPool()
      .reply({ dbTimeMs: "5", expiresAtDbMs: "35" })
      .fail(pgError("PF001", "superseded", { currentEpoch: "9" }));
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });
    const renewal = await store.renewManagerClaim({ identity, ttlMs: 30_000 });
    expect(renewal).toEqual({ dbTimeMs: 5, claimExpiresAtDbMs: 35 });
    expect(pool.calls[0]!.text).toContain("pfm.manager_renew($1,$2,$3,$4)");
    expect(pool.calls[0]!.values).toEqual(["3", "pfmgr_x", "pfmcap_secret", 30_000]);

    const error = await store.renewManagerClaim({ identity, ttlMs: 30_000 }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ManagerEpochSupersededError);
    expect((error as ManagerEpochSupersededError).staleEpoch).toBe("3");
    expect((error as ManagerEpochSupersededError).currentEpoch).toBe("9");
  });

  test("accessCreate parses the full operation result, verifies echoes, and enforces the forward projection", async () => {
    const row = {
      kind: "create",
      operationId: "op-1",
      leaseId: "pfal_1",
      tenantKey: "t:team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "sandbox-a",
      authorityInstanceId: "pfvcs_a",
      authorityRuntimeSeq: "1",
      authorityRuntimeId: "runtime-a",
      managerEpoch: "3",
      tokenGeneration: "1",
      controlSeq: "1",
      state: "active",
      expiresAt: "1060000",
      createdAtMs: "1000000",
      receiptFingerprint: "b".repeat(64),
      mintedToken: true,
      completedAtDbMs: "1000000",
      replayed: false,
      dbTimeMs: "1000000",
    };
    const pool = new ScriptedPool().reply({ ...row, currentFacts: { ...row } });
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });
    const result = await store.accessCreate({
      identity,
      operationId: "op-1",
      leaseId: "pfal_1",
      scope: { tenantKey: "t:team_1", volumeId: "vol_1", branch: "main" },
      consumerId: "sandbox-a",
      authorityInstanceId: "pfvcs_a",
      authorityRuntimeSeq: "1",
      authorityRuntimeId: "runtime-a",
      ttlMs: 60_000,
    });
    expect(result).toMatchObject({
      leaseId: "pfal_1",
      controlSeq: "1",
      expiresAt: 1_060_000,
      mintedToken: true,
    });
    expect(pool.calls[0]!.text).toContain("pfm.access_create(");
    expect(pool.calls[0]!.values).toEqual([
      "3",
      "pfmgr_x",
      "pfmcap_secret",
      "op-1",
      "pfal_1",
      "t:team_1",
      "vol_1",
      "main",
      "sandbox-a",
      "pfvcs_a",
      "1",
      "runtime-a",
      60_000,
    ]);

    // currentFacts that rewind the receipted controlSeq are refused at the
    // adapter boundary (fail closed, never a silent projection rewind).
    const rewound = new ScriptedPool().reply({
      ...row,
      controlSeq: "2",
      currentFacts: { ...row, controlSeq: "1" },
    });
    const rewindStore = new PostgresManagerControlStore("postgres://ignored", { pool: rewound });
    await expect(
      rewindStore.accessCreate({
        identity,
        operationId: "op-1",
        leaseId: "pfal_1",
        scope: { tenantKey: "t:team_1", volumeId: "vol_1", branch: "main" },
        consumerId: "sandbox-a",
        authorityInstanceId: "pfvcs_a",
        authorityRuntimeSeq: "1",
        authorityRuntimeId: "runtime-a",
        ttlMs: 60_000,
      })
    ).rejects.toBeInstanceOf(ControlStoreUnavailableError);
  });

  test("accessRenew maps PF014 to ControlReceiptEvictedError with the exact retained floor", async () => {
    const pool = new ScriptedPool().fail(
      pgError("PF014", "below floor", { leaseId: "pfal_1", receiptFloorControlSeq: "40" })
    );
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });
    const error = await store
      .accessRenew({
        identity,
        operationId: "op-old",
        tenantKey: "t:team_1",
        leaseId: "pfal_1",
        expectedControlSeq: parseAccessLeaseControlSeq("2"),
        ttlMs: 30_000,
        rotate: false,
      })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ControlReceiptEvictedError);
    expect((error as ControlReceiptEvictedError).receiptFloorControlSeq).toBe("40");
  });

  test("accessGet returns null for SQL NULL and refuses a wrong-lease echo", async () => {
    const pool = new ScriptedPool().replyRaw([{ r: null }]);
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });
    expect(
      await store.accessGet({ identity, tenantKey: "t:team_1", leaseId: "pfal_none" })
    ).toBeNull();

    const wrong = new ScriptedPool().reply({
      ...leaseFacts,
      leaseId: "pfal_OTHER",
      tenantKey: "t:team_1",
      dbTimeMs: "1783710000001",
    });
    const wrongStore = new PostgresManagerControlStore("postgres://ignored", { pool: wrong });
    await expect(
      wrongStore.accessGet({ identity, tenantKey: "t:team_1", leaseId: "pfal_test" })
    ).rejects.toBeInstanceOf(ControlStoreUnavailableError);
  });

  test("healthProbe reports pfm lineage and never throws on outages", async () => {
    const pool = new ScriptedPool().replyRaw([{ lineage: true }]);
    const store = new PostgresManagerControlStore("postgres://ignored", { pool });
    expect(await store.healthProbe()).toEqual({ ok: true, lineageComplete: true });
    expect(pool.calls[0]!.text).toContain("to_regproc('pfm.manager_renew')");

    const down = new ScriptedPool().fail(new Error("ECONNREFUSED"));
    const downStore = new PostgresManagerControlStore("postgres://ignored", { pool: down });
    expect(await downStore.healthProbe()).toEqual({ ok: false, lineageComplete: false });
  });

  test("an unexpected row count or malformed dbTime is a retryable store failure, never a guess", async () => {
    const empty = new ScriptedPool().replyRaw([]);
    const emptyStore = new PostgresManagerControlStore("postgres://ignored", { pool: empty });
    await expect(emptyStore.dbTimeMs()).rejects.toBeInstanceOf(ControlStoreUnavailableError);

    const malformed = new ScriptedPool().reply("not-a-decimal");
    const malformedStore = new PostgresManagerControlStore("postgres://ignored", { pool: malformed });
    await expect(malformedStore.dbTimeMs()).rejects.toBeInstanceOf(ControlStoreUnavailableError);

    const good = new ScriptedPool().reply("1234567");
    const goodStore = new PostgresManagerControlStore("postgres://ignored", { pool: good });
    expect(await goodStore.dbTimeMs()).toBe(1_234_567);
  });
});

// ---------------------------------------------------------------------------
// Real-Postgres integration (repo convention: PORTABLEFS_TEST_POSTGRES=true
// plus a DSN). Requires a database with the pfm manager-control migration
// applied (the OSS port of the manager-control SQL under
// packages/metadata-db/migrations) and, because pfm admission demands
// synchronous-replica durability evidence, a superuser session with
// portablefs.test_allow_unsafe_durability=on (add
// ?options=-c%20portablefs.test_allow_unsafe_durability%3Don to the DSN).
// ---------------------------------------------------------------------------

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const controlDatabaseUrl =
  process.env.PORTABLEFS_TEST_MANAGER_CONTROL_DATABASE_URL ??
  process.env.VOLUME_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/portablefs";

describePostgres("PostgresManagerControlStore (integration)", () => {
  test("claims, renews, and releases the singleton manager against the pfm schema", async () => {
    const store = new PostgresManagerControlStore(controlDatabaseUrl);
    try {
      const probe = await store.healthProbe();
      expect(probe.lineageComplete).toBe(true);
      const dbTime = await store.dbTimeMs();
      expect(dbTime).toBeGreaterThan(0);

      const runtimeId = `pfmgr_it_${Date.now()}`;
      const capability = `pfmcap_integration_${runtimeId}`;
      const claim = await store.claimManager({
        operationId: `pfclaim_${runtimeId}`,
        runtimeId,
        capabilityHash: sha256Hex(capability),
        ttlMs: 5_000,
      });
      expect(claim.current).toBe(true);
      const claimed: ManagerIdentity = {
        managerEpoch: claim.managerEpoch,
        managerRuntimeId: runtimeId,
        managerCapability: capability,
      };
      const renewal = await store.renewManagerClaim({ identity: claimed, ttlMs: 5_000 });
      expect(renewal.claimExpiresAtDbMs).toBeGreaterThanOrEqual(claim.expiresAtDbMs);
      await store.releaseManagerClaim({ identity: claimed });
      await expect(store.renewManagerClaim({ identity: claimed, ttlMs: 5_000 })).rejects.toBeInstanceOf(
        ManagerEpochSupersededError
      );
    } finally {
      await store.close();
    }
  });

  test("mints runtime read credentials bound to the live runtime, and resolution fails closed on expiry and revocation", async () => {
    const store = new PostgresManagerControlStore(controlDatabaseUrl);
    const pool = new pg.Pool({ connectionString: controlDatabaseUrl });
    const suffix = `${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
    const tenantId = `team_cred_${suffix}`;
    const volumeId = `vol_cred_${suffix}`;
    try {
      // pfm scope admission pins each volume to its metadata tenant
      // (require_scope_tenant), so the rows must exist like they would in a
      // real deployment.
      await pool.query(`INSERT INTO tenants (id, created_at) VALUES ($1, $2)`, [
        tenantId,
        Date.now(),
      ]);
      await pool.query(
        `INSERT INTO volumes (id, tenant_id, metadata, created_at) VALUES ($1, $2, '{}', $3)`,
        [volumeId, tenantId, Date.now()]
      );
      const runtimeId = `pfmgr_cred_${suffix}`;
      const capability = `pfmcap_credential_integration_${suffix}`;
      const claim = await store.claimManager({
        operationId: `pfclaim_cred_${suffix}`,
        runtimeId,
        capabilityHash: sha256Hex(capability),
        ttlMs: 30_000,
      });
      const identity: ManagerIdentity = {
        managerEpoch: claim.managerEpoch,
        managerRuntimeId: runtimeId,
        managerCapability: capability,
      };
      const scope = { tenantKey: `t:${tenantId}`, volumeId, branch: "main" };
      const runtime = await store.beginAuthorityRuntime({
        identity,
        scope,
        authorityInstanceId: `pfvcs_cred_${suffix}`,
        runtimeId: `runtime_cred_${suffix}`,
      });

      const secret = `pfrc_integration_${suffix}`;
      const minted = await store.runtimeCredentialMint({
        identity,
        credentialHash: sha256Hex(secret),
        tenantId,
        volumeId,
        branch: "main",
        authorityRuntimeSeq: runtime.runtimeSeq,
        authorityRuntimeId: `runtime_cred_${suffix}`,
        ttlMs: 3_600_000,
      });
      expect(minted).toMatchObject({
        tenantId,
        volumeId,
        branchName: "main",
        authEpoch: "1",
        admissionEpoch: "1",
      });

      const resolve = async (hash: string): Promise<unknown> => {
        const result = await pool.query(`SELECT public.runtime_credential_resolve($1) AS r`, [hash]);
        return result.rows[0]?.r ?? null;
      };
      expect(await resolve(sha256Hex(secret))).toMatchObject({
        tenantId,
        volumeId,
        branchName: "main",
        readOnly: true,
      });
      expect(await resolve(sha256Hex("pfrc_never-minted"))).toBeNull();

      // A stale runtime binding can never receive a credential.
      await expect(
        store.runtimeCredentialMint({
          identity,
          credentialHash: sha256Hex(`${secret}-stale`),
          tenantId,
          volumeId,
          branch: "main",
          authorityRuntimeSeq: runtime.runtimeSeq,
          authorityRuntimeId: "runtime-somebody-else",
          ttlMs: 3_600_000,
        })
      ).rejects.toThrow();

      // Expiry and revocation both fail closed at resolve time.
      await pool.query(
        `UPDATE public.runtime_read_credentials SET expires_db_ms = 1 WHERE credential_hash = $1`,
        [sha256Hex(secret)]
      );
      expect(await resolve(sha256Hex(secret))).toBeNull();

      const revokedSecret = `pfrc_integration_revoked_${suffix}`;
      await store.runtimeCredentialMint({
        identity,
        credentialHash: sha256Hex(revokedSecret),
        tenantId,
        volumeId,
        branch: "main",
        authorityRuntimeSeq: runtime.runtimeSeq,
        authorityRuntimeId: `runtime_cred_${suffix}`,
        ttlMs: 3_600_000,
      });
      await pool.query(
        `UPDATE public.runtime_read_credentials SET revoked_db_ms = 1 WHERE credential_hash = $1`,
        [sha256Hex(revokedSecret)]
      );
      expect(await resolve(sha256Hex(revokedSecret))).toBeNull();

      await store.endAuthorityRuntime({
        identity,
        scope,
        runtimeSeq: runtime.runtimeSeq,
        runtimeId: `runtime_cred_${suffix}`,
        reason: "integration-test-complete",
      });
      await store.releaseManagerClaim({ identity });
    } finally {
      await pool
        .query(`DELETE FROM public.runtime_read_credentials WHERE tenant_id = $1`, [tenantId])
        .catch(() => undefined);
      await pool.query(`DELETE FROM volumes WHERE id = $1`, [volumeId]).catch(() => undefined);
      await pool.query(`DELETE FROM tenants WHERE id = $1`, [tenantId]).catch(() => undefined);
      await pool.end();
      await store.close();
    }
  });
});
