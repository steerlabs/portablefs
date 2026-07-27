import { describe, expect, test } from "vitest";
import type {
  AdoptCutResult,
  GenerationBacklogStatus,
  HistoryCutCreateInput,
  HistoryCutStatus,
  ServingPinStatus,
} from "@portablefs/metadata-db";
import {
  adoptionOperationId,
  HistoryMaintenanceLoop,
  historyMaintenanceSettingsFromEnv,
  isBenignHistoryRefusal,
  recoveryCutOperationId,
  type HistoryMaintenanceCycleSummary,
  type HistoryMaintenanceStore,
  type HistoryOperationReplay,
} from "./history-maintenance.js";
import type { VolumeApiTelemetryEvent } from "./telemetry.js";

// ---------------------------------------------------------------------------
// The fake reproduces the database facts the loop's exactness rests on:
// permanent resource operations keyed by (domain, operationId) whose replay
// returns the RECORDED outcome without re-mutating, fingerprint conflicts on
// divergent bytes, adoption advancing the generation base and subtracting
// the captured backlog, and fenced pin release refusing (PF011) until marked
// superseded. Operation begin is recorded synchronously at call entry, so
// concurrent same-id calls dedupe exactly like the row lock does.
// ---------------------------------------------------------------------------

interface FakeGeneration {
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  generationId: string;
  status: "active" | "suspended";
  baseSeq: number;
  nextSeq: number;
  backlogBytes: number;
  backlogRecords: number;
  quotaBytes: number;
  quotaRecords: number;
}

interface FakeCut {
  cutId: string;
  tenantId: string;
  generationId: string;
  state: "pending" | "materializing" | "ready" | "failed" | "canceled";
  recoveryAnchorId?: string;
  capturedBaseSeq: number;
  cutSeqExclusive: number;
  capturedBacklogBytes: number;
  capturedBacklogRecords: number;
}

interface FakeOperation {
  canonicalJson: string;
  state: string;
  targetIds: Record<string, string>;
  response?: unknown;
}

function pfError(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

class FakeHistoryStore implements HistoryMaintenanceStore {
  readonly generations = new Map<string, FakeGeneration>();
  readonly cuts = new Map<string, FakeCut>();
  readonly operations = new Map<string, FakeOperation>();
  readonly pins = new Map<string, { adoptionId: string; tenantId: string; generationId: string }>();
  readonly supersededPins = new Set<string>();

  readonly createCutCalls: HistoryCutCreateInput[] = [];
  readonly adoptCalls: Array<{ cutId: string; operationId: string }> = [];
  cutCreateMutations = 0;
  adoptMutations = 0;
  pinReleaseMutations = 0;
  /** State cuts are born in ("pending" matches the real database). */
  bornCutState: FakeCut["state"] = "pending";

  addGeneration(generation: FakeGeneration): void {
    this.generations.set(generation.generationId, generation);
  }

  markCutReady(cutId: string): void {
    const cut = this.cuts.get(cutId);
    if (!cut) {
      throw new Error(`no fake cut ${cutId}`);
    }
    cut.state = "ready";
    cut.recoveryAnchorId = `hanchor_${cutId}`;
  }

  async generationsPastThreshold(
    backlogPercent: number,
    _limit?: number
  ): Promise<GenerationBacklogStatus[]> {
    const rows: GenerationBacklogStatus[] = [];
    for (const generation of this.generations.values()) {
      const percent = Math.max(
        Math.floor((generation.backlogBytes * 100) / generation.quotaBytes),
        Math.floor((generation.backlogRecords * 100) / generation.quotaRecords)
      );
      if (percent < backlogPercent) {
        continue;
      }
      rows.push({
        tenantId: generation.tenantId,
        volumeId: generation.volumeId,
        branchId: generation.branchId,
        branchName: generation.branchName,
        generationId: generation.generationId,
        journalEpoch: "1",
        status: generation.status,
        baseSeq: String(generation.baseSeq),
        nextSeq: String(generation.nextSeq),
        backlogBytes: String(generation.backlogBytes),
        backlogRecords: String(generation.backlogRecords),
        quotaBacklogBytes: String(generation.quotaBytes),
        quotaBacklogRecords: String(generation.quotaRecords),
        backlogPercent: percent,
      });
    }
    return rows;
  }

  async createCut(
    input: HistoryCutCreateInput
  ): Promise<HistoryCutStatus | HistoryOperationReplay> {
    this.createCutCalls.push(input);
    const key = `history-cut:${input.operationId}`;
    const existing = this.operations.get(key);
    if (existing) {
      if (existing.canonicalJson !== input.requestCanonicalJson) {
        throw pfError("PF009", "operation replayed with different content");
      }
      return {
        operationId: input.operationId,
        state: existing.state,
        replayed: true,
        targetIds: existing.targetIds,
        ...(existing.response !== undefined ? { response: existing.response } : {}),
      };
    }
    const generation = [...this.generations.values()].find(
      (candidate) =>
        candidate.tenantId === input.tenantId &&
        candidate.volumeId === input.volumeId &&
        candidate.branchName === input.branchName
    );
    if (!generation) {
      throw pfError("PF007", "branch not found");
    }
    this.cutCreateMutations += 1;
    const cutId = `hcutrow_${this.cutCreateMutations}`;
    const cut: FakeCut = {
      cutId,
      tenantId: input.tenantId,
      generationId: generation.generationId,
      state: this.bornCutState,
      ...(this.bornCutState === "ready" ? { recoveryAnchorId: `hanchor_${cutId}` } : {}),
      capturedBaseSeq: generation.baseSeq,
      cutSeqExclusive: generation.nextSeq,
      capturedBacklogBytes: generation.backlogBytes,
      capturedBacklogRecords: generation.backlogRecords,
    };
    this.cuts.set(cutId, cut);
    this.operations.set(key, {
      canonicalJson: input.requestCanonicalJson,
      state: "pending",
      targetIds: { ...(input.targetIds ?? {}), cutId },
    });
    return this.projectCut(cut);
  }

  async cutStatus(tenantId: string, cutId: string): Promise<HistoryCutStatus | null> {
    const cut = this.cuts.get(cutId);
    if (!cut || cut.tenantId !== tenantId) {
      return null;
    }
    return this.projectCut(cut);
  }

  async adoptCut(input: {
    tenantId: string;
    cutId: string;
    anchorId: string;
    operationId: string;
    requestCanonicalJson: string;
    servingCapability: string;
  }): Promise<AdoptCutResult | HistoryOperationReplay> {
    this.adoptCalls.push({ cutId: input.cutId, operationId: input.operationId });
    const key = `adoption:${input.operationId}`;
    const existing = this.operations.get(key);
    if (existing) {
      if (existing.canonicalJson !== input.requestCanonicalJson) {
        throw pfError("PF009", "operation replayed with different content");
      }
      return {
        operationId: input.operationId,
        state: existing.state,
        replayed: true,
        targetIds: existing.targetIds,
        ...(existing.response !== undefined ? { response: existing.response } : {}),
      };
    }
    if (input.servingCapability !== "pft2-base-v1") {
      throw pfError("PF011", "adoption requires the pft2-base-v1 serving capability proof");
    }
    const cut = this.cuts.get(input.cutId);
    if (!cut || cut.tenantId !== input.tenantId) {
      throw pfError("PF007", "cut not found");
    }
    if (cut.state !== "ready") {
      throw pfError("PF011", "cut is not ready");
    }
    if (cut.recoveryAnchorId !== input.anchorId) {
      throw pfError("PF011", "anchor does not bound cut");
    }
    const generation = this.generations.get(cut.generationId);
    if (!generation) {
      throw pfError("PF007", "generation not found");
    }
    if (generation.baseSeq !== cut.capturedBaseSeq) {
      throw pfError("PF002", "adoption expected base differs from generation base");
    }
    this.adoptMutations += 1;
    generation.baseSeq = cut.cutSeqExclusive;
    generation.backlogBytes -= cut.capturedBacklogBytes;
    generation.backlogRecords -= cut.capturedBacklogRecords;
    const adoptionId = `hadoptrow_${this.adoptMutations}`;
    this.pins.set(adoptionId, {
      adoptionId,
      tenantId: input.tenantId,
      generationId: generation.generationId,
    });
    const result: AdoptCutResult = {
      adoptionId,
      cutId: input.cutId,
      anchorId: input.anchorId,
      state: "applied",
      newBaseSeq: String(cut.cutSeqExclusive),
      newBaseDigest: "sha256:new-base",
      newBaseCommitId: `cmt_${input.cutId}`,
      writerFence: "1",
    };
    this.operations.set(key, {
      canonicalJson: input.requestCanonicalJson,
      state: "succeeded",
      targetIds: { adoptionId },
      response: result,
    });
    return result;
  }

  async unreleasedServingPins(_limit?: number): Promise<ServingPinStatus[]> {
    return [...this.pins.values()].map((pin) => ({
      adoptionId: pin.adoptionId,
      tenantId: pin.tenantId,
      generationId: pin.generationId,
      cutId: "hcutrow_x",
      writerFence: "1",
      createdDbMs: "0",
    }));
  }

  async releaseServingPinFenced(
    adoptionId: string
  ): Promise<{ released: boolean; reason: string }> {
    if (!this.pins.has(adoptionId)) {
      throw pfError("PF007", `serving pin ${adoptionId} not found`);
    }
    if (!this.supersededPins.has(adoptionId)) {
      throw pfError("PF011", `serving pin ${adoptionId} runtime is not durably superseded`);
    }
    this.pins.delete(adoptionId);
    this.pinReleaseMutations += 1;
    return { released: true, reason: "fenced" };
  }

  private projectCut(cut: FakeCut): HistoryCutStatus {
    const generation = this.generations.get(cut.generationId);
    return {
      cutId: cut.cutId,
      tenantId: cut.tenantId,
      volumeId: generation?.volumeId ?? "vol_x",
      branchId: generation?.branchId ?? "br_x",
      branchName: generation?.branchName ?? "main",
      kind: "recovery",
      sourceKind: "managed_journal",
      generationId: cut.generationId,
      materializerVersion: "pfm-test",
      replicationPolicy: { v: "1", requiredFailureDomains: [], policyEpoch: "1" },
      dedupRevision: "1",
      state: cut.state,
      claimEpoch: "0",
      attemptCount: 0,
      nextAttemptDbMs: "0",
      createdDbMs: "0",
      updatedDbMs: "0",
      ...(cut.recoveryAnchorId ? { recoveryAnchorId: cut.recoveryAnchorId } : {}),
    };
  }
}

function backloggedGeneration(overrides: Partial<FakeGeneration> = {}): FakeGeneration {
  return {
    tenantId: "t1",
    volumeId: "vol_1",
    branchId: "br_1",
    branchName: "main",
    generationId: "jgen_1",
    status: "active",
    baseSeq: 0,
    nextSeq: 900,
    backlogBytes: 800,
    backlogRecords: 10,
    quotaBytes: 1000,
    quotaRecords: 1000,
    ...overrides,
  };
}

function loopWith(
  store: HistoryMaintenanceStore,
  options: {
    events?: VolumeApiTelemetryEvent[];
    logs?: string[];
    shouldPause?: () => boolean;
    servingConfigured?: boolean;
  } = {}
): HistoryMaintenanceLoop {
  return new HistoryMaintenanceLoop({
    store,
    intervalMs: 60_000,
    backlogPercent: 70,
    telemetry: { emit: (event) => options.events?.push(event) },
    servingConfigured: options.servingConfigured ?? true,
    shouldPause: options.shouldPause,
    log: (message) => options.logs?.push(message),
  });
}

describe("historyMaintenanceSettingsFromEnv", () => {
  test("defaults to enabled with 60s interval and 70 percent threshold", () => {
    expect(historyMaintenanceSettingsFromEnv({})).toEqual({
      enabled: true,
      intervalMs: 60_000,
      backlogPercent: 70,
    });
  });

  test("refuses off in production with a clear error", () => {
    expect(() =>
      historyMaintenanceSettingsFromEnv({
        NODE_ENV: "production",
        PORTABLEFS_HISTORY_MAINTENANCE: "off",
      })
    ).toThrow(/refused in production/);
  });

  test("allows off outside production", () => {
    expect(
      historyMaintenanceSettingsFromEnv({
        NODE_ENV: "test",
        PORTABLEFS_HISTORY_MAINTENANCE: "off",
      }).enabled
    ).toBe(false);
  });

  test("rejects unknown modes and invalid numbers", () => {
    expect(() =>
      historyMaintenanceSettingsFromEnv({ PORTABLEFS_HISTORY_MAINTENANCE: "maybe" })
    ).toThrow(/must be on, off, or unset/);
    expect(() =>
      historyMaintenanceSettingsFromEnv({ PORTABLEFS_HISTORY_MAINTENANCE_INTERVAL_MS: "0" })
    ).toThrow(/PORTABLEFS_HISTORY_MAINTENANCE_INTERVAL_MS/);
    expect(() =>
      historyMaintenanceSettingsFromEnv({ PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT: "101" })
    ).toThrow(/PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT/);
    expect(() =>
      historyMaintenanceSettingsFromEnv({ PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT: "7x" })
    ).toThrow(/decimal integer/);
  });
});

describe("HistoryMaintenanceLoop", () => {
  test("threshold scan creates the recovery cut with the deterministic operation id", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const events: VolumeApiTelemetryEvent[] = [];
    const loop = loopWith(store, { events });

    const summary = await loop.runCycle();

    expect(store.createCutCalls).toHaveLength(1);
    expect(store.createCutCalls[0]?.operationId).toBe(recoveryCutOperationId("jgen_1", "0"));
    expect(store.createCutCalls[0]?.kind).toBe("recovery");
    expect(store.adoptCalls).toHaveLength(0);
    expect(summary.generationsScanned).toBe(1);
    expect(summary.cutsCreated).toBe(1);
    expect(summary.cutsPending).toBe(1);
    expect(summary.topBacklogPercent).toBe(80);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      type: "history_maintenance",
      generationsScanned: 1,
      cutsCreated: 1,
      topBacklogPercent: 80,
    });
  });

  test("below-threshold generations are not touched", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration({ backlogBytes: 100, backlogRecords: 1 }));
    const loop = loopWith(store);

    const summary = await loop.runCycle();

    expect(summary.generationsScanned).toBe(0);
    expect(store.createCutCalls).toHaveLength(0);
  });

  test("a ready cut is adopted with the deterministic adoption id", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const logs: string[] = [];
    const loop = loopWith(store, { logs });

    await loop.runCycle();
    store.markCutReady("hcutrow_1");
    const summary = await loop.runCycle();

    expect(summary.adoptionsApplied).toBe(1);
    expect(store.adoptMutations).toBe(1);
    expect(store.adoptCalls.at(-1)?.operationId).toBe(adoptionOperationId("hcutrow_1"));
    // Adoption advanced the base and subtracted the captured backlog.
    expect(store.generations.get("jgen_1")?.baseSeq).toBe(900);
    expect(store.generations.get("jgen_1")?.backlogBytes).toBe(0);
    expect(logs).toHaveLength(0);
  });

  test("without exact history serving configured, a ready cut is HELD (not adopted) and reported once", async () => {
    const store = new FakeHistoryStore();
    store.bornCutState = "ready";
    store.addGeneration(backloggedGeneration());
    const logs: string[] = [];
    const events: VolumeApiTelemetryEvent[] = [];
    const loop = loopWith(store, { logs, events, servingConfigured: false });

    const first = await loop.runCycle();
    const second = await loop.runCycle();

    // The cut exists and is ready, but adoption never dispatched: an adopted
    // PFT2 base would strand the next cold start behind
    // HISTORY_SERVING_UNAVAILABLE on a deployment with no history stores.
    expect(store.adoptCalls).toHaveLength(0);
    expect(store.adoptMutations).toBe(0);
    expect(store.generations.get("jgen_1")?.baseSeq).toBe(0);
    expect(first.adoptionsBlocked).toBe(1);
    expect(second.adoptionsBlocked).toBe(1);
    expect(first.failures + second.failures).toBe(0);
    // The operator warning is once per process, not once per cycle.
    expect(logs.filter((line) => /adoption is held/.test(line))).toHaveLength(1);
    expect(events.at(-1)).toMatchObject({
      type: "history_maintenance",
      adoptionsBlocked: 1,
    });
  });

  test("adoption replays exactly once across simulated crash and stale rescan", async () => {
    const store = new FakeHistoryStore();
    store.bornCutState = "ready";
    store.addGeneration(backloggedGeneration());
    const first = loopWith(store);

    const summaryA = await first.runCycle();
    expect(summaryA.adoptionsApplied).toBe(1);
    expect(store.adoptMutations).toBe(1);

    // Crash before the cycle's outcome was observed anywhere, then a stale
    // scan view: the generation row appears exactly as before the adoption.
    const generation = store.generations.get("jgen_1")!;
    generation.baseSeq = 0;
    generation.backlogBytes = 800;
    generation.backlogRecords = 10;

    const replayLoop = loopWith(store);
    const summaryB = await replayLoop.runCycle();

    // Same (generation, base) -> same operation ids -> recorded outcomes
    // replay; no second cut row and no second adoption mutation exist.
    expect(store.cutCreateMutations).toBe(1);
    expect(store.adoptMutations).toBe(1);
    expect(summaryB.adoptionsApplied).toBe(0);
    expect(summaryB.failures).toBe(0);
  });

  test("concurrent double-run on two loops produces no duplicate mutations", async () => {
    const store = new FakeHistoryStore();
    store.bornCutState = "ready";
    store.addGeneration(backloggedGeneration());
    const events: VolumeApiTelemetryEvent[] = [];
    const loopA = loopWith(store, { events });
    const loopB = loopWith(store, { events });

    const [summaryA, summaryB] = await Promise.all([loopA.runCycle(), loopB.runCycle()]);

    expect(store.cutCreateMutations).toBe(1);
    expect(store.adoptMutations).toBe(1);
    expect(summaryA.adoptionsApplied + summaryB.adoptionsApplied).toBe(1);
    expect(summaryA.failures + summaryB.failures).toBe(0);
    expect(events).toHaveLength(2);
  });

  test("pin sweep releases superseded pins and treats fenced refusal as benign", async () => {
    const store = new FakeHistoryStore();
    store.pins.set("hadopt_live", {
      adoptionId: "hadopt_live",
      tenantId: "t1",
      generationId: "jgen_1",
    });
    store.pins.set("hadopt_superseded", {
      adoptionId: "hadopt_superseded",
      tenantId: "t1",
      generationId: "jgen_1",
    });
    store.supersededPins.add("hadopt_superseded");
    const logs: string[] = [];
    const loop = loopWith(store, { logs });

    const summary = await loop.runCycle();

    expect(summary.pinsScanned).toBe(2);
    expect(summary.pinsReleased).toBe(1);
    expect(summary.benignRefusals).toBe(1);
    expect(summary.failures).toBe(0);
    // Benign refusals never log; the live pin is the fence working.
    expect(logs).toHaveLength(0);
    expect(store.pins.has("hadopt_live")).toBe(true);
    expect(store.pins.has("hadopt_superseded")).toBe(false);
  });

  test("a permanently failed cut is surfaced without counting as a race", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const logs: string[] = [];
    const loop = loopWith(store, { logs });

    await loop.runCycle();
    store.cuts.get("hcutrow_1")!.state = "failed";
    const summary = await loop.runCycle();

    expect(summary.cutsFailed).toBe(1);
    expect(summary.failures).toBe(0);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("failed");
    expect(store.adoptCalls).toHaveLength(0);
  });

  test("real failures are logged and counted; the cycle still completes", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    store.createCut = async () => {
      throw pfError("PF015", "history policy is not installed");
    };
    const logs: string[] = [];
    const events: VolumeApiTelemetryEvent[] = [];
    const loop = loopWith(store, { logs, events });

    const summary = await loop.runCycle();

    expect(summary.failures).toBe(1);
    expect(summary.benignRefusals).toBe(0);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("PF015");
    expect(events).toHaveLength(1);
  });

  test("pauses promptly while draining: no repository call is made", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const loop = loopWith(store, { shouldPause: () => true });

    const summary: HistoryMaintenanceCycleSummary = await loop.runCycle();

    expect(summary.generationsScanned).toBe(0);
    expect(summary.cutsCreated).toBe(0);
    expect(summary.adoptionsApplied).toBe(0);
    expect(store.createCutCalls).toHaveLength(0);
  });

  test("classifies the fenced SQLSTATE vocabulary", () => {
    expect(isBenignHistoryRefusal(pfError("PF011", "proof refusal"))).toBe(true);
    expect(isBenignHistoryRefusal(pfError("PF002", "exact-tuple conflict"))).toBe(true);
    expect(isBenignHistoryRefusal(pfError("PF007", "row vanished"))).toBe(true);
    expect(isBenignHistoryRefusal(pfError("PF015", "policy missing"))).toBe(false);
    expect(isBenignHistoryRefusal(new Error("plain"))).toBe(false);
  });
});
