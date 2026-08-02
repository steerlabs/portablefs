import { describe, expect, test } from "vitest";
import type {
  AdoptCutResult,
  GenerationBacklogStatus,
  HistoryCutCreateInput,
  HistoryCutStatus,
  ServingPinStatus,
  StuckRecoveryGeneration,
} from "@portablefs/metadata-db";
import {
  adoptionOperationId,
  classifyCutFailure,
  HistoryMaintenanceLoop,
  historyMaintenanceSettingsFromEnv,
  isBenignHistoryRefusal,
  recordedCutFailure,
  recoveryCutOperationId,
  terminalRemedy,
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
  /** pfh.cut_create mints MAX+1 at the dedup key after a definite failure. */
  dedupRevision: number;
  updatedDbMs: number;
  lastError?: unknown;
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
  /** The database clock the projections carry (pfh.now_ms). */
  dbNowMs = 1_000_000;

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
    cut.updatedDbMs = this.dbNowMs;
  }

  /**
   * Settle a cut the way the history worker's dead-letter / cut_fail does:
   * a terminal state plus the recorded failure the retry policy reads.
   */
  failCut(cutId: string, lastError: unknown): void {
    const cut = this.cuts.get(cutId);
    if (!cut) {
      throw new Error(`no fake cut ${cutId}`);
    }
    cut.state = "failed";
    cut.lastError = lastError;
    cut.updatedDbMs = this.dbNowMs;
  }

  /** Every cut still in flight settles failed with the same recorded error. */
  failAllPending(lastError: unknown): void {
    for (const cut of this.cuts.values()) {
      if (cut.state === "pending" || cut.state === "materializing") {
        this.failCut(cut.cutId, lastError);
      }
    }
  }

  /**
   * pfj.stuck_recovery_generations (migration 034): live generations whose
   * newest terminal cut would have moved the base and that have nothing live
   * in flight above it.
   */
  async stuckRecoveryGenerations(limit = 32): Promise<StuckRecoveryGeneration[]> {
    const out: StuckRecoveryGeneration[] = [];
    for (const generation of this.generations.values()) {
      const own = [...this.cuts.values()].filter(
        (cut) =>
          cut.generationId === generation.generationId &&
          cut.cutSeqExclusive > generation.baseSeq
      );
      const terminal = own.filter((cut) => cut.state === "failed" || cut.state === "canceled");
      if (terminal.length === 0 || own.some((cut) => !terminal.includes(cut))) {
        continue;
      }
      const newest = terminal.reduce((best, cut) =>
        cut.dedupRevision > best.dedupRevision ? cut : best
      );
      const firstFailed = Math.min(...terminal.map((cut) => cut.updatedDbMs));
      const error = newest.lastError as { kind?: string; message?: string } | undefined;
      out.push({
        tenantId: generation.tenantId,
        volumeId: generation.volumeId,
        branchId: generation.branchId,
        branchName: generation.branchName,
        generationId: generation.generationId,
        status: generation.status,
        baseSeq: String(generation.baseSeq),
        nextSeq: String(generation.nextSeq),
        backlogBytes: String(generation.backlogBytes),
        backlogRecords: String(generation.backlogRecords),
        cutId: newest.cutId,
        cutState: newest.state as "failed" | "canceled",
        cutKind: "recovery",
        cutSeqExclusive: String(newest.cutSeqExclusive),
        dedupRevision: String(newest.dedupRevision),
        attemptCount: 1,
        failureKind: error?.kind ?? "unknown",
        failureMessage: error?.message ?? "",
        firstFailedDbMs: String(firstFailed),
        lastFailedDbMs: String(newest.updatedDbMs),
        stuckAgeMs: String(Math.max(this.dbNowMs - firstFailed, 0)),
        terminalCuts: String(terminal.length),
        dbTimeMs: String(this.dbNowMs),
      });
    }
    return out.slice(0, limit);
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
    // Kind-agnostic dedup at (generation, boundary): a fresh revision is
    // minted only AFTER the previous one settled terminal, exactly as 029's
    // cut_create does (a live row would have converged instead).
    const dedupRevision =
      [...this.cuts.values()].filter(
        (candidate) =>
          candidate.generationId === generation.generationId &&
          candidate.capturedBaseSeq === generation.baseSeq &&
          candidate.cutSeqExclusive === generation.nextSeq
      ).length + 1;
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
      dedupRevision,
      updatedDbMs: this.dbNowMs,
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
      dedupRevision: String(cut.dedupRevision),
      state: cut.state,
      claimEpoch: "0",
      attemptCount: 0,
      nextAttemptDbMs: "0",
      createdDbMs: "0",
      updatedDbMs: String(cut.updatedDbMs),
      dbTimeMs: String(this.dbNowMs),
      ...(cut.lastError !== undefined ? { lastError: cut.lastError } : {}),
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
    recoveryCutMaxRevisions?: number;
    recoveryCutBackoffMs?: number;
    stuckLogIntervalMs?: number;
    now?: () => number;
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
    recoveryCutMaxRevisions: options.recoveryCutMaxRevisions,
    recoveryCutBackoffMs: options.recoveryCutBackoffMs,
    stuckLogIntervalMs: options.stuckLogIntervalMs,
    now: options.now,
  });
}

describe("historyMaintenanceSettingsFromEnv", () => {
  test("defaults to enabled with 60s interval and 70 percent threshold", () => {
    expect(historyMaintenanceSettingsFromEnv({})).toEqual({
      enabled: true,
      intervalMs: 60_000,
      backlogPercent: 70,
      // Journal reclamation defaults (migration 031): a 7-day suspended-
      // generation retention, and bounded reclaim work per cycle.
      journalRetentionMs: 604_800_000,
      reclaimBatchRows: 512,
      reclaimMaxPagesPerCycle: 64,
      // Terminal recovery-cut lifecycle (migration 034).
      recoveryCutMaxRevisions: 3,
      recoveryCutBackoffMs: 300_000,
      stuckLogIntervalMs: 3_600_000,
    });
  });

  test("the terminal recovery-cut lifecycle bounds are configurable and floored", () => {
    const settings = historyMaintenanceSettingsFromEnv({
      PORTABLEFS_HISTORY_RECOVERY_CUT_MAX_REVISIONS: "5",
      PORTABLEFS_HISTORY_RECOVERY_CUT_BACKOFF_MS: "60000",
      PORTABLEFS_HISTORY_STUCK_LOG_INTERVAL_MS: "900000",
    });
    expect(settings.recoveryCutMaxRevisions).toBe(5);
    expect(settings.recoveryCutBackoffMs).toBe(60_000);
    expect(settings.stuckLogIntervalMs).toBe(900_000);
    // A revision budget of zero would restore the dead end this replaces:
    // a failed cut with no path forward at all.
    expect(() =>
      historyMaintenanceSettingsFromEnv({
        PORTABLEFS_HISTORY_RECOVERY_CUT_MAX_REVISIONS: "0",
      })
    ).toThrow(/PORTABLEFS_HISTORY_RECOVERY_CUT_MAX_REVISIONS/);
  });

  test("journal reclamation bounds are configurable and floored", () => {
    const settings = historyMaintenanceSettingsFromEnv({
      PORTABLEFS_JOURNAL_RETENTION_MS: "3600000",
      PORTABLEFS_JOURNAL_RECLAIM_BATCH: "128",
      PORTABLEFS_JOURNAL_RECLAIM_MAX_PAGES: "8",
    });
    expect(settings.journalRetentionMs).toBe(3_600_000);
    expect(settings.reclaimBatchRows).toBe(128);
    expect(settings.reclaimMaxPagesPerCycle).toBe(8);
    // A retention below the one-hour floor would cut branches that are
    // merely between mounts. Refused loudly, never silently clamped.
    expect(() =>
      historyMaintenanceSettingsFromEnv({ PORTABLEFS_JOURNAL_RETENTION_MS: "1000" })
    ).toThrow(/PORTABLEFS_JOURNAL_RETENTION_MS/);
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
    store.failCut("hcutrow_1", { kind: "corrupt", message: "source corruption" });
    const summary = await loop.runCycle();

    expect(summary.cutsFailed).toBe(1);
    expect(summary.failures).toBe(0);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("failed");
    expect(store.adoptCalls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// TERMINAL RECOVERY CUTS (the live production defect).
//
// Production logged, every 60 seconds, for days:
//
//   "recovery cut hcut_f6c19bfeb58148138c86d3ea54ea0eb5 for generation
//    jgen_c6c2ed9f537c42a884edbffe2bfdddcc is failed; adoption is blocked
//    until an operator intervenes"
//
// with {cutsFailed: 1} and nothing else. The mechanism is exact: the
// deterministic operation id hcut-<generation>-<baseSeq> is a permanent
// database row, and baseSeq only advances THROUGH adoption, so every later
// cycle replayed the same recorded operation, read the same failed cut, and
// logged again. Nothing could ever change.
//
// The first test below is the regression: it runs ten cycles and asserts ONE
// log line and a terminal outcome. On the pre-fix loop it fails with ten.
// ---------------------------------------------------------------------------
describe("HistoryMaintenanceLoop terminal recovery cuts", () => {
  const corruptError = {
    kind: "corrupt",
    message: "historycut: source corruption: journal page at seq 0 is empty below the cut 32",
  };

  test("a failed cut replays the SAME operation forever: the dead end this fixes", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const loop = loopWith(store);

    await loop.runCycle();
    store.failCut("hcutrow_1", corruptError);

    // Presenting the revision-1 operation id again is a REPLAY: it returns
    // the recorded outcome and mints nothing. This is why the pre-fix loop
    // could never make progress — not a bug in the retry policy, the absence
    // of one.
    const replay = await store.createCut({
      tenantId: "t1",
      volumeId: "vol_1",
      branchName: "main",
      kind: "recovery",
      operationId: recoveryCutOperationId("jgen_1", "0"),
      requestCanonicalJson: store.createCutCalls[0]!.requestCanonicalJson,
      materializerVersion: "pfm-test",
    });
    expect((replay as HistoryOperationReplay).replayed).toBe(true);
    expect(store.cutCreateMutations).toBe(1);
    expect((await store.cutStatus("t1", "hcutrow_1"))!.state).toBe("failed");
  });

  test("a corrupt cut reaches a terminal outcome and stops logging every cycle", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const logs: string[] = [];
    const events: VolumeApiTelemetryEvent[] = [];
    let wall = 0;
    const loop = loopWith(store, { logs, events, now: () => wall });

    await loop.runCycle();
    store.failCut("hcutrow_1", corruptError);
    for (let cycle = 0; cycle < 10; cycle += 1) {
      wall += 60_000;
      store.dbNowMs += 60_000;
      await loop.runCycle();
    }

    // ONE line for ten cycles, not ten. The pre-fix loop logged every cycle.
    expect(logs).toHaveLength(1);
    // Re-cutting a corrupt source folds the same absent bytes: never tried.
    expect(store.cutCreateMutations).toBe(1);
    const last = events.at(-1) as Extract<
      VolumeApiTelemetryEvent,
      { type: "history_maintenance" }
    >;
    expect(last.cutsFailed).toBe(1);
    expect(last.cutsTerminal).toBe(1);
    expect(last.cutsRecreated).toBe(0);
    // The fleet-wide survey names it every cycle even though the log does not.
    expect(last.stuckGenerations).toBe(1);
    expect(last.oldestStuckAgeMs).toBeGreaterThan(0);
    expect(last.stuckSurveyUnavailable).toBe(false);
  });

  test("the terminal log carries the identity, the failure and the remedy", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const logs: string[] = [];
    const loop = loopWith(store, { logs, now: () => 0 });

    await loop.runCycle();
    store.failCut("hcutrow_1", corruptError);
    await loop.runCycle();

    const line = logs.join("\n");
    // Everything `cutsFailed: 1` never said.
    expect(line).toContain("t1");
    expect(line).toContain("vol_1");
    expect(line).toContain("main");
    expect(line).toContain("jgen_1");
    expect(line).toContain("hcutrow_1");
    expect(line).toContain("corrupt");
    expect(line).toContain("journal page at seq 0 is empty");
    expect(line).toContain("REMEDY");
    expect(line).toContain("pfj.journal_records");
  });

  test("a transient failure is re-cut under the next deterministic revision, and adoption unblocks", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const logs: string[] = [];
    const loop = loopWith(store, { logs, recoveryCutBackoffMs: 60_000, now: () => 0 });

    await loop.runCycle();
    store.failCut("hcutrow_1", {
      kind: "dead_letter",
      message: "cut exhausted its attempt budget",
      lastError: { kind: "transient", message: "history worker object store unreachable" },
    });

    // Inside the backoff: the cycle waits rather than hammering the worker.
    const waiting = await loop.runCycle();
    expect(waiting.cutsRetryDeferred).toBe(1);
    expect(waiting.cutsRecreated).toBe(0);
    expect(store.cutCreateMutations).toBe(1);

    // Past the backoff, on the DATABASE clock.
    store.dbNowMs += 120_000;
    const recut = await loop.runCycle();
    expect(recut.cutsRecreated).toBe(1);
    expect(store.cutCreateMutations).toBe(2);
    const operationIds = store.createCutCalls.map((call) => call.operationId);
    expect(operationIds).toContain(recoveryCutOperationId("jgen_1", "0"));
    expect(operationIds).toContain(recoveryCutOperationId("jgen_1", "0", 2));
    expect(recoveryCutOperationId("jgen_1", "0", 2)).toBe("hcut-jgen_1-0-r2");

    // The replacement materializes and the generation is UNBLOCKED: the base
    // advances and the backlog is subtracted, which is the whole point.
    store.markCutReady("hcutrow_2");
    const adopted = await loop.runCycle();
    expect(adopted.adoptionsApplied).toBe(1);
    expect(store.generations.get("jgen_1")!.baseSeq).toBe(900);
    expect(store.generations.get("jgen_1")!.backlogRecords).toBe(0);
    // A recovered generation is no longer stuck, and never logged at all.
    expect(adopted.stuckGenerations).toBe(0);
    expect(logs).toHaveLength(0);
  });

  test("revision 1 keeps its frozen operation id and request bytes", async () => {
    // The production operation rows for hcut-<generation>-<baseSeq> carry a
    // permanent request fingerprint. A changed shape would answer PF009 on
    // every cycle for every generation — one stuck cut traded for a
    // fleet-wide outage.
    expect(recoveryCutOperationId("jgen_1", "0")).toBe("hcut-jgen_1-0");
    expect(recoveryCutOperationId("jgen_1", "0", 1)).toBe("hcut-jgen_1-0");

    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    await loopWith(store).runCycle();
    expect(JSON.parse(store.createCutCalls[0]!.requestCanonicalJson)).toEqual({
      v: "1",
      op: "history-maintenance-recovery-cut",
      tenantId: "t1",
      volumeId: "vol_1",
      branchName: "main",
      generationId: "jgen_1",
      baseSeq: "0",
    });
  });

  test("the re-cut budget is bounded and ends in one terminal outcome", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const logs: string[] = [];
    const loop = loopWith(store, {
      logs,
      recoveryCutMaxRevisions: 3,
      recoveryCutBackoffMs: 1_000,
      now: () => 0,
    });

    await loop.runCycle();
    for (let cycle = 0; cycle < 8; cycle += 1) {
      store.failAllPending({ kind: "transient", message: "worker unreachable" });
      store.dbNowMs += 3_600_000;
      await loop.runCycle();
    }

    // Three revisions, then stop: a permanently broken source must not mint
    // cut rows without bound into the table reclamation is trying to shrink.
    expect(store.cutCreateMutations).toBe(3);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("budget");
    expect(store.adoptCalls).toHaveLength(0);
  });

  test("an operator's cancel is terminal: the loop never quietly re-cuts it", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const logs: string[] = [];
    const loop = loopWith(store, { logs, now: () => 0 });

    await loop.runCycle();
    store.cuts.get("hcutrow_1")!.state = "canceled";
    const summary = await loop.runCycle();

    expect(summary.cutsTerminal).toBe(1);
    expect(summary.cutsRecreated).toBe(0);
    expect(store.cutCreateMutations).toBe(1);
    expect(logs[0]).toContain("canceled");
  });

  test("a pre-034 store reports that nothing can enumerate the blocked volumes", async () => {
    const store = new FakeHistoryStore();
    store.addGeneration(backloggedGeneration());
    const older: HistoryMaintenanceStore = {
      generationsPastThreshold: (percent, limit) => store.generationsPastThreshold(percent, limit),
      createCut: (input) => store.createCut(input),
      cutStatus: (tenantId, cutId) => store.cutStatus(tenantId, cutId),
      adoptCut: (input) => store.adoptCut(input),
      unreleasedServingPins: (limit) => store.unreleasedServingPins(limit),
      releaseServingPinFenced: (id) => store.releaseServingPinFenced(id),
    };
    const summary = await loopWith(older).runCycle();

    // Silence would be indistinguishable from "nothing is stuck".
    expect(summary.stuckSurveyUnavailable).toBe(true);
    expect(summary.stuckGenerations).toBe(0);
    expect(summary.failures).toBe(0);
  });

  test("classifies the recorded failure the worker actually wrote", () => {
    expect(classifyCutFailure({ state: "failed", lastError: { kind: "corrupt" } })).toBe(
      "permanent"
    );
    expect(classifyCutFailure({ state: "canceled" })).toBe("permanent");
    expect(
      classifyCutFailure({
        state: "failed",
        lastError: { kind: "dead_letter", lastError: { kind: "corrupt" } },
      })
    ).toBe("permanent");
    // A dead letter that exhausted its budget on TRANSIENT errors is still a
    // transient story: a fresh cut, later, can succeed.
    expect(
      classifyCutFailure({
        state: "failed",
        lastError: { kind: "dead_letter", lastError: { kind: "transient" } },
      })
    ).toBe("transient");
    expect(classifyCutFailure({ state: "failed", lastError: { kind: "transient" } })).toBe(
      "transient"
    );
    // An unrecorded kind biases toward a bounded retry: wrongly calling a
    // transient failure permanent strands a writable volume.
    expect(classifyCutFailure({ state: "failed" })).toBe("transient");

    expect(
      recordedCutFailure({
        state: "failed",
        lastError: { kind: "dead_letter", lastError: { kind: "transient", message: "no worker" } },
      })
    ).toEqual({ kind: "dead_letter/transient", message: "no worker" });
  });

  test("every remedy names a concrete next step", () => {
    for (const kind of ["corrupt", "dead_letter/corrupt", "canceled", "transient", "unknown"]) {
      const remedy = terminalRemedy(kind);
      expect(remedy).toContain("REMEDY");
      expect(remedy.length).toBeGreaterThan(80);
    }
    expect(terminalRemedy("corrupt")).toContain("DELETE /v1/volumes/:id");
    expect(terminalRemedy("transient")).toContain("POST /v1/admin/history/cuts");
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
