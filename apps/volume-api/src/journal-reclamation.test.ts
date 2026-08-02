import { describe, expect, test } from "vitest";
import type {
  AdoptCutResult,
  GenerationBacklogStatus,
  HistoryCutCreateInput,
  HistoryCutStatus,
  JournalReclaimCandidate,
  JournalReclaimResult,
  ServingPinStatus,
} from "@portablefs/metadata-db";
import {
  HistoryMaintenanceLoop,
  recoveryCutOperationId,
  type HistoryMaintenanceStore,
  type HistoryOperationReplay,
} from "./history-maintenance.js";
import type { VolumeApiTelemetryEvent } from "./telemetry.js";

// ---------------------------------------------------------------------------
// Journal reclamation (migration 031).
//
// Verified gap this pins: pfj.journal_records rows were NEVER physically
// deleted. Adoption (pfh.cut_adopt -> pfj.history_adopt_base) advances
// base_seq and subtracts the backlog counters in O(1) — a LOGICAL trim —
// while every BYTEA payload below the base stays in Postgres forever.
// pfj.journal_physical_trim (009) was the only DELETE against that table in
// the repo, and it had no GRANT, no caller, and was frozen for pfj3 by the
// 013 freeze trigger. This deployment filled its production control store
// twice (5 GB, then 20 GB) purely with test-branch journal data, and the
// only cure was manual SQL.
//
// The fake below is DELIBERATELY faithful to that split: adopting moves the
// base and shrinks the backlog counters, and does not delete one record.
// Only the reclaim call deletes.
// ---------------------------------------------------------------------------

interface FakeGen {
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  generationId: string;
  status: "active" | "suspended";
  baseSeq: number;
  nextSeq: number;
  physicalTrimmedSeq: number;
  /** Idle age in ms; the loop's retention decides what to do with it. */
  idleMs: number;
  /** Every record ever appended, by seq. This is the control-store storage. */
  records: Map<number, number>;
}

class ReclaimingStore implements HistoryMaintenanceStore {
  readonly gens = new Map<string, FakeGen>();
  readonly reclaimCalls: string[] = [];
  readonly cutCalls: string[] = [];
  lastRetentionMs: number | undefined;

  addGeneration(gen: Omit<FakeGen, "records"> & { recordBytes: number }): void {
    const records = new Map<number, number>();
    for (let seq = gen.physicalTrimmedSeq; seq < gen.nextSeq; seq += 1) {
      records.set(seq, gen.recordBytes);
    }
    this.gens.set(gen.generationId, { ...gen, records });
  }

  totalStoredRecords(): number {
    let total = 0;
    for (const gen of this.gens.values()) {
      total += gen.records.size;
    }
    return total;
  }

  // ── the pre-existing backlog surface (unchanged) ─────────────────────────

  async generationsPastThreshold(): Promise<GenerationBacklogStatus[]> {
    return [];
  }

  async createCut(input: HistoryCutCreateInput): Promise<HistoryCutStatus> {
    this.cutCalls.push(input.operationId);
    // Cut + adopt: the base advances to the head. NOT ONE RECORD IS DELETED —
    // this is exactly the logical/physical split that filled the database.
    const gen = [...this.gens.values()].find(
      (candidate) => candidate.branchName === input.branchName
    );
    if (gen) {
      gen.baseSeq = gen.nextSeq;
    }
    return {
      cutId: `cut_${input.operationId}`,
      tenantId: input.tenantId,
      state: "pending",
    } as unknown as HistoryCutStatus;
  }

  async cutStatus(): Promise<HistoryCutStatus | null> {
    return null;
  }

  async adoptCut(): Promise<AdoptCutResult | HistoryOperationReplay> {
    throw new Error("not reached in these tests");
  }

  async unreleasedServingPins(): Promise<ServingPinStatus[]> {
    return [];
  }

  async releaseServingPinFenced(): Promise<{ released: boolean; reason: string }> {
    return { released: false, reason: "not reached" };
  }

  // ── the 031 reclamation surface ──────────────────────────────────────────

  async journalReclaimCandidates(
    limit = 32,
    retentionMs = 604_800_000
  ): Promise<JournalReclaimCandidate[]> {
    this.lastRetentionMs = retentionMs;
    const out: JournalReclaimCandidate[] = [];
    for (const gen of this.gens.values()) {
      // Faithful to 031: the span comes from the generation row, and only an
      // EXISTS touches the journal. Nothing counts the backlog.
      const horizon = gen.baseSeq;
      const span = Math.max(horizon - gen.physicalTrimmedSeq, 0);
      const anyLeft = [...gen.records.keys()].some((seq) => seq < horizon);
      const aged = gen.status === "suspended" && gen.idleMs > retentionMs;
      if (!(span > 0 && anyLeft) && !(aged && gen.nextSeq > gen.baseSeq)) {
        continue;
      }
      out.push({
        generationId: gen.generationId,
        tenantId: gen.tenantId,
        volumeId: gen.volumeId,
        branchId: gen.branchId,
        branchName: gen.branchName,
        status: gen.status,
        recordCodec: "pfj3",
        baseSeq: String(gen.baseSeq),
        nextSeq: String(gen.nextSeq),
        horizonSeq: String(horizon),
        reclaimableRecords: String(span > 0 && anyLeft ? span : 0),
        suspendedPastRetention: aged,
      });
    }
    out.sort((a, b) => Number(b.reclaimableRecords) - Number(a.reclaimableRecords));
    return out.slice(0, limit);
  }

  async reclaimJournalRecords(input: {
    generationId: string;
    maxRows?: number;
  }): Promise<JournalReclaimResult> {
    this.reclaimCalls.push(input.generationId);
    const gen = this.gens.get(input.generationId);
    if (!gen) {
      throw Object.assign(new Error("journal generation not found"), { code: "PF007" });
    }
    const limit = input.maxRows ?? 512;
    // The proven horizon: never at or above the logical base.
    const doomed = [...gen.records.keys()]
      .filter((seq) => seq < gen.baseSeq)
      .sort((a, b) => a - b)
      .slice(0, limit);
    let bytes = 0;
    for (const seq of doomed) {
      bytes += gen.records.get(seq) ?? 0;
      gen.records.delete(seq);
      gen.physicalTrimmedSeq = Math.max(gen.physicalTrimmedSeq, seq + 1);
    }
    return {
      generationId: input.generationId,
      deletedRecords: String(doomed.length),
      deletedBytes: String(bytes),
      horizonSeq: String(gen.baseSeq),
      more: doomed.length >= limit,
    };
  }
}

function loop(
  store: HistoryMaintenanceStore,
  options: {
    events?: VolumeApiTelemetryEvent[];
    reclaimBatchRows?: number;
    reclaimMaxPagesPerCycle?: number;
    journalRetentionMs?: number;
    logs?: string[];
  } = {}
): HistoryMaintenanceLoop {
  const events = options.events ?? [];
  return new HistoryMaintenanceLoop({
    store,
    intervalMs: 60_000,
    backlogPercent: 70,
    telemetry: { emit: (event) => events.push(event) },
    servingConfigured: true,
    log: (message) => options.logs?.push(message),
    ...(options.reclaimBatchRows !== undefined
      ? { reclaimBatchRows: options.reclaimBatchRows }
      : {}),
    ...(options.reclaimMaxPagesPerCycle !== undefined
      ? { reclaimMaxPagesPerCycle: options.reclaimMaxPagesPerCycle }
      : {}),
    ...(options.journalRetentionMs !== undefined
      ? { journalRetentionMs: options.journalRetentionMs }
      : {}),
  });
}

describe("journal storage reclamation", () => {
  test("a cycle physically DELETES the records below an adopted base", async () => {
    const store = new ReclaimingStore();
    store.addGeneration({
      tenantId: "t1",
      volumeId: "vol_1",
      branchId: "br_1",
      branchName: "main",
      generationId: "gen_1",
      status: "active",
      // Already cut and adopted: the base is at the head, and every record
      // below it is pure waste that used to live forever.
      baseSeq: 0,
      nextSeq: 1_000,
      physicalTrimmedSeq: 0,
      idleMs: 0,
      recordBytes: 4_096,
    });
    store.gens.get("gen_1")!.baseSeq = 1_000;
    expect(store.totalStoredRecords()).toBe(1_000);

    const summary = await loop(store, { reclaimBatchRows: 256 }).runCycle();

    expect(store.totalStoredRecords()).toBe(0);
    expect(summary.recordsReclaimed).toBe(1_000);
    expect(summary.bytesReclaimed).toBe(1_000 * 4_096);
    expect(summary.reclaimCandidates).toBe(1);
  });

  test("records at or above the base are NEVER reclaimed", async () => {
    const store = new ReclaimingStore();
    store.addGeneration({
      tenantId: "t1",
      volumeId: "vol_1",
      branchId: "br_1",
      branchName: "main",
      generationId: "gen_1",
      status: "active",
      baseSeq: 600,
      nextSeq: 1_000,
      physicalTrimmedSeq: 0,
      idleMs: 0,
      recordBytes: 1_000,
    });

    const summary = await loop(store).runCycle();

    // Exactly the 600 below the base; the live tail is untouched.
    expect(summary.recordsReclaimed).toBe(600);
    expect(store.totalStoredRecords()).toBe(400);
    expect(Math.min(...store.gens.get("gen_1")!.records.keys())).toBe(600);
  });

  test("reclamation is bounded per cycle: it never becomes one unbounded DELETE", async () => {
    const store = new ReclaimingStore();
    store.addGeneration({
      tenantId: "t1",
      volumeId: "vol_1",
      branchId: "br_1",
      branchName: "main",
      generationId: "gen_1",
      status: "active",
      baseSeq: 0,
      nextSeq: 10_000,
      physicalTrimmedSeq: 0,
      idleMs: 0,
      recordBytes: 1,
    });
    store.gens.get("gen_1")!.baseSeq = 10_000;

    const bounded = loop(store, { reclaimBatchRows: 100, reclaimMaxPagesPerCycle: 3 });
    const first = await bounded.runCycle();

    expect(first.recordsReclaimed).toBe(300);
    expect(store.reclaimCalls).toHaveLength(3);
    // The rest drains across later cycles; each transaction stays small,
    // because a database that is out of disk cannot afford a big one.
    expect(store.totalStoredRecords()).toBe(9_700);
  });

  test("a suspended generation idle past retention is cut on AGE, not on backlog size", async () => {
    const store = new ReclaimingStore();
    store.addGeneration({
      tenantId: "t1",
      volumeId: "vol_1",
      branchId: "br_1",
      branchName: "abandoned-test-branch",
      generationId: "gen_idle",
      status: "suspended",
      // Far below any percent-of-quota threshold: the backlog scan would
      // NEVER return this generation, so it was never cut, never adopted,
      // and never reclaimable. This is the shape of the data that filled
      // production twice.
      baseSeq: 0,
      nextSeq: 40,
      physicalTrimmedSeq: 0,
      idleMs: 30 * 24 * 60 * 60 * 1_000,
      recordBytes: 8_192,
    });

    const summary = await loop(store, { journalRetentionMs: 7 * 24 * 60 * 60 * 1_000 }).runCycle();

    expect(summary.agedGenerationsForced).toBe(1);
    expect(store.cutCalls).toContain(recoveryCutOperationId("gen_idle", "0"));
  });

  test("a suspended generation INSIDE its retention window is left alone", async () => {
    const store = new ReclaimingStore();
    store.addGeneration({
      tenantId: "t1",
      volumeId: "vol_1",
      branchId: "br_1",
      branchName: "between-mounts",
      generationId: "gen_recent",
      status: "suspended",
      baseSeq: 0,
      nextSeq: 40,
      physicalTrimmedSeq: 0,
      idleMs: 60_000,
      recordBytes: 8_192,
    });

    const summary = await loop(store, { journalRetentionMs: 7 * 24 * 60 * 60 * 1_000 }).runCycle();

    expect(summary.agedGenerationsForced).toBe(0);
    expect(store.cutCalls).toHaveLength(0);
    expect(store.totalStoredRecords()).toBe(40);
  });

  test("the retention window reaches the store verbatim", async () => {
    const store = new ReclaimingStore();
    await loop(store, { journalRetentionMs: 3_600_000 }).runCycle();
    expect(store.lastRetentionMs).toBe(3_600_000);
  });

  test("a store without the 031 surface reports it instead of silently accumulating", async () => {
    const events: VolumeApiTelemetryEvent[] = [];
    const logs: string[] = [];
    const store = new ReclaimingStore();
    const legacy = {
      ...store,
      journalReclaimCandidates: undefined,
      reclaimJournalRecords: undefined,
      generationsPastThreshold: () => store.generationsPastThreshold(),
      createCut: (input: HistoryCutCreateInput) => store.createCut(input),
      cutStatus: () => store.cutStatus(),
      adoptCut: () => store.adoptCut(),
      unreleasedServingPins: () => store.unreleasedServingPins(),
      releaseServingPinFenced: () => store.releaseServingPinFenced(),
    } as unknown as HistoryMaintenanceStore;

    const summary = await loop(legacy, { events, logs }).runCycle();

    expect(summary.reclaimUnavailable).toBe(true);
    // Not a failure and not a log line: an older lineage is a deployment
    // fact. It still reaches the operator through the cycle telemetry.
    expect(summary.failures).toBe(0);
    expect(logs).toHaveLength(0);
    expect(events.some((event) => (event as { reclaimUnavailable?: boolean }).reclaimUnavailable)).toBe(
      true
    );
  });

  test("a generation that vanished between scan and reclaim is benign, never a failure", async () => {
    const store = new ReclaimingStore();
    store.addGeneration({
      tenantId: "t1",
      volumeId: "vol_1",
      branchId: "br_1",
      branchName: "main",
      generationId: "gen_gone",
      status: "active",
      baseSeq: 0,
      nextSeq: 10,
      physicalTrimmedSeq: 0,
      idleMs: 0,
      recordBytes: 1,
    });
    store.gens.get("gen_gone")!.baseSeq = 10;
    const logs: string[] = [];
    const running = loop(store, { logs });
    const original = store.reclaimJournalRecords.bind(store);
    store.reclaimJournalRecords = async (input) => {
      store.gens.delete("gen_gone");
      return original(input);
    };

    const summary = await running.runCycle();

    expect(summary.failures).toBe(0);
    expect(summary.benignRefusals).toBe(1);
    expect(logs).toHaveLength(0);
  });

  test("the cycle telemetry carries the reclamation numbers an operator had none of", async () => {
    const events: VolumeApiTelemetryEvent[] = [];
    const store = new ReclaimingStore();
    store.addGeneration({
      tenantId: "t1",
      volumeId: "vol_1",
      branchId: "br_1",
      branchName: "main",
      generationId: "gen_1",
      status: "active",
      baseSeq: 0,
      nextSeq: 5,
      physicalTrimmedSeq: 0,
      idleMs: 0,
      recordBytes: 100,
    });
    store.gens.get("gen_1")!.baseSeq = 5;

    await loop(store, { events }).runCycle();

    const cycle = events.find((event) => event.type === "history_maintenance") as unknown as {
      recordsReclaimed: number;
      bytesReclaimed: number;
      reclaimCandidates: number;
    };
    expect(cycle.recordsReclaimed).toBe(5);
    expect(cycle.bytesReclaimed).toBe(500);
    expect(cycle.reclaimCandidates).toBe(1);
  });
});
