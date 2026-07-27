import {
  historyMaterializerVersion,
  pft2ServingCapability,
  type AdoptCutResult,
  type GenerationBacklogStatus,
  type HistoryCutCreateInput,
  type HistoryCutStatus,
  type ServingPinStatus,
} from "@portablefs/metadata-db";
import { intEnv } from "./config.js";
import type { VolumeApiTelemetry } from "./telemetry.js";

// ---------------------------------------------------------------------------
// Journal-bounding maintenance loop.
//
// PFJ3 generations are admission-bounded (4 GiB / 1,048,576 records by
// default, plus the fixed control reserve) and RESUMED — never rotated —
// across child restarts, so a branch's backlog persists for its lifetime.
// The ONLY way backlog shrinks is history-cut adoption: a ready RECOVERY cut
// of the managed journal is adopted (pfh.cut_adopt), which verifies the
// recovery anchor and advances the generation's base tuple while subtracting
// the captured cumulative backlog in O(1). Without a driver, every managed
// branch's backlog grows until the quota bricks its writes. This loop is the
// driver; keeping it on is what keeps volumes writable.
//
// Every cycle, on every replica, STATELESSLY:
//   1. Scan live PFJ3 generations past the backlog threshold (percent of the
//      generation quota; bytes OR records, whichever crosses first).
//   2. For each, call cut_create kind=recovery under the DETERMINISTIC
//      operation id hcut-<generationId>-<baseSeq>. The base seq advances
//      only through adoption, so there is exactly one live operation per
//      (generation, base) — replays (crash, restart, a concurrent replica)
//      return the recorded outcome instead of minting a second cut. Exact-
//      once is by construction, not by in-memory tracking.
//   3. When the cut reports ready, adopt it (anchor + serving capability)
//      under the deterministic id hadopt-<cutId>: an operation replay is a
//      recorded no-op, so a crash between adopt and ack replays cleanly.
//   4. Offer every unreleased serving pin to serving_pin_release_fenced.
//      Release happens ONLY on provable supersession (advanced writer fence,
//      terminal generation, released/expired lease — the idle eviction of
//      managed children supplies this naturally); refusal for a live pinned
//      runtime is the expected answer.
//
// Benign concurrency refusals (PF011 proof refusals such as "an older
// pending cut still pins the prefix" or "pin runtime is not durably
// superseded", PF002 exact-tuple conflicts from a racing adoption, PF007
// rows that vanished between scan and call) are counted, never logged as
// errors. Real failures (policy missing, dead-lettered cuts) are logged with
// their typed code and surface in the per-cycle counters.
//
// DRAIN INVARIANT (see runtime.ts): process shutdown must never checkpoint
// or block on history work. The loop's timer is unref'd, cycles check the
// pause hook between every repository call and bail promptly, nothing here
// registers with the runtime's tracked durable effects, and mid-cycle work
// simply resumes on the next process — the database operation ids make the
// resume exact.
// ---------------------------------------------------------------------------

export interface HistoryMaintenanceSettings {
  enabled: boolean;
  intervalMs: number;
  backlogPercent: number;
}

/**
 * PORTABLEFS_HISTORY_MAINTENANCE(_INTERVAL_MS/_BACKLOG_PERCENT) parsing.
 * "off" is refused in production NODE_ENV: without the loop, managed
 * branches accumulate backlog until the admission quota bricks writes.
 */
export function historyMaintenanceSettingsFromEnv(
  env: NodeJS.ProcessEnv
): HistoryMaintenanceSettings {
  const raw = env.PORTABLEFS_HISTORY_MAINTENANCE?.trim();
  let enabled: boolean;
  if (raw === undefined || raw === "" || raw === "on") {
    enabled = true;
  } else if (raw === "off") {
    if (env.NODE_ENV === "production") {
      throw new Error(
        "PORTABLEFS_HISTORY_MAINTENANCE=off is refused in production: the journal-bounding " +
          "maintenance loop is what keeps managed volumes writable (PFJ3 backlog only shrinks " +
          "through recovery-cut adoption). Unset it, or set it to on."
      );
    }
    enabled = false;
  } else {
    throw new Error("PORTABLEFS_HISTORY_MAINTENANCE must be on, off, or unset.");
  }
  return {
    enabled,
    // Floor of 1s: a misconfigured near-zero interval would hammer PostgreSQL.
    intervalMs: intEnv(env, "PORTABLEFS_HISTORY_MAINTENANCE_INTERVAL_MS", 60_000, 1_000),
    backlogPercent: intEnv(env, "PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT", 70, 1, 100),
  };
}

/**
 * The replayed-operation projection pfh.resource_operation_begin returns
 * when a deterministic operation id is presented again: the recorded state
 * plus the target ids / settled response of the ORIGINAL run.
 */
export interface HistoryOperationReplay {
  operationId: string;
  state: string;
  replayed: true;
  targetIds?: Record<string, string> | undefined;
  response?: unknown;
}

/**
 * The exact pfh caller surface the loop drives. PostgresHistoryRepository
 * satisfies it structurally; tests substitute a fake with database-faithful
 * operation-id replay semantics.
 */
export interface HistoryMaintenanceStore {
  generationsPastThreshold(
    backlogPercent: number,
    limit?: number
  ): Promise<GenerationBacklogStatus[]>;
  createCut(input: HistoryCutCreateInput): Promise<HistoryCutStatus | HistoryOperationReplay>;
  cutStatus(tenantId: string, cutId: string): Promise<HistoryCutStatus | null>;
  adoptCut(input: {
    tenantId: string;
    cutId: string;
    anchorId: string;
    operationId: string;
    requestCanonicalJson: string;
    servingCapability: string;
  }): Promise<AdoptCutResult | HistoryOperationReplay>;
  unreleasedServingPins(limit?: number): Promise<ServingPinStatus[]>;
  releaseServingPinFenced(adoptionId: string): Promise<{ released: boolean; reason: string }>;
}

export interface HistoryMaintenanceCycleSummary {
  generationsScanned: number;
  cutsCreated: number;
  cutsPending: number;
  cutsFailed: number;
  adoptionsApplied: number;
  /** Ready cuts NOT adopted because exact history serving is unconfigured. */
  adoptionsBlocked: number;
  pinsScanned: number;
  pinsReleased: number;
  benignRefusals: number;
  failures: number;
  topBacklogPercent: number;
}

export interface HistoryMaintenanceLoopOptions {
  store: HistoryMaintenanceStore;
  intervalMs: number;
  backlogPercent: number;
  /** One structured line per cycle (the shared telemetry event set). */
  telemetry: VolumeApiTelemetry;
  /**
   * Whether THIS deployment serves exact PFT2 history reads
   * (PFH_WORKER_STORES_JSON / VOLUME_HISTORY_STORES_JSON present). Adoption
   * moves the branch base onto a PFT2 commit that the NEXT cold start must
   * fetch through /v1/history/*; adopting while serving is unconfigured
   * would strand that restart behind HISTORY_SERVING_UNAVAILABLE. When
   * false, the loop still creates and materializes recovery cuts (ready
   * cuts are instantly adoptable once serving is configured) but refuses
   * the adoption step and reports it per cycle.
   */
  servingConfigured: boolean;
  /** Checked between repository calls; true bails the cycle (drain). */
  shouldPause?: (() => boolean) | undefined;
  /** Real failures only — benign concurrency refusals never reach it. */
  log?: ((message: string) => void) | undefined;
  scanLimit?: number | undefined;
}

/** Deterministic per-(generation, base) cut identity: exact-once by construction. */
export function recoveryCutOperationId(generationId: string, baseSeq: string): string {
  return `hcut-${generationId}-${baseSeq}`;
}

/** Deterministic per-cut adoption identity: crash/replay is a recorded no-op. */
export function adoptionOperationId(cutId: string): string {
  return `hadopt-${cutId}`;
}

// Canonical request bytes for the deterministic operations. Field order is
// FROZEN: the database fingerprints these bytes permanently, and a replay
// with different bytes is a typed PF009 conflict — every replica must
// therefore derive byte-identical requests from the same scan facts.
function recoveryCutCanonicalJson(row: {
  tenantId: string;
  volumeId: string;
  branchName: string;
  generationId: string;
  baseSeq: string;
}): string {
  return JSON.stringify({
    v: "1",
    op: "history-maintenance-recovery-cut",
    tenantId: row.tenantId,
    volumeId: row.volumeId,
    branchName: row.branchName,
    generationId: row.generationId,
    baseSeq: row.baseSeq,
  });
}

function adoptionCanonicalJson(input: {
  tenantId: string;
  cutId: string;
  anchorId: string;
}): string {
  return JSON.stringify({
    v: "1",
    op: "history-maintenance-adopt",
    tenantId: input.tenantId,
    cutId: input.cutId,
    anchorId: input.anchorId,
  });
}

/**
 * Benign concurrency refusals: the fenced SQL machinery refusing exactly as
 * designed while replicas race. PF011 = proof refusal (older pending cut
 * still pins the prefix; pin runtime not durably superseded), PF002 =
 * exact-tuple conflict (a racing adoption advanced the base first), PF007 =
 * the row vanished between scan and call.
 */
export function isBenignHistoryRefusal(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return code === "PF011" || code === "PF002" || code === "PF007";
}

function isOperationReplay(
  value: HistoryCutStatus | AdoptCutResult | HistoryOperationReplay
): value is HistoryOperationReplay {
  return (value as { replayed?: unknown }).replayed === true;
}

// The cut id of a replayed cut-create operation: recorded onto targetIds in
// the creating transaction, echoed in the settled response.
function replayCutId(replay: HistoryOperationReplay): string | undefined {
  const fromTargets = replay.targetIds?.cutId;
  if (typeof fromTargets === "string" && fromTargets.length > 0) {
    return fromTargets;
  }
  const response = replay.response as { cutId?: unknown } | null | undefined;
  return typeof response?.cutId === "string" && response.cutId.length > 0
    ? response.cutId
    : undefined;
}

function describeError(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  const message = error instanceof Error ? error.message : String(error);
  return `${typeof code === "string" ? `${code}: ` : ""}${message}`.slice(0, 256);
}

function emptySummary(): HistoryMaintenanceCycleSummary {
  return {
    generationsScanned: 0,
    cutsCreated: 0,
    cutsPending: 0,
    cutsFailed: 0,
    adoptionsApplied: 0,
    adoptionsBlocked: 0,
    pinsScanned: 0,
    pinsReleased: 0,
    benignRefusals: 0,
    failures: 0,
    topBacklogPercent: 0,
  };
}

export class HistoryMaintenanceLoop {
  private readonly store: HistoryMaintenanceStore;
  private readonly intervalMs: number;
  private readonly backlogPercent: number;
  private readonly telemetry: VolumeApiTelemetry;
  private readonly servingConfigured: boolean;
  private readonly shouldPause: () => boolean;
  private readonly log: (message: string) => void;
  private readonly scanLimit: number;
  private warnedServingUnconfigured = false;

  private stopped = false;
  private timer: NodeJS.Timeout | undefined;

  constructor(options: HistoryMaintenanceLoopOptions) {
    this.store = options.store;
    this.intervalMs = validatedPositiveInt(options.intervalMs, "intervalMs");
    this.backlogPercent = validatedPositiveInt(options.backlogPercent, "backlogPercent");
    this.telemetry = options.telemetry;
    this.servingConfigured = options.servingConfigured;
    this.shouldPause = options.shouldPause ?? (() => false);
    this.log = options.log ?? ((message) => console.warn(message));
    this.scanLimit = options.scanLimit ?? 256;
  }

  /** Runs one cycle immediately, then re-arms after each completed cycle. */
  start(): void {
    this.scheduleNext(0);
  }

  /**
   * Prompt and clean: clears the timer and stops admitting new steps. An
   * in-flight repository call is NOT awaited (drain must never block on
   * history work); the deterministic operation ids make next process's
   * resume exact.
   */
  stop(): void {
    this.stopped = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }

  private scheduleNext(delayMs: number): void {
    if (this.stopped) {
      return;
    }
    // Cycles never overlap in one process: the next timer is armed only
    // after the current cycle settles. unref keeps process exit independent.
    this.timer = setTimeout(() => {
      void this.runCycle().then(() => this.scheduleNext(this.intervalMs));
    }, delayMs);
    this.timer.unref?.();
  }

  private halted(): boolean {
    return this.stopped || this.shouldPause();
  }

  /** One full cycle. Never rejects; every outcome lands in the summary. */
  async runCycle(): Promise<HistoryMaintenanceCycleSummary> {
    const summary = emptySummary();
    if (this.halted()) {
      return summary;
    }

    let rows: GenerationBacklogStatus[] = [];
    try {
      rows = await this.store.generationsPastThreshold(this.backlogPercent, this.scanLimit);
    } catch (error) {
      this.recordFailure(summary, "generation scan", error);
      this.emit(summary);
      return summary;
    }
    summary.generationsScanned = rows.length;
    for (const row of rows) {
      summary.topBacklogPercent = Math.max(summary.topBacklogPercent, row.backlogPercent);
    }

    for (const row of rows) {
      if (this.halted()) {
        break;
      }
      await this.boundGeneration(row, summary);
    }

    if (!this.halted()) {
      await this.sweepServingPins(summary);
    }

    this.emit(summary);
    return summary;
  }

  // Drive one backlogged generation one step forward: ensure its recovery
  // cut exists (deterministic id; replay-safe), and adopt it once ready.
  private async boundGeneration(
    row: GenerationBacklogStatus,
    summary: HistoryMaintenanceCycleSummary
  ): Promise<void> {
    try {
      const outcome = await this.store.createCut({
        tenantId: row.tenantId,
        volumeId: row.volumeId,
        branchName: row.branchName,
        kind: "recovery",
        operationId: recoveryCutOperationId(row.generationId, row.baseSeq),
        requestCanonicalJson: recoveryCutCanonicalJson(row),
        materializerVersion: historyMaterializerVersion,
        targetIds: { generationId: row.generationId },
      });

      let cut: HistoryCutStatus;
      if (isOperationReplay(outcome)) {
        const cutId = replayCutId(outcome);
        if (!cutId) {
          // The operation exists but records no cut yet — only observable
          // mid-race; the next cycle re-derives everything from the database.
          summary.benignRefusals += 1;
          return;
        }
        const status = await this.store.cutStatus(row.tenantId, cutId);
        if (!status) {
          summary.benignRefusals += 1;
          return;
        }
        cut = status;
      } else {
        cut = outcome;
        if (cut.state === "pending") {
          summary.cutsCreated += 1;
        }
      }

      if (cut.state === "pending" || cut.state === "materializing") {
        summary.cutsPending += 1;
        return;
      }
      if (cut.state === "failed" || cut.state === "canceled") {
        // Permanent for this (generation, base): the worker dead-lettered or
        // an operator canceled. Not a race — surface it for operators (the
        // admin history routes drive the same machinery manually).
        summary.cutsFailed += 1;
        this.log(
          `PortableFS history maintenance: recovery cut ${cut.cutId} for generation ` +
            `${row.generationId} is ${cut.state}; adoption is blocked until an operator intervenes.`
        );
        return;
      }

      // ready → adopt. adopt(cutId, anchorId): both arms must bound the SAME
      // cut; a ready recovery cut always carries its recovery anchor.
      if (!cut.recoveryAnchorId) {
        this.recordFailure(
          summary,
          `cut ${cut.cutId}`,
          new Error("ready recovery cut reports no recovery anchor")
        );
        return;
      }
      // Adoption gate: the post-adoption base is a PFT2 commit the NEXT cold
      // start fetches through /v1/history/*. Without exact history serving
      // configured on this deployment, adopting would strand that restart —
      // hold at "ready" (still a trim pin, instantly adoptable once serving
      // is configured) and say so once per process plus once per cycle line.
      if (!this.servingConfigured) {
        summary.adoptionsBlocked += 1;
        if (!this.warnedServingUnconfigured) {
          this.warnedServingUnconfigured = true;
          this.log(
            "PortableFS history maintenance: recovery cuts are ready but adoption is held: " +
              "exact history serving is not configured (PFH_WORKER_STORES_JSON / " +
              "VOLUME_HISTORY_STORES_JSON), and an adopted PFT2 base would strand the next " +
              "cold start. Configure the history stores to resume journal bounding."
          );
        }
        return;
      }
      const adoption = await this.store.adoptCut({
        tenantId: row.tenantId,
        cutId: cut.cutId,
        anchorId: cut.recoveryAnchorId,
        operationId: adoptionOperationId(cut.cutId),
        requestCanonicalJson: adoptionCanonicalJson({
          tenantId: row.tenantId,
          cutId: cut.cutId,
          anchorId: cut.recoveryAnchorId,
        }),
        servingCapability: pft2ServingCapability,
      });
      if (!isOperationReplay(adoption)) {
        summary.adoptionsApplied += 1;
      }
      // A replay means an earlier run (or another replica) already adopted:
      // the recorded outcome IS the outcome — an exact no-op.
    } catch (error) {
      this.classify(summary, `generation ${row.generationId}`, error);
    }
  }

  private async sweepServingPins(summary: HistoryMaintenanceCycleSummary): Promise<void> {
    let pins: ServingPinStatus[] = [];
    try {
      pins = await this.store.unreleasedServingPins(this.scanLimit);
    } catch (error) {
      this.recordFailure(summary, "serving pin scan", error);
      return;
    }
    summary.pinsScanned = pins.length;
    for (const pin of pins) {
      if (this.halted()) {
        return;
      }
      try {
        const outcome = await this.store.releaseServingPinFenced(pin.adoptionId);
        if (outcome.released) {
          summary.pinsReleased += 1;
        }
      } catch (error) {
        // A live pinned runtime refuses with PF011 — the fence working as
        // designed, not an error. Release arrives once the child restarts or
        // fails over (the idle eviction guarantees an upper bound).
        this.classify(summary, `serving pin ${pin.adoptionId}`, error);
      }
    }
  }

  private classify(
    summary: HistoryMaintenanceCycleSummary,
    label: string,
    error: unknown
  ): void {
    if (isBenignHistoryRefusal(error)) {
      summary.benignRefusals += 1;
      return;
    }
    this.recordFailure(summary, label, error);
  }

  private recordFailure(
    summary: HistoryMaintenanceCycleSummary,
    label: string,
    error: unknown
  ): void {
    summary.failures += 1;
    this.log(`PortableFS history maintenance ${label} failed: ${describeError(error)}`);
  }

  private emit(summary: HistoryMaintenanceCycleSummary): void {
    this.telemetry.emit({ type: "history_maintenance", ...summary });
  }
}

function validatedPositiveInt(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`HistoryMaintenanceLoop ${name} must be a positive safe integer.`);
  }
  return value;
}
