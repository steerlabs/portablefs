import {
  historyMaterializerVersion,
  pft2ServingCapability,
  type AdoptCutResult,
  type GenerationBacklogStatus,
  type HistoryCutCreateInput,
  type HistoryCutStatus,
  type JournalReclaimCandidate,
  type JournalReclaimResult,
  type ServingPinStatus,
  type StuckRecoveryGeneration,
  type VolumeRetirementTask,
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
//   2b. If that cut is TERMINAL (failed/canceled), walk the revision chain:
//      the SAME deterministic scheme with an explicit revision suffix
//      (hcut-<generation>-<base>-r<N>) drives a BOUNDED re-cut. See
//      "TERMINAL RECOVERY CUTS" below — this is the step whose absence made
//      one dead cut log forever with adoption blocked.
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
// TERMINAL RECOVERY CUTS (the 60-second log loop this replaces).
//
// A recovery cut can reach 'failed'. Before this pass existed, that was a
// dead end with no exit at all: the operation id hcut-<generation>-<base> is
// a permanent database row, and the base seq only advances THROUGH adoption,
// so every later cycle replayed the same recorded operation, read the same
// failed cut, logged the same line, and gave up. Production did exactly that
// once a minute for days on one generation, with adoption blocked and its
// journal unreclaimable, while the cycle counter said only `cutsFailed: 1`.
//
// A terminal cut now reaches a DEFINITE outcome, chosen from the failure the
// worker actually recorded:
//
//   * TRANSIENT (last_error.kind 'transient', a dead_letter that exhausted
//     its 013 attempt budget on transient errors, or an unrecorded kind).
//     The source is intact; the environment was not. The loop re-cuts the
//     same boundary under the NEXT revision — pfh.cut_create already mints
//     dedup_revision = MAX+1 at the same dedup key after a definite failure
//     — bounded by recoveryCutMaxRevisions and spaced by an exponential
//     backoff measured on the DATABASE clock. Determinism is preserved:
//     the revision comes from the cut row, not from a replica's memory, so
//     every replica derives the same operation id for the same attempt.
//
//   * PERMANENT ('corrupt', or an operator's 'canceled'). Re-cutting folds
//     the same bytes and fails identically — production's cut died on
//     "journal page at seq 0 is empty below the cut 32", i.e. the captured
//     range has no records at all. There is no automatic outcome that is not
//     data loss, so the loop stops trying and reports a TERMINAL, operator-
//     visible state: the affected tenant/volume/branch/generation, the
//     recorded failure, how long it has been stuck, and the documented
//     remedy. Logged on first observation and then at most once per
//     stuckLogIntervalMs — never once per minute forever.
//
// WHY THE JOURNAL IS STILL NOT HOSTAGE. pfj.journal_reclaim_horizon (031)
// clamps on cuts in ('pending','materializing') only. A cut that might still
// materialize keeps its read window pinned — deleting under a live fold
// would corrupt it. A 'failed'/'canceled' cut is excluded, and must be: it
// can never produce the recovery anchor that gives its window meaning, so
// clamping on it would pin the prefix on a proof that will never arrive.
// What actually pins a terminally-stuck generation is that base_seq never
// advances (the horizon is at most base_seq), and moving a base without an
// adoption proof is a decision about DATA, not accounting: it discards the
// tail. That stays an operator action, named in the log line, never
// something this loop does on its own.
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
  /** PORTABLEFS_JOURNAL_RETENTION_MS — the age at which a suspended
   * generation is cut regardless of backlog size. Default 7 days. */
  journalRetentionMs: number;
  /** PORTABLEFS_JOURNAL_RECLAIM_BATCH — rows per bounded reclaim txn. */
  reclaimBatchRows: number;
  /** PORTABLEFS_JOURNAL_RECLAIM_MAX_PAGES — reclaim txns per cycle. */
  reclaimMaxPagesPerCycle: number;
  /**
   * PORTABLEFS_HISTORY_RECOVERY_CUT_MAX_REVISIONS — how many times ONE
   * boundary may be re-cut after a transient failure before the generation
   * is declared terminal and handed to an operator. The floor is 1 (never
   * re-cut); the ceiling keeps a permanently broken source from minting cut
   * rows without bound.
   */
  recoveryCutMaxRevisions: number;
  /**
   * PORTABLEFS_HISTORY_RECOVERY_CUT_BACKOFF_MS — base spacing before a
   * failed boundary is re-cut, doubled per revision. Measured on the
   * database clock, so replicas agree without a shared timer.
   */
  recoveryCutBackoffMs: number;
  /**
   * PORTABLEFS_HISTORY_STUCK_LOG_INTERVAL_MS — how often ONE stuck
   * generation may re-log. The first observation always logs; after that
   * the per-cycle counters carry it. The default is an hour, because the
   * behaviour this replaces was the same line every 60 seconds forever.
   */
  stuckLogIntervalMs: number;
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
    // Journal reclamation (migration 031). The retention floor is one hour:
    // shorter would cut branches that are merely between mounts. The batch
    // and page ceilings bound reclamation on a database that is, by
    // definition, already under storage pressure.
    journalRetentionMs: intEnv(
      env,
      "PORTABLEFS_JOURNAL_RETENTION_MS",
      604_800_000,
      3_600_000
    ),
    reclaimBatchRows: intEnv(env, "PORTABLEFS_JOURNAL_RECLAIM_BATCH", 512, 1, 4_096),
    reclaimMaxPagesPerCycle: intEnv(
      env,
      "PORTABLEFS_JOURNAL_RECLAIM_MAX_PAGES",
      64,
      1,
      4_096
    ),
    // Terminal recovery-cut lifecycle (migration 034). Three revisions is
    // deliberately small: a boundary that a fresh cut cannot materialize
    // three times, five minutes apart and doubling, is not waiting on
    // weather — it needs a human, and minting more cut rows only grows the
    // table the reclamation pass is trying to shrink.
    recoveryCutMaxRevisions: intEnv(
      env,
      "PORTABLEFS_HISTORY_RECOVERY_CUT_MAX_REVISIONS",
      3,
      1,
      16
    ),
    recoveryCutBackoffMs: intEnv(
      env,
      "PORTABLEFS_HISTORY_RECOVERY_CUT_BACKOFF_MS",
      300_000,
      1_000
    ),
    stuckLogIntervalMs: intEnv(
      env,
      "PORTABLEFS_HISTORY_STUCK_LOG_INTERVAL_MS",
      3_600_000,
      1_000
    ),
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
  // Journal reclamation (migration 031). Optional so an embedder on an older
  // lineage still composes; when absent the loop reports it once and does no
  // reclamation rather than pretending storage is bounded.
  journalReclaimCandidates?(
    limit?: number,
    retentionMs?: number
  ): Promise<JournalReclaimCandidate[]>;
  reclaimJournalRecords?(input: {
    generationId: string;
    maxRows?: number;
  }): Promise<JournalReclaimResult>;
  /**
   * Live generations whose history work is TERMINAL (migration 034).
   * Optional so an embedder on an older lineage still composes; when absent
   * the cycle reports it rather than pretending nothing is stuck. This is
   * the fleet-wide view — the threshold scan only ever sees the generations
   * that happen to be past a backlog percent, which is why production's
   * stuck generation was visible as a bare `cutsFailed: 1` and nothing else.
   */
  stuckRecoveryGenerations?(limit?: number): Promise<StuckRecoveryGeneration[]>;
}

/**
 * The durable volume-retirement queue (migration 033), as the loop uses it.
 *
 * It is deliberately NOT part of HistoryMaintenanceStore: the queue is a
 * metadata-repository surface (it spans public.volumes, pfh and pfj), and the
 * loop should be able to drain it on a deployment whose history store is a
 * test double. Optional throughout, so an embedder on a pre-033 lineage still
 * composes and reports the gap per cycle instead of pretending retirement
 * releases anything.
 */
export interface VolumeRetirementDrainStore {
  claimVolumeRetirementTasks(input?: {
    limit?: number;
    backoffMs?: number;
  }): Promise<VolumeRetirementTask[]>;
  finishVolumeRetirement(input: { tenantId: string; volumeId: string }): Promise<unknown>;
  deferVolumeRetirementTask?(input: {
    tenantId: string;
    volumeId: string;
    error: string;
  }): Promise<void>;
}

export interface HistoryMaintenanceCycleSummary {
  generationsScanned: number;
  cutsCreated: number;
  cutsPending: number;
  /** Terminal (failed/canceled) recovery cuts observed, one per generation. */
  cutsFailed: number;
  /**
   * Boundaries RE-CUT this cycle after a transient failure: a fresh dedup
   * revision was minted under the next deterministic operation id. The
   * number that was structurally impossible before — a failed cut had no
   * path forward at all.
   */
  cutsRecreated: number;
  /**
   * Terminal cuts whose re-cut is deliberately NOT attempted: the recorded
   * failure is permanent (corrupt source, operator cancel) or the revision
   * budget is spent. Each one is an operator obligation, logged with its
   * identity and remedy on first observation.
   */
  cutsTerminal: number;
  /**
   * Terminal cuts waiting out their re-cut backoff. Distinct from
   * cutsTerminal on purpose: this cycle chose to wait, not to give up.
   */
  cutsRetryDeferred: number;
  /**
   * Live generations the 034 survey reports as stuck, FLEET-WIDE — not just
   * the ones this cycle's backlog scan happened to reach.
   */
  stuckGenerations: number;
  /** Age of the oldest stuck generation, in ms, from the database clock. */
  oldestStuckAgeMs: number;
  /**
   * This store cannot survey stuck generations (migration 034 absent).
   * Reported per cycle, never as a failure: an older lineage is a deployment
   * fact, but "nobody can enumerate the blocked volumes" must not be silent.
   */
  stuckSurveyUnavailable: boolean;
  adoptionsApplied: number;
  /** Ready cuts NOT adopted because exact history serving is unconfigured. */
  adoptionsBlocked: number;
  pinsScanned: number;
  pinsReleased: number;
  benignRefusals: number;
  failures: number;
  topBacklogPercent: number;
  // ── journal reclamation (migration 031) ──────────────────────────────────
  /** Generations that had records below their proven reclamation horizon. */
  reclaimCandidates: number;
  /** Journal records physically DELETED from the control store this cycle. */
  recordsReclaimed: number;
  /** Bytes released. The number this deployment had no signal for, twice. */
  bytesReclaimed: number;
  /**
   * Suspended generations cut on AGE rather than on backlog size. A branch
   * that is suspended and abandoned never crosses a percent-of-quota
   * threshold, so it was never cut, never adopted, and never reclaimable.
   */
  agedGenerationsForced: number;
  /**
   * This store cannot reclaim (migration 031 absent). Surfaced per cycle
   * rather than logged as a failure: an older lineage is a deployment fact,
   * but "journal records accumulate without bound" must never be silent.
   */
  reclaimUnavailable: boolean;
  // ── volume retirement drain (migration 033) ──────────────────────────────
  /** Durable retirement obligations claimed this cycle. */
  retirementTasksClaimed: number;
  /** Obligations whose atomic cleanup+journal-retirement transition ran. */
  retirementTasksCompleted: number;
  /** Obligations that failed and stay queued with backoff. */
  retirementTasksDeferred: number;
  /**
   * This store cannot drain retirement obligations (migration 033 absent).
   * Surfaced per cycle, never as a failure: an older lineage is a deployment
   * fact, but "a retired volume's journal is never released" must not be
   * silent — it is the accumulation that filled this control store twice.
   */
  retirementDrainUnavailable: boolean;
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
  // ── journal reclamation bounds (migration 031) ───────────────────────────
  /**
   * How long a SUSPENDED generation may sit idle before it is cut on AGE
   * rather than on backlog size. A suspended-and-abandoned branch never
   * crosses a percent-of-quota threshold, so without this it is never cut,
   * never adopted, and its journal is never reclaimable — the exact shape of
   * the test-branch data that filled production twice.
   */
  journalRetentionMs?: number | undefined;
  /** Rows deleted per bounded reclaim transaction. */
  reclaimBatchRows?: number | undefined;
  /** Ceiling on reclaim transactions per cycle: a bound on a pressured DB. */
  reclaimMaxPagesPerCycle?: number | undefined;
  /** Generations examined per reclaim scan, largest waste first. */
  reclaimScanLimit?: number | undefined;
  // ── volume retirement drain (migration 033) ──────────────────────────────
  /**
   * The durable retirement queue. Absent on a pre-033 lineage (or in tests
   * that do not exercise it); the cycle then reports
   * `retirementDrainUnavailable` instead of silently dropping the work.
   */
  retirement?: VolumeRetirementDrainStore | undefined;
  /** Obligations claimed per cycle. */
  retirementBatch?: number | undefined;
  /** Base backoff before a failed obligation is retried (grows per attempt). */
  retirementBackoffMs?: number | undefined;
  // ── terminal recovery-cut lifecycle (migration 034) ──────────────────────
  /** How many revisions ONE boundary may be cut at before it is terminal. */
  recoveryCutMaxRevisions?: number | undefined;
  /** Base re-cut spacing, doubled per revision, on the database clock. */
  recoveryCutBackoffMs?: number | undefined;
  /** How often one stuck generation may re-log its operator line. */
  stuckLogIntervalMs?: number | undefined;
  /** Stuck generations surveyed per cycle (034). */
  stuckSurveyLimit?: number | undefined;
  /**
   * Wall clock, injectable for tests. Used ONLY for log throttling; every
   * retry decision is measured on database timestamps so replicas agree.
   */
  now?: (() => number) | undefined;
}

/**
 * Deterministic per-(generation, base, revision) cut identity: exact-once by
 * construction.
 *
 * Revision 1 is byte-identical to the pre-034 id (`hcut-<gen>-<base>`) ON
 * PURPOSE. Those operation rows are permanent and already exist in production
 * with a frozen request fingerprint; a changed shape would answer PF009
 * "operation replayed with different content" on every cycle for every
 * generation, replacing one stuck cut with a fleet-wide one.
 *
 * Revisions above 1 are the bounded re-cut of the SAME boundary after a
 * definite failure. The revision is read off the failed cut row
 * (dedup_revision, which pfh.cut_create mints as MAX+1 at the dedup key), so
 * two replicas racing on the same terminal cut derive the same id and dedupe
 * in the database exactly as revision 1 does.
 */
export function recoveryCutOperationId(
  generationId: string,
  baseSeq: string,
  revision = 1
): string {
  const base = `hcut-${generationId}-${baseSeq}`;
  return revision <= 1 ? base : `${base}-r${revision}`;
}

/** Deterministic per-cut adoption identity: crash/replay is a recorded no-op. */
export function adoptionOperationId(cutId: string): string {
  return `hadopt-${cutId}`;
}

// Canonical request bytes for the deterministic operations. Field order is
// FROZEN: the database fingerprints these bytes permanently, and a replay
// with different bytes is a typed PF009 conflict — every replica must
// therefore derive byte-identical requests from the same scan facts.
function recoveryCutCanonicalJson(
  row: {
    tenantId: string;
    volumeId: string;
    branchName: string;
    generationId: string;
    baseSeq: string;
  },
  revision = 1
): string {
  const base = {
    v: "1",
    op: "history-maintenance-recovery-cut",
    tenantId: row.tenantId,
    volumeId: row.volumeId,
    branchName: row.branchName,
    generationId: row.generationId,
    baseSeq: row.baseSeq,
  };
  // Revision 1 keeps the EXACT frozen bytes (see recoveryCutOperationId): the
  // production fingerprints were computed from this object and nothing may be
  // added to it. A re-cut carries its revision, which is what makes the two
  // requests legitimately different operations rather than a PF009 conflict.
  return revision <= 1
    ? JSON.stringify(base)
    : JSON.stringify({ ...base, revision: String(revision) });
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

/**
 * How a terminal cut should be treated. The distinction is the whole point of
 * the lifecycle: "permanent" means a re-cut folds the same bytes and fails
 * the same way, so attempting one is not recovery, it is a slower infinite
 * loop that also grows the cut table.
 */
export type CutFailureClass = "transient" | "permanent";

interface RecordedCutFailure {
  kind: string;
  message: string;
}

/** The worker's recorded failure, flattened for classification and display. */
export function recordedCutFailure(cut: {
  state: string;
  lastError?: unknown;
}): RecordedCutFailure {
  if (cut.state === "canceled") {
    return { kind: "canceled", message: "canceled by an operator" };
  }
  const error = cut.lastError as
    | { kind?: unknown; message?: unknown; lastError?: { kind?: unknown; message?: unknown } }
    | null
    | undefined;
  const kind = typeof error?.kind === "string" ? error.kind : "unknown";
  const message = typeof error?.message === "string" ? error.message : "";
  if (kind === "dead_letter") {
    // 013's dead letter wraps the error that exhausted the attempt budget.
    // The WRAPPED kind is the one that decides whether a fresh cut can do
    // better: sixteen transient failures are still a transient story.
    const inner = typeof error?.lastError?.kind === "string" ? error.lastError.kind : "unknown";
    const innerMessage =
      typeof error?.lastError?.message === "string" ? error.lastError.message : message;
    return { kind: `dead_letter/${inner}`, message: innerMessage };
  }
  return { kind, message };
}

/**
 * PERMANENT: 'corrupt' (a definite integrity failure of the captured source —
 * production's cut died on "journal page at seq 0 is empty below the cut 32",
 * i.e. the range has no records at all, and no future cut of that range can
 * find them) and an operator's 'canceled' (a human said stop; the loop must
 * not quietly undo that).
 *
 * TRANSIENT: everything else, INCLUDING an unrecorded kind. The bias is
 * deliberate — a bounded, backed-off re-cut of a boundary that turns out to
 * be unrecoverable costs at most recoveryCutMaxRevisions cut rows and then
 * reports terminal, while wrongly calling a transient failure permanent
 * strands a writable volume until a human notices.
 */
export function classifyCutFailure(cut: { state: string; lastError?: unknown }): CutFailureClass {
  const { kind } = recordedCutFailure(cut);
  if (kind === "canceled" || kind === "corrupt" || kind === "dead_letter/corrupt") {
    return "permanent";
  }
  return "transient";
}

/** dedup_revision as a positive integer; anything unparseable reads as 1. */
function cutRevision(cut: { dedupRevision?: string }): number {
  const value = Number(cut.dedupRevision);
  return Number.isSafeInteger(value) && value >= 1 ? value : 1;
}

/** A canonical decimal millisecond string as a number; unparseable reads as 0. */
function decimalMs(value: string | undefined): number {
  if (value === undefined || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    return 0;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : 0;
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
    cutsRecreated: 0,
    cutsTerminal: 0,
    cutsRetryDeferred: 0,
    stuckGenerations: 0,
    oldestStuckAgeMs: 0,
    stuckSurveyUnavailable: false,
    adoptionsApplied: 0,
    adoptionsBlocked: 0,
    pinsScanned: 0,
    pinsReleased: 0,
    benignRefusals: 0,
    failures: 0,
    topBacklogPercent: 0,
    reclaimCandidates: 0,
    recordsReclaimed: 0,
    bytesReclaimed: 0,
    agedGenerationsForced: 0,
    reclaimUnavailable: false,
    retirementTasksClaimed: 0,
    retirementTasksCompleted: 0,
    retirementTasksDeferred: 0,
    retirementDrainUnavailable: false,
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
  private readonly journalRetentionMs: number;
  private readonly reclaimBatchRows: number;
  private readonly reclaimMaxPagesPerCycle: number;
  private readonly reclaimScanLimit: number;
  private readonly retirement: VolumeRetirementDrainStore | undefined;
  private readonly retirementBatch: number;
  private readonly retirementBackoffMs: number;
  private readonly recoveryCutMaxRevisions: number;
  private readonly recoveryCutBackoffMs: number;
  private readonly stuckLogIntervalMs: number;
  private readonly stuckSurveyLimit: number;
  private readonly now: () => number;
  /**
   * Per-generation log throttle. Bounded: the map is cleared wholesale once
   * it passes the ceiling, which costs one extra log line per stuck
   * generation and can never grow without bound on a fleet with many.
   */
  private readonly stuckLoggedAt = new Map<string, number>();
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
    this.journalRetentionMs = validatedPositiveInt(
      options.journalRetentionMs ?? 604_800_000,
      "journalRetentionMs"
    );
    this.reclaimBatchRows = validatedPositiveInt(options.reclaimBatchRows ?? 512, "reclaimBatchRows");
    this.reclaimMaxPagesPerCycle = validatedPositiveInt(
      options.reclaimMaxPagesPerCycle ?? 64,
      "reclaimMaxPagesPerCycle"
    );
    this.reclaimScanLimit = validatedPositiveInt(options.reclaimScanLimit ?? 32, "reclaimScanLimit");
    this.retirement = options.retirement;
    this.retirementBatch = validatedPositiveInt(options.retirementBatch ?? 8, "retirementBatch");
    this.retirementBackoffMs = validatedPositiveInt(
      options.retirementBackoffMs ?? 60_000,
      "retirementBackoffMs"
    );
    this.recoveryCutMaxRevisions = validatedPositiveInt(
      options.recoveryCutMaxRevisions ?? 3,
      "recoveryCutMaxRevisions"
    );
    this.recoveryCutBackoffMs = validatedPositiveInt(
      options.recoveryCutBackoffMs ?? 300_000,
      "recoveryCutBackoffMs"
    );
    this.stuckLogIntervalMs = validatedPositiveInt(
      options.stuckLogIntervalMs ?? 3_600_000,
      "stuckLogIntervalMs"
    );
    this.stuckSurveyLimit = validatedPositiveInt(
      options.stuckSurveyLimit ?? 32,
      "stuckSurveyLimit"
    );
    this.now = options.now ?? (() => Date.now());
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

    // The fleet-wide stuck survey (034) runs right after the scan: the
    // backlog scan only reaches generations past a threshold, and the whole
    // point of this pass is that a stuck generation must be visible whether
    // or not it happens to be one of them.
    if (!this.halted()) {
      await this.surveyStuckGenerations(summary);
    }

    if (!this.halted()) {
      await this.sweepServingPins(summary);
    }

    // The retirement drain runs BEFORE reclamation: it is what makes a
    // retired volume's records reclaimable at all (it moves each generation's
    // base to its own tip), so draining first lets the same cycle delete what
    // it just released instead of waiting a full interval.
    if (!this.halted()) {
      await this.drainVolumeRetirements(summary);
    }

    if (!this.halted()) {
      await this.reclaimJournalStorage(summary);
    }

    this.emit(summary);
    return summary;
  }

  // ── volume retirement drain (migration 033) ──────────────────────────────
  //
  // The DELETE route commits the retirement receipt and this obligation in
  // ONE transaction, then attempts the transition inline as a fast path. This
  // pass is what makes the attempt optional. Before it existed, a transient
  // failure of the inline journal release was LOGGED and forgotten: nothing
  // retried it, and this loop's reclamation pass could not pick it up either
  // — reclamation only deletes below an EXISTING horizon, and a generation
  // that was never retired has a horizon of its own base_seq, so it offers
  // zero reclaimable records and never appears as a candidate. Without a
  // client replay, that volume's whole journal tail was retained forever.
  //
  // Bounded like every other pass: a fixed batch per cycle, one bounded
  // transaction per obligation, the drain check between each, and a
  // per-attempt backoff enforced by the claim itself.
  private async drainVolumeRetirements(summary: HistoryMaintenanceCycleSummary): Promise<void> {
    const retirement = this.retirement;
    if (!retirement) {
      summary.retirementDrainUnavailable = true;
      return;
    }
    let tasks: VolumeRetirementTask[] = [];
    try {
      tasks = await retirement.claimVolumeRetirementTasks({
        limit: this.retirementBatch,
        backoffMs: this.retirementBackoffMs,
      });
    } catch (error) {
      this.recordFailure(summary, "volume retirement claim", error);
      return;
    }
    summary.retirementTasksClaimed = tasks.length;
    for (const task of tasks) {
      if (this.halted()) {
        break;
      }
      try {
        await retirement.finishVolumeRetirement({
          tenantId: task.tenantId,
          volumeId: task.volumeId,
        });
        summary.retirementTasksCompleted += 1;
      } catch (error) {
        // The obligation stays queued: the claim already bumped its attempt
        // and pushed out next_attempt_ms, so this only records WHY, and its
        // own failure must not end the pass.
        summary.retirementTasksDeferred += 1;
        this.classify(summary, `volume retirement ${task.volumeId}`, error);
        await retirement
          .deferVolumeRetirementTask?.({
            tenantId: task.tenantId,
            volumeId: task.volumeId,
            error: describeError(error),
          })
          .catch(() => undefined);
      }
    }
  }

  // ── journal reclamation (migration 031) ──────────────────────────────────
  //
  // Cutting and adopting bounds the LOGICAL backlog; it does not delete one
  // byte. Every payload below a generation's base stayed in
  // pfj.journal_records forever, which is how this deployment filled its
  // production control store twice with nothing but test-branch journal
  // data. This pass is the physical half.
  //
  // Bounded on every axis, because reclamation runs on a database that is by
  // definition already under storage pressure: at most maxPages bounded
  // pages per cycle, each its own small transaction, largest waste first,
  // and the drain check between every call.
  private async reclaimJournalStorage(summary: HistoryMaintenanceCycleSummary): Promise<void> {
    if (!this.store.journalReclaimCandidates || !this.store.reclaimJournalRecords) {
      // Reported in the cycle telemetry, NOT through the failure log: the
      // log hook is documented as real failures only, and an older lineage
      // is a deployment fact, not a failure. It still has to be visible —
      // "journal records accumulate without bound" is the whole incident.
      summary.reclaimUnavailable = true;
      return;
    }
    let candidates: JournalReclaimCandidate[] = [];
    try {
      candidates = await this.store.journalReclaimCandidates(
        this.reclaimScanLimit,
        this.journalRetentionMs
      );
    } catch (error) {
      this.recordFailure(summary, "journal reclaim scan", error);
      return;
    }
    summary.reclaimCandidates = candidates.length;

    let pagesLeft = this.reclaimMaxPagesPerCycle;
    for (const candidate of candidates) {
      if (this.halted() || pagesLeft <= 0) {
        break;
      }
      // A suspended generation idle past retention still holding an un-cut
      // tail is driven through the SAME deterministic recovery-cut path as a
      // backlogged one. Nothing is deleted for it here — the cut and its
      // adoption are what move the base, after which its records fall below
      // the horizon like any other generation's.
      if (candidate.suspendedPastRetention && candidate.nextSeq !== candidate.baseSeq) {
        summary.agedGenerationsForced += 1;
        await this.boundGeneration(
          {
            tenantId: candidate.tenantId,
            volumeId: candidate.volumeId,
            branchName: candidate.branchName,
            generationId: candidate.generationId,
            baseSeq: candidate.baseSeq,
          } as GenerationBacklogStatus,
          summary
        );
        if (this.halted()) {
          break;
        }
      }
      if (candidate.reclaimableRecords === "0") {
        continue;
      }
      // Drain this generation in bounded pages; `more` says the horizon still
      // has work below it. One unbounded DELETE would need the very disk
      // space it is trying to release.
      let more = true;
      while (more && pagesLeft > 0 && !this.halted()) {
        pagesLeft -= 1;
        try {
          const result = await this.store.reclaimJournalRecords({
            generationId: candidate.generationId,
            maxRows: this.reclaimBatchRows,
          });
          summary.recordsReclaimed += safeCount(result.deletedRecords);
          summary.bytesReclaimed += safeCount(result.deletedBytes);
          more = result.more;
        } catch (error) {
          // A generation that vanished between scan and reclaim (PF007), or
          // a racing writer, is benign: the next cycle re-derives everything.
          this.classify(summary, `journal reclaim ${candidate.generationId}`, error);
          more = false;
        }
      }
    }
  }

  // ── terminal recovery-cut lifecycle (migration 034) ──────────────────────

  /**
   * Present the deterministic cut-create operation for ONE revision of this
   * (generation, base) boundary and return the cut it names. `minted` says
   * whether THIS call created the row (a replay is another replica's — or an
   * earlier cycle's — recorded outcome, and must not be counted twice).
   *
   * Returns undefined for the mid-race shapes the next cycle re-derives: an
   * operation that exists but records no cut yet, or a cut row that vanished
   * between the two calls.
   */
  private async ensureRecoveryCut(
    row: GenerationBacklogStatus,
    revision: number,
    summary: HistoryMaintenanceCycleSummary
  ): Promise<{ cut: HistoryCutStatus; minted: boolean } | undefined> {
    const outcome = await this.store.createCut({
      tenantId: row.tenantId,
      volumeId: row.volumeId,
      branchName: row.branchName,
      kind: "recovery",
      operationId: recoveryCutOperationId(row.generationId, row.baseSeq, revision),
      requestCanonicalJson: recoveryCutCanonicalJson(row, revision),
      materializerVersion: historyMaterializerVersion,
      targetIds: { generationId: row.generationId },
    });
    if (!isOperationReplay(outcome)) {
      return { cut: outcome, minted: true };
    }
    const cutId = replayCutId(outcome);
    if (!cutId) {
      summary.benignRefusals += 1;
      return undefined;
    }
    const status = await this.store.cutStatus(row.tenantId, cutId);
    if (!status) {
      summary.benignRefusals += 1;
      return undefined;
    }
    return { cut: status, minted: false };
  }

  /**
   * Take a terminal cut to a DEFINITE outcome, and return a live cut when
   * one now exists (so the caller can go on to adopt it).
   *
   * The walk is what makes this stateless and replica-safe. Every cycle
   * re-enters at revision 1 — the operation row is permanent, so revision 1
   * always replays the original failed cut — and follows dedup_revision
   * upward until it finds a live cut, a permanent failure, or the revision
   * budget. At most recoveryCutMaxRevisions store calls, no memory between
   * cycles, and two replicas racing derive identical operation ids.
   */
  private async resolveTerminalCut(
    row: GenerationBacklogStatus,
    terminal: HistoryCutStatus,
    summary: HistoryMaintenanceCycleSummary
  ): Promise<HistoryCutStatus | undefined> {
    summary.cutsFailed += 1;
    let cut = terminal;
    for (let hop = 0; hop < this.recoveryCutMaxRevisions; hop += 1) {
      const revision = cutRevision(cut);
      if (classifyCutFailure(cut) === "permanent") {
        this.reportTerminalCut(row, cut, "the recorded failure is permanent", summary);
        return undefined;
      }
      if (revision >= this.recoveryCutMaxRevisions) {
        this.reportTerminalCut(
          row,
          cut,
          `the re-cut budget of ${this.recoveryCutMaxRevisions} revisions is spent`,
          summary
        );
        return undefined;
      }
      // Backoff on the DATABASE clock (the cut carries both its own last
      // update and the server's current time), so replicas with skewed wall
      // clocks agree on when the next revision is due.
      const dbNow = decimalMs(cut.dbTimeMs) || decimalMs(cut.updatedDbMs);
      const waited = dbNow - decimalMs(cut.updatedDbMs);
      const due = this.recoveryCutBackoffMs * 2 ** (revision - 1);
      if (waited < due) {
        summary.cutsRetryDeferred += 1;
        return undefined;
      }
      const next = await this.ensureRecoveryCut(row, revision + 1, summary);
      if (!next) {
        return undefined;
      }
      if (next.minted) {
        summary.cutsRecreated += 1;
      }
      if (next.cut.state !== "failed" && next.cut.state !== "canceled") {
        return next.cut;
      }
      cut = next.cut;
    }
    this.reportTerminalCut(
      row,
      cut,
      `the re-cut budget of ${this.recoveryCutMaxRevisions} revisions is spent`,
      summary
    );
    return undefined;
  }

  /**
   * The fleet-wide stuck survey (034). The threshold scan only ever reaches
   * generations past a backlog percent, so a stuck generation below it was
   * invisible; this pass enumerates them all, oldest first, and gives the
   * cycle line a count and an age instead of a bare `cutsFailed: 1`.
   */
  private async surveyStuckGenerations(summary: HistoryMaintenanceCycleSummary): Promise<void> {
    if (!this.store.stuckRecoveryGenerations) {
      // A deployment fact, not a failure — reported in the cycle line for
      // the same reason reclaimUnavailable is: "nobody can enumerate the
      // blocked volumes" must never be silent.
      summary.stuckSurveyUnavailable = true;
      return;
    }
    let rows: StuckRecoveryGeneration[] = [];
    try {
      rows = await this.store.stuckRecoveryGenerations(this.stuckSurveyLimit);
    } catch (error) {
      this.recordFailure(summary, "stuck recovery survey", error);
      return;
    }
    summary.stuckGenerations = rows.length;
    for (const stuck of rows) {
      summary.oldestStuckAgeMs = Math.max(summary.oldestStuckAgeMs, decimalMs(stuck.stuckAgeMs));
      // Counted always, LOGGED only when the same policy the loop applies
      // says the generation is genuinely an operator's problem. A generation
      // merely waiting out a re-cut backoff is stuck this instant and fine by
      // the next cycle; paging on it would rebuild the noise this replaces.
      if (
        classifyCutFailure({ state: stuck.cutState, lastError: { kind: stuck.failureKind } }) ===
          "permanent" ||
        cutRevision(stuck) >= this.recoveryCutMaxRevisions
      ) {
        this.logStuck(stuck.generationId, describeStuckGeneration(stuck));
      }
    }
  }

  /** One terminal cut, with everything an operator needs to act on it. */
  private reportTerminalCut(
    row: GenerationBacklogStatus,
    cut: HistoryCutStatus,
    reason: string,
    summary: HistoryMaintenanceCycleSummary
  ): void {
    summary.cutsTerminal += 1;
    const failure = recordedCutFailure(cut);
    this.logStuck(
      row.generationId,
      `PortableFS history maintenance: generation ${row.generationId} is STUCK — recovery cut ` +
        `${cut.cutId} is ${cut.state} at revision ${cutRevision(cut)} and ${reason}. ` +
        `tenant=${row.tenantId} volume=${row.volumeId} branch=${row.branchName} ` +
        `baseSeq=${row.baseSeq} nextSeq=${row.nextSeq} failure=${failure.kind}` +
        (failure.message ? `: ${failure.message.slice(0, 200)}` : "") +
        `. Adoption is blocked, so this generation's backlog cannot shrink and its journal ` +
        `records stay unreclaimable. ${terminalRemedy(failure.kind)}`
    );
  }

  /**
   * Throttled operator logging, keyed by generation. The first observation
   * always logs; after that the per-cycle counters carry it until
   * stuckLogIntervalMs elapses. The behaviour this replaces printed the same
   * line every 60 seconds indefinitely.
   */
  private logStuck(generationId: string, message: string): void {
    const now = this.now();
    const last = this.stuckLoggedAt.get(generationId);
    if (last !== undefined && now - last < this.stuckLogIntervalMs) {
      return;
    }
    if (this.stuckLoggedAt.size >= 1024) {
      this.stuckLoggedAt.clear();
    }
    this.stuckLoggedAt.set(generationId, now);
    this.log(message);
  }

  // Drive one backlogged generation one step forward: ensure its recovery
  // cut exists (deterministic id; replay-safe), and adopt it once ready.
  private async boundGeneration(
    row: GenerationBacklogStatus,
    summary: HistoryMaintenanceCycleSummary
  ): Promise<void> {
    try {
      const first = await this.ensureRecoveryCut(row, 1, summary);
      if (!first) {
        return;
      }
      let cut = first.cut;
      if (first.minted && cut.state === "pending") {
        summary.cutsCreated += 1;
      }

      if (cut.state === "failed" || cut.state === "canceled") {
        // The dead end this loop used to log once a minute forever. Walk the
        // revision chain to a definite outcome: a bounded re-cut when the
        // recorded failure is transient, a terminal operator obligation when
        // it is not.
        const resolved = await this.resolveTerminalCut(row, cut, summary);
        if (!resolved) {
          return;
        }
        cut = resolved;
      }

      if (cut.state === "pending" || cut.state === "materializing") {
        summary.cutsPending += 1;
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

// Reclamation counts arrive as canonical decimal strings (BIGINT). A value
// past exact double representation is DROPPED from the cycle counter rather
// than rounded: a per-cycle count that large means something is wrong, and an
// approximate number would hide it.
function safeCount(decimal: string): number {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(decimal)) {
    return 0;
  }
  const value = Number(decimal);
  return Number.isSafeInteger(value) ? value : 0;
}

/**
 * The documented operator action for a terminal recovery cut. A log line that
 * says "an operator must intervene" without saying WITH WHAT is the defect
 * this replaces, so every branch here names a concrete next step.
 */
export function terminalRemedy(failureKind: string): string {
  if (failureKind === "canceled") {
    return (
      "REMEDY: an operator canceled this cut, so the loop will not re-cut it. " +
      "Create a replacement cut through POST /v1/admin/history/cuts with a fresh operationId " +
      "once the reason for the cancel is resolved."
    );
  }
  if (failureKind === "corrupt" || failureKind === "dead_letter/corrupt") {
    return (
      "REMEDY: the captured journal range cannot be folded, so re-cutting it can never " +
      "succeed — check pfj.journal_records for this generation (a range with no rows below " +
      "the cut is the shape production hit). Restore the missing records from a control-store " +
      "backup and re-cut, or, if the data is genuinely gone, retire the volume " +
      "(DELETE /v1/volumes/:id) which releases the whole journal through the 033 retirement " +
      "transition. Nothing here is safe to automate: both paths change what the branch holds."
    );
  }
  return (
    "REMEDY: inspect pfh.history_cuts.last_error for this generation, clear the underlying " +
    "failure (history worker health, object-store reachability, replication policy), then " +
    "drive a fresh cut through POST /v1/admin/history/cuts with a new operationId."
  );
}

/** One survey row rendered as the operator line for that generation. */
function describeStuckGeneration(stuck: StuckRecoveryGeneration): string {
  const ageMinutes = Math.floor(decimalMs(stuck.stuckAgeMs) / 60_000);
  return (
    `PortableFS history maintenance: generation ${stuck.generationId} is STUCK — cut ` +
    `${stuck.cutId} is ${stuck.cutState} at revision ${stuck.dedupRevision} ` +
    `(${stuck.terminalCuts} terminal cut(s), stuck ${ageMinutes} min). ` +
    `tenant=${stuck.tenantId} volume=${stuck.volumeId} branch=${stuck.branchName} ` +
    `baseSeq=${stuck.baseSeq} nextSeq=${stuck.nextSeq} ` +
    `backlogRecords=${stuck.backlogRecords} failure=${stuck.failureKind}` +
    (stuck.failureMessage ? `: ${stuck.failureMessage}` : "") +
    `. Adoption is blocked and this generation's journal stays unreclaimable. ` +
    `${terminalRemedy(stuck.failureKind)}`
  );
}

function validatedPositiveInt(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`HistoryMaintenanceLoop ${name} must be a positive safe integer.`);
  }
  return value;
}
