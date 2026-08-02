import { createHash } from "node:crypto";
import type { Pool } from "pg";
import { maxSignedInt64Decimal } from "@portablefs/protocol";
import { MetadataConflictError } from "./types.js";

// ---------------------------------------------------------------------------
// HistoryCut repository bindings (migrations 013/014).
//
// PostgreSQL pfh SECURITY DEFINER functions are the SOLE coordinator of the
// HistoryCut pipeline: exact capture under the append lock order (including
// the cumulative backlog counters adoption subtracts in O(1)), DB-time SKIP
// LOCKED worker claims with monotone claim epochs, verified per-incarnation
// object/copy receipts, atomic dual-root ready publication (user pft2 commit
// + internal recovery anchor), permanent pending-until-usable resource
// operations, adoption proof rows, fenced serving pins, durable scrub/repair
// scheduling and the ABA-safe GC sweep authority.
//
// This module is a THIN exact-caller binding for the CALLER surface only:
// the volume-api calls it with its admin DSN. The claim-fenced WORKER
// surface (cut claims, receipts, mark-ready, scrub, repair, GC sweep) is
// owned exclusively by the long-running Go history-worker
// (vcs/cmd/history-worker) over its restricted DSN — there is deliberately
// no TypeScript worker binding, no spool, and no child process.
//
// All 64-bit values cross this boundary as canonical decimal strings.
// ---------------------------------------------------------------------------

export type HistoryCutKind = "user" | "recovery" | "conversion_final";

/**
 * One branch's legacy→managed conversion record (pfh.conversions), exactly
 * as pfh.conversion_status projects it. States: migrating (begun, no final
 * cut yet) → final_cut (cut pinned, worker materializing) → finalizing
 * (mode/head flip in flight) → converted; failed is retryable.
 */
export interface ConversionStatus {
  conversionId: string;
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  state: "migrating" | "final_cut" | "finalizing" | "converted" | "failed";
  attempt: number;
  oldGenerationId?: string;
  finalCutId?: string;
  inodeNamespace?: string;
  headCommitIdPin?: string;
  lastError?: unknown;
  createdDbMs: string;
  updatedDbMs: string;
  convertedDbMs?: string;
}

export interface HistoryCutStatus {
  cutId: string;
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  kind: HistoryCutKind;
  /** The user snapshot label persisted on the cut row (migration 019). */
  userLabel?: string;
  // legacy_manifest exists for schema compatibility only; PortableFS volumes
  // are journal-born and user cuts always capture a managed journal head.
  sourceKind: "managed_journal" | "legacy_manifest";
  generationId?: string;
  journalEpoch?: string;
  recordCodec?: "pfr1" | "pfj3";
  controlCodec?: "pfc1" | "pfc2";
  sourceBaseCommitId?: string;
  sourceBaseSeq?: string;
  sourceBaseDigest?: string;
  cutSeqExclusive?: string;
  cutDigest?: string;
  /** Cumulative journal accounting at the cut boundary (O(1) adoption). */
  cutBacklogBytes?: string;
  cutBacklogRecords?: string;
  sourceHeadCommitId?: string;
  materializerVersion: string;
  replicationPolicy: { v: "1"; requiredFailureDomains: string[]; policyEpoch: string };
  dedupRevision: string;
  state: "pending" | "materializing" | "ready" | "failed" | "canceled";
  claimEpoch: string;
  attemptCount: number;
  nextAttemptDbMs: string;
  progress?: unknown;
  lastError?: unknown;
  resultCommitId?: string;
  recoveryAnchorId?: string;
  /** The permanent outer operation that stays pending until usable. */
  operationId?: string;
  inodeNamespace?: string;
  namespaceNextLocal?: string;
  namespaceMaxInoSeen?: string;
  baseCommit?: {
    commitId: string;
    commitKind: "manifest_v1" | "pft2";
    /**
     * Database-proven provenance of the base for THIS cut's branch:
     * "adopted" = same-branch pft2 anchor (import it exactly), "fork" =
     * another branch's pft2 commit (import ONLY the user root — never its
     * anchor/allocator), "conversion" = a manifest_v1 base (the authored
     * base manifest a journal-born branch starts from). Absent provenance
     * fails the cut closed in the materializer.
     */
    baseMode?: "adopted" | "fork" | "conversion";
    treeHash: string;
    rootDigest?: string;
    rootSize?: string;
    maxInoSeen?: string;
    anchorId?: string;
    recoveryRootDigest?: string;
    recoveryRootSize?: string;
    controlRootDigest?: string;
    orphanIndexDigest?: string;
    inodeNamespace?: string;
    nextLocal?: string;
    anchorMaxInoSeen?: string;
  };
  result?: {
    commitId: string;
    rootDigest: string;
    rootSize: string;
    maxInoSeen: string;
    objectCount: string;
    objectBytes: string;
    anchorId: string;
    recoveryRootDigest: string;
    recoveryRootSize: string;
    controlRootDigest?: string;
    orphanIndexDigest?: string;
    inodeNamespace: string;
    nextLocal: string;
    anchorObjectCount: string;
    anchorObjectBytes: string;
  };
  createdDbMs: string;
  updatedDbMs: string;
  readyDbMs?: string;
  leaseExpiresDbMs?: string;
  dbTimeMs?: string;
}

export interface HistoryCutCreateInput {
  tenantId: string;
  volumeId: string;
  branchName: string;
  kind: HistoryCutKind;
  operationId: string;
  /** Canonical request bytes; the fingerprint freezes them permanently. */
  requestCanonicalJson: string;
  materializerVersion: string;
  targetIds?: Record<string, string>;
  /**
   * The user snapshot label persisted on the cut row itself (migration 019),
   * so status and listing reads answer it — the canonical request JSON only
   * survives as a fingerprint. Bounded 1..256 in SQL.
   */
  userLabel?: string;
}

/**
 * Counts from one pfh.volume_retire_cleanup pass (migration 022). All are
 * bounded small integers; a replayed cleanup answers zeros.
 */
export interface VolumeRetireCleanupResult {
  volumeId: string;
  consumersReleased: number;
  conversionsVoided: number;
  cutsCanceled: number;
}

/**
 * One reclaimable generation (migration 031). Byte and record counts are
 * canonical decimal strings: they are BIGINTs, and a 20 GB journal is exactly
 * the situation where rounding them would be a lie.
 */
export interface JournalReclaimCandidate {
  generationId: string;
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  status: string;
  recordCodec: string;
  baseSeq: string;
  nextSeq: string;
  /** The proven exclusive floor below which records may be deleted. */
  horizonSeq: string;
  /**
   * Records below the horizon, taken from the generation's seq span rather
   * than counted: exact while seqs are dense, an upper bound after a partial
   * trim. Counting them would cost a scan of the very backlog this exists to
   * drain.
   */
  reclaimableRecords: string;
  /** Suspended and idle past retention: cut it on AGE, not on backlog size. */
  suspendedPastRetention: boolean;
}

export interface JournalReclaimResult {
  generationId: string;
  deletedRecords: string;
  deletedBytes: string;
  horizonSeq: string;
  /** Another bounded page is waiting below the horizon. */
  more: boolean;
}

export interface JournalRetireResult {
  volumeId: string;
  generationsRetired: string;
  reclaimableRecords: string;
}

export interface JournalStorageUsage {
  generations: string;
  terminalGenerations: string;
  records: string;
  /** Records below the PROVEN horizon (clamped by cut windows + anchors). */
  reclaimableRecords: string;
  /** heap + indexes + TOAST + bloat: what actually consumes the disk. */
  tableBytes: string;
  dbTimeMs: string;
}

export interface AdoptCutResult {
  adoptionId: string;
  cutId: string;
  anchorId: string;
  state: string;
  newBaseSeq: string;
  newBaseDigest: string;
  newBaseCommitId: string;
  writerFence: string;
  managerEpoch?: string;
  authorityRuntimeId?: string;
  authorityRuntimeSeq?: string;
}

/**
 * One live PFJ3 generation past the backlog threshold, exactly as
 * pfj.generations_past_threshold (migration 017) projects it. 64-bit
 * counters are canonical decimal strings; backlogPercent is the display
 * ratio (max of the byte and record ratios, floor-divided).
 */
export interface GenerationBacklogStatus {
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  generationId: string;
  journalEpoch: string;
  status: "active" | "suspended";
  baseSeq: string;
  nextSeq: string;
  backlogBytes: string;
  backlogRecords: string;
  quotaBacklogBytes: string;
  quotaBacklogRecords: string;
  backlogPercent: number;
}

/** One unreleased adoption serving pin (pfh.serving_pins_unreleased). */
export interface ServingPinStatus {
  adoptionId: string;
  tenantId: string;
  generationId: string;
  cutId: string;
  writerFence: string;
  createdDbMs: string;
}

/**
 * The atomic cross-volume fork projection (pfh.volume_fork_from_cut,
 * migration 018), exactly as the database returns it. The destination is
 * born managed_journal on the copied immutable PFT2 root; all 64-bit values
 * are canonical decimal strings.
 */
export interface VolumeForkFromCutResult {
  operationId: string;
  replayed: boolean;
  volumeId: string;
  branchId: string;
  branchName: string;
  commitId: string;
  sourceCutId: string;
  sourceCommitId: string;
  rootDigest: string;
  rootSize: string;
  maxInoSeen: string;
  objectCount: string;
  objectBytes: string;
  inodeNamespace: string;
  createdDbMs: string;
}

/** One recorded verified copy location (exact key; never derived). */
export interface HistoryObjectCopy {
  failureDomain: string;
  storageKey: string;
  size: string;
  lastVerifiedDbMs: string;
}

export interface HistoryObjectLocation {
  tenantId: string;
  kind: "pft2";
  digest: string;
  size: string;
  incarnation: string;
  state: string;
  copies: HistoryObjectCopy[];
}

export interface Pft2CommitProvenance {
  commitId: string;
  cutId: string;
  tenantId: string;
  rootDigest: string;
  rootSize: string;
  maxInoSeen: string;
  objectCount: string;
  objectBytes: string;
  anchor?: {
    anchorId: string;
    asOfSeq: string;
    recoveryRootDigest: string;
    recoveryRootSize: string;
    controlRootDigest?: string;
    controlRootSize?: string;
    orphanIndexDigest?: string;
    orphanIndexSize?: string;
    inodeNamespace: string;
    nextLocal: string;
    maxInoSeen: string;
  };
}

export interface ServingBaseProofCommon {
  v: "1";
  tenantId: string;
  commitId: string;
  volumeId: string;
  branchId: string;
  generationId: string;
  baseSeq: string;
  baseDigest: string;
  // pfj3/pfc2 is the only served codec pair: the retired pfr1/pfc1 era is
  // refused at volume-api startup (countPreJournalV3Generations), so no
  // provable generation tuple can carry it.
  recordCodec: "pfj3";
  controlCodec: "pfc2";
}

export interface ManifestServingBaseProof extends ServingBaseProofCommon {
  kind: "manifest_v1";
}

export interface Pft2ServingBaseProof extends ServingBaseProofCommon {
  kind: "pft2";
  baseMode: "fork" | "conversion" | "adopted";
  root: {
    digest: string;
    size: string;
    maxInoSeen: string;
  };
  /** Present for adopted/conversion bases; a fork imports only the root. */
  anchor?: {
    anchorId: string;
    asOfSeq: string;
    recoveryRootDigest: string;
    recoveryRootSize: string;
    controlRootDigest: string;
    controlRootSize: string;
    orphanIndexDigest?: string;
    orphanIndexSize?: string;
    inodeNamespace: string;
    nextLocal: string;
    maxInoSeen: string;
  };
  /** Present for fork bases: the NEW branch's never-reused allocator. */
  allocator?: {
    inodeNamespace: string;
    nextLocal: string;
    maxInoSeen: string;
  };
}

export type ServingBaseProof = ManifestServingBaseProof | Pft2ServingBaseProof;

export interface ServingBaseProofInput {
  tenantId: string;
  commitId: string;
  generationId: string;
  baseSeq: string;
  baseDigest: string;
  recordCodec: "pfj3";
  controlCodec: "pfc2";
}

export function sha256HexOf(canonicalJson: string): string {
  return createHash("sha256").update(canonicalJson, "utf8").digest("hex");
}

/**
 * The serving-capability proof adoption requires: the authority-manager
 * forwards it only after the serving child's bootstrap frame advertised the
 * pft2-base feature (an old binary can neither claim it nor open the base).
 */
export const pft2ServingCapability = "pft2-base-v1";

function firstRowJson<T>(rows: Array<Record<string, unknown>>, column: string): T | null {
  if (rows.length === 0) {
    return null;
  }
  return (rows[0]?.[column] ?? null) as T | null;
}

function isCanonicalInt64Decimal(value: unknown, allowZero: boolean): value is string {
  if (typeof value !== "string") {
    return false;
  }
  const pattern = allowZero ? /^(?:0|[1-9][0-9]{0,18})$/u : /^[1-9][0-9]{0,18}$/u;
  return (
    pattern.test(value) &&
    (value.length < maxSignedInt64Decimal.length ||
      (value.length === maxSignedInt64Decimal.length && value <= maxSignedInt64Decimal))
  );
}

function historyBoundaryError(code: string, message: string, status: number): MetadataConflictError {
  return new MetadataConflictError(code, message, status);
}

function parseHistoryPolicyInstallResult(value: unknown): {
  policyEpoch: string;
  installedAt: string;
  replayed: boolean;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw historyBoundaryError(
      "HISTORY_POLICY_RESPONSE_INVALID",
      "History policy install returned a malformed projection.",
      500
    );
  }
  const projection = value as Record<string, unknown>;
  if (
    !isCanonicalInt64Decimal(projection.policyEpoch, false) ||
    !isCanonicalInt64Decimal(projection.installedAt, true) ||
    typeof projection.replayed !== "boolean"
  ) {
    throw historyBoundaryError(
      "HISTORY_POLICY_RESPONSE_INVALID",
      "History policy install returned invalid epoch, timestamp, or replay facts.",
      500
    );
  }
  return {
    policyEpoch: projection.policyEpoch,
    installedAt: projection.installedAt,
    replayed: projection.replayed,
  };
}

/**
 * PostgresHistoryRepository binds the pfh CALLER surface onto one pg Pool
 * (the volume-api admin DSN). The database enforces the surface split — the
 * worker functions refuse this role and vice versa.
 */
export class PostgresHistoryRepository {
  constructor(private readonly pool: Pool) {}

  // ── policy (expected-epoch CAS; byte-identical retry is idempotent) ───────

  async installHistoryPolicy(
    canonicalJson: string,
    expectedEpoch: string
  ): Promise<{ policyEpoch: string; installedAt: string; replayed: boolean }> {
    if (!isCanonicalInt64Decimal(expectedEpoch, true)) {
      throw historyBoundaryError(
        "HISTORY_POLICY_EPOCH_INVALID",
        "History policy expected epoch must be a canonical nonnegative signed-int64 decimal string.",
        400
      );
    }
    const { rows } = await this.pool.query(
      `SELECT pfh.install_history_policy($1,$2) AS out`,
      [canonicalJson, expectedEpoch]
    );
    return parseHistoryPolicyInstallResult(firstRowJson<unknown>(rows, "out"));
  }

  // ── cuts (caller surface) ─────────────────────────────────────────────────

  async createCut(input: HistoryCutCreateInput): Promise<HistoryCutStatus> {
    const { rows } = await this.pool.query(
      `SELECT pfh.cut_create($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9) AS out`,
      [
        input.tenantId,
        input.volumeId,
        input.branchName,
        input.kind,
        input.operationId,
        sha256HexOf(input.requestCanonicalJson),
        input.materializerVersion,
        JSON.stringify(input.targetIds ?? {}),
        input.userLabel ?? null,
      ]
    );
    return firstRowJson<HistoryCutStatus>(rows, "out")!;
  }

  /**
   * Named-snapshot deletion (migration 028): clears the label (and
   * releases any snapshot consumers) of the named READY cuts of one
   * volume, so they age out of the retention window (named + newest-K +
   * pinned) and the ordinary GC sweep collects their objects. Refuses
   * typed (PF007) when the volume has no ready snapshot of that name.
   */
  async releaseSnapshotCut(input: {
    tenantId: string;
    volumeId: string;
    name: string;
  }): Promise<{ cutIds: string[]; snapshotConsumersReleased: string }> {
    const { rows } = await this.pool.query(
      `SELECT pfh.snapshot_cut_release($1,$2,$3) AS out`,
      [input.tenantId, input.volumeId, input.name]
    );
    return firstRowJson<{ cutIds: string[]; snapshotConsumersReleased: string }>(
      rows,
      "out"
    )!;
  }

  async cutStatus(tenantId: string, cutId: string): Promise<HistoryCutStatus | null> {
    const { rows } = await this.pool.query(`SELECT pfh.cut_status($1,$2) AS out`, [
      tenantId,
      cutId,
    ]);
    return firstRowJson<HistoryCutStatus>(rows, "out");
  }

  async cancelCut(input: {
    tenantId: string;
    cutId: string;
    operationId: string;
    requestCanonicalJson: string;
  }): Promise<{ cutId: string; state: string }> {
    const { rows } = await this.pool.query(`SELECT pfh.cut_cancel($1,$2,$3,$4) AS out`, [
      input.tenantId,
      input.cutId,
      input.operationId,
      sha256HexOf(input.requestCanonicalJson),
    ]);
    return firstRowJson<{ cutId: string; state: string }>(rows, "out")!;
  }

  /**
   * Retirement cascade (migration 022), driven by the retire route AFTER the
   * 021 retirement receipt is durable: releases the retired volume's
   * conversion/adoption consumer pins, voids its non-terminal conversions,
   * and cancels its pending/materializing cuts into the terminal 'canceled'
   * state with a typed {kind:'volume_retired'} last_error. Idempotent — a
   * replay matches nothing and answers zero counts. Refuses a live volume
   * (PF011): the receipt is the precondition, never an effect.
   */
  async volumeRetireCleanup(input: {
    tenantId: string;
    volumeId: string;
  }): Promise<VolumeRetireCleanupResult> {
    const { rows } = await this.pool.query(
      `SELECT pfh.volume_retire_cleanup($1,$2) AS out`,
      [input.tenantId, input.volumeId]
    );
    return firstRowJson<VolumeRetireCleanupResult>(rows, "out")!;
  }

  /**
   * O(1) adoption: adopt(cutId, anchorId) — both arms must bound the SAME
   * cut. Requires the pft2-base serving-capability proof; the journal
   * primitive verifies the exact old base tuple and subtracts the captured
   * cumulative backlog under the freeze trigger's proof-row check.
   */
  async adoptCut(input: {
    tenantId: string;
    cutId: string;
    anchorId: string;
    operationId: string;
    requestCanonicalJson: string;
    servingCapability: string;
  }): Promise<AdoptCutResult> {
    const { rows } = await this.pool.query(`SELECT pfh.cut_adopt($1,$2,$3,$4,$5,$6) AS out`, [
      input.tenantId,
      input.cutId,
      input.anchorId,
      input.operationId,
      sha256HexOf(input.requestCanonicalJson),
      input.servingCapability,
    ]);
    return firstRowJson<AdoptCutResult>(rows, "out")!;
  }

  /**
   * Verified base-swap acknowledgment: the EXACT pinned runtime facts must
   * present themselves. There is no TTL and no unauthenticated release.
   */
  async ackServingPin(input: {
    adoptionId: string;
    generationId: string;
    writerFence: string;
    authorityRuntimeId?: string;
  }): Promise<void> {
    await this.pool.query(`SELECT pfh.serving_pin_ack($1,$2,$3,$4)`, [
      input.adoptionId,
      input.generationId,
      input.writerFence,
      input.authorityRuntimeId ?? null,
    ]);
  }

  /**
   * Fenced release: only provable durable supersession of the pinned
   * runtime (advanced writer fence, terminal generation, released/expired
   * writer lease at DB time) releases the pin.
   */
  async releaseServingPinFenced(adoptionId: string): Promise<{ released: boolean; reason: string }> {
    const { rows } = await this.pool.query(
      `SELECT pfh.serving_pin_release_fenced($1) AS out`,
      [adoptionId]
    );
    return firstRowJson<{ released: boolean; reason: string }>(rows, "out")!;
  }

  // ── maintenance read surface (migration 017) ──────────────────────────────

  /**
   * Live PFJ3 generations whose cumulative backlog has reached
   * backlogPercent of the generation quota (bytes OR records — whichever
   * ratio crosses first), worst-first. A read-only MVCC scan: it never
   * enters the append lock order.
   */
  async generationsPastThreshold(
    backlogPercent: number,
    limit = 256
  ): Promise<GenerationBacklogStatus[]> {
    if (!Number.isSafeInteger(backlogPercent) || backlogPercent < 1 || backlogPercent > 100) {
      throw historyBoundaryError(
        "HISTORY_BACKLOG_PERCENT_INVALID",
        "Backlog threshold percent must be an integer in 1..100.",
        400
      );
    }
    const { rows } = await this.pool.query(
      `SELECT pfj.generations_past_threshold($1,$2) AS out`,
      [backlogPercent, limit]
    );
    return rows.map((row) => row.out as GenerationBacklogStatus);
  }

  /** Unreleased adoption serving pins, oldest-first (bounded). */
  async unreleasedServingPins(limit = 256): Promise<ServingPinStatus[]> {
    const { rows } = await this.pool.query(
      `SELECT pfh.serving_pins_unreleased($1) AS out`,
      [limit]
    );
    return rows.map((row) => row.out as ServingPinStatus);
  }

  // ── journal reclamation (migration 031) ───────────────────────────────────
  //
  // Adoption is a LOGICAL trim: it moves base_seq and subtracts the backlog
  // counters, leaving every BYTEA payload below the base in the table. That
  // is how this deployment filled its control store twice with nothing but
  // test-branch journal data. These four calls are the physical half.

  /**
   * Generations with records below their PROVEN reclamation horizon,
   * largest waste first. `suspendedPastRetention` marks a generation that a
   * backlog-percent threshold can never reach: suspended, idle past the
   * retention window, and therefore never cut, never adopted and never
   * reclaimable until it is cut on AGE instead of on size.
   */
  async journalReclaimCandidates(
    limit = 32,
    retentionMs = 604_800_000
  ): Promise<JournalReclaimCandidate[]> {
    const { rows } = await this.pool.query(
      `SELECT pfj.journal_reclaim_candidates($1,$2) AS out`,
      [limit, String(retentionMs)]
    );
    const out = firstRowJson<JournalReclaimCandidate[]>(rows, "out");
    return Array.isArray(out) ? out : [];
  }

  /**
   * Delete one BOUNDED page of records below the generation's proven
   * horizon. Bounded on purpose: a 20 GB backlog must drain as a stream of
   * small transactions, never as one unbounded DELETE that would itself need
   * the disk space it is trying to release. `more` says another page is
   * waiting; every call is independently retryable.
   */
  async reclaimJournalRecords(input: {
    generationId: string;
    maxRows?: number;
  }): Promise<JournalReclaimResult> {
    const { rows } = await this.pool.query(`SELECT pfj.journal_reclaim($1,$2) AS out`, [
      input.generationId,
      input.maxRows ?? 512,
    ]);
    return firstRowJson<JournalReclaimResult>(rows, "out")!;
  }

  /**
   * The reclamation half of `portablefs rm <volume>`. Retiring a volume used
   * to set volumes.retired_at and cancel its cuts while leaving every
   * journal record it ever wrote in the control store forever. This drives
   * the volume's generations terminal and moves each base to its own tip, so
   * the WHOLE journal falls below the reclaim horizon and the ordinary
   * bounded reclaim pass releases it. Refuses a live volume (PF008): the
   * retirement receipt is the precondition, never an effect.
   */
  async retireVolumeJournals(input: {
    tenantId: string;
    volumeId: string;
  }): Promise<JournalRetireResult> {
    const { rows } = await this.pool.query(
      `SELECT pfj.journal_retire_for_volume($1,$2) AS out`,
      [input.tenantId, input.volumeId]
    );
    return firstRowJson<JournalRetireResult>(rows, "out")!;
  }

  /**
   * Operator-visible journal accounting. Before this there was none: the
   * only storage signal in the whole deployment was a percent-of-quota
   * telemetry field that only counted generations already past 70%, so the
   * curve that filled the disk was invisible until it hit 100%.
   */
  async journalStorageUsage(): Promise<JournalStorageUsage> {
    const { rows } = await this.pool.query(`SELECT pfj.journal_storage_usage() AS out`, []);
    return firstRowJson<JournalStorageUsage>(rows, "out")!;
  }

  // ── legacy → managed conversion (the 013 activation plane) ────────────────

  /**
   * Begin (or answer the existing) conversion of one legacy branch. The
   * database dedups on the branch: an existing non-failed conversion is
   * answered as-is; a failed one must be retried explicitly.
   */
  async conversionBegin(input: {
    tenantId: string;
    volumeId: string;
    branchName: string;
    operationId: string;
    requestCanonicalJson: string;
  }): Promise<ConversionStatus> {
    const { rows } = await this.pool.query(`SELECT pfh.conversion_begin($1,$2,$3,$4,$5) AS out`, [
      input.tenantId,
      input.volumeId,
      input.branchName,
      input.operationId,
      sha256HexOf(input.requestCanonicalJson),
    ]);
    return firstRowJson<ConversionStatus>(rows, "out")!;
  }

  async conversionStatus(tenantId: string, conversionId: string): Promise<ConversionStatus | null> {
    const { rows } = await this.pool.query(`SELECT pfh.conversion_status($1,$2) AS out`, [
      tenantId,
      conversionId,
    ]);
    return firstRowJson<ConversionStatus>(rows, "out");
  }

  /** Pin the conversion_final cut as the conversion's finalization input. */
  async conversionAttachFinalCut(input: {
    tenantId: string;
    conversionId: string;
    cutId: string;
  }): Promise<ConversionStatus> {
    const { rows } = await this.pool.query(
      `SELECT pfh.conversion_attach_final_cut($1,$2,$3) AS out`,
      [input.tenantId, input.conversionId, input.cutId]
    );
    return firstRowJson<ConversionStatus>(rows, "out")!;
  }

  /**
   * Finalize a conversion whose final cut is ready: in ONE transaction the
   * journal-owner primitive verifies the pinned head, retires any drained
   * legacy generation, installs the PFT2 result commit as the branch head,
   * and moves the branch to managed_journal.
   */
  async conversionFinalize(input: {
    tenantId: string;
    conversionId: string;
    operationId: string;
    requestCanonicalJson: string;
  }): Promise<ConversionStatus> {
    const { rows } = await this.pool.query(`SELECT pfh.conversion_finalize($1,$2,$3,$4) AS out`, [
      input.tenantId,
      input.conversionId,
      input.operationId,
      sha256HexOf(input.requestCanonicalJson),
    ]);
    return firstRowJson<ConversionStatus>(rows, "out")!;
  }

  /** Abort a migrating/final_cut conversion into the retryable failed state. */
  async conversionAbort(input: {
    tenantId: string;
    conversionId: string;
    operationId: string;
    requestCanonicalJson: string;
    reason: unknown;
  }): Promise<ConversionStatus> {
    const { rows } = await this.pool.query(
      `SELECT pfh.conversion_abort($1,$2,$3,$4,$5::jsonb) AS out`,
      [
        input.tenantId,
        input.conversionId,
        input.operationId,
        sha256HexOf(input.requestCanonicalJson),
        JSON.stringify(input.reason ?? { kind: "aborted" }),
      ]
    );
    return firstRowJson<ConversionStatus>(rows, "out")!;
  }

  /** Re-queue a failed conversion (fresh final cut; bounded attempts). */
  async conversionRetry(input: {
    tenantId: string;
    conversionId: string;
    operationId: string;
    requestCanonicalJson: string;
  }): Promise<ConversionStatus> {
    const { rows } = await this.pool.query(`SELECT pfh.conversion_retry($1,$2,$3,$4) AS out`, [
      input.tenantId,
      input.conversionId,
      input.operationId,
      sha256HexOf(input.requestCanonicalJson),
    ]);
    return firstRowJson<ConversionStatus>(rows, "out")!;
  }

  /**
   * The atomic cross-volume fork (migration 018): in ONE database
   * transaction the SECURITY DEFINER operation authenticates the ready
   * same-tenant source cut, creates the destination volume + fork-point
   * pft2 commit + managed_journal branch, issues the fresh inode namespace,
   * attaches the ACTIVE 'fork' cut consumer (the GC root of the shared
   * history objects), and installs the immutable fork provenance row.
   * Exact-once on (tenantId, operationId): an identical retry replays the
   * recorded response; a refused fork rolls back entirely.
   */
  async forkVolumeFromCut(input: {
    tenantId: string;
    cutId: string;
    branchName: string;
    volumeId?: string;
    operationId: string;
    /** Canonical request bytes; the fingerprint freezes them permanently. */
    requestCanonicalJson: string;
  }): Promise<VolumeForkFromCutResult> {
    const { rows } = await this.pool.query(
      `SELECT pfh.volume_fork_from_cut($1,$2,$3,$4,$5,$6) AS out`,
      [
        input.tenantId,
        input.cutId,
        input.volumeId ?? null,
        input.branchName,
        input.operationId,
        sha256HexOf(input.requestCanonicalJson),
      ]
    );
    return firstRowJson<VolumeForkFromCutResult>(rows, "out")!;
  }

  async attachConsumer(input: {
    tenantId: string;
    cutId: string;
    consumerKind: "snapshot" | "branch" | "fork" | "publish" | "adoption" | "conversion";
    consumerId: string;
  }): Promise<void> {
    await this.pool.query(`SELECT pfh.consumer_attach($1,$2,$3,$4)`, [
      input.tenantId,
      input.cutId,
      input.consumerKind,
      input.consumerId,
    ]);
  }

  async releaseConsumer(input: {
    tenantId: string;
    consumerKind: string;
    consumerId: string;
  }): Promise<void> {
    await this.pool.query(`SELECT pfh.consumer_release($1,$2,$3)`, [
      input.tenantId,
      input.consumerKind,
      input.consumerId,
    ]);
  }

  async resourceOperation(
    tenantId: string,
    domain: "history-cut" | "adoption" | "scrub" | "conversion" | "volume-fork",
    operationId: string
  ): Promise<unknown | null> {
    const { rows } = await this.pool.query(
      `SELECT pfh.resource_operation_get($1,$2,$3) AS out`,
      [tenantId, domain, operationId]
    );
    return firstRowJson<unknown>(rows, "out");
  }

  async compactResourceOperations(beforeDbMs: string, limit = 256): Promise<number> {
    const { rows } = await this.pool.query(
      `SELECT pfh.resource_operation_compact($1,$2) AS out`,
      [beforeDbMs, limit]
    );
    return Number(rows[0]?.out ?? 0);
  }

  // ── PFT2 read surface (exact recorded keys; never derived paths) ──────────

  async locateObject(
    tenantId: string,
    kind: "pft2",
    digest: string
  ): Promise<HistoryObjectLocation | null> {
    const { rows } = await this.pool.query(`SELECT pfh.object_locate($1,$2,$3) AS out`, [
      tenantId,
      kind,
      digest,
    ]);
    return firstRowJson<HistoryObjectLocation>(rows, "out");
  }

  async pft2CommitProvenance(
    tenantId: string,
    commitId: string
  ): Promise<Pft2CommitProvenance | null> {
    const { rows } = await this.pool.query(
      `SELECT pfh.pft2_commit_provenance($1,$2) AS out`,
      [tenantId, commitId]
    );
    return firstRowJson<Pft2CommitProvenance>(rows, "out");
  }

  /**
   * Atomically proves the exact journal base tuple returned by a claimed
   * generation. The database returns a positive commit family; callers must
   * never infer manifest_v1 from a null/404/timeout response.
   */
  async servingBaseProof(input: ServingBaseProofInput): Promise<ServingBaseProof | null> {
    if (!isCanonicalInt64Decimal(input.baseSeq, true)) {
      throw historyBoundaryError(
        "HISTORY_BASE_SEQ_INVALID",
        "History base sequence must be a canonical nonnegative signed-int64 decimal string.",
        400
      );
    }
    const { rows } = await this.pool.query(
      `SELECT pfh.serving_base_prove($1,$2,$3,$4,$5,$6,$7) AS out`,
      [
        input.tenantId,
        input.commitId,
        input.generationId,
        input.baseSeq,
        input.baseDigest,
        input.recordCodec,
        input.controlCodec,
      ]
    );
    return firstRowJson<ServingBaseProof>(rows, "out");
  }

  /** Schedules the ordinary scrub loop after a serving read observed damage. */
  async scheduleServingCopyVerification(input: {
    tenantId: string;
    digest: string;
    incarnation: string;
    failureDomain: string;
    reason: "missing" | "corrupt" | "unreachable";
  }): Promise<boolean> {
    if (!isCanonicalInt64Decimal(input.incarnation, false)) {
      throw historyBoundaryError(
        "HISTORY_OBJECT_INCARNATION_INVALID",
        "History object incarnation must be a canonical positive signed-int64 decimal string.",
        400
      );
    }
    const { rows } = await this.pool.query(
      `SELECT pfh.serving_copy_degraded($1,$2,$3,$4,$5) AS out`,
      [
        input.tenantId,
        input.digest,
        input.incarnation,
        input.failureDomain,
        input.reason,
      ]
    );
    return rows[0]?.out === true;
  }

  // ── audits ────────────────────────────────────────────────────────────────

  async restoreAudit(): Promise<unknown> {
    const { rows } = await this.pool.query(`SELECT pfh.restore_audit() AS out`);
    return firstRowJson<unknown>(rows, "out");
  }

  async freshnessAudit(): Promise<unknown> {
    const { rows } = await this.pool.query(`SELECT pfh.history_freshness_audit() AS out`);
    return firstRowJson<unknown>(rows, "out");
  }
}
