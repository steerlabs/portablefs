import type {
  AttachMode,
  AttachSession,
  BranchId,
  CheckinRequest,
  CheckoutRequest,
  CommitDeltaRequest,
  CommitRequest,
  CreateBranchRequest,
  SnapshotId,
  PathDelegation,
  TreeManifest,
  TreeManifestDiff,
  Volume,
  VolumeBranch,
  VolumeCommit,
  VolumeCommitSummary,
  VolumeId,
  VolumeLease,
  VolumeSnapshot,
} from "@portablefs/protocol";
import type { BranchJournalBinding } from "./journal.js";

export interface CreateVolumeInput {
  tenantId: string;
  volumeId?: VolumeId;
  branchName: string;
  // Journal-born: INSERT the branch with branch_mode='managed_journal' (the
  // only conversion-free journal birth the schema admits). A PFJ3 claim
  // requires this mode and never sets it.
  managed?: boolean;
}

export interface CreateVolumeResult {
  volume: Volume;
  branch: VolumeBranch;
  head: VolumeCommit;
  activeLeases?: number;
  activeDelegations?: number;
}

export interface VolumeHeadResult {
  volume: Volume;
  branch: VolumeBranch;
  head: VolumeCommitSummary;
  activeLeases?: number;
  activeDelegations?: number;
}

export interface VolumeManifestDiffInput extends VolumeStatusInput {
  baseCommitId: string;
  rootPath: string;
}

export interface VolumeManifestDiffResult {
  volume: Volume;
  branch: VolumeBranch;
  head: VolumeCommitSummary;
  baseCommitId: string;
  rootPath: string;
  targetTreeHash: string;
  targetEntryCount: number;
  diff: TreeManifestDiff;
}

export interface AttachVolumeInput {
  /** Verified caller tenant; volume ids are unique only inside this scope. */
  tenantId: string;
  volumeId: VolumeId;
  branchName: string;
  mode: AttachMode;
  shared: boolean;
  rootPath: string;
  holderId: string;
  leaseTtlMs: number;
  prefetchPaths?: string[];
  clientInfo?: Record<string, unknown>;
  now?: number;
  // Receipted attach (exact-once): the verified tenant identity plus a
  // client-chosen operation id. When present, the repository resolves the
  // permanent attach receipt BEFORE executing and records it atomically with
  // the session/lease rows; a retry replays the recorded outcome.
  operationId?: string;
}

export interface AttachVolumeReceiptFacts {
  operationId: string;
  replayed: boolean;
  createdAt: number;
}

export interface AttachVolumeCurrentFacts {
  observedAt: number;
  branch: VolumeBranch;
  session: AttachSession;
  activeDelegations: number;
}

export interface AttachVolumeResult {
  session: AttachSession;
  branch: VolumeBranch;
  // Present only on legacy_manifest attaches (the rootPath-projected base
  // the manifest authoring surfaces consume). Journal-owned (receipted)
  // attaches are manifest-free: the authority child binds
  // branch.headCommitId and proves its base content through
  // pfh.serving_base_prove, so no manifest shape would be truthful here —
  // and the Go client parses the absent key as its zero value.
  manifest?: TreeManifest;
  delegations: PathDelegation[];
  // Present only on receipted attaches: the exact-once receipt plus the
  // live-now projection observed in the same transaction.
  receipt?: AttachVolumeReceiptFacts;
  current?: AttachVolumeCurrentFacts;
}

export interface CommitVolumeInput extends CommitRequest {
  attachSessionId: string;
  now?: number;
}

export interface CommitVolumeDeltaInput extends CommitDeltaRequest {
  attachSessionId: string;
  now?: number;
}

export interface CommitVolumeResult {
  commit: VolumeCommit;
  branch: VolumeBranch;
  mergedFromHeadCommitId?: string;
}

export interface CommitVolumeSummaryResult {
  commit: VolumeCommitSummary;
  branch: VolumeBranch;
  mergedFromHeadCommitId?: string;
}

export interface DetachVolumeInput {
  attachSessionId: string;
  releaseLease: boolean;
  now?: number;
}

export interface SnapshotInput {
  /** Verified caller tenant; volume ids are unique only inside this scope. */
  tenantId: string;
  volumeId: VolumeId;
  branchName: string;
  snapshotId?: SnapshotId;
  name?: string;
  now?: number;
}

export interface ForkSnapshotInput {
  snapshotId: SnapshotId;
  tenantId: string;
  volumeId?: VolumeId;
  branchName: string;
  now?: number;
}

export interface RenewLeaseInput {
  leaseId: string;
  fencingToken: number;
  leaseTtlMs: number;
  now?: number;
}

export interface VolumeStatusInput {
  /** Verified caller tenant; volume ids are unique only inside this scope. */
  tenantId: string;
  volumeId: VolumeId;
  branchName: string;
}

export interface WaitForHeadInput extends VolumeStatusInput {
  afterCommitId: string;
  timeoutMs: number;
  // Client disconnect / server drain releases the wait immediately — on
  // Postgres that returns the LISTEN connection to the pool.
  signal?: AbortSignal;
}

export interface CheckoutInput extends CheckoutRequest {
  attachSessionId: string;
  now?: number;
}

export interface CheckoutResult {
  delegation: PathDelegation;
  revoked: PathDelegation[];
}

export interface CheckinInput extends CheckinRequest {
  attachSessionId: string;
  now?: number;
}

export interface CheckinResult {
  released: PathDelegation[];
}

export interface ListDelegationsInput {
  /** Verified caller tenant; delegation rows are always tenant-filtered. */
  tenantId: string;
  volumeId?: VolumeId;
  branchName?: string;
  branchId?: BranchId;
  attachSessionId?: string;
  includeReleased?: boolean;
  now?: number;
}

export interface CreateBranchInput extends CreateBranchRequest {
  /** Verified caller tenant; volume ids are unique only inside this scope. */
  tenantId: string;
  volumeId: VolumeId;
  now?: number;
}

export interface ListBranchesInput {
  tenantId: string;
  volumeId: VolumeId;
}

export interface ListSnapshotsInput {
  tenantId: string;
  volumeId: VolumeId;
  branchName?: string;
}

export interface ListVolumesInput {
  tenantId: string;
  limit: number;
}

export interface RetireVolumeInput {
  volumeId: VolumeId;
  /** The verified tenant identity (retirement is tenant-scoped in SQL). */
  tenantId: string;
  now?: number;
}

/** The retirement receipt: the instant the volume left service (epoch ms). */
export interface RetireVolumeResult {
  volumeId: VolumeId;
  retiredAtMs: number;
}

/**
 * One outstanding volume-retirement obligation (migration 033). Enqueued in
 * the SAME transaction as the retirement flip, so a caller can never hold a
 * receipt the fleet has no record of. Drained by the maintenance loop.
 */
export interface VolumeRetirementTask {
  volumeId: VolumeId;
  tenantId: string;
  /** Attempts INCLUDING this claim; the backoff grows with it. */
  attempts: number;
}

/**
 * The result of the atomic retirement transition (migration 033): history
 * cleanup and journal retirement in ONE transaction, under every branch lock
 * of the volume.
 */
export interface VolumeRetirementFinishResult {
  volumeId: VolumeId;
  branchesLocked: string;
  cleanup: unknown;
  journal: unknown;
  completedAtMs: string;
}

export interface VolumeListEntry {
  volume: Volume;
  branches: Array<Pick<VolumeBranch, "name" | "headCommitId">>;
}

export interface ListCommitHistoryInput {
  tenantId: string;
  volumeId: VolumeId;
  branchName: string;
  limit: number;
}

// ---------------------------------------------------------------------------
// Journal-era capability surface (additive; migrations 009-014).
// ---------------------------------------------------------------------------

/**
 * The five authoritative branch storage modes (migration 012). A journal-born
 * volume's branch starts in `legacy_manifest` — the base-authoring phase where
 * the attach-session manifest-commit path authors the committed base the
 * journal generation later starts from — and branches born from a ready cut
 * are INSERTed `managed_journal`. `migrating`/`retiring`/`retired` exist for
 * schema compatibility with the transition matrix.
 */
export type VolumeBranchMode =
  | "legacy_manifest"
  | "managed_journal"
  | "migrating"
  | "retiring"
  | "retired";

/** The two immutable commit families (migration 013). */
export type VolumeCommitKind = "manifest_v1" | "pft2";

/**
 * Journal activation progress (the 013 legacy→managed conversion, driven by
 * POST /v1/volumes/:id/activate-journal). Poll-driven: "converting" answers
 * carry the conversion/cut facts a caller needs to keep polling; "failed"
 * carries the bounded typed error facts; "active" is terminal.
 */
export interface JournalActivationConversion {
  conversionId: string;
  state: "migrating" | "final_cut" | "finalizing" | "converted" | "failed";
  attempt: number;
  finalCutId?: string;
  lastError?: unknown;
}

export interface JournalActivationCut {
  cutId: string;
  state: string;
  attemptCount: number;
  lastError?: unknown;
}

export interface JournalActivationStatus {
  state: "active" | "converting" | "failed";
  branchMode: VolumeBranchMode;
  conversion?: JournalActivationConversion;
  cut?: JournalActivationCut;
}

/**
 * One snapshot record in the journal era. Manifest snapshots are born ready
 * (state "ready", commitId = the pinned manifest commit). Cut-backed records
 * mirror one pfh HistoryCut: commitId is the cut's base anchor commit,
 * resultCommitId the materialized PFT2 commit once ready.
 */
export interface SnapshotCutRecord {
  id: string;
  volumeId: string;
  branchId: string;
  commitId: string;
  name?: string;
  createdAt: number;
  state: "pending" | "materializing" | "ready" | "failed" | "canceled";
  cutId?: string;
  resultCommitId?: string;
  cutSeqExclusive?: string;
}

export interface SnapshotCutInput extends SnapshotInput {
  /** The verified tenant identity (cut capture is tenant-scoped in SQL). */
  tenantId: string;
  /** Exact-once identity; absent mints a fresh one per call. */
  operationId?: string;
}

/** Resolution of a snapshot-or-cut id for branch/fork gating. */
export type SnapshotSource =
  | { kind: "snapshot"; snapshot: VolumeSnapshot }
  | { kind: "cut"; record: SnapshotCutRecord };

export interface CreateBranchFromCutInput {
  volumeId: VolumeId;
  branchName: string;
  cutId: string;
  tenantId: string;
  now?: number;
}

export interface CreateBranchFromCutResult {
  branch: VolumeBranch;
  head: VolumeCommitSummary;
  commitKind: VolumeCommitKind;
}

export interface ForkVolumeFromCutInput {
  cutId: string;
  tenantId: string;
  branchName: string;
  volumeId?: VolumeId;
  /** Exact-once identity; absent mints a fresh one per call. */
  operationId?: string;
}

/**
 * A cross-volume fork born from a ready cut: same top-level shape as the
 * legacy snapshot fork (volume/branch/head), but the head is a manifest-free
 * PFT2 commit summary plus its kind — exactly like branch-from-cut heads.
 */
export interface ForkVolumeFromCutResult {
  volume: Volume;
  branch: VolumeBranch;
  head: VolumeCommitSummary;
  commitKind: VolumeCommitKind;
  operationId: string;
  replayed: boolean;
}

export interface MetadataRepository {
  createVolume(input: CreateVolumeInput): Promise<CreateVolumeResult>;
  getHead(input: VolumeStatusInput): Promise<VolumeHeadResult | null>;
  waitForHead?(input: WaitForHeadInput): Promise<VolumeHeadResult | null>;
  getManifestDiff(input: VolumeManifestDiffInput): Promise<VolumeManifestDiffResult | null>;
  getStatus(input: VolumeStatusInput): Promise<CreateVolumeResult | null>;
  getCommit(commitId: string): Promise<VolumeCommit | null>;
  getManifest(commitId: string): Promise<TreeManifest | null>;
  attachVolume(input: AttachVolumeInput): Promise<AttachVolumeResult>;
  renewLease(input: RenewLeaseInput): Promise<VolumeLease>;
  checkout(input: CheckoutInput): Promise<CheckoutResult>;
  checkin(input: CheckinInput): Promise<CheckinResult>;
  listDelegations(input: ListDelegationsInput): Promise<PathDelegation[]>;
  commit(input: CommitVolumeInput): Promise<CommitVolumeResult>;
  commitSummary(input: CommitVolumeInput): Promise<CommitVolumeSummaryResult>;
  commitDeltaSummary(input: CommitVolumeDeltaInput): Promise<CommitVolumeSummaryResult>;
  detach(input: DetachVolumeInput): Promise<AttachSession>;
  snapshot(input: SnapshotInput): Promise<VolumeSnapshot>;
  listSnapshots(input: ListSnapshotsInput): Promise<VolumeSnapshot[]>;
  createBranch(input: CreateBranchInput): Promise<{ branch: VolumeBranch; head: VolumeCommit }>;
  listBranches(input: ListBranchesInput): Promise<VolumeBranch[]>;
  // Tenant-scoped volume listing (oldest-first) with each volume's branch heads.
  // Retired volumes are absent.
  listVolumes(input: ListVolumesInput): Promise<VolumeListEntry[]>;
  // Receipted volume retirement (DELETE /v1/volumes/:id; additive — absent on
  // repositories without migration 021). One atomic conditional flip of
  // volumes.retired_at: null answers mean unknown, foreign, or ALREADY
  // retired (a replay collects its receipt via retiredVolumeReceipt below).
  // After the flip, the ownership resolvers below treat the volume (and its
  // sessions, leases, snapshots, and commits) as absent, which is what fences
  // every per-volume plane; live authorities are not force-detached — their
  // leases/credentials expire on their own. Storage reclamation is deferred.
  retireVolume?(input: RetireVolumeInput): Promise<RetireVolumeResult | null>;
  // The stored retirement receipt for the caller's OWN retired volume; null
  // for live, unknown, and foreign ids. Lets the retire route answer a
  // replayed DELETE with the original receipt — HTTP DELETE is idempotent,
  // and the hosted control plane's caller-keyed ledger recovers a lost or
  // crashed response by replaying the same key — while unknown and foreign
  // ids keep the non-enumerating 404.
  retiredVolumeReceipt?(input: RetireVolumeInput): Promise<RetireVolumeResult | null>;
  // The atomic retirement transition (migration 033; additive). Runs the
  // history cleanup AND the journal retirement in ONE transaction under every
  // branch advisory lock of the volume, then marks the durable task complete.
  // It is safe to call repeatedly: both halves are idempotent. A failure here
  // never costs the caller its receipt — the obligation is already durable
  // and the maintenance loop retries it.
  finishVolumeRetirement?(input: {
    tenantId: string;
    volumeId: VolumeId;
  }): Promise<VolumeRetirementFinishResult>;
  // Claim due retirement obligations for the drain (bounded, SKIP LOCKED,
  // attempt/backoff bumped in the claim transaction so a crashed claimer
  // still yields a retry).
  claimVolumeRetirementTasks?(input?: {
    limit?: number;
    backoffMs?: number;
  }): Promise<VolumeRetirementTask[]>;
  // Record why an attempt failed. Observability only: the retry is already
  // scheduled by the claim, and this must be callable in a FRESH transaction
  // after the failed one rolled back.
  deferVolumeRetirementTask?(input: {
    tenantId: string;
    volumeId: VolumeId;
    error: string;
  }): Promise<void>;
  // Manifest-free branch history, newest-first, walking parent links from the
  // branch head (crossing branch points into pre-fork ancestry). Returns null when
  // the volume or branch does not exist.
  listCommitHistory(input: ListCommitHistoryInput): Promise<VolumeCommitSummary[] | null>;
  forkSnapshot(input: ForkSnapshotInput): Promise<CreateVolumeResult>;
  recordBlobs(blobs: Array<{ digest: string; size: number; storageKey?: string }>): Promise<void>;
  hasBlobs?(digests: string[]): Promise<Set<string>>;
  listCommits?(): Promise<VolumeCommit[]>;
  listBlobRecords?(): Promise<Array<{ digest: string; size: number; storageKey?: string }>>;
  deleteBlobRecord?(digest: string): Promise<void>;
  // Garbage collection (mark + sweep). referencedDigests is the global live set;
  // listBlobsCreatedBefore returns sweep candidates older than a grace cutoff.
  referencedDigests?(): Promise<Set<string>>;
  listBlobsCreatedBefore?(
    cutoffMs: number
  ): Promise<Array<{ digest: string; size: number; storageKey?: string; createdAt: number }>>;

  // --- Multi-tenant isolation ---
  // Tenant + API token provisioning (admin). A bearer token resolves to a tenant
  // server-side, so tenant identity is never trusted from a request body.
  createTenant(tenantId: string): Promise<void>;
  createTenantToken(input: { tenantId: string; tokenHash: string; label?: string }): Promise<void>;
  resolveTenantToken(tokenHash: string): Promise<{ tenantId: string } | null>;
  // Manager-minted short-lived runtime READ credentials (migration 015): the
  // per-child volume-api identity of managed production authorities.
  // Resolution is fail-closed in the database — expiry and revocation both
  // resolve to null.
  resolveRuntimeReadCredential(credentialHash: string): Promise<{
    tenantId: string;
    volumeId: string;
    branchName: string;
    readOnly: true;
  } | null>;
  // Ownership resolvers. Volume ids are tenant-local, so a volume is resolved
  // only by the composite tenant+id key; an unqualified volume->tenant lookup
  // would be ambiguous and is deliberately not part of this interface.
  // A RETIRED volume — and every session/lease/snapshot/commit belonging to one —
  // resolves to null, so all per-volume routes answer the same non-enumerating 404
  // after retirement (this is the single fencing point; see retireVolume).
  tenantOwnsVolume(input: {
    tenantId: string;
    volumeId: string;
    includeRetired?: boolean;
  }): Promise<boolean>;
  sessionTenant(sessionId: string): Promise<string | null>;
  leaseTenant(leaseId: string): Promise<string | null>;
  // Volume resolvers for runtime-credential pinning: a manager-minted child
  // credential may drive the authority lifecycle (attach, detach, lease
  // renew) ONLY on rows of its pinned volume.
  sessionVolume(sessionId: string): Promise<string | null>;
  leaseVolume(leaseId: string): Promise<string | null>;
  snapshotTenant(snapshotId: string): Promise<string | null>;
  commitTenant(commitId: string): Promise<string | null>;
  // Reference-checked blob reads: true iff tenantId has uploaded/inherited digest.
  tenantReferencesBlob(tenantId: string, digest: string): Promise<boolean>;
  // Batched reference check: the subset of digests the tenant references. Used to
  // authorize a commit's whole manifest in one round-trip.
  tenantReferencesBlobs(tenantId: string, digests: string[]): Promise<Set<string>>;
  // Grant a tenant read access to blobs it has uploaded (called on upload).
  addBlobRefs(tenantId: string, digests: string[]): Promise<void>;
  // Batched inverse of tenantReferencesBlobs, for upload probing: the subset of
  // digests the tenant does NOT reference (deduplicated, first-appearance order).
  // Consults only this tenant's refs — never global blob existence — so a digest
  // another tenant stored is still reported unreferenced. Probing therefore never
  // leaks cross-tenant content existence and cannot bypass proof-of-possession.
  filterUnreferencedBlobs(tenantId: string, digests: string[]): Promise<string[]>;

  // --- Journal-era capabilities (additive; absent on pure-manifest fakes) ---
  // Authoritative branch-mode resolution for route gating. A repository that
  // serves journal state implements ALL of these; the route layer fails
  // closed when journal capability is declared but mode resolution is not.
  branchMode?(input: VolumeStatusInput): Promise<VolumeBranchMode | null>;
  sessionBranchMode?(attachSessionId: string): Promise<VolumeBranchMode | null>;
  leaseBranchMode?(leaseId: string): Promise<VolumeBranchMode | null>;
  // The immutable commit family of one commit row (null = unknown commit).
  commitKind?(commitId: string): Promise<VolumeCommitKind | null>;
  // Manifest-free commit identity (works for BOTH commit families; a pft2
  // row's treeHash is its stored content-addressed root identity).
  getCommitSummary?(commitId: string): Promise<VolumeCommitSummary | null>;
  // The live journal-generation binding of a branch (null = no nonterminal
  // generation: the branch is in its base-authoring phase). Read-only and
  // redacted; capability material never crosses this boundary.
  journalBinding?(input: VolumeStatusInput): Promise<BranchJournalBinding | null>;
  // Cut-based snapshot capture: journal-served branches record an exact
  // pfh HistoryCut (async, worker-materialized); manifest-headed branches
  // produce a born-ready commit-pinned record (there is nothing to
  // materialize — the manifest commit IS the exact immutable revision).
  snapshotCut?(input: SnapshotCutInput): Promise<SnapshotCutRecord>;
  // Snapshot listing with lifecycle states: commit-pinned records plus this
  // volume's cut-backed records, oldest-first.
  listSnapshotRecords?(input: ListSnapshotsInput): Promise<SnapshotCutRecord[]>;
  // Resolves a snapshot-or-cut id for branch/fork source gating.
  resolveSnapshotSource?(snapshotOrCutId: string): Promise<SnapshotSource | null>;
  // Branch birth from a READY PFT2 cut: attaches the durable cut consumer,
  // issues the branch's never-reused inode namespace, and INSERTs the branch
  // born managed_journal with the cut's result commit as head — the exact
  // shape pfh.serving_base_prove later proves as a fork base.
  createBranchFromCut?(input: CreateBranchFromCutInput): Promise<CreateBranchFromCutResult>;
  // Cross-volume fork of a READY PFT2 cut into a NEW volume (migration 018):
  // zero-copy — the destination volume's default branch is born
  // managed_journal on the cut's immutable copied root, holds an ACTIVE
  // 'fork' cut consumer as the durable GC root of the shared history
  // objects, and gets its own never-reused inode namespace. Exact-once on
  // an explicit operationId. Absent on repositories without migration 018.
  forkVolumeFromCut?(input: ForkVolumeFromCutInput): Promise<ForkVolumeFromCutResult>;
  // Journal activation: converge one base-authored (legacy_manifest) branch
  // into managed_journal service through the 013 conversion plane. Poll-
  // driven and idempotent; the resident history worker materializes the
  // conversion cut between calls. Absent on repositories without the
  // history plane.
  activateJournalBranch?(input: {
    tenantId: string;
    volumeId: string;
    branchName: string;
  }): Promise<JournalActivationStatus>;
  // Bounded control-plane readiness probe: a migration lineage check plus a
  // DURABLE WRITE against a bounded probe ring. It deliberately mutates —
  // a read-only probe cannot tell a serving control store apart from one
  // that cannot accept another byte, and that gap once shipped a healthy
  // deploy through a total out-of-disk outage. Never touches blob stores.
  // Implementations must honor the abort signal.
  probeControlPlane?(options?: { signal?: AbortSignal }): Promise<ControlPlaneProbeResult>;
  // Exact control-store consumption for operator accounting. Never inferred:
  // PostgreSQL exposes no free-space primitive, so this reports what IS
  // consumed and the caller owns the capacity budget.
  controlStoreUsage?(): Promise<ControlStoreUsage>;
}

export interface ControlPlaneProbeResult {
  ok: boolean;
  /** Applied migration lineage is complete for this build. */
  migrationLineageComplete: boolean;
  /** True when the round-trip itself succeeded (lineage may still be short). */
  reachable?: boolean;
  /**
   * True when a durable write COMMITTED during this probe. This is the leg an
   * out-of-disk primary fails while every read still succeeds.
   */
  writable?: boolean;
  error?: string;
}

/**
 * Exact control-store consumption. Every value is a canonical decimal string:
 * these are BIGINT byte counts that outgrow the JS safe integer exactly when
 * a deployment is large enough to care about them.
 */
export interface ControlStoreUsage {
  databaseBytes: string;
  /**
   * pg_total_relation_size of the journal: heap + indexes + TOAST + bloat.
   * Deliberately the relation size and not a sum of payload bytes — this is
   * what consumes the disk, and it costs O(1) instead of a full scan that
   * would slow down exactly as the backlog it reports grows.
   */
  journalTableBytes: string;
  journalRecords: string;
  /**
   * Records below every generation's logical base. An UPPER BOUND: the
   * proven horizon additionally clamps to in-flight cut windows and
   * recovery-anchor evidence (see pfj.journal_storage_usage).
   */
  reclaimableJournalRecords: string;
}

export class MetadataConflictError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status = 409) {
    super(message);
    this.name = "MetadataConflictError";
    this.code = code;
    this.status = status;
  }
}

export function requireBranchId(branch: VolumeBranch | null): BranchId {
  if (!branch) {
    throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
  }
  return branch.id;
}
