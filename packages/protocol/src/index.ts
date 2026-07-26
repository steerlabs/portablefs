import { z } from "zod";

export * from "./access-leases.js";

export const protocolVersion = "portablefs-v1" as const;

export type TenantId = string;
export type VolumeId = string;
export type BranchId = string;
export type CommitId = string;
export type SnapshotId = string;
export type BlobDigest = string;
export type LeaseId = string;
export type AttachSessionId = string;
export type DelegationId = string;

export const idSchema = z.string().min(1).max(256);
export const sha256Schema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
// isWellFormedString rejects lone (unpaired) UTF-16 surrogates. JSON.stringify (the TS
// tree hash) re-escapes a lone surrogate to "\uXXXX", while Go's JSON decoder replaces
// it with U+FFFD — so the SAME path would hash to different tree hashes (and even land
// in different Merkle shards) on the two implementations, breaking the Go↔TS parity
// invariant. Rejecting at the boundary keeps both sides on the same domain.
export function isWellFormedString(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false; // high surrogate not followed by low
      i += 1;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false; // lone low surrogate
    }
  }
  return true;
}

export const posixPathSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((value) => !value.startsWith("/") && !value.includes("\0"), {
    message: "Path must be relative POSIX path",
  })
  .refine(isWellFormedString, { message: "Path must not contain unpaired UTF-16 surrogates" });
export const volumePathSchema = z
  .string()
  .max(4096)
  .transform((value) => (value === "." ? "" : value.replace(/^\/+/, "").replace(/\/+$/, "")))
  .refine((value) => !value.includes("\0") && !value.split("/").includes(".."), {
    message: "Path must stay within the volume",
  });
export type VolumePath = z.infer<typeof volumePathSchema>;

export const treeEntryKindSchema = z.enum(["file", "directory", "symlink"]);
export type TreeEntryKind = z.infer<typeof treeEntryKindSchema>;

export const blobRefSchema = z.object({
  digest: sha256Schema,
  size: z.number().int().nonnegative(),
  storageKey: z.string().min(1).optional(),
  compression: z.enum(["none", "gzip"]).default("none"),
  packed: z.boolean().default(false),
});
export type BlobRef = z.infer<typeof blobRefSchema>;

export const chunkRefSchema = z.object({
  digest: sha256Schema,
  size: z.number().int().nonnegative(),
  offset: z.number().int().nonnegative(),
});
export type ChunkRef = z.infer<typeof chunkRefSchema>;

export const treeEntrySchema = z.object({
  path: posixPathSchema,
  kind: treeEntryKindSchema,
  // mode/uid/gid are bounded to uint32 — the Go VCS decodes them as uint32, so a value
  // above 0xffffffff (e.g. an overflow uid of 2^32) would make the committed manifest
  // undecodable on the Go side. Reject at the boundary instead.
  mode: z.number().int().nonnegative().max(0xffffffff),
  size: z.number().int().nonnegative().default(0),
  mtimeMs: z.number().nonnegative().default(0),
  // POSIX metadata times: persisted for stat fidelity, but excluded from the canonical
  // tree hash alongside mtimeMs/ino.
  ctimeMs: z.number().nonnegative().optional(),
  atimeMs: z.number().nonnegative().optional(),
  executable: z.boolean().default(false),
  // POSIX ownership; omitted from the canonical tree hash when 0 (root) so existing
  // manifests are unaffected (back-compatible optional fields).
  uid: z.number().int().nonnegative().max(0xffffffff).optional(),
  gid: z.number().int().nonnegative().max(0xffffffff).optional(),
  // Stable inode identity (authority-assigned, Ceph-CInode style): persisted in the manifest so
  // st_ino survives restarts/renames, but EXCLUDED from the canonical tree hash (see
  // comparableEntry) so adding it never changes an existing hash. uint64 in the Go VCS; bounded
  // to a safe JS integer here (inos are monotonic and tiny in practice, far below 2^53).
  ino: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  blob: blobRefSchema.optional(),
  chunks: z.array(chunkRefSchema).optional(),
  linkTarget: z.string().max(4096).refine(isWellFormedString, {
    message: "linkTarget must not contain unpaired UTF-16 surrogates",
  }).optional(),
});
export type TreeEntry = z.infer<typeof treeEntrySchema>;

export const treeManifestSchema = z.object({
  version: z.literal(protocolVersion),
  treeHash: sha256Schema,
  entries: z.array(treeEntrySchema),
});
export type TreeManifest = z.infer<typeof treeManifestSchema>;

export const treeManifestDiffSchema = z.object({
  added: z.array(treeEntrySchema),
  changed: z.array(treeEntrySchema),
  removed: z.array(treeEntrySchema),
  mutationCount: z.number().int().nonnegative(),
  byteCount: z.number().int().nonnegative(),
});
export type TreeManifestDiff = z.infer<typeof treeManifestDiffSchema>;

export const commitSchema = z.object({
  id: idSchema,
  volumeId: idSchema,
  branchId: idSchema,
  parentCommitId: idSchema.optional(),
  treeHash: sha256Schema,
  manifest: treeManifestSchema,
  mutationCount: z.number().int().nonnegative(),
  byteCount: z.number().int().nonnegative(),
  createdByAttachSessionId: idSchema.optional(),
  createdAt: z.number().int().nonnegative(),
});
export type VolumeCommit = z.infer<typeof commitSchema>;

export const commitSummarySchema = commitSchema.omit({ manifest: true });
export type VolumeCommitSummary = z.infer<typeof commitSummarySchema>;

export const volumeSchema = z.object({
  id: idSchema,
  tenantId: idSchema,
  defaultBranchId: idSchema,
  createdAt: z.number().int().nonnegative(),
});
export type Volume = z.infer<typeof volumeSchema>;

export const branchSchema = z.object({
  id: idSchema,
  volumeId: idSchema,
  name: z.string().min(1).max(128),
  parentBranchId: idSchema.optional(),
  forkedFromSnapshotId: idSchema.optional(),
  headCommitId: idSchema,
  createdAt: z.number().int().nonnegative(),
  updatedAt: z.number().int().nonnegative(),
});
export type VolumeBranch = z.infer<typeof branchSchema>;

export const snapshotSchema = z.object({
  id: idSchema,
  volumeId: idSchema,
  branchId: idSchema,
  commitId: idSchema,
  name: z.string().min(1).max(256).optional(),
  createdAt: z.number().int().nonnegative(),
});
export type VolumeSnapshot = z.infer<typeof snapshotSchema>;

export const leaseSchema = z.object({
  id: idSchema,
  volumeId: idSchema,
  branchId: idSchema,
  attachSessionId: idSchema,
  holderId: z.string().min(1).max(256),
  fencingToken: z.number().int().positive(),
  exclusive: z.boolean().default(true),
  expiresAt: z.number().int().nonnegative(),
  releasedAt: z.number().int().nonnegative().optional(),
});
export type VolumeLease = z.infer<typeof leaseSchema>;

export const attachModeSchema = z.enum(["read", "write"]);
export type AttachMode = z.infer<typeof attachModeSchema>;

export const attachSessionSchema = z.object({
  id: idSchema,
  volumeId: idSchema,
  branchId: idSchema,
  mode: attachModeSchema,
  shared: z.boolean().default(false),
  rootPath: volumePathSchema.default(""),
  baseCommitId: idSchema,
  lease: leaseSchema.optional(),
  attachedAt: z.number().int().nonnegative(),
  detachedAt: z.number().int().nonnegative().optional(),
});
export type AttachSession = z.infer<typeof attachSessionSchema>;

export const pathDelegationSchema = z.object({
  id: idSchema,
  volumeId: idSchema,
  branchId: idSchema,
  attachSessionId: idSchema,
  holderId: z.string().min(1).max(256),
  path: volumePathSchema,
  recursive: z.boolean().default(true),
  fencingToken: z.number().int().positive(),
  expiresAt: z.number().int().nonnegative(),
  createdAt: z.number().int().nonnegative(),
  releasedAt: z.number().int().nonnegative().optional(),
  revokedAt: z.number().int().nonnegative().optional(),
});
export type PathDelegation = z.infer<typeof pathDelegationSchema>;

export const createVolumeRequestSchema = z.object({
  // Optional for tenant tokens (the volume defaults to the token's tenant); the
  // admin token carries no tenant and must name one explicitly.
  tenantId: idSchema.optional(),
  volumeId: idSchema.optional(),
  branchName: z.string().min(1).max(128).default("main"),
  // Journal-born volume: the branch is BORN managed_journal — before any
  // attach session, lease, or claim can exist — so the managed authority's
  // first PFJ3 claim starts the journal from the empty genesis commit
  // (a PFJ3 claim requires this mode and never sets it). The default (false)
  // keeps the base-authoring shape: a legacy_manifest branch whose committed
  // base manifest is authored through attach sessions (adopt) and later
  // converted (migration 013) into journal service.
  managed: z.boolean().default(false),
});
export type CreateVolumeRequest = z.input<typeof createVolumeRequestSchema>;

export const createVolumeResponseSchema = z.object({
  volume: volumeSchema,
  branch: branchSchema,
  head: commitSchema,
});
export type CreateVolumeResponse = z.infer<typeof createVolumeResponseSchema>;

export const activateJournalRequestSchema = z.object({
  branch: z.string().min(1).max(128).default("main"),
});
export type ActivateJournalRequest = z.input<typeof activateJournalRequestSchema>;

export const attachVolumeRequestSchema = z.object({
  branch: z.string().min(1).max(128).default("main"),
  mode: attachModeSchema.default("write"),
  shared: z.boolean().default(false),
  rootPath: volumePathSchema.default(""),
  holderId: z.string().min(1).max(256),
  leaseTtlMs: z.number().int().positive().max(24 * 60 * 60 * 1000).default(10 * 60 * 1000),
  prefetchPaths: z.array(volumePathSchema).default([]),
  clientInfo: z.record(z.string(), z.unknown()).optional(),
});
export type AttachVolumeRequest = z.input<typeof attachVolumeRequestSchema>;

export const attachVolumeResponseSchema = z.object({
  session: attachSessionSchema,
  branch: branchSchema,
  manifest: treeManifestSchema,
  delegations: z.array(pathDelegationSchema).default([]),
});
export type AttachVolumeResponse = z.infer<typeof attachVolumeResponseSchema>;

export const uploadBlobResponseSchema = z.object({
  blob: blobRefSchema,
});
export type UploadBlobResponse = z.infer<typeof uploadBlobResponseSchema>;

export const uploadBlobBatchRequestSchema = z.object({
  blobs: z
    .array(
      z.object({
        digest: sha256Schema,
        bytesBase64: z.string(),
      })
    )
    .min(1)
    .max(1024),
});
export type UploadBlobBatchRequest = z.infer<typeof uploadBlobBatchRequestSchema>;

export const uploadBlobBatchResponseSchema = z.object({
  blobs: z.array(blobRefSchema),
});
export type UploadBlobBatchResponse = z.infer<typeof uploadBlobBatchResponseSchema>;

export const uploadBlobBatchAckResponseSchema = z.object({
  count: z.number().int().nonnegative(),
  bytes: z.number().int().nonnegative(),
});
export type UploadBlobBatchAckResponse = z.infer<typeof uploadBlobBatchAckResponseSchema>;

export const commitRequestSchema = z.object({
  leaseId: idSchema,
  fencingToken: z.number().int().positive(),
  expectedHeadCommitId: idSchema,
  manifest: treeManifestSchema,
  mutationCount: z.number().int().nonnegative(),
  byteCount: z.number().int().nonnegative(),
});
export type CommitRequest = z.infer<typeof commitRequestSchema>;

export const commitDeltaRequestSchema = z.object({
  leaseId: idSchema,
  fencingToken: z.number().int().positive(),
  expectedHeadCommitId: idSchema,
  targetTreeHash: sha256Schema,
  diff: treeManifestDiffSchema,
});
export type CommitDeltaRequest = z.infer<typeof commitDeltaRequestSchema>;

export const commitResponseSchema = z.object({
  commit: commitSchema,
  branch: branchSchema,
  mergedFromHeadCommitId: idSchema.optional(),
});
export type CommitResponse = z.infer<typeof commitResponseSchema>;

export const commitSummaryResponseSchema = z.object({
  commit: commitSummarySchema,
  branch: branchSchema,
  mergedFromHeadCommitId: idSchema.optional(),
});
export type CommitSummaryResponse = z.infer<typeof commitSummaryResponseSchema>;

export const checkoutRequestSchema = z.object({
  leaseId: idSchema,
  fencingToken: z.number().int().positive(),
  path: volumePathSchema.default(""),
  recursive: z.boolean().default(true),
  force: z.boolean().default(false),
});
export type CheckoutRequest = z.input<typeof checkoutRequestSchema>;

export const checkoutResponseSchema = z.object({
  delegation: pathDelegationSchema,
  revoked: z.array(pathDelegationSchema).default([]),
});
export type CheckoutResponse = z.infer<typeof checkoutResponseSchema>;

export const checkinRequestSchema = z.object({
  delegationId: idSchema.optional(),
  path: volumePathSchema.optional(),
});
export type CheckinRequest = z.input<typeof checkinRequestSchema>;

export const checkinResponseSchema = z.object({
  released: z.array(pathDelegationSchema),
});
export type CheckinResponse = z.infer<typeof checkinResponseSchema>;

export const delegationsResponseSchema = z.object({
  delegations: z.array(pathDelegationSchema),
});
export type DelegationsResponse = z.infer<typeof delegationsResponseSchema>;

export const detachRequestSchema = z.object({
  releaseLease: z.boolean().default(true),
});
export type DetachRequest = z.input<typeof detachRequestSchema>;

export const detachResponseSchema = z.object({
  session: attachSessionSchema,
});
export type DetachResponse = z.infer<typeof detachResponseSchema>;

export const snapshotRequestSchema = z.object({
  branch: z.string().min(1).max(128).default("main"),
  name: z.string().min(1).max(256).optional(),
});
export type SnapshotRequest = z.input<typeof snapshotRequestSchema>;

export const snapshotResponseSchema = z.object({
  snapshot: snapshotSchema,
});
export type SnapshotResponse = z.infer<typeof snapshotResponseSchema>;

export const forkRequestSchema = z.object({
  tenantId: idSchema,
  volumeId: idSchema.optional(),
  branchName: z.string().min(1).max(128).default("main"),
});
export type ForkRequest = z.input<typeof forkRequestSchema>;

export const forkResponseSchema = z.object({
  volume: volumeSchema,
  branch: branchSchema,
  head: commitSchema,
});
export type ForkResponse = z.infer<typeof forkResponseSchema>;

export const createBranchRequestSchema = z.object({
  branchName: z.string().min(1).max(128),
  fromSnapshotId: idSchema.optional(),
  fromSnapshotName: z.string().min(1).max(256).optional(),
  fromBranch: z.string().min(1).max(128).default("main"),
});
export type CreateBranchRequest = z.input<typeof createBranchRequestSchema>;

export const createBranchResponseSchema = z.object({
  branch: branchSchema,
  head: commitSchema,
});
export type CreateBranchResponse = z.infer<typeof createBranchResponseSchema>;

export const listBranchesResponseSchema = z.object({
  branches: z.array(branchSchema),
});
export type ListBranchesResponse = z.infer<typeof listBranchesResponseSchema>;

export const listSnapshotsResponseSchema = z.object({
  snapshots: z.array(snapshotSchema),
});
export type ListSnapshotsResponse = z.infer<typeof listSnapshotsResponseSchema>;

export const volumeStatusResponseSchema = z.object({
  volume: volumeSchema,
  branch: branchSchema,
  head: commitSchema,
  activeLeases: z.number().int().nonnegative().optional(),
  activeDelegations: z.number().int().nonnegative().optional(),
});
export type VolumeStatusResponse = z.infer<typeof volumeStatusResponseSchema>;

export const volumeHeadResponseSchema = z.object({
  volume: volumeSchema,
  branch: branchSchema,
  head: commitSummarySchema,
  activeLeases: z.number().int().nonnegative().optional(),
  activeDelegations: z.number().int().nonnegative().optional(),
});
export type VolumeHeadResponse = z.infer<typeof volumeHeadResponseSchema>;

export const volumeWaitHeadResponseSchema = volumeHeadResponseSchema.extend({
  changed: z.boolean(),
});
export type VolumeWaitHeadResponse = z.infer<typeof volumeWaitHeadResponseSchema>;

export const volumeManifestDiffResponseSchema = z.object({
  volume: volumeSchema,
  branch: branchSchema,
  head: commitSummarySchema,
  baseCommitId: idSchema,
  rootPath: volumePathSchema.default(""),
  targetTreeHash: sha256Schema,
  targetEntryCount: z.number().int().nonnegative(),
  diff: treeManifestDiffSchema,
});
export type VolumeManifestDiffResponse = z.infer<typeof volumeManifestDiffResponseSchema>;

export const renewLeaseRequestSchema = z.object({
  fencingToken: z.number().int().positive(),
  leaseTtlMs: z.number().int().positive().max(24 * 60 * 60 * 1000),
});
export type RenewLeaseRequest = z.infer<typeof renewLeaseRequestSchema>;

export const renewLeaseResponseSchema = z.object({
  lease: leaseSchema,
});
export type RenewLeaseResponse = z.infer<typeof renewLeaseResponseSchema>;

export const execRequestSchema = z.object({
  branch: z.string().min(1).max(128).default("main"),
  command: z.string().min(1).max(16_384),
  write: z.boolean().default(false),
  timeoutMs: z.number().int().positive().max(5 * 60 * 1000).default(60_000),
  env: z.record(z.string(), z.string()).default({}),
});
export type ExecRequest = z.input<typeof execRequestSchema>;

export const execResponseSchema = z.object({
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number().int(),
  signal: z.string().nullable().optional(),
  timing: z.object({
    totalMs: z.number().nonnegative(),
    setupMs: z.number().nonnegative(),
    executeMs: z.number().nonnegative(),
    commitMs: z.number().nonnegative(),
  }),
  headCommitId: idSchema,
  committed: z.boolean(),
});
export type ExecResponse = z.infer<typeof execResponseSchema>;

// Read-only browse: a directory listing of a committed tree. Entries are the
// DIRECT children of the requested path — directories first, then files and
// symlinks, each group ordered by name (UTF-16 code unit order, matching the
// manifest path sort). `digest` is the whole-file blob digest for file entries.
export const volumeTreeEntrySchema = z.object({
  name: z.string().min(1),
  path: posixPathSchema,
  kind: treeEntryKindSchema,
  size: z.number().int().nonnegative(),
  mode: z.number().int().nonnegative(),
  executable: z.boolean(),
  mtimeMs: z.number().nonnegative(),
  linkTarget: z.string().optional(),
  digest: sha256Schema.optional(),
});
export type VolumeTreeEntry = z.infer<typeof volumeTreeEntrySchema>;

export const volumeTreeResponseSchema = z.object({
  volumeId: idSchema,
  branchName: z.string().min(1).max(128),
  commitId: idSchema,
  treeHash: sha256Schema,
  path: volumePathSchema,
  entries: z.array(volumeTreeEntrySchema),
  // Opaque continuation token derived from the last returned child. Present only
  // when more children remain. Pass back as ?cursor= (pin ?commit= for stable
  // pagination across pages).
  nextCursor: z.string().optional(),
});
export type VolumeTreeResponse = z.infer<typeof volumeTreeResponseSchema>;

// Proof-of-possession probe: which of these digests must the calling tenant
// still upload? `missing` includes every digest the tenant does not already
// reference — even digests other tenants have stored (global existence is never
// revealed, and skipping an upload without possession proof is forbidden).
export const blobProbeRequestSchema = z.object({
  digests: z.array(sha256Schema).min(1).max(4096),
});
export type BlobProbeRequest = z.infer<typeof blobProbeRequestSchema>;

export const blobProbeResponseSchema = z.object({
  missing: z.array(sha256Schema),
});
export type BlobProbeResponse = z.infer<typeof blobProbeResponseSchema>;

export const grepRequestSchema = z.object({
  branch: z.string().min(1).max(128).default("main"),
  directory: volumePathSchema.default(""),
  pattern: z.string().min(1).max(4096),
  recursive: z.boolean().default(true),
  maxResults: z.number().int().positive().max(50_000).default(1000),
  deadlineMs: z.number().int().positive().max(60_000).default(30_000),
});
export type GrepRequest = z.input<typeof grepRequestSchema>;

export const grepMatchSchema = z.object({
  file: posixPathSchema,
  line: z.number().int().positive(),
  text: z.string(),
});
export type GrepMatch = z.infer<typeof grepMatchSchema>;

export const grepResponseSchema = z.object({
  matches: z.array(grepMatchSchema),
  stoppedReason: z.enum(["completed", "max_results", "deadline"]),
  durationMs: z.number().nonnegative(),
  headCommitId: idSchema,
});
export type GrepResponse = z.infer<typeof grepResponseSchema>;

export * from "./release-identity.js";
export * from "./journal-era.js";

export class VolumeProtocolError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status = 400) {
    super(message);
    this.name = "VolumeProtocolError";
    this.code = code;
    this.status = status;
  }
}

export function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${String(value)}`);
}
