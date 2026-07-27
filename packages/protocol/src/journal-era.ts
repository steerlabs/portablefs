import { z } from "zod";

// ---------------------------------------------------------------------------
// Journal-era additive wire schemas.
//
// Everything here is ADDITIVE to the frozen /v1 surface: new routes
// (attach-receipted, history serving, branch-from-cut) and new optional
// fields on existing shapes (snapshot cut states). No existing field is
// removed or repurposed; old clients strip the additions.
//
// This module is deliberately self-contained (index.ts re-exports it, so
// importing index's consts back would evaluate them before initialization).
// The base field shapes below restate the frozen contracts byte-for-byte;
// the authoritative definitions stay in index.ts.
// ---------------------------------------------------------------------------

const journalEraIdSchema = z.string().min(1).max(256);
const canonicalDecimalSchema = z.string().regex(/^(?:0|[1-9][0-9]{0,18})$/u);
// Byte-identical restatement of the frozen volumePathSchema rules (index.ts
// is not importable from here without an evaluation cycle).
const journalEraVolumePathSchema = z
  .string()
  .max(4096)
  .transform((value) => (value === "." ? "" : value.replace(/^\/+/, "").replace(/\/+$/, "")))
  .refine((value) => !value.includes("\0") && !value.split("/").includes(".."), {
    message: "Path must stay within the volume",
  });

/**
 * Client-chosen exact-once identity for a receipted operation. Bounded so it
 * can key a permanent receipt row.
 */
export const attachOperationIdSchema = journalEraIdSchema;

/**
 * Receipted attach request: the frozen attach shape plus the mandatory
 * operation id. A retry with the same id and a semantically identical body
 * replays the recorded outcome; the same id with a different body conflicts.
 */
export const attachVolumeReceiptedRequestSchema = z.object({
  branch: z.string().min(1).max(128).default("main"),
  mode: z.enum(["read", "write"]).default("write"),
  shared: z.boolean().default(false),
  rootPath: journalEraVolumePathSchema.default(""),
  holderId: z.string().min(1).max(256),
  leaseTtlMs: z
    .number()
    .int()
    .positive()
    .max(24 * 60 * 60 * 1000)
    .default(10 * 60 * 1000),
  prefetchPaths: z.array(journalEraVolumePathSchema).default([]),
  clientInfo: z.record(z.string(), z.unknown()).optional(),
  operationId: attachOperationIdSchema,
});
export type AttachVolumeReceiptedRequest = z.input<typeof attachVolumeReceiptedRequestSchema>;

export const attachVolumeReceiptSchema = z.object({
  operationId: attachOperationIdSchema,
  replayed: z.boolean(),
  createdAt: z.number().int().nonnegative(),
});
export type AttachVolumeReceipt = z.infer<typeof attachVolumeReceiptSchema>;

/**
 * Snapshot lifecycle states in the journal era. A snapshot of a
 * manifest-headed branch is born ready (its pinned manifest commit already
 * is the exact immutable revision). A snapshot of a journal-served branch is
 * an asynchronous HistoryCut: pending until the history worker materializes
 * it, then ready with a PFT2 result commit; failed/canceled are definite.
 */
export const snapshotStateSchema = z.enum([
  "pending",
  "materializing",
  "ready",
  "failed",
  "canceled",
]);
export type SnapshotState = z.infer<typeof snapshotStateSchema>;

/**
 * The snapshot record with additive journal-era fields. `commitId` keeps its
 * frozen meaning on manifest snapshots (the pinned content commit). On
 * cut-backed records — which only journal-era servers emit — `commitId` is
 * the cut's database-proven BASE anchor commit at creation time and stays
 * stable; the materialized content commit is the additive `resultCommitId`,
 * present once the cut is ready.
 */
export const snapshotRecordSchema = z.object({
  id: journalEraIdSchema,
  volumeId: journalEraIdSchema,
  branchId: journalEraIdSchema,
  commitId: journalEraIdSchema,
  name: z.string().min(1).max(256).optional(),
  createdAt: z.number().int().nonnegative(),
  state: snapshotStateSchema.optional(),
  cutId: journalEraIdSchema.optional(),
  resultCommitId: journalEraIdSchema.optional(),
  cutSeqExclusive: canonicalDecimalSchema.optional(),
});
export type SnapshotRecord = z.infer<typeof snapshotRecordSchema>;

export const snapshotRecordResponseSchema = z.object({
  snapshot: snapshotRecordSchema,
});
export type SnapshotRecordResponse = z.infer<typeof snapshotRecordResponseSchema>;

export const listSnapshotRecordsResponseSchema = z.object({
  snapshots: z.array(snapshotRecordSchema),
});
export type ListSnapshotRecordsResponse = z.infer<typeof listSnapshotRecordsResponseSchema>;

/**
 * Optional exact-once identity for snapshot creation. Absent, the server
 * mints one per call; concurrent identical captures of one journal position
 * still converge on one cut row through the database dedup key.
 */
export const snapshotOperationIdSchema = attachOperationIdSchema;

/**
 * Journal-era commit summaries carry an additive commitKind: manifest_v1
 * rows keep the canonical sha256 tree hash; pft2 rows are content-addressed
 * PFT2 roots whose treeHash is the stored `pft2:<hex>` identity.
 */
export const commitKindSchema = z.enum(["manifest_v1", "pft2"]);
export type WireCommitKind = z.infer<typeof commitKindSchema>;

export const historyErrorCodes = [
  "HISTORY_SERVING_UNAVAILABLE",
  "HISTORY_NOT_FOUND",
  "HISTORY_OBJECT_UNAVAILABLE",
  "HISTORY_BASE_PROOF_REJECTED",
  "HISTORY_BASE_PROOF_INVALID",
  "HISTORY_REQUEST_INVALID",
  "HISTORY_QUERY_INVALID",
  "HISTORY_BODY_NOT_ALLOWED",
  "HISTORY_RANGE_UNSUPPORTED",
  "HISTORY_METHOD_NOT_ALLOWED",
  "HISTORY_CUT_NOT_READY",
  "HISTORY_CUT_FAILED",
  "HISTORY_FORK_UNSUPPORTED",
] as const;
export type HistoryErrorCode = (typeof historyErrorCodes)[number];
