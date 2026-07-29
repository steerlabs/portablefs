import { createHash } from "node:crypto";
import { MetadataConflictError } from "./types.js";

// The remote journal is the durability layer for a branch's live mutation
// suffix. It lives entirely inside PostgreSQL (migrations 009-012: the pfj
// schema, its SECURITY DEFINER functions, and the restricted
// portablefs_authority role); the Go authority reaches it directly over pgx
// with a restricted login. The volume-api neither proxies journal mutations
// nor exposes journal state to tenant tokens.
//
// This module keeps only the cross-language digest primitives and the frozen
// bounds, so TypeScript tests can verify the SQL functions' chain math and
// limits byte for byte without reimplementing the journal.
//
// Chain formula (must match vcs/internal/wal ChainDigestBytes and
// pfj.chain_step exactly):
//   chain'     = sha256(chain[32] || be64(len(payload)) || payload)
//   recordHash = chain step anchored at 32 zero bytes
// where payload is the exact canonical encoding of one journal record.

export const zeroJournalDigest = "0".repeat(64);

const journalDigestPattern = /^[0-9a-f]{64}$/;

export function isJournalDigest(value: string): boolean {
  return journalDigestPattern.test(value);
}

export function journalChainDigest(previousHex: string, payload: Buffer): string {
  if (!isJournalDigest(previousHex)) {
    throw new MetadataConflictError(
      "JOURNAL_PAYLOAD_INVALID",
      "Journal chain digest must be 64 lowercase hex characters.",
      400
    );
  }
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(payload.byteLength));
  return createHash("sha256")
    .update(Buffer.from(previousHex, "hex"))
    .update(length)
    .update(payload)
    .digest("hex");
}

export function journalRecordHash(payload: Buffer): string {
  return journalChainDigest(zeroJournalDigest, payload);
}

// Frozen bounds, enforced server-side by the pfj functions and client-side
// by the Go remote journal BEFORE staging. One user write is bounded
// separately at 1 MiB by the Go admission layer; the values here are the
// storage-facing bounds.
export const journalLimits = {
  // One record payload — a whole logical intent (one whole PFJ3 entry).
  maxRecordPayloadBytes: 8 * 1024 * 1024,
  // One append group (one journal commit transaction).
  maxGroupRecords: 128,
  maxGroupPayloadBytes: 16 * 1024 * 1024,
  // One replay page.
  maxPageRecords: 256,
  maxPageBytes: 16 * 1024 * 1024,
} as const;

// The immutable journal codec pair (migration 012). A generation declares
// exactly one pair at creation and can never switch in place. pfj3/pfc2 is
// the ONLY supported pair: the pre-012 pfr1/pfc1 era is retired, and a
// deployment still carrying such a generation row is refused at volume-api
// startup (countPreJournalV3Generations) rather than served. PFJ3 rows are
// whole journal entries: optionally one canonical tree intent plus 0..128
// ordered canonical PFC2 controls, hashed, chained, receipted, and replayed
// as their exact complete bytes.
export const journalCodecPairs = [
  { recordCodec: "pfj3", controlCodec: "pfc2" },
] as const;

export type JournalRecordCodec = (typeof journalCodecPairs)[number]["recordCodec"];
export type JournalControlCodec = (typeof journalCodecPairs)[number]["controlCodec"];

// Frozen 4-byte payload magic (part of the canonical hashed bytes).
export const journalPayloadMagics = {
  pfj3: Buffer.from("PFJ3", "ascii"),
} as const;

// PFJ3 entry bounds (must match vcs/internal/pfj3 exactly).
export const pfj3Limits = {
  maxEntryBytes: 8 * 1024 * 1024,
  maxControls: 128,
  maxControlBytes: 64 * 1024,
} as const;

export function journalPayloadCodec(payload: Buffer): JournalRecordCodec | null {
  if (payload.byteLength >= 4 && payload.subarray(0, 4).equals(journalPayloadMagics.pfj3)) {
    return "pfj3";
  }
  return null;
}

/**
 * The redacted live-generation binding of one branch, as read by the serving
 * layer (capability material is never included). All 64-bit journal facts
 * cross this boundary as canonical decimal strings.
 */
export interface BranchJournalBinding {
  generationId: string;
  branchId: string;
  epoch: string;
  recordCodec: JournalRecordCodec;
  controlCodec: JournalControlCodec;
  baseCommitId: string;
  baseSeq: string;
  baseDigest: string;
  nextSeq: string;
  tipDigest: string;
  status: "active" | "suspended" | "retiring";
}
