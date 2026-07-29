import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  PFT2_MAX_INO,
  PFT2_MAX_INODE_LOCAL_COUNTER,
  PFT2_MAX_INODE_NAMESPACE,
  PFT2_MAX_NODE_BYTES,
  PFT2_MAX_PACK_BYTES,
  PFT2_MIN_NODE_BYTES,
} from "@portablefs/core";
import {
  MetadataConflictError,
  type HistoryObjectLocation,
  type PostgresHistoryRepository,
  type ServingBaseProof,
} from "@portablefs/metadata-db";
import { ExactKeyReadError, type HistoryStoreRegistry } from "./history-stores.js";
import type { VolumeApiTelemetry } from "./telemetry.js";
import { isAbortError } from "./errors.js";

// ---------------------------------------------------------------------------
// Exact history serving: GET /v1/history/*.
//
// Tenant history reads are exact. Every read obtains a POSITIVE database
// proof first — the base-provenance route proves the already-claimed journal
// base tuple, and object reads locate the digest's live registration —
// before any storage byte is touched. Object bytes come only from
// database-recorded exact storage keys in declared failure domains, bounded
// by the frozen PFT2 maximum size, and SHA-256 verified before any response
// byte is exposed. A missing or corrupt copy falls through to the next
// independent failure domain and is queued for the worker's ordinary
// scrub/repair loop. No aggregate blob-store lookup, caller-supplied storage
// key, absence inference, or inline repair participates.
// ---------------------------------------------------------------------------

const sha256Digest = /^sha256:[0-9a-f]{64}$/u;
const hexDigest = /^[0-9a-f]{64}$/u;
const boundedId = /^[A-Za-z0-9._-]{1,256}$/u;
const canonicalDecimal = /^(?:0|[1-9][0-9]{0,18})$/u;
const maxSignedInt64 = 9_223_372_036_854_775_807n;
const maxPft2ObjectBytes = PFT2_MAX_PACK_BYTES;
const defaultCopyTimeoutMs = 15_000;

export interface HistoryServingContext {
  metadata: unknown;
  stores: HistoryStoreRegistry | undefined;
  requestSignal: AbortSignal;
  events: VolumeApiTelemetry;
  copyTimeoutMs?: number;
}

export async function routeHistoryServingRequest(
  req: IncomingMessage,
  res: ServerResponse,
  deps: HistoryServingContext,
  tenantId: string,
  url: URL,
  parts: string[]
): Promise<boolean> {
  if (parts[0] !== "v1" || parts[1] !== "history") return false;
  const method = req.method ?? "GET";
  if (method !== "GET" && method !== "HEAD") {
    sendJson(res, 405, {
      error: { code: "HISTORY_METHOD_NOT_ALLOWED", message: "Only GET and HEAD are supported." },
    });
    return true;
  }
  const history = (deps.metadata as { history?: PostgresHistoryRepository }).history;
  if (!history || !deps.stores) {
    sendJson(res, 503, {
      error: {
        code: "HISTORY_SERVING_UNAVAILABLE",
        message: "Exact history serving is not configured on this deployment.",
      },
    });
    return true;
  }

  try {
    rejectRequestBodyAndRange(req);
    if (parts.length === 4 && parts[2] === "base-provenance") {
      const commitId = parts[3] ?? "";
      if (!boundedId.test(commitId)) {
        sendNotFound(res);
        return true;
      }
      const query = exactQuery(url, [
        "generationId",
        "baseSeq",
        "baseDigest",
        "recordCodec",
        "controlCodec",
      ]);
      const generationId = query.generationId!;
      const baseSeq = query.baseSeq!;
      const baseDigest = query.baseDigest!;
      const recordCodec = query.recordCodec!;
      const controlCodec = query.controlCodec!;
      // pfj3/pfc2 is the only served codec pair: the retired pfr1/pfc1
      // generation era is refused at volume-api startup (no generation row
      // may predate migration 012), so a pfr1 proof presented here can only
      // be malformed input.
      if (
        !boundedId.test(generationId) ||
        !isCanonicalSignedInt64(baseSeq, true) ||
        !hexDigest.test(baseDigest) ||
        recordCodec !== "pfj3" ||
        controlCodec !== "pfc2"
      ) {
        throw new MetadataConflictError(
          "HISTORY_BASE_PROOF_INVALID",
          "History base proof query is invalid.",
          400
        );
      }
      const proof = await history.servingBaseProof({
        tenantId,
        commitId,
        generationId,
        baseSeq,
        baseDigest,
        recordCodec,
        controlCodec,
      });
      if (!proof) {
        sendNotFound(res);
        return true;
      }
      assertServingProof(proof, {
        tenantId,
        commitId,
        generationId,
        baseSeq,
        baseDigest,
        recordCodec,
        controlCodec,
      });
      const body = Buffer.from(JSON.stringify({ provenance: proof }));
      sendBuffer(res, method, body, "application/json");
      return true;
    }

    if (parts.length === 4 && parts[2] === "objects") {
      if ([...url.searchParams.keys()].length !== 0) {
        throw new MetadataConflictError(
          "HISTORY_QUERY_INVALID",
          "History object reads do not accept query parameters.",
          400
        );
      }
      const digest = parts[3] ?? "";
      if (!sha256Digest.test(digest)) {
        sendNotFound(res);
        return true;
      }
      // DB proof FIRST: an object present in storage but absent from the
      // tenant-scoped registry does not exist for this caller.
      const location = await history.locateObject(tenantId, "pft2", digest);
      const parsed = parseObjectLocation(location, tenantId, digest);
      if (!parsed || parsed.copies.length === 0) {
        sendNotFound(res);
        return true;
      }
      const bytes = await readVerifiedCopy(
        history,
        deps.stores,
        parsed,
        deps.requestSignal,
        deps.events,
        deps.copyTimeoutMs ?? defaultCopyTimeoutMs
      );
      res.setHeader("etag", `"${digest}"`);
      res.setHeader("cache-control", "private, max-age=31536000, immutable");
      res.setHeader("vary", "authorization");
      sendBuffer(res, method, bytes, "application/octet-stream");
      return true;
    }

    sendNotFound(res);
    return true;
  } catch (error) {
    // Let the central server error path distinguish a disconnected client
    // from a drain-cancelled request. When the socket is still open it sends
    // the standard retryable 503; swallowing here would leave it hanging.
    if (isAbortError(error)) throw error;
    sendServingError(res, error);
    return true;
  }
}

function rejectRequestBodyAndRange(req: IncomingMessage): void {
  const contentLength = req.headers["content-length"];
  const declared = Array.isArray(contentLength) ? contentLength[0] : contentLength;
  if ((declared !== undefined && declared !== "0") || req.headers["transfer-encoding"] !== undefined) {
    throw new MetadataConflictError(
      "HISTORY_BODY_NOT_ALLOWED",
      "History reads do not accept request bodies.",
      400
    );
  }
  if (req.headers.range !== undefined) {
    throw new MetadataConflictError(
      "HISTORY_RANGE_UNSUPPORTED",
      "History object ranges are not supported.",
      400
    );
  }
}

function exactQuery(url: URL, expected: string[]): Record<string, string> {
  const allowed = new Set(expected);
  const out: Record<string, string> = {};
  for (const [key, value] of url.searchParams) {
    if (!allowed.has(key) || out[key] !== undefined || value === "") {
      throw new MetadataConflictError(
        "HISTORY_QUERY_INVALID",
        "History base proof query has missing, duplicate, or unknown fields.",
        400
      );
    }
    out[key] = value;
  }
  if (expected.some((key) => out[key] === undefined)) {
    throw new MetadataConflictError(
      "HISTORY_QUERY_INVALID",
      "History base proof query has missing, duplicate, or unknown fields.",
      400
    );
  }
  return out;
}

function assertServingProof(
  value: ServingBaseProof,
  expected: {
    tenantId: string;
    commitId: string;
    generationId: string;
    baseSeq: string;
    baseDigest: string;
    recordCodec: "pfj3";
    controlCodec: "pfc2";
  }
): void {
  const forkMode = value.kind === "pft2" && value.baseMode === "fork";
  const row = recordWithExactKeys(value, [
    "v",
    "kind",
    "tenantId",
    "commitId",
    "volumeId",
    "branchId",
    "generationId",
    "baseSeq",
    "baseDigest",
    "recordCodec",
    "controlCodec",
    // The fork proof carries the NEW branch's allocator instead of an
    // anchor (a fork imports only the immutable user root); adopted and
    // conversion bases carry the recovery anchor.
    ...(value.kind === "pft2" ? ["baseMode", "root", ...(forkMode ? ["allocator"] : ["anchor"])] : []),
  ]);
  if (
    row.v !== "1" ||
    (row.kind !== "manifest_v1" && row.kind !== "pft2") ||
    row.tenantId !== expected.tenantId ||
    row.commitId !== expected.commitId ||
    row.generationId !== expected.generationId ||
    row.baseSeq !== expected.baseSeq ||
    row.baseDigest !== expected.baseDigest ||
    row.recordCodec !== expected.recordCodec ||
    row.controlCodec !== expected.controlCodec ||
    typeof row.volumeId !== "string" ||
    !boundedId.test(row.volumeId) ||
    typeof row.branchId !== "string" ||
    !boundedId.test(row.branchId)
  ) {
    throw new Error("History base proof response contradicted the requested tuple.");
  }
  if (row.kind === "manifest_v1") return;
  if (row.recordCodec !== "pfj3" || row.controlCodec !== "pfc2") {
    throw new Error("PFT2 base proof returned the wrong codec pair.");
  }
  if (row.baseMode !== "fork" && row.baseMode !== "conversion" && row.baseMode !== "adopted") {
    throw new Error("PFT2 base proof returned an unknown base mode.");
  }
  const root = recordWithExactKeys(row.root, ["digest", "size", "maxInoSeen"]);
  requireRef(root.digest, root.size, PFT2_MAX_NODE_BYTES);
  requireDecimal(root.maxInoSeen, 1n, PFT2_MAX_INO);
  if (row.baseMode === "fork") {
    const allocator = recordWithExactKeys(row.allocator, [
      "inodeNamespace",
      "nextLocal",
      "maxInoSeen",
    ]);
    requireDecimal(allocator.inodeNamespace, 1n, BigInt(PFT2_MAX_INODE_NAMESPACE));
    requireDecimal(allocator.nextLocal, 1n, PFT2_MAX_INODE_LOCAL_COUNTER + 1n);
    requireDecimal(allocator.maxInoSeen, 1n, PFT2_MAX_INO);
    return;
  }
  const anchor = recordWithExactKeys(row.anchor, [
    "anchorId",
    "asOfSeq",
    "recoveryRootDigest",
    "recoveryRootSize",
    "controlRootDigest",
    "controlRootSize",
    ...(isRecord(row.anchor) && row.anchor.orphanIndexDigest !== undefined
      ? ["orphanIndexDigest", "orphanIndexSize"]
      : []),
    "inodeNamespace",
    "nextLocal",
    "maxInoSeen",
  ]);
  if (typeof anchor.anchorId !== "string" || !boundedId.test(anchor.anchorId)) {
    throw new Error("PFT2 anchor id is invalid.");
  }
  requireDecimal(anchor.asOfSeq, 0n, maxSignedInt64);
  if (row.baseMode === "adopted" && anchor.asOfSeq !== row.baseSeq) {
    throw new Error("Adopted PFT2 anchor does not match the journal base sequence.");
  }
  requireRef(anchor.recoveryRootDigest, anchor.recoveryRootSize, PFT2_MAX_NODE_BYTES);
  requireRef(anchor.controlRootDigest, anchor.controlRootSize, PFT2_MAX_NODE_BYTES);
  if (anchor.orphanIndexDigest !== undefined || anchor.orphanIndexSize !== undefined) {
    requireRef(anchor.orphanIndexDigest, anchor.orphanIndexSize, PFT2_MAX_NODE_BYTES);
  }
  requireDecimal(anchor.inodeNamespace, 1n, BigInt(PFT2_MAX_INODE_NAMESPACE));
  requireDecimal(anchor.nextLocal, 1n, PFT2_MAX_INODE_LOCAL_COUNTER + 1n);
  requireDecimal(anchor.maxInoSeen, 1n, PFT2_MAX_INO);
}

export function parseObjectLocation(
  value: HistoryObjectLocation | null,
  tenantId: string,
  digest: string
): HistoryObjectLocation | null {
  if (value === null) return null;
  const row = recordWithExactKeys(value, [
    "tenantId",
    "kind",
    "digest",
    "size",
    "incarnation",
    "state",
    "copies",
  ]);
  if (
    row.tenantId !== tenantId ||
    row.kind !== "pft2" ||
    row.digest !== digest ||
    row.state !== "live" ||
    !isCanonicalSignedInt64(row.size, false) ||
    BigInt(row.size) > BigInt(maxPft2ObjectBytes) ||
    !isCanonicalSignedInt64(row.incarnation, false) ||
    !Array.isArray(row.copies) ||
    row.copies.length > 16
  ) {
    throw new Error("History object location response is malformed.");
  }
  const domains = new Set<string>();
  for (const item of row.copies) {
    const copy = recordWithExactKeys(item, [
      "failureDomain",
      "storageKey",
      "size",
      "lastVerifiedDbMs",
    ]);
    if (
      typeof copy.failureDomain !== "string" ||
      !/^[A-Za-z0-9._-]{1,64}$/u.test(copy.failureDomain) ||
      domains.has(copy.failureDomain) ||
      typeof copy.storageKey !== "string" ||
      copy.storageKey.length < 1 ||
      copy.storageKey.length > 1024 ||
      copy.size !== row.size ||
      !isCanonicalSignedInt64(copy.lastVerifiedDbMs, true)
    ) {
      throw new Error("History object copy response is malformed.");
    }
    domains.add(copy.failureDomain);
  }
  return value;
}

export async function readVerifiedCopy(
  history: PostgresHistoryRepository,
  stores: HistoryStoreRegistry,
  location: HistoryObjectLocation,
  signal: AbortSignal,
  events: VolumeApiTelemetry,
  timeoutMs: number
): Promise<Buffer> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    throw new Error("History copy timeout is invalid.");
  }
  const size = Number(location.size);
  let failures = 0;
  for (const copy of location.copies) {
    if (signal.aborted) throw new DOMException("History object read aborted.", "AbortError");
    const domain = stores.get(copy.failureDomain);
    let reason: "missing" | "corrupt" | "unreachable" = "unreachable";
    try {
      if (!domain) {
        reason = "unreachable";
      } else {
        const timed = childDeadline(signal, timeoutMs);
        try {
          const bytes = await domain.reader.readExactKey(copy.storageKey, {
            expectedSize: size,
            maxBytes: maxPft2ObjectBytes,
            signal: timed.signal,
          });
          if (bytes.byteLength !== size || digestOf(bytes) !== location.digest) {
            reason = "corrupt";
          } else {
            events.emit({
              type: "history_copy",
              outcome: failures === 0 ? "ok" : "failover",
            });
            return bytes;
          }
        } finally {
          timed.dispose();
        }
      }
    } catch (error) {
      if (signal.aborted) throw new DOMException("History object read aborted.", "AbortError");
      reason = classifyCopyFailure(error);
    }
    failures += 1;
    events.emit({ type: "history_copy", outcome: reason });
    await history
      .scheduleServingCopyVerification({
        tenantId: location.tenantId,
        digest: location.digest,
        incarnation: location.incarnation,
        failureDomain: copy.failureDomain,
        reason,
      })
      .catch(() => undefined);
  }
  events.emit({ type: "history_copy", outcome: "unavailable" });
  throw new HistoryServingUnavailableError();
}

export class HistoryServingUnavailableError extends Error {}

function classifyCopyFailure(error: unknown): "missing" | "corrupt" | "unreachable" {
  if (error instanceof ExactKeyReadError) {
    if (error.code === "not_found") return "missing";
    if (error.code === "invalid_key" || error.code === "size_mismatch") return "corrupt";
  }
  return "unreachable";
}

function childDeadline(
  parent: AbortSignal,
  timeoutMs: number
): {
  signal: AbortSignal;
  dispose(): void;
} {
  const controller = new AbortController();
  const onParent = () => controller.abort();
  parent.addEventListener("abort", onParent, { once: true });
  if (parent.aborted) controller.abort();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  return {
    signal: controller.signal,
    dispose: () => {
      clearTimeout(timer);
      parent.removeEventListener("abort", onParent);
    },
  };
}

function digestOf(bytes: Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function requireRef(digest: unknown, size: unknown, maxBytes: number): void {
  if (
    typeof digest !== "string" ||
    !hexDigest.test(digest) ||
    typeof size !== "string" ||
    !isCanonicalSignedInt64(size, false)
  ) {
    throw new Error("PFT2 reference is invalid.");
  }
  const parsed = BigInt(size);
  if (parsed < BigInt(PFT2_MIN_NODE_BYTES) || parsed > BigInt(maxBytes)) {
    throw new Error("PFT2 reference exceeds its frozen size bound.");
  }
}

function requireDecimal(value: unknown, min: bigint, max: bigint): void {
  if (typeof value !== "string" || !isCanonicalSignedInt64(value, min === 0n)) {
    throw new Error("PFT2 decimal fact is invalid.");
  }
  const parsed = BigInt(value);
  if (parsed < min || parsed > max) throw new Error("PFT2 decimal fact exceeds its bound.");
}

function isCanonicalSignedInt64(value: unknown, allowZero: boolean): value is string {
  if (typeof value !== "string" || !canonicalDecimal.test(value)) return false;
  const parsed = BigInt(value);
  return (allowZero ? parsed >= 0n : parsed >= 1n) && parsed <= maxSignedInt64;
}

function recordWithExactKeys(value: unknown, keys: string[]): Record<string, unknown> {
  if (!isRecord(value)) throw new Error("History response is not an object.");
  const expected = new Set(keys);
  const actual = Object.keys(value);
  if (actual.length !== expected.size || actual.some((key) => !expected.has(key))) {
    throw new Error("History response has missing or unknown fields.");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sendServingError(res: ServerResponse, error: unknown): void {
  if (res.headersSent) return;
  if (error instanceof MetadataConflictError) {
    sendJson(res, error.status, { error: { code: error.code, message: error.message } });
    return;
  }
  if (error instanceof HistoryServingUnavailableError) {
    sendJson(res, 503, {
      error: {
        code: "HISTORY_OBJECT_UNAVAILABLE",
        message: "No verified history object copy is currently available.",
      },
    });
    return;
  }
  const code = (error as { code?: unknown }).code;
  if (code === "PF002" || code === "PF005" || code === "PF011") {
    sendJson(res, 409, {
      error: { code: "HISTORY_BASE_PROOF_REJECTED", message: "History base proof was rejected." },
    });
    return;
  }
  if (code === "PF008") {
    sendJson(res, 400, {
      error: { code: "HISTORY_REQUEST_INVALID", message: "History request is invalid." },
    });
    return;
  }
  sendJson(res, 503, {
    error: { code: "HISTORY_SERVING_UNAVAILABLE", message: "History serving is unavailable." },
  });
}

function sendNotFound(res: ServerResponse): void {
  sendJson(res, 404, { error: { code: "HISTORY_NOT_FOUND", message: "Not found." } });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const bytes = Buffer.from(JSON.stringify(body));
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.setHeader("content-length", String(bytes.byteLength));
  res.end(bytes);
}

function sendBuffer(res: ServerResponse, method: string, bytes: Buffer, contentType: string): void {
  res.statusCode = 200;
  res.setHeader("content-type", contentType);
  res.setHeader("content-length", String(bytes.byteLength));
  res.end(method === "HEAD" ? undefined : bytes);
}
