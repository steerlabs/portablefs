import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import type { BlobDigest } from "@portablefs/protocol";
import type {
  BlobByteStream,
  BlobRangeRequest,
  BlobStore,
  OpenBlobStreamOptions,
} from "./blob-store.js";

// ---------------------------------------------------------------------------
// Streaming blob reads: range resolution, content-address verification, and
// the buffered fallback for stores without a streaming surface.
//
// Range semantics follow RFC 9110 single ranges exactly as the browse file
// route already does: bytes=a-b clamps the end to the blob, bytes=a- reads to
// the end, bytes=-n reads the last n bytes. Multi-range and syntactically
// malformed headers are the CALLER's concern (parsed before a store is asked);
// a range whose start lies at or past the blob (or any range against an empty
// blob) is unsatisfiable and rejects typed so HTTP layers can answer 416 with
// the true total length.
// ---------------------------------------------------------------------------

export class BlobRangeNotSatisfiableError extends Error {
  readonly totalLength: number;

  constructor(digest: BlobDigest, totalLength: number) {
    super(`Requested range of ${digest} is not satisfiable within ${totalLength} bytes.`);
    this.name = "BlobRangeNotSatisfiableError";
    this.totalLength = totalLength;
  }
}

export interface ResolvedBlobRange {
  /** Inclusive start offset. */
  start: number;
  /** Inclusive end offset; -1 only for the full read of an empty blob. */
  end: number;
}

/**
 * Resolves a parsed range request against the blob's total length. No range
 * means the whole blob. Throws {@link BlobRangeNotSatisfiableError} for
 * unsatisfiable requests (start at/past the end, suffix of zero, any range
 * against an empty blob) — matching what the browse file route serves as 416.
 */
export function resolveBlobRange(
  range: BlobRangeRequest | undefined,
  digest: BlobDigest,
  totalLength: number
): ResolvedBlobRange {
  if (!range) {
    return { start: 0, end: totalLength - 1 };
  }
  if (totalLength === 0) {
    throw new BlobRangeNotSatisfiableError(digest, totalLength);
  }
  if (range.kind === "suffix") {
    if (range.length <= 0) {
      throw new BlobRangeNotSatisfiableError(digest, totalLength);
    }
    return { start: Math.max(0, totalLength - range.length), end: totalLength - 1 };
  }
  if (range.start >= totalLength) {
    throw new BlobRangeNotSatisfiableError(digest, totalLength);
  }
  if (range.kind === "open") {
    return { start: range.start, end: totalLength - 1 };
  }
  if (range.end < range.start) {
    throw new BlobRangeNotSatisfiableError(digest, totalLength);
  }
  return { start: range.start, end: Math.min(range.end, totalLength - 1) };
}

/**
 * Wraps a full-blob source so every byte is hashed and the FINAL chunk is
 * withheld until the digest (and exact length) prove out. A store fault can
 * therefore never complete a corrupt body: the consumer sees a stream error
 * while at least one declared byte is still outstanding, which HTTP layers
 * surface as a destroyed connection rather than a clean end.
 */
export async function* verifyBlobStreamTrailing(
  source: AsyncIterable<Uint8Array>,
  digest: BlobDigest,
  totalLength: number
): AsyncGenerator<Buffer> {
  const hash = createHash("sha256");
  let seen = 0;
  let held: Buffer | undefined;
  for await (const chunk of source) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (bytes.byteLength === 0) {
      continue;
    }
    seen += bytes.byteLength;
    if (seen > totalLength) {
      throw new Error(`Blob ${digest} produced ${seen} bytes, above its declared ${totalLength}.`);
    }
    hash.update(bytes);
    if (held) {
      yield held;
    }
    held = bytes;
  }
  if (seen !== totalLength) {
    throw new Error(`Blob ${digest} truncated at ${seen} of ${totalLength} bytes.`);
  }
  const actual = `sha256:${hash.digest("hex")}`;
  if (actual !== digest) {
    throw new Error(`Blob checksum mismatch for ${digest}: ${actual}`);
  }
  if (held) {
    yield held;
  }
}

/**
 * Emits exactly the inclusive [start, end] window of a byte source, then
 * stops pulling (the abandoned source is destroyed through the generator's
 * finally when the returned iterator closes). Used where the underlying
 * transport cannot seek — for example gzip-stored objects that must be
 * decompressed from byte zero.
 */
export async function* sliceByteStream(
  source: AsyncIterable<Uint8Array>,
  start: number,
  end: number
): AsyncGenerator<Buffer> {
  let offset = 0;
  for await (const chunk of source) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const chunkStart = offset;
    offset += bytes.byteLength;
    if (offset <= start) {
      continue;
    }
    const from = Math.max(0, start - chunkStart);
    const to = Math.min(bytes.byteLength, end + 1 - chunkStart);
    if (to > from) {
      yield bytes.subarray(from, to);
    }
    if (offset > end) {
      return;
    }
  }
  if (offset <= end) {
    throw new Error(`Byte source ended at ${offset} before the requested range end ${end}.`);
  }
}

/**
 * A {@link BlobByteStream} over bytes that are already resident in memory.
 * Zero-copy: range views share the buffer's memory (content-addressed bytes
 * are immutable; consumers must not mutate them).
 */
export function bufferedBlobByteStream(
  digest: BlobDigest,
  bytes: Buffer,
  range: BlobRangeRequest | undefined
): BlobByteStream {
  const resolved = resolveBlobRange(range, digest, bytes.byteLength);
  const body = bytes.subarray(resolved.start, resolved.end + 1);
  return {
    totalLength: bytes.byteLength,
    start: resolved.start,
    end: resolved.end,
    buffered: true,
    stream: Readable.from(body.byteLength === 0 ? [] : [body], { objectMode: false }),
  };
}

/**
 * The one entry point for streaming blob reads: uses the store's streaming
 * surface when present, otherwise falls back to a buffered `get()` with
 * identical range semantics. The fallback materializes the whole blob, which
 * the result reports through `buffered` so callers can account memory
 * honestly.
 */
export async function openBlobByteStream(
  store: BlobStore,
  digest: BlobDigest,
  options?: OpenBlobStreamOptions
): Promise<BlobByteStream> {
  if (options?.signal?.aborted) {
    throw new DOMException("The blob stream open was aborted.", "AbortError");
  }
  if (store.openBlobStream) {
    return store.openBlobStream(digest, options);
  }
  const bytes = await store.get(digest);
  return bufferedBlobByteStream(digest, bytes, options?.range);
}
