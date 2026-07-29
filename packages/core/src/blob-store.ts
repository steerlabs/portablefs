import type { Readable } from "node:stream";
import type { BlobDigest, BlobRef } from "@portablefs/protocol";

export interface BlobStorePutResult {
  blob: BlobRef;
}

export interface BlobStorePutOptions {
  digest?: BlobDigest;
  checkExisting?: boolean;
  /** Cancels storage work when the originating upload is abandoned. */
  signal?: AbortSignal;
}

/**
 * A byte-range request as parsed from an HTTP Range header, BEFORE resolution
 * against the blob's size (the caller usually does not know the size yet —
 * that is what the store resolves). Offsets are bytes; `end` is inclusive.
 */
export type BlobRangeRequest =
  | { kind: "bounded"; start: number; end: number } // bytes=a-b
  | { kind: "open"; start: number } // bytes=a-
  | { kind: "suffix"; length: number }; // bytes=-n

export interface OpenBlobStreamOptions {
  range?: BlobRangeRequest;
  /**
   * Aborting destroys the underlying read promptly. Stores that cannot cancel
   * in-flight I/O must still refuse an operation that is already aborted.
   */
  signal?: AbortSignal;
}

export interface BlobByteStream {
  /** Whole-blob size in bytes (the Content-Range denominator), not the range's. */
  totalLength: number;
  /** Resolved inclusive byte range actually served; a full read of an empty blob is start 0, end -1. */
  start: number;
  end: number;
  /**
   * True when the whole blob is resident in process memory behind this stream
   * (a cache hit or a buffered fallback). Callers that account memory must
   * charge `totalLength` for buffered streams and only a fixed pipe window
   * for true streams.
   */
  buffered: boolean;
  /**
   * The range's bytes with backpressure. Full (non-range) reads are verified
   * against the content address before the FINAL chunk is released, so a
   * digest mismatch always surfaces as a stream error before the body can
   * complete; range reads cannot re-verify the digest by construction and
   * trust the immutable store. Destroying the stream releases the source.
   */
  stream: Readable;
}

export interface BlobStore {
  put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult>;
  get(digest: BlobDigest): Promise<Buffer>;
  has(digest: BlobDigest): Promise<boolean>;
  delete?(digest: BlobDigest): Promise<void>;
  /**
   * Optional streaming read surface. Stores that can serve bytes without
   * materializing the whole blob implement it; callers must use
   * {@link openBlobByteStream} (never call this directly) so stores without
   * it fall back to a buffered read with identical range semantics.
   * Unsatisfiable ranges reject with {@link BlobRangeNotSatisfiableError}.
   */
  openBlobStream?(digest: BlobDigest, options?: OpenBlobStreamOptions): Promise<BlobByteStream>;
}
