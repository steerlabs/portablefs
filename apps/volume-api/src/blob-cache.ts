import { Readable } from "node:stream";
import {
  bufferedBlobByteStream,
  type BlobByteStream,
  type BlobStore,
  type BlobStorePutOptions,
  type BlobStorePutResult,
  type OpenBlobStreamOptions,
} from "@portablefs/core";
import type { BlobDigest } from "@portablefs/protocol";

const MiB = 1024 * 1024;

/**
 * Entries above this size are served but never cached: one 64 MiB blob would
 * displace an eighth of the default cache for a single reader, and large
 * blobs are exactly the ones the streaming path exists for. Cached blobs
 * (<= this bound) keep the buffered fast path; everything else streams from
 * the backing store on every read.
 */
export const blobCacheMaxEntryBytes = 8 * MiB;

export const defaultBlobCacheMaxBytes = 512 * MiB;

interface CacheEntry {
  bytes: Buffer;
}

/**
 * In-memory LRU over immutable content-addressed blobs.
 *
 * NO COPIES ON HIT: entries are digest-keyed immutable bytes, so hits return
 * the cached buffer itself (a 64 MiB defensive copy per hit was pure memcpy +
 * GC churn). Callers must treat returned buffers as read-only — every caller
 * in this service reads, hashes, slices, or writes them out; none mutate.
 * (Object.freeze cannot enforce this: freezing a non-empty TypedArray throws.)
 *
 * O(1) LRU: a Map preserves insertion order, so a hit is delete+set (move to
 * newest) and eviction pops the oldest key until the budget holds — the old
 * sort-all-entries eviction was O(n log n) on every overflow.
 */
export class MemoryCachingBlobStore implements BlobStore {
  private readonly maxBytes: number;
  private readonly maxEntryBytes: number;
  private readonly entries = new Map<BlobDigest, CacheEntry>();
  private totalBytes = 0;

  constructor(
    private readonly inner: BlobStore,
    maxBytes = defaultBlobCacheMaxBytes,
    maxEntryBytes = blobCacheMaxEntryBytes
  ) {
    this.maxBytes = maxBytes;
    this.maxEntryBytes = Math.min(maxEntryBytes, maxBytes);
  }

  get cachedBytes(): number {
    return this.totalBytes;
  }

  get cachedEntries(): number {
    return this.entries.size;
  }

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    const result = await this.inner.put(buffer, options);
    this.set(result.blob.digest, buffer);
    return result;
  }

  async get(digest: BlobDigest): Promise<Buffer> {
    const cached = this.entries.get(digest);
    if (cached) {
      this.touch(digest, cached);
      return cached.bytes;
    }
    const bytes = await this.inner.get(digest);
    // Serve the same allocation the cache keeps, so hits and the admitting
    // miss observe one identity and later hits never need a copy.
    return this.set(digest, bytes);
  }

  async has(digest: BlobDigest): Promise<boolean> {
    return this.entries.has(digest) || this.inner.has(digest);
  }

  async delete(digest: BlobDigest): Promise<void> {
    const cached = this.entries.get(digest);
    if (cached) {
      this.totalBytes -= cached.bytes.byteLength;
      this.entries.delete(digest);
    }
    await this.inner.delete?.(digest);
  }

  /**
   * Streaming read through the cache: hits serve zero-copy buffered streams
   * from RAM; misses stream from the backing store, teeing cacheable full
   * reads (<= the entry bound) into the cache once the store's trailing
   * digest verification lets the final byte through. Range reads and large
   * blobs never populate the cache.
   */
  async openBlobStream(digest: BlobDigest, options?: OpenBlobStreamOptions): Promise<BlobByteStream> {
    const cached = this.entries.get(digest);
    if (cached) {
      this.touch(digest, cached);
      return bufferedBlobByteStream(digest, cached.bytes, options?.range);
    }
    if (!this.inner.openBlobStream) {
      // Buffered fallback fills the cache exactly like a get() miss.
      const bytes = await this.get(digest);
      return bufferedBlobByteStream(digest, bytes, options?.range);
    }
    const opened = await this.inner.openBlobStream(digest, options);
    if (options?.range || opened.buffered || opened.totalLength > this.maxEntryBytes) {
      return opened;
    }
    return {
      ...opened,
      stream: Readable.from(this.teeIntoCache(digest, opened), { objectMode: false }),
    };
  }

  // Admission happens only after the source stream ENDS: full store streams
  // verify the digest before releasing their final chunk, so a completed tee
  // is verified content. An aborted or failed stream admits nothing.
  private async *teeIntoCache(digest: BlobDigest, opened: BlobByteStream): AsyncGenerator<Buffer> {
    const chunks: Buffer[] = [];
    for await (const chunk of opened.stream) {
      chunks.push(chunk);
      yield chunk;
    }
    this.set(digest, Buffer.concat(chunks, opened.totalLength));
  }

  private touch(digest: BlobDigest, entry: CacheEntry): void {
    this.entries.delete(digest);
    this.entries.set(digest, entry);
  }

  private set(digest: BlobDigest, bytes: Buffer): Buffer {
    if (bytes.byteLength > this.maxEntryBytes) {
      return bytes;
    }
    const existing = this.entries.get(digest);
    if (existing) {
      this.totalBytes -= existing.bytes.byteLength;
      this.entries.delete(digest);
    }
    // Adopt exact allocations by reference (hits already share them, so a
    // copy here would only burn memory). A VIEW over a larger allocation —
    // a batch-body subarray or a pooled slab slice — is copied into an exact
    // unpooled allocation so caching 4 KiB can never pin 64 MiB of parent
    // buffer (and the accounted bytes equal the retained bytes).
    const owned = bytes.byteLength === bytes.buffer.byteLength ? bytes : exactCopy(bytes);
    this.entries.set(digest, { bytes: owned });
    this.totalBytes += owned.byteLength;
    while (this.totalBytes > this.maxBytes) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      const evicted = this.entries.get(oldest);
      this.entries.delete(oldest);
      if (evicted) {
        this.totalBytes -= evicted.bytes.byteLength;
      }
    }
    return owned;
  }
}

function exactCopy(bytes: Buffer): Buffer {
  const copy = Buffer.allocUnsafeSlow(bytes.byteLength);
  bytes.copy(copy);
  return copy;
}
