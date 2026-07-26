import { Readable } from "node:stream";
import { describe, expect, test } from "vitest";
import {
  sha256Buffer,
  type BlobByteStream,
  type BlobStore,
  type BlobStorePutOptions,
  type BlobStorePutResult,
  type OpenBlobStreamOptions,
  resolveBlobRange,
} from "@portablefs/core";
import type { BlobDigest } from "@portablefs/protocol";
import { MemoryCachingBlobStore } from "./blob-cache.js";

async function collect(stream: AsyncIterable<Buffer>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

class InnerStore implements BlobStore {
  getCount = 0;
  streamCount = 0;
  readonly blobs = new Map<BlobDigest, Buffer>();
  supportsStreaming = true;
  streamChunkBytes = 4;

  seed(bytes: Buffer): BlobDigest {
    const digest = sha256Buffer(bytes);
    this.blobs.set(digest, bytes);
    return digest;
  }

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    const digest = options?.digest ?? sha256Buffer(buffer);
    this.blobs.set(digest, Buffer.from(buffer));
    return {
      blob: { digest, size: buffer.byteLength, compression: "none", packed: false },
    };
  }

  async get(digest: BlobDigest): Promise<Buffer> {
    this.getCount += 1;
    const bytes = this.blobs.get(digest);
    if (!bytes) {
      throw new Error(`missing ${digest}`);
    }
    return bytes;
  }

  async has(digest: BlobDigest): Promise<boolean> {
    return this.blobs.has(digest);
  }

  openBlobStream = async (
    digest: BlobDigest,
    options?: OpenBlobStreamOptions
  ): Promise<BlobByteStream> => {
    if (!this.supportsStreaming) {
      throw new Error("streaming disabled for this test");
    }
    this.streamCount += 1;
    const bytes = this.blobs.get(digest);
    if (!bytes) {
      throw new Error(`missing ${digest}`);
    }
    const resolved = resolveBlobRange(options?.range, digest, bytes.byteLength);
    const body = bytes.subarray(resolved.start, resolved.end + 1);
    const chunkBytes = this.streamChunkBytes;
    async function* chunks(): AsyncGenerator<Buffer> {
      for (let offset = 0; offset < body.byteLength; offset += chunkBytes) {
        yield body.subarray(offset, Math.min(offset + chunkBytes, body.byteLength));
      }
    }
    return {
      totalLength: bytes.byteLength,
      start: resolved.start,
      end: resolved.end,
      buffered: false,
      stream: Readable.from(chunks()),
    };
  };
}

function bufferlessInner(inner: InnerStore): BlobStore {
  // The same store without a streaming surface: exercises the buffered fallback.
  return {
    put: (buffer, options) => inner.put(buffer, options),
    get: (digest) => inner.get(digest),
    has: (digest) => inner.has(digest),
  };
}

describe("MemoryCachingBlobStore", () => {
  test("a hit returns the cached buffer itself — no copy", async () => {
    const inner = new InnerStore();
    const bytes = Buffer.from("immutable content-addressed bytes");
    const digest = inner.seed(bytes);
    const cache = new MemoryCachingBlobStore(inner, 1024 * 1024);

    const first = await cache.get(digest);
    const second = await cache.get(digest);
    const third = await cache.get(digest);
    // Identity, not equality: the exact same underlying allocation on every hit.
    expect(second).toBe(first);
    expect(third).toBe(first);
    expect(inner.getCount).toBe(1);
  });

  test("caching a view of a larger allocation copies it out instead of pinning the parent", async () => {
    const inner = new InnerStore();
    const cache = new MemoryCachingBlobStore(inner, 1024 * 1024);
    const batchBody = Buffer.alloc(64 * 1024, 7);
    const entry = batchBody.subarray(100, 200);
    const digest = sha256Buffer(entry);

    await cache.put(entry, { digest });
    const cached = await cache.get(digest);
    expect(cached).toEqual(entry);
    // The cached allocation is exactly entry-sized, not the 64 KiB parent.
    expect(cached.buffer.byteLength).toBe(entry.byteLength);
    expect(cache.cachedBytes).toBe(entry.byteLength);
  });

  test("evicts oldest-used first and keeps the total under budget without a sort", async () => {
    const inner = new InnerStore();
    const kilobyte = (fill: string) => Buffer.alloc(1024, fill);
    const a = inner.seed(kilobyte("a"));
    const b = inner.seed(kilobyte("b"));
    const c = inner.seed(kilobyte("c"));
    const d = inner.seed(kilobyte("d"));
    const cache = new MemoryCachingBlobStore(inner, 3 * 1024);

    await cache.get(a);
    await cache.get(b);
    await cache.get(c);
    expect(cache.cachedEntries).toBe(3);

    // Touch a so b becomes the least recently used.
    await cache.get(a);
    expect(inner.getCount).toBe(3);

    // Overflow evicts EXACTLY the oldest-used entry (b), nothing else.
    await cache.get(d);
    expect(cache.cachedBytes).toBeLessThanOrEqual(3 * 1024);
    expect(cache.cachedEntries).toBe(3);
    await cache.get(a);
    await cache.get(c);
    await cache.get(d);
    expect(inner.getCount).toBe(4); // a, c, d all still cached
    await cache.get(b);
    expect(inner.getCount).toBe(5); // b was the one evicted
  });

  test("entries above the per-entry bound are served but never cached", async () => {
    const inner = new InnerStore();
    const big = Buffer.alloc(2048, 9);
    const digest = inner.seed(big);
    const cache = new MemoryCachingBlobStore(inner, 1024 * 1024, 1024);

    await cache.get(digest);
    await cache.get(digest);
    expect(inner.getCount).toBe(2); // never admitted
    expect(cache.cachedEntries).toBe(0);
  });

  test("openBlobStream serves hits from RAM zero-copy, including ranges", async () => {
    const inner = new InnerStore();
    const bytes = Buffer.from("0123456789abcdefghij");
    const digest = inner.seed(bytes);
    const cache = new MemoryCachingBlobStore(inner, 1024 * 1024);
    const cached = await cache.get(digest); // warm

    const full = await cache.openBlobStream(digest);
    expect(full.buffered).toBe(true);
    expect(full.totalLength).toBe(bytes.byteLength);
    const fullChunks: Buffer[] = [];
    for await (const chunk of full.stream) {
      fullChunks.push(chunk);
    }
    expect(Buffer.concat(fullChunks)).toEqual(bytes);
    // The emitted chunk is a view of the cached allocation itself — no copy.
    expect(fullChunks[0]?.buffer).toBe(cached.buffer);

    const ranged = await cache.openBlobStream(digest, {
      range: { kind: "bounded", start: 2, end: 5 },
    });
    expect(ranged.buffered).toBe(true);
    expect(ranged.start).toBe(2);
    expect(ranged.end).toBe(5);
    expect((await collect(ranged.stream)).toString()).toBe("2345");
    expect(inner.streamCount).toBe(0);
    expect(inner.getCount).toBe(1);
  });

  test("openBlobStream misses stream from the store and admit cacheable full reads on completion", async () => {
    const inner = new InnerStore();
    const bytes = Buffer.from("stream me and then cache me");
    const digest = inner.seed(bytes);
    const cache = new MemoryCachingBlobStore(inner, 1024 * 1024);

    const miss = await cache.openBlobStream(digest);
    expect(miss.buffered).toBe(false);
    expect(await collect(miss.stream)).toEqual(bytes);
    expect(inner.streamCount).toBe(1);

    // The completed verified stream warmed the cache: next read is a RAM hit.
    const hit = await cache.openBlobStream(digest);
    expect(hit.buffered).toBe(true);
    expect(await collect(hit.stream)).toEqual(bytes);
    expect(inner.streamCount).toBe(1);
  });

  test("range reads and abandoned streams never populate the cache", async () => {
    const inner = new InnerStore();
    const bytes = Buffer.from("never cached through a partial read");
    const digest = inner.seed(bytes);
    const cache = new MemoryCachingBlobStore(inner, 1024 * 1024);

    const ranged = await cache.openBlobStream(digest, { range: { kind: "open", start: 6 } });
    expect(await collect(ranged.stream)).toEqual(bytes.subarray(6));
    expect(cache.cachedEntries).toBe(0);

    // Abandon a full stream after one chunk: nothing may be admitted.
    const abandoned = await cache.openBlobStream(digest);
    for await (const chunk of abandoned.stream) {
      void chunk;
      break; // async-iterator break destroys the stream
    }
    expect(cache.cachedEntries).toBe(0);
    expect(inner.streamCount).toBe(2);
  });

  test("falls back to a buffered stream (and warms the cache) when the store cannot stream", async () => {
    const inner = new InnerStore();
    const bytes = Buffer.from("buffered fallback body");
    const digest = inner.seed(bytes);
    const cache = new MemoryCachingBlobStore(bufferlessInner(inner), 1024 * 1024);

    const opened = await cache.openBlobStream(digest, { range: { kind: "suffix", length: 4 } });
    expect(opened.buffered).toBe(true);
    expect(opened.totalLength).toBe(bytes.byteLength);
    expect((await collect(opened.stream)).toString()).toBe("body");
    expect(inner.getCount).toBe(1);

    const hit = await cache.openBlobStream(digest);
    expect(hit.buffered).toBe(true);
    expect(inner.getCount).toBe(1);
  });

  test("delete removes the cached entry and reaches the inner store", async () => {
    const inner = new InnerStore();
    const bytes = Buffer.from("deleted bytes");
    const digest = inner.seed(bytes);
    const cache = new MemoryCachingBlobStore(inner, 1024 * 1024);
    await cache.get(digest);
    expect(cache.cachedEntries).toBe(1);

    await cache.delete(digest);
    expect(cache.cachedEntries).toBe(0);
    expect(cache.cachedBytes).toBe(0);
    expect(inner.blobs.has(digest)).toBe(true); // InnerStore has no delete — optional member
  });
});
