import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, test } from "vitest";
import {
  BlobRangeNotSatisfiableError,
  sha256Buffer,
  type BlobByteStream,
  type BlobRangeRequest,
} from "@portablefs/core";
import { FilesystemBlobStore, filesystemBlobStoreConfigFromEnv } from "./index.js";

async function collect(stream: AsyncIterable<Buffer>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function withStore(
  run: (store: FilesystemBlobStore, rootDir: string) => Promise<void>
): Promise<void> {
  const rootDir = await mkdtemp(path.join(tmpdir(), "portablefs-fs-store-"));
  try {
    await run(new FilesystemBlobStore({ rootDir }), rootDir);
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
}

describe("FilesystemBlobStore", () => {
  test("stores, verifies, reads, and deletes content-addressed blobs", async () => {
    const rootDir = await mkdtemp(path.join(tmpdir(), "portablefs-fs-store-"));
    try {
      const store = new FilesystemBlobStore({ rootDir });
      const bytes = Buffer.from("local portablefs blob\n");
      const digest = sha256Buffer(bytes);

      const result = await store.put(bytes);

      expect(result.blob.digest).toBe(digest);
      expect(result.blob.size).toBe(bytes.byteLength);
      expect(result.blob.storageKey).toContain("/blobs/sha256/");
      expect(await store.has(digest)).toBe(true);
      expect(await store.get(digest)).toEqual(bytes);

      await store.delete(digest);
      expect(await store.has(digest)).toBe(false);
    } finally {
      await rm(rootDir, { recursive: true, force: true });
    }
  });

  test("rejects digest mismatches", async () => {
    const rootDir = await mkdtemp(path.join(tmpdir(), "portablefs-fs-store-"));
    try {
      const store = new FilesystemBlobStore({ rootDir });
      await expect(
        store.put(Buffer.from("bytes"), {
          digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        })
      ).rejects.toThrow(/digest mismatch/);
    } finally {
      await rm(rootDir, { recursive: true, force: true });
    }
  });

  test("requires a root directory from env", () => {
    expect(() => filesystemBlobStoreConfigFromEnv({})).toThrow(/VOLUME_FILESYSTEM_BLOB_ROOT/);
    expect(filesystemBlobStoreConfigFromEnv({ VOLUME_FILESYSTEM_BLOB_ROOT: "blobs" })).toEqual({
      rootDir: path.resolve("blobs"),
    });
  });

  test("streams a full blob with trailing digest verification", async () => {
    await withStore(async (store) => {
      const bytes = Buffer.from("stream me from disk\n".repeat(1000));
      const digest = sha256Buffer(bytes);
      await store.put(bytes);

      const opened = await store.openBlobStream(digest);
      expect(opened.totalLength).toBe(bytes.byteLength);
      expect(opened.start).toBe(0);
      expect(opened.end).toBe(bytes.byteLength - 1);
      expect(opened.buffered).toBe(false);
      expect(await collect(opened.stream)).toEqual(bytes);

      const empty = Buffer.alloc(0);
      const emptyDigest = sha256Buffer(empty);
      await store.put(empty);
      const emptyStream = await store.openBlobStream(emptyDigest);
      expect(emptyStream.totalLength).toBe(0);
      expect(await collect(emptyStream.stream)).toEqual(empty);
    });
  });

  test("serves resolved byte ranges without whole-blob buffering semantics", async () => {
    await withStore(async (store) => {
      const bytes = Buffer.from("0123456789abcdefghij");
      const digest = sha256Buffer(bytes);
      await store.put(bytes);

      const cases: Array<{ range: BlobRangeRequest; start: number; end: number; body: string }> = [
        { range: { kind: "bounded", start: 2, end: 5 }, start: 2, end: 5, body: "2345" },
        { range: { kind: "bounded", start: 10, end: 999 }, start: 10, end: 19, body: "abcdefghij" },
        { range: { kind: "open", start: 15 }, start: 15, end: 19, body: "fghij" },
        { range: { kind: "suffix", length: 4 }, start: 16, end: 19, body: "ghij" },
        { range: { kind: "suffix", length: 999 }, start: 0, end: 19, body: bytes.toString() },
      ];
      for (const testCase of cases) {
        const opened: BlobByteStream = await store.openBlobStream(digest, { range: testCase.range });
        expect(opened.totalLength).toBe(bytes.byteLength);
        expect(opened.start).toBe(testCase.start);
        expect(opened.end).toBe(testCase.end);
        expect((await collect(opened.stream)).toString()).toBe(testCase.body);
      }

      await expect(
        store.openBlobStream(digest, { range: { kind: "open", start: 20 } })
      ).rejects.toBeInstanceOf(BlobRangeNotSatisfiableError);
      await expect(
        store.openBlobStream(digest, { range: { kind: "bounded", start: 5, end: 2 } })
      ).rejects.toBeInstanceOf(BlobRangeNotSatisfiableError);
    });
  });

  test("a corrupted blob file errors the full stream before the body can complete", async () => {
    await withStore(async (store) => {
      const bytes = Buffer.from("original verified content\n");
      const digest = sha256Buffer(bytes);
      await store.put(bytes);
      // Same length, different bytes: only the digest proof can catch it.
      await writeFile(store.pathForDigest(digest), Buffer.from("tampered corrupt content!\n"));

      const opened = await store.openBlobStream(digest);
      const received: Buffer[] = [];
      await expect(
        (async () => {
          for await (const chunk of opened.stream) {
            received.push(chunk);
          }
        })()
      ).rejects.toThrow(/checksum mismatch/);
      // The final chunk was withheld: the consumer never assembled a full body.
      expect(Buffer.concat(received).byteLength).toBeLessThan(bytes.byteLength);
    });
  });
});
