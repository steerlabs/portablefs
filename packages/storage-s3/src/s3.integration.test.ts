import { randomBytes, randomUUID } from "node:crypto";
import { afterAll, describe, expect, test } from "vitest";
import { sha256Buffer } from "@portablefs/core";
import type { BlobDigest } from "@portablefs/protocol";
import { S3BlobStore, s3ConfigFromEnv } from "./index.js";

const runS3Bucket = process.env.PORTABLEFS_TEST_S3_BUCKET === "true";
const testS3Bucket = runS3Bucket ? test : test.skip;

describe("S3BlobStore against a real bucket", () => {
  let store: S3BlobStore | undefined;
  const uploaded = new Set<BlobDigest>();
  const deleted = new Set<BlobDigest>();

  afterAll(async () => {
    if (!store) {
      return;
    }
    for (const digest of uploaded) {
      if (!deleted.has(digest)) {
        await store.delete(digest).catch(() => undefined);
      }
    }
  });

  testS3Bucket("puts, dedupes, verifies, downloads, and deletes blobs", async () => {
    store = new S3BlobStore(realBucketConfig());
    const buffers = [
      Buffer.from(`portablefs s3 bucket smoke ${randomUUID()}\n`),
      randomBytes(2 * 1024 * 1024 + 17),
    ];

    for (const buffer of buffers) {
      const digest = sha256Buffer(buffer);
      const first = await store.put(buffer, { digest });
      uploaded.add(digest);

      expect(first.blob.digest).toBe(digest);
      expect(first.blob.size).toBe(buffer.byteLength);
      await expect(store.has(digest)).resolves.toBe(true);
      await expect(store.get(digest)).resolves.toEqual(buffer);

      const second = await store.put(buffer, { digest });
      expect(second.blob.storageKey).toBe(first.blob.storageKey);

      await store.delete(digest);
      deleted.add(digest);
      await expect(store.has(digest)).resolves.toBe(false);
    }
  }, 120_000);
});

function realBucketConfig() {
  return s3ConfigFromEnv({
    ...process.env,
    VOLUME_S3_PREFIX: testPrefix(),
  });
}

function testPrefix(): string {
  const base =
    process.env.VOLUME_S3_PREFIX?.trim() ||
    process.env.VOLUME_RAILWAY_BUCKET_PREFIX?.trim() ||
    "portablefs";
  return `${base.replace(/^\/+|\/+$/g, "")}/s3-bucket-test/${Date.now()}-${randomUUID()}`;
}
