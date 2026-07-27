import { randomBytes, randomUUID } from "node:crypto";
import { afterAll, describe, expect, test } from "vitest";
import { sha256Buffer } from "@portablefs/core";
import type { BlobDigest } from "@portablefs/protocol";
import {
  RailwayBucketBlobStore,
  railwayBucketConfigFromEnv,
  railwayBucketConfigFromRailwayCliEnv,
} from "./index.js";

const runRailwayBucket = process.env.PORTABLEFS_TEST_RAILWAY_BUCKET === "true";
const testRailwayBucket = runRailwayBucket ? test : test.skip;

describe("RailwayBucketBlobStore against a real Railway Bucket", () => {
  let store: RailwayBucketBlobStore | undefined;
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

  testRailwayBucket("puts, dedupes, verifies, downloads, and deletes blobs", async () => {
    store = new RailwayBucketBlobStore(realRailwayConfig());
    const buffers = [
      Buffer.from(`portablefs railway bucket smoke ${randomUUID()}\n`),
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

function realRailwayConfig() {
  const env = {
    ...process.env,
    VOLUME_RAILWAY_BUCKET_PREFIX: testPrefix(),
  };
  if (process.env.VOLUME_RAILWAY_BUCKET_ENDPOINT) {
    return railwayBucketConfigFromEnv(env);
  }
  return railwayBucketConfigFromRailwayCliEnv(env);
}

function testPrefix(): string {
  const base = process.env.VOLUME_RAILWAY_BUCKET_PREFIX?.trim() || "portablefs";
  return `${base.replace(/^\/+|\/+$/g, "")}/railway-bucket-test/${Date.now()}-${randomUUID()}`;
}
