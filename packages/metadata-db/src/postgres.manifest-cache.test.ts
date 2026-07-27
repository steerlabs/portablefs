import { describe, expect, test } from "vitest";
import { computeTreeHash, createManifestIndex, type ManifestIndex } from "@portablefs/core";
import type { TreeEntry, TreeManifest } from "@portablefs/protocol";
import {
  estimateManifestIndexBytes,
  ManifestIndexCache,
  manifestIndexCacheMaxBytesFromEnv,
} from "./postgres.js";

function syntheticIndex(entryCount: number): ManifestIndex {
  const entries: TreeEntry[] = Array.from({ length: entryCount }, (_, index) => {
    const name = String(index).padStart(8, "0");
    return {
      path: `workspace/deep/dir-${name.slice(0, 4)}/${name}.txt`,
      kind: "file" as const,
      mode: 0o644,
      size: 100 + index,
      mtimeMs: 1_700_000_000_000 + index,
      executable: false,
      blob: {
        digest: `sha256:${index.toString(16).padStart(64, "0").slice(-64)}`,
        size: 100 + index,
        compression: "none" as const,
        packed: false,
      },
    };
  });
  const manifest: TreeManifest = {
    version: "portablefs-v1",
    treeHash: computeTreeHash(entries),
    entries,
  };
  return createManifestIndex(manifest);
}

describe("ManifestIndexCache", () => {
  test("estimates size from the entry count at the documented per-entry footprint", () => {
    expect(estimateManifestIndexBytes(syntheticIndex(1000))).toBe(1000 * 1024);
    // Empty manifests still charge their fixed structures.
    expect(estimateManifestIndexBytes(syntheticIndex(0))).toBe(1024);
  });

  test("enforces the byte bound with large synthetic indexes, evicting least recently used first", () => {
    // Budget: three 1000-entry indexes (1000 KiB each) fit; a fourth evicts.
    const cache = new ManifestIndexCache(3 * 1000 * 1024);
    const indexes = [syntheticIndex(1000), syntheticIndex(1000), syntheticIndex(1000), syntheticIndex(1000)];
    cache.set("cmt_a", indexes[0] as ManifestIndex);
    cache.set("cmt_b", indexes[1] as ManifestIndex);
    cache.set("cmt_c", indexes[2] as ManifestIndex);
    expect(cache.size).toBe(3);
    expect(cache.estimatedBytes).toBe(3 * 1000 * 1024);

    // Touch a so b is the least recently used, then overflow.
    expect(cache.get("cmt_a")).toBe(indexes[0]);
    cache.set("cmt_d", indexes[3] as ManifestIndex);
    expect(cache.estimatedBytes).toBeLessThanOrEqual(3 * 1000 * 1024);
    expect(cache.get("cmt_b")).toBeUndefined(); // evicted
    expect(cache.get("cmt_a")).toBe(indexes[0]);
    expect(cache.get("cmt_c")).toBe(indexes[2]);
    expect(cache.get("cmt_d")).toBe(indexes[3]);
  });

  test("one index larger than the whole budget is served uncached instead of purging the cache", () => {
    const cache = new ManifestIndexCache(1000 * 1024);
    const small = syntheticIndex(100);
    cache.set("cmt_small", small);

    cache.set("cmt_huge", syntheticIndex(5000)); // 5x the budget
    expect(cache.get("cmt_huge")).toBeUndefined();
    // The resident small entry survived.
    expect(cache.get("cmt_small")).toBe(small);
    expect(cache.estimatedBytes).toBe(100 * 1024);
  });

  test("keeps the 128-entry cap as a secondary bound under the byte budget", () => {
    const cache = new ManifestIndexCache(1024 * 1024 * 1024);
    const indexes = Array.from({ length: 130 }, () => syntheticIndex(1));
    indexes.forEach((index, position) => cache.set(`cmt_${position}`, index));
    expect(cache.size).toBe(128);
    // The two oldest fell out; the newest 128 remain.
    expect(cache.get("cmt_0")).toBeUndefined();
    expect(cache.get("cmt_1")).toBeUndefined();
    expect(cache.get("cmt_2")).toBe(indexes[2]);
    expect(cache.get("cmt_129")).toBe(indexes[129]);
  });

  test("re-setting a commit replaces its accounting instead of double-charging", () => {
    const cache = new ManifestIndexCache(1000 * 1024);
    cache.set("cmt_x", syntheticIndex(500));
    expect(cache.estimatedBytes).toBe(500 * 1024);
    const replacement = syntheticIndex(200);
    cache.set("cmt_x", replacement);
    expect(cache.estimatedBytes).toBe(200 * 1024);
    expect(cache.size).toBe(1);
    expect(cache.get("cmt_x")).toBe(replacement);
  });
});

describe("manifestIndexCacheMaxBytesFromEnv", () => {
  test("defaults to 256 MiB and honors explicit values", () => {
    expect(manifestIndexCacheMaxBytesFromEnv({})).toBe(256 * 1024 * 1024);
    expect(manifestIndexCacheMaxBytesFromEnv({ VOLUME_MANIFEST_INDEX_CACHE_MB: "512" })).toBe(
      512 * 1024 * 1024
    );
    expect(manifestIndexCacheMaxBytesFromEnv({ VOLUME_MANIFEST_INDEX_CACHE_MB: "0" })).toBe(0);
  });

  test("rejects garbage instead of silently unbounding the cache", () => {
    for (const value of ["-1", "1.5", "lots", "Infinity", "0x10"]) {
      expect(() =>
        manifestIndexCacheMaxBytesFromEnv({ VOLUME_MANIFEST_INDEX_CACHE_MB: value })
      ).toThrow(/VOLUME_MANIFEST_INDEX_CACHE_MB/);
    }
  });
});
