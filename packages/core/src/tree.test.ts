import { mkdir, open, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, test } from "vitest";
import type { BlobDigest, TreeEntry } from "@portablefs/protocol";
import {
  applyManifestDiff,
  applyManifestDiffIndexed,
  canonicalizeManifestDiff,
  collectMissingBlobDigests,
  comparePaths,
  computeTreeHash,
  createManifestIndex,
  diffManifests,
  diffManifestIndexes,
  emptyScanWorkspaceCache,
  materializeManifest,
  materializeManifestDiff,
  scanWorkspace,
  scanWorkspacePaths,
} from "./tree.js";

describe("tree manifests", () => {
  test("tree hash is locale-independent (code-unit ordering, not collation)", () => {
    // Enough entries that FNV shards collide, with mixed-case + accented names so a
    // collation-sensitive comparator would reorder within-shard members and change
    // the hash. The hash must stay constant regardless of host locale / ICU version.
    const names: string[] = [];
    for (let index = 0; index < 2000; index += 1) {
      names.push(`dir/f${index.toString(36)}.txt`);
    }
    for (const extra of ["ä", "ö", "z", "Z", "İ", "i", "café", "cafe", "straße"]) {
      names.push(`unicode/${extra}.txt`);
    }
    const entries: TreeEntry[] = names.map((entryPath, index) => ({
      path: entryPath,
      kind: "file",
      mode: 0o644,
      size: 1,
      mtimeMs: 0,
      executable: false,
      blob: {
        digest: `sha256:${index.toString(16).padStart(64, "0")}` as BlobDigest,
        size: 1,
        compression: "none",
        packed: false,
      },
    }));
    expect(comparePaths("B", "a")).toBeLessThan(0); // code-unit: uppercase before lowercase
    const expected = computeTreeHash(entries);
    const originalLocaleCompare = String.prototype.localeCompare;
    try {
      // Emulate a different host locale by forcing a hostile collation order.
      String.prototype.localeCompare = function (this: string, that: string): number {
        const left = String(this);
        const right = String(that);
        return left < right ? 1 : left > right ? -1 : 0;
      } as typeof String.prototype.localeCompare;
      expect(computeTreeHash(entries)).toBe(expected);
    } finally {
      String.prototype.localeCompare = originalLocaleCompare;
    }
  });

  test("scan and materialize round trip content-addressed files", async () => {
    const source = path.join(tmpdir(), `portablefs-core-source-${Date.now()}-${Math.random()}`);
    const target = path.join(tmpdir(), `portablefs-core-target-${Date.now()}-${Math.random()}`);
    await mkdir(path.join(source, "nested"), { recursive: true });
    await writeFile(path.join(source, "nested", "hello.txt"), "hello\n");

    const manifest = await scanWorkspace(source);
    const store = new Map<BlobDigest, Buffer>();
    for (const entry of manifest.entries) {
      if (entry.kind === "file" && entry.blob) {
        store.set(entry.blob.digest, await readFile(path.join(source, entry.path)));
      }
    }
    await materializeManifest(target, manifest, async (digest) => {
      const bytes = store.get(digest);
      if (!bytes) {
        throw new Error(`missing ${digest}`);
      }
      return bytes;
    });
    expect(await readFile(path.join(target, "nested", "hello.txt"), "utf8")).toBe("hello\n");
    expect((await scanWorkspace(target)).treeHash).toBe(manifest.treeHash);
  });

  test("materializes unchanged existing files without fetching blobs again", async () => {
    const source = path.join(tmpdir(), `portablefs-core-skip-source-${Date.now()}-${Math.random()}`);
    const target = path.join(tmpdir(), `portablefs-core-skip-target-${Date.now()}-${Math.random()}`);
    const scanOptions = {
      largeFileThresholdBytes: 1024,
      largeFileChunkBytes: 1024,
    };
    await mkdir(path.join(source, "nested"), { recursive: true });
    await writeFile(path.join(source, "nested", "hello.txt"), "hello\n");
    await writeFile(
      path.join(source, "large.bin"),
      Buffer.concat([Buffer.alloc(1024, "a"), Buffer.alloc(1024, "b")])
    );

    const manifest = await scanWorkspace(source, scanOptions);
    const store = new Map<BlobDigest, Buffer>();
    await collectBlobs(source, manifest, store);
    await materializeManifest(target, manifest, async (digest) => requireBlob(store, digest));
    const smallMtime = (await stat(path.join(target, "nested", "hello.txt"))).mtimeMs;
    const largeMtime = (await stat(path.join(target, "large.bin"))).mtimeMs;
    let fetchCount = 0;

    await materializeManifest(target, manifest, async (digest) => {
      fetchCount += 1;
      throw new Error(`unexpected blob fetch for ${digest}`);
    });

    expect(fetchCount).toBe(0);
    expect((await scanWorkspace(target, scanOptions)).treeHash).toBe(manifest.treeHash);
    expect((await stat(path.join(target, "nested", "hello.txt"))).mtimeMs).toBe(smallMtime);
    expect((await stat(path.join(target, "large.bin"))).mtimeMs).toBe(largeMtime);

    await rm(source, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  });

  test("materializes independent files with bounded concurrency", async () => {
    const source = path.join(tmpdir(), `portablefs-core-concurrent-source-${Date.now()}-${Math.random()}`);
    const target = path.join(tmpdir(), `portablefs-core-concurrent-target-${Date.now()}-${Math.random()}`);
    await mkdir(source, { recursive: true });
    for (let index = 0; index < 8; index += 1) {
      await writeFile(path.join(source, `file-${index}.txt`), `file ${index}\n`);
    }
    const manifest = await scanWorkspace(source);
    const store = new Map<BlobDigest, Buffer>();
    await collectBlobs(source, manifest, store);
    let activeReads = 0;
    let maxActiveReads = 0;

    await materializeManifest(
      target,
      manifest,
      async (digest) => {
        activeReads += 1;
        maxActiveReads = Math.max(maxActiveReads, activeReads);
        await new Promise((resolve) => setTimeout(resolve, 10));
        activeReads -= 1;
        return requireBlob(store, digest);
      },
      { concurrency: 4 }
    );

    expect(maxActiveReads).toBeGreaterThan(1);
    expect(maxActiveReads).toBeLessThanOrEqual(4);
    expect((await scanWorkspace(target)).treeHash).toBe(manifest.treeHash);

    await rm(source, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  });

  test("diffs added changed and removed paths", async () => {
    const root = path.join(tmpdir(), `portablefs-core-diff-${Date.now()}-${Math.random()}`);
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, "a.txt"), "a\n");
    await writeFile(path.join(root, "b.txt"), "b\n");
    const before = await scanWorkspace(root);
    await writeFile(path.join(root, "a.txt"), "changed\n");
    await writeFile(path.join(root, "c.txt"), "c\n");
    await import("node:fs/promises").then((fs) => fs.rm(path.join(root, "b.txt")));
    const after = await scanWorkspace(root);
    const diff = diffManifests(before, after);
    expect(diff.changed.map((entry) => entry.path)).toEqual(["a.txt"]);
    expect(diff.added.map((entry) => entry.path)).toEqual(["c.txt"]);
    expect(diff.removed.map((entry) => entry.path)).toEqual(["b.txt"]);
  });

  test("indexed helpers preserve manifest diff and apply semantics", async () => {
    const root = path.join(tmpdir(), `portablefs-core-indexed-diff-${Date.now()}-${Math.random()}`);
    await mkdir(path.join(root, "nested"), { recursive: true });
    await writeFile(path.join(root, "nested", "a.txt"), "a\n");
    await writeFile(path.join(root, "b.txt"), "b\n");
    const before = await scanWorkspace(root);
    await writeFile(path.join(root, "nested", "a.txt"), "changed\n");
    await writeFile(path.join(root, "c.txt"), "c\n");
    await rm(path.join(root, "b.txt"));
    const after = await scanWorkspace(root);

    const legacyDiff = diffManifests(before, after);
    const indexedDiff = diffManifestIndexes(createManifestIndex(before), createManifestIndex(after));
    const legacyApplied = applyManifestDiff(before, legacyDiff);
    const indexedApplied = applyManifestDiffIndexed(createManifestIndex(before), legacyDiff);

    expect(indexedDiff).toEqual(legacyDiff);
    expect(indexedApplied.manifest).toEqual(legacyApplied);
    expect(indexedApplied.index.entriesByPath.get("nested/a.txt")).toEqual(
      after.entries.find((entry) => entry.path === "nested/a.txt")
    );

    await rm(root, { recursive: true, force: true });
  });

  test("canonicalizes client manifest diffs by touched path only", async () => {
    const root = path.join(tmpdir(), `portablefs-core-canonical-diff-${Date.now()}-${Math.random()}`);
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, "existing.txt"), "before\n");
    const before = await scanWorkspace(root);
    const existing = before.entries.find((entry) => entry.path === "existing.txt");
    expect(existing).toBeTruthy();

    const unchanged = canonicalizeManifestDiff(createManifestIndex(before), {
      added: [],
      changed: [existing!],
      removed: [],
      mutationCount: 1,
      byteCount: 999,
    });
    expect(unchanged.mutationCount).toBe(0);
    expect(unchanged.byteCount).toBe(0);

    await writeFile(path.join(root, "existing.txt"), "after\n");
    const after = await scanWorkspace(root);
    const changedEntry = after.entries.find((entry) => entry.path === "existing.txt");
    expect(changedEntry).toBeTruthy();
    const canonical = canonicalizeManifestDiff(createManifestIndex(before), {
      added: [changedEntry!],
      changed: [],
      removed: [],
      mutationCount: 1,
      byteCount: 0,
    });
    expect(canonical.added).toEqual([]);
    expect(canonical.changed.map((entry) => entry.path)).toEqual(["existing.txt"]);
    expect(canonical.byteCount).toBe(changedEntry!.blob!.size);

    await rm(root, { recursive: true, force: true });
  });

  test("indexed helper keeps shared blob digests live until the final reference is removed", async () => {
    const root = path.join(tmpdir(), `portablefs-core-indexed-digest-count-${Date.now()}-${Math.random()}`);
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, "a.txt"), "same\n");
    await writeFile(path.join(root, "b.txt"), "same\n");
    const before = await scanWorkspace(root);
    const digest = before.entries.find((entry) => entry.path === "a.txt")?.blob?.digest;
    expect(digest).toBeTruthy();

    await rm(path.join(root, "a.txt"));
    const after = await scanWorkspace(root);
    const applied = applyManifestDiffIndexed(createManifestIndex(before), diffManifests(before, after));

    expect(applied.index.storedBlobDigestCounts.get(digest!)).toBe(1);
    expect(applied.index.storedBlobDigests.has(digest!)).toBe(true);

    await rm(path.join(root, "b.txt"));
    const empty = await scanWorkspace(root);
    const emptyApplied = applyManifestDiffIndexed(applied.index, diffManifests(after, empty));
    expect(emptyApplied.index.storedBlobDigests.has(digest!)).toBe(false);

    await rm(root, { recursive: true, force: true });
  });

  test("reuses cached scan entries for unchanged files", async () => {
    const root = path.join(tmpdir(), `portablefs-core-scan-cache-${Date.now()}-${Math.random()}`);
    const cache = emptyScanWorkspaceCache();
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, "unchanged.txt"), "same\n");

    const first = await scanWorkspace(root, { cache });
    const cachedEntry = cache.entries["unchanged.txt"]?.entry;
    const second = await scanWorkspace(root, { cache });

    expect(second).toEqual(first);
    expect(second.entries[0]).toBe(cachedEntry);

    await rm(root, { recursive: true, force: true });
  });

  test("reuses cached root hashes only when the scanned entry set is unchanged", async () => {
    const root = path.join(tmpdir(), `portablefs-core-root-cache-${Date.now()}-${Math.random()}`);
    const cache = emptyScanWorkspaceCache();
    await mkdir(root, { recursive: true });
    await writeFile(path.join(root, "unchanged.txt"), "same\n");

    const first = await scanWorkspace(root, { cache });
    cache.treeHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const unchanged = await scanWorkspace(root, { cache });
    expect(unchanged.treeHash).toBe(cache.treeHash);

    await writeFile(path.join(root, "changed.txt"), "changed\n");
    const changed = await scanWorkspace(root, { cache });
    expect(changed.treeHash).not.toBe("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    expect(changed.treeHash).not.toBe(first.treeHash);

    await rm(root, { recursive: true, force: true });
  });

  test("invalidates cached file digests when ctime changes even if mtime is restored", async () => {
    const root = path.join(tmpdir(), `portablefs-core-scan-cache-ctime-${Date.now()}-${Math.random()}`);
    const cache = emptyScanWorkspaceCache();
    await mkdir(root, { recursive: true });
    const filePath = path.join(root, "changed.txt");
    await writeFile(filePath, "first\n");
    const first = await scanWorkspace(root, { cache });
    const originalMtime = (await stat(filePath)).mtime;

    await writeFile(filePath, "second\n");
    await utimes(filePath, originalMtime, originalMtime);
    const second = await scanWorkspace(root, { cache });

    expect(second.entries[0]?.blob?.digest).not.toBe(first.entries[0]?.blob?.digest);

    await rm(root, { recursive: true, force: true });
  });

  test("incrementally scans dirty paths to match a full manifest", async () => {
    const root = path.join(tmpdir(), `portablefs-core-incremental-${Date.now()}-${Math.random()}`);
    await mkdir(path.join(root, "nested"), { recursive: true });
    await writeFile(path.join(root, "nested", "changed.txt"), "before\n");
    await writeFile(path.join(root, "nested", "unchanged.txt"), "same\n");
    await writeFile(path.join(root, "remove.txt"), "remove\n");
    const before = await scanWorkspace(root);

    await writeFile(path.join(root, "nested", "changed.txt"), "after\n");
    await mkdir(path.join(root, "added-dir"), { recursive: true });
    await writeFile(path.join(root, "added-dir", "added.txt"), "added\n");
    await rm(path.join(root, "remove.txt"));
    const incremental = await scanWorkspacePaths(root, before, [
      "nested/changed.txt",
      "added-dir",
      "remove.txt",
    ]);
    const full = await scanWorkspace(root);

    expect(incremental).toEqual(full);

    await rm(root, { recursive: true, force: true });
  });

  test("incremental scans ignore volume metadata paths", async () => {
    const root = path.join(tmpdir(), `portablefs-core-incremental-ignore-${Date.now()}-${Math.random()}`);
    await mkdir(path.join(root, ".portablefs"), { recursive: true });
    await writeFile(path.join(root, "a.txt"), "a\n");
    const before = await scanWorkspace(root);
    await writeFile(path.join(root, ".portablefs", "state.json"), "{}\n");

    const incremental = await scanWorkspacePaths(root, before, [".portablefs/state.json"]);

    expect(incremental).toEqual(before);

    await rm(root, { recursive: true, force: true });
  });

  test("materializes manifest diffs without rewriting unchanged files", async () => {
    const source = path.join(tmpdir(), `portablefs-core-diff-source-${Date.now()}-${Math.random()}`);
    const target = path.join(tmpdir(), `portablefs-core-diff-target-${Date.now()}-${Math.random()}`);
    await mkdir(path.join(source, "nested"), { recursive: true });
    await writeFile(path.join(source, "nested", "keep.txt"), "keep\n");
    await writeFile(path.join(source, "nested", "change.txt"), "before\n");
    await writeFile(path.join(source, "remove.txt"), "remove\n");
    const before = await scanWorkspace(source);
    const store = new Map<BlobDigest, Buffer>();
    await collectBlobs(source, before, store);
    await materializeManifest(target, before, async (digest) => requireBlob(store, digest));
    const unchangedMtime = (await stat(path.join(target, "nested", "keep.txt"))).mtimeMs;

    await writeFile(path.join(source, "nested", "change.txt"), "after\n");
    await writeFile(path.join(source, "added.txt"), "added\n");
    await rm(path.join(source, "remove.txt"));
    const after = await scanWorkspace(source);
    await collectBlobs(source, after, store);
    const diff = diffManifests(before, after);

    await materializeManifestDiff(target, diff, async (digest) => requireBlob(store, digest));

    expect((await scanWorkspace(target)).treeHash).toBe(after.treeHash);
    await expect(readFile(path.join(target, "remove.txt"))).rejects.toThrow();
    expect(await readFile(path.join(target, "nested", "keep.txt"), "utf8")).toBe("keep\n");
    expect((await stat(path.join(target, "nested", "keep.txt"))).mtimeMs).toBe(unchangedMtime);

    await rm(source, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  });

  test("chunks large files and diffs only changed chunk bytes", async () => {
    const source = path.join(tmpdir(), `portablefs-core-chunk-source-${Date.now()}-${Math.random()}`);
    const target = path.join(tmpdir(), `portablefs-core-chunk-target-${Date.now()}-${Math.random()}`);
    const scanOptions = {
      largeFileThresholdBytes: 1024,
      largeFileChunkBytes: 1024,
    };
    await mkdir(source, { recursive: true });
    await writeFile(
      path.join(source, "database.sqlite"),
      Buffer.concat([
        Buffer.alloc(1024, "a"),
        Buffer.alloc(1024, "b"),
        Buffer.alloc(1024, "c"),
      ])
    );

    const before = await scanWorkspace(source, scanOptions);
    const beforeEntry = before.entries.find((entry) => entry.path === "database.sqlite");
    expect(beforeEntry?.chunks).toHaveLength(3);

    const handle = await open(path.join(source, "database.sqlite"), "r+");
    try {
      await handle.write(Buffer.alloc(64, "z"), 0, 64, 1024 + 128);
    } finally {
      await handle.close();
    }

    const after = await scanWorkspace(source, scanOptions);
    const diff = diffManifests(before, after);
    const missing = collectMissingBlobDigests(before, after);
    expect(diff.mutationCount).toBe(1);
    expect(diff.byteCount).toBe(1024);
    expect(missing).toHaveLength(1);

    const store = new Map<BlobDigest, Buffer>();
    const afterEntry = after.entries.find((entry) => entry.path === "database.sqlite");
    expect(afterEntry?.chunks).toHaveLength(3);
    for (const chunk of afterEntry?.chunks ?? []) {
      const bytes = Buffer.alloc(chunk.size);
      const sourceHandle = await open(path.join(source, "database.sqlite"), "r");
      try {
        await sourceHandle.read(bytes, 0, chunk.size, chunk.offset);
      } finally {
        await sourceHandle.close();
      }
      store.set(chunk.digest, bytes);
    }
    await materializeManifest(target, after, async (digest) => {
      const bytes = store.get(digest);
      if (!bytes) {
        throw new Error(`missing ${digest}`);
      }
      return bytes;
    });
    expect(await readFile(path.join(target, "database.sqlite"))).toEqual(
      await readFile(path.join(source, "database.sqlite"))
    );

    await rm(source, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  });
});

async function collectBlobs(
  root: string,
  manifest: Awaited<ReturnType<typeof scanWorkspace>>,
  store: Map<BlobDigest, Buffer>
): Promise<void> {
  for (const entry of manifest.entries) {
    if (entry.kind !== "file" || !entry.blob) {
      continue;
    }
    if (entry.chunks?.length) {
      const handle = await open(path.join(root, entry.path), "r");
      try {
        for (const chunk of entry.chunks) {
          store.set(chunk.digest, await readRange(handle, chunk.size, chunk.offset));
        }
      } finally {
        await handle.close();
      }
    } else {
      store.set(entry.blob.digest, await readFile(path.join(root, entry.path)));
    }
  }
}

async function readRange(
  handle: Awaited<ReturnType<typeof open>>,
  size: number,
  offset: number
): Promise<Buffer> {
  const buffer = Buffer.allocUnsafe(size);
  let readOffset = 0;
  while (readOffset < size) {
    const result = await handle.read(buffer, readOffset, size - readOffset, offset + readOffset);
    if (result.bytesRead === 0) {
      throw new Error(`Unexpected EOF at ${offset}.`);
    }
    readOffset += result.bytesRead;
  }
  return buffer;
}

function requireBlob(store: Map<BlobDigest, Buffer>, digest: BlobDigest): Buffer {
  const bytes = store.get(digest);
  if (!bytes) {
    throw new Error(`missing ${digest}`);
  }
  return bytes;
}
