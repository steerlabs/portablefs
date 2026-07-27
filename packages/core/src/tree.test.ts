import { mkdir, open, rm, stat, utimes, writeFile } from "node:fs/promises";
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

  test("chunks large files and diffs only changed chunk bytes", async () => {
    const source = path.join(tmpdir(), `portablefs-core-chunk-source-${Date.now()}-${Math.random()}`);
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
    const afterEntry = after.entries.find((entry) => entry.path === "database.sqlite");
    expect(afterEntry?.chunks).toHaveLength(3);

    await rm(source, { recursive: true, force: true });
  });
});
