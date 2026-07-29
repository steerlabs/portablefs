import { describe, expect, test } from "vitest";
import type { BlobDigest, TreeEntry, TreeManifest } from "@portablefs/protocol";
import { protocolVersion } from "@portablefs/protocol";
import { sha256Buffer } from "./hash.js";
import {
  applyManifestDiffIndexed,
  canonicalizeManifestDiff,
  comparePaths,
  computeTreeHash,
  createManifestIndex,
  diffManifests,
  diffManifestIndexes,
} from "./tree.js";

function fileEntry(entryPath: string, content: string): TreeEntry {
  const bytes = Buffer.from(content);
  return {
    path: entryPath,
    kind: "file",
    mode: 0o644,
    size: bytes.byteLength,
    mtimeMs: 0,
    executable: false,
    blob: {
      digest: sha256Buffer(bytes),
      size: bytes.byteLength,
      compression: "none",
      packed: false,
    },
  };
}

function manifestOf(entries: TreeEntry[]): TreeManifest {
  const sorted = [...entries].sort((left, right) => comparePaths(left.path, right.path));
  return {
    version: protocolVersion,
    treeHash: computeTreeHash(sorted),
    entries: sorted,
  };
}

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

  test("diffs added changed and removed paths", () => {
    const before = manifestOf([fileEntry("a.txt", "a\n"), fileEntry("b.txt", "b\n")]);
    const after = manifestOf([fileEntry("a.txt", "changed\n"), fileEntry("c.txt", "c\n")]);
    const diff = diffManifests(before, after);
    expect(diff.changed.map((entry) => entry.path)).toEqual(["a.txt"]);
    expect(diff.added.map((entry) => entry.path)).toEqual(["c.txt"]);
    expect(diff.removed.map((entry) => entry.path)).toEqual(["b.txt"]);
  });

  test("indexed apply reproduces the target manifest from a diff", () => {
    const before = manifestOf([fileEntry("nested/a.txt", "a\n"), fileEntry("b.txt", "b\n")]);
    const after = manifestOf([fileEntry("nested/a.txt", "changed\n"), fileEntry("c.txt", "c\n")]);

    const legacyDiff = diffManifests(before, after);
    const indexedDiff = diffManifestIndexes(createManifestIndex(before), createManifestIndex(after));
    const applied = applyManifestDiffIndexed(createManifestIndex(before), legacyDiff);

    expect(indexedDiff).toEqual(legacyDiff);
    expect(applied.manifest).toEqual(after);
    expect(applied.index.entriesByPath.get("nested/a.txt")).toEqual(
      after.entries.find((entry) => entry.path === "nested/a.txt")
    );
  });

  test("canonicalizes client manifest diffs by touched path only", () => {
    const existing = fileEntry("existing.txt", "before\n");
    const before = manifestOf([existing]);

    const unchanged = canonicalizeManifestDiff(createManifestIndex(before), {
      added: [],
      changed: [existing],
      removed: [],
      mutationCount: 1,
      byteCount: 999,
    });
    expect(unchanged.mutationCount).toBe(0);
    expect(unchanged.byteCount).toBe(0);

    const changedEntry = fileEntry("existing.txt", "after\n");
    const canonical = canonicalizeManifestDiff(createManifestIndex(before), {
      added: [changedEntry],
      changed: [],
      removed: [],
      mutationCount: 1,
      byteCount: 0,
    });
    expect(canonical.added).toEqual([]);
    expect(canonical.changed.map((entry) => entry.path)).toEqual(["existing.txt"]);
    expect(canonical.byteCount).toBe(changedEntry.blob!.size);
  });

  test("indexed helper keeps shared blob digests live until the final reference is removed", () => {
    const shared = "same\n";
    const before = manifestOf([fileEntry("a.txt", shared), fileEntry("b.txt", shared)]);
    const digest = before.entries[0]?.blob?.digest;
    expect(digest).toBeTruthy();

    const after = manifestOf([fileEntry("b.txt", shared)]);
    const applied = applyManifestDiffIndexed(createManifestIndex(before), diffManifests(before, after));

    expect(applied.index.storedBlobDigestCounts.get(digest!)).toBe(1);
    expect(applied.index.storedBlobDigests.has(digest!)).toBe(true);

    const empty = manifestOf([]);
    const emptyApplied = applyManifestDiffIndexed(applied.index, diffManifests(after, empty));
    expect(emptyApplied.index.storedBlobDigests.has(digest!)).toBe(false);
  });
});
