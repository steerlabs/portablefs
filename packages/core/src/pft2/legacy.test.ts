import { describe, expect, it } from "vitest";
import { Pft2LegacyBaseTree, type Pft2LegacyManifestEntry } from "./basetree.js";
import {
  Pft2CorruptError,
  Pft2FileKind,
  Pft2InvalidNodeError,
  Pft2NotFoundError,
  checkNodeRefBounds,
} from "./types.js";

function legacyManifestEntries(): Pft2LegacyManifestEntry[] {
  return [
    {
      path: "src/main.go",
      kind: "file",
      mode: 0o644,
      size: 9000000,
      blob: { digest: "sha256:aaaa", size: 9000000 },
      chunks: [
        { digest: "sha256:c1", size: 4194304, offset: 0 },
        { digest: "sha256:c2", size: 4194304, offset: 4194304 },
        { digest: "sha256:c3", size: 611392, offset: 8388608 },
      ],
      ino: 77n,
    },
    {
      path: "README.md",
      kind: "file",
      mode: 0o644,
      size: 5,
      blob: { digest: "sha256:bbbb", size: 5 },
      mtimeMs: 1700000000000,
    },
    { path: "src", kind: "directory", mode: 0o755 },
    { path: "docs/deep/nested.txt", kind: "file", mode: 0o600, size: 0 },
    { path: "link", kind: "symlink", mode: 0o777, linkTarget: "README.md" },
  ];
}

describe("Pft2LegacyBaseTree", () => {
  it("adapts a legacy manifest with synthesized directories and stable inos", async () => {
    const tree = new Pft2LegacyBaseTree(legacyManifestEntries());
    const root = await tree.getInode(1n);
    expect(root.inode.kind).toBe(Pft2FileKind.Directory);

    const srcEntry = await tree.lookup(root.ref, "src");
    const src = await tree.getInode(srcEntry.ino);
    const mainEntry = await tree.lookup(src.ref, "main.go");
    expect(mainEntry.ino).toBe(77n);

    const docsEntry = await tree.lookup(root.ref, "docs");
    expect(docsEntry.kind).toBe(Pft2FileKind.Directory);
    expect(docsEntry.ino > 77n).toBe(true);
    const docs = await tree.getInode(docsEntry.ino);
    const deepEntry = await tree.lookup(docs.ref, "deep");
    const deep = await tree.getInode(deepEntry.ino);
    await expect(tree.lookup(deep.ref, "nested.txt")).resolves.toBeDefined();

    const names: string[] = [];
    let cursor = "";
    for (;;) {
      const { entries, next } = await tree.readDir(root.ref, cursor, 2);
      names.push(...entries.map((entry) => entry.name));
      if (next === "") {
        break;
      }
      cursor = next;
    }
    expect(names).toEqual(["README.md", "docs", "link", "src"]);

    const linkEntry = await tree.lookup(root.ref, "link");
    const link = await tree.getInode(linkEntry.ino);
    expect(link.inode.symlinkTarget).toBe("README.md");
    expect(link.inode.size).toBe(BigInt("README.md".length));

    await expect(tree.lookup(root.ref, "absent")).rejects.toThrow(Pft2NotFoundError);
    await expect(tree.getInode(123456n)).rejects.toThrow(Pft2NotFoundError);
  });

  it("exposes legacy blob and chunk objects as extents", async () => {
    const tree = new Pft2LegacyBaseTree(legacyManifestEntries());
    const main = await tree.getInode(77n);

    const spanning = await tree.readExtents(main.ref, 4194304n - 100n, 200n);
    expect(spanning).toHaveLength(2);
    expect(spanning[0]!.legacy!.objectDigest).toBe("sha256:c1");
    expect(spanning[0]!.fileOffset).toBe(4194304n - 100n);
    expect(spanning[0]!.length).toBe(100n);
    expect(spanning[0]!.legacy!.objectOffset).toBe(4194304n - 100n);
    expect(spanning[1]!.legacy!.objectDigest).toBe("sha256:c2");
    expect(spanning[1]!.fileOffset).toBe(4194304n);
    expect(spanning[1]!.length).toBe(100n);
    expect(spanning[1]!.legacy!.objectOffset).toBe(0n);

    const root = await tree.getInode(1n);
    const readmeEntry = await tree.lookup(root.ref, "README.md");
    const readme = await tree.getInode(readmeEntry.ino);
    const window = await tree.readExtents(readme.ref, 1n, 100n);
    expect(window).toHaveLength(1);
    expect(window[0]!.fileOffset).toBe(1n);
    expect(window[0]!.length).toBe(4n);
    expect(window[0]!.legacy!.objectOffset).toBe(1n);
    expect(window[0]!.legacy!.objectSize).toBe(5n);

    expect(await tree.readExtents(main.ref, 9000000n, 10n)).toHaveLength(0);
    await expect(tree.readExtents(root.ref, 0n, 10n)).rejects.toThrow(Pft2CorruptError);
  });

  it("rejects malformed legacy manifests", () => {
    const cases: Record<string, Pft2LegacyManifestEntry[]> = {
      "duplicate ino": [
        { path: "a", kind: "file", mode: 0o644, ino: 5n },
        { path: "b", kind: "file", mode: 0o644, ino: 5n },
      ],
      "root ino claimed": [{ path: "a", kind: "file", mode: 0o644, ino: 1n }],
      "duplicate path": [
        { path: "a", kind: "file", mode: 0o644 },
        { path: "a", kind: "directory", mode: 0o755 },
      ],
      "file as parent": [
        { path: "a", kind: "file", mode: 0o644 },
        { path: "a/b", kind: "file", mode: 0o644 },
      ],
      "blob size mismatch": [
        { path: "a", kind: "file", mode: 0o644, size: 10, blob: { digest: "sha256:x", size: 9 } },
      ],
      "missing blob": [{ path: "a", kind: "file", mode: 0o644, size: 10 }],
      "non-contiguous chunks": [
        {
          path: "a",
          kind: "file",
          mode: 0o644,
          size: 10,
          chunks: [{ digest: "sha256:c", size: 5, offset: 1 }],
        },
      ],
      "chunk sum mismatch": [
        {
          path: "a",
          kind: "file",
          mode: 0o644,
          size: 10,
          chunks: [{ digest: "sha256:c", size: 5, offset: 0 }],
        },
      ],
      "bad path": [{ path: "a//b", kind: "file", mode: 0o644 }],
      "dotdot path": [{ path: "a/../b", kind: "file", mode: 0o644 }],
      "negative size": [{ path: "a", kind: "file", mode: 0o644, size: -1 }],
      // Full inode-invariant parity with the Go adapter (gate F): every
      // synthesized inode passes the exact PFT2 validation rules.
      "empty symlink target": [{ path: "l", kind: "symlink", mode: 0o777, linkTarget: "" }],
      "symlink target with NUL": [{ path: "l", kind: "symlink", mode: 0o777, linkTarget: "a\0b" }],
      "timestamp beyond bound": [
        { path: "a", kind: "file", mode: 0o644, mtimeMs: 2 ** 60 },
      ],
      "negative timestamp beyond bound": [
        { path: "a", kind: "file", mode: 0o644, ctimeMs: -(2 ** 60) },
      ],
      "uid out of range": [{ path: "a", kind: "file", mode: 0o644, uid: 2 ** 40 }],
      "gid not an integer": [{ path: "a", kind: "file", mode: 0o644, gid: 1.5 }],
    };
    for (const [name, entries] of Object.entries(cases)) {
      expect(() => new Pft2LegacyBaseTree(entries), name).toThrow(Pft2InvalidNodeError);
    }
  });

  it("masks legacy modes to the stored permission bits like Go", async () => {
    // Both adapters keep only the 0o7777 mode bits (S_IFMT bits are carried
    // by the kind), so a legacy mode with type bits still adapts.
    const tree = new Pft2LegacyBaseTree([
      { path: "a", kind: "file", mode: 0o100644, size: 0 },
    ]);
    const root = await tree.getInode(1n);
    const entry = await tree.lookup(root.ref, "a");
    const file = await tree.getInode(entry.ino);
    expect(file.inode.mode).toBe(0o644);
  });

  it("issues handles that fail closed against real PFT2 readers", async () => {
    const tree = new Pft2LegacyBaseTree(legacyManifestEntries());
    const root = await tree.getInode(1n);
    // Legacy handles have size 0, below the minimum node size, so they can
    // never pass the pre-fetch bounds check of a real reader.
    expect(() => checkNodeRefBounds("probe", root.ref)).toThrow(Pft2InvalidNodeError);
  });
});
