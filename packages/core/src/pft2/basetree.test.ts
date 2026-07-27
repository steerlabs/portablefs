import { describe, expect, it } from "vitest";
import {
  Pft2MemoryStore,
  Pft2TreeReader,
  verifyCellBytes,
  verifyPft2EdgeSummary,
  type Pft2Fetcher,
} from "./basetree.js";
import { Pft2CellPacker, buildFileExtents, buildInodeIndexTree } from "./builder.js";
import { encodePft2Node } from "./codec.js";
import {
  PFT2_CELL_BYTES,
  PFT2_MAX_NODE_BYTES,
  PFT2_MIN_NODE_BYTES,
  PFT2_PAGE_BYTES,
  Pft2BoundExceededError,
  Pft2CorruptError,
  Pft2FileKind,
  Pft2InvalidNodeError,
  Pft2NodeKind,
  Pft2NotFoundError,
  pft2RefOf,
  type Pft2Node,
  type Pft2Ref,
} from "./types.js";
import { buildGoldenFilesystem, labelDigest } from "./golden-shared.js";

class CountingFetcher implements Pft2Fetcher {
  calls = 0;
  delayMs = 0;

  constructor(private readonly store: Pft2MemoryStore) {}

  async fetch(ref: Pft2Ref): Promise<Uint8Array> {
    this.calls += 1;
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    return this.store.fetch(ref);
  }
}

function goldenReader(config: {
  cacheBytes?: number;
  maxNodes?: number;
  maxBytes?: bigint;
} = {}): { reader: Pft2TreeReader; fetcher: CountingFetcher; store: Pft2MemoryStore; root: Pft2Ref } {
  const store = new Pft2MemoryStore();
  const root = buildGoldenFilesystem(store);
  const fetcher = new CountingFetcher(store);
  const reader = new Pft2TreeReader(
    {
      fetcher,
      ...(config.cacheBytes !== undefined ? { cacheBytes: config.cacheBytes } : {}),
      bounds: {
        ...(config.maxNodes !== undefined ? { maxNodes: config.maxNodes } : {}),
        ...(config.maxBytes !== undefined ? { maxBytes: config.maxBytes } : {}),
      },
    },
    root
  );
  return { reader, fetcher, store, root };
}

function putNode(store: Pft2MemoryStore, node: Pft2Node): Pft2Ref {
  const encoded = encodePft2Node(node);
  const ref = pft2RefOf(encoded);
  store.putNode(ref, encoded);
  return ref;
}

describe("Pft2TreeReader", () => {
  it("walks the golden filesystem lazily", async () => {
    const { reader } = goldenReader();
    const root = await reader.getInode(1n);
    expect(root.inode.kind).toBe(Pft2FileKind.Directory);

    const entryA = await reader.lookup(root.ref, "a");
    expect(entryA.ino).toBe(2n);
    expect(entryA.kind).toBe(Pft2FileKind.Directory);
    await expect(reader.lookup(root.ref, "missing")).rejects.toThrow(Pft2NotFoundError);

    const dirA = await reader.getInode(2n);
    const hello = await reader.lookup(dirA.ref, "hello.bin");
    expect(hello.ino).toBe(4n);

    const link = await reader.getInode(5n);
    expect(link.inode.symlinkTarget).toBe("a/hello.bin");
    await expect(reader.lookup(link.ref, "x")).rejects.toThrow(Pft2CorruptError);
    await expect(reader.getInode(999n)).rejects.toThrow(Pft2NotFoundError);
  });

  it("pages readdir deterministically", async () => {
    const { reader } = goldenReader();
    const root = await reader.getInode(1n);
    const names: string[] = [];
    let cursor = "";
    for (;;) {
      const { entries, next } = await reader.readDir(root.ref, cursor, 2);
      names.push(...entries.map((entry) => entry.name));
      if (next === "") {
        break;
      }
      cursor = next;
    }
    expect(names).toEqual(["a", "link", "small"]);
    await expect(reader.readDir(root.ref, "", 0)).rejects.toThrow(Pft2InvalidNodeError);
  });

  it("returns extents overlapping the window only, skipping holes", async () => {
    const { reader } = goldenReader();
    const hello = await reader.getInode(4n);

    const all = await reader.readExtents(hello.ref, 0n, 200000n);
    expect(all).toHaveLength(12);
    for (const extent of all) {
      expect(extent.cell).toBeDefined();
      expect(extent.legacy).toBeUndefined();
      expect(extent.length).toBe(BigInt(PFT2_CELL_BYTES));
    }
    expect(all[4]!.fileOffset).toBe(BigInt(8 * PFT2_CELL_BYTES));

    const holeWindow = await reader.readExtents(
      hello.ref,
      BigInt(4 * PFT2_CELL_BYTES),
      BigInt(4 * PFT2_CELL_BYTES)
    );
    expect(holeWindow).toHaveLength(0);

    expect(await reader.readExtents(hello.ref, 0n, 0n)).toHaveLength(0);
    expect(await reader.readExtents(hello.ref, 1n << 40n, 10n)).toHaveLength(0);

    const small = await reader.getInode(6n);
    const smallExtents = await reader.readExtents(small.ref, 0n, 65536n);
    expect(smallExtents).toHaveLength(1);
    expect(smallExtents[0]!.length).toBe(3n);

    const empty = await reader.getInode(3n);
    expect(await reader.readExtents(empty.ref, 0n, 100n)).toHaveLength(0);

    const rootDir = await reader.getInode(1n);
    await expect(reader.readExtents(rootDir.ref, 0n, 10n)).rejects.toThrow(Pft2CorruptError);
  });

  it("rejects oversized/undersized advertised refs before fetching", async () => {
    const { reader, fetcher } = goldenReader();
    await reader.getInode(1n);
    const callsBefore = fetcher.calls;
    const oversized: Pft2Ref = { digest: labelDigest("big"), size: BigInt(PFT2_MAX_NODE_BYTES + 1) };
    await expect(reader.lookup(oversized, "x")).rejects.toThrow(Pft2InvalidNodeError);
    const undersized: Pft2Ref = { digest: labelDigest("small"), size: BigInt(PFT2_MIN_NODE_BYTES - 1) };
    await expect(reader.lookup(undersized, "x")).rejects.toThrow(Pft2InvalidNodeError);
    expect(fetcher.calls).toBe(callsBefore);
  });

  it("fails closed on corrupted bytes and does not cache the failure", async () => {
    const store = new Pft2MemoryStore();
    const root = buildGoldenFilesystem(store);
    const fetcher = new CountingFetcher(store);
    const reader = new Pft2TreeReader({ fetcher }, root);
    store.corruptObject(root, 10);
    await expect(reader.getInode(1n)).rejects.toThrow(Pft2CorruptError);
    store.corruptObject(root, 10); // xor restores the original byte
    const view = await reader.getInode(1n);
    expect(view.inode.ino).toBe(1n);
  });

  it("fails closed on a size-lying root reference", async () => {
    const store = new Pft2MemoryStore();
    const root = buildGoldenFilesystem(store);
    const lied: Pft2Ref = { digest: root.digest, size: root.size + 1n };
    const fetcher: Pft2Fetcher = {
      // A fetcher that returns the true bytes regardless of advertised size.
      fetch: () => store.fetch(root),
    };
    const reader = new Pft2TreeReader({ fetcher }, lied);
    await expect(reader.getInode(1n)).rejects.toThrow(Pft2CorruptError);
  });

  it("fails closed when an edge resolves to the wrong node kind", async () => {
    const store = new Pft2MemoryStore();
    const inodeRef = putNode(store, {
      kind: Pft2NodeKind.Inode,
      inode: {
        ino: 1n,
        kind: Pft2FileKind.Directory,
        mode: 0,
        uid: 0,
        gid: 0,
        nlink: 1n,
        size: 0n,
        mtimeMs: 0n,
        ctimeMs: 0n,
        atimeMs: 0n,
        symlinkTarget: "",
      },
    });
    // ROOT whose inode index points at an INODE object.
    const rootRef = putNode(store, {
      kind: Pft2NodeKind.Root,
      root: {
        rootInode: inodeRef,
        inodeIndex: inodeRef,
        maxInoSeen: 1n,
        inodeCount: 1n,
        direntCount: 0n,
        logicalBytes: 0n,
        features: 0n,
      },
    });
    const reader = new Pft2TreeReader({ fetcher: new CountingFetcher(store) }, rootRef);
    await expect(reader.getInode(1n)).rejects.toThrow(Pft2CorruptError);
  });

  it("fails closed when an inode object advertises the wrong ino", async () => {
    const store = new Pft2MemoryStore();
    const wrongInode = putNode(store, {
      kind: Pft2NodeKind.Inode,
      inode: {
        ino: 9n,
        kind: Pft2FileKind.Directory,
        mode: 0,
        uid: 0,
        gid: 0,
        nlink: 1n,
        size: 0n,
        mtimeMs: 0n,
        ctimeMs: 0n,
        atimeMs: 0n,
        symlinkTarget: "",
      },
    });
    const index = buildInodeIndexTree([{ ino: 1n, inode: wrongInode }], store);
    const rootRef = putNode(store, {
      kind: Pft2NodeKind.Root,
      root: {
        rootInode: wrongInode,
        inodeIndex: index.root!,
        maxInoSeen: 1n,
        inodeCount: 1n,
        direntCount: 0n,
        logicalBytes: 0n,
        features: 0n,
      },
    });
    const reader = new Pft2TreeReader({ fetcher: new CountingFetcher(store) }, rootRef);
    await expect(reader.getInode(1n)).rejects.toThrow(Pft2CorruptError);
  });

  it("enforces node and byte budgets", async () => {
    const nodeBudget = goldenReader({ maxNodes: 1 });
    await expect(nodeBudget.reader.getInode(4n)).rejects.toThrow(Pft2BoundExceededError);
    const byteBudget = goldenReader({ maxBytes: 64n });
    await expect(byteBudget.reader.getInode(4n)).rejects.toThrow(Pft2BoundExceededError);
  });

  it("serves repeats from the immutable cache and coalesces concurrent fetches", async () => {
    const { reader, fetcher } = goldenReader();
    await reader.getInode(4n);
    const cold = fetcher.calls;
    expect(cold).toBeGreaterThan(0);
    await reader.getInode(4n);
    expect(fetcher.calls).toBe(cold);

    const cacheless = goldenReader({ cacheBytes: -1 });
    await cacheless.reader.getInode(4n);
    const first = cacheless.fetcher.calls;
    await cacheless.reader.getInode(4n);
    expect(cacheless.fetcher.calls).toBeGreaterThan(first);

    const coalesced = goldenReader();
    coalesced.fetcher.delayMs = 5;
    const results = await Promise.all(
      Array.from({ length: 32 }, () => coalesced.reader.getInode(4n))
    );
    for (const view of results) {
      expect(view.inode.ino).toBe(4n);
    }
    // Root, one index leaf, one inode: three objects, one fetch each.
    expect(coalesced.fetcher.calls).toBe(3);
  });

  it("verifies cell bytes including the terminal zero suffix", async () => {
    const store = new Pft2MemoryStore();
    const content = new Uint8Array(PFT2_CELL_BYTES);
    content.set([104, 105, 10]); // "hi\n"
    const packer = new Pft2CellPacker();
    packer.add(content);
    const cells = packer.finish(store);
    const cell = cells[0]!;
    const packBytes = await store.fetch(cell.object);
    const logical = verifyCellBytes(cell, packBytes, 3n);
    expect([...logical.subarray(0, 3)]).toEqual([104, 105, 10]);

    const dirty = new Uint8Array(packBytes);
    dirty[100] = 0xaa;
    expect(() => verifyCellBytes(cell, dirty, 3n)).toThrow(Pft2CorruptError);
    expect(() => verifyCellBytes(cell, packBytes.subarray(1), 3n)).toThrow(Pft2CorruptError);
    expect(() => verifyCellBytes(cell, packBytes, BigInt(PFT2_CELL_BYTES + 1))).toThrow(
      Pft2InvalidNodeError
    );
  });

  it("builds no objects for all-zero content and reuses deterministic packs", () => {
    const emptyStore = new Pft2MemoryStore();
    expect(buildFileExtents(new Uint8Array(3 * 65536), emptyStore, emptyStore)).toBeUndefined();
    expect(emptyStore.size).toBe(0);
  });

  it("charges the root visit on every operation (deterministic budgets)", async () => {
    // getInode(1) visits exactly root + index leaf + inode = 3 nodes; a
    // budget of 3 must succeed on every repeat (I/O amortized by the
    // cache), and a budget of 2 must fail on every repeat, independent of
    // cache history.
    const exact = goldenReader({ maxNodes: 3 });
    for (let i = 0; i < 3; i += 1) {
      await expect(exact.reader.getInode(1n)).resolves.toBeDefined();
    }
    const warmCalls = exact.fetcher.calls;
    await exact.reader.getInode(1n);
    expect(exact.fetcher.calls).toBe(warmCalls);

    const short = goldenReader({ maxNodes: 2 });
    for (let i = 0; i < 3; i += 1) {
      await expect(short.reader.getInode(1n)).rejects.toThrow(Pft2BoundExceededError);
    }
  });
});

describe("Pft2TreeReader edge verification", () => {
  function leafOfNames(store: Pft2MemoryStore, ...names: string[]): Pft2Ref {
    return putNode(store, {
      kind: Pft2NodeKind.DirectoryLeaf,
      directoryLeaf: {
        entries: names.map((name, i) => ({ name, ino: BigInt(10 + i), kind: Pft2FileKind.Regular })),
      },
    });
  }

  function singleDirFixture(
    store: Pft2MemoryStore,
    dirRoot: Pft2Ref,
    direntCount: bigint
  ): { root: Pft2Ref; inode: Pft2Ref } {
    const inodeRef = putNode(store, {
      kind: Pft2NodeKind.Inode,
      inode: {
        ino: 1n,
        kind: Pft2FileKind.Directory,
        mode: 0o755,
        uid: 0,
        gid: 0,
        nlink: 1n,
        size: 0n,
        mtimeMs: 0n,
        ctimeMs: 0n,
        atimeMs: 0n,
        directoryRoot: dirRoot,
        symlinkTarget: "",
      },
    });
    const index = buildInodeIndexTree([{ ino: 1n, inode: inodeRef }], store);
    const root = putNode(store, {
      kind: Pft2NodeKind.Root,
      root: {
        rootInode: inodeRef,
        inodeIndex: index.root!,
        maxInoSeen: 1n,
        inodeCount: 1n,
        direntCount,
        logicalBytes: 0n,
        features: 0n,
      },
    });
    return { root, inode: inodeRef };
  }

  function readerOver(store: Pft2MemoryStore, root: Pft2Ref): Pft2TreeReader {
    return new Pft2TreeReader(
      { fetcher: new CountingFetcher(store), bounds: { maxNodes: 1 << 16, maxBytes: 1n << 40n } },
      root
    );
  }

  it("fails closed on a lying directory child count and range", async () => {
    const store = new Pft2MemoryStore();
    const left = leafOfNames(store, "aa", "ab");
    const right = leafOfNames(store, "mm");
    const dirRoot = putNode(store, {
      kind: Pft2NodeKind.DirectoryIndex,
      directoryIndex: {
        children: [
          { firstName: "aa", lastName: "ab", child: left, entryCount: 3n }, // actual 2
          { firstName: "mm", lastName: "mm", child: right, entryCount: 1n },
        ],
      },
    });
    const { root, inode } = singleDirFixture(store, dirRoot, 4n);
    const reader = readerOver(store, root);
    await expect(reader.lookup(inode, "aa")).rejects.toThrow(Pft2CorruptError);
    await expect(reader.readDir(inode, "", 1024)).rejects.toThrow(Pft2CorruptError);

    const hidden = new Pft2MemoryStore();
    const wide = leafOfNames(hidden, "aa", "ab", "zz"); // "zz" hidden by the advertisement
    const other = leafOfNames(hidden, "mm");
    const lyingRoot = putNode(hidden, {
      kind: Pft2NodeKind.DirectoryIndex,
      directoryIndex: {
        children: [
          { firstName: "aa", lastName: "ab", child: wide, entryCount: 3n },
          { firstName: "mm", lastName: "mm", child: other, entryCount: 1n },
        ],
      },
    });
    const fixture = singleDirFixture(hidden, lyingRoot, 4n);
    const hiddenReader = readerOver(hidden, fixture.root);
    await expect(hiddenReader.lookup(fixture.inode, "aa")).rejects.toThrow(Pft2CorruptError);
  });

  it("fails closed on a cursor-looping range lie during readDir paging", async () => {
    const store = new Pft2MemoryStore();
    const left = leafOfNames(store, "aa", "ab");
    const right = leafOfNames(store, "zz");
    const dirRoot = putNode(store, {
      kind: Pft2NodeKind.DirectoryIndex,
      directoryIndex: {
        children: [
          { firstName: "aa", lastName: "yy", child: left, entryCount: 2n }, // actual last "ab"
          { firstName: "zz", lastName: "zz", child: right, entryCount: 1n },
        ],
      },
    });
    const { root, inode } = singleDirFixture(store, dirRoot, 3n);
    const reader = readerOver(store, root);
    await expect(reader.readDir(inode, "", 2)).rejects.toThrow(Pft2CorruptError);
  });

  it("fails closed on hidden extent pages instead of reading holes", async () => {
    const store = new Pft2MemoryStore();
    const cell = new Uint8Array(PFT2_CELL_BYTES);
    cell[0] = 1;
    const packer = new Pft2CellPacker();
    packer.add(cell);
    const cells = packer.finish(store);
    const pageCells = Array.from({ length: 16 }, () => null) as (typeof cells)[0][] | null[];
    pageCells[0] = cells[0]!;
    const page = putNode(store, { kind: Pft2NodeKind.DataPage, dataPage: { cells: pageCells } });
    const pageBytes = BigInt(PFT2_PAGE_BYTES);
    const left = putNode(store, {
      kind: Pft2NodeKind.ExtentLeaf,
      extentLeaf: {
        entries: [
          { pageOffset: 0n, page },
          { pageOffset: pageBytes, page }, // hidden by the parent advertisement
        ],
      },
    });
    const right = putNode(store, {
      kind: Pft2NodeKind.ExtentLeaf,
      extentLeaf: { entries: [{ pageOffset: 4n * pageBytes, page }] },
    });
    const extentRoot = putNode(store, {
      kind: Pft2NodeKind.ExtentIndex,
      extentIndex: {
        children: [
          { firstPage: 0n, lastPage: 0n, child: left, entryCount: 1n },
          { firstPage: 4n * pageBytes, lastPage: 4n * pageBytes, child: right, entryCount: 1n },
        ],
      },
    });
    const fileRef = putNode(store, {
      kind: Pft2NodeKind.Inode,
      inode: {
        ino: 2n,
        kind: Pft2FileKind.Regular,
        mode: 0o644,
        uid: 0,
        gid: 0,
        nlink: 1n,
        size: 5n * pageBytes,
        mtimeMs: 0n,
        ctimeMs: 0n,
        atimeMs: 0n,
        extentRoot,
        symlinkTarget: "",
      },
    });
    const rootInode = putNode(store, {
      kind: Pft2NodeKind.Inode,
      inode: {
        ino: 1n,
        kind: Pft2FileKind.Directory,
        mode: 0o755,
        uid: 0,
        gid: 0,
        nlink: 1n,
        size: 0n,
        mtimeMs: 0n,
        ctimeMs: 0n,
        atimeMs: 0n,
        symlinkTarget: "",
      },
    });
    const index = buildInodeIndexTree(
      [
        { ino: 1n, inode: rootInode },
        { ino: 2n, inode: fileRef },
      ],
      store
    );
    const root = putNode(store, {
      kind: Pft2NodeKind.Root,
      root: {
        rootInode,
        inodeIndex: index.root!,
        maxInoSeen: 2n,
        inodeCount: 2n,
        direntCount: 0n,
        logicalBytes: 5n * pageBytes,
        features: 0n,
      },
    });
    const reader = readerOver(store, root);
    await expect(reader.readExtents(fileRef, 0n, 5n * pageBytes)).rejects.toThrow(Pft2CorruptError);
  });

  it("pins the inode index root against the ROOT facts", async () => {
    const makeInode = (store: Pft2MemoryStore, ino: bigint): Pft2Ref =>
      putNode(store, {
        kind: Pft2NodeKind.Inode,
        inode: {
          ino,
          kind: ino === 1n ? Pft2FileKind.Directory : Pft2FileKind.Regular,
          mode: 0,
          uid: 0,
          gid: 0,
          nlink: 1n,
          size: 0n,
          mtimeMs: 0n,
          ctimeMs: 0n,
          atimeMs: 0n,
          symlinkTarget: "",
        },
      });

    // Count mismatch.
    const countStore = new Pft2MemoryStore();
    const countIndex = buildInodeIndexTree(
      [
        { ino: 1n, inode: makeInode(countStore, 1n) },
        { ino: 2n, inode: makeInode(countStore, 2n) },
      ],
      countStore
    );
    const countRoot = putNode(countStore, {
      kind: Pft2NodeKind.Root,
      root: {
        rootInode: makeInode(countStore, 1n),
        inodeIndex: countIndex.root!,
        maxInoSeen: 2n,
        inodeCount: 1n, // actual 2
        direntCount: 0n,
        logicalBytes: 0n,
        features: 0n,
      },
    });
    await expect(readerOver(countStore, countRoot).getInode(1n)).rejects.toThrow(Pft2CorruptError);

    // Present ino above the advertised high-water.
    const highStore = new Pft2MemoryStore();
    const highIndex = buildInodeIndexTree(
      [
        { ino: 1n, inode: makeInode(highStore, 1n) },
        { ino: 9n, inode: makeInode(highStore, 9n) },
      ],
      highStore
    );
    const highRoot = putNode(highStore, {
      kind: Pft2NodeKind.Root,
      root: {
        rootInode: makeInode(highStore, 1n),
        inodeIndex: highIndex.root!,
        maxInoSeen: 5n,
        inodeCount: 2n,
        direntCount: 0n,
        logicalBytes: 0n,
        features: 0n,
      },
    });
    await expect(readerOver(highStore, highRoot).getInode(1n)).rejects.toThrow(Pft2CorruptError);

    // Index missing the root inode.
    const missingStore = new Pft2MemoryStore();
    const missingIndex = buildInodeIndexTree(
      [
        { ino: 2n, inode: makeInode(missingStore, 2n) },
        { ino: 3n, inode: makeInode(missingStore, 3n) },
      ],
      missingStore
    );
    const missingRoot = putNode(missingStore, {
      kind: Pft2NodeKind.Root,
      root: {
        rootInode: makeInode(missingStore, 1n),
        inodeIndex: missingIndex.root!,
        maxInoSeen: 3n,
        inodeCount: 2n,
        direntCount: 0n,
        logicalBytes: 0n,
        features: 0n,
      },
    });
    await expect(readerOver(missingStore, missingRoot).getInode(2n)).rejects.toThrow(Pft2CorruptError);
  });

  it("verifies control summaries through the shared verifier", () => {
    const leaf: Pft2Node = {
      kind: Pft2NodeKind.ControlLeaf,
      controlLeaf: {
        entries: [
          { key: new Uint8Array([0x61]), kind: 1n, value: new Uint8Array() },
          { key: new Uint8Array([0x62]), kind: 1n, value: new Uint8Array([0x76]) },
        ],
      },
    };
    const ref = { digest: labelDigest("control"), size: 100n };
    const good = { first: new Uint8Array([0x61]), last: new Uint8Array([0x62]), count: 2n };
    expect(() => verifyPft2EdgeSummary("control child", ref, leaf, good)).not.toThrow();
    expect(() =>
      verifyPft2EdgeSummary("control child", ref, leaf, { ...good, count: 3n })
    ).toThrow(Pft2CorruptError);
    expect(() =>
      verifyPft2EdgeSummary("control child", ref, leaf, { ...good, last: new Uint8Array([0x63]) })
    ).toThrow(Pft2CorruptError);
  });
});
