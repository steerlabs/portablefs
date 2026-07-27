/**
 * Deterministic PFT2 builders — the TypeScript mirror of
 * vcs/internal/pft2/builder.go, sharing the FROZEN CONSTRUCTION RULE:
 * elements pack left to right; a node closes when it already holds the
 * level's maximum element count or when appending the next element would push
 * its element region (the sum of every element's length-delimited encoded
 * size at field 1) beyond PFT2_TARGET_NODE_BYTES. On index levels, if the
 * final run holds fewer than PFT2_MIN_INDEX_CHILDREN children, children move
 * from the end of the previous run. The same ordered element sequence always
 * produces the same tree.
 *
 * Builders never touch an object store on a mutation path: they run in
 * HistoryCut/materializer context and callers decide where bytes go.
 */
import { createHash } from "node:crypto";
import {
  encodeControlEntryBody,
  encodeControlIndexChildBody,
  encodeDirEntryBody,
  encodeDirectoryIndexChildBody,
  encodeExtentEntryBody,
  encodeExtentIndexChildBody,
  encodeInodeIndexChildBody,
  encodeInodeIndexEntryBody,
  encodePft2Node,
} from "./codec.js";
import {
  PFT2_CELL_BYTES,
  PFT2_CELLS_PER_PAGE,
  PFT2_MAX_CONTROL_ENTRY_KIND,
  PFT2_MAX_INDEX_CHILDREN,
  PFT2_MAX_LEAF_ENTRIES,
  PFT2_MAX_LOGICAL_FILE_BYTES,
  PFT2_MAX_PACK_BYTES,
  PFT2_MAX_TREE_DEPTH,
  PFT2_MIN_INDEX_CHILDREN,
  PFT2_PAGE_BYTES,
  PFT2_TARGET_NODE_BYTES,
  Pft2NodeKind,
  checkPackRefBounds,
  compareNames,
  invalidNode,
  pft2RefOf,
  type Pft2CellRef,
  type Pft2ControlEntry,
  type Pft2ControlKindCount,
  type Pft2DataPage,
  type Pft2DirEntry,
  type Pft2ExtentEntry,
  type Pft2InodeIndexEntry,
  type Pft2Node,
  type Pft2Ref,
} from "./types.js";
import { compareBytes, sizeTagged } from "./wire.js";

/** Persists one encoded metadata node (reference computed by the builder). */
export interface Pft2NodeSink {
  putNode(ref: Pft2Ref, encoded: Uint8Array): void;
}

/** Persists one packed immutable data object. */
export interface Pft2PackSink {
  putPack(ref: Pft2Ref, data: Uint8Array): void;
}

function shouldClose(currentBytes: number, elemBytes: number, count: number, maxCount: number): boolean {
  return count > 0 && (count >= maxCount || currentBytes + elemBytes > PFT2_TARGET_NODE_BYTES);
}

function chunkRun(elementCount: number, maxCount: number, elemBytes: (i: number) => number): [number, number][] {
  const runs: [number, number][] = [];
  let start = 0;
  let currentBytes = 0;
  for (let i = 0; i < elementCount; i += 1) {
    const size = elemBytes(i);
    if (shouldClose(currentBytes, size, i - start, maxCount)) {
      runs.push([start, i]);
      start = i;
      currentBytes = 0;
    }
    currentBytes += size;
  }
  if (elementCount > start) {
    runs.push([start, elementCount]);
  }
  return runs;
}

function chunkLeaves(elementCount: number, elemBytes: (i: number) => number): [number, number][] {
  return chunkRun(elementCount, PFT2_MAX_LEAF_ENTRIES, elemBytes);
}

function chunkIndex(elementCount: number, elemBytes: (i: number) => number): [number, number][] {
  const runs = chunkRun(elementCount, PFT2_MAX_INDEX_CHILDREN, elemBytes);
  if (runs.length >= 2) {
    const last = runs[runs.length - 1]!;
    if (last[1] - last[0] < PFT2_MIN_INDEX_CHILDREN) {
      const shift = PFT2_MIN_INDEX_CHILDREN - (last[1] - last[0]);
      runs[runs.length - 2]![1] -= shift;
      last[0] -= shift;
    }
  }
  return runs;
}

interface LevelChild<C> {
  summaryBytes: number;
  child: C;
}

function putNode(node: Pft2Node, sink: Pft2NodeSink): Pft2Ref {
  const encoded = encodePft2Node(node);
  const ref = pft2RefOf(encoded);
  sink.putNode(ref, encoded);
  return ref;
}

/**
 * Stacks index levels over a leaf level until one root remains, under the
 * frozen rule.
 */
function buildLevels<C>(
  leaves: LevelChild<C>[],
  makeIndexNode: (children: C[]) => Pft2Node,
  summarize: (children: C[], ref: Pft2Ref) => LevelChild<C>,
  sink: Pft2NodeSink,
  rootRefOfLeaf: (leaf: LevelChild<C>) => Pft2Ref
): Pft2Ref {
  let level = leaves;
  let depth = 1;
  while (level.length > 1) {
    depth += 1;
    if (depth > PFT2_MAX_TREE_DEPTH) {
      throw invalidNode(`tree exceeds max depth ${PFT2_MAX_TREE_DEPTH}`);
    }
    const runs = chunkIndex(level.length, (i) => sizeTagged(1, level[i]!.summaryBytes));
    const next: LevelChild<C>[] = [];
    for (const [start, end] of runs) {
      const children = level.slice(start, end).map((entry) => entry.child);
      const node = makeIndexNode(children);
      const ref = putNode(node, sink);
      next.push(summarize(children, ref));
    }
    level = next;
  }
  return rootRefOfLeaf(level[0]!);
}

interface BuiltTree {
  root: Pft2Ref | undefined;
  entryCount: bigint;
}

/**
 * Deterministically builds a directory B+tree from entries sorted strictly
 * ascending by canonical name bytes.
 */
export function buildDirectoryTree(entries: Pft2DirEntry[], sink: Pft2NodeSink): BuiltTree {
  if (entries.length === 0) {
    return { root: undefined, entryCount: 0n };
  }
  entries.forEach((entry, i) => {
    if (i > 0 && compareNames(entries[i - 1]!.name, entry.name) >= 0) {
      throw invalidNode(`directory build: entry ${i} name not strictly above previous`);
    }
  });
  const bodies = entries.map((entry) => encodeDirEntryBody(entry));
  const runs = chunkLeaves(entries.length, (i) => sizeTagged(1, bodies[i]!.length));

  interface Child {
    firstName: string;
    lastName: string;
    child: Pft2Ref;
    entryCount: bigint;
  }
  const leaves: LevelChild<Child>[] = runs.map(([start, end]) => {
    const slice = entries.slice(start, end);
    const ref = putNode({ kind: Pft2NodeKind.DirectoryLeaf, directoryLeaf: { entries: slice } }, sink);
    const child: Child = {
      firstName: slice[0]!.name,
      lastName: slice[slice.length - 1]!.name,
      child: ref,
      entryCount: BigInt(slice.length),
    };
    return { summaryBytes: encodeDirectoryIndexChildBody(child).length, child };
  });
  const root = buildLevels(
    leaves,
    (children) => ({ kind: Pft2NodeKind.DirectoryIndex, directoryIndex: { children } }),
    (children, ref) => {
      const child: Child = {
        firstName: children[0]!.firstName,
        lastName: children[children.length - 1]!.lastName,
        child: ref,
        entryCount: children.reduce((total, c) => total + c.entryCount, 0n),
      };
      return { summaryBytes: encodeDirectoryIndexChildBody(child).length, child };
    },
    sink,
    (leaf) => leaf.child.child
  );
  return { root, entryCount: BigInt(entries.length) };
}

/**
 * Deterministically builds an extent B+tree from entries sorted strictly
 * ascending by page offset.
 */
export function buildExtentTree(entries: Pft2ExtentEntry[], sink: Pft2NodeSink): BuiltTree {
  if (entries.length === 0) {
    return { root: undefined, entryCount: 0n };
  }
  entries.forEach((entry, i) => {
    if (i > 0 && entries[i - 1]!.pageOffset >= entry.pageOffset) {
      throw invalidNode(`extent build: entry ${i} offset not strictly above previous`);
    }
  });
  const bodies = entries.map((entry) => encodeExtentEntryBody(entry));
  const runs = chunkLeaves(entries.length, (i) => sizeTagged(1, bodies[i]!.length));

  interface Child {
    firstPage: bigint;
    lastPage: bigint;
    child: Pft2Ref;
    entryCount: bigint;
  }
  const leaves: LevelChild<Child>[] = runs.map(([start, end]) => {
    const slice = entries.slice(start, end);
    const ref = putNode({ kind: Pft2NodeKind.ExtentLeaf, extentLeaf: { entries: slice } }, sink);
    const child: Child = {
      firstPage: slice[0]!.pageOffset,
      lastPage: slice[slice.length - 1]!.pageOffset,
      child: ref,
      entryCount: BigInt(slice.length),
    };
    return { summaryBytes: encodeExtentIndexChildBody(child).length, child };
  });
  const root = buildLevels(
    leaves,
    (children) => ({ kind: Pft2NodeKind.ExtentIndex, extentIndex: { children } }),
    (children, ref) => {
      const child: Child = {
        firstPage: children[0]!.firstPage,
        lastPage: children[children.length - 1]!.lastPage,
        child: ref,
        entryCount: children.reduce((total, c) => total + c.entryCount, 0n),
      };
      return { summaryBytes: encodeExtentIndexChildBody(child).length, child };
    },
    sink,
    (leaf) => leaf.child.child
  );
  return { root, entryCount: BigInt(entries.length) };
}

/**
 * Deterministically builds an inode-index B+tree from entries sorted
 * strictly ascending by ino.
 */
export function buildInodeIndexTree(entries: Pft2InodeIndexEntry[], sink: Pft2NodeSink): BuiltTree {
  if (entries.length === 0) {
    return { root: undefined, entryCount: 0n };
  }
  entries.forEach((entry, i) => {
    if (i > 0 && entries[i - 1]!.ino >= entry.ino) {
      throw invalidNode(`inode index build: entry ${i} ino not strictly above previous`);
    }
  });
  const bodies = entries.map((entry) => encodeInodeIndexEntryBody(entry));
  const runs = chunkLeaves(entries.length, (i) => sizeTagged(1, bodies[i]!.length));

  interface Child {
    firstIno: bigint;
    lastIno: bigint;
    child: Pft2Ref;
    entryCount: bigint;
  }
  const leaves: LevelChild<Child>[] = runs.map(([start, end]) => {
    const slice = entries.slice(start, end);
    const ref = putNode({ kind: Pft2NodeKind.InodeIndexLeaf, inodeIndexLeaf: { entries: slice } }, sink);
    const child: Child = {
      firstIno: slice[0]!.ino,
      lastIno: slice[slice.length - 1]!.ino,
      child: ref,
      entryCount: BigInt(slice.length),
    };
    return { summaryBytes: encodeInodeIndexChildBody(child).length, child };
  });
  const root = buildLevels(
    leaves,
    (children) => ({ kind: Pft2NodeKind.InodeIndexIndex, inodeIndexIndex: { children } }),
    (children, ref) => {
      const child: Child = {
        firstIno: children[0]!.firstIno,
        lastIno: children[children.length - 1]!.lastIno,
        child: ref,
        entryCount: children.reduce((total, c) => total + c.entryCount, 0n),
      };
      return { summaryBytes: encodeInodeIndexChildBody(child).length, child };
    },
    sink,
    (leaf) => leaf.child.child
  );
  return { root, entryCount: BigInt(entries.length) };
}

export interface BuiltControlTree extends BuiltTree {
  counts: Pft2ControlKindCount[];
}

/**
 * Deterministically builds a control-map B+tree from entries sorted strictly
 * ascending by raw key bytes, plus the ascending per-kind counts.
 */
export function buildControlTree(entries: Pft2ControlEntry[], sink: Pft2NodeSink): BuiltControlTree {
  if (entries.length === 0) {
    return { root: undefined, entryCount: 0n, counts: [] };
  }
  entries.forEach((entry, i) => {
    if (i > 0 && compareBytes(entries[i - 1]!.key, entry.key) >= 0) {
      throw invalidNode(`control build: entry ${i} key not strictly above previous`);
    }
  });
  const bodies = entries.map((entry) => encodeControlEntryBody(entry));
  const runs = chunkLeaves(entries.length, (i) => sizeTagged(1, bodies[i]!.length));

  interface Child {
    firstKey: Uint8Array;
    lastKey: Uint8Array;
    child: Pft2Ref;
    entryCount: bigint;
  }
  const leaves: LevelChild<Child>[] = runs.map(([start, end]) => {
    const slice = entries.slice(start, end);
    const ref = putNode({ kind: Pft2NodeKind.ControlLeaf, controlLeaf: { entries: slice } }, sink);
    const child: Child = {
      firstKey: slice[0]!.key,
      lastKey: slice[slice.length - 1]!.key,
      child: ref,
      entryCount: BigInt(slice.length),
    };
    return { summaryBytes: encodeControlIndexChildBody(child).length, child };
  });
  const root = buildLevels(
    leaves,
    (children) => ({ kind: Pft2NodeKind.ControlIndex, controlIndex: { children } }),
    (children, ref) => {
      const child: Child = {
        firstKey: children[0]!.firstKey,
        lastKey: children[children.length - 1]!.lastKey,
        child: ref,
        entryCount: children.reduce((total, c) => total + c.entryCount, 0n),
      };
      return { summaryBytes: encodeControlIndexChildBody(child).length, child };
    },
    sink,
    (leaf) => leaf.child.child
  );

  const byKind = new Map<bigint, bigint>();
  for (const entry of entries) {
    byKind.set(entry.kind, (byKind.get(entry.kind) ?? 0n) + 1n);
  }
  const counts: Pft2ControlKindCount[] = [];
  for (let kind = 1n; kind <= PFT2_MAX_CONTROL_ENTRY_KIND; kind += 1n) {
    const count = byKind.get(kind);
    if (count) {
      counts.push({ kind, count });
    }
  }
  return { root, entryCount: BigInt(entries.length), counts };
}

/** True when every byte is zero (the cell is canonically a hole). */
export function isZeroCell(cell: Uint8Array): boolean {
  for (const byte of cell) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
}

/**
 * Packs changed nonzero cells into immutable data objects under the frozen
 * deterministic policy: cells append in ascending (inode, pageOffset,
 * cellIndex) order (caller-owned ordering); every pack except the last closes
 * at exactly PFT2_MAX_PACK_BYTES; the terminal pack may be underfilled in
 * exact PFT2_CELL_BYTES increments.
 */
export class Pft2CellPacker {
  private packs: Uint8Array[][] = [];
  private current: Uint8Array[] = [];
  private currentBytes = 0;
  private perPack: number[] = [];
  private perOffset: bigint[] = [];
  private digests: Uint8Array[] = [];
  private finished = false;

  /** Appends the canonical CellBytes logical bytes of one changed cell. */
  add(cell: Uint8Array): number {
    if (this.finished) {
      throw invalidNode("cell packer: add after finish");
    }
    if (cell.length !== PFT2_CELL_BYTES) {
      throw invalidNode(`cell packer: cell is ${cell.length} bytes (want ${PFT2_CELL_BYTES})`);
    }
    if (isZeroCell(cell)) {
      throw invalidNode("cell packer: all-zero cell must be a hole");
    }
    if (this.currentBytes + PFT2_CELL_BYTES > PFT2_MAX_PACK_BYTES) {
      this.packs.push(this.current);
      this.current = [];
      this.currentBytes = 0;
    }
    const index = this.perPack.length;
    this.perPack.push(this.packs.length);
    this.perOffset.push(BigInt(this.currentBytes));
    this.digests.push(createHash("sha256").update(cell).digest());
    this.current.push(new Uint8Array(cell));
    this.currentBytes += PFT2_CELL_BYTES;
    return index;
  }

  /**
   * Seals the terminal pack, persists packs in deterministic order, and
   * returns one CellRef per added cell (in add order).
   */
  finish(sink: Pft2PackSink): Pft2CellRef[] {
    if (this.finished) {
      throw invalidNode("cell packer: double finish");
    }
    this.finished = true;
    const packs = this.current.length > 0 ? [...this.packs, this.current] : this.packs;
    const refs: Pft2Ref[] = packs.map((cells) => {
      const data = new Uint8Array(cells.length * PFT2_CELL_BYTES);
      cells.forEach((cell, i) => data.set(cell, i * PFT2_CELL_BYTES));
      const ref = pft2RefOf(data);
      checkPackRefBounds("cell packer pack", ref);
      sink.putPack(ref, data);
      return ref;
    });
    return this.perPack.map((packIndex, i) => ({
      cellDigest: this.digests[i]!,
      object: refs[packIndex]!,
      objectOffset: this.perOffset[i]!,
    }));
  }
}

/**
 * Materializes one file's complete logical bytes into canonical PFT2 form
 * (pages/cells/holes/packs/extent tree), mirroring Go BuildFileExtents.
 * Returns the extent root, or undefined when every byte is zero.
 */
export function buildFileExtents(
  content: Uint8Array,
  nodes: Pft2NodeSink,
  packs: Pft2PackSink
): Pft2Ref | undefined {
  if (BigInt(content.length) > PFT2_MAX_LOGICAL_FILE_BYTES) {
    throw invalidNode(`file content ${content.length} bytes exceeds ${PFT2_MAX_LOGICAL_FILE_BYTES}`);
  }
  interface PendingCell {
    pageOffset: bigint;
    cellIndex: number;
    packIndex: number;
  }
  const packer = new Pft2CellPacker();
  const pending: PendingCell[] = [];
  for (let pageStart = 0; pageStart < content.length; pageStart += PFT2_PAGE_BYTES) {
    for (let cellIndex = 0; cellIndex < PFT2_CELLS_PER_PAGE; cellIndex += 1) {
      const cellStart = pageStart + cellIndex * PFT2_CELL_BYTES;
      if (cellStart >= content.length) {
        break;
      }
      const cellEnd = cellStart + PFT2_CELL_BYTES;
      let cell: Uint8Array;
      if (cellEnd <= content.length) {
        cell = content.subarray(cellStart, cellEnd);
      } else {
        const padded = new Uint8Array(PFT2_CELL_BYTES);
        padded.set(content.subarray(cellStart));
        cell = padded;
      }
      if (isZeroCell(cell)) {
        continue;
      }
      const packIndex = packer.add(cell);
      pending.push({ pageOffset: BigInt(pageStart), cellIndex, packIndex });
    }
  }
  if (pending.length === 0) {
    return undefined;
  }
  const cellRefs = packer.finish(packs);
  const entries: Pft2ExtentEntry[] = [];
  for (let start = 0; start < pending.length; ) {
    const pageOffset = pending[start]!.pageOffset;
    const page: Pft2DataPage = { cells: Array.from({ length: PFT2_CELLS_PER_PAGE }, () => null) };
    let end = start;
    while (end < pending.length && pending[end]!.pageOffset === pageOffset) {
      page.cells[pending[end]!.cellIndex] = cellRefs[pending[end]!.packIndex]!;
      end += 1;
    }
    const ref = putNode({ kind: Pft2NodeKind.DataPage, dataPage: page }, nodes);
    entries.push({ pageOffset, page: ref });
    start = end;
  }
  return buildExtentTree(entries, nodes).root;
}
