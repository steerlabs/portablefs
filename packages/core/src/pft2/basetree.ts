/**
 * Lazy BaseTree — the TypeScript mirror of vcs/internal/pft2/basetree.go and
 * legacy.go. WorkFS-side consumers read immutable filesystems through
 * lookup/getInode/readExtents/readDir without ever allocating a full
 * manifest; every fetched node verifies advertised size before fetch, digest
 * before decode, kind against its edge, and structural invariants, under
 * explicit node/byte/depth bounds with a digest-keyed immutable cache and
 * singleflight fetch coalescing.
 */
import { createHash } from "node:crypto";
import { decodePft2Node } from "./codec.js";
import {
  PFT2_CELL_BYTES,
  PFT2_MAX_COUNT64,
  PFT2_MAX_INO,
  PFT2_MAX_LOGICAL_FILE_BYTES,
  PFT2_MAX_MODE_BITS,
  PFT2_MAX_TREE_DEPTH,
  PFT2_PAGE_BYTES,
  PFT2_ROOT_INO,
  Pft2BoundExceededError,
  Pft2FileKind,
  Pft2NodeKind,
  Pft2NotFoundError,
  checkNodeRefBounds,
  compareNames,
  corrupt,
  invalidNode,
  pft2RefKey,
  validateEntryName,
  validatePft2Node,
  verifyObjectBytes,
  type Pft2CellRef,
  type Pft2DirEntry,
  type Pft2DirectoryIndex,
  type Pft2DirectoryIndexChild,
  type Pft2ExtentIndexChild,
  type Pft2Inode,
  type Pft2InodeIndexChild,
  type Pft2InodeIndexIndex,
  type Pft2Node,
  type Pft2Ref,
  type Pft2Root,
  isZeroCell,
  type Pft2NodeSink,
  type Pft2PackSink,
} from "./types.js";
import { compareBytes, utf8Encode } from "./wire.js";

// ─── per-edge child verification (mirror of vcs/internal/pft2/verify.go) ────
//
// Every parent-advertised child summary (first key, last key, entry count)
// must exactly equal the fetched child's actual canonical summary; anything
// else is a crafted or corrupt graph and fails closed before an entry is
// served. Only fetched edges are checked, so lazy reads stay lazy.

/** Canonical edge summary; keys normalized to canonical bytes. */
interface EdgeSummary {
  first: Uint8Array;
  last: Uint8Array;
  count: bigint;
}

function u64KeyBytes(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let rest = value;
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

function keyBytesToU64(key: Uint8Array): bigint {
  let value = 0n;
  for (const byte of key) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function directoryChildSummary(child: Pft2DirectoryIndexChild): EdgeSummary {
  return { first: utf8Encode(child.firstName), last: utf8Encode(child.lastName), count: child.entryCount };
}

function extentChildSummary(child: Pft2ExtentIndexChild): EdgeSummary {
  return { first: u64KeyBytes(child.firstPage), last: u64KeyBytes(child.lastPage), count: child.entryCount };
}

function inodeChildSummary(child: Pft2InodeIndexChild): EdgeSummary {
  return { first: u64KeyBytes(child.firstIno), last: u64KeyBytes(child.lastIno), count: child.entryCount };
}

function summedCount(what: string, counts: readonly bigint[]): bigint {
  let total = 0n;
  for (const count of counts) {
    total += count;
    if (total > PFT2_MAX_COUNT64) {
      throw invalidNode(`${what}: entry count overflows ${PFT2_MAX_COUNT64}`);
    }
  }
  return total;
}

/**
 * The actual canonical summary of one fetched B+tree node (leaf length, or
 * the checked sum of an index node's advertised child counts).
 */
export function pft2NodeSummary(node: Pft2Node): EdgeSummary {
  switch (node.kind) {
    case Pft2NodeKind.DirectoryLeaf: {
      const entries = node.directoryLeaf.entries;
      return {
        first: utf8Encode(entries[0]!.name),
        last: utf8Encode(entries[entries.length - 1]!.name),
        count: BigInt(entries.length),
      };
    }
    case Pft2NodeKind.DirectoryIndex: {
      const children = node.directoryIndex.children;
      return {
        first: utf8Encode(children[0]!.firstName),
        last: utf8Encode(children[children.length - 1]!.lastName),
        count: summedCount("directory index summary", children.map((child) => child.entryCount)),
      };
    }
    case Pft2NodeKind.ExtentLeaf: {
      const entries = node.extentLeaf.entries;
      return {
        first: u64KeyBytes(entries[0]!.pageOffset),
        last: u64KeyBytes(entries[entries.length - 1]!.pageOffset),
        count: BigInt(entries.length),
      };
    }
    case Pft2NodeKind.ExtentIndex: {
      const children = node.extentIndex.children;
      return {
        first: u64KeyBytes(children[0]!.firstPage),
        last: u64KeyBytes(children[children.length - 1]!.lastPage),
        count: summedCount("extent index summary", children.map((child) => child.entryCount)),
      };
    }
    case Pft2NodeKind.InodeIndexLeaf: {
      const entries = node.inodeIndexLeaf.entries;
      return {
        first: u64KeyBytes(entries[0]!.ino),
        last: u64KeyBytes(entries[entries.length - 1]!.ino),
        count: BigInt(entries.length),
      };
    }
    case Pft2NodeKind.InodeIndexIndex: {
      const children = node.inodeIndexIndex.children;
      return {
        first: u64KeyBytes(children[0]!.firstIno),
        last: u64KeyBytes(children[children.length - 1]!.lastIno),
        count: summedCount("inode index summary", children.map((child) => child.entryCount)),
      };
    }
    case Pft2NodeKind.ControlLeaf: {
      const entries = node.controlLeaf.entries;
      return {
        first: entries[0]!.key,
        last: entries[entries.length - 1]!.key,
        count: BigInt(entries.length),
      };
    }
    case Pft2NodeKind.ControlIndex: {
      const children = node.controlIndex.children;
      return {
        first: children[0]!.firstKey,
        last: children[children.length - 1]!.lastKey,
        count: summedCount("control index summary", children.map((child) => child.entryCount)),
      };
    }
    default:
      throw corrupt(`node kind ${node.kind} carries no child summary`);
  }
}

/** Fails closed unless the fetched child exactly matches its advertisement. */
export function verifyPft2EdgeSummary(what: string, ref: Pft2Ref, node: Pft2Node, want: EdgeSummary): void {
  const got = pft2NodeSummary(node);
  if (
    got.count !== want.count ||
    compareBytes(got.first, want.first) !== 0 ||
    compareBytes(got.last, want.last) !== 0
  ) {
    throw corrupt(
      `${what}: object ${pft2RefKey(ref)} actual summary (count ${got.count}) does not match advertised (count ${want.count})`
    );
  }
}

/**
 * Pins the filesystem inode index root against the ROOT object's facts:
 * exactly inodeCount entries, first ino is the always-live root inode, and
 * the last ino does not exceed the maxInoSeen allocation high-water (an
 * upper bound, so only <= is provable).
 */
function verifyFSIndexRootFacts(facts: Pft2Root, ref: Pft2Ref, node: Pft2Node): void {
  const got = pft2NodeSummary(node);
  if (got.count !== facts.inodeCount) {
    throw corrupt(
      `inode index root ${pft2RefKey(ref)} holds ${got.count} entries, root advertised inode_count ${facts.inodeCount}`
    );
  }
  if (keyBytesToU64(got.first) !== PFT2_ROOT_INO) {
    throw corrupt(`inode index root ${pft2RefKey(ref)} first ino is not root ino ${PFT2_ROOT_INO}`);
  }
  if (keyBytesToU64(got.last) > facts.maxInoSeen) {
    throw corrupt(
      `inode index root ${pft2RefKey(ref)} last ino ${keyBytesToU64(got.last)} exceeds max_ino_seen ${facts.maxInoSeen}`
    );
  }
}

/** Retrieves the exact complete bytes of one immutable object by reference. */
export interface Pft2Fetcher {
  fetch(ref: Pft2Ref): Promise<Uint8Array>;
}

/**
 * In-memory object store implementing the sink and fetcher interfaces; the
 * reference store for tests and golden-vector construction.
 */
export class Pft2MemoryStore implements Pft2Fetcher, Pft2NodeSink, Pft2PackSink {
  private readonly objects = new Map<string, Uint8Array>();

  putNode(ref: Pft2Ref, encoded: Uint8Array): void {
    this.put(ref, encoded);
  }

  putPack(ref: Pft2Ref, data: Uint8Array): void {
    this.put(ref, data);
  }

  private put(ref: Pft2Ref, data: Uint8Array): void {
    verifyObjectBytes(ref, data);
    const key = pft2RefKey(ref);
    if (!this.objects.has(key)) {
      this.objects.set(key, new Uint8Array(data));
    }
  }

  fetch(ref: Pft2Ref): Promise<Uint8Array> {
    const data = this.objects.get(pft2RefKey(ref));
    if (!data) {
      return Promise.reject(corrupt(`object ${pft2RefKey(ref)} missing from store`));
    }
    return Promise.resolve(data);
  }

  /** Test hook: mutates stored bytes in place (same length). */
  corruptObject(ref: Pft2Ref, byteIndex: number): void {
    const data = this.objects.get(pft2RefKey(ref));
    if (!data) {
      throw new Error("object not stored");
    }
    data[byteIndex] = data[byteIndex]! ^ 0x40;
  }

  get size(): number {
    return this.objects.size;
  }

  /** Stable content fingerprint lines ("<hex>:<size>"), sorted. */
  objectSetLines(): string[] {
    return [...this.objects.keys()].map((key) => key.replace("/", ":")).sort();
  }
}

/** Pairs a decoded immutable inode with its reference handle. */
export interface Pft2InodeView {
  ref: Pft2Ref;
  inode: Pft2Inode;
}

/** References bytes inside a legacy (pre-PFT2) content object. */
export interface Pft2LegacyExtent {
  objectDigest: string;
  objectSize: bigint;
  objectOffset: bigint;
}

/** One present logical range of a file. Exactly one source is set. */
export interface Pft2Extent {
  fileOffset: bigint;
  /** Logical bytes covered, clamped to the inode's EOF. */
  length: bigint;
  cell?: Pft2CellRef;
  legacy?: Pft2LegacyExtent;
}

/**
 * The lazy immutable-filesystem read interface. Handles are references
 * issued by the same tree (Pft2InodeView.ref); the entry point is
 * getInode(PFT2_ROOT_INO).
 */
export interface Pft2BaseTree {
  lookup(parent: Pft2Ref, name: string): Promise<Pft2DirEntry>;
  getInode(ino: bigint): Promise<Pft2InodeView>;
  readExtents(file: Pft2Ref, offset: bigint, length: bigint): Promise<Pft2Extent[]>;
  readDir(dir: Pft2Ref, cursor: string, limit: number): Promise<{ entries: Pft2DirEntry[]; next: string }>;
}

/** Per-operation read bounds; exceeding any bound throws typed. */
export interface Pft2ReadBounds {
  maxNodes?: number;
  maxBytes?: bigint;
  maxDepth?: number;
}

export interface Pft2TreeReaderConfig {
  fetcher: Pft2Fetcher;
  /** Decoded-node cache budget in bytes (default 32 MiB; <0 disables). */
  cacheBytes?: number;
  /** Bound on simultaneous fetcher calls (default 8). */
  maxConcurrentFetches?: number;
  bounds?: Pft2ReadBounds;
}

interface OpBudget {
  nodesLeft: number;
  bytesLeft: bigint;
  maxDepth: number;
}

interface CacheEntry {
  key: string;
  node: Pft2Node;
  size: number;
}

/** Byte-budgeted LRU of decoded immutable nodes keyed by reference. */
class NodeCache {
  private readonly entries = new Map<string, CacheEntry>();
  private currentBytes = 0;

  constructor(private readonly maxBytes: number) {}

  get(key: string): Pft2Node | undefined {
    if (this.maxBytes <= 0) {
      return undefined;
    }
    const entry = this.entries.get(key);
    if (!entry) {
      return undefined;
    }
    // Map preserves insertion order; re-inserting marks recently used.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.node;
  }

  add(key: string, node: Pft2Node, size: number): void {
    if (this.maxBytes <= 0 || size > this.maxBytes || this.entries.has(key)) {
      return;
    }
    this.entries.set(key, { key, node, size });
    this.currentBytes += size;
    for (const oldest of this.entries.values()) {
      if (this.currentBytes <= this.maxBytes) {
        break;
      }
      this.entries.delete(oldest.key);
      this.currentBytes -= oldest.size;
    }
  }
}

/** Async semaphore bounding concurrent fetches. */
class Semaphore {
  private available: number;
  private readonly waiters: (() => void)[] = [];

  constructor(limit: number) {
    this.available = limit;
  }

  async acquire(): Promise<void> {
    if (this.available > 0) {
      this.available -= 1;
      return;
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  release(): void {
    const next = this.waiters.shift();
    if (next) {
      next();
    } else {
      this.available += 1;
    }
  }
}

function boundExceeded(message: string): Pft2BoundExceededError {
  return new Pft2BoundExceededError(message);
}

function notFound(message: string): Pft2NotFoundError {
  return new Pft2NotFoundError(message);
}

/** Production lazy BaseTree over PFT2 objects. */
export class Pft2TreeReader implements Pft2BaseTree {
  private readonly fetcher: Pft2Fetcher;
  private readonly cache: NodeCache;
  private readonly semaphore: Semaphore;
  private readonly flight = new Map<string, Promise<{ node: Pft2Node; size: number }>>();
  private readonly maxNodes: number;
  private readonly maxBytes: bigint;
  private readonly maxDepth: number;
  private readonly rootRef: Pft2Ref;
  private root: Promise<Pft2Node> | undefined;

  constructor(config: Pft2TreeReaderConfig, root: Pft2Ref) {
    checkNodeRefBounds("tree root", root);
    this.fetcher = config.fetcher;
    this.cache = new NodeCache(config.cacheBytes === undefined ? 32 * 1024 * 1024 : config.cacheBytes);
    this.semaphore = new Semaphore(config.maxConcurrentFetches && config.maxConcurrentFetches > 0 ? config.maxConcurrentFetches : 8);
    this.maxNodes = config.bounds?.maxNodes && config.bounds.maxNodes > 0 ? config.bounds.maxNodes : 64;
    this.maxBytes = config.bounds?.maxBytes && config.bounds.maxBytes > 0n ? config.bounds.maxBytes : 8n * 1024n * 1024n;
    const depth = config.bounds?.maxDepth ?? PFT2_MAX_TREE_DEPTH;
    this.maxDepth = depth > 0 && depth <= PFT2_MAX_TREE_DEPTH ? depth : PFT2_MAX_TREE_DEPTH;
    this.rootRef = root;
  }

  private newOp(): OpBudget {
    return { nodesLeft: this.maxNodes, bytesLeft: this.maxBytes, maxDepth: this.maxDepth };
  }

  private charge(op: OpBudget, size: bigint): void {
    if (op.nodesLeft <= 0 || op.bytesLeft < size) {
      throw boundExceeded("node/byte budget exhausted");
    }
    op.nodesLeft -= 1;
    op.bytesLeft -= size;
  }

  private async fetchNode<K extends Pft2NodeKind>(
    op: OpBudget,
    ref: Pft2Ref,
    allowed: readonly K[]
  ): Promise<Extract<Pft2Node, { kind: K }>> {
    checkNodeRefBounds("fetch", ref);
    this.charge(op, ref.size);
    const node = await this.loadNode(ref);
    if (!allowed.includes(node.kind as K)) {
      throw corrupt(`object ${pft2RefKey(ref)}: kind ${node.kind} not valid for this edge`);
    }
    return node as Extract<Pft2Node, { kind: K }>;
  }

  private async loadNode(ref: Pft2Ref): Promise<Pft2Node> {
    const key = pft2RefKey(ref);
    const cached = this.cache.get(key);
    if (cached) {
      return cached;
    }
    const inflight = this.flight.get(key);
    if (inflight) {
      return (await inflight).node;
    }
    const promise = this.fetchVerifyDecode(ref);
    this.flight.set(key, promise);
    try {
      const { node, size } = await promise;
      this.cache.add(key, node, size);
      return node;
    } finally {
      this.flight.delete(key);
    }
  }

  private async fetchVerifyDecode(ref: Pft2Ref): Promise<{ node: Pft2Node; size: number }> {
    await this.semaphore.acquire();
    try {
      const data = await this.fetcher.fetch(ref);
      verifyObjectBytes(ref, data);
      return { node: decodePft2Node(data), size: data.length };
    } finally {
      this.semaphore.release();
    }
  }

  private loadRoot(op: OpBudget): Promise<Pft2Node> {
    // The root resolves lazily once; budget is charged per operation.
    this.charge(op, this.rootRef.size);
    if (!this.root) {
      const promise = (async () => {
        const node = await this.loadNodeUncharged(this.rootRef);
        if (node.kind !== Pft2NodeKind.Root) {
          throw corrupt(`tree root resolves to kind ${node.kind}`);
        }
        return node;
      })();
      this.root = promise;
      promise.catch(() => {
        // A failed root fetch is not sticky; the next operation retries.
        if (this.root === promise) {
          this.root = undefined;
        }
      });
    }
    return this.root;
  }

  private loadNodeUncharged(ref: Pft2Ref): Promise<Pft2Node> {
    return this.loadNode(ref);
  }

  async getInode(ino: bigint): Promise<Pft2InodeView> {
    if (ino < 1n || ino > PFT2_MAX_INO) {
      throw invalidNode(`ino ${ino} outside 1..${PFT2_MAX_INO}`);
    }
    const op = this.newOp();
    const rootNode = await this.loadRoot(op);
    if (rootNode.kind !== Pft2NodeKind.Root) {
      throw corrupt("root handle is not a ROOT node");
    }
    if (ino > rootNode.root.maxInoSeen) {
      throw notFound("ino beyond the allocation high-water");
    }
    let ref = rootNode.root.inodeIndex;
    let edge: EdgeSummary | undefined;
    for (let depth = 1; ; depth += 1) {
      if (depth > op.maxDepth) {
        throw boundExceeded("inode index depth");
      }
      const node = await this.fetchNode(op, ref, [Pft2NodeKind.InodeIndexLeaf, Pft2NodeKind.InodeIndexIndex]);
      if (edge) {
        verifyPft2EdgeSummary("inode index child", ref, node, edge);
      } else {
        verifyFSIndexRootFacts(rootNode.root, ref, node);
      }
      if (node.kind === Pft2NodeKind.InodeIndexLeaf) {
        for (const entry of node.inodeIndexLeaf.entries) {
          if (entry.ino === ino) {
            return this.resolveInode(op, entry.inode, ino);
          }
        }
        throw notFound("ino not in leaf");
      }
      const child = findInodeIndexChild(node.inodeIndexIndex, ino);
      if (!child) {
        throw notFound("ino not covered by index");
      }
      edge = inodeChildSummary(child);
      ref = child.child;
    }
  }

  private async resolveInode(op: OpBudget, ref: Pft2Ref, wantIno: bigint): Promise<Pft2InodeView> {
    const node = await this.fetchNode(op, ref, [Pft2NodeKind.Inode]);
    if (node.inode.ino !== wantIno) {
      throw corrupt(`inode object ${pft2RefKey(ref)} carries ino ${node.inode.ino}, index advertised ${wantIno}`);
    }
    return { ref, inode: node.inode };
  }

  private async directoryInode(op: OpBudget, ref: Pft2Ref): Promise<Pft2Inode> {
    const node = await this.fetchNode(op, ref, [Pft2NodeKind.Inode]);
    if (node.inode.kind !== Pft2FileKind.Directory) {
      throw corrupt(`inode ${node.inode.ino} is not a directory`);
    }
    return node.inode;
  }

  async lookup(parent: Pft2Ref, name: string): Promise<Pft2DirEntry> {
    validateEntryName(name);
    const op = this.newOp();
    const dir = await this.directoryInode(op, parent);
    if (!dir.directoryRoot) {
      throw notFound("empty directory");
    }
    let ref = dir.directoryRoot;
    let edge: EdgeSummary | undefined;
    for (let depth = 1; ; depth += 1) {
      if (depth > op.maxDepth) {
        throw boundExceeded("directory depth");
      }
      const node = await this.fetchNode(op, ref, [Pft2NodeKind.DirectoryLeaf, Pft2NodeKind.DirectoryIndex]);
      if (edge) {
        verifyPft2EdgeSummary("directory child", ref, node, edge);
      }
      if (node.kind === Pft2NodeKind.DirectoryLeaf) {
        for (const entry of node.directoryLeaf.entries) {
          if (entry.name === name) {
            return entry;
          }
        }
        throw notFound("name not in leaf");
      }
      const child = findDirectoryChild(node.directoryIndex, name);
      if (!child) {
        throw notFound("name not covered by index");
      }
      edge = directoryChildSummary(child);
      ref = child.child;
    }
  }

  async readDir(
    dir: Pft2Ref,
    cursor: string,
    limit: number
  ): Promise<{ entries: Pft2DirEntry[]; next: string }> {
    if (!Number.isInteger(limit) || limit <= 0) {
      throw invalidNode(`readdir limit ${limit} must be positive`);
    }
    const op = this.newOp();
    const inode = await this.directoryInode(op, dir);
    if (!inode.directoryRoot) {
      return { entries: [], next: "" };
    }
    const out: Pft2DirEntry[] = [];
    const more = await this.readDirWalk(op, inode.directoryRoot, undefined, 1, cursor, limit, out);
    return { entries: out, next: more && out.length > 0 ? out[out.length - 1]!.name : "" };
  }

  private async readDirWalk(
    op: OpBudget,
    ref: Pft2Ref,
    edge: EdgeSummary | undefined,
    depth: number,
    cursor: string,
    limit: number,
    out: Pft2DirEntry[]
  ): Promise<boolean> {
    if (depth > op.maxDepth) {
      throw boundExceeded("directory depth");
    }
    const node = await this.fetchNode(op, ref, [Pft2NodeKind.DirectoryLeaf, Pft2NodeKind.DirectoryIndex]);
    if (edge) {
      verifyPft2EdgeSummary("directory child", ref, node, edge);
    }
    if (node.kind === Pft2NodeKind.DirectoryLeaf) {
      for (const entry of node.directoryLeaf.entries) {
        if (cursor !== "" && compareNames(entry.name, cursor) <= 0) {
          continue;
        }
        if (out.length >= limit) {
          return true;
        }
        out.push(entry);
      }
      return false;
    }
    const children = node.directoryIndex.children;
    for (let i = 0; i < children.length; i += 1) {
      const child = children[i]!;
      if (cursor !== "" && compareNames(child.lastName, cursor) <= 0) {
        continue;
      }
      const more = await this.readDirWalk(
        op,
        child.child,
        directoryChildSummary(child),
        depth + 1,
        cursor,
        limit,
        out
      );
      if (more) {
        return true;
      }
      if (out.length >= limit && i < children.length - 1) {
        return true;
      }
    }
    return false;
  }

  async readExtents(file: Pft2Ref, offset: bigint, length: bigint): Promise<Pft2Extent[]> {
    if (offset < 0n || length < 0n) {
      throw invalidNode("negative offset or length");
    }
    const op = this.newOp();
    const node = await this.fetchNode(op, file, [Pft2NodeKind.Inode]);
    const inode = node.inode;
    if (inode.kind !== Pft2FileKind.Regular) {
      throw corrupt(`inode ${inode.ino} is not a regular file`);
    }
    const size = inode.size;
    if (length === 0n || offset >= size || !inode.extentRoot) {
      return [];
    }
    let end = offset + length;
    if (end > size) {
      end = size;
    }
    const window = {
      start: offset,
      end,
      firstPage: (offset / BigInt(PFT2_PAGE_BYTES)) * BigInt(PFT2_PAGE_BYTES),
      lastPage: ((end - 1n) / BigInt(PFT2_PAGE_BYTES)) * BigInt(PFT2_PAGE_BYTES),
    };
    const out: Pft2Extent[] = [];
    await this.extentWalk(op, inode.extentRoot, undefined, 1, size, window, out);
    return out;
  }

  private async extentWalk(
    op: OpBudget,
    ref: Pft2Ref,
    edge: EdgeSummary | undefined,
    depth: number,
    size: bigint,
    window: { start: bigint; end: bigint; firstPage: bigint; lastPage: bigint },
    out: Pft2Extent[]
  ): Promise<void> {
    if (depth > op.maxDepth) {
      throw boundExceeded("extent depth");
    }
    const node = await this.fetchNode(op, ref, [Pft2NodeKind.ExtentLeaf, Pft2NodeKind.ExtentIndex]);
    if (edge) {
      verifyPft2EdgeSummary("extent child", ref, node, edge);
    }
    if (node.kind === Pft2NodeKind.ExtentLeaf) {
      for (const entry of node.extentLeaf.entries) {
        if (entry.pageOffset < window.firstPage || entry.pageOffset > window.lastPage) {
          continue;
        }
        if (entry.pageOffset >= size) {
          throw corrupt(`extent page ${entry.pageOffset} at or beyond logical EOF ${size}`);
        }
        await this.appendPageExtents(op, entry.pageOffset, entry.page, size, window, out);
      }
      return;
    }
    for (const child of node.extentIndex.children) {
      if (child.lastPage < window.firstPage || child.firstPage > window.lastPage) {
        continue;
      }
      await this.extentWalk(op, child.child, extentChildSummary(child), depth + 1, size, window, out);
    }
  }

  private async appendPageExtents(
    op: OpBudget,
    pageOffset: bigint,
    pageRef: Pft2Ref,
    size: bigint,
    window: { start: bigint; end: bigint },
    out: Pft2Extent[]
  ): Promise<void> {
    const node = await this.fetchNode(op, pageRef, [Pft2NodeKind.DataPage]);
    node.dataPage.cells.forEach((cell, cellIndex) => {
      if (!cell) {
        return;
      }
      const cellStart = pageOffset + BigInt(cellIndex * PFT2_CELL_BYTES);
      if (cellStart >= size) {
        throw corrupt(`data page ${pft2RefKey(pageRef)} cell ${cellIndex} at or beyond logical EOF ${size}`);
      }
      if (cellStart + BigInt(PFT2_CELL_BYTES) <= window.start || cellStart >= window.end) {
        return;
      }
      let logical = BigInt(PFT2_CELL_BYTES);
      if (cellStart + logical > size) {
        logical = size - cellStart;
      }
      out.push({ fileOffset: cellStart, length: logical, cell });
    });
  }
}

function findInodeIndexChild(index: Pft2InodeIndexIndex, ino: bigint): Pft2InodeIndexChild | undefined {
  for (const child of index.children) {
    if (ino >= child.firstIno && ino <= child.lastIno) {
      return child;
    }
  }
  return undefined;
}

function findDirectoryChild(index: Pft2DirectoryIndex, name: string): Pft2DirectoryIndexChild | undefined {
  for (const child of index.children) {
    if (compareNames(name, child.firstName) >= 0 && compareNames(name, child.lastName) <= 0) {
      return child;
    }
  }
  return undefined;
}

/**
 * Extracts and verifies one cell's canonical bytes from its fetched (and
 * already object-digest-verified) pack bytes. logicalValid is the count of
 * logically valid bytes; the suffix beyond it must be canonically zero
 * (terminal-zeroing invariant).
 */
export function verifyCellBytes(cell: Pft2CellRef, packBytes: Uint8Array, logicalValid: bigint): Uint8Array {
  if (BigInt(packBytes.length) !== cell.object.size) {
    throw corrupt(`pack: fetched ${packBytes.length} bytes, advertised ${cell.object.size}`);
  }
  if (logicalValid < 0n || logicalValid > BigInt(PFT2_CELL_BYTES)) {
    throw invalidNode(`logical valid ${logicalValid} exceeds cell size ${PFT2_CELL_BYTES}`);
  }
  const start = Number(cell.objectOffset);
  const slice = packBytes.subarray(start, start + PFT2_CELL_BYTES);
  if (slice.length !== PFT2_CELL_BYTES) {
    throw corrupt("pack: cell slice out of object bounds");
  }
  const digest = createHash("sha256").update(slice).digest();
  if (compareBytes(digest, cell.cellDigest) !== 0) {
    throw corrupt("pack: cell slice fails its logical digest");
  }
  if (!isZeroCell(slice.subarray(Number(logicalValid)))) {
    throw corrupt("pack: cell slice has nonzero bytes beyond logical EOF");
  }
  return slice;
}

// ─── legacy manifest adapter ─────────────────────────────────────────────────

/**
 * Legacy manifest entry (the portablefs-v1 TreeEntry shape) accepted by the
 * adapter. Sizes/offsets are JS numbers because the legacy manifest format
 * itself carries JSON numbers; they are converted to bigint at this boundary.
 * Inode ids are accepted as bigint or canonical decimal string, never parsed
 * from a JSON number.
 */
export interface Pft2LegacyManifestEntry {
  path: string;
  kind: "file" | "directory" | "symlink";
  mode: number;
  size?: number;
  mtimeMs?: number;
  ctimeMs?: number;
  atimeMs?: number;
  uid?: number;
  gid?: number;
  ino?: bigint | string;
  blob?: { digest: string; size: number };
  chunks?: { digest: string; size: number; offset: number }[];
  linkTarget?: string;
}

interface LegacyFile {
  view: Pft2InodeView;
  blob?: Pft2LegacyExtent;
  chunks: { digest: string; size: bigint; offset: bigint }[];
  children: Map<string, Pft2DirEntry>;
  sortedNames: string[];
}

function legacyRef(ino: bigint): Pft2Ref {
  // Size 0 is below PFT2_MIN_NODE_BYTES, so a legacy handle presented to a
  // real PFT2 reader or object store fails closed instead of resolving.
  const digest = createHash("sha256").update(`pft2-legacy-inode\0${ino.toString(10)}`).digest();
  return { digest, size: 0n };
}

function toBigIntMs(value: number | undefined): bigint {
  if (value === undefined) {
    return 0n;
  }
  if (!Number.isFinite(value)) {
    throw invalidNode("legacy timestamp is not finite");
  }
  return BigInt(Math.trunc(value));
}

/**
 * Exposes a legacy flat manifest through the Pft2BaseTree interface without
 * rewriting any blob. Explicit inode ids are preserved exactly; entries
 * without one receive deterministic ids above the maximum explicit id in
 * ascending path-byte order; missing intermediate directories are
 * synthesized. The root directory is always inode 1.
 */
export class Pft2LegacyBaseTree implements Pft2BaseTree {
  private readonly byIno = new Map<bigint, LegacyFile>();
  private readonly byRef = new Map<string, LegacyFile>();

  constructor(entries: readonly Pft2LegacyManifestEntry[]) {
    const sorted = [...entries].sort((a, b) => compareNames(a.path, b.path));
    const inoByPath = new Map<string, bigint>([["", PFT2_ROOT_INO]]);
    const pathByIno = new Map<bigint, string>([[PFT2_ROOT_INO, ""]]);

    let maxExplicit = PFT2_ROOT_INO;
    const seenPaths = new Set<string>();
    for (const entry of sorted) {
      if (
        entry.path === "" ||
        entry.path.startsWith("/") ||
        entry.path.endsWith("/") ||
        entry.path.includes("//")
      ) {
        throw invalidNode(`legacy entry has invalid path ${JSON.stringify(entry.path)}`);
      }
      for (const segment of entry.path.split("/")) {
        validateEntryName(segment);
      }
      if (seenPaths.has(entry.path)) {
        throw invalidNode(`legacy manifest repeats path ${JSON.stringify(entry.path)}`);
      }
      seenPaths.add(entry.path);
      const ino = parseLegacyIno(entry);
      if (ino !== undefined) {
        if (ino === PFT2_ROOT_INO) {
          throw invalidNode(`legacy entry ${entry.path} claims reserved root ino 1`);
        }
        if (ino > maxExplicit) {
          maxExplicit = ino;
        }
      }
    }

    let nextSynthetic = maxExplicit + 1n;
    this.register(makeLegacyDirectory(PFT2_ROOT_INO, 0o755));

    const ensureDir = (path: string): void => {
      const existing = inoByPath.get(path);
      if (existing !== undefined) {
        const file = this.byIno.get(existing)!;
        if (file.view.inode.kind !== Pft2FileKind.Directory) {
          throw invalidNode(`legacy path ${JSON.stringify(path)} is used as a directory but is not one`);
        }
        return;
      }
      const ino = nextSynthetic;
      nextSynthetic += 1n;
      if (ino > PFT2_MAX_INO) {
        throw invalidNode("legacy manifest exhausts synthetic inode space");
      }
      inoByPath.set(path, ino);
      pathByIno.set(ino, path);
      this.register(makeLegacyDirectory(ino, 0o755));
      this.linkToParent(inoByPath, path, ino, Pft2FileKind.Directory);
    };

    for (const entry of sorted) {
      for (let i = 0; i < entry.path.length; i += 1) {
        if (entry.path[i] === "/") {
          ensureDir(entry.path.slice(0, i));
        }
      }
      if (inoByPath.has(entry.path)) {
        throw invalidNode(`legacy path ${JSON.stringify(entry.path)} registered twice`);
      }
      let ino = parseLegacyIno(entry);
      if (ino === undefined) {
        ino = nextSynthetic;
        nextSynthetic += 1n;
        if (ino > PFT2_MAX_INO) {
          throw invalidNode("legacy manifest exhausts synthetic inode space");
        }
      } else if (pathByIno.has(ino)) {
        throw invalidNode(
          `legacy entries ${JSON.stringify(pathByIno.get(ino))} and ${JSON.stringify(entry.path)} share ino ${ino}`
        );
      }
      inoByPath.set(entry.path, ino);
      pathByIno.set(ino, entry.path);
      const file = makeLegacyFile(entry, ino);
      this.register(file);
      this.linkToParent(inoByPath, entry.path, ino, file.view.inode.kind);
    }

    // Every adapted inode — synthesized directories and the root included —
    // must satisfy the exact PFT2 inode invariants (kind-specific state,
    // mode/uid/gid ranges, timestamp bounds, symlink target rules), the
    // same rules the Go adapter enforces.
    for (const file of this.byIno.values()) {
      file.sortedNames = [...file.children.keys()].sort(compareNames);
      validatePft2Node({ kind: Pft2NodeKind.Inode, inode: file.view.inode });
    }
  }

  private register(file: LegacyFile): void {
    this.byIno.set(file.view.inode.ino, file);
    this.byRef.set(pft2RefKey(file.view.ref), file);
  }

  private linkToParent(
    inoByPath: Map<string, bigint>,
    path: string,
    ino: bigint,
    kind: Pft2FileKind
  ): void {
    const slash = path.lastIndexOf("/");
    const parentPath = slash >= 0 ? path.slice(0, slash) : "";
    const name = slash >= 0 ? path.slice(slash + 1) : path;
    const parentIno = inoByPath.get(parentPath);
    const parent = parentIno === undefined ? undefined : this.byIno.get(parentIno);
    if (!parent || parent.view.inode.kind !== Pft2FileKind.Directory) {
      throw invalidNode(`legacy entry ${JSON.stringify(path)} has non-directory parent`);
    }
    parent.children.set(name, { name, ino, kind });
  }

  private fileFor(ref: Pft2Ref): LegacyFile {
    const file = this.byRef.get(pft2RefKey(ref));
    if (!file) {
      throw corrupt(`unknown legacy handle ${pft2RefKey(ref)}`);
    }
    return file;
  }

  getInode(ino: bigint): Promise<Pft2InodeView> {
    const file = this.byIno.get(ino);
    if (!file) {
      return Promise.reject(notFound("legacy ino"));
    }
    return Promise.resolve(file.view);
  }

  lookup(parent: Pft2Ref, name: string): Promise<Pft2DirEntry> {
    validateEntryName(name);
    const file = this.fileFor(parent);
    if (file.view.inode.kind !== Pft2FileKind.Directory) {
      return Promise.reject(corrupt(`legacy inode ${file.view.inode.ino} is not a directory`));
    }
    const entry = file.children.get(name);
    if (!entry) {
      return Promise.reject(notFound("legacy name"));
    }
    return Promise.resolve(entry);
  }

  readDir(dir: Pft2Ref, cursor: string, limit: number): Promise<{ entries: Pft2DirEntry[]; next: string }> {
    if (!Number.isInteger(limit) || limit <= 0) {
      return Promise.reject(invalidNode(`readdir limit ${limit} must be positive`));
    }
    const file = this.fileFor(dir);
    if (file.view.inode.kind !== Pft2FileKind.Directory) {
      return Promise.reject(corrupt(`legacy inode ${file.view.inode.ino} is not a directory`));
    }
    const out: Pft2DirEntry[] = [];
    for (const name of file.sortedNames) {
      if (cursor !== "" && compareNames(name, cursor) <= 0) {
        continue;
      }
      if (out.length >= limit) {
        return Promise.resolve({ entries: out, next: out[out.length - 1]!.name });
      }
      out.push(file.children.get(name)!);
    }
    return Promise.resolve({ entries: out, next: "" });
  }

  readExtents(ref: Pft2Ref, offset: bigint, length: bigint): Promise<Pft2Extent[]> {
    if (offset < 0n || length < 0n) {
      return Promise.reject(invalidNode("negative offset or length"));
    }
    const file = this.fileFor(ref);
    if (file.view.inode.kind !== Pft2FileKind.Regular) {
      return Promise.reject(corrupt(`legacy inode ${file.view.inode.ino} is not a regular file`));
    }
    const size = file.view.inode.size;
    if (length === 0n || offset >= size) {
      return Promise.resolve([]);
    }
    let end = offset + length;
    if (end > size) {
      end = size;
    }
    const out: Pft2Extent[] = [];
    const appendRange = (
      objectDigest: string,
      objectSize: bigint,
      objectStart: bigint,
      fileStart: bigint,
      fileEnd: bigint
    ): void => {
      if (fileEnd <= offset || fileStart >= end) {
        return;
      }
      const from = fileStart > offset ? fileStart : offset;
      const to = fileEnd < end ? fileEnd : end;
      out.push({
        fileOffset: from,
        length: to - from,
        legacy: { objectDigest, objectSize, objectOffset: objectStart + (from - fileStart) },
      });
    };
    if (file.chunks.length > 0) {
      for (const chunk of file.chunks) {
        appendRange(chunk.digest, chunk.size, 0n, chunk.offset, chunk.offset + chunk.size);
      }
    } else if (file.blob) {
      appendRange(file.blob.objectDigest, file.blob.objectSize, 0n, 0n, size);
    }
    return Promise.resolve(out);
  }
}

function parseLegacyIno(entry: Pft2LegacyManifestEntry): bigint | undefined {
  if (entry.ino === undefined) {
    return undefined;
  }
  const ino = typeof entry.ino === "string" ? BigInt(entry.ino) : entry.ino;
  if (ino === 0n) {
    return undefined;
  }
  if (ino < 0n || ino > PFT2_MAX_INO) {
    throw invalidNode(`legacy entry ${entry.path} ino ${ino} outside 1..${PFT2_MAX_INO}`);
  }
  return ino;
}

function makeLegacyDirectory(ino: bigint, mode: number): LegacyFile {
  return {
    view: {
      ref: legacyRef(ino),
      inode: {
        ino,
        kind: Pft2FileKind.Directory,
        mode,
        uid: 0,
        gid: 0,
        nlink: 1n,
        size: 0n,
        mtimeMs: 0n,
        ctimeMs: 0n,
        atimeMs: 0n,
        // Legacy manifests carry neither a birth time nor BSD flags; 0 is the
        // canonical "absent" value the format defines for both.
        birthtimeMs: 0n,
        flags: 0,
        symlinkTarget: "",
      },
    },
    chunks: [],
    children: new Map(),
    sortedNames: [],
  };
}

function makeLegacyFile(entry: Pft2LegacyManifestEntry, ino: bigint): LegacyFile {
  const size = entry.size ?? 0;
  if (!Number.isInteger(size) || size < 0) {
    throw invalidNode(`legacy entry ${entry.path} has invalid size`);
  }
  const base: LegacyFile = {
    view: {
      ref: legacyRef(ino),
      inode: {
        ino,
        kind: Pft2FileKind.Regular,
        mode: (entry.mode ?? 0) & PFT2_MAX_MODE_BITS,
        uid: entry.uid ?? 0,
        gid: entry.gid ?? 0,
        nlink: 1n,
        size: 0n,
        mtimeMs: toBigIntMs(entry.mtimeMs),
        ctimeMs: toBigIntMs(entry.ctimeMs),
        atimeMs: toBigIntMs(entry.atimeMs),
        // Legacy manifests predate both durable fields; 0 is canonically absent.
        birthtimeMs: 0n,
        flags: 0,
        symlinkTarget: "",
      },
    },
    chunks: [],
    children: new Map(),
    sortedNames: [],
  };
  switch (entry.kind) {
    case "directory": {
      base.view.inode.kind = Pft2FileKind.Directory;
      return validatedLegacyInode(entry.path, base);
    }
    case "symlink": {
      const target = entry.linkTarget ?? "";
      base.view.inode.kind = Pft2FileKind.Symlink;
      base.view.inode.symlinkTarget = target;
      // The target is authoritative for size (legacy manifests occasionally
      // disagree with the byte length).
      base.view.inode.size = BigInt(utf8Encode(target).length);
      return validatedLegacyInode(entry.path, base);
    }
    case "file": {
      base.view.inode.size = BigInt(size);
      if (base.view.inode.size > PFT2_MAX_LOGICAL_FILE_BYTES) {
        throw invalidNode(`legacy entry ${entry.path} size exceeds ${PFT2_MAX_LOGICAL_FILE_BYTES}`);
      }
      if (entry.chunks && entry.chunks.length > 0) {
        const chunks = [...entry.chunks].sort((a, b) => a.offset - b.offset);
        let expected = 0n;
        for (const chunk of chunks) {
          if (!chunk.digest || chunk.size <= 0 || BigInt(chunk.offset) !== expected) {
            throw invalidNode(`legacy entry ${entry.path} has non-contiguous or invalid chunks`);
          }
          expected += BigInt(chunk.size);
          base.chunks.push({ digest: chunk.digest, size: BigInt(chunk.size), offset: BigInt(chunk.offset) });
        }
        if (expected !== base.view.inode.size) {
          throw invalidNode(`legacy entry ${entry.path} chunk sizes do not sum to size`);
        }
      } else if (base.view.inode.size > 0n) {
        if (!entry.blob?.digest) {
          throw invalidNode(`legacy entry ${entry.path} has size ${size} but no blob`);
        }
        if (BigInt(entry.blob.size) !== base.view.inode.size) {
          throw invalidNode(`legacy entry ${entry.path} blob size ${entry.blob.size}, size ${size}`);
        }
        base.blob = {
          objectDigest: entry.blob.digest,
          objectSize: base.view.inode.size,
          objectOffset: 0n,
        };
      }
      return validatedLegacyInode(entry.path, base);
    }
    default:
      throw invalidNode(`legacy entry ${entry.path} has unknown kind ${(entry as { kind: string }).kind}`);
  }
}

/** Applies the exact PFT2 inode invariants to one adapted legacy entry. */
function validatedLegacyInode(path: string, file: LegacyFile): LegacyFile {
  try {
    validatePft2Node({ kind: Pft2NodeKind.Inode, inode: file.view.inode });
  } catch (error) {
    throw invalidNode(`legacy entry ${JSON.stringify(path)}: ${(error as Error).message}`);
  }
  return file;
}