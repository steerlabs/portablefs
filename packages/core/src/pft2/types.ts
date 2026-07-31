/**
 * PFT2 immutable filesystem format — TypeScript value model and structural
 * validation, mirroring vcs/internal/pft2 (see docs/history.md). Every
 * 64-bit quantity is a bigint; inode and allocator values never pass through
 * a JavaScript number.
 */
import { createHash } from "node:crypto";
import { compareBytes, utf8Encode } from "./wire.js";

/** "PFT2" magic prefixing every canonical object; digests cover it. */
export const PFT2_MAGIC = new Uint8Array([0x50, 0x46, 0x54, 0x32]);

export const PFT2_DIGEST_BYTES = 32;
export const PFT2_CELL_BYTES = 4096;
export const PFT2_CELLS_PER_PAGE = 16;
export const PFT2_PAGE_BYTES = PFT2_CELL_BYTES * PFT2_CELLS_PER_PAGE;
export const PFT2_TARGET_NODE_BYTES = 64 * 1024;
export const PFT2_MAX_NODE_BYTES = 256 * 1024;
/** Smallest canonical node: a minimal CONTROL_ROOT is exactly 12 bytes. */
export const PFT2_MIN_NODE_BYTES = 12;
export const PFT2_MAX_LEAF_ENTRIES = 4096;
export const PFT2_MAX_INDEX_CHILDREN = 256;
export const PFT2_MIN_INDEX_CHILDREN = 2;
export const PFT2_MAX_XATTR_NAME_BYTES = 255;
export const PFT2_MAX_XATTR_VALUE_BYTES = 64 << 10;
export const PFT2_MAX_NAME_BYTES = 255;
export const PFT2_MAX_SYMLINK_TARGET_BYTES = 4096;
export const PFT2_MAX_TREE_DEPTH = 12;
export const PFT2_MIN_PACK_BYTES = PFT2_CELL_BYTES;
export const PFT2_MAX_PACK_BYTES = 4 * 1024 * 1024;
export const PFT2_MAX_LOGICAL_FILE_BYTES = 1n << 62n;
export const PFT2_MAX_INO = (1n << 63n) - 1n;
export const PFT2_MAX_NLINK = (1n << 32n) - 1n;
export const PFT2_MAX_MODE_BITS = 0o7777;
export const PFT2_MAX_ABS_TIME_MS = (1n << 56n) - 1n;
export const PFT2_MAX_COUNT64 = (1n << 63n) - 1n;
export const PFT2_MAX_CONTROL_KEY_BYTES = 512;
export const PFT2_MAX_CONTROL_VALUE_BYTES = 4096;
export const PFT2_MAX_CONTROL_ENTRY_KIND = 64n;
export const PFT2_CONTROL_SCHEMA_VERSION = 1n;
export const PFT2_MAX_CHECKOUT_EPOCH = (1n << 63n) - 1n;
export const PFT2_ROOT_INO = 1n;
export const PFT2_MAX_INODE_NAMESPACE = 0x7fffffff;
export const PFT2_MAX_INODE_LOCAL_COUNTER = (1n << 32n) - 1n;

/** sha256 of PFT2_CELL_BYTES zero bytes; a CellRef must never carry it. */
export const PFT2_ZERO_CELL_DIGEST: Uint8Array = createHash("sha256")
  .update(new Uint8Array(PFT2_CELL_BYTES))
  .digest();

/** Node kinds (frozen wire constants). */
export const Pft2NodeKind = {
  Root: 1,
  Inode: 2,
  DirectoryLeaf: 3,
  DirectoryIndex: 4,
  ExtentLeaf: 5,
  ExtentIndex: 6,
  InodeIndexLeaf: 7,
  InodeIndexIndex: 8,
  RecoveryRoot: 9,
  DataPage: 10,
  ControlRoot: 11,
  ControlLeaf: 12,
  ControlIndex: 13,
  XattrLeaf: 14,
} as const;
export type Pft2NodeKind = (typeof Pft2NodeKind)[keyof typeof Pft2NodeKind];

/** File kinds (frozen wire constants). */
export const Pft2FileKind = {
  Regular: 1,
  Directory: 2,
  Symlink: 3,
} as const;
export type Pft2FileKind = (typeof Pft2FileKind)[keyof typeof Pft2FileKind];

/** Structural validation rejection (encode- and decode-side). */
export class Pft2InvalidNodeError extends Error {
  constructor(message: string) {
    super(`pft2: invalid node: ${message}`);
    this.name = "Pft2InvalidNodeError";
  }
}

/** Cross-object verification failure (digest/size/kind/invariant). */
export class Pft2CorruptError extends Error {
  constructor(message: string) {
    super(`pft2: corrupt object: ${message}`);
    this.name = "Pft2CorruptError";
  }
}

/** Missing name/inode/key (a normal outcome). */
export class Pft2NotFoundError extends Error {
  constructor(message: string) {
    super(`pft2: not found: ${message}`);
    this.name = "Pft2NotFoundError";
  }
}

/** A caller-supplied read bound was exhausted. */
export class Pft2BoundExceededError extends Error {
  constructor(message: string) {
    super(`pft2: read bound exceeded: ${message}`);
    this.name = "Pft2BoundExceededError";
  }
}

/** Typed terminal error: namespace local counter consumed (never wraps). */
export class Pft2InodeCounterExhaustedError extends Error {
  constructor(message: string) {
    super(`pft2: inode local counter exhausted: ${message}`);
    this.name = "Pft2InodeCounterExhaustedError";
  }
}

/** Typed terminal error: namespace outside 1..PFT2_MAX_INODE_NAMESPACE. */
export class Pft2InodeNamespaceExhaustedError extends Error {
  constructor(message: string) {
    super(`pft2: inode namespace exhausted: ${message}`);
    this.name = "Pft2InodeNamespaceExhaustedError";
  }
}

export function invalidNode(message: string): Pft2InvalidNodeError {
  return new Pft2InvalidNodeError(message);
}

export function corrupt(message: string): Pft2CorruptError {
  return new Pft2CorruptError(message);
}

/**
 * One object reference: raw SHA-256 digest of the exact complete encoded
 * bytes plus that exact byte count.
 */
export interface Pft2Ref {
  digest: Uint8Array;
  size: bigint;
}

/** Computes the reference of encoded object bytes. */
export function pft2RefOf(encoded: Uint8Array): Pft2Ref {
  return {
    digest: createHash("sha256").update(encoded).digest(),
    size: BigInt(encoded.length),
  };
}

export function pft2RefHex(ref: Pft2Ref): string {
  return Buffer.from(ref.digest).toString("hex");
}

export function pft2RefsEqual(a: Pft2Ref, b: Pft2Ref): boolean {
  return a.size === b.size && compareBytes(a.digest, b.digest) === 0;
}

/** Stable map key for a reference. */
export function pft2RefKey(ref: Pft2Ref): string {
  return `${pft2RefHex(ref)}/${ref.size}`;
}

export function checkNodeRefBounds(what: string, ref: Pft2Ref): void {
  if (ref.digest.length !== PFT2_DIGEST_BYTES) {
    throw invalidNode(`${what}: digest is ${ref.digest.length} bytes (want ${PFT2_DIGEST_BYTES})`);
  }
  if (ref.size < BigInt(PFT2_MIN_NODE_BYTES) || ref.size > BigInt(PFT2_MAX_NODE_BYTES)) {
    throw invalidNode(
      `${what}: node ref size ${ref.size} outside ${PFT2_MIN_NODE_BYTES}..${PFT2_MAX_NODE_BYTES}`
    );
  }
}

export function checkPackRefBounds(what: string, ref: Pft2Ref): void {
  if (ref.digest.length !== PFT2_DIGEST_BYTES) {
    throw invalidNode(`${what}: digest is ${ref.digest.length} bytes (want ${PFT2_DIGEST_BYTES})`);
  }
  if (ref.size < BigInt(PFT2_MIN_PACK_BYTES) || ref.size > BigInt(PFT2_MAX_PACK_BYTES)) {
    throw invalidNode(
      `${what}: pack ref size ${ref.size} outside ${PFT2_MIN_PACK_BYTES}..${PFT2_MAX_PACK_BYTES}`
    );
  }
  if (ref.size % BigInt(PFT2_CELL_BYTES) !== 0n) {
    throw invalidNode(`${what}: pack ref size ${ref.size} is not a multiple of ${PFT2_CELL_BYTES}`);
  }
}

/**
 * Verifies fetched bytes against their reference: exact size first (before
 * any decode work), then the digest over the complete bytes.
 */
export function verifyObjectBytes(ref: Pft2Ref, data: Uint8Array): void {
  if (BigInt(data.length) !== ref.size) {
    throw corrupt(`object ${pft2RefHex(ref)}: fetched ${data.length} bytes, advertised ${ref.size}`);
  }
  const digest = createHash("sha256").update(data).digest();
  if (compareBytes(digest, ref.digest) !== 0) {
    throw corrupt(`object ${pft2RefHex(ref)}: digest mismatch over ${data.length} bytes`);
  }
}

// ─── node value model ────────────────────────────────────────────────────────

export interface Pft2Root {
  rootInode: Pft2Ref;
  inodeIndex: Pft2Ref;
  /**
   * Monotonic allocation/observation high-water: every inode id ever live
   * in this filesystem's history — parked orphans included — is <=
   * maxInoSeen. Ids are never reused, so it never decreases; it is an upper
   * bound on the ids present in inodeIndex, NOT the exact maximum currently
   * present after deletion. Wire field 3 (formerly documented as max_ino;
   * tag and encoding unchanged).
   */
  maxInoSeen: bigint;
  inodeCount: bigint;
  direntCount: bigint;
  logicalBytes: bigint;
  features: bigint;
  /**
   * Ordered XATTR_LEAF references carrying attributes of live
   * filesystem-homed inodes. These references are part of the user closure,
   * so snapshots and forks preserve the metadata. Omitted on older roots and
   * when no named inode carries xattrs.
   */
  xattrLeaves?: Pft2Ref[];
}

export interface Pft2Inode {
  ino: bigint;
  kind: Pft2FileKind;
  mode: number;
  uid: number;
  gid: number;
  nlink: bigint;
  size: bigint;
  mtimeMs: bigint;
  ctimeMs: bigint;
  atimeMs: bigint;
  /**
   * Durable creation time (wire field 14). Stamped once, at inode creation,
   * from the journaled record's op time and never moved again — writes,
   * truncates, chmods, renames, and hard links all leave it alone. 0n is
   * canonically absent: every inode written by a pre-birthtime authority
   * decodes to 0n, and consumers must read 0n as "unknown", never as 1970.
   */
  birthtimeMs: bigint;
  /**
   * BSD file flags (Darwin st_flags / chflags(2)) as the full opaque uint32
   * the client sent (wire field 15). The format defines no bit policy —
   * masking which flags a mount may set is a client-side decision. 0 is
   * canonically absent and is what every pre-flags inode decodes to.
   */
  flags: number;
  directoryRoot?: Pft2Ref;
  extentRoot?: Pft2Ref;
  symlinkTarget: string;
}

export interface Pft2DirEntry {
  name: string;
  ino: bigint;
  kind: Pft2FileKind;
}

export interface Pft2DirectoryLeaf {
  entries: Pft2DirEntry[];
}

export interface Pft2DirectoryIndexChild {
  firstName: string;
  lastName: string;
  child: Pft2Ref;
  entryCount: bigint;
}

export interface Pft2DirectoryIndex {
  children: Pft2DirectoryIndexChild[];
}

export interface Pft2ExtentEntry {
  pageOffset: bigint;
  page: Pft2Ref;
}

export interface Pft2ExtentLeaf {
  entries: Pft2ExtentEntry[];
}

export interface Pft2ExtentIndexChild {
  firstPage: bigint;
  lastPage: bigint;
  child: Pft2Ref;
  entryCount: bigint;
}

export interface Pft2ExtentIndex {
  children: Pft2ExtentIndexChild[];
}

export interface Pft2InodeIndexEntry {
  ino: bigint;
  inode: Pft2Ref;
}

export interface Pft2InodeIndexLeaf {
  entries: Pft2InodeIndexEntry[];
}

export interface Pft2InodeIndexChild {
  firstIno: bigint;
  lastIno: bigint;
  child: Pft2Ref;
  entryCount: bigint;
}

export interface Pft2InodeIndexIndex {
  children: Pft2InodeIndexChild[];
}

export interface Pft2RecoveryRoot {
  asOfSeq: bigint;
  filesystemRoot: Pft2Ref;
  controlRoot?: Pft2Ref;
  orphanIndex?: Pft2Ref;
  inoNamespace: number;
  nextLocal: bigint;
  features: bigint;
  /**
   * Ordered XATTR_LEAF references carrying the LIVE per-inode extended
   * attributes at the cut, including parked open-after-unlink orphans. Root
   * carries the filesystem-homed subset for snapshots and forks.
   */
  xattrLeaves?: Pft2Ref[];
}

export interface Pft2CellRef {
  cellDigest: Uint8Array;
  object: Pft2Ref;
  objectOffset: bigint;
}

export interface Pft2DataPage {
  /** Exactly PFT2_CELLS_PER_PAGE slots; null slots are holes. */
  cells: (Pft2CellRef | null)[];
}

export interface Pft2ControlKindCount {
  kind: bigint;
  count: bigint;
}

export interface Pft2ControlEntry {
  key: Uint8Array;
  kind: bigint;
  value: Uint8Array;
}

export interface Pft2ControlLeaf {
  entries: Pft2ControlEntry[];
}

/** One live extended attribute of one inode. */
export interface Pft2XattrEntry {
  ino: bigint;
  /** 1..PFT2_MAX_XATTR_NAME_BYTES bytes of NUL-free UTF-8. */
  name: string;
  /** 0..PFT2_MAX_XATTR_VALUE_BYTES raw bytes. */
  value: Uint8Array;
}

/**
 * Extended-attribute entries sorted strictly ascending by (ino, name bytes).
 */
export interface Pft2XattrLeaf {
  entries: Pft2XattrEntry[];
}

export interface Pft2ControlIndexChild {
  firstKey: Uint8Array;
  lastKey: Uint8Array;
  child: Pft2Ref;
  entryCount: bigint;
}

export interface Pft2ControlIndex {
  children: Pft2ControlIndexChild[];
}

export interface Pft2ControlRoot {
  schema: bigint;
  mapRoot?: Pft2Ref;
  nextCheckoutEpoch: bigint;
  features: bigint;
  counts: Pft2ControlKindCount[];
  /**
   * Durable database-time floor at the anchor cut (ms; 0 = no time fact
   * ever journaled). Carried on the root — not a map entry — so it survives
   * cuts whose reduced control map is empty.
   */
  dbTimeFloorMs: bigint;
}

/** One decoded PFT2 object (discriminated union on kind). */
export type Pft2Node =
  | { kind: typeof Pft2NodeKind.Root; root: Pft2Root }
  | { kind: typeof Pft2NodeKind.Inode; inode: Pft2Inode }
  | { kind: typeof Pft2NodeKind.DirectoryLeaf; directoryLeaf: Pft2DirectoryLeaf }
  | { kind: typeof Pft2NodeKind.DirectoryIndex; directoryIndex: Pft2DirectoryIndex }
  | { kind: typeof Pft2NodeKind.ExtentLeaf; extentLeaf: Pft2ExtentLeaf }
  | { kind: typeof Pft2NodeKind.ExtentIndex; extentIndex: Pft2ExtentIndex }
  | { kind: typeof Pft2NodeKind.InodeIndexLeaf; inodeIndexLeaf: Pft2InodeIndexLeaf }
  | { kind: typeof Pft2NodeKind.InodeIndexIndex; inodeIndexIndex: Pft2InodeIndexIndex }
  | { kind: typeof Pft2NodeKind.RecoveryRoot; recoveryRoot: Pft2RecoveryRoot }
  | { kind: typeof Pft2NodeKind.DataPage; dataPage: Pft2DataPage }
  | { kind: typeof Pft2NodeKind.ControlRoot; controlRoot: Pft2ControlRoot }
  | { kind: typeof Pft2NodeKind.ControlLeaf; controlLeaf: Pft2ControlLeaf }
  | { kind: typeof Pft2NodeKind.ControlIndex; controlIndex: Pft2ControlIndex }
  | { kind: typeof Pft2NodeKind.XattrLeaf; xattrLeaf: Pft2XattrLeaf };

// ─── validation (applied on BOTH encode and decode) ─────────────────────────

function hasLoneSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return true;
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/**
 * Validates one directory entry name: 1..255 UTF-8 bytes, NUL- and
 * slash-free, not "." or "..", and well-formed (no lone surrogates — a lone
 * surrogate cannot round-trip through canonical UTF-8 bytes).
 */
export function validateEntryName(name: string): void {
  if (hasLoneSurrogate(name)) {
    throw invalidNode(`name contains a lone surrogate`);
  }
  const bytes = utf8Encode(name);
  if (bytes.length < 1 || bytes.length > PFT2_MAX_NAME_BYTES) {
    throw invalidNode(`name length ${bytes.length} outside 1..${PFT2_MAX_NAME_BYTES}`);
  }
  if (name === "." || name === "..") {
    throw invalidNode(`name ${JSON.stringify(name)} is reserved`);
  }
  for (const byte of bytes) {
    if (byte === 0 || byte === 0x2f) {
      throw invalidNode(`name contains NUL or '/'`);
    }
  }
}

function validateSymlinkTarget(target: string): void {
  if (hasLoneSurrogate(target)) {
    throw invalidNode(`symlink target contains a lone surrogate`);
  }
  const bytes = utf8Encode(target);
  if (bytes.length < 1 || bytes.length > PFT2_MAX_SYMLINK_TARGET_BYTES) {
    throw invalidNode(
      `symlink target length ${bytes.length} outside 1..${PFT2_MAX_SYMLINK_TARGET_BYTES}`
    );
  }
  for (const byte of bytes) {
    if (byte === 0) {
      throw invalidNode(`symlink target contains NUL`);
    }
  }
}

function validTimeMs(v: bigint): boolean {
  return v >= -PFT2_MAX_ABS_TIME_MS && v <= PFT2_MAX_ABS_TIME_MS;
}

function validFileKind(kind: number): kind is Pft2FileKind {
  return kind === Pft2FileKind.Regular || kind === Pft2FileKind.Directory || kind === Pft2FileKind.Symlink;
}

/** Compares two names by canonical UTF-8 bytes (the frozen PFT2 order). */
export function compareNames(a: string, b: string): number {
  return compareBytes(utf8Encode(a), utf8Encode(b));
}

function addCount(what: string, total: bigint, add: bigint): bigint {
  const sum = total + add;
  if (sum > PFT2_MAX_COUNT64) {
    throw invalidNode(`${what}: entry count overflows ${PFT2_MAX_COUNT64}`);
  }
  return sum;
}

function validateRoot(root: Pft2Root): void {
  checkNodeRefBounds("root.root_inode", root.rootInode);
  checkNodeRefBounds("root.inode_index", root.inodeIndex);
  if (root.maxInoSeen < PFT2_ROOT_INO || root.maxInoSeen > PFT2_MAX_INO) {
    throw invalidNode(`root: max_ino_seen ${root.maxInoSeen} outside ${PFT2_ROOT_INO}..${PFT2_MAX_INO}`);
  }
  if (root.inodeCount < 1n || root.inodeCount > PFT2_MAX_COUNT64) {
    throw invalidNode(`root: inode_count ${root.inodeCount} outside 1..${PFT2_MAX_COUNT64}`);
  }
  if (root.inodeCount > root.maxInoSeen) {
    throw invalidNode(`root: inode_count ${root.inodeCount} exceeds max_ino_seen ${root.maxInoSeen}`);
  }
  if (root.direntCount < 0n || root.direntCount > PFT2_MAX_COUNT64) {
    throw invalidNode(`root: dirent_count ${root.direntCount} exceeds ${PFT2_MAX_COUNT64}`);
  }
  if (root.logicalBytes < 0n || root.logicalBytes > PFT2_MAX_COUNT64) {
    throw invalidNode(`root: logical_bytes ${root.logicalBytes} exceeds ${PFT2_MAX_COUNT64}`);
  }
  if (root.features !== 0n) {
    throw invalidNode(`root: unknown feature bits ${root.features}`);
  }
  (root.xattrLeaves ?? []).forEach((ref, i) => {
    try {
      checkNodeRefBounds("root.xattr_leaves", ref);
    } catch (err) {
      throw invalidNode(`root xattr leaf ${i}: ${(err as Error).message}`);
    }
  });
}

function validateInode(inode: Pft2Inode): void {
  if (inode.ino < 1n || inode.ino > PFT2_MAX_INO) {
    throw invalidNode(`inode: ino ${inode.ino} outside 1..${PFT2_MAX_INO}`);
  }
  if (!Number.isInteger(inode.mode) || inode.mode < 0 || inode.mode > PFT2_MAX_MODE_BITS) {
    throw invalidNode(`inode ${inode.ino}: mode ${inode.mode} exceeds ${PFT2_MAX_MODE_BITS}`);
  }
  if (!Number.isInteger(inode.uid) || inode.uid < 0 || inode.uid > 0xffffffff) {
    throw invalidNode(`inode ${inode.ino}: uid out of range`);
  }
  if (!Number.isInteger(inode.gid) || inode.gid < 0 || inode.gid > 0xffffffff) {
    throw invalidNode(`inode ${inode.ino}: gid out of range`);
  }
  if (inode.nlink < 1n || inode.nlink > PFT2_MAX_NLINK) {
    throw invalidNode(`inode ${inode.ino}: nlink ${inode.nlink} outside 1..${PFT2_MAX_NLINK}`);
  }
  if (!validTimeMs(inode.mtimeMs) || !validTimeMs(inode.ctimeMs) || !validTimeMs(inode.atimeMs)) {
    throw invalidNode(`inode ${inode.ino}: timestamp outside ±${PFT2_MAX_ABS_TIME_MS} ms`);
  }
  if (!validTimeMs(inode.birthtimeMs)) {
    throw invalidNode(`inode ${inode.ino}: birth time outside ±${PFT2_MAX_ABS_TIME_MS} ms`);
  }
  // flags is the full uint32 the client sent: no bit is reserved or rejected
  // here (see the Pft2Inode.flags contract).
  if (!Number.isInteger(inode.flags) || inode.flags < 0 || inode.flags > 0xffffffff) {
    throw invalidNode(`inode ${inode.ino}: flags out of range`);
  }
  if (inode.size < 0n) {
    throw invalidNode(`inode ${inode.ino}: negative size`);
  }
  switch (inode.kind) {
    case Pft2FileKind.Regular: {
      if (inode.directoryRoot || inode.symlinkTarget !== "") {
        throw invalidNode(`inode ${inode.ino}: file carries directory or symlink state`);
      }
      if (inode.size > PFT2_MAX_LOGICAL_FILE_BYTES) {
        throw invalidNode(`inode ${inode.ino}: size ${inode.size} exceeds ${PFT2_MAX_LOGICAL_FILE_BYTES}`);
      }
      if (inode.extentRoot) {
        if (inode.size === 0n) {
          throw invalidNode(`inode ${inode.ino}: zero-size file carries an extent root`);
        }
        checkNodeRefBounds("inode.extent_root", inode.extentRoot);
      }
      break;
    }
    case Pft2FileKind.Directory: {
      if (inode.extentRoot || inode.symlinkTarget !== "") {
        throw invalidNode(`inode ${inode.ino}: directory carries extent or symlink state`);
      }
      if (inode.size !== 0n) {
        throw invalidNode(`inode ${inode.ino}: directory size must be 0 (got ${inode.size})`);
      }
      if (inode.directoryRoot) {
        checkNodeRefBounds("inode.directory_root", inode.directoryRoot);
      }
      break;
    }
    case Pft2FileKind.Symlink: {
      if (inode.directoryRoot || inode.extentRoot) {
        throw invalidNode(`inode ${inode.ino}: symlink carries directory or extent state`);
      }
      validateSymlinkTarget(inode.symlinkTarget);
      if (inode.size !== BigInt(utf8Encode(inode.symlinkTarget).length)) {
        throw invalidNode(`inode ${inode.ino}: symlink size ${inode.size} != target byte length`);
      }
      break;
    }
    default:
      throw invalidNode(`inode ${inode.ino}: unknown file kind ${(inode as Pft2Inode).kind}`);
  }
}

function validateDirectoryLeaf(leaf: Pft2DirectoryLeaf): void {
  if (leaf.entries.length < 1 || leaf.entries.length > PFT2_MAX_LEAF_ENTRIES) {
    throw invalidNode(`directory leaf: ${leaf.entries.length} entries outside 1..${PFT2_MAX_LEAF_ENTRIES}`);
  }
  leaf.entries.forEach((entry, i) => {
    validateEntryName(entry.name);
    if (entry.ino < 1n || entry.ino > PFT2_MAX_INO) {
      throw invalidNode(`directory leaf entry ${entry.name}: ino ${entry.ino} outside 1..${PFT2_MAX_INO}`);
    }
    if (!validFileKind(entry.kind)) {
      throw invalidNode(`directory leaf entry ${entry.name}: unknown kind`);
    }
    if (i > 0 && compareNames(leaf.entries[i - 1]!.name, entry.name) >= 0) {
      throw invalidNode(`directory leaf: entry ${i} name not strictly above previous`);
    }
  });
}

function validateDirectoryIndex(index: Pft2DirectoryIndex): void {
  if (
    index.children.length < PFT2_MIN_INDEX_CHILDREN ||
    index.children.length > PFT2_MAX_INDEX_CHILDREN
  ) {
    throw invalidNode(
      `directory index: ${index.children.length} children outside ${PFT2_MIN_INDEX_CHILDREN}..${PFT2_MAX_INDEX_CHILDREN}`
    );
  }
  let total = 0n;
  index.children.forEach((child, i) => {
    validateEntryName(child.firstName);
    validateEntryName(child.lastName);
    if (compareNames(child.firstName, child.lastName) > 0) {
      throw invalidNode(`directory index child ${i}: first name above last name`);
    }
    checkNodeRefBounds("directory index child", child.child);
    if (child.entryCount < 1n) {
      throw invalidNode(`directory index child ${i}: zero entry count`);
    }
    total = addCount("directory index", total, child.entryCount);
    if (i > 0 && compareNames(index.children[i - 1]!.lastName, child.firstName) >= 0) {
      throw invalidNode(`directory index child ${i}: first name not strictly above previous last`);
    }
  });
}

function validPageOffset(offset: bigint): boolean {
  return (
    offset >= 0n &&
    offset % BigInt(PFT2_PAGE_BYTES) === 0n &&
    offset <= PFT2_MAX_LOGICAL_FILE_BYTES - BigInt(PFT2_PAGE_BYTES)
  );
}

function validateExtentLeaf(leaf: Pft2ExtentLeaf): void {
  if (leaf.entries.length < 1 || leaf.entries.length > PFT2_MAX_LEAF_ENTRIES) {
    throw invalidNode(`extent leaf: ${leaf.entries.length} entries outside 1..${PFT2_MAX_LEAF_ENTRIES}`);
  }
  leaf.entries.forEach((entry, i) => {
    if (!validPageOffset(entry.pageOffset)) {
      throw invalidNode(`extent leaf entry ${i}: page offset ${entry.pageOffset} unaligned or out of range`);
    }
    checkNodeRefBounds("extent leaf page", entry.page);
    if (i > 0 && leaf.entries[i - 1]!.pageOffset >= entry.pageOffset) {
      throw invalidNode(`extent leaf: entry ${i} offset not strictly above previous`);
    }
  });
}

function validateExtentIndex(index: Pft2ExtentIndex): void {
  if (
    index.children.length < PFT2_MIN_INDEX_CHILDREN ||
    index.children.length > PFT2_MAX_INDEX_CHILDREN
  ) {
    throw invalidNode(
      `extent index: ${index.children.length} children outside ${PFT2_MIN_INDEX_CHILDREN}..${PFT2_MAX_INDEX_CHILDREN}`
    );
  }
  let total = 0n;
  index.children.forEach((child, i) => {
    if (!validPageOffset(child.firstPage) || !validPageOffset(child.lastPage)) {
      throw invalidNode(`extent index child ${i}: unaligned or out-of-range page bound`);
    }
    if (child.firstPage > child.lastPage) {
      throw invalidNode(`extent index child ${i}: first page above last page`);
    }
    checkNodeRefBounds("extent index child", child.child);
    if (child.entryCount < 1n) {
      throw invalidNode(`extent index child ${i}: zero entry count`);
    }
    // Pages are PageBytes-aligned and strictly ascending, so the range can
    // hold at most (lastPage-firstPage)/PageBytes + 1 entries (bigint
    // arithmetic; both operands validated above).
    if (child.entryCount - 1n > (child.lastPage - child.firstPage) / BigInt(PFT2_PAGE_BYTES)) {
      throw invalidNode(
        `extent index child ${i}: entry count ${child.entryCount} exceeds possible pages in ${child.firstPage}..${child.lastPage}`
      );
    }
    total = addCount("extent index", total, child.entryCount);
    if (i > 0 && index.children[i - 1]!.lastPage >= child.firstPage) {
      throw invalidNode(`extent index child ${i}: first page not strictly above previous last`);
    }
  });
}

function validateInodeIndexLeaf(leaf: Pft2InodeIndexLeaf): void {
  if (leaf.entries.length < 1 || leaf.entries.length > PFT2_MAX_LEAF_ENTRIES) {
    throw invalidNode(`inode index leaf: ${leaf.entries.length} entries outside 1..${PFT2_MAX_LEAF_ENTRIES}`);
  }
  leaf.entries.forEach((entry, i) => {
    if (entry.ino < 1n || entry.ino > PFT2_MAX_INO) {
      throw invalidNode(`inode index leaf entry ${i}: ino outside 1..${PFT2_MAX_INO}`);
    }
    checkNodeRefBounds("inode index leaf entry", entry.inode);
    if (i > 0 && leaf.entries[i - 1]!.ino >= entry.ino) {
      throw invalidNode(`inode index leaf: entry ${i} ino not strictly above previous`);
    }
  });
}

function validateInodeIndexIndex(index: Pft2InodeIndexIndex): void {
  if (
    index.children.length < PFT2_MIN_INDEX_CHILDREN ||
    index.children.length > PFT2_MAX_INDEX_CHILDREN
  ) {
    throw invalidNode(
      `inode index index: ${index.children.length} children outside ${PFT2_MIN_INDEX_CHILDREN}..${PFT2_MAX_INDEX_CHILDREN}`
    );
  }
  let total = 0n;
  index.children.forEach((child, i) => {
    if (child.firstIno < 1n || child.firstIno > PFT2_MAX_INO || child.lastIno < 1n || child.lastIno > PFT2_MAX_INO) {
      throw invalidNode(`inode index child ${i}: ino bound outside 1..${PFT2_MAX_INO}`);
    }
    if (child.firstIno > child.lastIno) {
      throw invalidNode(`inode index child ${i}: first ino above last ino`);
    }
    checkNodeRefBounds("inode index child", child.child);
    if (child.entryCount < 1n) {
      throw invalidNode(`inode index child ${i}: zero entry count`);
    }
    if (child.entryCount - 1n > child.lastIno - child.firstIno) {
      throw invalidNode(`inode index child ${i}: entry count exceeds ino range`);
    }
    total = addCount("inode index", total, child.entryCount);
    if (i > 0 && index.children[i - 1]!.lastIno >= child.firstIno) {
      throw invalidNode(`inode index child ${i}: first ino not strictly above previous last`);
    }
  });
}

function validateRecoveryRoot(root: Pft2RecoveryRoot): void {
  if (root.asOfSeq < 0n) {
    throw invalidNode(`recovery: negative as-of sequence`);
  }
  checkNodeRefBounds("recovery.filesystem_root", root.filesystemRoot);
  if (root.controlRoot) {
    checkNodeRefBounds("recovery.control_root", root.controlRoot);
  }
  if (root.orphanIndex) {
    checkNodeRefBounds("recovery.orphan_index", root.orphanIndex);
  }
  if (
    !Number.isInteger(root.inoNamespace) ||
    root.inoNamespace < 1 ||
    root.inoNamespace > PFT2_MAX_INODE_NAMESPACE
  ) {
    throw invalidNode(
      `recovery: inode namespace ${root.inoNamespace} outside 1..${PFT2_MAX_INODE_NAMESPACE}`
    );
  }
  if (root.nextLocal < 1n || root.nextLocal > PFT2_MAX_INODE_LOCAL_COUNTER + 1n) {
    throw invalidNode(
      `recovery: next local counter ${root.nextLocal} outside 1..${PFT2_MAX_INODE_LOCAL_COUNTER + 1n}`
    );
  }
  if (root.features !== 0n) {
    throw invalidNode(`recovery: unknown feature bits ${root.features}`);
  }
  (root.xattrLeaves ?? []).forEach((ref, i) => {
    try {
      checkNodeRefBounds("recovery.xattr_leaves", ref);
    } catch (err) {
      throw invalidNode(`recovery xattr leaf ${i}: ${(err as Error).message}`);
    }
  });
}

/** Validates one xattr name: 1..255 bytes of NUL-free, well-formed UTF-8. */
export function validateXattrName(name: string): void {
  if (hasLoneSurrogate(name)) {
    throw invalidNode(`xattr name contains a lone surrogate`);
  }
  const bytes = utf8Encode(name);
  if (bytes.length < 1 || bytes.length > PFT2_MAX_XATTR_NAME_BYTES) {
    throw invalidNode(`xattr name length ${bytes.length} outside 1..${PFT2_MAX_XATTR_NAME_BYTES}`);
  }
  for (const byte of bytes) {
    if (byte === 0) {
      throw invalidNode(`xattr name contains NUL`);
    }
  }
}

function validateXattrLeaf(leaf: Pft2XattrLeaf): void {
  if (leaf.entries.length < 1 || leaf.entries.length > PFT2_MAX_LEAF_ENTRIES) {
    throw invalidNode(`xattr leaf: ${leaf.entries.length} entries outside 1..${PFT2_MAX_LEAF_ENTRIES}`);
  }
  leaf.entries.forEach((entry, i) => {
    if (entry.ino < 1n || entry.ino > PFT2_MAX_INO) {
      throw invalidNode(`xattr leaf entry ${i}: ino ${entry.ino} outside 1..${PFT2_MAX_INO}`);
    }
    try {
      validateXattrName(entry.name);
    } catch (err) {
      throw invalidNode(`xattr leaf entry ${i}: ${(err as Error).message}`);
    }
    if (entry.value.length > PFT2_MAX_XATTR_VALUE_BYTES) {
      throw invalidNode(
        `xattr leaf entry ${i}: value length ${entry.value.length} exceeds ${PFT2_MAX_XATTR_VALUE_BYTES}`
      );
    }
    if (i > 0) {
      const prev = leaf.entries[i - 1]!;
      if (prev.ino > entry.ino || (prev.ino === entry.ino && compareNames(prev.name, entry.name) >= 0)) {
        throw invalidNode(
          `xattr leaf: entry ${i} (ino ${entry.ino}, ${JSON.stringify(entry.name)}) not strictly above (ino ${prev.ino}, ${JSON.stringify(prev.name)})`
        );
      }
    }
  });
}

function validateCellRef(cell: Pft2CellRef): void {
  if (cell.cellDigest.length !== PFT2_DIGEST_BYTES) {
    throw invalidNode(`cell ref: digest is ${cell.cellDigest.length} bytes`);
  }
  if (compareBytes(cell.cellDigest, PFT2_ZERO_CELL_DIGEST) === 0) {
    throw invalidNode(`cell ref: all-zero cell must be a hole, not a reference`);
  }
  checkPackRefBounds("cell ref object", cell.object);
  if (cell.objectOffset < 0n || cell.objectOffset % BigInt(PFT2_CELL_BYTES) !== 0n) {
    throw invalidNode(`cell ref: object offset ${cell.objectOffset} is not ${PFT2_CELL_BYTES}-aligned`);
  }
  if (cell.objectOffset > cell.object.size - BigInt(PFT2_CELL_BYTES)) {
    throw invalidNode(`cell ref: slice exceeds object size ${cell.object.size}`);
  }
}

function validateDataPage(page: Pft2DataPage): void {
  if (page.cells.length !== PFT2_CELLS_PER_PAGE) {
    throw invalidNode(`data page: ${page.cells.length} cell slots (want ${PFT2_CELLS_PER_PAGE})`);
  }
  let present = 0;
  page.cells.forEach((cell, i) => {
    if (!cell) {
      return;
    }
    present += 1;
    try {
      validateCellRef(cell);
    } catch (error) {
      throw invalidNode(`data page cell ${i}: ${(error as Error).message}`);
    }
  });
  if (present === 0) {
    throw invalidNode(`data page: all-hole page must be omitted, not encoded`);
  }
}

function validateControlKey(what: string, key: Uint8Array): void {
  if (key.length < 1 || key.length > PFT2_MAX_CONTROL_KEY_BYTES) {
    throw invalidNode(`${what}: key length ${key.length} outside 1..${PFT2_MAX_CONTROL_KEY_BYTES}`);
  }
}

function validateControlLeaf(leaf: Pft2ControlLeaf): void {
  if (leaf.entries.length < 1 || leaf.entries.length > PFT2_MAX_LEAF_ENTRIES) {
    throw invalidNode(`control leaf: ${leaf.entries.length} entries outside 1..${PFT2_MAX_LEAF_ENTRIES}`);
  }
  leaf.entries.forEach((entry, i) => {
    validateControlKey("control leaf entry", entry.key);
    if (entry.kind < 1n || entry.kind > PFT2_MAX_CONTROL_ENTRY_KIND) {
      throw invalidNode(`control leaf entry ${i}: kind outside 1..${PFT2_MAX_CONTROL_ENTRY_KIND}`);
    }
    if (entry.value.length > PFT2_MAX_CONTROL_VALUE_BYTES) {
      throw invalidNode(`control leaf entry ${i}: value length exceeds ${PFT2_MAX_CONTROL_VALUE_BYTES}`);
    }
    if (i > 0 && compareBytes(leaf.entries[i - 1]!.key, entry.key) >= 0) {
      throw invalidNode(`control leaf: entry ${i} key not strictly above previous`);
    }
  });
}

function validateControlIndex(index: Pft2ControlIndex): void {
  if (
    index.children.length < PFT2_MIN_INDEX_CHILDREN ||
    index.children.length > PFT2_MAX_INDEX_CHILDREN
  ) {
    throw invalidNode(
      `control index: ${index.children.length} children outside ${PFT2_MIN_INDEX_CHILDREN}..${PFT2_MAX_INDEX_CHILDREN}`
    );
  }
  let total = 0n;
  index.children.forEach((child, i) => {
    validateControlKey("control index child first", child.firstKey);
    validateControlKey("control index child last", child.lastKey);
    if (compareBytes(child.firstKey, child.lastKey) > 0) {
      throw invalidNode(`control index child ${i}: first key above last key`);
    }
    checkNodeRefBounds("control index child", child.child);
    if (child.entryCount < 1n) {
      throw invalidNode(`control index child ${i}: zero entry count`);
    }
    total = addCount("control index", total, child.entryCount);
    if (i > 0 && compareBytes(index.children[i - 1]!.lastKey, child.firstKey) >= 0) {
      throw invalidNode(`control index child ${i}: first key not strictly above previous last`);
    }
  });
}

function validateControlRoot(root: Pft2ControlRoot): void {
  if (root.schema !== PFT2_CONTROL_SCHEMA_VERSION) {
    throw invalidNode(`control root: schema ${root.schema} is not ${PFT2_CONTROL_SCHEMA_VERSION}`);
  }
  if (root.mapRoot) {
    checkNodeRefBounds("control root map", root.mapRoot);
  }
  if (root.nextCheckoutEpoch < 1n || root.nextCheckoutEpoch > PFT2_MAX_CHECKOUT_EPOCH) {
    throw invalidNode(`control root: next checkout epoch outside 1..${PFT2_MAX_CHECKOUT_EPOCH}`);
  }
  if (root.features !== 0n) {
    throw invalidNode(`control root: unknown feature bits ${root.features}`);
  }
  if ((root.mapRoot === undefined) !== (root.counts.length === 0)) {
    throw invalidNode(`control root: counts must be present exactly when the map is non-empty`);
  }
  let total = 0n;
  root.counts.forEach((count, i) => {
    if (count.kind < 1n || count.kind > PFT2_MAX_CONTROL_ENTRY_KIND) {
      throw invalidNode(`control root count ${i}: kind outside 1..${PFT2_MAX_CONTROL_ENTRY_KIND}`);
    }
    if (count.count < 1n) {
      throw invalidNode(`control root count ${i}: zero count`);
    }
    total = addCount("control root", total, count.count);
    if (i > 0 && root.counts[i - 1]!.kind >= count.kind) {
      throw invalidNode(`control root count ${i}: kind not strictly above previous`);
    }
  });
  if (root.dbTimeFloorMs < 0n || root.dbTimeFloorMs > PFT2_MAX_ABS_TIME_MS) {
    throw invalidNode(`control root: database-time floor outside 0..${PFT2_MAX_ABS_TIME_MS} ms`);
  }
}

/** Checks a node's structural invariants (same rules as the Go validator). */
export function validatePft2Node(node: Pft2Node): void {
  switch (node.kind) {
    case Pft2NodeKind.Root:
      return validateRoot(node.root);
    case Pft2NodeKind.Inode:
      return validateInode(node.inode);
    case Pft2NodeKind.DirectoryLeaf:
      return validateDirectoryLeaf(node.directoryLeaf);
    case Pft2NodeKind.DirectoryIndex:
      return validateDirectoryIndex(node.directoryIndex);
    case Pft2NodeKind.ExtentLeaf:
      return validateExtentLeaf(node.extentLeaf);
    case Pft2NodeKind.ExtentIndex:
      return validateExtentIndex(node.extentIndex);
    case Pft2NodeKind.InodeIndexLeaf:
      return validateInodeIndexLeaf(node.inodeIndexLeaf);
    case Pft2NodeKind.InodeIndexIndex:
      return validateInodeIndexIndex(node.inodeIndexIndex);
    case Pft2NodeKind.RecoveryRoot:
      return validateRecoveryRoot(node.recoveryRoot);
    case Pft2NodeKind.DataPage:
      return validateDataPage(node.dataPage);
    case Pft2NodeKind.ControlRoot:
      return validateControlRoot(node.controlRoot);
    case Pft2NodeKind.ControlLeaf:
      return validateControlLeaf(node.controlLeaf);
    case Pft2NodeKind.ControlIndex:
      return validateControlIndex(node.controlIndex);
    case Pft2NodeKind.XattrLeaf:
      return validateXattrLeaf(node.xattrLeaf);
    default: {
      const kind = (node as { kind: number }).kind;
      throw invalidNode(`unknown kind ${kind}`);
    }
  }
}

/** Persists one encoded metadata node (reference computed by the writer). */
export interface Pft2NodeSink {
  putNode(ref: Pft2Ref, encoded: Uint8Array): void;
}

/** Persists one packed immutable data object. */
export interface Pft2PackSink {
  putPack(ref: Pft2Ref, data: Uint8Array): void;
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
