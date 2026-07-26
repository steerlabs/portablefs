/**
 * Strict canonical PFT2 codec — the TypeScript mirror of
 * vcs/internal/pft2/codec.go. Field numbers, bounds, and rejection rules are
 * frozen and identical; any accepted object re-encodes to identical bytes in
 * both languages.
 */
import {
  PFT2_CELLS_PER_PAGE,
  PFT2_DIGEST_BYTES,
  PFT2_MAGIC,
  PFT2_MAX_CONTROL_KEY_BYTES,
  PFT2_MAX_CONTROL_VALUE_BYTES,
  PFT2_MAX_CONTROL_ENTRY_KIND,
  PFT2_MAX_LEAF_ENTRIES,
  PFT2_MAX_NAME_BYTES,
  PFT2_MAX_NODE_BYTES,
  PFT2_MAX_SYMLINK_TARGET_BYTES,
  PFT2_MAX_XATTR_NAME_BYTES,
  PFT2_MAX_XATTR_VALUE_BYTES,
  PFT2_MIN_NODE_BYTES,
  Pft2FileKind,
  Pft2NodeKind,
  corrupt,
  invalidNode,
  validatePft2Node,
  type Pft2CellRef,
  type Pft2ControlEntry,
  type Pft2ControlIndex,
  type Pft2ControlIndexChild,
  type Pft2ControlKindCount,
  type Pft2ControlLeaf,
  type Pft2ControlRoot,
  type Pft2DataPage,
  type Pft2DirEntry,
  type Pft2DirectoryIndex,
  type Pft2DirectoryIndexChild,
  type Pft2DirectoryLeaf,
  type Pft2ExtentEntry,
  type Pft2ExtentIndex,
  type Pft2ExtentIndexChild,
  type Pft2ExtentLeaf,
  type Pft2Inode,
  type Pft2InodeIndexEntry,
  type Pft2InodeIndexChild,
  type Pft2InodeIndexIndex,
  type Pft2InodeIndexLeaf,
  type Pft2Node,
  type Pft2XattrEntry,
  type Pft2XattrLeaf,
  type Pft2RecoveryRoot,
  type Pft2Ref,
  type Pft2Root,
} from "./types.js";
import {
  ByteWriter,
  WIRE_TYPE_BYTES,
  WIRE_TYPE_VARINT,
  WireReader,
  appendBytes,
  appendSint,
  appendUint,
  utf8Encode,
} from "./wire.js";

// ─── encoding ────────────────────────────────────────────────────────────────

function appendString(out: ByteWriter, field: number, value: string): void {
  appendBytes(out, field, utf8Encode(value));
}

function encodeRefBody(ref: Pft2Ref): Uint8Array {
  const out = new ByteWriter();
  appendBytes(out, 1, ref.digest);
  appendUint(out, 2, ref.size);
  return out.finish();
}

function appendRef(out: ByteWriter, field: number, ref: Pft2Ref): void {
  appendBytes(out, field, encodeRefBody(ref));
}

function appendOptionalRef(out: ByteWriter, field: number, ref: Pft2Ref | undefined): void {
  if (ref) {
    appendRef(out, field, ref);
  }
}

function encodeRoot(root: Pft2Root): Uint8Array {
  const out = new ByteWriter();
  appendRef(out, 1, root.rootInode);
  appendRef(out, 2, root.inodeIndex);
  appendUint(out, 3, root.maxInoSeen);
  appendUint(out, 4, root.inodeCount);
  appendUint(out, 5, root.direntCount);
  appendUint(out, 6, root.logicalBytes);
  appendUint(out, 7, root.features);
  for (const ref of root.xattrLeaves ?? []) {
    appendRef(out, 8, ref);
  }
  return out.finish();
}

function encodeInode(inode: Pft2Inode): Uint8Array {
  const out = new ByteWriter();
  appendUint(out, 1, inode.ino);
  appendUint(out, 2, BigInt(inode.kind));
  appendUint(out, 3, BigInt(inode.mode));
  appendUint(out, 4, BigInt(inode.uid));
  appendUint(out, 5, BigInt(inode.gid));
  appendUint(out, 6, inode.nlink);
  appendUint(out, 7, inode.size);
  appendSint(out, 8, inode.mtimeMs);
  appendSint(out, 9, inode.ctimeMs);
  appendSint(out, 10, inode.atimeMs);
  appendOptionalRef(out, 11, inode.directoryRoot);
  appendOptionalRef(out, 12, inode.extentRoot);
  appendString(out, 13, inode.symlinkTarget);
  return out.finish();
}

export function encodeDirEntryBody(entry: Pft2DirEntry): Uint8Array {
  const out = new ByteWriter();
  appendString(out, 1, entry.name);
  appendUint(out, 2, entry.ino);
  appendUint(out, 3, BigInt(entry.kind));
  return out.finish();
}

function encodeDirectoryLeaf(leaf: Pft2DirectoryLeaf): Uint8Array {
  const out = new ByteWriter();
  for (const entry of leaf.entries) {
    appendBytes(out, 1, encodeDirEntryBody(entry));
  }
  return out.finish();
}

export function encodeDirectoryIndexChildBody(child: Pft2DirectoryIndexChild): Uint8Array {
  const out = new ByteWriter();
  appendString(out, 1, child.firstName);
  appendString(out, 2, child.lastName);
  appendRef(out, 3, child.child);
  appendUint(out, 4, child.entryCount);
  return out.finish();
}

function encodeDirectoryIndex(index: Pft2DirectoryIndex): Uint8Array {
  const out = new ByteWriter();
  for (const child of index.children) {
    appendBytes(out, 1, encodeDirectoryIndexChildBody(child));
  }
  return out.finish();
}

export function encodeExtentEntryBody(entry: Pft2ExtentEntry): Uint8Array {
  const out = new ByteWriter();
  appendUint(out, 1, entry.pageOffset);
  appendRef(out, 2, entry.page);
  return out.finish();
}

function encodeExtentLeaf(leaf: Pft2ExtentLeaf): Uint8Array {
  const out = new ByteWriter();
  for (const entry of leaf.entries) {
    appendBytes(out, 1, encodeExtentEntryBody(entry));
  }
  return out.finish();
}

export function encodeExtentIndexChildBody(child: Pft2ExtentIndexChild): Uint8Array {
  const out = new ByteWriter();
  appendUint(out, 1, child.firstPage);
  appendUint(out, 2, child.lastPage);
  appendRef(out, 3, child.child);
  appendUint(out, 4, child.entryCount);
  return out.finish();
}

function encodeExtentIndex(index: Pft2ExtentIndex): Uint8Array {
  const out = new ByteWriter();
  for (const child of index.children) {
    appendBytes(out, 1, encodeExtentIndexChildBody(child));
  }
  return out.finish();
}

export function encodeInodeIndexEntryBody(entry: Pft2InodeIndexEntry): Uint8Array {
  const out = new ByteWriter();
  appendUint(out, 1, entry.ino);
  appendRef(out, 2, entry.inode);
  return out.finish();
}

function encodeInodeIndexLeaf(leaf: Pft2InodeIndexLeaf): Uint8Array {
  const out = new ByteWriter();
  for (const entry of leaf.entries) {
    appendBytes(out, 1, encodeInodeIndexEntryBody(entry));
  }
  return out.finish();
}

export function encodeInodeIndexChildBody(child: Pft2InodeIndexChild): Uint8Array {
  const out = new ByteWriter();
  appendUint(out, 1, child.firstIno);
  appendUint(out, 2, child.lastIno);
  appendRef(out, 3, child.child);
  appendUint(out, 4, child.entryCount);
  return out.finish();
}

function encodeInodeIndexIndex(index: Pft2InodeIndexIndex): Uint8Array {
  const out = new ByteWriter();
  for (const child of index.children) {
    appendBytes(out, 1, encodeInodeIndexChildBody(child));
  }
  return out.finish();
}

function encodeRecoveryRoot(root: Pft2RecoveryRoot): Uint8Array {
  const out = new ByteWriter();
  appendUint(out, 1, root.asOfSeq);
  appendRef(out, 2, root.filesystemRoot);
  appendOptionalRef(out, 3, root.controlRoot);
  appendOptionalRef(out, 4, root.orphanIndex);
  appendUint(out, 5, BigInt(root.inoNamespace));
  appendUint(out, 6, root.nextLocal);
  appendUint(out, 7, root.features);
  for (const ref of root.xattrLeaves ?? []) {
    appendRef(out, 8, ref);
  }
  return out.finish();
}

function encodeXattrEntryBody(entry: Pft2XattrEntry): Uint8Array {
  const out = new ByteWriter();
  appendUint(out, 1, entry.ino);
  appendBytes(out, 2, utf8Encode(entry.name));
  appendBytes(out, 3, entry.value);
  return out.finish();
}

function encodeXattrLeaf(leaf: Pft2XattrLeaf): Uint8Array {
  const out = new ByteWriter();
  for (const entry of leaf.entries) {
    appendBytes(out, 1, encodeXattrEntryBody(entry));
  }
  return out.finish();
}

function encodeDataPage(page: Pft2DataPage): Uint8Array {
  const out = new ByteWriter();
  page.cells.forEach((cell, i) => {
    if (!cell) {
      return;
    }
    const body = new ByteWriter();
    appendBytes(body, 1, cell.cellDigest);
    appendRef(body, 2, cell.object);
    appendUint(body, 3, cell.objectOffset);
    appendBytes(out, i + 1, body.finish());
  });
  return out.finish();
}

function encodeControlRoot(root: Pft2ControlRoot): Uint8Array {
  const out = new ByteWriter();
  appendUint(out, 1, root.schema);
  appendOptionalRef(out, 2, root.mapRoot);
  appendUint(out, 3, root.nextCheckoutEpoch);
  appendUint(out, 4, root.features);
  for (const count of root.counts) {
    const body = new ByteWriter();
    appendUint(body, 1, count.kind);
    appendUint(body, 2, count.count);
    appendBytes(out, 5, body.finish());
  }
  appendUint(out, 6, root.dbTimeFloorMs);
  return out.finish();
}

export function encodeControlEntryBody(entry: Pft2ControlEntry): Uint8Array {
  const out = new ByteWriter();
  appendBytes(out, 1, entry.key);
  appendUint(out, 2, entry.kind);
  appendBytes(out, 3, entry.value);
  return out.finish();
}

function encodeControlLeaf(leaf: Pft2ControlLeaf): Uint8Array {
  const out = new ByteWriter();
  for (const entry of leaf.entries) {
    appendBytes(out, 1, encodeControlEntryBody(entry));
  }
  return out.finish();
}

export function encodeControlIndexChildBody(child: Pft2ControlIndexChild): Uint8Array {
  const out = new ByteWriter();
  appendBytes(out, 1, child.firstKey);
  appendBytes(out, 2, child.lastKey);
  appendRef(out, 3, child.child);
  appendUint(out, 4, child.entryCount);
  return out.finish();
}

function encodeControlIndex(index: Pft2ControlIndex): Uint8Array {
  const out = new ByteWriter();
  for (const child of index.children) {
    appendBytes(out, 1, encodeControlIndexChildBody(child));
  }
  return out.finish();
}

function encodeArm(node: Pft2Node): Uint8Array {
  switch (node.kind) {
    case Pft2NodeKind.Root:
      return encodeRoot(node.root);
    case Pft2NodeKind.Inode:
      return encodeInode(node.inode);
    case Pft2NodeKind.DirectoryLeaf:
      return encodeDirectoryLeaf(node.directoryLeaf);
    case Pft2NodeKind.DirectoryIndex:
      return encodeDirectoryIndex(node.directoryIndex);
    case Pft2NodeKind.ExtentLeaf:
      return encodeExtentLeaf(node.extentLeaf);
    case Pft2NodeKind.ExtentIndex:
      return encodeExtentIndex(node.extentIndex);
    case Pft2NodeKind.InodeIndexLeaf:
      return encodeInodeIndexLeaf(node.inodeIndexLeaf);
    case Pft2NodeKind.InodeIndexIndex:
      return encodeInodeIndexIndex(node.inodeIndexIndex);
    case Pft2NodeKind.RecoveryRoot:
      return encodeRecoveryRoot(node.recoveryRoot);
    case Pft2NodeKind.DataPage:
      return encodeDataPage(node.dataPage);
    case Pft2NodeKind.ControlRoot:
      return encodeControlRoot(node.controlRoot);
    case Pft2NodeKind.ControlLeaf:
      return encodeControlLeaf(node.controlLeaf);
    case Pft2NodeKind.ControlIndex:
      return encodeControlIndex(node.controlIndex);
    case Pft2NodeKind.XattrLeaf:
      return encodeXattrLeaf(node.xattrLeaf);
  }
}

/**
 * Encodes a validated node into its unique canonical PFT2 byte string
 * ("PFT2" magic plus strict body).
 */
export function encodePft2Node(node: Pft2Node): Uint8Array {
  validatePft2Node(node);
  const out = new ByteWriter();
  out.pushBytes(PFT2_MAGIC);
  appendUint(out, 1, BigInt(node.kind));
  appendBytes(out, node.kind + 1, encodeArm(node));
  const encoded = out.finish();
  if (encoded.length > PFT2_MAX_NODE_BYTES) {
    throw invalidNode(`encoded node is ${encoded.length} bytes (max ${PFT2_MAX_NODE_BYTES})`);
  }
  return encoded;
}

// ─── decoding ────────────────────────────────────────────────────────────────

function decodeRefBody(what: string, body: Uint8Array): Pft2Ref {
  const reader = new WireReader(what, body);
  let digest: Uint8Array | undefined;
  let size = 0n;
  for (;;) {
    const header = reader.next();
    if (!header) {
      break;
    }
    reader.require(header.field);
    if (header.field === 1 && header.wireType === WIRE_TYPE_BYTES) {
      const raw = reader.bytes(header.field, PFT2_DIGEST_BYTES);
      if (raw.length !== PFT2_DIGEST_BYTES) {
        throw reader.malformed(`digest is ${raw.length} bytes (want ${PFT2_DIGEST_BYTES})`);
      }
      digest = new Uint8Array(raw);
    } else if (header.field === 2 && header.wireType === WIRE_TYPE_VARINT) {
      size = reader.uint(header.field);
    } else {
      throw reader.rejectUnknown(header.field);
    }
  }
  if (!digest) {
    throw reader.malformed("missing digest");
  }
  if (size === 0n) {
    throw reader.malformed("missing size");
  }
  return { digest, size };
}

type FieldHandler = (reader: WireReader, field: number, wireType: number) => boolean;

/** Drives one message: handler returns false to reject the field. */
function decodeMessage(what: string, body: Uint8Array, repeatedFields: ReadonlySet<number>, handle: FieldHandler): void {
  const reader = new WireReader(what, body);
  for (;;) {
    const header = reader.next();
    if (!header) {
      return;
    }
    if (repeatedFields.has(header.field)) {
      reader.requireRepeated(header.field);
    } else {
      reader.require(header.field);
    }
    if (!handle(reader, header.field, header.wireType)) {
      throw reader.rejectUnknown(header.field);
    }
  }
}

const noRepeats: ReadonlySet<number> = new Set();
const repeatField1: ReadonlySet<number> = new Set([1]);

function decodeRoot(body: Uint8Array): Pft2Root {
  const root: Pft2Root = {
    rootInode: undefined as unknown as Pft2Ref,
    inodeIndex: undefined as unknown as Pft2Ref,
    maxInoSeen: 0n,
    inodeCount: 0n,
    direntCount: 0n,
    logicalBytes: 0n,
    features: 0n,
  };
  decodeMessage("pft2 root", body, rootRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_BYTES) {
      root.rootInode = decodeRefBody("pft2 root inode ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else if (field === 2 && wireType === WIRE_TYPE_BYTES) {
      root.inodeIndex = decodeRefBody("pft2 root inode index ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else if (field === 3 && wireType === WIRE_TYPE_VARINT) {
      root.maxInoSeen = reader.uint(field);
    } else if (field === 4 && wireType === WIRE_TYPE_VARINT) {
      root.inodeCount = reader.uint(field);
    } else if (field === 5 && wireType === WIRE_TYPE_VARINT) {
      root.direntCount = reader.uint(field);
    } else if (field === 6 && wireType === WIRE_TYPE_VARINT) {
      root.logicalBytes = reader.uint(field);
    } else if (field === 7 && wireType === WIRE_TYPE_VARINT) {
      root.features = reader.uint(field);
    } else if (field === 8 && wireType === WIRE_TYPE_BYTES) {
      const ref = decodeRefBody(
        "pft2 root xattr leaf ref",
        reader.bytes(field, PFT2_MAX_NODE_BYTES)
      );
      (root.xattrLeaves ??= []).push(ref);
    } else {
      return false;
    }
    return true;
  });
  if (!root.rootInode || !root.inodeIndex) {
    throw invalidNode("root: missing required references");
  }
  return root;
}

const rootRepeats: ReadonlySet<number> = new Set([8]);

function decodeFileKind(reader: WireReader, field: number): Pft2FileKind {
  const value = reader.uint(field);
  if (value > BigInt(Pft2FileKind.Symlink)) {
    throw reader.malformed(`unknown file kind ${value}`);
  }
  return Number(value) as Pft2FileKind;
}

function decodeInode(body: Uint8Array): Pft2Inode {
  const inode: Pft2Inode = {
    ino: 0n,
    kind: 0 as Pft2FileKind,
    mode: 0,
    uid: 0,
    gid: 0,
    nlink: 0n,
    size: 0n,
    mtimeMs: 0n,
    ctimeMs: 0n,
    atimeMs: 0n,
    symlinkTarget: "",
  };
  decodeMessage("pft2 inode", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      inode.ino = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_VARINT) {
      inode.kind = decodeFileKind(reader, field);
    } else if (field === 3 && wireType === WIRE_TYPE_VARINT) {
      inode.mode = reader.uint32(field);
    } else if (field === 4 && wireType === WIRE_TYPE_VARINT) {
      inode.uid = reader.uint32(field);
    } else if (field === 5 && wireType === WIRE_TYPE_VARINT) {
      inode.gid = reader.uint32(field);
    } else if (field === 6 && wireType === WIRE_TYPE_VARINT) {
      inode.nlink = reader.uint(field);
    } else if (field === 7 && wireType === WIRE_TYPE_VARINT) {
      inode.size = reader.uint(field);
    } else if (field === 8 && wireType === WIRE_TYPE_VARINT) {
      inode.mtimeMs = reader.sint(field);
    } else if (field === 9 && wireType === WIRE_TYPE_VARINT) {
      inode.ctimeMs = reader.sint(field);
    } else if (field === 10 && wireType === WIRE_TYPE_VARINT) {
      inode.atimeMs = reader.sint(field);
    } else if (field === 11 && wireType === WIRE_TYPE_BYTES) {
      inode.directoryRoot = decodeRefBody(
        "pft2 inode directory root ref",
        reader.bytes(field, PFT2_MAX_NODE_BYTES)
      );
    } else if (field === 12 && wireType === WIRE_TYPE_BYTES) {
      inode.extentRoot = decodeRefBody(
        "pft2 inode extent root ref",
        reader.bytes(field, PFT2_MAX_NODE_BYTES)
      );
    } else if (field === 13 && wireType === WIRE_TYPE_BYTES) {
      inode.symlinkTarget = reader.string(field, PFT2_MAX_SYMLINK_TARGET_BYTES);
    } else {
      return false;
    }
    return true;
  });
  return inode;
}

/** Decodes a repeated-message body (field 1 only) with a count bound. */
function decodeRepeated(what: string, body: Uint8Array, decodeElement: (msg: Uint8Array) => void): void {
  let count = 0;
  decodeMessage(what, body, repeatField1, (reader, field, wireType) => {
    if (field !== 1 || wireType !== WIRE_TYPE_BYTES) {
      return false;
    }
    const msg = reader.bytes(field, PFT2_MAX_NODE_BYTES);
    count += 1;
    if (count > PFT2_MAX_LEAF_ENTRIES) {
      throw reader.malformed(`more than ${PFT2_MAX_LEAF_ENTRIES} elements`);
    }
    decodeElement(msg);
    return true;
  });
}

function decodeDirEntry(body: Uint8Array): Pft2DirEntry {
  const entry: Pft2DirEntry = { name: "", ino: 0n, kind: 0 as Pft2FileKind };
  decodeMessage("pft2 dir entry", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_BYTES) {
      entry.name = reader.string(field, PFT2_MAX_NAME_BYTES);
    } else if (field === 2 && wireType === WIRE_TYPE_VARINT) {
      entry.ino = reader.uint(field);
    } else if (field === 3 && wireType === WIRE_TYPE_VARINT) {
      entry.kind = decodeFileKind(reader, field);
    } else {
      return false;
    }
    return true;
  });
  return entry;
}

function decodeDirectoryLeaf(body: Uint8Array): Pft2DirectoryLeaf {
  const leaf: Pft2DirectoryLeaf = { entries: [] };
  decodeRepeated("pft2 directory leaf", body, (msg) => {
    leaf.entries.push(decodeDirEntry(msg));
  });
  return leaf;
}

function decodeDirectoryIndexChild(body: Uint8Array): Pft2DirectoryIndexChild {
  const child: Pft2DirectoryIndexChild = {
    firstName: "",
    lastName: "",
    child: undefined as unknown as Pft2Ref,
    entryCount: 0n,
  };
  decodeMessage("pft2 directory index child", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_BYTES) {
      child.firstName = reader.string(field, PFT2_MAX_NAME_BYTES);
    } else if (field === 2 && wireType === WIRE_TYPE_BYTES) {
      child.lastName = reader.string(field, PFT2_MAX_NAME_BYTES);
    } else if (field === 3 && wireType === WIRE_TYPE_BYTES) {
      child.child = decodeRefBody("pft2 directory index child ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else if (field === 4 && wireType === WIRE_TYPE_VARINT) {
      child.entryCount = reader.uint(field);
    } else {
      return false;
    }
    return true;
  });
  if (!child.child) {
    throw invalidNode("directory index child: missing child reference");
  }
  return child;
}

function decodeDirectoryIndex(body: Uint8Array): Pft2DirectoryIndex {
  const index: Pft2DirectoryIndex = { children: [] };
  decodeRepeated("pft2 directory index", body, (msg) => {
    index.children.push(decodeDirectoryIndexChild(msg));
  });
  return index;
}

function decodeExtentEntry(body: Uint8Array): Pft2ExtentEntry {
  const entry: Pft2ExtentEntry = { pageOffset: 0n, page: undefined as unknown as Pft2Ref };
  decodeMessage("pft2 extent entry", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      entry.pageOffset = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_BYTES) {
      entry.page = decodeRefBody("pft2 extent page ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else {
      return false;
    }
    return true;
  });
  if (!entry.page) {
    throw invalidNode("extent entry: missing page reference");
  }
  return entry;
}

function decodeExtentLeaf(body: Uint8Array): Pft2ExtentLeaf {
  const leaf: Pft2ExtentLeaf = { entries: [] };
  decodeRepeated("pft2 extent leaf", body, (msg) => {
    leaf.entries.push(decodeExtentEntry(msg));
  });
  return leaf;
}

function decodeExtentIndexChild(body: Uint8Array): Pft2ExtentIndexChild {
  const child: Pft2ExtentIndexChild = {
    firstPage: 0n,
    lastPage: 0n,
    child: undefined as unknown as Pft2Ref,
    entryCount: 0n,
  };
  decodeMessage("pft2 extent index child", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      child.firstPage = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_VARINT) {
      child.lastPage = reader.uint(field);
    } else if (field === 3 && wireType === WIRE_TYPE_BYTES) {
      child.child = decodeRefBody("pft2 extent index child ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else if (field === 4 && wireType === WIRE_TYPE_VARINT) {
      child.entryCount = reader.uint(field);
    } else {
      return false;
    }
    return true;
  });
  if (!child.child) {
    throw invalidNode("extent index child: missing child reference");
  }
  return child;
}

function decodeExtentIndex(body: Uint8Array): Pft2ExtentIndex {
  const index: Pft2ExtentIndex = { children: [] };
  decodeRepeated("pft2 extent index", body, (msg) => {
    index.children.push(decodeExtentIndexChild(msg));
  });
  return index;
}

function decodeInodeIndexEntry(body: Uint8Array): Pft2InodeIndexEntry {
  const entry: Pft2InodeIndexEntry = { ino: 0n, inode: undefined as unknown as Pft2Ref };
  decodeMessage("pft2 inode index entry", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      entry.ino = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_BYTES) {
      entry.inode = decodeRefBody("pft2 inode index inode ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else {
      return false;
    }
    return true;
  });
  if (!entry.inode) {
    throw invalidNode("inode index entry: missing inode reference");
  }
  return entry;
}

function decodeInodeIndexLeaf(body: Uint8Array): Pft2InodeIndexLeaf {
  const leaf: Pft2InodeIndexLeaf = { entries: [] };
  decodeRepeated("pft2 inode index leaf", body, (msg) => {
    leaf.entries.push(decodeInodeIndexEntry(msg));
  });
  return leaf;
}

function decodeInodeIndexChild(body: Uint8Array): Pft2InodeIndexChild {
  const child: Pft2InodeIndexChild = {
    firstIno: 0n,
    lastIno: 0n,
    child: undefined as unknown as Pft2Ref,
    entryCount: 0n,
  };
  decodeMessage("pft2 inode index child", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      child.firstIno = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_VARINT) {
      child.lastIno = reader.uint(field);
    } else if (field === 3 && wireType === WIRE_TYPE_BYTES) {
      child.child = decodeRefBody("pft2 inode index child ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else if (field === 4 && wireType === WIRE_TYPE_VARINT) {
      child.entryCount = reader.uint(field);
    } else {
      return false;
    }
    return true;
  });
  if (!child.child) {
    throw invalidNode("inode index child: missing child reference");
  }
  return child;
}

function decodeInodeIndexIndex(body: Uint8Array): Pft2InodeIndexIndex {
  const index: Pft2InodeIndexIndex = { children: [] };
  decodeRepeated("pft2 inode index index", body, (msg) => {
    index.children.push(decodeInodeIndexChild(msg));
  });
  return index;
}

function decodeRecoveryRoot(body: Uint8Array): Pft2RecoveryRoot {
  const root: Pft2RecoveryRoot = {
    asOfSeq: 0n,
    filesystemRoot: undefined as unknown as Pft2Ref,
    inoNamespace: 0,
    nextLocal: 0n,
    features: 0n,
  };
  decodeMessage("pft2 recovery root", body, recoveryRootRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      root.asOfSeq = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_BYTES) {
      root.filesystemRoot = decodeRefBody(
        "pft2 recovery filesystem root ref",
        reader.bytes(field, PFT2_MAX_NODE_BYTES)
      );
    } else if (field === 3 && wireType === WIRE_TYPE_BYTES) {
      root.controlRoot = decodeRefBody(
        "pft2 recovery control root ref",
        reader.bytes(field, PFT2_MAX_NODE_BYTES)
      );
    } else if (field === 4 && wireType === WIRE_TYPE_BYTES) {
      root.orphanIndex = decodeRefBody(
        "pft2 recovery orphan index ref",
        reader.bytes(field, PFT2_MAX_NODE_BYTES)
      );
    } else if (field === 5 && wireType === WIRE_TYPE_VARINT) {
      root.inoNamespace = reader.uint32(field);
    } else if (field === 6 && wireType === WIRE_TYPE_VARINT) {
      root.nextLocal = reader.uint(field);
    } else if (field === 7 && wireType === WIRE_TYPE_VARINT) {
      root.features = reader.uint(field);
    } else if (field === 8 && wireType === WIRE_TYPE_BYTES) {
      const ref = decodeRefBody(
        "pft2 recovery xattr leaf ref",
        reader.bytes(field, PFT2_MAX_NODE_BYTES)
      );
      (root.xattrLeaves ??= []).push(ref);
    } else {
      return false;
    }
    return true;
  });
  if (!root.filesystemRoot) {
    throw invalidNode("recovery root: missing filesystem root");
  }
  return root;
}

const recoveryRootRepeats: ReadonlySet<number> = new Set([8]);

function decodeXattrEntry(body: Uint8Array): Pft2XattrEntry {
  const entry: Pft2XattrEntry = { ino: 0n, name: "", value: new Uint8Array() };
  decodeMessage("pft2 xattr entry", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      entry.ino = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_BYTES) {
      entry.name = reader.string(field, PFT2_MAX_XATTR_NAME_BYTES);
    } else if (field === 3 && wireType === WIRE_TYPE_BYTES) {
      entry.value = new Uint8Array(reader.bytes(field, PFT2_MAX_XATTR_VALUE_BYTES));
    } else {
      return false;
    }
    return true;
  });
  return entry;
}

function decodeXattrLeaf(body: Uint8Array): Pft2XattrLeaf {
  const leaf: Pft2XattrLeaf = { entries: [] };
  decodeRepeated("pft2 xattr leaf", body, (msg) => {
    leaf.entries.push(decodeXattrEntry(msg));
  });
  return leaf;
}

function decodeCellRef(body: Uint8Array): Pft2CellRef {
  const reader = new WireReader("pft2 cell ref", body);
  let cellDigest: Uint8Array | undefined;
  let object: Pft2Ref | undefined;
  let objectOffset = 0n;
  for (;;) {
    const header = reader.next();
    if (!header) {
      break;
    }
    reader.require(header.field);
    if (header.field === 1 && header.wireType === WIRE_TYPE_BYTES) {
      const raw = reader.bytes(header.field, PFT2_DIGEST_BYTES);
      if (raw.length !== PFT2_DIGEST_BYTES) {
        throw reader.malformed(`cell digest is ${raw.length} bytes (want ${PFT2_DIGEST_BYTES})`);
      }
      cellDigest = new Uint8Array(raw);
    } else if (header.field === 2 && header.wireType === WIRE_TYPE_BYTES) {
      object = decodeRefBody("pft2 cell object ref", reader.bytes(header.field, PFT2_MAX_NODE_BYTES));
    } else if (header.field === 3 && header.wireType === WIRE_TYPE_VARINT) {
      objectOffset = reader.uint(header.field);
    } else {
      throw reader.rejectUnknown(header.field);
    }
  }
  if (!cellDigest || !object) {
    throw reader.malformed("cell ref requires digest and object");
  }
  return { cellDigest, object, objectOffset };
}

function decodeDataPage(body: Uint8Array): Pft2DataPage {
  const page: Pft2DataPage = { cells: Array.from({ length: PFT2_CELLS_PER_PAGE }, () => null) };
  const reader = new WireReader("pft2 data page", body);
  for (;;) {
    const header = reader.next();
    if (!header) {
      break;
    }
    reader.require(header.field);
    if (header.field < 1 || header.field > PFT2_CELLS_PER_PAGE) {
      throw reader.rejectUnknown(header.field);
    }
    if (header.wireType !== WIRE_TYPE_BYTES) {
      throw reader.malformed(`cell field ${header.field} wire type ${header.wireType}`);
    }
    page.cells[header.field - 1] = decodeCellRef(reader.bytes(header.field, PFT2_MAX_NODE_BYTES));
  }
  return page;
}

function decodeControlKindCount(body: Uint8Array): Pft2ControlKindCount {
  const count: Pft2ControlKindCount = { kind: 0n, count: 0n };
  decodeMessage("pft2 control kind count", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      count.kind = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_VARINT) {
      count.count = reader.uint(field);
    } else {
      return false;
    }
    return true;
  });
  return count;
}

function decodeControlRoot(body: Uint8Array): Pft2ControlRoot {
  const root: Pft2ControlRoot = {
    schema: 0n,
    nextCheckoutEpoch: 0n,
    features: 0n,
    counts: [],
    dbTimeFloorMs: 0n,
  };
  decodeMessage("pft2 control root", body, new Set([5]), (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_VARINT) {
      root.schema = reader.uint(field);
    } else if (field === 2 && wireType === WIRE_TYPE_BYTES) {
      root.mapRoot = decodeRefBody("pft2 control map root ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else if (field === 3 && wireType === WIRE_TYPE_VARINT) {
      root.nextCheckoutEpoch = reader.uint(field);
    } else if (field === 4 && wireType === WIRE_TYPE_VARINT) {
      root.features = reader.uint(field);
    } else if (field === 5 && wireType === WIRE_TYPE_BYTES) {
      const msg = reader.bytes(field, PFT2_MAX_NODE_BYTES);
      if (root.counts.length >= Number(PFT2_MAX_CONTROL_ENTRY_KIND)) {
        throw reader.malformed(`more than ${PFT2_MAX_CONTROL_ENTRY_KIND} kind counts`);
      }
      root.counts.push(decodeControlKindCount(msg));
    } else if (field === 6 && wireType === WIRE_TYPE_VARINT) {
      root.dbTimeFloorMs = reader.uint(field);
    } else {
      return false;
    }
    return true;
  });
  return root;
}

function decodeControlEntry(body: Uint8Array): Pft2ControlEntry {
  const entry: Pft2ControlEntry = { key: new Uint8Array(), kind: 0n, value: new Uint8Array() };
  decodeMessage("pft2 control entry", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_BYTES) {
      entry.key = new Uint8Array(reader.bytes(field, PFT2_MAX_CONTROL_KEY_BYTES));
    } else if (field === 2 && wireType === WIRE_TYPE_VARINT) {
      entry.kind = reader.uint(field);
    } else if (field === 3 && wireType === WIRE_TYPE_BYTES) {
      entry.value = new Uint8Array(reader.bytes(field, PFT2_MAX_CONTROL_VALUE_BYTES));
    } else {
      return false;
    }
    return true;
  });
  return entry;
}

function decodeControlLeaf(body: Uint8Array): Pft2ControlLeaf {
  const leaf: Pft2ControlLeaf = { entries: [] };
  decodeRepeated("pft2 control leaf", body, (msg) => {
    leaf.entries.push(decodeControlEntry(msg));
  });
  return leaf;
}

function decodeControlIndexChild(body: Uint8Array): Pft2ControlIndexChild {
  const child: Pft2ControlIndexChild = {
    firstKey: new Uint8Array(),
    lastKey: new Uint8Array(),
    child: undefined as unknown as Pft2Ref,
    entryCount: 0n,
  };
  decodeMessage("pft2 control index child", body, noRepeats, (reader, field, wireType) => {
    if (field === 1 && wireType === WIRE_TYPE_BYTES) {
      child.firstKey = new Uint8Array(reader.bytes(field, PFT2_MAX_CONTROL_KEY_BYTES));
    } else if (field === 2 && wireType === WIRE_TYPE_BYTES) {
      child.lastKey = new Uint8Array(reader.bytes(field, PFT2_MAX_CONTROL_KEY_BYTES));
    } else if (field === 3 && wireType === WIRE_TYPE_BYTES) {
      child.child = decodeRefBody("pft2 control index child ref", reader.bytes(field, PFT2_MAX_NODE_BYTES));
    } else if (field === 4 && wireType === WIRE_TYPE_VARINT) {
      child.entryCount = reader.uint(field);
    } else {
      return false;
    }
    return true;
  });
  if (!child.child) {
    throw invalidNode("control index child: missing child reference");
  }
  return child;
}

function decodeControlIndex(body: Uint8Array): Pft2ControlIndex {
  const index: Pft2ControlIndex = { children: [] };
  decodeRepeated("pft2 control index", body, (msg) => {
    index.children.push(decodeControlIndexChild(msg));
  });
  return index;
}

function decodeArm(kind: Pft2NodeKind, msg: Uint8Array): Pft2Node {
  switch (kind) {
    case Pft2NodeKind.Root:
      return { kind, root: decodeRoot(msg) };
    case Pft2NodeKind.Inode:
      return { kind, inode: decodeInode(msg) };
    case Pft2NodeKind.DirectoryLeaf:
      return { kind, directoryLeaf: decodeDirectoryLeaf(msg) };
    case Pft2NodeKind.DirectoryIndex:
      return { kind, directoryIndex: decodeDirectoryIndex(msg) };
    case Pft2NodeKind.ExtentLeaf:
      return { kind, extentLeaf: decodeExtentLeaf(msg) };
    case Pft2NodeKind.ExtentIndex:
      return { kind, extentIndex: decodeExtentIndex(msg) };
    case Pft2NodeKind.InodeIndexLeaf:
      return { kind, inodeIndexLeaf: decodeInodeIndexLeaf(msg) };
    case Pft2NodeKind.InodeIndexIndex:
      return { kind, inodeIndexIndex: decodeInodeIndexIndex(msg) };
    case Pft2NodeKind.RecoveryRoot:
      return { kind, recoveryRoot: decodeRecoveryRoot(msg) };
    case Pft2NodeKind.DataPage:
      return { kind, dataPage: decodeDataPage(msg) };
    case Pft2NodeKind.ControlRoot:
      return { kind, controlRoot: decodeControlRoot(msg) };
    case Pft2NodeKind.ControlLeaf:
      return { kind, controlLeaf: decodeControlLeaf(msg) };
    case Pft2NodeKind.ControlIndex:
      return { kind, controlIndex: decodeControlIndex(msg) };
    case Pft2NodeKind.XattrLeaf:
      return { kind, xattrLeaf: decodeXattrLeaf(msg) };
  }
}

/**
 * Strictly decodes one canonical PFT2 object; rejects anything
 * non-canonical, unknown, out of bounds, or trailing, and re-validates, so
 * any accepted object re-encodes to identical bytes. Callers must have
 * verified size and digest first (verifyObjectBytes).
 */
export function decodePft2Node(data: Uint8Array): Pft2Node {
  if (data.length > PFT2_MAX_NODE_BYTES) {
    throw invalidNode(`node is ${data.length} bytes (max ${PFT2_MAX_NODE_BYTES})`);
  }
  if (data.length < PFT2_MIN_NODE_BYTES) {
    throw invalidNode(`node is ${data.length} bytes (min ${PFT2_MIN_NODE_BYTES})`);
  }
  for (let i = 0; i < 4; i += 1) {
    if (data[i] !== PFT2_MAGIC[i]) {
      throw invalidNode("object does not begin with the PFT2 magic");
    }
  }
  const reader = new WireReader("pft2 node", data.subarray(4));
  let kind = 0;
  let node: Pft2Node | undefined;
  for (;;) {
    const header = reader.next();
    if (!header) {
      break;
    }
    reader.require(header.field);
    if (header.field === 1) {
      if (header.wireType !== WIRE_TYPE_VARINT) {
        throw reader.malformed(`kind wire type ${header.wireType}`);
      }
      const value = reader.uint(header.field);
      if (value < 1n || value > BigInt(Pft2NodeKind.XattrLeaf)) {
        throw reader.malformed(`unknown kind ${value}`);
      }
      kind = Number(value);
      continue;
    }
    if (kind === 0) {
      throw reader.malformed(`arm field ${header.field} before kind`);
    }
    if (header.field !== kind + 1) {
      throw reader.malformed(`kind ${kind} cannot carry arm field ${header.field}`);
    }
    if (header.wireType !== WIRE_TYPE_BYTES) {
      throw reader.malformed(`arm field ${header.field} wire type ${header.wireType}`);
    }
    const msg = reader.bytes(header.field, PFT2_MAX_NODE_BYTES);
    node = decodeArm(kind as Pft2NodeKind, msg);
  }
  if (kind === 0) {
    throw invalidNode("node is missing kind");
  }
  if (!node) {
    throw invalidNode(`kind ${kind} node is missing its arm`);
  }
  validatePft2Node(node);
  return node;
}

/**
 * Decodes and additionally requires the node kind advertised by the edge the
 * object was reached through.
 */
export function decodePft2NodeKind(data: Uint8Array, want: Pft2NodeKind): Pft2Node {
  const node = decodePft2Node(data);
  if (node.kind !== want) {
    throw corrupt(`expected kind ${want} node, decoded ${node.kind}`);
  }
  return node;
}
