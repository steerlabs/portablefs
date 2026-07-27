/**
 * Shared golden-vector construction, mirroring the fixtures defined in
 * vcs/internal/pft2 (codec_test.go sampleNodes and golden_test.go
 * buildGoldenFilesystem/buildGoldenRecovery). Both implementations must
 * produce byte-identical objects from these definitions. Test-only module —
 * deliberately not exported from the package barrel.
 */
import { createHash } from "node:crypto";
import { buildControlTree, buildDirectoryTree, buildFileExtents, buildInodeIndexTree } from "./builder.js";
import { encodePft2Node } from "./codec.js";
import { Pft2MemoryStore } from "./basetree.js";
import {
  PFT2_CELL_BYTES,
  PFT2_CONTROL_SCHEMA_VERSION,
  PFT2_PAGE_BYTES,
  Pft2FileKind,
  Pft2NodeKind,
  pft2RefOf,
  type Pft2DataPage,
  type Pft2Inode,
  type Pft2Node,
  type Pft2Ref,
} from "./types.js";
import { utf8Encode } from "./wire.js";

export function labelDigest(label: string): Uint8Array {
  return createHash("sha256").update(label).digest();
}

export function labelRef(label: string, size: bigint): Pft2Ref {
  return { digest: labelDigest(label), size };
}

function inode(fields: Partial<Pft2Inode> & Pick<Pft2Inode, "ino" | "kind">): Pft2Inode {
  return {
    mode: 0,
    uid: 0,
    gid: 0,
    nlink: 1n,
    size: 0n,
    mtimeMs: 0n,
    ctimeMs: 0n,
    atimeMs: 0n,
    symlinkTarget: "",
    ...fields,
  };
}

/** One valid instance of every node kind (identical to the Go sampleNodes). */
export function sampleNodes(): Map<string, Pft2Node> {
  const symlinkTarget = "π/→/target";
  const dataPage: Pft2DataPage = { cells: Array.from({ length: 16 }, () => null) };
  dataPage.cells[0] = {
    cellDigest: labelDigest("cell-0"),
    object: labelRef("pack-0", 16384n),
    objectOffset: 0n,
  };
  dataPage.cells[15] = {
    cellDigest: labelDigest("cell-15"),
    object: labelRef("pack-0", 16384n),
    objectOffset: 12288n,
  };
  return new Map<string, Pft2Node>([
    [
      "root",
      {
        kind: Pft2NodeKind.Root,
        root: {
          rootInode: labelRef("root-inode", 120n),
          inodeIndex: labelRef("inode-index", 321n),
          maxInoSeen: 4294967298n,
          inodeCount: 3n,
          direntCount: 2n,
          logicalBytes: 70000n,
          features: 0n,
        },
      },
    ],
    [
      "root-xattrs",
      {
        kind: Pft2NodeKind.Root,
        root: {
          rootInode: labelRef("root-inode", 120n),
          inodeIndex: labelRef("inode-index", 321n),
          maxInoSeen: 4294967298n,
          inodeCount: 3n,
          direntCount: 2n,
          logicalBytes: 70000n,
          features: 0n,
          xattrLeaves: [labelRef("xattr-leaf-0", 300n), labelRef("xattr-leaf-1", 301n)],
        },
      },
    ],
    [
      "inode-file",
      {
        kind: Pft2NodeKind.Inode,
        inode: inode({
          ino: 21474836487n,
          kind: Pft2FileKind.Regular,
          mode: 0o644,
          uid: 1000,
          gid: 1000,
          size: 70000n,
          mtimeMs: 1700000000123n,
          ctimeMs: 1700000000456n,
          atimeMs: -777n,
          extentRoot: labelRef("extent-root", 555n),
        }),
      },
    ],
    [
      "inode-dir",
      {
        kind: Pft2NodeKind.Inode,
        inode: inode({
          ino: 1n,
          kind: Pft2FileKind.Directory,
          mode: 0o755,
          directoryRoot: labelRef("dir-root", 200n),
        }),
      },
    ],
    [
      "inode-symlink",
      {
        kind: Pft2NodeKind.Inode,
        inode: inode({
          ino: 42n,
          kind: Pft2FileKind.Symlink,
          mode: 0o777,
          size: BigInt(utf8Encode(symlinkTarget).length),
          symlinkTarget,
        }),
      },
    ],
    [
      "inode-empty-file",
      {
        kind: Pft2NodeKind.Inode,
        inode: inode({ ino: 99n, kind: Pft2FileKind.Regular }),
      },
    ],
    [
      "directory-leaf",
      {
        kind: Pft2NodeKind.DirectoryLeaf,
        directoryLeaf: {
          entries: [
            { name: ".hidden", ino: 12n, kind: Pft2FileKind.Regular },
            { name: "a", ino: 10n, kind: Pft2FileKind.Directory },
            { name: "ab", ino: 11n, kind: Pft2FileKind.Symlink },
            { name: "béta", ino: 13n, kind: Pft2FileKind.Regular },
          ],
        },
      },
    ],
    [
      "directory-index",
      {
        kind: Pft2NodeKind.DirectoryIndex,
        directoryIndex: {
          children: [
            {
              firstName: ".hidden",
              lastName: "ab",
              child: labelRef("dir-leaf-0", 5000n),
              entryCount: 3n,
            },
            {
              firstName: "béta",
              lastName: "zz",
              child: labelRef("dir-leaf-1", 6000n),
              entryCount: 2n,
            },
          ],
        },
      },
    ],
    [
      "extent-leaf",
      {
        kind: Pft2NodeKind.ExtentLeaf,
        extentLeaf: {
          entries: [
            { pageOffset: 0n, page: labelRef("page-0", 900n) },
            { pageOffset: 65536n, page: labelRef("page-1", 901n) },
            { pageOffset: 6553600n, page: labelRef("page-100", 902n) },
          ],
        },
      },
    ],
    [
      "extent-index",
      {
        kind: Pft2NodeKind.ExtentIndex,
        extentIndex: {
          children: [
            { firstPage: 0n, lastPage: 65536n, child: labelRef("extent-leaf-0", 1000n), entryCount: 2n },
            {
              firstPage: 131072n,
              lastPage: 6553600n,
              child: labelRef("extent-leaf-1", 1001n),
              entryCount: 7n,
            },
          ],
        },
      },
    ],
    [
      "inode-index-leaf",
      {
        kind: Pft2NodeKind.InodeIndexLeaf,
        inodeIndexLeaf: {
          entries: [
            { ino: 1n, inode: labelRef("ino-1", 150n) },
            { ino: 21474836487n, inode: labelRef("ino-file", 151n) },
          ],
        },
      },
    ],
    [
      "inode-index-index",
      {
        kind: Pft2NodeKind.InodeIndexIndex,
        inodeIndexIndex: {
          children: [
            { firstIno: 1n, lastIno: 100n, child: labelRef("ino-leaf-0", 400n), entryCount: 5n },
            {
              firstIno: 101n,
              lastIno: 21474836487n,
              child: labelRef("ino-leaf-1", 401n),
              entryCount: 6n,
            },
          ],
        },
      },
    ],
    [
      "recovery-root",
      {
        kind: Pft2NodeKind.RecoveryRoot,
        recoveryRoot: {
          asOfSeq: 123456789012345n,
          filesystemRoot: labelRef("fs-root", 180n),
          controlRoot: labelRef("control-root", 90n),
          orphanIndex: labelRef("orphan-index", 91n),
          inoNamespace: 2147483647,
          nextLocal: 4294967296n,
          features: 0n,
        },
      },
    ],
    [
      "recovery-root-fresh",
      {
        kind: Pft2NodeKind.RecoveryRoot,
        recoveryRoot: {
          asOfSeq: 0n,
          filesystemRoot: labelRef("fs-root", 180n),
          inoNamespace: 7,
          nextLocal: 1n,
          features: 0n,
        },
      },
    ],
    [
      "recovery-root-xattrs",
      {
        kind: Pft2NodeKind.RecoveryRoot,
        recoveryRoot: {
          asOfSeq: 99n,
          filesystemRoot: labelRef("fs-root", 180n),
          controlRoot: labelRef("control-root", 90n),
          inoNamespace: 7,
          nextLocal: 12n,
          features: 0n,
          xattrLeaves: [labelRef("xattr-leaf-0", 300n), labelRef("xattr-leaf-1", 301n)],
        },
      },
    ],
    [
      "xattr-leaf",
      {
        kind: Pft2NodeKind.XattrLeaf,
        xattrLeaf: {
          entries: [
            { ino: 2n, name: "com.apple.FinderInfo", value: new Uint8Array(32).fill(0xab) },
            { ino: 2n, name: "user.empty", value: new Uint8Array() },
            { ino: 21474836487n, name: "user.\u03c0", value: utf8Encode("v") },
          ],
        },
      },
    ],
    ["data-page", { kind: Pft2NodeKind.DataPage, dataPage: dataPage }],
    [
      "control-root-empty",
      {
        kind: Pft2NodeKind.ControlRoot,
        controlRoot: {
          schema: PFT2_CONTROL_SCHEMA_VERSION,
          nextCheckoutEpoch: 1n,
          features: 0n,
          counts: [],
          dbTimeFloorMs: 0n,
        },
      },
    ],
    [
      "control-root",
      {
        kind: Pft2NodeKind.ControlRoot,
        controlRoot: {
          schema: PFT2_CONTROL_SCHEMA_VERSION,
          mapRoot: labelRef("control-map", 777n),
          nextCheckoutEpoch: 922337203685477580n,
          features: 0n,
          counts: [
            { kind: 1n, count: 3n },
            { kind: 7n, count: 1n },
          ],
          dbTimeFloorMs: 0n,
        },
      },
    ],
    [
      "control-root-floor",
      {
        kind: Pft2NodeKind.ControlRoot,
        controlRoot: {
          schema: PFT2_CONTROL_SCHEMA_VERSION,
          nextCheckoutEpoch: 42n,
          features: 0n,
          counts: [],
          dbTimeFloorMs: 1_752_222_333_444n,
        },
      },
    ],
    [
      "control-leaf",
      {
        kind: Pft2NodeKind.ControlLeaf,
        controlLeaf: {
          entries: [
            { key: utf8Encode("a-key"), kind: 1n, value: utf8Encode("value-bytes") },
            { key: utf8Encode("b-key"), kind: 7n, value: new Uint8Array() },
          ],
        },
      },
    ],
    [
      "control-index",
      {
        kind: Pft2NodeKind.ControlIndex,
        controlIndex: {
          children: [
            {
              firstKey: utf8Encode("a"),
              lastKey: utf8Encode("m"),
              child: labelRef("control-leaf-0", 800n),
              entryCount: 12n,
            },
            {
              firstKey: utf8Encode("n"),
              lastKey: utf8Encode("z"),
              child: labelRef("control-leaf-1", 801n),
              entryCount: 9n,
            },
          ],
        },
      },
    ],
  ]);
}

/** The deterministic 100000-byte golden file content (see Go twin). */
export function goldenFileContentA(): Uint8Array {
  const content = new Uint8Array(100000);
  for (let i = 0; i < content.length; i += 1) {
    content[i] = (i * 7 + 13) % 251;
  }
  content.fill(0, 4 * PFT2_CELL_BYTES, 8 * PFT2_CELL_BYTES);
  content.fill(0, PFT2_PAGE_BYTES);
  return content;
}

function putInode(store: Pft2MemoryStore, value: Pft2Inode): Pft2Ref {
  const encoded = encodePft2Node({ kind: Pft2NodeKind.Inode, inode: value });
  const ref = pft2RefOf(encoded);
  store.putNode(ref, encoded);
  return ref;
}

/** Builds the shared golden filesystem; returns the ROOT reference. */
export function buildGoldenFilesystem(store: Pft2MemoryStore): Pft2Ref {
  const timeMs = 1700000000000n;

  const extentA = buildFileExtents(goldenFileContentA(), store, store);
  if (!extentA) {
    throw new Error("golden file A must have present pages");
  }
  const extentSmall = buildFileExtents(utf8Encode("hi\n"), store, store);

  const emptyRef = putInode(
    store,
    inode({ ino: 3n, kind: Pft2FileKind.Regular, mode: 0o644, mtimeMs: timeMs, ctimeMs: timeMs })
  );
  const helloRef = putInode(
    store,
    inode({
      ino: 4n,
      kind: Pft2FileKind.Regular,
      mode: 0o644,
      size: 100000n,
      mtimeMs: timeMs,
      ctimeMs: timeMs,
      extentRoot: extentA,
    })
  );
  const linkRef = putInode(
    store,
    inode({
      ino: 5n,
      kind: Pft2FileKind.Symlink,
      mode: 0o777,
      size: BigInt("a/hello.bin".length),
      mtimeMs: timeMs,
      ctimeMs: timeMs,
      symlinkTarget: "a/hello.bin",
    })
  );
  const smallRef = putInode(
    store,
    inode({
      ino: 6n,
      kind: Pft2FileKind.Regular,
      mode: 0o644,
      size: 3n,
      mtimeMs: timeMs,
      ctimeMs: timeMs,
      ...(extentSmall ? { extentRoot: extentSmall } : {}),
    })
  );

  const dirA = buildDirectoryTree(
    [
      { name: "empty", ino: 3n, kind: Pft2FileKind.Regular },
      { name: "hello.bin", ino: 4n, kind: Pft2FileKind.Regular },
    ],
    store
  );
  const dirARef = putInode(
    store,
    inode({
      ino: 2n,
      kind: Pft2FileKind.Directory,
      mode: 0o755,
      mtimeMs: timeMs,
      ctimeMs: timeMs,
      ...(dirA.root ? { directoryRoot: dirA.root } : {}),
    })
  );

  const rootDir = buildDirectoryTree(
    [
      { name: "a", ino: 2n, kind: Pft2FileKind.Directory },
      { name: "link", ino: 5n, kind: Pft2FileKind.Symlink },
      { name: "small", ino: 6n, kind: Pft2FileKind.Regular },
    ],
    store
  );
  const rootInodeRef = putInode(
    store,
    inode({
      ino: 1n,
      kind: Pft2FileKind.Directory,
      mode: 0o755,
      mtimeMs: timeMs,
      ctimeMs: timeMs,
      ...(rootDir.root ? { directoryRoot: rootDir.root } : {}),
    })
  );

  const inodeIndex = buildInodeIndexTree(
    [
      { ino: 1n, inode: rootInodeRef },
      { ino: 2n, inode: dirARef },
      { ino: 3n, inode: emptyRef },
      { ino: 4n, inode: helloRef },
      { ino: 5n, inode: linkRef },
      { ino: 6n, inode: smallRef },
    ],
    store
  );
  if (!inodeIndex.root) {
    throw new Error("golden inode index must exist");
  }

  const rootEncoded = encodePft2Node({
    kind: Pft2NodeKind.Root,
    root: {
      rootInode: rootInodeRef,
      inodeIndex: inodeIndex.root,
      maxInoSeen: 6n,
      inodeCount: inodeIndex.entryCount,
      direntCount: dirA.entryCount + rootDir.entryCount,
      logicalBytes: 100000n + 3n + BigInt("a/hello.bin".length),
      features: 0n,
    },
  });
  const rootRef = pft2RefOf(rootEncoded);
  store.putNode(rootRef, rootEncoded);
  return rootRef;
}

/** Layers the golden control/recovery objects over the filesystem root. */
export function buildGoldenRecovery(store: Pft2MemoryStore, fsRoot: Pft2Ref): Pft2Ref {
  const control = buildControlTree(
    [
      { key: utf8Encode("lock\0ino:4\x000"), kind: 3n, value: utf8Encode("interval:0-4096") },
      { key: utf8Encode("session\0s-1"), kind: 1n, value: utf8Encode("generation:9") },
      { key: utf8Encode("session\0s-2"), kind: 1n, value: new Uint8Array() },
    ],
    store
  );
  if (control.entryCount !== 3n || !control.root) {
    throw new Error(`control entry count ${control.entryCount}`);
  }
  const controlEncoded = encodePft2Node({
    kind: Pft2NodeKind.ControlRoot,
    controlRoot: {
      schema: PFT2_CONTROL_SCHEMA_VERSION,
      mapRoot: control.root,
      nextCheckoutEpoch: 12n,
      features: 0n,
      counts: control.counts,
      dbTimeFloorMs: 0n,
    },
  });
  const controlRef = pft2RefOf(controlEncoded);
  store.putNode(controlRef, controlEncoded);

  const recoveryEncoded = encodePft2Node({
    kind: Pft2NodeKind.RecoveryRoot,
    recoveryRoot: {
      asOfSeq: 987654321n,
      filesystemRoot: fsRoot,
      controlRoot: controlRef,
      inoNamespace: 42,
      nextLocal: 7n,
      features: 0n,
    },
  });
  const recoveryRef = pft2RefOf(recoveryEncoded);
  store.putNode(recoveryRef, recoveryEncoded);
  return recoveryRef;
}

/**
 * A 10000-entry directory whose tree has real index nodes, pinning
 * multi-level deterministic construction (mirrors the Go twin).
 */
export function buildGoldenWideDirectory(store: Pft2MemoryStore): Pft2Ref {
  const entries = Array.from({ length: 10000 }, (_, i) => ({
    name: `entry-${String(i).padStart(5, "0")}-qqqqqqqqqqqqqqqqqqqqqqqq`,
    ino: BigInt(i + 2),
    kind: i % 7 === 0 ? Pft2FileKind.Directory : Pft2FileKind.Regular,
  }));
  const built = buildDirectoryTree(entries, store);
  if (!built.root || built.entryCount !== 10000n) {
    throw new Error("wide directory build failed");
  }
  return built.root;
}

/** sha256 over sorted "hex:size\n" lines — matches the Go objectSetHash. */
export function objectSetHash(store: Pft2MemoryStore): string {
  const hash = createHash("sha256");
  for (const line of store.objectSetLines()) {
    hash.update(line);
    hash.update("\n");
  }
  return hash.digest("hex");
}
