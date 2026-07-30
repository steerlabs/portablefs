import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import {
  encodePft2Node,
  Pft2FileKind,
  Pft2MemoryStore,
  Pft2NodeKind,
  pft2RefOf,
  PFT2_PAGE_BYTES,
  type Pft2Inode,
  type Pft2Ref,
} from "@portablefs/core";
// The deterministic builder is test-only fixture support, deliberately
// outside the shipped @portablefs/core barrel (the Go worker is the sole
// production PFT2 producer).
import {
  buildDirectoryTree,
  buildFileExtents,
  buildInodeIndexTree,
} from "@portablefs/core/dist/pft2/builder.js";
import type { BlobStore } from "@portablefs/core";
import type {
  HistoryObjectLocation,
  MetadataRepository,
  Pft2CommitProvenance,
  PostgresHistoryRepository,
} from "@portablefs/metadata-db";
import type { VolumeTreeResponse } from "@portablefs/protocol";
import {
  ExactKeyReadError,
  HistoryStoreRegistry,
  type ExactKeyReader,
} from "./history-stores.js";
import { createVolumeApiServer } from "./server.js";

// ---------------------------------------------------------------------------
// Tree/file browse over a REAL PFT2 commit: the golden filesystem (shared
// Go/TS vectors) served through the exact located-copy read path — every
// object located in the fake registry first, then read from the fake failure
// domain, size- and digest-verified before decode.
// ---------------------------------------------------------------------------

const servers: Array<ReturnType<typeof createVolumeApiServer>> = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
        })
    )
  );
});

const TENANT_HEADERS = { authorization: "Bearer tenant-token" } as const;
const COMMIT_ID = "cpft2_golden";

interface GoldenWorld {
  baseUrl: string;
  rootHex: string;
  objectSizesByStorageKey: Map<string, number>;
  readsByStorageKey: Map<string, number>;
}

// The golden test tree (mirrors the shared golden filesystem shape):
//   /a/empty       empty regular file (ino 3)
//   /a/hello.bin   100000-byte patterned file, first page a hole (ino 4)
//   /link          symlink -> a/hello.bin (ino 5)
//   /small         3-byte file "hi\n" (ino 6)
function goldenContent(): Uint8Array {
  const content = new Uint8Array(100000);
  for (let i = 0; i < content.length; i += 1) {
    content[i] = (i * 7 + 13) % 251;
  }
  content.fill(0, 0, PFT2_PAGE_BYTES);
  return content;
}

function inodeOf(partial: {
  ino: bigint;
  kind: Pft2FileKind;
  mode: number;
  size?: bigint;
  symlinkTarget?: string;
  directoryRoot?: Pft2Ref;
  extentRoot?: Pft2Ref;
}): Pft2Inode {
  return {
    ino: partial.ino,
    kind: partial.kind,
    mode: partial.mode,
    uid: 0,
    gid: 0,
    nlink: 1n,
    size: partial.size ?? 0n,
    mtimeMs: 1700000000000n,
    ctimeMs: 1700000000000n,
    atimeMs: 0n,
    symlinkTarget: partial.symlinkTarget ?? "",
    ...(partial.directoryRoot ? { directoryRoot: partial.directoryRoot } : {}),
    ...(partial.extentRoot ? { extentRoot: partial.extentRoot } : {}),
  };
}

function buildTestFilesystem(store: Pft2MemoryStore): Pft2Ref {
  const putInode = (inode: Pft2Inode): Pft2Ref => {
    const encoded = encodePft2Node({ kind: Pft2NodeKind.Inode, inode });
    const ref = pft2RefOf(encoded);
    store.putNode(ref, encoded);
    return ref;
  };

  const extentA = buildFileExtents(goldenContent(), store, store);
  if (!extentA) {
    throw new Error("hello.bin must have present pages");
  }
  const extentSmall = buildFileExtents(new TextEncoder().encode("hi\n"), store, store);

  const emptyRef = putInode(inodeOf({ ino: 3n, kind: Pft2FileKind.Regular, mode: 0o644 }));
  const helloRef = putInode(
    inodeOf({ ino: 4n, kind: Pft2FileKind.Regular, mode: 0o644, size: 100000n, extentRoot: extentA })
  );
  const linkRef = putInode(
    inodeOf({
      ino: 5n,
      kind: Pft2FileKind.Symlink,
      mode: 0o777,
      size: BigInt("a/hello.bin".length),
      symlinkTarget: "a/hello.bin",
    })
  );
  const smallRef = putInode(
    inodeOf({
      ino: 6n,
      kind: Pft2FileKind.Regular,
      mode: 0o644,
      size: 3n,
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
    inodeOf({
      ino: 2n,
      kind: Pft2FileKind.Directory,
      mode: 0o755,
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
    inodeOf({
      ino: 1n,
      kind: Pft2FileKind.Directory,
      mode: 0o755,
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
    throw new Error("inode index must exist");
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

async function startGoldenServer(
  build: (store: Pft2MemoryStore) => Pft2Ref = buildTestFilesystem
): Promise<GoldenWorld> {
  const store = new Pft2MemoryStore();
  const rootRef = build(store);
  const rootHex = Buffer.from(rootRef.digest).toString("hex");

  // Every golden object becomes one registered live copy at an exact key.
  const objects = new Map<string, Buffer>();
  const locations = new Map<string, HistoryObjectLocation>();
  for (const line of store.objectSetLines()) {
    const [hex, size] = line.split(":");
    const bytes = Buffer.from(
      await store.fetch({ digest: Buffer.from(hex!, "hex"), size: BigInt(size!) })
    );
    const storageKey = `t1/pft2/${hex}/i1`;
    objects.set(storageKey, bytes);
    locations.set(`sha256:${hex}`, {
      tenantId: "t1",
      kind: "pft2",
      digest: `sha256:${hex}`,
      size: String(bytes.byteLength),
      incarnation: "1",
      state: "live",
      copies: [
        {
          failureDomain: "dom-a",
          storageKey,
          size: String(bytes.byteLength),
          lastVerifiedDbMs: "0",
        },
      ],
    });
  }

  const reader: ExactKeyReader = {
    async readExactKey(storageKey, options) {
      readsByStorageKey.set(storageKey, (readsByStorageKey.get(storageKey) ?? 0) + 1);
      const bytes = objects.get(storageKey);
      if (!bytes) {
        throw new ExactKeyReadError("not_found", "missing");
      }
      if (bytes.byteLength !== options.expectedSize) {
        throw new ExactKeyReadError("size_mismatch", "size");
      }
      return bytes;
    },
  };
  const readsByStorageKey = new Map<string, number>();
  const objectSizesByStorageKey = new Map(
    [...objects].map(([storageKey, bytes]) => [storageKey, bytes.byteLength])
  );
  const stores = new HistoryStoreRegistry([{ failureDomain: "dom-a", reader }]);

  const provenance: Pft2CommitProvenance = {
    commitId: COMMIT_ID,
    cutId: "hcut_golden",
    tenantId: "t1",
    rootDigest: rootHex,
    rootSize: String(rootRef.size),
    maxInoSeen: "6",
    objectCount: String(objects.size),
    objectBytes: "0",
  };
  const history = {
    locateObject: async (_tenant: string, _kind: "pft2", digest: string) =>
      locations.get(digest) ?? null,
    pft2CommitProvenance: async (_tenant: string, commitId: string) =>
      commitId === COMMIT_ID ? provenance : null,
    scheduleServingCopyVerification: async () => true,
  } as unknown as PostgresHistoryRepository;

  const metadata = tenantMetadata();
  metadata.commitKind = async (commitId) => (commitId === COMMIT_ID ? "pft2" : null);
  metadata.getCommitSummary = async (commitId) =>
    commitId === COMMIT_ID
      ? {
          id: COMMIT_ID,
          volumeId: "vol_a",
          branchId: "br_a",
          treeHash: `pft2:${rootHex}`,
          mutationCount: 0,
          byteCount: 0,
          createdAt: 1,
        }
      : null;
  metadata.listBranches = async () => [
    {
      id: "br_a",
      volumeId: "vol_a",
      name: "main",
      headCommitId: COMMIT_ID,
      createdAt: 0,
      updatedAt: 0,
    },
  ];
  Object.defineProperty(metadata, "history", { value: history, enumerable: true });

  const server = createVolumeApiServer({
    authToken: "secret-token",
    metadata,
    blobStore: throwingBlobStore(),
    historyStores: stores,
    historyCopyTimeoutMs: 1_000,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    rootHex,
    objectSizesByStorageKey,
    readsByStorageKey,
  };
}

describe("PFT2 tree browse", () => {
  test("lists the golden root with kinds, sizes, and link targets over verified reads", async () => {
    const { baseUrl, rootHex } = await startGoldenServer();
    const response = await fetch(
      `${baseUrl}/v1/volumes/vol_a/tree?commit=${COMMIT_ID}`,
      { headers: TENANT_HEADERS }
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as VolumeTreeResponse;
    expect(body.commitId).toBe(COMMIT_ID);
    expect(body.treeHash).toBe(`pft2:${rootHex}`);
    expect(body.branchName).toBe("main");
    expect(body.entries.map((entry) => [entry.name, entry.kind])).toEqual([
      ["a", "directory"],
      ["link", "symlink"],
      ["small", "file"],
    ]);
    const link = body.entries.find((entry) => entry.name === "link");
    expect(link?.linkTarget).toBe("a/hello.bin");
    const small = body.entries.find((entry) => entry.name === "small");
    expect(small?.size).toBe(3);
  });

  test("lists a subdirectory and paginates in canonical name order", async () => {
    const { baseUrl } = await startGoldenServer();
    const first = await fetch(
      `${baseUrl}/v1/volumes/vol_a/tree?commit=${COMMIT_ID}&path=a&limit=1`,
      { headers: TENANT_HEADERS }
    );
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as VolumeTreeResponse;
    expect(firstBody.entries.map((entry) => entry.name)).toEqual(["empty"]);
    expect(firstBody.nextCursor).toBe("empty");

    const second = await fetch(
      `${baseUrl}/v1/volumes/vol_a/tree?commit=${COMMIT_ID}&path=a&limit=5&cursor=empty`,
      { headers: TENANT_HEADERS }
    );
    const secondBody = (await second.json()) as VolumeTreeResponse;
    expect(secondBody.entries.map((entry) => entry.name)).toEqual(["hello.bin"]);
    expect(secondBody.nextCursor).toBeUndefined();
  });

  test("missing paths 404 and files refuse directory listing", async () => {
    const { baseUrl } = await startGoldenServer();
    const missing = await fetch(
      `${baseUrl}/v1/volumes/vol_a/tree?commit=${COMMIT_ID}&path=nope`,
      { headers: TENANT_HEADERS }
    );
    expect(missing.status).toBe(404);
    const file = await fetch(
      `${baseUrl}/v1/volumes/vol_a/tree?commit=${COMMIT_ID}&path=small`,
      { headers: TENANT_HEADERS }
    );
    expect(file.status).toBe(409);
  });
});

describe("PFT2 file serving", () => {
  test("serves whole files with holes reading as zero", async () => {
    const { baseUrl } = await startGoldenServer();
    const response = await fetch(
      `${baseUrl}/v1/volumes/vol_a/file?commit=${COMMIT_ID}&path=a/hello.bin`,
      { headers: TENANT_HEADERS }
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("x-portablefs-kind")).toBe("file");
    expect(response.headers.get("cache-control")).toContain("immutable");
    const body = Buffer.from(await response.arrayBuffer());
    expect(body.byteLength).toBe(100000);
    expect(body).toEqual(Buffer.from(goldenContent()));
    // The first page is a hole and reads as zero.
    expect(body.subarray(0, PFT2_PAGE_BYTES).every((byte) => byte === 0)).toBe(true);
  });

  test("serves exact byte ranges with 206 and content-range", async () => {
    const { baseUrl } = await startGoldenServer();
    const content = Buffer.from(goldenContent());
    const response = await fetch(
      `${baseUrl}/v1/volumes/vol_a/file?commit=${COMMIT_ID}&path=a/hello.bin`,
      { headers: { ...TENANT_HEADERS, range: "bytes=70000-70099" } }
    );
    expect(response.status).toBe(206);
    expect(response.headers.get("content-range")).toBe("bytes 70000-70099/100000");
    expect(Buffer.from(await response.arrayBuffer())).toEqual(content.subarray(70000, 70100));
  });

  test("serves small files and symlink targets with the kind header", async () => {
    const { baseUrl } = await startGoldenServer();
    const small = await fetch(
      `${baseUrl}/v1/volumes/vol_a/file?commit=${COMMIT_ID}&path=small`,
      { headers: TENANT_HEADERS }
    );
    expect(small.status).toBe(200);
    expect(Buffer.from(await small.arrayBuffer()).toString("utf8")).toBe("hi\n");

    const link = await fetch(
      `${baseUrl}/v1/volumes/vol_a/file?commit=${COMMIT_ID}&path=link`,
      { headers: TENANT_HEADERS }
    );
    expect(link.status).toBe(200);
    expect(link.headers.get("x-portablefs-kind")).toBe("symlink");
    expect(await link.text()).toBe("a/hello.bin");
  });

  // Regression: one readExtents operation visits one DataPage node per 64 KiB
  // page of the requested window, so a file (or range) spanning more pages
  // than the reader's per-op node budget used to fail typed 413
  // (VOLUME_RESPONSE_TOO_LARGE) even though the request was far below the
  // route's documented 64 MiB bound. The serving reader now sizes its bounds
  // from that contract; a whole-file read of 8 MiB (128 pages, 2x the old
  // 64-node default) must serve byte-exact.
  test("serves multi-megabyte files whose page count exceeds the old per-op node budget", async () => {
    const bigContent = new Uint8Array(8 * 1024 * 1024);
    for (let i = 0; i < bigContent.length; i += 1) {
      bigContent[i] = (i * 31 + 7) % 253;
    }
    const buildBigWorld = (store: Pft2MemoryStore): Pft2Ref => {
      const putInode = (inode: Pft2Inode): Pft2Ref => {
        const encoded = encodePft2Node({ kind: Pft2NodeKind.Inode, inode });
        const ref = pft2RefOf(encoded);
        store.putNode(ref, encoded);
        return ref;
      };
      const extents = buildFileExtents(bigContent, store, store);
      if (!extents) {
        throw new Error("big.bin must have present pages");
      }
      const bigRef = putInode(
        inodeOf({
          ino: 2n,
          kind: Pft2FileKind.Regular,
          mode: 0o644,
          size: BigInt(bigContent.length),
          extentRoot: extents,
        })
      );
      const rootDir = buildDirectoryTree(
        [{ name: "big.bin", ino: 2n, kind: Pft2FileKind.Regular }],
        store
      );
      const rootInodeRef = putInode(
        inodeOf({
          ino: 1n,
          kind: Pft2FileKind.Directory,
          mode: 0o755,
          ...(rootDir.root ? { directoryRoot: rootDir.root } : {}),
        })
      );
      const inodeIndex = buildInodeIndexTree(
        [
          { ino: 1n, inode: rootInodeRef },
          { ino: 2n, inode: bigRef },
        ],
        store
      );
      if (!inodeIndex.root) {
        throw new Error("inode index must exist");
      }
      const rootEncoded = encodePft2Node({
        kind: Pft2NodeKind.Root,
        root: {
          rootInode: rootInodeRef,
          inodeIndex: inodeIndex.root,
          maxInoSeen: 2n,
          inodeCount: inodeIndex.entryCount,
          direntCount: rootDir.entryCount,
          logicalBytes: BigInt(bigContent.length),
          features: 0n,
        },
      });
      const rootRef = pft2RefOf(rootEncoded);
      store.putNode(rootRef, rootEncoded);
      return rootRef;
    };

    const { baseUrl, objectSizesByStorageKey, readsByStorageKey } =
      await startGoldenServer(buildBigWorld);
    const whole = await fetch(
      `${baseUrl}/v1/volumes/vol_a/file?commit=${COMMIT_ID}&path=big.bin`,
      { headers: TENANT_HEADERS }
    );
    expect(whole.status).toBe(200);
    const wholeBody = Buffer.from(await whole.arrayBuffer());
    expect(wholeBody.byteLength).toBe(bigContent.length);
    expect(wholeBody.equals(Buffer.from(bigContent))).toBe(true);

    // A range spanning ~96 pages (the old failure started past ~64 pages).
    const start = 1 * 1024 * 1024;
    const end = start + 6 * 1024 * 1024 - 1;
    const ranged = await fetch(
      `${baseUrl}/v1/volumes/vol_a/file?commit=${COMMIT_ID}&path=big.bin`,
      { headers: { ...TENANT_HEADERS, range: `bytes=${start}-${end}` } }
    );
    expect(ranged.status).toBe(206);
    const rangedBody = Buffer.from(await ranged.arrayBuffer());
    expect(rangedBody.equals(Buffer.from(bigContent.subarray(start, end + 1)))).toBe(true);

    // The canonical builder emits two 4 MiB packs. Each request must locate,
    // read, and verify each immutable pack once, not once per 4 KiB cell.
    const packKeys = [...objectSizesByStorageKey]
      .filter(([, size]) => size === 4 * 1024 * 1024)
      .map(([storageKey]) => storageKey);
    expect(packKeys).toHaveLength(2);
    for (const storageKey of packKeys) {
      expect(readsByStorageKey.get(storageKey)).toBe(2);
    }
  });
});

function tenantMetadata(): MetadataRepository {
  const fail = async (): Promise<never> => {
    throw new Error("metadata should not be used by this test");
  };
  return {
    createVolume: fail,
    getHead: fail,
    getManifestDiff: fail,
    getStatus: fail,
    getCommit: fail,
    getManifest: fail,
    attachVolume: fail,
    renewLease: fail,
    checkout: fail,
    checkin: fail,
    listDelegations: fail,
    commit: fail,
    commitSummary: fail,
    commitDeltaSummary: fail,
    detach: fail,
    snapshot: fail,
    listSnapshots: fail,
    createBranch: fail,
    listBranches: fail,
    listVolumes: fail,
    listCommitHistory: fail,
    forkSnapshot: fail,
    recordBlobs: fail,
    createTenant: async () => undefined,
    createTenantToken: async () => undefined,
    resolveTenantToken: async () => ({ tenantId: "t1" }),
    resolveRuntimeReadCredential: async () => null,
    tenantOwnsVolume: async ({ tenantId }) => tenantId === "t1",
    sessionTenant: async () => "t1",
    leaseTenant: async () => "t1",
    sessionVolume: async () => null,
    leaseVolume: async () => null,
    snapshotTenant: async () => "t1",
    commitTenant: async () => "t1",
    tenantReferencesBlob: async () => true,
    tenantReferencesBlobs: async (_tenantId, digests) => new Set(digests),
    addBlobRefs: async () => undefined,
    filterUnreferencedBlobs: fail,
  };
}

function throwingBlobStore(): BlobStore {
  const fail = async (): Promise<never> => {
    throw new Error("blob store should not be used by this test");
  };
  return {
    put: fail,
    get: fail,
    has: fail,
  };
}
