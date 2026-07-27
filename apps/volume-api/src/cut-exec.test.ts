import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import {
  buildDirectoryTree,
  buildFileExtents,
  buildInodeIndexTree,
  compareNames,
  encodePft2Node,
  Pft2FileKind,
  Pft2MemoryStore,
  Pft2NodeKind,
  pft2RefOf,
  sha256Buffer,
  type BlobStore,
  type Pft2DirEntry,
  type Pft2Inode,
  type Pft2InodeIndexEntry,
  type Pft2Ref,
} from "@portablefs/core";
import type {
  BranchJournalBinding,
  CreateVolumeResult,
  HistoryCutStatus,
  HistoryObjectLocation,
  MetadataRepository,
  Pft2CommitProvenance,
  PostgresHistoryRepository,
  SnapshotCutRecord,
  VolumeBranchMode,
} from "@portablefs/metadata-db";
import type { TreeManifest } from "@portablefs/protocol";
import {
  ExactKeyReadError,
  HistoryStoreRegistry,
  type ExactKeyReader,
} from "./history-stores.js";
import { createVolumeApiServer } from "./server.js";

// ---------------------------------------------------------------------------
// Cut-based exec/grep on journal-served branches, over a REAL in-memory PFT2
// commit served through the exact located-copy read path (the same fixture
// discipline as pft2-read.test.ts). The journal-era metadata surfaces
// (branchMode, journalBinding, snapshotCut, listSnapshotRecords, cutStatus)
// are faked at the repository boundary so these tests stay independent of
// the Postgres schema while exercising the full route logic: dispatch,
// reuse, minting, readiness waits, refusals, and workspace exactness.
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

const TENANT_HEADERS = {
  authorization: "Bearer tenant-token",
  "content-type": "application/json",
} as const;
const COMMIT_ID = "cpft2_exec";

// ---------------------------------------------------------------------------
// PFT2 world builder: a nested file spec becomes a canonical PFT2 commit.
// ---------------------------------------------------------------------------

interface SpecEntry {
  path: string;
  content?: string | Uint8Array;
  mode?: number;
  symlinkTarget?: string;
  dir?: boolean;
}

type BuiltNode =
  | { kind: "dir"; mode: number; children: Map<string, BuiltNode>; ino: bigint }
  | { kind: "file"; mode: number; content: Uint8Array; ino: bigint }
  | { kind: "symlink"; target: string; ino: bigint };

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

function buildPft2World(store: Pft2MemoryStore, spec: SpecEntry[]): Pft2Ref {
  const root: BuiltNode = { kind: "dir", mode: 0o755, children: new Map(), ino: 0n };
  for (const entry of spec) {
    const segments = entry.path.split("/");
    let dir = root;
    for (let index = 0; index < segments.length - 1; index += 1) {
      const name = segments[index]!;
      let child = dir.children.get(name);
      if (!child) {
        child = { kind: "dir", mode: 0o755, children: new Map(), ino: 0n };
        dir.children.set(name, child);
      }
      if (child.kind !== "dir") {
        throw new Error(`spec path ${entry.path} crosses a non-directory`);
      }
      dir = child;
    }
    const leafName = segments[segments.length - 1]!;
    if (entry.dir) {
      if (!dir.children.has(leafName)) {
        dir.children.set(leafName, {
          kind: "dir",
          mode: entry.mode ?? 0o755,
          children: new Map(),
          ino: 0n,
        });
      }
    } else if (entry.symlinkTarget !== undefined) {
      dir.children.set(leafName, { kind: "symlink", target: entry.symlinkTarget, ino: 0n });
    } else {
      const content =
        typeof entry.content === "string"
          ? new TextEncoder().encode(entry.content)
          : (entry.content ?? new Uint8Array());
      dir.children.set(leafName, {
        kind: "file",
        mode: entry.mode ?? 0o644,
        content,
        ino: 0n,
      });
    }
  }

  let nextIno = 1n;
  const assignInos = (node: BuiltNode): void => {
    node.ino = nextIno;
    nextIno += 1n;
    if (node.kind === "dir") {
      for (const child of node.children.values()) {
        assignInos(child);
      }
    }
  };
  assignInos(root);

  const putInode = (inode: Pft2Inode): Pft2Ref => {
    const encoded = encodePft2Node({ kind: Pft2NodeKind.Inode, inode });
    const ref = pft2RefOf(encoded);
    store.putNode(ref, encoded);
    return ref;
  };

  const inodeIndexEntries: Pft2InodeIndexEntry[] = [];
  let direntCount = 0n;
  let logicalBytes = 0n;

  const buildNode = (node: BuiltNode): { ref: Pft2Ref; kind: Pft2FileKind } => {
    if (node.kind === "file") {
      logicalBytes += BigInt(node.content.length);
      const extentRoot = buildFileExtents(node.content, store, store);
      const ref = putInode(
        inodeOf({
          ino: node.ino,
          kind: Pft2FileKind.Regular,
          mode: node.mode,
          size: BigInt(node.content.length),
          ...(extentRoot ? { extentRoot } : {}),
        })
      );
      inodeIndexEntries.push({ ino: node.ino, inode: ref });
      return { ref, kind: Pft2FileKind.Regular };
    }
    if (node.kind === "symlink") {
      const targetBytes = BigInt(new TextEncoder().encode(node.target).length);
      logicalBytes += targetBytes;
      const ref = putInode(
        inodeOf({
          ino: node.ino,
          kind: Pft2FileKind.Symlink,
          mode: 0o777,
          size: targetBytes,
          symlinkTarget: node.target,
        })
      );
      inodeIndexEntries.push({ ino: node.ino, inode: ref });
      return { ref, kind: Pft2FileKind.Symlink };
    }
    const names = [...node.children.keys()].sort(compareNames);
    const dirEntries: Pft2DirEntry[] = [];
    for (const name of names) {
      const child = node.children.get(name)!;
      const built = buildNode(child);
      dirEntries.push({ name, ino: child.ino, kind: built.kind });
    }
    direntCount += BigInt(dirEntries.length);
    const tree = buildDirectoryTree(dirEntries, store);
    const ref = putInode(
      inodeOf({
        ino: node.ino,
        kind: Pft2FileKind.Directory,
        mode: node.mode,
        ...(tree.root ? { directoryRoot: tree.root } : {}),
      })
    );
    inodeIndexEntries.push({ ino: node.ino, inode: ref });
    return { ref, kind: Pft2FileKind.Directory };
  };

  const rootBuilt = buildNode(root);
  inodeIndexEntries.sort((left, right) => (left.ino < right.ino ? -1 : 1));
  const inodeIndex = buildInodeIndexTree(inodeIndexEntries, store);
  if (!inodeIndex.root) {
    throw new Error("inode index must exist");
  }
  const rootEncoded = encodePft2Node({
    kind: Pft2NodeKind.Root,
    root: {
      rootInode: rootBuilt.ref,
      inodeIndex: inodeIndex.root,
      maxInoSeen: nextIno - 1n,
      inodeCount: BigInt(inodeIndexEntries.length),
      direntCount,
      logicalBytes,
      features: 0n,
    },
  });
  const rootRef = pft2RefOf(rootEncoded);
  store.putNode(rootRef, rootEncoded);
  return rootRef;
}

function defaultSpec(): SpecEntry[] {
  return [
    { path: "a/hello.txt", content: "hello from pft2\n" },
    { path: "small", content: "hi\n" },
    { path: "empty", content: "" },
    { path: "zero.bin", content: new Uint8Array(8192) },
    { path: "link", symlinkTarget: "small" },
    { path: "tools/run.sh", content: "#!/bin/sh\necho ran\n", mode: 0o755 },
    { path: "nested/empty-dir", dir: true },
  ];
}

// ---------------------------------------------------------------------------
// Server fixture.
// ---------------------------------------------------------------------------

interface CutWorld {
  baseUrl: string;
  commitId: string;
  counters: { snapshotCut: number; cutStatusPolls: number };
  binding: { current: BranchJournalBinding | null };
  records: SnapshotCutRecord[];
  contentScans: Array<{ generationId: string; fromSeq: string; toSeqExclusive: string }>;
}

interface CutServerOptions {
  spec?: SpecEntry[];
  mode: VolumeBranchMode;
  /** Initial journal binding; null models an unclaimed managed branch. */
  binding?: BranchJournalBinding | null;
  records?: SnapshotCutRecord[];
  cut?: {
    readyAfterPolls?: number;
    stayPending?: boolean;
    terminalState?: "failed" | "canceled";
    /** Simulate the DB listing the minted cut once materialized. */
    appendReadyRecord?: boolean;
  };
  /** Branch head family for the unclaimed (binding null) route. */
  headKind?: "pft2" | "manifest_v1";
  /**
   * Wires metadata.journalContentRowsSince with a fixed classification of
   * the rows since a candidate cut (absent = no classification surface).
   */
  contentScan?: { contentRows: number; truncated?: boolean; scanned?: number };
  headManifest?: TreeManifest;
  omitHistoryStores?: boolean;
}

function activeBinding(nextSeq: string): BranchJournalBinding {
  return {
    generationId: "gen_1",
    branchId: "br_a",
    epoch: "1",
    recordCodec: "pfj3",
    controlCodec: "pfc2",
    baseCommitId: "cmt_anchor",
    baseSeq: "0",
    baseDigest: "d".repeat(64),
    nextSeq,
    tipDigest: "e".repeat(64),
    status: "active",
  };
}

function cutStatusOf(partial: {
  cutId: string;
  state: HistoryCutStatus["state"];
  generationId?: string;
  cutSeqExclusive?: string;
  resultCommitId?: string;
}): HistoryCutStatus {
  return {
    cutId: partial.cutId,
    tenantId: "t1",
    volumeId: "vol_a",
    branchId: "br_a",
    branchName: "main",
    kind: "user",
    sourceKind: "managed_journal",
    materializerVersion: "test",
    replicationPolicy: { v: "1", requiredFailureDomains: ["dom-a"], policyEpoch: "1" },
    dedupRevision: "1",
    state: partial.state,
    claimEpoch: "0",
    attemptCount: 1,
    nextAttemptDbMs: "0",
    createdDbMs: "0",
    updatedDbMs: "0",
    ...(partial.generationId ? { generationId: partial.generationId } : {}),
    ...(partial.cutSeqExclusive ? { cutSeqExclusive: partial.cutSeqExclusive } : {}),
    ...(partial.resultCommitId ? { resultCommitId: partial.resultCommitId } : {}),
  };
}

function readyRecord(partial: {
  cutId: string;
  resultCommitId: string;
  cutSeqExclusive?: string;
  createdAt?: number;
}): SnapshotCutRecord {
  return {
    id: partial.cutId,
    volumeId: "vol_a",
    branchId: "br_a",
    commitId: "cmt_anchor",
    createdAt: partial.createdAt ?? 10,
    state: "ready",
    cutId: partial.cutId,
    resultCommitId: partial.resultCommitId,
    ...(partial.cutSeqExclusive ? { cutSeqExclusive: partial.cutSeqExclusive } : {}),
  };
}

async function startCutServer(options: CutServerOptions): Promise<CutWorld> {
  const store = new Pft2MemoryStore();
  const rootRef = buildPft2World(store, options.spec ?? defaultSpec());
  const rootHex = Buffer.from(rootRef.digest).toString("hex");

  // Every object becomes one registered live copy at an exact key.
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
        { failureDomain: "dom-a", storageKey, size: String(bytes.byteLength), lastVerifiedDbMs: "0" },
      ],
    });
  }
  const reader: ExactKeyReader = {
    async readExactKey(storageKey, readOptions) {
      const bytes = objects.get(storageKey);
      if (!bytes) {
        throw new ExactKeyReadError("not_found", "missing");
      }
      if (bytes.byteLength !== readOptions.expectedSize) {
        throw new ExactKeyReadError("size_mismatch", "size");
      }
      return bytes;
    },
  };
  const stores = new HistoryStoreRegistry([{ failureDomain: "dom-a", reader }]);

  const world: CutWorld = {
    baseUrl: "",
    commitId: COMMIT_ID,
    counters: { snapshotCut: 0, cutStatusPolls: 0 },
    binding: { current: options.binding !== undefined ? options.binding : activeBinding("7") },
    records: options.records ?? [],
    contentScans: [],
  };

  const provenance: Pft2CommitProvenance = {
    commitId: COMMIT_ID,
    cutId: "hcut_publisher",
    tenantId: "t1",
    rootDigest: rootHex,
    rootSize: String(rootRef.size),
    maxInoSeen: "64",
    objectCount: String(objects.size),
    objectBytes: "0",
  };

  const mintedCuts = new Map<string, { polls: number }>();
  const readyAfterPolls = options.cut?.readyAfterPolls ?? 1;
  const history = {
    locateObject: async (_tenant: string, _kind: "pft2", digest: string) =>
      locations.get(digest) ?? null,
    pft2CommitProvenance: async (_tenant: string, commitId: string) =>
      commitId === COMMIT_ID ? provenance : null,
    scheduleServingCopyVerification: async () => true,
    cutStatus: async (_tenant: string, cutId: string): Promise<HistoryCutStatus | null> => {
      world.counters.cutStatusPolls += 1;
      const seeded = world.records.find(
        (record) => record.cutId === cutId && record.state === "ready" && !mintedCuts.has(cutId)
      );
      if (seeded) {
        return cutStatusOf({
          cutId,
          state: "ready",
          generationId: "gen_1",
          ...(seeded.cutSeqExclusive ? { cutSeqExclusive: seeded.cutSeqExclusive } : {}),
          ...(seeded.resultCommitId ? { resultCommitId: seeded.resultCommitId } : {}),
        });
      }
      const minted = mintedCuts.get(cutId);
      if (!minted) {
        return null;
      }
      if (options.cut?.terminalState) {
        return cutStatusOf({ cutId, state: options.cut.terminalState });
      }
      if (options.cut?.stayPending) {
        return cutStatusOf({ cutId, state: "pending" });
      }
      minted.polls += 1;
      if (minted.polls < readyAfterPolls) {
        return cutStatusOf({ cutId, state: "materializing" });
      }
      return cutStatusOf({
        cutId,
        state: "ready",
        generationId: world.binding.current?.generationId ?? "gen_1",
        ...(world.binding.current ? { cutSeqExclusive: world.binding.current.nextSeq } : {}),
        resultCommitId: COMMIT_ID,
      });
    },
  } as unknown as PostgresHistoryRepository;

  const metadata = baseMetadata();
  metadata.branchMode = async () => options.mode;
  metadata.journalBinding = async () => world.binding.current;
  metadata.listSnapshotRecords = async () => [...world.records];
  if (options.contentScan) {
    const fixed = options.contentScan;
    metadata.journalContentRowsSince = async (input) => {
      world.contentScans.push({
        generationId: input.generationId,
        fromSeq: input.fromSeq,
        toSeqExclusive: input.toSeqExclusive,
      });
      return {
        scanned: fixed.scanned ?? fixed.contentRows,
        contentRows: fixed.contentRows,
        truncated: fixed.truncated ?? false,
      };
    };
  }
  metadata.snapshotCut = async (input) => {
    world.counters.snapshotCut += 1;
    expect(input.tenantId).toBe("t1");
    const cutId = `hcut_mint_${world.counters.snapshotCut}`;
    mintedCuts.set(cutId, { polls: 0 });
    const record: SnapshotCutRecord = {
      id: cutId,
      volumeId: "vol_a",
      branchId: "br_a",
      commitId: "cmt_anchor",
      createdAt: 100 + world.counters.snapshotCut,
      state: "pending",
      cutId,
      ...(world.binding.current ? { cutSeqExclusive: world.binding.current.nextSeq } : {}),
    };
    if (options.cut?.appendReadyRecord) {
      world.records.push({ ...record, state: "ready", resultCommitId: COMMIT_ID });
    }
    return record;
  };
  metadata.listBranches = async () => [
    {
      id: "br_a",
      volumeId: "vol_a",
      name: "main",
      headCommitId: options.headKind === "manifest_v1" ? "cmt_genesis" : COMMIT_ID,
      createdAt: 0,
      updatedAt: 0,
    },
  ];
  metadata.commitKind = async (commitId) => {
    if (options.headKind === "manifest_v1" && commitId === "cmt_genesis") {
      return "manifest_v1";
    }
    return commitId === COMMIT_ID ? "pft2" : null;
  };
  metadata.getManifest = async (commitId) =>
    options.headManifest && commitId === "cmt_genesis" ? options.headManifest : null;
  Object.defineProperty(metadata, "history", { value: history, enumerable: true });

  const server = createVolumeApiServer({
    authToken: "secret-token",
    metadata,
    blobStore: throwingBlobStore(),
    ...(options.omitHistoryStores ? {} : { historyStores: stores }),
    historyCopyTimeoutMs: 1_000,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  world.baseUrl = `http://127.0.0.1:${address.port}`;
  return world;
}

async function postJson(
  baseUrl: string,
  route: string,
  body: Record<string, unknown>
): Promise<Response> {
  return fetch(`${baseUrl}${route}`, {
    method: "POST",
    headers: TENANT_HEADERS,
    body: JSON.stringify(body),
  });
}

interface GrepResponseBody {
  matches: Array<{ file: string; line: number; text: string }>;
  stoppedReason: string;
  durationMs: number;
  headCommitId: string;
  cutId?: string;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

describe("grep on journal-served branches", () => {
  test("answers matches from the exact live cut", async () => {
    const world = await startCutServer({ mode: "managed_journal" });
    const response = await postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "hello from",
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as GrepResponseBody;
    expect(body.matches).toEqual([{ file: "a/hello.txt", line: 1, text: "hello from pft2" }]);
    expect(body.stoppedReason).toBe("completed");
    expect(body.headCommitId).toBe(COMMIT_ID);
    expect(body.cutId).toBe("hcut_mint_1");
    expect(world.counters.snapshotCut).toBe(1);
  });

  test("scopes to directories, honors non-recursive listings, and caps results", async () => {
    const spec: SpecEntry[] = [
      { path: "top.txt", content: "match top\n" },
      { path: "a/one.txt", content: "match one\nmatch two\n" },
      { path: "a/b/deep.txt", content: "match deep\n" },
    ];
    const world = await startCutServer({ mode: "managed_journal", spec });

    const scoped = await postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "^match",
      directory: "a",
      recursive: false,
    });
    const scopedBody = (await scoped.json()) as GrepResponseBody;
    expect(scopedBody.matches).toEqual([
      { file: "a/one.txt", line: 1, text: "match one" },
      { file: "a/one.txt", line: 2, text: "match two" },
    ]);

    const exactFile = await postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "^match",
      directory: "top.txt",
      recursive: false,
    });
    expect(((await exactFile.json()) as GrepResponseBody).matches).toEqual([
      { file: "top.txt", line: 1, text: "match top" },
    ]);

    const capped = await postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "^match",
      maxResults: 2,
    });
    const cappedBody = (await capped.json()) as GrepResponseBody;
    expect(cappedBody.matches).toHaveLength(2);
    expect(cappedBody.stoppedReason).toBe("max_results");

    // A directory that does not exist scans nothing (legacy parity).
    const missing = await postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "^match",
      directory: "nope",
    });
    const missingBody = (await missing.json()) as GrepResponseBody;
    expect(missingBody.matches).toEqual([]);
    expect(missingBody.stoppedReason).toBe("completed");
  });

  test("catastrophic backtracking is killed at the deadline without blocking the API event loop", async () => {
    const world = await startCutServer({
      mode: "managed_journal",
      binding: null,
      spec: [{ path: "attack.txt", content: `${"a".repeat(48)}!\n` }],
    });
    const attack = postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "^(a|aa)+$",
      deadlineMs: 200,
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    const healthStarted = Date.now();
    const health = await fetch(`${world.baseUrl}/healthz`);
    expect(health.status).toBe(200);
    expect(Date.now() - healthStarted).toBeLessThan(500);

    const response = await attack;
    expect(response.status).toBe(200);
    const body = (await response.json()) as GrepResponseBody;
    expect(body.stoppedReason).toBe("deadline");
    expect(body.matches).toEqual([]);
    expect(world.counters.snapshotCut).toBe(0);
  });

  test("invalid regex syntax is rejected before a cut is minted", async () => {
    const world = await startCutServer({ mode: "managed_journal" });
    const response = await postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "(",
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_PATTERN_REJECTED"
    );
    expect(world.counters.snapshotCut).toBe(0);
  });

  test("PFT2 grep rejects an over-limit line with a typed bounded error", async () => {
    const world = await startCutServer({
      mode: "managed_journal",
      binding: null,
      spec: [{ path: "long.txt", content: "x".repeat(256 * 1024 + 1) }],
    });
    const response = await postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "x",
    });
    expect(response.status).toBe(413);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_GREP_LIMIT_EXCEEDED"
    );
  });

  test("a cut that cannot become ready inside the deadline share refuses typed", async () => {
    const world = await startCutServer({ mode: "managed_journal", cut: { stayPending: true } });
    const response = await postJson(world.baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "x",
      deadlineMs: 700,
    });
    expect(response.status).toBe(409);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_CUT_NOT_READY"
    );
  });
});

describe("legacy branches retain bounded read compatibility", () => {
  test("grep reads a manifest-headed branch without materializing host paths", async () => {
    const content = Buffer.from("legacy content\n");
    const digest = sha256Buffer(content);
    const blobs = new Map<string, Buffer>([[digest, content]]);
    const metadata = baseMetadata();
    metadata.branchMode = async () => "legacy_manifest";
    // Journal capability present (snapshotCut) so the dispatch is exercised
    // with mode resolution, exactly like the production repository.
    metadata.snapshotCut = async () => {
      throw new Error("a legacy branch must never mint a cut");
    };
    metadata.getStatus = async () => legacyStatus(digest, content.byteLength);
    const server = createVolumeApiServer({
      authToken: "secret-token",
      metadata,
      blobStore: mapBlobStore(blobs),
    });
    servers.push(server);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const grep = await postJson(baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "legacy",
    });
    expect(grep.status).toBe(200);
    const grepBody = (await grep.json()) as GrepResponseBody;
    expect(grepBody.matches).toEqual([{ file: "hello.txt", line: 1, text: "legacy content" }]);
    expect(grepBody.headCommitId).toBe("cmt_legacy");

    const exactFile = await postJson(baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "legacy",
      directory: "hello.txt",
      recursive: false,
    });
    expect(((await exactFile.json()) as GrepResponseBody).matches).toEqual([
      { file: "hello.txt", line: 1, text: "legacy content" },
    ]);
  });

  test("legacy grep also isolates catastrophic regex execution", async () => {
    const content = Buffer.from(`${"a".repeat(48)}!\n`);
    const digest = sha256Buffer(content);
    const metadata = baseMetadata();
    metadata.branchMode = async () => "legacy_manifest";
    metadata.getStatus = async () => legacyStatus(digest, content.byteLength);
    const server = createVolumeApiServer({
      authToken: "secret-token",
      metadata,
      blobStore: mapBlobStore(new Map([[digest, content]])),
    });
    servers.push(server);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const attack = postJson(baseUrl, "/v1/volumes/vol_a/grep", {
      pattern: "^(a|aa)+$",
      deadlineMs: 200,
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    const health = await fetch(`${baseUrl}/healthz`);
    expect(health.status).toBe(200);
    const response = await attack;
    expect(response.status).toBe(200);
    expect(((await response.json()) as GrepResponseBody).stoppedReason).toBe("deadline");
  });

  test("legacy grep uses the same line quota as PFT2", async () => {
    const content = Buffer.from("x".repeat(256 * 1024 + 1));
    const digest = sha256Buffer(content);
    const metadata = baseMetadata();
    metadata.branchMode = async () => "legacy_manifest";
    metadata.getStatus = async () => legacyStatus(digest, content.byteLength);
    const server = createVolumeApiServer({
      authToken: "secret-token",
      metadata,
      blobStore: mapBlobStore(new Map([[digest, content]])),
    });
    servers.push(server);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const response = await postJson(baseUrl, "/v1/volumes/vol_a/grep", { pattern: "x" });
    expect(response.status).toBe(413);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_GREP_LIMIT_EXCEEDED"
    );
  });
});

// ---------------------------------------------------------------------------
// Fixture plumbing.
// ---------------------------------------------------------------------------

function legacyStatus(digest: string, size: number): CreateVolumeResult {
  const manifest: TreeManifest = {
    version: "portablefs-v1",
    treeHash: `sha256:${"1".repeat(64)}`,
    entries: [
      {
        path: "hello.txt",
        kind: "file",
        mode: 0o644,
        size,
        mtimeMs: 0,
        executable: false,
        blob: { digest, size, compression: "none", packed: false },
      },
    ],
  };
  return {
    volume: { id: "vol_a", tenantId: "t1", defaultBranchId: "br_a", createdAt: 0 },
    branch: {
      id: "br_a",
      volumeId: "vol_a",
      name: "main",
      headCommitId: "cmt_legacy",
      createdAt: 0,
      updatedAt: 0,
    },
    head: {
      id: "cmt_legacy",
      volumeId: "vol_a",
      branchId: "br_a",
      treeHash: manifest.treeHash,
      manifest,
      mutationCount: 1,
      byteCount: size,
      createdAt: 0,
    },
  };
}

function baseMetadata(): MetadataRepository {
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

function mapBlobStore(blobs: Map<string, Buffer>): BlobStore {
  return {
    put: async () => {
      throw new Error("blob uploads are not exercised by this test");
    },
    get: async (digest) => {
      const bytes = blobs.get(digest);
      if (!bytes) {
        throw new Error(`Blob not found: ${digest}`);
      }
      return Buffer.from(bytes);
    },
    has: async (digest) => blobs.has(digest),
  };
}
