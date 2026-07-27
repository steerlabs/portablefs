import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { sha256Buffer, type BlobStore } from "@portablefs/core";
import type { MetadataRepository } from "@portablefs/metadata-db";
import type {
  BlobDigest,
  TreeEntry,
  TreeManifest,
  VolumeCommit,
  VolumeTreeResponse,
} from "@portablefs/protocol";
import { protocolVersion } from "@portablefs/protocol";
import { createVolumeApiServer } from "./server.js";

// Browse routes read committed manifests only, so every test drives the server
// through a metadata fake pinned to one volume ("vol_b") and one commit
// ("cmt_b") whose manifest is built from `fixtureEntries`.

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

const CHUNK_A = Buffer.from("chunk-a-0123456789");
const CHUNK_B = Buffer.from("chunk-b-abcdefghij");
const README = Buffer.from("hello portablefs\n");

function fileEntry(path: string, bytes: Buffer, overrides: Partial<TreeEntry> = {}): TreeEntry {
  return {
    path,
    kind: "file",
    mode: 0o644,
    size: bytes.byteLength,
    mtimeMs: 1000,
    executable: false,
    blob: { digest: sha256Buffer(bytes), size: bytes.byteLength, compression: "none", packed: false },
    ...overrides,
  };
}

function fixtureEntries(): TreeEntry[] {
  const chunked = Buffer.concat([CHUNK_A, CHUNK_B]);
  return [
    { path: "src", kind: "directory", mode: 0o755, size: 0, mtimeMs: 500, executable: false },
    fileEntry("README.md", README),
    fileEntry("src/app.ts", Buffer.from("export const app = 1;\n")),
    fileEntry("src/zz-last.ts", Buffer.from("zz\n")),
    {
      path: "src/link.ts",
      kind: "symlink",
      mode: 0o777,
      size: 0,
      mtimeMs: 600,
      executable: false,
      linkTarget: "./app.ts",
    },
    // Chunked file: two chunks, whole-file digest over the concatenation. The
    // manifest deliberately omits an explicit entry for "deep" and "deep/nested"
    // so ancestor synthesis is exercised.
    {
      path: "deep/nested/big.bin",
      kind: "file",
      mode: 0o644,
      size: chunked.byteLength,
      mtimeMs: 700,
      executable: false,
      blob: {
        digest: sha256Buffer(chunked),
        size: chunked.byteLength,
        compression: "none",
        packed: false,
      },
      chunks: [
        { digest: sha256Buffer(CHUNK_A), size: CHUNK_A.byteLength, offset: 0 },
        { digest: sha256Buffer(CHUNK_B), size: CHUNK_B.byteLength, offset: CHUNK_A.byteLength },
      ],
    },
  ];
}

function manifestOf(entries: TreeEntry[]): TreeManifest {
  return { version: protocolVersion, treeHash: `sha256:${"a".repeat(64)}`, entries };
}

function browseMetadata(tenantId = "t1"): MetadataRepository {
  const fail = async (): Promise<never> => {
    throw new Error("not used by browse tests");
  };
  const manifest = manifestOf(fixtureEntries());
  const commit: VolumeCommit = {
    id: "cmt_b",
    volumeId: "vol_b",
    branchId: "br_b",
    treeHash: manifest.treeHash,
    manifest,
    mutationCount: manifest.entries.length,
    byteCount: 0,
    createdAt: 42,
  };
  return {
    createVolume: fail,
    getHead: async ({ volumeId, branchName }) =>
      volumeId === "vol_b" && branchName === "main"
        ? {
            volume: { id: "vol_b", tenantId, defaultBranchId: "br_b", createdAt: 0 },
            branch: {
              id: "br_b",
              volumeId: "vol_b",
              name: "main",
              headCommitId: commit.id,
              createdAt: 0,
              updatedAt: 0,
            },
            head: {
              id: commit.id,
              volumeId: commit.volumeId,
              branchId: commit.branchId,
              treeHash: commit.treeHash,
              mutationCount: commit.mutationCount,
              byteCount: commit.byteCount,
              createdAt: commit.createdAt,
            },
          }
        : null,
    getManifestDiff: fail,
    getStatus: fail,
    getCommit: async (commitId) => (commitId === commit.id ? commit : null),
    getManifest: async (commitId) => (commitId === commit.id ? manifest : null),
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
    listBranches: async () => [
      {
        id: "br_b",
        volumeId: "vol_b",
        name: "main",
        headCommitId: commit.id,
        createdAt: 0,
        updatedAt: 0,
      },
    ],
    listVolumes: fail,
    listCommitHistory: fail,
    forkSnapshot: fail,
    recordBlobs: fail,
    createTenant: async () => undefined,
    createTenantToken: async () => undefined,
    resolveTenantToken: async () => ({ tenantId }),
    resolveRuntimeReadCredential: async () => null,
    tenantOwnsVolume: async (input) =>
      input.tenantId === tenantId && input.volumeId === "vol_b",
    sessionTenant: async () => null,
    leaseTenant: async () => null,
    sessionVolume: async () => null,
    leaseVolume: async () => null,
    snapshotTenant: async () => null,
    commitTenant: async () => null,
    tenantReferencesBlob: async () => true,
    tenantReferencesBlobs: async (_tenant, digests) => new Set(digests),
    addBlobRefs: async () => undefined,
    filterUnreferencedBlobs: fail,
  };
}

function fixtureBlobStore(): BlobStore {
  const blobs = new Map<BlobDigest, Buffer>();
  for (const bytes of [CHUNK_A, CHUNK_B, README]) {
    blobs.set(sha256Buffer(bytes), bytes);
  }
  for (const entry of fixtureEntries()) {
    if (entry.kind === "file" && entry.blob && !entry.chunks) {
      // Whole-file blobs; recompute from fixture definitions above.
    }
  }
  blobs.set(sha256Buffer(Buffer.from("export const app = 1;\n")), Buffer.from("export const app = 1;\n"));
  blobs.set(sha256Buffer(Buffer.from("zz\n")), Buffer.from("zz\n"));
  return {
    async put() {
      throw new Error("browse tests never write blobs");
    },
    async get(digest: BlobDigest) {
      const bytes = blobs.get(digest);
      if (!bytes) {
        throw new Error(`missing blob ${digest}`);
      }
      return Buffer.from(bytes);
    },
    async has(digest: BlobDigest) {
      return blobs.has(digest);
    },
  };
}

async function startBrowseServer(
  metadata: MetadataRepository = browseMetadata()
): Promise<string> {
  const server = createVolumeApiServer({
    authToken: "admin-token",
    metadata,
    blobStore: fixtureBlobStore(),
    blobCacheMaxBytes: 0,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

const AUTH = { authorization: "Bearer tenant-token" } as const;

async function getTree(baseUrl: string, query: string): Promise<Response> {
  return fetch(`${baseUrl}/v1/volumes/vol_b/tree${query}`, { headers: AUTH });
}

async function getFile(
  baseUrl: string,
  query: string,
  headers: Record<string, string> = {}
): Promise<Response> {
  return fetch(`${baseUrl}/v1/volumes/vol_b/file${query}`, { headers: { ...AUTH, ...headers } });
}

describe("GET /v1/volumes/:id/tree", () => {
  test("lists root children directories-first with synthesized ancestors", async () => {
    const baseUrl = await startBrowseServer();
    const response = await getTree(baseUrl, "");
    expect(response.status).toBe(200);
    const body = (await response.json()) as VolumeTreeResponse;
    expect(body.volumeId).toBe("vol_b");
    expect(body.branchName).toBe("main");
    expect(body.commitId).toBe("cmt_b");
    expect(body.entries.map((entry) => `${entry.kind}:${entry.name}`)).toEqual([
      "directory:deep",
      "directory:src",
      "file:README.md",
    ]);
    const readme = body.entries.find((entry) => entry.name === "README.md");
    expect(readme?.digest).toBe(sha256Buffer(README));
  });

  test("lists a subdirectory with files and symlinks after directories", async () => {
    const baseUrl = await startBrowseServer();
    const response = await getTree(baseUrl, "?path=src");
    const body = (await response.json()) as VolumeTreeResponse;
    expect(body.path).toBe("src");
    expect(body.entries.map((entry) => `${entry.kind}:${entry.name}`)).toEqual([
      "file:app.ts",
      "symlink:link.ts",
      "file:zz-last.ts",
    ]);
    const link = body.entries.find((entry) => entry.kind === "symlink");
    expect(link?.linkTarget).toBe("./app.ts");
  });

  test("paginates with an opaque last-name cursor across three pages", async () => {
    const baseUrl = await startBrowseServer();
    const names: string[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 3; page += 1) {
      const query = `?path=src&limit=1${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      const body = (await (await getTree(baseUrl, query)).json()) as VolumeTreeResponse;
      expect(body.entries).toHaveLength(1);
      const entry = body.entries[0];
      if (!entry) {
        throw new Error("expected one entry per page");
      }
      names.push(entry.name);
      cursor = body.nextCursor;
      if (page < 2) {
        expect(cursor).toBeDefined();
      }
    }
    expect(cursor).toBeUndefined();
    expect(names).toEqual(["app.ts", "link.ts", "zz-last.ts"]);
  });

  test("404s a missing path and 409s a file path", async () => {
    const baseUrl = await startBrowseServer();
    const missing = await getTree(baseUrl, "?path=no/such/dir");
    expect(missing.status).toBe(404);
    expect(((await missing.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_PATH_NOT_FOUND"
    );

    const file = await getTree(baseUrl, "?path=README.md");
    expect(file.status).toBe(409);
    expect(((await file.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_PATH_NOT_DIRECTORY"
    );
  });

  test("404s a commit that does not belong to the volume", async () => {
    const metadata = browseMetadata();
    const foreign: VolumeCommit = {
      id: "cmt_foreign",
      volumeId: "vol_other",
      branchId: "br_x",
      treeHash: `sha256:${"b".repeat(64)}`,
      manifest: manifestOf([]),
      mutationCount: 0,
      byteCount: 0,
      createdAt: 0,
    };
    metadata.getCommit = async (commitId) =>
      commitId === "cmt_foreign" ? foreign : commitId === "cmt_b" ? await browseMetadata().getCommit(commitId) : null;
    const baseUrl = await startBrowseServer(metadata);
    const response = await getTree(baseUrl, "?commit=cmt_foreign");
    expect(response.status).toBe(404);
  });

  test("404s cross-tenant access through the tenant guard", async () => {
    const metadata = browseMetadata();
    metadata.tenantOwnsVolume = async () => false;
    const baseUrl = await startBrowseServer(metadata);
    const response = await getTree(baseUrl, "");
    expect(response.status).toBe(404);
  });
});

describe("GET /v1/volumes/:id/file", () => {
  test("serves bytes with a strong digest ETag and no-store on branch reads", async () => {
    const baseUrl = await startBrowseServer();
    const response = await getFile(baseUrl, "?path=README.md");
    expect(response.status).toBe(200);
    expect(Buffer.from(await response.arrayBuffer())).toEqual(README);
    expect(response.headers.get("etag")).toBe(`"${sha256Buffer(README)}"`);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-portablefs-kind")).toBe("file");
    expect(response.headers.get("accept-ranges")).toBe("bytes");
  });

  test("marks pinned-commit reads immutable and honors If-None-Match with 304", async () => {
    const baseUrl = await startBrowseServer();
    const pinned = await getFile(baseUrl, "?path=README.md&commit=cmt_b");
    expect(pinned.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");

    const etag = pinned.headers.get("etag");
    expect(etag).toBeTruthy();
    const conditional = await getFile(baseUrl, "?path=README.md&commit=cmt_b", {
      "if-none-match": etag ?? "",
    });
    expect(conditional.status).toBe(304);
  });

  test("serves a single byte range with 206 and rejects bad ranges with 416", async () => {
    const baseUrl = await startBrowseServer();
    const partial = await getFile(baseUrl, "?path=README.md", { range: "bytes=6-15" });
    expect(partial.status).toBe(206);
    expect(partial.headers.get("content-range")).toBe(`bytes 6-15/${README.byteLength}`);
    expect(Buffer.from(await partial.arrayBuffer())).toEqual(README.subarray(6, 16));

    const invalid = await getFile(baseUrl, "?path=README.md", { range: "bytes=999-" });
    expect(invalid.status).toBe(416);
    expect(invalid.headers.get("content-range")).toBe(`bytes */${README.byteLength}`);
  });

  test("rejects a chunked file whose assembled bytes mismatch the digest", async () => {
    // Same chunk list, but the manifest's whole-file digest disagrees with the
    // assembly — the server must refuse rather than serve bytes under a wrong
    // strong ETag.
    const metadata = browseMetadata();
    const good = await metadata.getCommit("cmt_b");
    if (!good) {
      throw new Error("fixture commit missing");
    }
    const corrupted: VolumeCommit = {
      ...good,
      manifest: {
        ...good.manifest,
        entries: good.manifest.entries.map((entry) =>
          entry.path === "deep/nested/big.bin" && entry.blob
            ? { ...entry, blob: { ...entry.blob, digest: `sha256:${"c".repeat(64)}` } }
            : entry
        ),
      },
    };
    metadata.getCommit = async (commitId) => (commitId === "cmt_b" ? corrupted : null);
    metadata.getManifest = async (commitId) => (commitId === "cmt_b" ? corrupted.manifest : null);
    const baseUrl = await startBrowseServer(metadata);
    const response = await getFile(baseUrl, "?path=deep/nested/big.bin&commit=cmt_b");
    expect(response.status).toBe(500);
  });

  test("assembles chunked-file ranges across a chunk boundary", async () => {
    const baseUrl = await startBrowseServer();
    const whole = Buffer.concat([CHUNK_A, CHUNK_B]);
    const start = CHUNK_A.byteLength - 4;
    const end = CHUNK_A.byteLength + 5;
    const response = await getFile(baseUrl, "?path=deep/nested/big.bin", {
      range: `bytes=${start}-${end}`,
    });
    expect(response.status).toBe(206);
    expect(Buffer.from(await response.arrayBuffer())).toEqual(whole.subarray(start, end + 1));

    const full = await getFile(baseUrl, "?path=deep/nested/big.bin");
    expect(full.status).toBe(200);
    expect(Buffer.from(await full.arrayBuffer())).toEqual(whole);
  });

  test("returns symlink targets and 409s directories", async () => {
    const baseUrl = await startBrowseServer();
    const link = await getFile(baseUrl, "?path=src/link.ts");
    expect(link.status).toBe(200);
    expect(link.headers.get("x-portablefs-kind")).toBe("symlink");
    expect(await link.text()).toBe("./app.ts");

    const dir = await getFile(baseUrl, "?path=src");
    expect(dir.status).toBe(409);
    expect(((await dir.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_PATH_NOT_FILE"
    );

    const synthesized = await getFile(baseUrl, "?path=deep/nested");
    expect(synthesized.status).toBe(409);
  });

  test("sets a download disposition when requested", async () => {
    const baseUrl = await startBrowseServer();
    const response = await getFile(baseUrl, "?path=README.md&download=1");
    expect(response.headers.get("content-disposition")).toBe('attachment; filename="README.md"');
  });
});

describe("POST /v1/blobs/probe", () => {
  test("reports only digests the calling tenant does not reference", async () => {
    const metadata = browseMetadata();
    const referenced = sha256Buffer(Buffer.from("mine"));
    const foreign = sha256Buffer(Buffer.from("someone-elses"));
    metadata.filterUnreferencedBlobs = async (_tenantId, digests) =>
      digests.filter((digest) => digest !== referenced);
    const baseUrl = await startBrowseServer(metadata);
    const response = await fetch(`${baseUrl}/v1/blobs/probe`, {
      method: "POST",
      headers: { ...AUTH, "content-type": "application/json" },
      body: JSON.stringify({ digests: [referenced, foreign] }),
    });
    expect(response.status).toBe(200);
    // The foreign digest exists globally (another tenant stored it) but the
    // caller holds no reference — it MUST come back missing so possession is
    // always proven by upload.
    expect(await response.json()).toEqual({ missing: [foreign] });
  });

  test("treats every digest as missing for the admin token", async () => {
    const baseUrl = await startBrowseServer();
    const digest = sha256Buffer(Buffer.from("anything"));
    const response = await fetch(`${baseUrl}/v1/blobs/probe`, {
      method: "POST",
      headers: { authorization: "Bearer admin-token", "content-type": "application/json" },
      body: JSON.stringify({ digests: [digest, digest] }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ missing: [digest] });
  });
});

describe("blob body limits", () => {
  test("413s a blob PUT larger than maxBlobBodyBytes", async () => {
    const metadata = browseMetadata();
    const server = createVolumeApiServer({
      authToken: "admin-token",
      metadata,
      blobStore: fixtureBlobStore(),
      blobCacheMaxBytes: 0,
      maxBlobBodyBytes: 8,
    });
    servers.push(server);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address() as AddressInfo;
    const bytes = Buffer.from("way more than eight bytes");
    const response = await fetch(
      `http://127.0.0.1:${address.port}/v1/blobs/${sha256Buffer(bytes)}`,
      { method: "PUT", headers: AUTH, body: bytes }
    );
    expect(response.status).toBe(413);
  });
});
