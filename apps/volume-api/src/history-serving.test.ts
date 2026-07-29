import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { createHash } from "node:crypto";
import type { BlobStore } from "@portablefs/core";
import type {
  HistoryObjectLocation,
  MetadataRepository,
  PostgresHistoryRepository,
  ServingBaseProof,
} from "@portablefs/metadata-db";
import {
  ExactKeyReadError,
  HistoryStoreRegistry,
  validateExactStorageKey,
  type ExactKeyReader,
} from "./history-stores.js";
import { createVolumeApiServer } from "./server.js";

// ---------------------------------------------------------------------------
// Exact history serving over an in-process server: DB proof first (including
// the negative case — stored bytes without a database registration must
// 404), size-bounded hash-verified reads, failure-domain failover on
// corruption, and the base-provenance proof route.
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

class MapReader implements ExactKeyReader {
  reads = 0;
  constructor(private readonly objects: Map<string, Buffer>) {}

  async readExactKey(
    storageKey: string,
    options: { expectedSize: number; maxBytes: number }
  ): Promise<Buffer> {
    this.reads += 1;
    validateExactStorageKey(storageKey);
    const bytes = this.objects.get(storageKey);
    if (!bytes) {
      throw new ExactKeyReadError("not_found", "missing");
    }
    if (bytes.byteLength !== options.expectedSize) {
      throw new ExactKeyReadError("size_mismatch", "size");
    }
    return bytes;
  }
}

function digestOf(bytes: Buffer): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function liveLocation(
  tenantId: string,
  digest: string,
  size: number,
  copies: Array<{ failureDomain: string; storageKey: string }>
): HistoryObjectLocation {
  return {
    tenantId,
    kind: "pft2",
    digest,
    size: String(size),
    incarnation: "1",
    state: "live",
    copies: copies.map((copy) => ({
      failureDomain: copy.failureDomain,
      storageKey: copy.storageKey,
      size: String(size),
      lastVerifiedDbMs: "0",
    })),
  };
}

interface FakeHistory {
  locate: (tenantId: string, digest: string) => Promise<HistoryObjectLocation | null>;
  proof?: (input: Record<string, unknown>) => Promise<ServingBaseProof | null>;
  degraded: Array<{ digest: string; failureDomain: string; reason: string }>;
}

function fakeHistoryRepository(fake: FakeHistory): PostgresHistoryRepository {
  const facade = {
    locateObject: (tenantId: string, _kind: "pft2", digest: string) =>
      fake.locate(tenantId, digest),
    servingBaseProof: (input: Record<string, unknown>) =>
      fake.proof ? fake.proof(input) : Promise.resolve(null),
    scheduleServingCopyVerification: async (input: {
      digest: string;
      failureDomain: string;
      reason: string;
    }) => {
      fake.degraded.push({
        digest: input.digest,
        failureDomain: input.failureDomain,
        reason: input.reason,
      });
      return true;
    },
  };
  return facade as unknown as PostgresHistoryRepository;
}

async function startHistoryServer(
  history: PostgresHistoryRepository,
  stores: HistoryStoreRegistry | undefined
): Promise<string> {
  const metadata = tenantMetadata();
  Object.defineProperty(metadata, "history", { value: history, enumerable: true });
  const server = createVolumeApiServer({
    authToken: "secret-token",
    metadata,
    blobStore: throwingBlobStore(),
    ...(stores ? { historyStores: stores } : {}),
    historyCopyTimeoutMs: 1_000,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

describe("GET /v1/history/objects/:digest", () => {
  test("serves verified bytes only after a positive database location proof", async () => {
    const bytes = Buffer.from("exact history object bytes");
    const digest = digestOf(bytes);
    const reader = new MapReader(new Map([["t/t1/pft2/aa/obj/i1", bytes]]));
    const stores = new HistoryStoreRegistry([{ failureDomain: "dom-a", reader }]);
    const fake: FakeHistory = {
      locate: async (tenantId, requested) =>
        requested === digest
          ? liveLocation(tenantId, digest, bytes.byteLength, [
              { failureDomain: "dom-a", storageKey: "t/t1/pft2/aa/obj/i1" },
            ])
          : null,
      degraded: [],
    };
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), stores);

    const response = await fetch(`${baseUrl}/v1/history/objects/${digest}`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);
    expect(Buffer.from(await response.arrayBuffer())).toEqual(bytes);
    expect(response.headers.get("etag")).toBe(`"${digest}"`);
    expect(response.headers.get("cache-control")).toContain("immutable");

    const head = await fetch(`${baseUrl}/v1/history/objects/${digest}`, {
      method: "HEAD",
      headers: TENANT_HEADERS,
    });
    expect(head.status).toBe(200);
    expect(head.headers.get("content-length")).toBe(String(bytes.byteLength));
  });

  test("an object present in storage but absent from the database answers 404 and never touches a store", async () => {
    const bytes = Buffer.from("stored but unregistered");
    const digest = digestOf(bytes);
    const reader = new MapReader(new Map([["t/t1/pft2/aa/orphan/i1", bytes]]));
    const stores = new HistoryStoreRegistry([{ failureDomain: "dom-a", reader }]);
    const fake: FakeHistory = { locate: async () => null, degraded: [] };
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), stores);

    const response = await fetch(`${baseUrl}/v1/history/objects/${digest}`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(404);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_NOT_FOUND"
    );
    expect(reader.reads).toBe(0);
  });

  test("a hash-mismatched copy fails closed, falls through to the next domain, and schedules scrub work", async () => {
    const bytes = Buffer.from("the true object bytes");
    const digest = digestOf(bytes);
    const corrupted = Buffer.from(bytes);
    corrupted[0] = corrupted[0]! ^ 0xff;
    const readerA = new MapReader(new Map([["t/t1/pft2/aa/x/i1", corrupted]]));
    const readerB = new MapReader(new Map([["t/t1/pft2/aa/x/i1", bytes]]));
    const stores = new HistoryStoreRegistry([
      { failureDomain: "dom-a", reader: readerA },
      { failureDomain: "dom-b", reader: readerB },
    ]);
    const fake: FakeHistory = {
      locate: async (tenantId) =>
        liveLocation(tenantId, digest, bytes.byteLength, [
          { failureDomain: "dom-a", storageKey: "t/t1/pft2/aa/x/i1" },
          { failureDomain: "dom-b", storageKey: "t/t1/pft2/aa/x/i1" },
        ]),
      degraded: [],
    };
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), stores);

    const response = await fetch(`${baseUrl}/v1/history/objects/${digest}`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);
    expect(Buffer.from(await response.arrayBuffer())).toEqual(bytes);
    expect(fake.degraded).toEqual([{ digest, failureDomain: "dom-a", reason: "corrupt" }]);
  });

  test("every copy failing answers a typed 503 HISTORY_OBJECT_UNAVAILABLE", async () => {
    const bytes = Buffer.from("unavailable object");
    const digest = digestOf(bytes);
    const reader = new MapReader(new Map());
    const stores = new HistoryStoreRegistry([{ failureDomain: "dom-a", reader }]);
    const fake: FakeHistory = {
      locate: async (tenantId) =>
        liveLocation(tenantId, digest, bytes.byteLength, [
          { failureDomain: "dom-a", storageKey: "t/t1/pft2/aa/gone/i1" },
        ]),
      degraded: [],
    };
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), stores);

    const response = await fetch(`${baseUrl}/v1/history/objects/${digest}`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(503);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_OBJECT_UNAVAILABLE"
    );
    expect(fake.degraded).toEqual([{ digest, failureDomain: "dom-a", reason: "missing" }]);
  });

  test("history serving without configured stores answers a typed 503", async () => {
    const fake: FakeHistory = { locate: async () => null, degraded: [] };
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), undefined);
    const response = await fetch(
      `${baseUrl}/v1/history/objects/${digestOf(Buffer.from("x"))}`,
      { headers: TENANT_HEADERS }
    );
    expect(response.status).toBe(503);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_SERVING_UNAVAILABLE"
    );
  });
});

describe("GET /v1/history/base-provenance/:commitId", () => {
  const baseProofQuery =
    "generationId=jgen_1&baseSeq=0&baseDigest=" +
    "0".repeat(64) +
    "&recordCodec=pfj3&controlCodec=pfc2";

  test("returns the positive manifest_v1 proof verbatim", async () => {
    const proof: ServingBaseProof = {
      v: "1",
      kind: "manifest_v1",
      tenantId: "t1",
      commitId: "cmt_base",
      volumeId: "vol_a",
      branchId: "br_a",
      generationId: "jgen_1",
      baseSeq: "0",
      baseDigest: "0".repeat(64),
      recordCodec: "pfj3",
      controlCodec: "pfc2",
    };
    const fake: FakeHistory = {
      locate: async () => null,
      proof: async () => proof,
      degraded: [],
    };
    const stores = new HistoryStoreRegistry([
      { failureDomain: "dom-a", reader: new MapReader(new Map()) },
    ]);
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), stores);

    const response = await fetch(
      `${baseUrl}/v1/history/base-provenance/cmt_base?${baseProofQuery}`,
      { headers: TENANT_HEADERS }
    );
    expect(response.status).toBe(200);
    expect((await response.json()) as Record<string, unknown>).toEqual({ provenance: proof });
  });

  test("the retired pfr1/pfc1 codec pair is refused as an invalid proof query", async () => {
    const fake: FakeHistory = {
      locate: async () => null,
      proof: async () => {
        throw new Error("a pfr1 proof query must never reach the repository");
      },
      degraded: [],
    };
    const stores = new HistoryStoreRegistry([
      { failureDomain: "dom-a", reader: new MapReader(new Map()) },
    ]);
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), stores);
    const legacyQuery =
      "generationId=jgen_1&baseSeq=0&baseDigest=" +
      "0".repeat(64) +
      "&recordCodec=pfr1&controlCodec=pfc1";
    const response = await fetch(
      `${baseUrl}/v1/history/base-provenance/cmt_base?${legacyQuery}`,
      { headers: TENANT_HEADERS }
    );
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_BASE_PROOF_INVALID"
    );
  });

  test("absence is a 404, never an inferred commit family", async () => {
    const fake: FakeHistory = {
      locate: async () => null,
      proof: async () => null,
      degraded: [],
    };
    const stores = new HistoryStoreRegistry([
      { failureDomain: "dom-a", reader: new MapReader(new Map()) },
    ]);
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), stores);
    const response = await fetch(
      `${baseUrl}/v1/history/base-provenance/cmt_base?${baseProofQuery}`,
      { headers: TENANT_HEADERS }
    );
    expect(response.status).toBe(404);
  });

  test("missing, duplicate, or unknown query fields are a typed 400", async () => {
    const fake: FakeHistory = { locate: async () => null, degraded: [] };
    const stores = new HistoryStoreRegistry([
      { failureDomain: "dom-a", reader: new MapReader(new Map()) },
    ]);
    const baseUrl = await startHistoryServer(fakeHistoryRepository(fake), stores);
    const response = await fetch(`${baseUrl}/v1/history/base-provenance/cmt_base?baseSeq=0`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_QUERY_INVALID"
    );
  });
});

function tenantMetadata(): MetadataRepository {
  const fail = async (): Promise<never> => {
    throw new Error("metadata should not be used by this test");
  };
  const metadata: MetadataRepository = {
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
  return metadata;
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
