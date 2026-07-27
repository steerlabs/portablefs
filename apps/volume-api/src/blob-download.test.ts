import { createHash } from "node:crypto";
import { once } from "node:events";
import { get as httpGet } from "node:http";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import { afterEach, describe, expect, test } from "vitest";
import {
  resolveBlobRange,
  sha256Buffer,
  type BlobByteStream,
  type BlobStore,
  type BlobStorePutOptions,
  type BlobStorePutResult,
  type OpenBlobStreamOptions,
} from "@portablefs/core";
import type { MetadataRepository } from "@portablefs/metadata-db";
import type { BlobDigest } from "@portablefs/protocol";
import { AdmissionController, blobStreamWindowBytes } from "./limits.js";
import { VolumeApiRuntime } from "./runtime.js";
import { createVolumeApiServer, type VolumeApiServerDeps } from "./server.js";

const servers: Array<ReturnType<typeof createVolumeApiServer>> = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          if (!server.listening) {
            resolve();
            return;
          }
          server.close(() => resolve());
        })
    )
  );
});

async function waitFor(condition: () => boolean, label: string): Promise<void> {
  const deadline = Date.now() + 4_000;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error(`Timed out waiting for ${label}.`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

// A store whose stream yields in chunks and can be gated chunk-by-chunk, so
// tests can observe partial delivery, destruction, and admission mid-flight.
class ManualStreamStore implements BlobStore {
  readonly blobs = new Map<BlobDigest, Buffer>();
  chunkBytes = 64 * 1024;
  manualGate = false;
  streamOpens = 0;
  yieldedChunks = 0;
  streamClosed = false;
  streamCompleted = false;
  lastStream: Readable | undefined;
  private chunkCredits = 0;
  private readonly gateQueue: Array<() => void> = [];

  seed(bytes: Buffer): BlobDigest {
    const digest = sha256Buffer(bytes);
    this.blobs.set(digest, bytes);
    return digest;
  }

  get pendingGates(): number {
    return this.gateQueue.length;
  }

  // Credits apply to future chunks too, so a single release-all unblocks the
  // whole remaining stream.
  releaseChunks(count: number): void {
    this.chunkCredits += count;
    while (this.chunkCredits > 0 && this.gateQueue.length > 0) {
      this.chunkCredits -= 1;
      this.gateQueue.shift()?.();
    }
  }

  private gate(): Promise<void> {
    if (!this.manualGate) {
      return Promise.resolve();
    }
    if (this.chunkCredits > 0) {
      this.chunkCredits -= 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      this.gateQueue.push(resolve);
    });
  }

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    const digest = options?.digest ?? sha256Buffer(buffer);
    this.blobs.set(digest, Buffer.from(buffer));
    return { blob: { digest, size: buffer.byteLength, compression: "none", packed: false } };
  }

  async get(digest: BlobDigest): Promise<Buffer> {
    const bytes = this.blobs.get(digest);
    if (!bytes) {
      throw new Error(`missing ${digest}`);
    }
    return bytes;
  }

  async has(digest: BlobDigest): Promise<boolean> {
    return this.blobs.has(digest);
  }

  openBlobStream = async (
    digest: BlobDigest,
    options?: OpenBlobStreamOptions
  ): Promise<BlobByteStream> => {
    const bytes = this.blobs.get(digest);
    if (!bytes) {
      throw new Error(`missing ${digest}`);
    }
    this.streamOpens += 1;
    const resolved = resolveBlobRange(options?.range, digest, bytes.byteLength);
    const body = bytes.subarray(resolved.start, resolved.end + 1);
    const store = this;
    async function* chunks(): AsyncGenerator<Buffer> {
      try {
        for (let offset = 0; offset < body.byteLength; offset += store.chunkBytes) {
          await store.gate();
          store.yieldedChunks += 1;
          yield body.subarray(offset, Math.min(offset + store.chunkBytes, body.byteLength));
        }
        store.streamCompleted = true;
      } finally {
        store.streamClosed = true;
      }
    }
    const stream = Readable.from(chunks());
    this.lastStream = stream;
    return {
      totalLength: bytes.byteLength,
      start: resolved.start,
      end: resolved.end,
      buffered: false,
      stream,
    };
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

// Minimal metadata: resolves the given bearer tokens to tenants and reports
// every digest as referenced. Everything else must never be reached.
function blobReadMetadata(tokens: Record<string, string> = { "tenant-token": "t1" }): MetadataRepository {
  const fail = async (): Promise<never> => {
    throw new Error("metadata should not be used by this test");
  };
  const byHash = new Map(Object.entries(tokens).map(([token, tenant]) => [sha256Hex(token), tenant]));
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
    resolveTenantToken: async (hash: string) => {
      const tenantId = byHash.get(hash);
      return tenantId ? { tenantId } : null;
    },
    resolveRuntimeReadCredential: async () => null,
    tenantOwnsVolume: async () => false,
    sessionTenant: async () => null,
    leaseTenant: async () => null,
    sessionVolume: async () => null,
    leaseVolume: async () => null,
    snapshotTenant: async () => null,
    commitTenant: async () => null,
    tenantReferencesBlob: async () => true,
    tenantReferencesBlobs: async () => new Set<string>(),
    addBlobRefs: async () => undefined,
    filterUnreferencedBlobs: fail,
  };
}

async function startServer(deps: Partial<VolumeApiServerDeps> & Pick<VolumeApiServerDeps, "blobStore">) {
  const server = createVolumeApiServer({
    authToken: "admin-token",
    metadata: blobReadMetadata(),
    ...deps,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

const AUTH = { authorization: "Bearer tenant-token" } as const;

describe("blob download streaming and ranges", () => {
  test("serves 200 full reads and 206 for bytes=a-b / a- / -n with exact Content-Range", async () => {
    const store = new ManualStreamStore();
    const bytes = Buffer.from("0123456789abcdefghij");
    const digest = store.seed(bytes);
    // No cache: every case exercises the streaming path.
    const baseUrl = await startServer({ blobStore: store, blobCacheMaxBytes: 0 });
    const url = `${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`;

    const full = await fetch(url, { headers: AUTH });
    expect(full.status).toBe(200);
    expect(full.headers.get("accept-ranges")).toBe("bytes");
    expect(full.headers.get("content-length")).toBe(String(bytes.byteLength));
    expect(Buffer.from(await full.arrayBuffer())).toEqual(bytes);

    const cases = [
      { range: "bytes=2-5", status: 206, contentRange: "bytes 2-5/20", body: "2345" },
      { range: "bytes=10-999", status: 206, contentRange: "bytes 10-19/20", body: "abcdefghij" },
      { range: "bytes=15-", status: 206, contentRange: "bytes 15-19/20", body: "fghij" },
      { range: "bytes=-4", status: 206, contentRange: "bytes 16-19/20", body: "ghij" },
      { range: "bytes=-999", status: 206, contentRange: "bytes 0-19/20", body: "0123456789abcdefghij" },
    ];
    for (const testCase of cases) {
      const response = await fetch(url, { headers: { ...AUTH, range: testCase.range } });
      expect(response.status, testCase.range).toBe(testCase.status);
      expect(response.headers.get("content-range"), testCase.range).toBe(testCase.contentRange);
      expect(response.headers.get("content-length")).toBe(String(testCase.body.length));
      expect(Buffer.from(await response.arrayBuffer()).toString()).toBe(testCase.body);
    }
  });

  test("marks blobs immutable and answers If-None-Match revalidation with a bodyless 304", async () => {
    const store = new ManualStreamStore();
    const bytes = Buffer.from("immutable-content-addressed-bytes");
    const digest = store.seed(bytes);
    const baseUrl = await startServer({ blobStore: store, blobCacheMaxBytes: 0 });
    const url = `${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`;

    // The digest IS the entity tag; private because the route is
    // authenticated (shared caches must never cross tenants).
    const full = await fetch(url, { headers: AUTH });
    expect(full.status).toBe(200);
    expect(full.headers.get("etag")).toBe(`"${digest}"`);
    expect(full.headers.get("cache-control")).toBe("private, max-age=31536000, immutable");
    expect(Buffer.from(await full.arrayBuffer())).toEqual(bytes);

    const revalidated = await fetch(url, {
      headers: { ...AUTH, "if-none-match": `"${digest}"` },
    });
    expect(revalidated.status).toBe(304);
    expect((await revalidated.arrayBuffer()).byteLength).toBe(0);

    // A stale validator streams the full body again.
    const stale = await fetch(url, { headers: { ...AUTH, "if-none-match": '"other"' } });
    expect(stale.status).toBe(200);
    expect(Buffer.from(await stale.arrayBuffer())).toEqual(bytes);

    // Range requests keep the validators but never answer 304 (the partial
    // is what was asked for).
    const ranged = await fetch(url, {
      headers: { ...AUTH, range: "bytes=0-3", "if-none-match": `"${digest}"` },
    });
    expect(ranged.status).toBe(206);
    expect(ranged.headers.get("etag")).toBe(`"${digest}"`);
  });

  test("answers 416 for unsatisfiable ranges (with total) and malformed/multi ranges", async () => {
    const store = new ManualStreamStore();
    const digest = store.seed(Buffer.from("0123456789"));
    const baseUrl = await startServer({ blobStore: store, blobCacheMaxBytes: 0 });
    const url = `${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`;

    // Unsatisfiable: the store resolved the size, so the total is reported.
    const past = await fetch(url, { headers: { ...AUTH, range: "bytes=10-" } });
    expect(past.status).toBe(416);
    expect(past.headers.get("content-range")).toBe("bytes */10");

    const pastBounded = await fetch(url, { headers: { ...AUTH, range: "bytes=99-100" } });
    expect(pastBounded.status).toBe(416);
    expect(pastBounded.headers.get("content-range")).toBe("bytes */10");

    // Malformed / multi-range / foreign units: refused without opening the store.
    for (const malformed of ["bytes=5-2", "bytes=", "bytes=0-1,3-4", "chars=0-5", "bytes=-0"]) {
      const before = store.streamOpens;
      const response = await fetch(url, { headers: { ...AUTH, range: malformed } });
      expect(response.status, malformed).toBe(416);
      expect(store.streamOpens, malformed).toBe(before);
    }
  });

  test("streams incrementally: bytes reach the client before the source finishes", async () => {
    const store = new ManualStreamStore();
    store.manualGate = true;
    store.chunkBytes = 64 * 1024;
    const bytes = Buffer.alloc(256 * 1024);
    for (let index = 0; index < bytes.byteLength; index += 1) {
      bytes[index] = index % 251;
    }
    const digest = store.seed(bytes);
    const baseUrl = await startServer({ blobStore: store, blobCacheMaxBytes: 0 });

    const response = await fetch(`${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`, {
      headers: AUTH,
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-length")).toBe(String(bytes.byteLength));
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error("response has no body reader");
    }

    // Let exactly one source chunk through and observe it client-side while
    // the remaining three chunks have not even been produced.
    await waitFor(() => store.pendingGates > 0, "first chunk gate");
    store.releaseChunks(1);
    const first = await reader.read();
    expect(first.done).toBe(false);
    expect((first.value?.byteLength ?? 0) > 0).toBe(true);
    expect(store.yieldedChunks).toBe(1);

    store.releaseChunks(999);
    const received: Buffer[] = [Buffer.from(first.value ?? new Uint8Array())];
    while (true) {
      const next = await reader.read();
      if (next.done) {
        break;
      }
      received.push(Buffer.from(next.value));
    }
    expect(Buffer.concat(received)).toEqual(bytes);
    expect(store.streamCompleted).toBe(true);
  });

  test("a client abort mid-stream releases admission and destroys the source stream", async () => {
    const store = new ManualStreamStore();
    store.manualGate = true;
    store.chunkBytes = 16 * 1024;
    const digest = store.seed(Buffer.alloc(128 * 1024, 3));
    const admission = new AdmissionController();
    const baseUrl = await startServer({ blobStore: store, blobCacheMaxBytes: 0, admission });

    const request = httpGet(`${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`, {
      headers: { ...AUTH },
    });
    const [response] = (await once(request, "response")) as [
      import("node:http").IncomingMessage,
    ];
    expect(response.statusCode).toBe(200);
    await waitFor(() => store.pendingGates > 0, "first chunk gate");
    store.releaseChunks(1);
    await once(response, "data");
    expect(admission.activeRequests).toBe(1);

    // Kill the client socket mid-transfer and wait for the teardown to REACH
    // the source (destroyed flips synchronously at the destroy request);
    // only then unpark the gated generator so its injected return can run —
    // a generator suspended on a gate cannot observe destruction until it
    // resumes.
    request.destroy();
    await waitFor(() => store.lastStream?.destroyed ?? false, "source destroy request");
    store.releaseChunks(999);
    await waitFor(() => admission.activeRequests === 0, "admission release after abort");
    expect(admission.reservedTransientBytes).toBe(0);
    await waitFor(() => store.streamClosed, "source stream teardown");
    // Destroyed, not completed: the source never ran to its natural end.
    expect(store.streamCompleted).toBe(false);
  });

  test("a drain destroys in-flight blob streams at the read-abort point", async () => {
    const store = new ManualStreamStore();
    store.manualGate = true;
    store.chunkBytes = 16 * 1024;
    const digest = store.seed(Buffer.alloc(128 * 1024, 7));
    const admission = new AdmissionController();
    const runtime = new VolumeApiRuntime({
      drainEffectsGraceMs: 1,
      forceCloseConnectionsMs: 50,
      hardExitMs: 60_000,
      exit: () => undefined,
      log: () => undefined,
    });
    const baseUrl = await startServer({ blobStore: store, blobCacheMaxBytes: 0, admission, runtime });

    const response = await fetch(`${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`, {
      headers: AUTH,
    });
    expect(response.status).toBe(200);
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error("response has no body reader");
    }
    await waitFor(() => store.pendingGates > 0, "first chunk gate");
    store.releaseChunks(1);
    await reader.read();

    // The client is still connected and reading; only the drain aborts it —
    // at the same point every other read-only wait dies (drainSignal).
    const shutdown = runtime.shutdown("test drain");
    const clientOutcome = await (async () => {
      const received: number[] = [];
      try {
        while (true) {
          const next = await reader.read();
          if (next.done) {
            return { failed: false, bytes: received.reduce((a, b) => a + b, 0) };
          }
          received.push(next.value.byteLength);
        }
      } catch {
        return { failed: true, bytes: received.reduce((a, b) => a + b, 0) };
      }
    })();
    // The transfer never completed: the connection died with bytes outstanding.
    expect(clientOutcome.failed).toBe(true);
    expect(clientOutcome.bytes).toBeLessThan(128 * 1024 - 16 * 1024);

    // Unpark the gated source once its teardown was requested so it can run.
    await waitFor(() => store.lastStream?.destroyed ?? false, "source destroy request");
    store.releaseChunks(999);
    await waitFor(() => admission.activeRequests === 0, "admission release during drain");
    expect(admission.reservedTransientBytes).toBe(0);
    await waitFor(() => store.streamClosed, "source stream teardown during drain");
    expect(store.streamCompleted).toBe(false);
    await shutdown;
  });
});

describe("blob download admission charges", () => {
  test("a streamed miss reserves exactly the documented window while in flight", async () => {
    const store = new ManualStreamStore();
    store.manualGate = true;
    store.chunkBytes = 32 * 1024;
    const digest = store.seed(Buffer.alloc(4 * 1024 * 1024, 5)); // far above the window
    const admission = new AdmissionController();
    const baseUrl = await startServer({ blobStore: store, blobCacheMaxBytes: 0, admission });

    const responsePromise = fetch(`${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`, {
      headers: AUTH,
    });
    await waitFor(() => store.pendingGates > 0, "stream start");
    // Mid-flight: the 4 MiB body reserves only the fixed stream window.
    expect(admission.reservedTransientBytes).toBe(blobStreamWindowBytes);

    store.releaseChunks(9999);
    const response = await responsePromise;
    expect(Buffer.from(await response.arrayBuffer()).byteLength).toBe(4 * 1024 * 1024);
    await waitFor(() => admission.reservedTransientBytes === 0, "release on completion");
  });

  test("a buffered cache hit charges its actual byte length and refuses typed when the budget cannot take it", async () => {
    const store = new ManualStreamStore();
    const bytes = Buffer.alloc(200 * 1024, 9);
    const digest = store.seed(bytes);
    // Budget: the window (route reserve) plus only 100 KiB of headroom — a
    // 200 KiB RESIDENT response must refuse, while the same blob streaming
    // (window-only) fit fine.
    const admission = new AdmissionController({
      maxTransientBytes: blobStreamWindowBytes + 100 * 1024,
    });
    const baseUrl = await startServer({ blobStore: store, admission });
    const url = `${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`;

    // Miss: streams within the window and tees the blob into the cache.
    const miss = await fetch(url, { headers: AUTH });
    expect(miss.status).toBe(200);
    expect(Buffer.from(await miss.arrayBuffer())).toEqual(bytes);

    // Hit: now buffered — charging the honest 200 KiB overflows the budget.
    const hit = await fetch(url, { headers: AUTH });
    expect(hit.status).toBe(429);
    const body = (await hit.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VOLUME_OVERLOADED");
    await waitFor(() => admission.reservedTransientBytes === 0, "release after refusal");
  });
});

describe("per-tenant admission", () => {
  test("one tenant tripping its request cap answers VOLUME_TENANT_OVERLOADED while other tenants proceed", async () => {
    const store = new ManualStreamStore();
    store.manualGate = true;
    const digest = store.seed(Buffer.alloc(64 * 1024, 1));
    const admission = new AdmissionController({ tenantMaxRequests: 1 });
    const metadata = blobReadMetadata({ "token-a": "tenant-a", "token-b": "tenant-b" });
    const baseUrl = await startServer({ blobStore: store, blobCacheMaxBytes: 0, admission, metadata });
    const url = `${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`;

    // Tenant A holds its single slot with a gated in-flight stream.
    const held = fetch(url, { headers: { authorization: "Bearer token-a" } });
    await waitFor(() => store.pendingGates > 0, "held stream start");

    const refused = await fetch(url, { headers: { authorization: "Bearer token-a" } });
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toBe("1");
    const refusedBody = (await refused.json()) as { error: { code: string } };
    expect(refusedBody.error.code).toBe("VOLUME_TENANT_OVERLOADED");

    // A different tenant is untouched by tenant A's saturation.
    const other = fetch(url, { headers: { authorization: "Bearer token-b" } });
    await waitFor(() => store.pendingGates > 1, "tenant B stream start");
    store.releaseChunks(999);
    const [heldResponse, otherResponse] = await Promise.all([held, other]);
    expect(heldResponse.status).toBe(200);
    expect(otherResponse.status).toBe(200);
    await heldResponse.arrayBuffer();
    await otherResponse.arrayBuffer();

    // The slot frees on completion: tenant A admits again.
    await waitFor(() => admission.activeRequests === 0, "all requests released");
    store.manualGate = false;
    const again = await fetch(url, { headers: { authorization: "Bearer token-a" } });
    expect(again.status).toBe(200);
    await again.arrayBuffer();
  });
});
