import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { sha256Buffer, type BlobStore, type BlobStorePutOptions, type BlobStorePutResult } from "@portablefs/core";
import type {
  CreateVolumeInput,
  ListCommitHistoryInput,
  ListVolumesInput,
  MetadataRepository,
  VolumeHeadResult,
  VolumeListEntry,
} from "@portablefs/metadata-db";
import {
  protocolVersion,
  type BlobDigest,
  type TreeEntry,
  type VolumeBranch,
  type VolumeCommitSummary,
  type Volume,
} from "@portablefs/protocol";
import { ControlReadiness } from "./readiness.js";
import { createVolumeApiServer, type VolumeApiServerDeps } from "./server.js";

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

describe("createVolumeApiServer", () => {
  test("allows unauthenticated Railway health checks while keeping API routes protected", async () => {
    const baseUrl = await startServer("secret-token");

    const health = await fetch(`${baseUrl}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true });

    const unauthorizedApi = await fetch(`${baseUrl}/v1/volumes/example/status`);
    expect(unauthorizedApi.status).toBe(401);
    expect(await unauthorizedApi.json()).toEqual({
      error: {
        code: "VOLUME_UNAUTHORIZED",
        message: "Unauthorized.",
      },
    });
  });

  test("serves unauthenticated /readyz from the control probe, fail-closed", async () => {
    let probeResult = async (): Promise<{
      ok: boolean;
      migrationLineageComplete: boolean;
      reachable?: boolean;
    }> => ({ ok: true, migrationLineageComplete: true, reachable: true });
    const readiness = new ControlReadiness({
      phase: () => "serving",
      controlProbe: () => probeResult(),
      cacheTtlMs: 1,
    });
    const baseUrl = await startServer("secret-token", throwingBlobStore(), throwingMetadata(), {
      readiness,
    });

    const ready = await fetch(`${baseUrl}/readyz`);
    expect(ready.status).toBe(200);
    expect(await ready.json()).toEqual({
      ok: true,
      phase: "serving",
      control: { ok: true, migrationLineageComplete: true },
    });

    // Fail closed on a thrown probe: 503 with only the coarse code.
    probeResult = async () => {
      throw new Error("postgres://user:secret@db exploded");
    };
    await new Promise((resolve) => setTimeout(resolve, 5));
    const unready = await fetch(`${baseUrl}/readyz`);
    expect(unready.status).toBe(503);
    const body = (await unready.json()) as { ok: boolean; control: { code?: string } };
    expect(body.ok).toBe(false);
    expect(body.control.code).toBe("unreachable");
    expect(JSON.stringify(body)).not.toContain("secret");

    // /healthz stays dependency-free liveness (the quickstart compose probes it).
    const health = await fetch(`${baseUrl}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true });
  });

  test("fails /readyz closed when no readiness coordinator is configured", async () => {
    const baseUrl = await startServer("secret-token");

    const response = await fetch(`${baseUrl}/readyz`);
    expect(response.status).toBe(503);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_READINESS_UNCONFIGURED"
    );
  });

  test("applies validated transport defenses to the HTTP server", () => {
    const server = createVolumeApiServer({
      metadata: throwingMetadata(),
      blobStore: throwingBlobStore(),
    });
    expect(server.headersTimeout).toBe(30_000);
    expect(server.requestTimeout).toBe(300_000);
    expect(server.keepAliveTimeout).toBe(5_000);
    expect(server.maxRequestsPerSocket).toBe(1000);
    expect(server.maxConnections).toBe(1024);

    const tuned = createVolumeApiServer({
      metadata: throwingMetadata(),
      blobStore: throwingBlobStore(),
      httpDefenses: { maxConnections: 64, requestTimeoutMs: 60_000 },
    });
    expect(tuned.maxConnections).toBe(64);
    expect(tuned.requestTimeout).toBe(60_000);

    // A typo can never silently disable a bound.
    expect(() =>
      createVolumeApiServer({
        metadata: throwingMetadata(),
        blobStore: throwingBlobStore(),
        httpDefenses: { keepAliveTimeoutMs: 30_000 },
      })
    ).toThrow(/keepAliveTimeoutMs < headersTimeoutMs/);
    expect(() =>
      createVolumeApiServer({
        metadata: throwingMetadata(),
        blobStore: throwingBlobStore(),
        httpDefenses: { maxConnections: 0 },
      })
    ).toThrow(/maxConnections/);
  });

  test("admin history routes require the admin token and answer typed errors", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata);
    const createCutCalls: Array<Record<string, unknown>> = [];
    let adoptError: Error | undefined;
    const fakeHistory = {
      createCut: async (input: Record<string, unknown>) => {
        createCutCalls.push(input);
        return { cutId: "hcut_1", state: "pending", kind: input.kind };
      },
      cutStatus: async (_tenantId: string, cutId: string) =>
        cutId === "hcut_1" ? { cutId: "hcut_1", state: "ready", recoveryAnchorId: "ha_1" } : null,
      adoptCut: async (input: Record<string, unknown>) => {
        if (adoptError) {
          throw adoptError;
        }
        return {
          adoptionId: "hadopt_1",
          cutId: input.cutId,
          anchorId: input.anchorId,
          state: "applied",
        };
      },
    };
    (metadata as MetadataRepository & { history?: unknown }).history = fakeHistory;
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    // Fail-closed auth: no token 401, tenant token 403 (admin only).
    const unauthenticated = await fetch(`${baseUrl}/v1/admin/history/cuts`, {
      method: "POST",
      body: "{}",
    });
    expect(unauthenticated.status).toBe(401);
    const tenant = await fetch(`${baseUrl}/v1/admin/history/cuts`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: "{}",
    });
    expect(tenant.status).toBe(403);
    expect(((await tenant.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_ADMIN_REQUIRED"
    );

    const adminHeaders = {
      authorization: "Bearer secret-token",
      "content-type": "application/json",
    };

    // Create passes the exact caller shape through; the database owns
    // idempotency via the caller-supplied operation id.
    const created = await fetch(`${baseUrl}/v1/admin/history/cuts`, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({
        tenantId: "t1",
        volumeId: "vol_1",
        branchName: "main",
        kind: "recovery",
        operationId: "hcut-manual-1",
      }),
    });
    expect(created.status).toBe(200);
    expect(await created.json()).toEqual({
      cut: { cutId: "hcut_1", state: "pending", kind: "recovery" },
    });
    expect(createCutCalls[0]).toMatchObject({
      tenantId: "t1",
      volumeId: "vol_1",
      branchName: "main",
      kind: "recovery",
      operationId: "hcut-manual-1",
    });

    // Typed validation errors.
    const missingField = await fetch(`${baseUrl}/v1/admin/history/cuts`, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({ tenantId: "t1", volumeId: "vol_1", branchName: "main" }),
    });
    expect(missingField.status).toBe(400);
    expect(((await missingField.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_BODY_INVALID"
    );
    const badKind = await fetch(`${baseUrl}/v1/admin/history/cuts`, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({
        tenantId: "t1",
        volumeId: "vol_1",
        branchName: "main",
        kind: "rotate",
        operationId: "op",
      }),
    });
    expect(badKind.status).toBe(400);

    // Status: tenantId query required; 404 for unknown; passthrough otherwise.
    const noTenant = await fetch(`${baseUrl}/v1/admin/history/cuts/hcut_1`, {
      headers: adminHeaders,
    });
    expect(noTenant.status).toBe(400);
    const missing = await fetch(`${baseUrl}/v1/admin/history/cuts/hcut_404?tenantId=t1`, {
      headers: adminHeaders,
    });
    expect(missing.status).toBe(404);
    expect(((await missing.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_CUT_NOT_FOUND"
    );
    const status = await fetch(`${baseUrl}/v1/admin/history/cuts/hcut_1?tenantId=t1`, {
      headers: adminHeaders,
    });
    expect(status.status).toBe(200);
    expect(await status.json()).toEqual({
      cut: { cutId: "hcut_1", state: "ready", recoveryAnchorId: "ha_1" },
    });

    // Adopt passthrough.
    const adoptBody = JSON.stringify({
      tenantId: "t1",
      anchorId: "ha_1",
      operationId: "hadopt-manual-1",
      servingCapability: "pft2-base-v1",
    });
    const adopted = await fetch(`${baseUrl}/v1/admin/history/cuts/hcut_1/adopt`, {
      method: "POST",
      headers: adminHeaders,
      body: adoptBody,
    });
    expect(adopted.status).toBe(200);
    expect(await adopted.json()).toEqual({
      adoptionId: "hadopt_1",
      cutId: "hcut_1",
      anchorId: "ha_1",
      state: "applied",
    });

    // Typed PF0xx SQLSTATEs surface as structured conflicts, never 500s.
    for (const [code, expectedStatus] of [
      ["PF011", 400],
      ["PF002", 409],
      ["PF007", 404],
    ] as const) {
      adoptError = Object.assign(new Error(`refused ${code}`), { code });
      const refused = await fetch(`${baseUrl}/v1/admin/history/cuts/hcut_1/adopt`, {
        method: "POST",
        headers: adminHeaders,
        body: adoptBody,
      });
      expect(refused.status).toBe(expectedStatus);
      expect(((await refused.json()) as { error: { code: string } }).error.code).toBe(
        `HISTORY_${code}`
      );
    }
  });

  test("admin history routes answer 501 when the repository has no history surface", async () => {
    const baseUrl = await startServer("secret-token");

    const response = await fetch(`${baseUrl}/v1/admin/history/cuts`, {
      method: "POST",
      headers: { authorization: "Bearer secret-token", "content-type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(501);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_UNAVAILABLE"
    );
  });

  test("admin GC sweeps old unreferenced blobs, supports dry-run, and requires auth", async () => {
    const deletedObjects: string[] = [];
    const blobStore = {
      async put() {
        throw new Error("unused");
      },
      async get() {
        throw new Error("unused");
      },
      async has() {
        return false;
      },
      async delete(digest: BlobDigest) {
        deletedObjects.push(digest);
      },
    } as unknown as BlobStore;

    const metadata = throwingMetadata();
    const live = new Set<string>(["sha256:live"]);
    let blobs = [
      { digest: "sha256:live", size: 10, createdAt: 0 },
      { digest: "sha256:garbage", size: 20, createdAt: 0 },
    ];
    metadata.referencedDigests = async () => live;
    metadata.listBlobsCreatedBefore = async (cutoffMs: number) =>
      blobs.filter((blob) => blob.createdAt < cutoffMs);
    metadata.deleteBlobRecord = async (digest: string) => {
      blobs = blobs.filter((blob) => blob.digest !== digest);
    };

    const baseUrl = await startServer("secret-token", blobStore, metadata);
    const auth = { authorization: "Bearer secret-token", "content-type": "application/json" };

    const dry = await fetch(`${baseUrl}/v1/admin/gc`, {
      method: "POST",
      headers: auth,
      body: JSON.stringify({ dryRun: true }),
    });
    expect(dry.status).toBe(200);
    const dryReport = (await dry.json()) as { candidateBlobs: number; deletedBlobs: number };
    expect(dryReport.candidateBlobs).toBe(1);
    expect(dryReport.deletedBlobs).toBe(0);
    expect(deletedObjects).toEqual([]);

    const real = await fetch(`${baseUrl}/v1/admin/gc`, {
      method: "POST",
      headers: auth,
      body: JSON.stringify({}),
    });
    const report = (await real.json()) as { deletedBlobs: number; reclaimedBytes: number };
    expect(report.deletedBlobs).toBe(1);
    expect(report.reclaimedBytes).toBe(20);
    expect(deletedObjects).toEqual(["sha256:garbage"]);

    const unauth = await fetch(`${baseUrl}/v1/admin/gc`, { method: "POST", body: "{}" });
    expect(unauth.status).toBe(401);
  });

  test("admin integrity walks referenced blobs and chunks and reports the missing ones", async () => {
    const present = new Set<string>(["sha256:present", "sha256:chunk-present"]);
    const blobStore = {
      async has(digest: BlobDigest) {
        return present.has(digest);
      },
    } as unknown as BlobStore;

    const entry = (overrides: Partial<TreeEntry> & Pick<TreeEntry, "path" | "kind">): TreeEntry => ({
      mode: 0o644,
      size: 1,
      mtimeMs: 0,
      executable: false,
      ...overrides,
    });
    const zeroHash = `sha256:${"0".repeat(64)}`;
    const metadata = throwingMetadata();
    metadata.listCommits = async () => [
      {
        id: "cmt_1",
        volumeId: "vol_1",
        branchId: "brn_1",
        treeHash: zeroHash,
        mutationCount: 0,
        byteCount: 0,
        createdAt: 0,
        manifest: {
          version: protocolVersion,
          treeHash: zeroHash,
          entries: [
            entry({ kind: "directory", path: "src", mode: 0o755, size: 0 }),
            entry({
              kind: "file",
              path: "a",
              blob: { digest: "sha256:present", size: 1, compression: "none", packed: false },
            }),
            entry({
              kind: "file",
              path: "b",
              chunks: [
                { digest: "sha256:chunk-present", size: 1, offset: 0 },
                { digest: "sha256:chunk-missing", size: 1, offset: 1 },
              ],
            }),
            entry({
              kind: "file",
              path: "c",
              blob: { digest: "sha256:missing", size: 1, compression: "none", packed: false },
            }),
          ],
        },
      },
    ];

    const baseUrl = await startServer("secret-token", blobStore, metadata);
    const response = await fetch(`${baseUrl}/v1/admin/integrity`, {
      headers: { authorization: "Bearer secret-token" },
    });
    expect(response.status).toBe(200);
    const report = (await response.json()) as {
      commitsChecked: number;
      blobsChecked: number;
      missingBlobs: string[];
    };
    expect(report.commitsChecked).toBe(1);
    expect(report.blobsChecked).toBe(4);
    expect(report.missingBlobs.sort()).toEqual(["sha256:chunk-missing", "sha256:missing"]);

    const unauth = await fetch(`${baseUrl}/v1/admin/integrity`);
    expect(unauth.status).toBe(401);
  });

  test("keeps hot blob reads off the backing store", async () => {
    const bytes = Buffer.from("hot bytes\n");
    const digest = sha256Buffer(bytes);
    const blobStore = new CountingBlobStore(new Map([[digest, bytes]]));
    const metadata = throwingMetadata();
    asTenant(metadata);
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    for (let index = 0; index < 2; index += 1) {
      const response = await fetch(`${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`, {
        headers: { authorization: "Bearer tenant-token" },
      });
      expect(response.status).toBe(200);
      expect(Buffer.from(await response.arrayBuffer())).toEqual(bytes);
    }

    expect(blobStore.getCount).toBe(1);
  });

  test("uploads small blobs in one verified batch and records metadata", async () => {
    const first = Buffer.from("first\n");
    const empty = Buffer.alloc(0);
    const firstDigest = sha256Buffer(first);
    const emptyDigest = sha256Buffer(empty);
    const blobStore = new CountingBlobStore(new Map());
    const metadata = recordingMetadata();
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    const response = await fetch(`${baseUrl}/v1/blobs/batch`, {
      method: "POST",
      headers: {
        authorization: "Bearer tenant-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        blobs: [
          { digest: firstDigest, bytesBase64: first.toString("base64") },
          { digest: emptyDigest, bytesBase64: "" },
        ],
      }),
    });

    expect(response.status).toBe(201);
    await expect(blobStore.get(firstDigest)).resolves.toEqual(first);
    await expect(blobStore.get(emptyDigest)).resolves.toEqual(empty);
    expect(metadata.recorded.map((record) => record.digest).sort()).toEqual(
      [emptyDigest, firstDigest].sort()
    );
    expect(blobStore.putOptions.every((options) => options?.checkExisting === false)).toBe(true);
  });

  test("uploads small blobs through compact binary batch and records metadata", async () => {
    const first = Buffer.from("binary first\n");
    const second = Buffer.from("binary second\n");
    const firstDigest = sha256Buffer(first);
    const secondDigest = sha256Buffer(second);
    const blobStore = new CountingBlobStore(new Map());
    const metadata = recordingMetadata();
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    const response = await fetch(`${baseUrl}/v1/blobs/batch-binary`, {
      method: "POST",
      headers: {
        authorization: "Bearer tenant-token",
        "content-type": "application/vnd.portablefs.blob-batch.v1",
      },
      body: new Uint8Array(encodeTestBlobBatch([
        { digest: firstDigest, bytes: first },
        { digest: secondDigest, bytes: second },
      ])),
    });

    expect(response.status).toBe(201);
    await expect(blobStore.get(firstDigest)).resolves.toEqual(first);
    await expect(blobStore.get(secondDigest)).resolves.toEqual(second);
    expect(metadata.recorded.map((record) => record.digest).sort()).toEqual(
      [firstDigest, secondDigest].sort()
    );
    expect(blobStore.putOptions.every((options) => options?.checkExisting === false)).toBe(true);
  });

  test("can acknowledge binary blob batches without returning every blob ref", async () => {
    const first = Buffer.from("ack binary first\n");
    const second = Buffer.from("ack binary second\n");
    const firstDigest = sha256Buffer(first);
    const secondDigest = sha256Buffer(second);
    const blobStore = new CountingBlobStore(new Map());
    const metadata = recordingMetadata();
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    const response = await fetch(`${baseUrl}/v1/blobs/batch-binary?response=ack`, {
      method: "POST",
      headers: {
        authorization: "Bearer tenant-token",
        "content-type": "application/vnd.portablefs.blob-batch.v1",
      },
      body: new Uint8Array(encodeTestBlobBatch([
        { digest: firstDigest, bytes: first },
        { digest: secondDigest, bytes: second },
      ])),
    });

    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({
      count: 2,
      bytes: first.byteLength + second.byteLength,
    });
    await expect(blobStore.get(firstDigest)).resolves.toEqual(first);
    await expect(blobStore.get(secondDigest)).resolves.toEqual(second);
    expect(metadata.recorded.map((record) => record.digest).sort()).toEqual(
      [firstDigest, secondDigest].sort()
    );
  });

  test("uploads binary blobs without object-store existence preflight", async () => {
    const bytes = Buffer.from("large-ish chunk bytes\n");
    const digest = sha256Buffer(bytes);
    const blobStore = new CountingBlobStore(new Map());
    const metadata = recordingMetadata();
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    const response = await fetch(`${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`, {
      method: "PUT",
      headers: {
        authorization: "Bearer tenant-token",
        "content-type": "application/octet-stream",
      },
      body: new Uint8Array(bytes),
    });

    expect(response.status).toBe(201);
    expect(blobStore.putOptions[0]?.checkExisting).toBe(false);
    await expect(blobStore.get(digest)).resolves.toEqual(bytes);
  });

  test("validates commit blobs from metadata without object-store hot-path checks", async () => {
    const bytes = Buffer.from("commit delta bytes\n");
    const digest = sha256Buffer(bytes);
    const treeHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const blobStore = new CountingBlobStore(new Map([[digest, bytes]]));
    const metadata = throwingMetadata();
    metadata.hasBlobs = async (digests) => new Set(digests);
    metadata.commitDeltaSummary = async () => ({
      commit: {
        id: "cmt_next",
        volumeId: "vol_commit",
        branchId: "br_commit",
        parentCommitId: "cmt_base",
        treeHash,
        mutationCount: 1,
        byteCount: bytes.byteLength,
        createdAt: Date.now(),
      },
      branch: {
        id: "br_commit",
        volumeId: "vol_commit",
        name: "main",
        headCommitId: "cmt_next",
        createdAt: Date.now(),
        updatedAt: Date.now(),
      },
    });
    asTenant(metadata);
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    const response = await fetch(`${baseUrl}/v1/attach-sessions/as_commit/commit-delta-summary`, {
      method: "POST",
      headers: {
        authorization: "Bearer tenant-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        leaseId: "lease_commit",
        fencingToken: 1,
        expectedHeadCommitId: "cmt_base",
        targetTreeHash: treeHash,
        diff: {
          added: [
            {
              path: "file.txt",
              kind: "file",
              mode: 420,
              size: bytes.byteLength,
              mtimeMs: Date.now(),
              executable: false,
              blob: {
                digest,
                size: bytes.byteLength,
                compression: "none",
                packed: false,
              },
            },
          ],
          changed: [],
          removed: [],
          mutationCount: 1,
          byteCount: bytes.byteLength,
        },
      }),
    });

    expect(response.status).toBe(200);
    expect(blobStore.hasCount).toBe(0);
  });

  test("waits for branch head changes without returning a stale manifest", async () => {
    const metadata = waitingMetadata();
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    const started = Date.now();
    const wait = fetch(
      `${baseUrl}/v1/volumes/vol_wait/wait-head?branch=main&afterCommitId=cmt_initial&timeoutMs=5000`,
      {
        headers: { authorization: "Bearer tenant-token" },
      }
    );
    setTimeout(() => metadata.advance("cmt_next"), 25);

    const response = await wait;
    expect(response.status).toBe(200);
    const body = (await response.json()) as { changed: boolean; branch: VolumeBranch };
    expect(body.changed).toBe(true);
    expect(body.branch.headCommitId).toBe("cmt_next");
    expect(Date.now() - started).toBeLessThan(1000);
  });

  test("denies cross-tenant volume access with 404 (no existence leak)", async () => {
    const metadata = throwingMetadata();
    metadata.resolveTenantToken = async () => ({ tenantId: "t2" }); // caller is t2
    metadata.tenantOwnsVolume = async () => false; // the volume belongs to t1, not caller t2
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    const res = await fetch(`${baseUrl}/v1/volumes/vol_t1/status`, {
      headers: { authorization: "Bearer tenant-token" },
    });
    expect(res.status).toBe(404); // not 403 — cross-tenant existence is not revealed
  });

  test("blob read requires a reference; an unreferenced digest is 404 and never touches the store", async () => {
    const bytes = Buffer.from("another tenant's secret\n");
    const digest = sha256Buffer(bytes);
    const blobStore = new CountingBlobStore(new Map([[digest, bytes]]));
    const metadata = throwingMetadata();
    metadata.resolveTenantToken = async () => ({ tenantId: "t2" });
    metadata.tenantReferencesBlob = async () => false; // t2 references nothing
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    const res = await fetch(`${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`, {
      headers: { authorization: "Bearer tenant-token" },
    });
    expect(res.status).toBe(404);
    expect(blobStore.getCount).toBe(0); // the exfiltration oracle is closed
  });

  test("commit referencing a blob the tenant never uploaded is rejected before any ref is minted", async () => {
    // The exfiltration: a tenant commits a manifest naming another tenant's blob
    // digest (a tree hash needs no bytes). If the commit only checked global
    // existence and then minted a reference, the attacker would gain read access.
    const bytes = Buffer.from("victim tenant's bytes\n");
    const digest = sha256Buffer(bytes);
    const blobStore = new CountingBlobStore(new Map([[digest, bytes]])); // exists globally
    const metadata = throwingMetadata();
    asTenant(metadata, "t2"); // attacker t2 owns the session it commits to
    metadata.tenantReferencesBlobs = async () => new Set<string>(); // t2 uploaded nothing
    let commitReached = false;
    metadata.commitSummary = async () => {
      commitReached = true; // minting refs happens here — it must never be reached
      throw new Error("commit must not be reached");
    };
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    const response = await fetch(`${baseUrl}/v1/attach-sessions/as_x/commit-summary`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({
        leaseId: "lease_x",
        fencingToken: 1,
        expectedHeadCommitId: "cmt_base",
        manifest: {
          version: "portablefs-v1",
          treeHash: `sha256:${"2".repeat(64)}`,
          entries: [
            {
              path: "stolen.txt",
              kind: "file",
              mode: 420,
              size: bytes.byteLength,
              mtimeMs: 0,
              executable: false,
              blob: { digest, size: bytes.byteLength, compression: "none", packed: false },
            },
          ],
        },
        mutationCount: 1,
        byteCount: bytes.byteLength,
      }),
    });

    expect(response.status).toBe(400);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VOLUME_BLOB_MISSING");
    expect(commitReached).toBe(false); // the ref-minting commit is never reached
    expect(blobStore.getCount).toBe(0); // and the victim's bytes are never served
  });

  test("commit referencing a blob the tenant uploaded is authorized", async () => {
    const bytes = Buffer.from("my own uploaded bytes\n");
    const digest = sha256Buffer(bytes);
    const blobStore = new CountingBlobStore(new Map([[digest, bytes]]));
    const metadata = throwingMetadata();
    asTenant(metadata, "t1"); // asTenant makes tenantReferencesBlobs report possession
    metadata.hasBlobs = async (digests) => new Set(digests);
    let committed = false;
    metadata.commitSummary = async () => {
      committed = true;
      return {
        commit: {
          id: "cmt_ok",
          volumeId: "vol_ok",
          branchId: "br_ok",
          parentCommitId: "cmt_base",
          treeHash: `sha256:${"3".repeat(64)}`,
          mutationCount: 1,
          byteCount: bytes.byteLength,
          createdAt: 0,
        },
        branch: {
          id: "br_ok",
          volumeId: "vol_ok",
          name: "main",
          headCommitId: "cmt_ok",
          createdAt: 0,
          updatedAt: 0,
        },
      };
    };
    const baseUrl = await startServer("secret-token", blobStore, metadata);

    const response = await fetch(`${baseUrl}/v1/attach-sessions/as_ok/commit-summary`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({
        leaseId: "lease_ok",
        fencingToken: 1,
        expectedHeadCommitId: "cmt_base",
        manifest: {
          version: "portablefs-v1",
          treeHash: `sha256:${"3".repeat(64)}`,
          entries: [
            {
              path: "mine.txt",
              kind: "file",
              mode: 420,
              size: bytes.byteLength,
              mtimeMs: 0,
              executable: false,
              blob: { digest, size: bytes.byteLength, compression: "none", packed: false },
            },
          ],
        },
        mutationCount: 1,
        byteCount: bytes.byteLength,
      }),
    });

    expect(response.status).toBe(200);
    expect(committed).toBe(true);
    expect(blobStore.hasCount).toBe(0); // possession + metadata existence; no hot-path store check
  });

  test("admin provisions a tenant token; a tenant token cannot reach admin routes", async () => {
    const metadata = throwingMetadata();
    const created: Array<{ tenantId: string; tokenHash: string }> = [];
    metadata.createTenantToken = async (input) => {
      created.push({ tenantId: input.tenantId, tokenHash: input.tokenHash });
    };
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    const prov = await fetch(`${baseUrl}/v1/admin/tenants`, {
      method: "POST",
      headers: { authorization: "Bearer secret-token", "content-type": "application/json" },
      body: JSON.stringify({ tenantId: "tnt_x" }),
    });
    expect(prov.status).toBe(201);
    const body = (await prov.json()) as { tenantId: string; token: string };
    expect(body.tenantId).toBe("tnt_x");
    expect(typeof body.token).toBe("string");
    expect(created).toHaveLength(1);
    expect(created[0]?.tenantId).toBe("tnt_x");

    // A tenant token is rejected from admin routes.
    metadata.resolveTenantToken = async () => ({ tenantId: "tnt_x" });
    const denied = await fetch(`${baseUrl}/v1/admin/gc`, {
      method: "POST",
      headers: { authorization: "Bearer tenant-token", "content-type": "application/json" },
      body: "{}",
    });
    expect(denied.status).toBe(403);
  });

  test("an admin token cannot perform tenant data operations", async () => {
    const metadata = throwingMetadata();
    metadata.tenantOwnsVolume = async () => true;
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    const res = await fetch(`${baseUrl}/v1/volumes/vol_t1/status`, {
      headers: { authorization: "Bearer secret-token" }, // admin has no tenant
    });
    expect(res.status).toBe(403);
  });

  test("volume listing is scoped to the caller's tenant, even when another tenantId is requested", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata, "t1");
    const listCalls: ListVolumesInput[] = [];
    metadata.listVolumes = async (input) => {
      listCalls.push(input);
      return listableVolumesByTenant()[input.tenantId] ?? [];
    };
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    // The tenantId query parameter is admin-only; a tenant always lists itself.
    const res = await fetch(`${baseUrl}/v1/volumes?tenantId=t2`, {
      headers: { authorization: "Bearer tenant-token" },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      volumes: [
        {
          volumeId: "vol_a",
          tenantId: "t1",
          createdAtMs: 111,
          branches: [
            { name: "main", headCommitId: "cmt_a1" },
            { name: "dev", headCommitId: "cmt_a2" },
          ],
        },
      ],
    });
    expect(listCalls).toEqual([{ tenantId: "t1", limit: 100 }]);
  });

  test("admin volume listing requires an explicit tenantId and lists that tenant", async () => {
    const metadata = throwingMetadata();
    metadata.listVolumes = async (input) => listableVolumesByTenant()[input.tenantId] ?? [];
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const adminHeaders = { authorization: "Bearer secret-token" };

    const missing = await fetch(`${baseUrl}/v1/volumes`, { headers: adminHeaders });
    expect(missing.status).toBe(400);
    const missingBody = (await missing.json()) as { error: { code: string } };
    expect(missingBody.error.code).toBe("VOLUME_TENANT_ID_REQUIRED");

    const listed = await fetch(`${baseUrl}/v1/volumes?tenantId=t2`, { headers: adminHeaders });
    expect(listed.status).toBe(200);
    expect(await listed.json()).toEqual({
      volumes: [
        {
          volumeId: "vol_b",
          tenantId: "t2",
          createdAtMs: 222,
          branches: [{ name: "main", headCommitId: "cmt_b1" }],
        },
      ],
    });
  });

  test("volume listing clamps the limit and returns empty lists", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata, "t1");
    const limits: number[] = [];
    metadata.listVolumes = async (input) => {
      limits.push(input.limit);
      return [];
    };
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const headers = { authorization: "Bearer tenant-token" };

    const capped = await fetch(`${baseUrl}/v1/volumes?limit=9999`, { headers });
    expect(capped.status).toBe(200);
    expect(await capped.json()).toEqual({ volumes: [] });

    const small = await fetch(`${baseUrl}/v1/volumes?limit=2`, { headers });
    expect(small.status).toBe(200);

    const invalid = await fetch(`${baseUrl}/v1/volumes?limit=nope`, { headers });
    expect(invalid.status).toBe(200);

    expect(limits).toEqual([500, 2, 100]);
  });

  test("returns newest-first manifest-free commit history for a branch", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata, "t1");
    const historyCalls: ListCommitHistoryInput[] = [];
    metadata.listCommitHistory = async (input) => {
      historyCalls.push(input);
      return [
        {
          id: "cmt_2",
          volumeId: "vol_1",
          branchId: "br_1",
          parentCommitId: "cmt_1",
          treeHash: `sha256:${"2".repeat(64)}`,
          mutationCount: 3,
          byteCount: 12,
          createdAt: 2000,
        },
        {
          id: "cmt_1",
          volumeId: "vol_1",
          branchId: "br_1",
          treeHash: `sha256:${"1".repeat(64)}`,
          mutationCount: 0,
          byteCount: 0,
          createdAt: 1000,
        },
      ];
    };
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const headers = { authorization: "Bearer tenant-token" };

    const res = await fetch(`${baseUrl}/v1/volumes/vol_1/commits?branch=dev&limit=2`, { headers });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      commits: [
        {
          id: "cmt_2",
          treeHash: `sha256:${"2".repeat(64)}`,
          createdAtMs: 2000,
          mutationCount: 3,
          byteCount: 12,
          parentCommitId: "cmt_1",
        },
        {
          id: "cmt_1",
          treeHash: `sha256:${"1".repeat(64)}`,
          createdAtMs: 1000,
          mutationCount: 0,
          byteCount: 0,
        },
      ],
    });

    const defaults = await fetch(`${baseUrl}/v1/volumes/vol_1/commits`, { headers });
    expect(defaults.status).toBe(200);

    const capped = await fetch(`${baseUrl}/v1/volumes/vol_1/commits?limit=99999`, { headers });
    expect(capped.status).toBe(200);

    expect(historyCalls).toEqual([
      { tenantId: "t1", volumeId: "vol_1", branchName: "dev", limit: 2 },
      { tenantId: "t1", volumeId: "vol_1", branchName: "main", limit: 50 },
      { tenantId: "t1", volumeId: "vol_1", branchName: "main", limit: 500 },
    ]);
  });

  test("commit history returns 404 for unknown branches and cross-tenant volumes", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata, "t1");
    metadata.listCommitHistory = async () => null; // volume/branch not found
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    const unknownBranch = await fetch(`${baseUrl}/v1/volumes/vol_1/commits?branch=missing`, {
      headers: { authorization: "Bearer tenant-token" },
    });
    expect(unknownBranch.status).toBe(404);

    // Cross-tenant: the ownership guard answers 404 before the handler runs
    // (listCommitHistory stays unused, so throwingMetadata would 500 if reached).
    const crossTenant = throwingMetadata();
    crossTenant.resolveTenantToken = async () => ({ tenantId: "t2" });
    crossTenant.tenantOwnsVolume = async () => false;
    const otherBaseUrl = await startServer("secret-token", throwingBlobStore(), crossTenant);
    const denied = await fetch(`${otherBaseUrl}/v1/volumes/vol_t1/commits`, {
      headers: { authorization: "Bearer tenant-token" },
    });
    expect(denied.status).toBe(404);
  });

  test("volume creation with a tenant token defaults tenantId to the token's tenant", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata, "t1");
    const created: CreateVolumeInput[] = [];
    metadata.createVolume = async (input) => {
      created.push(input);
      return fakeCreateVolumeResult(input.tenantId);
    };
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    const omitted = await fetch(`${baseUrl}/v1/volumes`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({}),
    });
    expect(omitted.status).toBe(201);
    expect(created[0]?.tenantId).toBe("t1");

    const matching = await fetch(`${baseUrl}/v1/volumes`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ tenantId: "t1", branchName: "dev" }),
    });
    expect(matching.status).toBe(201);
    expect(created[1]).toMatchObject({ tenantId: "t1", branchName: "dev" });

    const mismatched = await fetch(`${baseUrl}/v1/volumes`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ tenantId: "t2" }),
    });
    expect(mismatched.status).toBe(403);
    const mismatchBody = (await mismatched.json()) as { error: { code: string } };
    expect(mismatchBody.error.code).toBe("VOLUME_TENANT_MISMATCH");
    expect(created).toHaveLength(2);
  });

  test("volume creation with the admin token requires an explicit tenantId", async () => {
    const metadata = throwingMetadata();
    const created: CreateVolumeInput[] = [];
    metadata.createVolume = async (input) => {
      created.push(input);
      return fakeCreateVolumeResult(input.tenantId);
    };
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const adminHeaders = {
      authorization: "Bearer secret-token",
      "content-type": "application/json",
    };

    const missing = await fetch(`${baseUrl}/v1/volumes`, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({}),
    });
    expect(missing.status).toBe(400);
    const missingBody = (await missing.json()) as { error: { code: string } };
    expect(missingBody.error.code).toBe("VOLUME_TENANT_ID_REQUIRED");
    expect(created).toHaveLength(0);

    const explicit = await fetch(`${baseUrl}/v1/volumes`, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({ tenantId: "t9" }),
    });
    expect(explicit.status).toBe(201);
    expect(created[0]?.tenantId).toBe("t9");
  });
});

// Journal activation: the poll-driven legacy→managed conversion adopt drives
// after authoring its base. The route is tenant-scoped and answers the
// orchestrator's status verbatim.
describe("journal activation route", () => {
  test("drives activateJournalBranch for the authenticated tenant and answers its status", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata);
    const calls: Array<{ tenantId: string; volumeId: string; branchName: string }> = [];
    metadata.activateJournalBranch = async (input) => {
      calls.push(input);
      return {
        state: "converting",
        branchMode: "legacy_manifest",
        conversion: { conversionId: "hconv_1", state: "final_cut", attempt: 1 },
        cut: { cutId: "hcut_1", state: "materializing", attemptCount: 1 },
      };
    };
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/activate-journal`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branch: "main" }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      state: "converting",
      branchMode: "legacy_manifest",
      conversion: { conversionId: "hconv_1" },
      // The additive top-level cut observability contract (CLI-rendered).
      cutState: "materializing",
      attemptCount: 1,
    });
    // No cut error yet -> no lastError key at all.
    expect("lastError" in body).toBe(false);
    expect(calls).toEqual([{ tenantId: "t1", volumeId: "vol_a", branchName: "main" }]);

    // The admin token carries no tenant identity and cannot activate.
    const admin = await fetch(`${baseUrl}/v1/volumes/vol_a/activate-journal`, {
      method: "POST",
      headers: { authorization: "Bearer secret-token", "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(admin.status).toBe(403);

    const unauthenticated = await fetch(`${baseUrl}/v1/volumes/vol_a/activate-journal`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(unauthenticated.status).toBe(401);
  });

  test("fails closed when the repository cannot drive activation", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata);
    delete (metadata as { activateJournalBranch?: unknown }).activateJournalBranch;
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/activate-journal`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({}),
    });
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VOLUME_ACTIVATION_UNAVAILABLE");
  });

  test("surfaces the cut's human-readable error message only, truncated to 300 chars", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata);
    const longMessage = "cut worker refused: " + "x".repeat(400);
    metadata.activateJournalBranch = async () => ({
      state: "failed",
      branchMode: "legacy_manifest",
      conversion: { conversionId: "hconv_1", state: "failed", attempt: 2 },
      cut: {
        cutId: "hcut_1",
        state: "failed",
        attemptCount: 16,
        lastError: {
          kind: "dead_letter",
          message: longMessage,
          bucketKey: "s3://internal-bucket/never-shown",
          stack: "Error: never shown\n  at worker.go:123",
        },
      },
    });
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/activate-journal`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branch: "main" }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      state: string;
      cutState: string;
      attemptCount: number;
      lastError: string;
    };
    expect(body.state).toBe("failed");
    expect(body.cutState).toBe("failed");
    expect(body.attemptCount).toBe(16);
    // The message string only — bounded, no errDoc internals.
    expect(body.lastError).toBe(longMessage.slice(0, 300));
    expect(body.lastError).toHaveLength(300);
    expect(JSON.stringify(body.lastError)).not.toContain("bucket");
  });

  test("a terminally canceled cut answers a terminal activation, never an eternal converting", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata);
    // The repository edge shape behind the incident: the cut settled
    // terminally but the conversion projection still reads mid-flight.
    metadata.activateJournalBranch = async () => ({
      state: "converting",
      branchMode: "legacy_manifest",
      conversion: { conversionId: "hconv_1", state: "final_cut", attempt: 1 },
      cut: {
        cutId: "hcut_1",
        state: "canceled",
        attemptCount: 3,
        lastError: { kind: "volume_retired", message: "volume vol_a was retired" },
      },
    });
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/activate-journal`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branch: "main" }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.state).toBe("failed");
    expect(body.cutState).toBe("canceled");
    expect(body.attemptCount).toBe(3);
    expect(body.lastError).toBe("volume vol_a was retired");
    // The nested facts stay untouched for existing consumers.
    expect(body.cut).toMatchObject({ cutId: "hcut_1", state: "canceled" });
  });

  test("an activation without a cut stays byte-compatible: no cut fields appear", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata);
    metadata.activateJournalBranch = async () => ({
      state: "active",
      branchMode: "managed_journal",
    });
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/activate-journal`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branch: "main" }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toEqual({ state: "active", branchMode: "managed_journal" });
    expect("cutState" in body).toBe(false);
    expect("attemptCount" in body).toBe(false);
    expect("lastError" in body).toBe(false);
  });
});

// The advertised minimum CLI version (PORTABLEFS_MIN_CLI_VERSION in main.ts):
// one transport hook stamps EVERY /v1 answer — routed, refused, or unknown —
// and non-/v1 surfaces stay clean. Unset, the header never appears.
describe("minimum CLI version header", () => {
  const headerName = "x-portablefs-min-cli-version";

  test("set: every /v1 response carries the header, including refusals and unknown routes", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata);
    metadata.listVolumes = async () => [];
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata, {
      minCliVersion: "0.4.7",
    });

    const listed = await fetch(`${baseUrl}/v1/volumes`, { headers: TENANT_HEADERS });
    expect(listed.status).toBe(200);
    expect(listed.headers.get(headerName)).toBe("0.4.7");

    const unauthenticated = await fetch(`${baseUrl}/v1/volumes`);
    expect(unauthenticated.status).toBe(401);
    expect(unauthenticated.headers.get(headerName)).toBe("0.4.7");

    const unknownRoute = await fetch(`${baseUrl}/v1/no-such-route?x=1`, {
      headers: TENANT_HEADERS,
    });
    expect(unknownRoute.status).toBe(404);
    expect(unknownRoute.headers.get(headerName)).toBe("0.4.7");

    // Non-/v1 surfaces (liveness) advertise nothing.
    const health = await fetch(`${baseUrl}/healthz`);
    expect(health.status).toBe(200);
    expect(health.headers.get(headerName)).toBeNull();
  });

  test("unset: no /v1 response carries the header", async () => {
    const metadata = throwingMetadata();
    asTenant(metadata);
    metadata.listVolumes = async () => [];
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const listed = await fetch(`${baseUrl}/v1/volumes`, { headers: TENANT_HEADERS });
    expect(listed.status).toBe(200);
    expect(listed.headers.get(headerName)).toBeNull();
  });
});

// Manager-minted runtime read credentials (migration 015): the per-child
// volume-api identity of managed production authorities. Tenant-scoped
// reads plus EXACTLY the pinned volume's authority lifecycle — nothing else.
describe("runtime read credentials", () => {
  const credentialSecret = "pfrc_test-runtime-credential";
  const CREDENTIAL_HEADERS = {
    authorization: `Bearer ${credentialSecret}`,
    "content-type": "application/json",
  } as const;

  // A credential pinned to vol_pinned@main of tenant t1, in a metadata world
  // where t1 owns EVERY volume — so any 404 in these tests is the pinning
  // check, never the ownership guard.
  function credentialMetadata(): MetadataRepository {
    const metadata = throwingMetadata();
    metadata.resolveRuntimeReadCredential = async (hash) =>
      hash === createHash("sha256").update(credentialSecret).digest("hex")
        ? { tenantId: "t1", volumeId: "vol_pinned", branchName: "main", readOnly: true }
        : null;
    metadata.tenantOwnsVolume = async ({ tenantId }) => tenantId === "t1";
    metadata.sessionTenant = async () => "t1";
    metadata.leaseTenant = async () => "t1";
    metadata.sessionVolume = async (id) => (id === "sess_own" ? "vol_pinned" : "vol_other");
    metadata.leaseVolume = async (id) => (id === "lease_own" ? "vol_pinned" : "vol_other");
    metadata.tenantReferencesBlob = async () => true;
    return metadata;
  }

  test("authorizes tenant-scoped reads and refuses every other volume by pinning (404, no enumeration)", async () => {
    const bytes = Buffer.from("credential-read\n");
    const digest = sha256Buffer(bytes);
    const metadata = credentialMetadata();
    const baseUrl = await startServer(
      "secret-token",
      new CountingBlobStore(new Map([[digest, bytes]])),
      metadata
    );

    const read = await fetch(`${baseUrl}/v1/blobs/${encodeURIComponent(digest)}`, {
      headers: { authorization: `Bearer ${credentialSecret}` },
    });
    expect(read.status).toBe(200);
    expect(Buffer.from(await read.arrayBuffer())).toEqual(bytes);

    // A volume route addressing ANY other volume is invisible even for
    // reads — the pinning check answers before the ownership guard.
    const foreign = await fetch(`${baseUrl}/v1/volumes/vol_other/status`, {
      headers: { authorization: `Bearer ${credentialSecret}` },
    });
    expect(foreign.status).toBe(404);
    const foreignBody = (await foreign.json()) as { error: { code: string } };
    expect(foreignBody.error.code).toBe("VOLUME_NOT_FOUND");
  });

  test("refuses mutations outside the exact lifecycle allowlist with VOLUME_READ_ONLY_CREDENTIAL", async () => {
    const metadata = credentialMetadata();
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    // A legacy manifest commit is deliberately absent from the allowlist —
    // a managed child journals through PostgreSQL, never manifest commits.
    for (const [path, body] of [
      ["/v1/attach-sessions/sess_own/commit", { manifest: { entries: [] } }],
      ["/v1/volumes/vol_pinned/snapshots", {}],
      ["/v1/volumes/vol_pinned/branches", { name: "b" }],
    ] as const) {
      const refused = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: CREDENTIAL_HEADERS,
        body: JSON.stringify(body),
      });
      expect(refused.status).toBe(403);
      const refusedBody = (await refused.json()) as { error: { code: string } };
      expect(refusedBody.error.code).toBe("VOLUME_READ_ONLY_CREDENTIAL");
    }
  });

  test("allows EXACTLY the pinned volume's authority lifecycle: attach, own-session detach, own-lease renew", async () => {
    const metadata = credentialMetadata();
    const attached: string[] = [];
    metadata.attachVolume = async (input) => {
      attached.push(input.volumeId);
      return { session: { id: "sess_own" } } as unknown as Awaited<
        ReturnType<MetadataRepository["attachVolume"]>
      >;
    };
    const detached: string[] = [];
    metadata.detach = async (input) => {
      detached.push(input.attachSessionId);
      return { id: input.attachSessionId } as unknown as Awaited<
        ReturnType<MetadataRepository["detach"]>
      >;
    };
    const renewed: string[] = [];
    metadata.renewLease = async (input) => {
      renewed.push(input.leaseId);
      return { lease: { id: input.leaseId } } as unknown as Awaited<
        ReturnType<MetadataRepository["renewLease"]>
      >;
    };
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);

    const attach = await fetch(`${baseUrl}/v1/volumes/vol_pinned/attach`, {
      method: "POST",
      headers: CREDENTIAL_HEADERS,
      body: JSON.stringify({ holderId: "authority-1" }),
    });
    expect(attach.status).toBe(200);
    expect(attached).toEqual(["vol_pinned"]);

    // Attach addressed at any other volume is refused BEFORE the handler.
    const foreignAttach = await fetch(`${baseUrl}/v1/volumes/vol_other/attach`, {
      method: "POST",
      headers: CREDENTIAL_HEADERS,
      body: JSON.stringify({ holderId: "authority-1" }),
    });
    expect(foreignAttach.status).toBe(403);
    expect(attached).toEqual(["vol_pinned"]);

    const detach = await fetch(`${baseUrl}/v1/attach-sessions/sess_own/detach`, {
      method: "POST",
      headers: CREDENTIAL_HEADERS,
      body: JSON.stringify({}),
    });
    expect(detach.status).toBe(200);
    expect(detached).toEqual(["sess_own"]);

    // A session of a DIFFERENT volume is outside the credential's shape.
    const foreignDetach = await fetch(`${baseUrl}/v1/attach-sessions/sess_foreign/detach`, {
      method: "POST",
      headers: CREDENTIAL_HEADERS,
      body: JSON.stringify({}),
    });
    expect(foreignDetach.status).toBe(403);
    expect(detached).toEqual(["sess_own"]);

    const renew = await fetch(`${baseUrl}/v1/leases/lease_own/renew`, {
      method: "POST",
      headers: CREDENTIAL_HEADERS,
      body: JSON.stringify({ fencingToken: 1, leaseTtlMs: 60_000 }),
    });
    expect(renew.status).toBe(200);
    expect(renewed).toEqual(["lease_own"]);

    const foreignRenew = await fetch(`${baseUrl}/v1/leases/lease_foreign/renew`, {
      method: "POST",
      headers: CREDENTIAL_HEADERS,
      body: JSON.stringify({ fencingToken: 1, leaseTtlMs: 60_000 }),
    });
    expect(foreignRenew.status).toBe(403);
    expect(renewed).toEqual(["lease_own"]);
  });

  test("an unknown, expired, or revoked credential is unauthorized (database resolution is the only truth)", async () => {
    const metadata = credentialMetadata();
    const baseUrl = await startServer("secret-token", throwingBlobStore(), metadata);
    const response = await fetch(`${baseUrl}/v1/volumes/vol_pinned/status`, {
      headers: { authorization: "Bearer pfrc_unknown-or-expired" },
    });
    expect(response.status).toBe(401);
  });
});

async function startServer(
  authToken: string,
  blobStore: BlobStore = throwingBlobStore(),
  metadata: MetadataRepository = throwingMetadata(),
  extras: Partial<VolumeApiServerDeps> = {}
): Promise<string> {
  const server = createVolumeApiServer({
    authToken,
    metadata,
    blobStore,
    ...extras,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function recordingMetadata(): MetadataRepository & {
  recorded: Array<{ digest: string; size: number; storageKey?: string }>;
} {
  const metadata = throwingMetadata() as MetadataRepository & {
    recorded: Array<{ digest: string; size: number; storageKey?: string }>;
  };
  metadata.recorded = [];
  metadata.recordBlobs = async (records) => {
    metadata.recorded.push(...records);
  };
  asTenant(metadata);
  return metadata;
}

function waitingMetadata(): MetadataRepository & { advance: (commitId: string) => void } {
  const metadata = throwingMetadata() as MetadataRepository & { advance: (commitId: string) => void };
  const volume: Volume = {
    id: "vol_wait",
    tenantId: "tenant_wait",
    defaultBranchId: "br_wait",
    createdAt: Date.now(),
  };
  let branch: VolumeBranch = {
    id: "br_wait",
    volumeId: volume.id,
    name: "main",
    headCommitId: "cmt_initial",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  let head: VolumeCommitSummary = {
    id: branch.headCommitId,
    volumeId: volume.id,
    branchId: branch.id,
    treeHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    mutationCount: 0,
    byteCount: 0,
    createdAt: Date.now(),
  };
  const waiters = new Set<() => void>();
  const current = (): VolumeHeadResult => ({ volume, branch, head });
  metadata.getHead = async () => current();
  metadata.waitForHead = async (input) => {
    const immediate = current();
    if (immediate.branch.headCommitId !== input.afterCommitId) {
      return immediate;
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, input.timeoutMs);
      const waiter = () => {
        clearTimeout(timer);
        waiters.delete(waiter);
        resolve();
      };
      waiters.add(waiter);
    });
    return current();
  };
  metadata.advance = (commitId: string) => {
    branch = { ...branch, headCommitId: commitId, updatedAt: Date.now() };
    head = { ...head, id: commitId, createdAt: Date.now() };
    for (const waiter of [...waiters]) {
      waiter();
    }
  };
  asTenant(metadata);
  return metadata;
}

class CountingBlobStore implements BlobStore {
  getCount = 0;
  hasCount = 0;
  readonly putOptions: Array<BlobStorePutOptions | undefined> = [];

  constructor(private readonly blobs: Map<BlobDigest, Buffer>) {}

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    this.putOptions.push(options);
    const digest = options?.digest ?? sha256Buffer(buffer);
    this.blobs.set(digest, Buffer.from(buffer));
    return {
      blob: {
        digest,
        size: buffer.byteLength,
        compression: "none",
        packed: false,
      },
    };
  }

  async get(digest: BlobDigest): Promise<Buffer> {
    this.getCount += 1;
    const bytes = this.blobs.get(digest);
    if (!bytes) {
      throw new Error(`Blob not found: ${digest}`);
    }
    return Buffer.from(bytes);
  }

  async has(digest: BlobDigest): Promise<boolean> {
    this.hasCount += 1;
    return this.blobs.has(digest);
  }
}

function encodeTestBlobBatch(entries: Array<{ digest: BlobDigest; bytes: Buffer }>): Buffer {
  const header = Buffer.allocUnsafe(8);
  header.write("OSVB", 0, "ascii");
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(entries.length, 6);
  const parts: Buffer[] = [header];
  let totalBytes = header.byteLength;
  for (const entry of entries) {
    const digest = Buffer.from(entry.digest, "utf8");
    const entryHeader = Buffer.allocUnsafe(6);
    entryHeader.writeUInt16BE(digest.byteLength, 0);
    entryHeader.writeUInt32BE(entry.bytes.byteLength, 2);
    parts.push(entryHeader, digest, entry.bytes);
    totalBytes += entryHeader.byteLength + digest.byteLength + entry.bytes.byteLength;
  }
  return Buffer.concat(parts, totalBytes);
}

function throwingMetadata(): MetadataRepository {
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
    // Auth/isolation: safe defaults so the guard never throws; tests opt in via asTenant.
    createTenant: async () => undefined,
    createTenantToken: async () => undefined,
    resolveTenantToken: async () => null,
    resolveRuntimeReadCredential: async () => null,
    tenantOwnsVolume: async () => false,
    sessionTenant: async () => null,
    leaseTenant: async () => null,
    sessionVolume: async () => null,
    leaseVolume: async () => null,
    snapshotTenant: async () => null,
    commitTenant: async () => null,
    tenantReferencesBlob: async () => false,
    tenantReferencesBlobs: async () => new Set<string>(),
    addBlobRefs: async () => undefined,
    filterUnreferencedBlobs: fail,
  };
}

// asTenant makes a mock resolve a (non-admin) bearer token to tenantId and report
// it as the owner of every resource the request touches — so a test can exercise a
// data route as an authenticated tenant.
function asTenant(metadata: MetadataRepository, tenantId = "t1"): string {
  metadata.resolveTenantToken = async () => ({ tenantId });
  metadata.tenantOwnsVolume = async (input) => input.tenantId === tenantId;
  metadata.sessionTenant = async () => tenantId;
  metadata.leaseTenant = async () => tenantId;
  metadata.snapshotTenant = async () => tenantId;
  metadata.commitTenant = async () => tenantId;
  metadata.tenantReferencesBlob = async () => true;
  metadata.tenantReferencesBlobs = async (_tenantId, digests) => new Set(digests);
  return tenantId;
}

const TENANT_HEADERS = {
  authorization: "Bearer tenant-token",
  "content-type": "application/json",
} as const;

function listableVolumesByTenant(): Record<string, VolumeListEntry[]> {
  return {
    t1: [
      {
        volume: { id: "vol_a", tenantId: "t1", defaultBranchId: "br_a", createdAt: 111 },
        branches: [
          { name: "main", headCommitId: "cmt_a1" },
          { name: "dev", headCommitId: "cmt_a2" },
        ],
      },
    ],
    t2: [
      {
        volume: { id: "vol_b", tenantId: "t2", defaultBranchId: "br_b", createdAt: 222 },
        branches: [{ name: "main", headCommitId: "cmt_b1" }],
      },
    ],
  };
}

function fakeCreateVolumeResult(tenantId: string) {
  const emptyTreeHash = `sha256:${"0".repeat(64)}`;
  return {
    volume: { id: "vol_new", tenantId, defaultBranchId: "br_new", createdAt: 0 },
    branch: {
      id: "br_new",
      volumeId: "vol_new",
      name: "main",
      headCommitId: "cmt_new",
      createdAt: 0,
      updatedAt: 0,
    },
    head: {
      id: "cmt_new",
      volumeId: "vol_new",
      branchId: "br_new",
      treeHash: emptyTreeHash,
      manifest: { version: "portablefs-v1" as const, treeHash: emptyTreeHash, entries: [] },
      mutationCount: 0,
      byteCount: 0,
      createdAt: 0,
    },
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
