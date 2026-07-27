import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import type { BlobStore } from "@portablefs/core";
import type {
  MetadataRepository,
  SnapshotCutRecord,
  CreateBranchFromCutInput,
} from "@portablefs/metadata-db";
import { AdmissionController } from "./limits.js";
import { VolumeApiRuntime } from "./runtime.js";
import { createVolumeApiServer, type VolumeApiServerDeps } from "./server.js";

// ---------------------------------------------------------------------------
// Journal-era serving behavior over in-process servers and fake repositories:
// admission budgets (before authentication), drain refusal, branch-mode
// gates, cut-based snapshots, branch/fork gating on cut states, receipted
// attach, wait-head abort propagation, and the additive commit-kind
// discriminator.
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

describe("admission control", () => {
  test("admits before authentication: a saturated server refuses unauthenticated floods with 429, not 401", async () => {
    const metadata = fakeMetadata();
    let releaseAuth = () => undefined as void;
    const authGate = new Promise<void>((resolve) => {
      releaseAuth = () => resolve();
    });
    // The first request parks INSIDE authentication (post-admission), holding
    // its permit; the second request must be refused by admission BEFORE its
    // (absent) credential is even looked at.
    metadata.resolveTenantToken = async () => {
      await authGate;
      return { tenantId: "t1" };
    };
    const baseUrl = await startServer({
      metadata,
      admission: new AdmissionController({ maxActiveRequests: 1 }),
    });

    const parked = fetch(`${baseUrl}/v1/volumes/vol_a/status`, {
      headers: { authorization: "Bearer tenant-token" },
    });
    await waitUntil(async () => {
      const second = await fetch(`${baseUrl}/v1/volumes/vol_a/status`);
      return second.status === 429 ? second : null;
    }).then(async (second) => {
      expect(second.status).toBe(429);
      const body = (await second.json()) as { error: { code: string } };
      expect(body.error.code).toBe("VOLUME_OVERLOADED");
    });

    releaseAuth();
    metadata.getStatus = async () => null;
    metadata.tenantOwnsVolume = async ({ tenantId }) => tenantId === "t1";
    const first = await parked;
    expect([200, 404]).toContain(first.status);
  });

  test("exec is permanently retired before body parsing or volume access", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    metadata.getStatus = async () => {
      throw new Error("retired exec must not resolve a volume");
    };
    metadata.tenantOwnsVolume = async () => {
      throw new Error("retired exec must not perform an ownership lookup");
    };
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/exec`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: "{not-json",
    });
    expect(response.status).toBe(410);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("VOLUME_EXEC_RETIRED");
    expect(body.error.message).toContain("Mount the volume");
  });

  test("a Content-Length above the route bound is refused 413 without reading the body", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    const baseUrl = await startServer({ metadata });
    // Control routes bound bodies at 64 KiB; declare 1 MiB without sending it.
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/snapshots`, {
      method: "POST",
      headers: {
        ...TENANT_HEADERS,
        "content-length": String(1024 * 1024),
      },
      body: new Uint8Array(1024 * 1024),
    }).catch(() => undefined);
    // Node may surface the early refusal as a socket reset once the server
    // answers before consuming the body; a delivered response must be 413.
    if (response) {
      expect(response.status).toBe(413);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe("VOLUME_BODY_TOO_LARGE");
    }
  });

  test("a response above the route serialization bound is a typed VOLUME_RESPONSE_TOO_LARGE", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    // Snapshot listing rides the 4 MiB control budget; return ~8 MiB of records.
    metadata.listSnapshots = async () =>
      Array.from({ length: 2000 }, (_, index) => ({
        id: `snp_${index}`,
        volumeId: "vol_a",
        branchId: "br_a",
        commitId: "cmt_a",
        name: "x".repeat(4096),
        createdAt: index,
      }));
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/snapshots`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(413);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VOLUME_RESPONSE_TOO_LARGE");
  });
});

describe("drain", () => {
  test("new work on a surviving keepalive connection is refused 503 VOLUME_DRAINING with Connection: close", async () => {
    const metadata = fakeMetadata();
    let releaseAuth = () => undefined as void;
    const authGate = new Promise<void>((resolve) => {
      releaseAuth = () => resolve();
    });
    metadata.resolveTenantToken = async () => {
      await authGate;
      return null; // resolves to 401 once released; the drain answer comes first
    };
    const runtime = new VolumeApiRuntime({
      exit: () => undefined,
      log: () => undefined,
      drainEffectsGraceMs: 50,
      forceCloseConnectionsMs: 10_000,
      hardExitMs: 10_000,
    });
    const baseUrl = await startServer({ metadata, runtime });
    const port = Number(new URL(baseUrl).port);

    // One raw keepalive socket. Request A parks inside authentication, so
    // the connection is BUSY (not idle) when the drain starts and survives
    // server.close()/closeIdleConnections(). Request B is pipelined on the
    // same surviving connection and must hit the drain refusal.
    const net = await import("node:net");
    const socket = net.connect(port, "127.0.0.1");
    await once(socket, "connect");
    const received: Buffer[] = [];
    socket.on("data", (chunk) => received.push(chunk));
    socket.write(
      `GET /v1/volumes/vol_a/status HTTP/1.1\r\nhost: x\r\nauthorization: Bearer tenant-token\r\n\r\n`
    );
    await sleep(50); // let request A park post-admission, pre-auth-resolution
    const shutdown = runtime.shutdown("test");
    socket.write(
      `GET /v1/volumes/vol_a/status HTTP/1.1\r\nhost: x\r\nauthorization: Bearer tenant-token\r\n\r\n`
    );
    await sleep(50);
    releaseAuth();
    await waitUntil(async () =>
      Buffer.concat(received).toString("utf8").includes("VOLUME_DRAINING") ? true : null
    );
    const wire = Buffer.concat(received).toString("utf8");
    expect(wire).toContain("VOLUME_DRAINING");
    expect(wire.toLowerCase()).toContain("connection: close");
    socket.destroy();
    await shutdown;
    expect(runtime.phase).toBe("closed");
    // The drain already closed the listener; the shared afterEach must not
    // double-close it.
    servers.pop();
  });
});

describe("branch-mode gates", () => {
  test("manifest reads, attach, exec, and wait-head refuse a journal-served branch typed", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    metadata.branchMode = async () => "managed_journal";
    metadata.sessionBranchMode = async () => "managed_journal";
    const baseUrl = await startServer({ metadata });

    for (const url of [
      `/v1/volumes/vol_a/status`,
      `/v1/volumes/vol_a/head`,
      `/v1/volumes/vol_a/wait-head?afterCommitId=cmt_a`,
      `/v1/volumes/vol_a/manifest-diff?baseCommitId=cmt_a`,
      `/v1/volumes/vol_a/tree`,
      `/v1/volumes/vol_a/file?path=x`,
    ]) {
      const response = await fetch(`${baseUrl}${url}`, { headers: TENANT_HEADERS });
      expect(response.status).toBe(409);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe("LIVE_AUTHORITY_ROUTE_REQUIRED");
    }

    const attach = await fetch(`${baseUrl}/v1/volumes/vol_a/attach`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ holderId: "h1" }),
    });
    expect(attach.status).toBe(409);

    const commit = await fetch(`${baseUrl}/v1/attach-sessions/as_a/commit-summary`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({}),
    });
    expect(commit.status).toBe(409);
    const commitBody = (await commit.json()) as { error: { code: string } };
    expect(commitBody.error.code).toBe("LIVE_AUTHORITY_ROUTE_REQUIRED");
  });

  test("a journal-capable repository without mode resolution fails closed 503", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    // Journal capability declared (snapshotCut) but no branchMode: never
    // infer safety from the absent capability.
    metadata.snapshotCut = async () => {
      throw new Error("unused");
    };
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/status`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VOLUME_BRANCH_MODE_UNAVAILABLE");
  });

  test("a pure-manifest repository (no journal capability) serves manifest routes as before", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    metadata.getStatus = async () => null;
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/status`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(404);
  });
});

describe("cut-based snapshots", () => {
  test("answers the cut record with its state and passes the exact-once operationId through", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    const captured: Array<{ operationId?: string; tenantId: string }> = [];
    metadata.branchMode = async () => "managed_journal";
    metadata.snapshotCut = async (input) => {
      captured.push({ tenantId: input.tenantId, ...(input.operationId ? { operationId: input.operationId } : {}) });
      return pendingCut("hcut_1");
    };
    const baseUrl = await startServer({ metadata });

    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/snapshots`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branch: "main", operationId: "op-snap-1" }),
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as { snapshot: SnapshotCutRecord };
    expect(body.snapshot.state).toBe("pending");
    expect(body.snapshot.cutId).toBe("hcut_1");
    expect(body.snapshot.commitId).toBe("cmt_base");
    expect(captured).toEqual([{ tenantId: "t1", operationId: "op-snap-1" }]);
  });

  test("lists snapshot records with lifecycle states when the repository serves them", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    metadata.listSnapshotRecords = async () => [
      { ...pendingCut("hcut_1") },
      {
        id: "snp_1",
        volumeId: "vol_a",
        branchId: "br_a",
        commitId: "cmt_pinned",
        createdAt: 5,
        state: "ready",
      },
    ];
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/snapshots`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { snapshots: SnapshotCutRecord[] };
    expect(body.snapshots.map((snapshot) => snapshot.state)).toEqual(["pending", "ready"]);
  });
});

describe("branch and fork gating on cut states", () => {
  test("a pending cut cannot be branched (typed 409); a ready cut births a managed branch", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    const fromCut: CreateBranchFromCutInput[] = [];
    let state: SnapshotCutRecord["state"] = "pending";
    metadata.resolveSnapshotSource = async () => ({
      kind: "cut",
      record: { ...pendingCut("hcut_1"), state },
    });
    metadata.createBranchFromCut = async (input) => {
      fromCut.push(input);
      return {
        branch: {
          id: "br_new",
          volumeId: "vol_a",
          name: "from-cut",
          headCommitId: "cpft2_1",
          createdAt: 0,
          updatedAt: 0,
        },
        head: {
          id: "cpft2_1",
          volumeId: "vol_a",
          branchId: "br_new",
          treeHash: `pft2:${"a".repeat(64)}`,
          mutationCount: 0,
          byteCount: 0,
          createdAt: 0,
        },
        commitKind: "pft2",
      };
    };
    const baseUrl = await startServer({ metadata });

    const pending = await fetch(`${baseUrl}/v1/volumes/vol_a/branches`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branchName: "from-cut", fromSnapshotId: "hcut_1" }),
    });
    expect(pending.status).toBe(409);
    expect(((await pending.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_CUT_NOT_READY"
    );

    state = "failed";
    const failed = await fetch(`${baseUrl}/v1/volumes/vol_a/branches`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branchName: "from-cut", fromSnapshotId: "hcut_1" }),
    });
    expect(failed.status).toBe(409);
    expect(((await failed.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_CUT_FAILED"
    );
    expect(fromCut).toHaveLength(0);

    state = "ready";
    const ready = await fetch(`${baseUrl}/v1/volumes/vol_a/branches`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branchName: "from-cut", fromSnapshotId: "hcut_1" }),
    });
    expect(ready.status).toBe(201);
    const readyBody = (await ready.json()) as { commitKind: string; branch: { name: string } };
    expect(readyBody.commitKind).toBe("pft2");
    expect(readyBody.branch.name).toBe("from-cut");
    expect(fromCut).toEqual([
      { volumeId: "vol_a", branchName: "from-cut", cutId: "hcut_1", tenantId: "t1" },
    ]);
  });

  test("a ready cut on a repository without cross-volume fork capability refuses typed; commit-pinned snapshots keep forking", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    // No forkVolumeFromCut on the fake: the route must fail closed instead
    // of birthing a destination the serving proof could never open.
    let source: Awaited<ReturnType<NonNullable<MetadataRepository["resolveSnapshotSource"]>>> = {
      kind: "cut",
      record: { ...pendingCut("hcut_1"), state: "ready" },
    };
    metadata.resolveSnapshotSource = async () => source;
    let forked = 0;
    metadata.forkSnapshot = async () => {
      forked += 1;
      return fakeCreateVolumeResult("t1");
    };
    const baseUrl = await startServer({ metadata });

    const refused = await fetch(`${baseUrl}/v1/snapshots/hcut_1/fork`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ tenantId: "t1", branchName: "main" }),
    });
    expect(refused.status).toBe(409);
    expect(((await refused.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_FORK_UNSUPPORTED"
    );
    expect(forked).toBe(0);

    source = {
      kind: "snapshot",
      snapshot: {
        id: "snp_1",
        volumeId: "vol_a",
        branchId: "br_a",
        commitId: "cmt_pinned",
        createdAt: 0,
      },
    };
    const allowed = await fetch(`${baseUrl}/v1/snapshots/snp_1/fork`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ tenantId: "t1", branchName: "main" }),
    });
    expect(allowed.status).toBe(201);
    expect(forked).toBe(1);
  });

  test("a ready journal cut forks into a new managed volume with a PFT2 head and passes the exact-once operationId through", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    metadata.resolveSnapshotSource = async () => ({
      kind: "cut",
      record: { ...pendingCut("hcut_1"), state: "ready" },
    });
    let legacyForks = 0;
    metadata.forkSnapshot = async () => {
      legacyForks += 1;
      return fakeCreateVolumeResult("t1");
    };
    const captured: Array<Parameters<NonNullable<MetadataRepository["forkVolumeFromCut"]>>[0]> = [];
    metadata.forkVolumeFromCut = async (input) => {
      captured.push(input);
      return {
        volume: { id: "pvol_new", tenantId: "t1", defaultBranchId: "pbr_new", createdAt: 0 },
        branch: {
          id: "pbr_new",
          volumeId: "pvol_new",
          name: input.branchName,
          headCommitId: "cpft2f_1",
          createdAt: 0,
          updatedAt: 0,
        },
        head: {
          id: "cpft2f_1",
          volumeId: "pvol_new",
          branchId: "pbr_new",
          parentCommitId: "cpft2_src",
          treeHash: `pft2:${"a".repeat(64)}`,
          mutationCount: 0,
          byteCount: 4096,
          createdAt: 0,
        },
        commitKind: "pft2",
        operationId: input.operationId ?? "volfork_minted",
        replayed: false,
      };
    };
    const baseUrl = await startServer({ metadata });

    const response = await fetch(`${baseUrl}/v1/snapshots/hcut_1/fork`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({
        tenantId: "t1",
        branchName: "forked",
        volumeId: "pvol_explicit",
        operationId: "op-fork-1",
      }),
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      volume: { id: string };
      branch: { name: string; headCommitId: string };
      head: { treeHash: string };
      commitKind: string;
      operationId: string;
      replayed: boolean;
    };
    expect(body.volume.id).toBe("pvol_new");
    expect(body.branch).toMatchObject({ name: "forked", headCommitId: "cpft2f_1" });
    expect(body.head.treeHash).toBe(`pft2:${"a".repeat(64)}`);
    expect(body.commitKind).toBe("pft2");
    expect(body.operationId).toBe("op-fork-1");
    expect(body.replayed).toBe(false);
    // The verified tenant, the cut id, and the explicit destination all
    // reach the repository; the legacy path is never touched.
    expect(captured).toEqual([
      {
        cutId: "hcut_1",
        tenantId: "t1",
        branchName: "forked",
        volumeId: "pvol_explicit",
        operationId: "op-fork-1",
      },
    ]);
    expect(legacyForks).toBe(0);
  });

  test("a pending cut cannot be forked", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    metadata.resolveSnapshotSource = async () => ({
      kind: "cut",
      record: pendingCut("hcut_1"),
    });
    metadata.forkVolumeFromCut = async () => {
      throw new Error("a pending cut must never reach the fork repository");
    };
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/snapshots/hcut_1/fork`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ tenantId: "t1", branchName: "main" }),
    });
    expect(response.status).toBe(409);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_CUT_NOT_READY"
    );
  });

  test("a failed cut can never be forked (typed, before the repository)", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    metadata.resolveSnapshotSource = async () => ({
      kind: "cut",
      record: { ...pendingCut("hcut_1"), state: "failed" },
    });
    metadata.forkVolumeFromCut = async () => {
      throw new Error("a failed cut must never reach the fork repository");
    };
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/snapshots/hcut_1/fork`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ tenantId: "t1", branchName: "main" }),
    });
    expect(response.status).toBe(409);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "HISTORY_CUT_FAILED"
    );
  });

  test("another tenant's cut is invisible to the fork route (404, not 403)", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    // The ownership guard resolves the cut's owner to a DIFFERENT tenant:
    // the route must answer 404 before any fork logic runs.
    metadata.snapshotTenant = async () => "t-other";
    metadata.resolveSnapshotSource = async () => {
      throw new Error("the guard must refuse before source resolution");
    };
    metadata.forkVolumeFromCut = async () => {
      throw new Error("a foreign cut must never reach the fork repository");
    };
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/snapshots/hcut_foreign/fork`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ tenantId: "t1", branchName: "main" }),
    });
    expect(response.status).toBe(404);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_NOT_FOUND"
    );
  });
});

describe("receipted attach", () => {
  test("answers 426 while disabled and never reaches the repository", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/attach-receipted`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ holderId: "h1", operationId: "op-1" }),
    });
    expect(response.status).toBe(426);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_ATTACH_RECEIPTS_UNAVAILABLE"
    );
  });

  test("passes the verified tenant and operation id into the repository and returns the receipt", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    const inputs: Array<{ tenantId?: string; operationId?: string }> = [];
    metadata.attachVolume = async (input) => {
      inputs.push({
        ...(input.tenantId ? { tenantId: input.tenantId } : {}),
        ...(input.operationId ? { operationId: input.operationId } : {}),
      });
      const session = {
        id: "att_1",
        volumeId: "vol_a",
        branchId: "br_a",
        mode: "read" as const,
        shared: false,
        rootPath: "",
        baseCommitId: "cmt_base",
        attachedAt: 1,
      };
      const branch = {
        id: "br_a",
        volumeId: "vol_a",
        name: "main",
        headCommitId: "cmt_base",
        createdAt: 0,
        updatedAt: 0,
      };
      return {
        session,
        branch,
        manifest: { version: "portablefs-v1" as const, treeHash: `sha256:${"0".repeat(64)}`, entries: [] },
        delegations: [],
        receipt: { operationId: "op-1", replayed: false, createdAt: 1 },
        current: { observedAt: 1, branch, session, activeDelegations: 0 },
      };
    };
    const baseUrl = await startServer({ metadata, receiptedAttachEnabled: true });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/attach-receipted`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ holderId: "h1", mode: "read", operationId: "op-1" }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      receipt: { operationId: string; replayed: boolean };
      current: { activeDelegations: number };
    };
    expect(body.receipt).toMatchObject({ operationId: "op-1", replayed: false });
    expect(body.current.activeDelegations).toBe(0);
    expect(inputs).toEqual([{ tenantId: "t1", operationId: "op-1" }]);
  });
});

describe("wait-head abort propagation", () => {
  test("a disconnected client aborts the repository wait through the request signal", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    let sawAbort = false;
    metadata.waitForHead = async (input) => {
      await new Promise<void>((resolve) => {
        input.signal?.addEventListener(
          "abort",
          () => {
            sawAbort = true;
            resolve();
          },
          { once: true }
        );
      });
      throw new DOMException("The head wait was aborted.", "AbortError");
    };
    const baseUrl = await startServer({ metadata });

    const controller = new AbortController();
    const request = fetch(
      `${baseUrl}/v1/volumes/vol_a/wait-head?afterCommitId=cmt_base&timeoutMs=30000`,
      { headers: TENANT_HEADERS, signal: controller.signal }
    ).catch(() => undefined);
    // Give the request time to park inside the wait, then drop the client.
    await sleep(50);
    controller.abort();
    await request;
    await waitUntil(async () => (sawAbort ? true : null));
    expect(sawAbort).toBe(true);
  });
});

describe("commit listing", () => {
  test("marks PFT2 history commits with the additive commitKind discriminator", async () => {
    const metadata = fakeMetadata();
    asTenant(metadata);
    metadata.listCommitHistory = async () => [
      {
        id: "cpft2_2",
        volumeId: "vol_a",
        branchId: "br_a",
        parentCommitId: "cmt_1",
        treeHash: `pft2:${"b".repeat(64)}`,
        mutationCount: 0,
        byteCount: 7,
        createdAt: 2,
      },
      {
        id: "cmt_1",
        volumeId: "vol_a",
        branchId: "br_a",
        treeHash: `sha256:${"1".repeat(64)}`,
        mutationCount: 1,
        byteCount: 3,
        createdAt: 1,
      },
    ];
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_a/commits`, {
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { commits: Array<Record<string, unknown>> };
    expect(body.commits[0]).toMatchObject({ id: "cpft2_2", commitKind: "pft2" });
    expect(body.commits[1]?.commitKind).toBeUndefined();
  });
});

async function startServer(extra: Partial<VolumeApiServerDeps>): Promise<string> {
  const server = createVolumeApiServer({
    authToken: "secret-token",
    metadata: fakeMetadata(),
    blobStore: throwingBlobStore(),
    ...extra,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function pendingCut(cutId: string): SnapshotCutRecord {
  return {
    id: cutId,
    volumeId: "vol_a",
    branchId: "br_a",
    commitId: "cmt_base",
    createdAt: 10,
    state: "pending",
    cutId,
    cutSeqExclusive: "4",
  };
}

function fakeMetadata(): MetadataRepository {
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil<T>(probe: () => Promise<T | null>, timeoutMs = 5000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const outcome = await probe();
    if (outcome !== null && outcome !== false) {
      return outcome as T;
    }
    if (Date.now() > deadline) {
      throw new Error("waitUntil timed out");
    }
    await sleep(10);
  }
}
