import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import type { BlobStore } from "@portablefs/core";
import type {
  JournalRetireResult,
  MetadataRepository,
  PostgresHistoryRepository,
  VolumeRetireCleanupResult,
} from "@portablefs/metadata-db";
import type { VolumeLease, VolumeSnapshot } from "@portablefs/protocol";
import { createVolumeApiServer, type VolumeApiServerDeps } from "./server.js";

// ---------------------------------------------------------------------------
// Receipted volume retirement (DELETE /v1/volumes/:volumeId) over in-process
// servers and a stateful fake repository that mirrors the migration-021
// semantics: one atomic conditional flip, after which the ownership
// resolvers treat the volume — and its leases and snapshots — as absent.
// The routes never special-case retirement; every refusal below is the
// central guard answering the same non-enumerating 404 it answers for
// unknown and foreign ids. That equivalence is the contract under test.
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

const NOT_FOUND_BODY = { error: { code: "VOLUME_NOT_FOUND", message: "Not found." } };

describe("volume retirement", () => {
  test("retire answers the receipt and the volume vanishes from listings", async () => {
    const metadata = retireFixture();
    const baseUrl = await startServer({ metadata });

    const before = await listVolumeIds(baseUrl);
    expect(before).toContain("vol_live");
    expect(before).toContain("vol_other");

    const retiredAtLowerBound = Date.now();
    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);
    const receipt = (await response.json()) as { volumeId: string; retiredAt: string };
    expect(receipt.volumeId).toBe("vol_live");
    // retiredAt is ISO8601 and names the instant of the flip.
    expect(new Date(receipt.retiredAt).toISOString()).toBe(receipt.retiredAt);
    expect(new Date(receipt.retiredAt).getTime()).toBeGreaterThanOrEqual(retiredAtLowerBound);
    expect(new Date(receipt.retiredAt).getTime()).toBeLessThanOrEqual(Date.now());

    // The retired volume is gone; the tenant's other volume still lists.
    const after = await listVolumeIds(baseUrl);
    expect(after).not.toContain("vol_live");
    expect(after).toContain("vol_other");
  });

  test("a replayed retire answers the stored receipt; unknown and foreign ids answer the same non-enumerating 404", async () => {
    const metadata = retireFixture();
    const baseUrl = await startServer({ metadata });

    const first = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(first.status).toBe(200);
    const firstReceipt = (await first.json()) as { volumeId: string; retiredAt: string };

    // HTTP DELETE is idempotent and the hosted ledger recovers a lost
    // response by replaying the same key: the owner's replay collects the
    // ORIGINAL receipt byte-for-byte, not a 404.
    const replay = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(firstReceipt);

    const unknown = await fetch(`${baseUrl}/v1/volumes/vol_unknown`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    const foreign = await fetch(`${baseUrl}/v1/volumes/vol_foreign`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    for (const response of [unknown, foreign]) {
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual(NOT_FOUND_BODY);
    }
    // The foreign tenant's volume was never touched.
    expect(metadata.state.retired.has("vol_foreign")).toBe(false);
  });

  test("a repository without the receipt lookup keeps the original replay 404", async () => {
    const metadata = retireFixture();
    delete (metadata as { retiredVolumeReceipt?: unknown }).retiredVolumeReceipt;
    const baseUrl = await startServer({ metadata });

    const first = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(first.status).toBe(200);

    const replay = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(replay.status).toBe(404);
    expect(await replay.json()).toEqual(NOT_FOUND_BODY);
  });

  test("retirement is tenant-scoped exactly like the sibling routes: the admin token is refused", async () => {
    const metadata = retireFixture();
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: { authorization: "Bearer secret-token" },
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VOLUME_TENANT_REQUIRED");
  });

  test("a repository without the retirement capability answers typed 501, never a silent 404", async () => {
    const metadata = retireFixture();
    delete (metadata as { retireVolume?: unknown }).retireVolume;
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(501);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("VOLUME_RETIREMENT_UNSUPPORTED");
  });

  test("every per-volume plane refuses a retired volume with the same 404", async () => {
    const metadata = retireFixture();
    const baseUrl = await startServer({ metadata });

    // The volume is demonstrably live first: attach mints a lease, the lease
    // renews, and a snapshot records — so the refusals below are caused by
    // retirement, not by a fixture that never worked.
    const attach = await fetch(`${baseUrl}/v1/volumes/vol_live/attach`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ holderId: "h1", mode: "write" }),
    });
    expect(attach.status).toBe(200);
    const renewBody = JSON.stringify({ fencingToken: 1, leaseTtlMs: 60_000 });
    const renewBefore = await fetch(`${baseUrl}/v1/leases/lease_live/renew`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: renewBody,
    });
    expect(renewBefore.status).toBe(200);
    const snapshotBefore = await fetch(`${baseUrl}/v1/volumes/vol_live/snapshots`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ branch: "main", name: "pre-retire" }),
    });
    expect(snapshotBefore.status).toBe(201);

    const retire = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(retire.status).toBe(200);

    // Every live data plane the contract names — attach, the volume's write
    // lease (renewal), grep, branch create/list, snapshot create/list, the
    // read routes, activate-journal — refuses with the guard's exact 404.
    const refusals: Array<[string, string, string | undefined]> = [
      ["POST", "/v1/volumes/vol_live/attach", JSON.stringify({ holderId: "h1", mode: "read" })],
      ["POST", "/v1/leases/lease_live/renew", renewBody],
      ["POST", "/v1/volumes/vol_live/grep", JSON.stringify({ pattern: "x" })],
      ["POST", "/v1/volumes/vol_live/branches", JSON.stringify({ branchName: "b2" })],
      ["GET", "/v1/volumes/vol_live/branches", undefined],
      ["POST", "/v1/volumes/vol_live/snapshots", JSON.stringify({ branch: "main" })],
      ["GET", "/v1/volumes/vol_live/snapshots", undefined],
      ["GET", "/v1/volumes/vol_live/commits", undefined],
      ["GET", "/v1/volumes/vol_live/status", undefined],
      ["GET", "/v1/volumes/vol_live/head", undefined],
      ["GET", "/v1/volumes/vol_live/wait-head?afterCommitId=cmt_base&timeoutMs=100", undefined],
      ["GET", "/v1/volumes/vol_live/manifest-diff?baseCommitId=cmt_base", undefined],
      ["GET", "/v1/volumes/vol_live/tree", undefined],
      ["GET", "/v1/volumes/vol_live/file?path=README.md", undefined],
      ["GET", "/v1/volumes/vol_live/delegations", undefined],
      ["POST", "/v1/volumes/vol_live/activate-journal", JSON.stringify({ branch: "main" })],
    ];
    for (const [method, path, body] of refusals) {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: TENANT_HEADERS,
        ...(body === undefined ? {} : { body }),
      });
      expect(response.status, `${method} ${path}`).toBe(404);
      expect(await response.json(), `${method} ${path}`).toEqual(NOT_FOUND_BODY);
    }

    // Exec is a route-level retirement contract independent of volume
    // existence/lifecycle, so it refuses before any ownership lookup.
    const exec = await fetch(`${baseUrl}/v1/volumes/vol_live/exec`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: JSON.stringify({ command: "true" }),
    });
    expect(exec.status).toBe(410);
    expect(((await exec.json()) as { error: { code: string } }).error.code).toBe(
      "VOLUME_EXEC_RETIRED"
    );
  });

  test("retire drives the history cascade AFTER the receipt; the receipt stays exact", async () => {
    const metadata = retireFixture();
    const history = fakeRetireHistory(metadata);
    const baseUrl = await startServer({ metadata });

    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);
    const receipt = (await response.json()) as Record<string, unknown>;
    // EXACTLY {volumeId, retiredAt}: the hosted ledger's finalize mutation
    // fails closed on unknown fields, so cleanup counts must never ride the
    // receipt (they are logged server-side instead).
    expect(Object.keys(receipt).sort()).toEqual(["retiredAt", "volumeId"]);

    // Exactly one cascade, tenant-scoped, and only after the flip was durable.
    expect(history.state.calls).toEqual([
      { tenantId: "t1", volumeId: "vol_live", volumeAlreadyRetired: true },
    ]);
    // The pending cut is terminally canceled with the typed retirement
    // reason (distinct from a genuine failure); the ready cut is untouched.
    expect(history.state.cuts).toEqual([
      {
        id: "hcut_pending",
        state: "canceled",
        lastError: { kind: "volume_retired" },
      },
      { id: "hcut_ready", state: "ready" },
    ]);
    // Both blocking consumer pins released; the conversion is voided.
    expect(history.state.consumers.every((consumer) => consumer.released)).toBe(true);
    expect(history.state.conversions).toEqual([{ id: "hconv_1", state: "failed" }]);
  });

  // ── the `portablefs rm` ledger item ──────────────────────────────────────
  //
  // Verified gap: retirement set volumes.retired_at (021, whose own header
  // says "this migration deletes nothing") and cancelled the volume's cuts
  // (022). NOTHING released pfj.journal_records. `portablefs rm` on test
  // volumes is exactly what filled this production Postgres twice.
  test("retire RELEASES the volume's journal storage, not just its metadata flag", async () => {
    const metadata = retireFixture();
    const history = fakeRetireHistory(metadata);
    const baseUrl = await startServer({ metadata });

    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);

    // Tenant-scoped, and strictly AFTER the retirement receipt is durable:
    // the receipt is the precondition for journal retirement, never an
    // effect of it.
    expect(history.state.journalCalls).toEqual([
      { tenantId: "t1", volumeId: "vol_live", volumeAlreadyRetired: true },
    ]);
    // Every generation is terminal with its base driven to its own tip —
    // which is what puts the WHOLE journal below the reclamation horizon.
    // The bounded maintenance pass deletes the rows; the route does not do
    // unbounded work while the caller waits.
    expect(history.state.journalGenerations).toEqual([
      { id: "gen_live", status: "retired", baseSeq: 4_000, nextSeq: 4_000 },
      { id: "gen_old", status: "retired", baseSeq: 900, nextSeq: 900 },
    ]);
    // The receipt shape is unchanged: reclamation detail never rides it.
    const receipt = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(receipt).sort()).toEqual(["retiredAt", "volumeId"]);
  });

  test("a failed journal release never costs the caller its durable retirement receipt", async () => {
    const metadata = retireFixture();
    const history = fakeRetireHistory(metadata);
    (history.repository as unknown as { retireVolumeJournals: () => Promise<never> })
      .retireVolumeJournals = async () => {
      throw Object.assign(new Error("control store unavailable"), { code: "57P01" });
    };
    const baseUrl = await startServer({ metadata });

    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });

    // The flip is already durable, so it MUST be answered. The release is
    // retried by the next replay and by the maintenance loop, which derives
    // its candidates from rows rather than from this call succeeding.
    expect(response.status).toBe(200);
    const receipt = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(receipt).sort()).toEqual(["retiredAt", "volumeId"]);
    expect(history.state.calls).toHaveLength(1);
  });

  test("a replayed retire re-runs the idempotent cascade and answers the identical receipt", async () => {
    const metadata = retireFixture();
    const history = fakeRetireHistory(metadata);
    const baseUrl = await startServer({ metadata });

    const first = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(first.status).toBe(200);
    const firstReceipt = await first.json();
    expect(history.state.calls).toHaveLength(1);

    // The replay collects the stored receipt AND re-runs the cleanup — this
    // is the crash-window repair: a process that died between the flip and
    // the first cleanup heals on the caller's next replay. The re-run is
    // idempotent (everything is already terminal, so it changes nothing).
    const replay = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(firstReceipt);
    expect(history.state.calls).toHaveLength(2);
    expect(history.state.cuts).toEqual([
      {
        id: "hcut_pending",
        state: "canceled",
        lastError: { kind: "volume_retired" },
      },
      { id: "hcut_ready", state: "ready" },
    ]);

    // The cleanup's own replay answer (the direct repair path) is zero counts.
    const replayed = await history.repository.volumeRetireCleanup({
      tenantId: "t1",
      volumeId: "vol_live",
    });
    expect(replayed).toEqual({
      volumeId: "vol_live",
      consumersReleased: 0,
      conversionsVoided: 0,
      cutsCanceled: 0,
    });
  });

  test("a repository without the history surface retires cleanly with the exact receipt", async () => {
    const metadata = retireFixture();
    const baseUrl = await startServer({ metadata });
    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);
    const receipt = (await response.json()) as Record<string, unknown>;
    expect(receipt.volumeId).toBe("vol_live");
    expect(Object.keys(receipt).sort()).toEqual(["retiredAt", "volumeId"]);
  });

  test("fork from a retired volume's snapshot 404s; a fork taken before retirement survives", async () => {
    const metadata = retireFixture();
    const baseUrl = await startServer({ metadata });
    const forkBody = JSON.stringify({ tenantId: "t1", branchName: "main" });

    // Forking the live volume's snapshot works and births an independent volume.
    const before = await fetch(`${baseUrl}/v1/snapshots/snp_live/fork`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: forkBody,
    });
    expect(before.status).toBe(201);
    const forked = (await before.json()) as { volume: { id: string } };

    const retire = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(retire.status).toBe(200);

    // The retired volume's snapshot is no longer forkable (same 404)...
    const after = await fetch(`${baseUrl}/v1/snapshots/snp_live/fork`, {
      method: "POST",
      headers: TENANT_HEADERS,
      body: forkBody,
    });
    expect(after.status).toBe(404);
    expect(await after.json()).toEqual(NOT_FOUND_BODY);

    // ...while the pre-retirement fork is its own live volume and still lists.
    expect(await listVolumeIds(baseUrl)).toContain(forked.volume.id);
  });
});

async function startServer(extra: Partial<VolumeApiServerDeps>): Promise<string> {
  const server = createVolumeApiServer({
    authToken: "secret-token",
    metadata: retireFixture(),
    blobStore: throwingBlobStore(),
    ...extra,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

async function listVolumeIds(baseUrl: string): Promise<string[]> {
  const response = await fetch(`${baseUrl}/v1/volumes`, { headers: TENANT_HEADERS });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { volumes: Array<{ volumeId: string }> };
  return body.volumes.map((volume) => volume.volumeId);
}

interface RetireFixtureState {
  volumes: Map<string, { tenantId: string }>;
  retired: Map<string, number>;
  leases: Map<string, { volumeId: string }>;
  snapshots: Map<string, VolumeSnapshot>;
}

type RetireFixture = MetadataRepository & { state: RetireFixtureState };

// retireFixture is a stateful pure-manifest repository double seeded with the
// caller tenant's live volumes vol_live (lease lease_live, snapshot snp_live)
// and vol_other, plus another tenant's vol_foreign. Its resolvers mirror the
// migration-021 fencing exactly: a retired volume — and its leases and
// snapshots — resolves as absent, so the central guard produces every 404.
function retireFixture(): RetireFixture {
  const fail = async (): Promise<never> => {
    throw new Error("metadata should not be used by this test");
  };
  const state: RetireFixtureState = {
    volumes: new Map([
      ["vol_live", { tenantId: "t1" }],
      ["vol_other", { tenantId: "t1" }],
      ["vol_foreign", { tenantId: "t2" }],
    ]),
    retired: new Map(),
    leases: new Map([["lease_live", { volumeId: "vol_live" }]]),
    snapshots: new Map([
      [
        "snp_live",
        { id: "snp_live", volumeId: "vol_live", branchId: "br_live", commitId: "cmt_base", createdAt: 1 },
      ],
    ]),
  };
  const liveVolumeTenant = (volumeId: string): string | null =>
    state.retired.has(volumeId) ? null : state.volumes.get(volumeId)?.tenantId ?? null;
  return {
    state,
    createVolume: fail,
    getHead: fail,
    getManifestDiff: fail,
    getStatus: fail,
    getCommit: fail,
    getManifest: fail,
    attachVolume: async (input) => {
      const branch = {
        id: "br_live",
        volumeId: input.volumeId,
        name: input.branchName,
        headCommitId: "cmt_base",
        createdAt: 0,
        updatedAt: 0,
      };
      const session = {
        id: "att_1",
        volumeId: input.volumeId,
        branchId: branch.id,
        mode: input.mode,
        shared: input.shared,
        rootPath: "",
        baseCommitId: "cmt_base",
        attachedAt: 1,
      };
      return {
        session,
        branch,
        manifest: { version: "portablefs-v1" as const, treeHash: `sha256:${"0".repeat(64)}`, entries: [] },
        delegations: [],
      };
    },
    renewLease: async (input) => {
      const lease = state.leases.get(input.leaseId);
      if (!lease) {
        throw new Error(`unknown lease ${input.leaseId}`);
      }
      return {
        id: input.leaseId,
        volumeId: lease.volumeId,
        branchId: "br_live",
        attachSessionId: "att_1",
        holderId: "h1",
        fencingToken: input.fencingToken,
        exclusive: true,
        expiresAt: Date.now() + input.leaseTtlMs,
      } satisfies VolumeLease;
    },
    checkout: fail,
    checkin: fail,
    listDelegations: fail,
    commit: fail,
    commitSummary: fail,
    commitDeltaSummary: fail,
    detach: fail,
    snapshot: async (input) => {
      const snapshot: VolumeSnapshot = {
        id: `snp_${state.snapshots.size + 1}`,
        volumeId: input.volumeId,
        branchId: "br_live",
        commitId: "cmt_base",
        ...(input.name ? { name: input.name } : {}),
        createdAt: Date.now(),
      };
      state.snapshots.set(snapshot.id, snapshot);
      return snapshot;
    },
    listSnapshots: async (input) =>
      [...state.snapshots.values()].filter((snapshot) => snapshot.volumeId === input.volumeId),
    createBranch: fail,
    listBranches: async () => [],
    listVolumes: async (input) =>
      [...state.volumes.entries()]
        .filter(([id, volume]) => volume.tenantId === input.tenantId && !state.retired.has(id))
        .map(([id, volume]) => ({
          volume: { id, tenantId: volume.tenantId, defaultBranchId: "br_live", createdAt: 0 },
          branches: [{ name: "main", headCommitId: "cmt_base" }],
        })),
    retireVolume: async (input) => {
      const volume = state.volumes.get(input.volumeId);
      if (!volume || volume.tenantId !== input.tenantId || state.retired.has(input.volumeId)) {
        return null;
      }
      const retiredAtMs = input.now ?? Date.now();
      state.retired.set(input.volumeId, retiredAtMs);
      return { volumeId: input.volumeId, retiredAtMs };
    },
    retiredVolumeReceipt: async (input) => {
      const volume = state.volumes.get(input.volumeId);
      const retiredAtMs = state.retired.get(input.volumeId);
      if (!volume || volume.tenantId !== input.tenantId || retiredAtMs === undefined) {
        return null;
      }
      return { volumeId: input.volumeId, retiredAtMs };
    },
    listCommitHistory: fail,
    forkSnapshot: async (input) => {
      const snapshot = state.snapshots.get(input.snapshotId);
      if (!snapshot) {
        throw new Error(`unknown snapshot ${input.snapshotId}`);
      }
      const volumeId = input.volumeId ?? `vol_fork_${state.volumes.size + 1}`;
      state.volumes.set(volumeId, { tenantId: input.tenantId });
      const branch = {
        id: "br_fork",
        volumeId,
        name: input.branchName,
        headCommitId: "cmt_fork",
        createdAt: 0,
        updatedAt: 0,
      };
      const manifest = { version: "portablefs-v1" as const, treeHash: `sha256:${"0".repeat(64)}`, entries: [] };
      return {
        volume: { id: volumeId, tenantId: input.tenantId, defaultBranchId: branch.id, createdAt: 0 },
        branch,
        head: {
          id: "cmt_fork",
          volumeId,
          branchId: branch.id,
          treeHash: manifest.treeHash,
          manifest,
          mutationCount: 0,
          byteCount: 0,
          createdAt: 0,
        },
      };
    },
    recordBlobs: fail,
    createTenant: async () => undefined,
    createTenantToken: async () => undefined,
    resolveTenantToken: async () => ({ tenantId: "t1" }),
    resolveRuntimeReadCredential: async () => null,
    tenantOwnsVolume: async ({ tenantId, volumeId }) =>
      liveVolumeTenant(volumeId) === tenantId,
    sessionTenant: async () => null,
    leaseTenant: async (leaseId) => {
      const lease = state.leases.get(leaseId);
      return lease ? liveVolumeTenant(lease.volumeId) : null;
    },
    sessionVolume: async () => null,
    leaseVolume: async (leaseId) => state.leases.get(leaseId)?.volumeId ?? null,
    snapshotTenant: async (snapshotId) => {
      const snapshot = state.snapshots.get(snapshotId);
      return snapshot ? liveVolumeTenant(snapshot.volumeId) : null;
    },
    commitTenant: async () => null,
    tenantReferencesBlob: async () => false,
    tenantReferencesBlobs: async () => new Set<string>(),
    addBlobRefs: async () => undefined,
    filterUnreferencedBlobs: fail,
  };
}

interface FakeRetireHistoryState {
  cuts: Array<{ id: string; state: string; lastError?: unknown }>;
  consumers: Array<{ kind: "conversion" | "adoption"; id: string; released: boolean }>;
  conversions: Array<{ id: string; state: string }>;
  calls: Array<{ tenantId: string; volumeId: string; volumeAlreadyRetired: boolean }>;
  // Journal reclamation (migration 031): the generations the route drove
  // terminal, and whether the volume was already retired when it did.
  journalCalls: Array<{ tenantId: string; volumeId: string; volumeAlreadyRetired: boolean }>;
  journalGenerations: Array<{ id: string; status: string; baseSeq: number; nextSeq: number }>;
}

// fakeRetireHistory attaches a stateful pfh.volume_retire_cleanup double to
// the fixture's `history` escape hatch, seeded with the exact incident shape:
// one pending conversion cut pinned by an unreleased conversion consumer
// (plus an adoption consumer on a ready cut). Its cleanup mirrors the
// migration-022 semantics — release conversion/adoption consumers, void
// non-terminal conversions, cancel non-terminal cuts with the typed
// volume_retired reason — and is idempotent (a replay counts zero).
function fakeRetireHistory(metadata: RetireFixture): {
  repository: PostgresHistoryRepository;
  state: FakeRetireHistoryState;
} {
  const state: FakeRetireHistoryState = {
    cuts: [
      { id: "hcut_pending", state: "pending" },
      { id: "hcut_ready", state: "ready" },
    ],
    consumers: [
      { kind: "conversion", id: "hconv_1", released: false },
      { kind: "adoption", id: "hadopt_1", released: false },
    ],
    conversions: [{ id: "hconv_1", state: "final_cut" }],
    calls: [],
    journalCalls: [],
    journalGenerations: [
      { id: "gen_live", status: "active", baseSeq: 0, nextSeq: 4_000 },
      { id: "gen_old", status: "suspended", baseSeq: 100, nextSeq: 900 },
    ],
  };
  const facade = {
    volumeRetireCleanup: async (input: {
      tenantId: string;
      volumeId: string;
    }): Promise<VolumeRetireCleanupResult> => {
      state.calls.push({
        ...input,
        // Proves the route sequenced the cascade AFTER the durable receipt.
        volumeAlreadyRetired: metadata.state.retired.has(input.volumeId),
      });
      let consumersReleased = 0;
      for (const consumer of state.consumers) {
        if (!consumer.released) {
          consumer.released = true;
          consumersReleased += 1;
        }
      }
      let conversionsVoided = 0;
      for (const conversion of state.conversions) {
        if (conversion.state === "migrating" || conversion.state === "final_cut") {
          conversion.state = "failed";
          conversionsVoided += 1;
        }
      }
      let cutsCanceled = 0;
      for (const cut of state.cuts) {
        if (cut.state === "pending" || cut.state === "materializing") {
          cut.state = "canceled";
          cut.lastError = { kind: "volume_retired" };
          cutsCanceled += 1;
        }
      }
      return { volumeId: input.volumeId, consumersReleased, conversionsVoided, cutsCanceled };
    },
    // pfj.journal_retire_for_volume (migration 031): drives the volume's
    // generations terminal and moves each base to its own tip, which is what
    // makes the WHOLE journal fall below the reclamation horizon. Idempotent.
    retireVolumeJournals: async (input: {
      tenantId: string;
      volumeId: string;
    }): Promise<JournalRetireResult> => {
      state.journalCalls.push({
        ...input,
        volumeAlreadyRetired: metadata.state.retired.has(input.volumeId),
      });
      let generationsRetired = 0;
      for (const generation of state.journalGenerations) {
        if (generation.status !== "retired") {
          generation.status = "retired";
          generation.baseSeq = generation.nextSeq;
          generationsRetired += 1;
        }
      }
      return {
        volumeId: input.volumeId,
        generationsRetired: String(generationsRetired),
        reclaimableRecords: String(
          state.journalGenerations.reduce((sum, g) => sum + g.baseSeq, 0)
        ),
      };
    },
  };
  const repository = facade as unknown as PostgresHistoryRepository;
  (metadata as MetadataRepository & { history?: PostgresHistoryRepository }).history = repository;
  return { repository, state };
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
