import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import type { BlobStore } from "@portablefs/core";
import type { MetadataRepository, VolumeRetirementTask } from "@portablefs/metadata-db";
import { createVolumeApiServer, type VolumeApiServerDeps } from "./server.js";
import { HistoryMaintenanceLoop, type HistoryMaintenanceStore } from "./history-maintenance.js";
import { createTelemetry } from "./telemetry.js";

// ---------------------------------------------------------------------------
// ROUND 17c / FINDING 5: volume retirement must DURABLY schedule the journal
// release, and must run cleanup + journal retirement as ONE transition.
//
// What round 16 shipped: the DELETE route called retireVolumeJournals inline,
// caught any failure, LOGGED it, and answered success. Nothing was written
// down. And the maintenance loop could not pick the work up either — it only
// reclaims below an EXISTING horizon (journal_reclaim_candidates +
// journal_reclaim) and never retires a generation, while a live generation's
// horizon is its own base_seq, so it offers ZERO reclaimable records and
// never appears as a candidate. Without a client replay of the DELETE, that
// volume's whole journal tail was retained forever: exactly the accumulation
// that filled this production control store twice.
//
// The fake below models the migration-033 SQL semantics that fix it: the
// retirement flip and the obligation commit together, the transition is
// atomic and idempotent, and the queue is what the maintenance loop drains.
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

interface Generation {
  id: string;
  status: string;
  baseSeq: number;
  nextSeq: number;
  /** Records still physically present below the tip. */
  records: number;
}

interface RetirementFixtureState {
  retiredAtMs: Map<string, number>;
  /** The durable obligation queue (public.portablefs_volume_retirement_tasks). */
  tasks: Map<string, { tenantId: string; attempts: number; nextAttemptMs: number; done: boolean; lastError?: string }>;
  generations: Generation[];
  /** Non-terminal cuts pinning the reclamation horizon. */
  pendingCuts: Array<{ id: string; sourceBaseSeq: number; state: string }>;
  transitionCalls: number;
  /** Set to fail the transition, modelling a transient control-store fault. */
  failTransition: boolean;
}

function fixture(): { metadata: MetadataRepository; state: RetirementFixtureState } {
  const fail = async (): Promise<never> => {
    throw new Error("metadata should not be used by this test");
  };
  const state: RetirementFixtureState = {
    retiredAtMs: new Map(),
    tasks: new Map(),
    generations: [
      { id: "gen_live", status: "active", baseSeq: 1_200, nextSeq: 4_000, records: 4_000 },
      { id: "gen_old", status: "suspended", baseSeq: 100, nextSeq: 900, records: 900 },
    ],
    pendingCuts: [{ id: "hcut_pending", sourceBaseSeq: 1_200, state: "pending" }],
    transitionCalls: 0,
    failTransition: false,
  };
  const metadata = {
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
    listVolumes: async () => [],
    listCommitHistory: fail,
    forkSnapshot: fail,
    recordBlobs: fail,
    createTenant: async () => undefined,
    createTenantToken: async () => undefined,
    resolveTenantToken: async () => ({ tenantId: "t1" }),
    resolveRuntimeReadCredential: async () => null,
    tenantOwnsVolume: async ({ tenantId, volumeId }: { tenantId: string; volumeId: string }) =>
      volumeId === "vol_live" && tenantId === "t1" && !state.retiredAtMs.has(volumeId),
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

    // ── migration 033 ──────────────────────────────────────────────────────
    // The flip and the obligation are ONE transaction. There is no state in
    // which a caller holds a receipt and the fleet has no record of the work.
    retireVolume: async (input: { volumeId: string; tenantId: string; now?: number }) => {
      if (input.volumeId !== "vol_live" || input.tenantId !== "t1") {
        return null;
      }
      const now = input.now ?? Date.now();
      const already = state.retiredAtMs.has(input.volumeId);
      if (!already) {
        state.retiredAtMs.set(input.volumeId, now);
      }
      const task = state.tasks.get(input.volumeId);
      if (!task) {
        state.tasks.set(input.volumeId, {
          tenantId: input.tenantId,
          attempts: 0,
          nextAttemptMs: now,
          done: false,
        });
      } else if (!task.done) {
        task.nextAttemptMs = Math.min(task.nextAttemptMs, now);
      }
      return already
        ? null
        : { volumeId: input.volumeId, retiredAtMs: state.retiredAtMs.get(input.volumeId)! };
    },
    retiredVolumeReceipt: async (input: { volumeId: string; tenantId: string }) => {
      const at = state.retiredAtMs.get(input.volumeId);
      return at !== undefined && input.tenantId === "t1"
        ? { volumeId: input.volumeId, retiredAtMs: at }
        : null;
    },
    finishVolumeRetirement: async (input: { tenantId: string; volumeId: string }) => {
      state.transitionCalls += 1;
      if (state.failTransition) {
        throw Object.assign(new Error("control store unavailable"), { code: "57P01" });
      }
      if (!state.retiredAtMs.has(input.volumeId)) {
        throw Object.assign(new Error("volume is not retired"), { code: "PF011" });
      }
      // ONE transaction: cancel every non-terminal cut AND retire every
      // generation. Nothing can create a cut in between, because the whole
      // transition holds every branch lock of the volume.
      for (const cut of state.pendingCuts) {
        cut.state = "canceled";
      }
      for (const generation of state.generations) {
        generation.status = "retired";
        generation.baseSeq = generation.nextSeq;
      }
      const task = state.tasks.get(input.volumeId);
      if (task) {
        task.done = true;
        task.attempts += 1;
        delete task.lastError;
      }
      return {
        volumeId: input.volumeId,
        branchesLocked: "2",
        cleanup: { cutsCanceled: 1 },
        journal: { generationsRetired: "2" },
        completedAtMs: String(Date.now()),
      };
    },
    claimVolumeRetirementTasks: async (input?: { limit?: number; backoffMs?: number }) => {
      const now = Date.now();
      const claimed: VolumeRetirementTask[] = [];
      for (const [volumeId, task] of state.tasks) {
        if (claimed.length >= (input?.limit ?? 8)) {
          break;
        }
        if (task.done || task.nextAttemptMs > now) {
          continue;
        }
        task.attempts += 1;
        task.nextAttemptMs = now + (input?.backoffMs ?? 60_000) * task.attempts;
        claimed.push({ volumeId, tenantId: task.tenantId, attempts: task.attempts });
      }
      return claimed;
    },
    deferVolumeRetirementTask: async (input: {
      tenantId: string;
      volumeId: string;
      error: string;
    }) => {
      const task = state.tasks.get(input.volumeId);
      if (task && !task.done) {
        task.lastError = input.error;
      }
    },
  } as unknown as MetadataRepository;
  return { metadata, state };
}

/** The reclamation horizon exactly as pfj.journal_reclaim_horizon computes it. */
function reclaimHorizon(state: RetirementFixtureState, generationId: string): number {
  const generation = state.generations.find((g) => g.id === generationId)!;
  let horizon = generation.baseSeq;
  for (const cut of state.pendingCuts) {
    if (cut.state === "pending" || cut.state === "materializing") {
      horizon = Math.min(horizon, cut.sourceBaseSeq);
    }
  }
  return horizon;
}

async function startServer(metadata: MetadataRepository): Promise<string> {
  const blobStore = {
    put: async () => {
      throw new Error("blob store should not be used by this test");
    },
    get: async () => {
      throw new Error("blob store should not be used by this test");
    },
    has: async () => {
      throw new Error("blob store should not be used by this test");
    },
  } as unknown as BlobStore;
  const server = createVolumeApiServer({
    authToken: "secret-token",
    metadata,
    blobStore,
  } as unknown as VolumeApiServerDeps);
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function drainLoop(
  metadata: MetadataRepository,
  store: HistoryMaintenanceStore
): HistoryMaintenanceLoop {
  return new HistoryMaintenanceLoop({
    store,
    intervalMs: 60_000,
    backlogPercent: 70,
    telemetry: createTelemetry(() => {}),
    servingConfigured: true,
    retirement: metadata as never,
    retirementBackoffMs: 1_000,
  });
}

const inertStore: HistoryMaintenanceStore = {
  generationsPastThreshold: async () => [],
  createCut: async () => {
    throw new Error("unused");
  },
  cutStatus: async () => null,
  adoptCut: async () => {
    throw new Error("unused");
  },
  unreleasedServingPins: async () => [],
  releaseServingPinFenced: async () => ({ released: false, reason: "unused" }),
};

describe("volume retirement transition (finding 5)", () => {
  test("a failed journal release leaves a DURABLE obligation, not only a log line", async () => {
    const { metadata, state } = fixture();
    state.failTransition = true;
    const baseUrl = await startServer(metadata);

    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });

    // Round 16's property is kept: the receipt is durable, so it is answered.
    expect(response.status).toBe(200);
    const receipt = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(receipt).sort()).toEqual(["retiredAt", "volumeId"]);

    // ...and the work is WRITTEN DOWN. Before 033 this was the whole bug: the
    // route logged the failure and nothing anywhere retried it, while the
    // maintenance loop could not derive the work from rows because an
    // un-retired generation's horizon is its own base_seq and therefore
    // offers zero reclaimable records.
    const task = state.tasks.get("vol_live");
    expect(task, "the retirement obligation must be durable").toBeDefined();
    expect(task!.done).toBe(false);
    expect(task!.lastError).toContain("control store unavailable");

    // The tail is still fully retained at this point — this is exactly the
    // state that used to be permanent.
    expect(state.generations.map((g) => g.status)).toEqual(["active", "suspended"]);
    expect(reclaimHorizon(state, "gen_live")).toBe(1_200);
  });

  test("the maintenance loop DRAINS the obligation and releases the retained tail", async () => {
    const { metadata, state } = fixture();
    state.failTransition = true;
    const baseUrl = await startServer(metadata);

    await fetch(`${baseUrl}/v1/volumes/vol_live`, { method: "DELETE", headers: TENANT_HEADERS });
    expect(state.tasks.get("vol_live")!.done).toBe(false);

    const loop = drainLoop(metadata, inertStore);

    // A cycle while the store is still unhappy: claimed, failed, requeued.
    const failed = await loop.runCycle();
    expect(failed.retirementTasksClaimed).toBe(1);
    expect(failed.retirementTasksCompleted).toBe(0);
    expect(failed.retirementTasksDeferred).toBe(1);
    expect(state.tasks.get("vol_live")!.done).toBe(false);
    // The backoff is enforced by the claim itself, so the very next cycle
    // does NOT hammer a store that is already in trouble.
    const backedOff = await loop.runCycle();
    expect(backedOff.retirementTasksClaimed).toBe(0);

    // The store recovers; the obligation is still there and now completes.
    state.failTransition = false;
    state.tasks.get("vol_live")!.nextAttemptMs = 0;
    const drained = await loop.runCycle();
    expect(drained.retirementTasksClaimed).toBe(1);
    expect(drained.retirementTasksCompleted).toBe(1);
    expect(state.tasks.get("vol_live")!.done).toBe(true);

    // Every generation is terminal with its base at its own tip, so the WHOLE
    // journal is below the horizon and the bounded reclaim pass can delete it.
    expect(state.generations).toEqual([
      { id: "gen_live", status: "retired", baseSeq: 4_000, nextSeq: 4_000, records: 4_000 },
      { id: "gen_old", status: "retired", baseSeq: 900, nextSeq: 900, records: 900 },
    ]);
    expect(reclaimHorizon(state, "gen_live")).toBe(4_000);
    expect(reclaimHorizon(state, "gen_old")).toBe(900);
  });

  test("cleanup and journal retirement are ONE transition, so no cut survives to clamp the horizon", async () => {
    const { metadata, state } = fixture();
    const baseUrl = await startServer(metadata);

    const response = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(response.status).toBe(200);

    // Both halves ran, in one call. Round 16 made two separate calls with no
    // common lock, so a cut created between them stayed pending forever:
    // the cleanup had already passed, the maintenance loop only creates cuts,
    // and the volume was gone so no client would ever settle it.
    expect(state.transitionCalls).toBe(1);
    expect(state.pendingCuts.every((cut) => cut.state === "canceled")).toBe(true);
    expect(state.generations.every((g) => g.status === "retired")).toBe(true);
    expect(reclaimHorizon(state, "gen_live")).toBe(4_000);
  });

  test("a replayed DELETE re-asserts the obligation and re-runs the idempotent transition", async () => {
    const { metadata, state } = fixture();
    const baseUrl = await startServer(metadata);

    const first = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(first.status).toBe(200);
    const firstReceipt = await first.json();

    const replay = await fetch(`${baseUrl}/v1/volumes/vol_live`, {
      method: "DELETE",
      headers: TENANT_HEADERS,
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(firstReceipt);
    expect(state.transitionCalls).toBe(2);
    expect(state.tasks.get("vol_live")!.done).toBe(true);
  });

  test("a loop without the 033 queue reports the gap per cycle instead of pretending", async () => {
    const loop = new HistoryMaintenanceLoop({
      store: inertStore,
      intervalMs: 60_000,
      backlogPercent: 70,
      telemetry: createTelemetry(() => {}),
      servingConfigured: true,
    });
    const summary = await loop.runCycle();
    expect(summary.retirementDrainUnavailable).toBe(true);
    expect(summary.failures).toBe(0);
  });
});
