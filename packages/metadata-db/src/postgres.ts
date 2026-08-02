import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";
import { Pool, type Notification, type PoolClient, type PoolConfig } from "pg";
import {
  applyManifestDiffIndexed,
  canonicalizeManifestDiff,
  collectMutationPaths,
  computeTreeHash,
  createManifestIndex,
  diffHasPathConflict,
  diffManifestIndexes,
  diffManifests,
  isEqualOrDescendantPath,
  joinVolumePath,
  normalizeVolumePath,
  pathDelegationsOverlap,
  projectManifest,
  type ManifestIndex,
} from "@portablefs/core";
import {
  attachSessionSchema,
  branchSchema,
  pathDelegationSchema,
  protocolVersion,
  treeManifestDiffSchema,
  treeManifestSchema,
  type AttachMode,
  type AttachSession,
  type PathDelegation,
  type TreeManifestDiff,
  type TreeManifest,
  type Volume,
  type VolumeBranch,
  type VolumeCommit,
  type VolumeCommitSummary,
  type VolumeLease,
  type VolumeSnapshot,
} from "@portablefs/protocol";
import {
  MetadataConflictError,
  type AttachVolumeInput,
  type AttachVolumeResult,
  type CheckinInput,
  type CheckinResult,
  type CheckoutInput,
  type CheckoutResult,
  type CreateBranchFromCutInput,
  type CreateBranchFromCutResult,
  type CreateBranchInput,
  type CommitVolumeDeltaInput,
  type CommitVolumeInput,
  type CommitVolumeResult,
  type CommitVolumeSummaryResult,
  type ControlPlaneProbeResult,
  type ControlStoreUsage,
  type CreateVolumeInput,
  type CreateVolumeResult,
  type DetachVolumeInput,
  type ForkSnapshotInput,
  type ForkVolumeFromCutInput,
  type ForkVolumeFromCutResult,
  type ListBranchesInput,
  type ListCommitHistoryInput,
  type ListDelegationsInput,
  type ListSnapshotsInput,
  type ListVolumesInput,
  type MetadataRepository,
  type RenewLeaseInput,
  type RetireVolumeInput,
  type RetireVolumeResult,
  type SnapshotCutInput,
  type SnapshotCutRecord,
  type SnapshotInput,
  type SnapshotSource,
  type VolumeBranchMode,
  type VolumeCommitKind,
  type WaitForHeadInput,
  type VolumeListEntry,
  type VolumeManifestDiffInput,
  type VolumeManifestDiffResult,
  type VolumeHeadResult,
  type VolumeStatusInput,
} from "./types.js";
import { attachRequestFingerprint } from "./attach.js";
import {
  PostgresHistoryRepository,
  type ConversionStatus,
  type HistoryCutStatus,
  type VolumeForkFromCutResult,
} from "./history.js";
import type {
  JournalActivationConversion,
  JournalActivationCut,
  JournalActivationStatus,
} from "./types.js";
import type { BranchJournalBinding } from "./journal.js";

const migrationIds = [
  "001_init",
  "002_volume_features",
  "003_diff_backed_commits",
  "004_hot_path_indexes",
  "005_tenant_isolation",
  "006_volume_listing",
  "007_commit_receipts",
  "008_auxiliary_blob_refs",
  // 009 requires CREATE ROLE: it provisions the journal owner role, the
  // restricted portablefs_authority capability role, and the pfj schema of
  // SECURITY DEFINER functions the Go authority calls directly over pgx.
  "009_remote_journal",
  // 010 provisions the pfm manager-control schema: the singleton manager
  // claim lease, authority runtime rows, access lease rows, and permanent
  // operation receipts behind the restricted portablefs_manager role.
  "010_manager_control",
  // 011 hardens pfj for production: scope-namespaced permanent receipts,
  // pfm manager-binding validation inside every journal transaction,
  // capability-fenced reads, receipted exact suspension, the safety
  // interlock (cut/trim/rotate/retire revoked from the authority role),
  // and verifiable durability evidence.
  "011_journal_hardening",
  // 012 admits the PFJ3/PFC2 live-data-plane pair: immutable codec pairs
  // per journal generation, whole-entry PFJ3 rows (optional PFR1 tree
  // intent + ordered PFC2 controls in one fenced transaction),
  // authoritative branch storage modes, capability-bound short-lived
  // admission time facts (issue at admission, freeze into the bytes,
  // validate + consume atomically at append), and the permanent private
  // attach_receipts identity table behind the receipted attach.
  "012_pfj3_pfc2",
  // 013 is the history plane: the pfh schema (HistoryCuts, PFT2 commit
  // provenance, replicated-object registry, permanent resource operations,
  // conversion/adoption proof rows, scrub scheduling, and the durable GC
  // sweep authority) behind the NOLOGIN history owner / worker / auditor
  // roles, commits.commit_kind (manifest_v1|pft2), and the replaced
  // branch/freeze guards whose privileged edges verify durable proof ROWS.
  "013_managed_history",
  // 014 is the additive serving proof: one tenant-scoped atomic proof of an
  // exact journal base tuple (manifest_v1 or PFT2 fork/conversion/adoption),
  // plus the narrow degraded-copy hook that schedules ordinary scrub work.
  "014_history_serving",
  // 015 is the manager-minted runtime read credential plane: per-child
  // short-lived volume-api credentials bound to the live authority runtime,
  // replacing any statically configured child token (which could only ever
  // represent one tenant).
  "015_runtime_credentials",
  // 016 installs database-owned session deadlines (statement/lock/idle-in-
  // transaction) so transaction-pooled journal children — whose startup GUCs
  // a pooler cannot preserve — keep the exact historical safety timeouts.
  "016_pooler_timeouts",
  // 017 adds the journal-bounding maintenance read surface: two SECURITY
  // DEFINER projections (pfj.generations_past_threshold,
  // pfh.serving_pins_unreleased) granted to the metadata caller role, so the
  // volume-api's maintenance loop can find backlogged generations and
  // sweepable serving pins without owner-table access.
  "017_history_maintenance",
  // 018 is the atomic cross-volume fork of a ready journal-era cut: the
  // immutable pfh.pft2_fork_commits provenance plane, the exact-once
  // pfh.volume_fork_from_cut operation (zero-copy: the destination is born
  // managed_journal on the copied PFT2 root with an ACTIVE 'fork' cut
  // consumer as the GC root), and the forward-replaced serving proof /
  // cut-status projections that recognize fork destinations positively.
  "018_managed_volume_fork",
  // 019 persists the user snapshot label on the cut row itself (the request
  // canonical JSON only survives as a fingerprint): the nullable bounded
  // pfh.history_cuts.user_label column, the labeled 9-argument
  // pfh.cut_create (the 013 signature delegates label-free for rollout
  // overlap), and the forward-replaced cut_status projecting userLabel.
  "019_snapshot_cut_labels",
  // 020 records the USER root object's own allocation high-water on the
  // cut's pft2 commit provenance (the value attach proofs bind byte-exactly
  // against the hashed ROOT), distinct from the branch allocator watermark
  // that stays on the recovery anchor and the namespace row: the
  // 18-argument pfh.cut_mark_ready (the 013 signature delegates with the
  // allocator fallback for rollout overlap).
  "020_cut_root_high_water",
  // 021 is receipted volume retirement: the nullable volumes.retired_at
  // timestamptz (NULL = live). The flip is one atomic conditional UPDATE and
  // the ownership resolvers treat retired volumes as absent, fencing every
  // per-volume plane with the same non-enumerating 404. No data is deleted;
  // storage reclamation is deferred.
  "021_volume_retirement",
  // 022 cascades retirement to the history plane: the idempotent
  // pfh.volume_retire_cleanup(tenant, volume) the retire route drives after
  // the 021 receipt is durable — it releases the volume's conversion/adoption
  // consumer pins, voids its non-terminal conversions, and cancels its
  // pending/materializing cuts (terminal 'canceled' with a typed
  // {kind:'volume_retired'} last_error, settling each cut's permanent
  // operation), so no pending history work survives a retired volume.
  "022_retire_cut_cleanup",
  // 023 changes a volume's public identity from deployment-global to
  // tenant-local. Public metadata rows carry tenant_id and volume lookup
  // indexes/FKs use (tenant_id, volume_id), so equal ids in two tenants are
  // isolated without scans or ambiguous joins.
  "023_tenant_scoped_volume_identity",
  // 024 adds pfh.object_locate_batch (worker-only): the bounded batched
  // location read behind convergent cut retries — a retried attempt skips
  // objects a previous attempt already uploaded and receipted instead of
  // re-uploading its entire object set.
  "024_history_locate_batch",
  // 025 installs the history storage policy: batched copy receipts
  // (pfh.object_copy_receipt_batch) and W-of-N readiness with
  // W = min(2, N) (pfh.write_quorum) in the receipt live-flip and the
  // publication proof, whose freshness window now applies only to objects
  // the cut produced (upload-intent rows).
  "025_history_write_quorum",
  // 026 makes managed-journal capture chain on the branch's newest ready
  // cut of the same generation (the fold covers only the tail since it),
  // teaches adoption to verify/replace the GENERATION's live base (a
  // chained cut's source base is a ready-cut boundary), and roots the
  // closures of any cut serving as a live fold's source base.
  "026_history_chained_cuts",
  // 027 adds pfh.cut_objects_add_from_base (worker-only): the O(delta)
  // publication — the worker registers only the objects a chained fold
  // produced and the database copies the adopted base cut's closure rows
  // server-side, returning the final totals.
  "027_history_delta_publish",
  // 028 bounds history storage: pfh.object_is_root becomes the retention
  // policy (pinned + named + newest-8 ready cuts per live-volume branch;
  // the unbounded child-commit clause is removed), pfh.retention_release
  // (worker) releases superseded adoption consumers, and
  // pfh.snapshot_cut_release (caller) deletes named snapshots by clearing
  // their labels so the existing GC sweep collects them.
  "028_history_retention",
  // 029 converges user and recovery cuts at the same exact boundary onto
  // ONE materialization (kind-agnostic dedup; a labeled request adopts
  // its label onto an unlabeled live row) and lets adoption consume any
  // ready pfj3 managed cut — every ready cut carries a verified anchor.
  "029_history_cut_kind_dedup",
  // 030 makes readiness able to fail. Both control probes were catalog
  // READS, which an out-of-disk primary answers perfectly while every lease
  // write fails; 030 adds the bounded DURABLE WRITE probe (public
  // portablefs_control_write_probes for this service, pfm.control_write_probe
  // for the manager — same durability admission as a lease write) plus
  // pfm.control_store_usage() consumption accounting. Both targets are
  // bounded to a fixed ring of rows updated in place.
  "030_control_store_headroom",
  // 031 gives journal records a release path. pfj.journal_records rows were
  // NEVER physically deleted: adoption advanced base_seq logically while the
  // BYTEA payloads below it stayed forever, pfj.journal_physical_trim was
  // ungranted, uncalled and frozen for pfj3, and volume retirement deleted
  // nothing. 031 unfreezes trim behind a horizon proven by ROWS
  // (pfj.journal_reclaim_horizon), adds bounded pfj.journal_reclaim,
  // pfj.journal_retire_for_volume (the reclamation half of `portablefs rm`),
  // an age-aware candidate list, and pfj.journal_storage_usage accounting.
  "031_journal_reclamation",
] as const;
const maxManifestDiffChainDepth = 32;
const headNotifyChannel = "portablefs_head";

// ---------------------------------------------------------------------------
// Manifest index cache: byte-bounded LRU.
//
// A ManifestIndex retains its manifest, three per-path maps (entry,
// comparable key, tree-hash shard rows), a per-digest count map/set, and the
// TreeEntry objects themselves. Measured resident cost (Node 22 arm64,
// fresh-process heapUsed deltas over synthetic single-blob file entries with
// ~60-char paths, at 50k/200k/500k entries): 823-861 bytes per entry, nearly
// flat across sizes. The accounting constant rounds up to 1 KiB per entry for
// headroom on longer real-world paths and chunked entries. One 500k-entry
// index therefore charges ~488 MiB — above the 256 MiB default budget, which
// is exactly the point: an index that would dominate the process's memory is
// served uncached (recomputed per read) instead of being allowed to OOM it.
// ---------------------------------------------------------------------------
const manifestIndexCacheEntryLimit = 128;
const manifestIndexBytesPerEntry = 1024;
const defaultManifestIndexCacheMb = 256;

/**
 * Estimated resident bytes of one cached manifest index: entry count times
 * the measured-and-rounded per-entry footprint (see the section comment).
 * Empty manifests still charge one entry for their fixed structures.
 */
export function estimateManifestIndexBytes(index: ManifestIndex): number {
  return Math.max(1, index.entriesByPath.size) * manifestIndexBytesPerEntry;
}

/**
 * LRU over commit manifest indexes with BYTE accounting as the primary bound
 * (a handful of 500k-entry indexes could otherwise OOM the process while
 * respecting any entry-count cap) and the historical 128-entry cap as the
 * secondary bound. O(1) per operation: Map insertion order is the LRU.
 */
export class ManifestIndexCache {
  private readonly entries = new Map<string, { index: ManifestIndex; bytes: number }>();
  private totalBytes = 0;

  constructor(
    private readonly maxBytes: number,
    private readonly maxEntries = manifestIndexCacheEntryLimit
  ) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
      throw new Error("ManifestIndexCache maxBytes must be a non-negative safe integer.");
    }
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new Error("ManifestIndexCache maxEntries must be a positive safe integer.");
    }
  }

  get estimatedBytes(): number {
    return this.totalBytes;
  }

  get size(): number {
    return this.entries.size;
  }

  get(commitId: string): ManifestIndex | undefined {
    const cached = this.entries.get(commitId);
    if (!cached) {
      return undefined;
    }
    this.entries.delete(commitId);
    this.entries.set(commitId, cached);
    return cached.index;
  }

  set(commitId: string, index: ManifestIndex): void {
    const existing = this.entries.get(commitId);
    if (existing) {
      this.totalBytes -= existing.bytes;
      this.entries.delete(commitId);
    }
    const bytes = estimateManifestIndexBytes(index);
    if (bytes > this.maxBytes) {
      // An index that alone exceeds the whole budget is served uncached
      // rather than evicting everything for one reader.
      return;
    }
    this.entries.set(commitId, { index, bytes });
    this.totalBytes += bytes;
    while (this.totalBytes > this.maxBytes || this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      const evicted = this.entries.get(oldest);
      this.entries.delete(oldest);
      if (evicted) {
        this.totalBytes -= evicted.bytes;
      }
    }
  }
}

/**
 * VOLUME_MANIFEST_INDEX_CACHE_MB bounds the estimated resident bytes of the
 * manifest index cache (default 256 MiB). Strictly validated: a typo is a
 * startup failure, never a silently unbounded cache.
 */
export function manifestIndexCacheMaxBytesFromEnv(env: NodeJS.ProcessEnv): number {
  const raw = env.VOLUME_MANIFEST_INDEX_CACHE_MB?.trim();
  if (raw === undefined || raw === "") {
    return defaultManifestIndexCacheMb * 1024 * 1024;
  }
  if (!/^\d+$/.test(raw)) {
    throw new Error(`VOLUME_MANIFEST_INDEX_CACHE_MB must be a non-negative integer of MiB, got ${JSON.stringify(raw)}.`);
  }
  const megabytes = Number(raw);
  if (!Number.isSafeInteger(megabytes) || megabytes * 1024 * 1024 > Number.MAX_SAFE_INTEGER) {
    throw new Error(`VOLUME_MANIFEST_INDEX_CACHE_MB is out of range: ${raw}.`);
  }
  return megabytes * 1024 * 1024;
}
// Advisory lock identity for the migration runner (classid, objid): one
// fleet-wide lock so concurrently starting replicas serialize on DDL.
const migrationLockClassId = 0x70667321; // "pfs!"
const migrationLockObjectId = 0x6d696772; // "migr"
// The exact deterministic reduction the resident history worker implements
// (vcs/internal/historycut MaterializerVersion). Cut requests carry it so a
// worker from another release refuses rather than materializing differently.
// Exported for the callers that mint cut requests outside this repository
// (the volume-api maintenance loop and admin history routes).
export const historyMaterializerVersion = "pfm-2026.07-2";
const attachReceiptLockPrefix = "portablefs-attach-receipt";
// Bounded connection pool: the API's global request admission (not the pool)
// is the concurrency control, so the pool never needs to grow past a fixed
// ceiling — waiters queue on checkout instead of piling connections onto the
// database. Callers may configure smaller pools; larger requests are clamped.
const maxPoolConnections = 32;

// The readiness write probe. ON CONFLICT DO UPDATE on a fixed key: exactly
// one heap tuple version, one WAL record, one commit — the same durable
// transition class as a journal or lease write — with NO row accumulation.
// The database clock stamps the row; the caller's host clock never does.
//
// The 4 KiB incompressible filler is what makes this catch an out-of-disk
// DATA volume and not merely an out-of-disk WAL volume: a one-word update
// can be satisfied in place by a HOT update, but a new 4 KiB row version on
// a fillfactor-100 page must find a free page or EXTEND the relation — the
// exact "could not extend file ... No space left on device" the failing
// lease writes hit. Fresh bytes every probe, so it can never be a no-op.
const controlWriteProbeStatement = `INSERT INTO portablefs_control_write_probes AS p
    (probe_key, probe_seq, probed_at_ms, filler)
  VALUES (
    $1,
    1,
    (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT,
    (SELECT decode(string_agg(md5(random()::TEXT || g::TEXT), ''), 'hex')
       FROM generate_series(1, 256) g))
  ON CONFLICT (probe_key) DO UPDATE
    SET probe_seq = p.probe_seq + 1,
        probed_at_ms = EXCLUDED.probed_at_ms,
        filler = EXCLUDED.filler`;

// The probe ring bound. One slot is picked per repository instance so N
// replicas do not serialize every readiness check on one row lock (a lock
// convoy on a healthy store must never read as an outage), while the table
// stays bounded at this many rows forever.
const controlWriteProbeSlots = 16;

// Control-store consumption. Sizes come from the RELATION, not from summing
// row payloads: pg_total_relation_size is O(1) and also the more honest
// number, because it counts indexes, TOAST and dead-tuple bloat — the things
// that actually consume the disk. Summing payload_bytes across the journal
// would cost a full sequential scan that gets slower precisely as the
// problem it reports gets worse (measured: 63 ms on a 320k-record fixture).
//
// Record counts come from each generation's seq span, so this statement
// reads only pfj.journal_generations (a handful of rows) plus catalog size.
// `reclaimable` here uses base_seq, an UPPER BOUND: the exact, proven
// horizon additionally clamps to in-flight cut windows and recovery-anchor
// evidence, and is reported by pfj.journal_storage_usage().
const controlStoreUsageStatement = `SELECT
    pg_database_size(current_database())::TEXT AS database_bytes,
    pg_total_relation_size('pfj.journal_records')::TEXT AS journal_table_bytes,
    COALESCE(SUM(GREATEST(g.next_seq - g.physical_trimmed_seq, 0)), 0)::TEXT
      AS journal_records,
    COALESCE(SUM(GREATEST(g.base_seq - g.physical_trimmed_seq, 0)), 0)::TEXT
      AS reclaimable_journal_records
  FROM pfj.journal_generations g`;

function decimalString(value: string | undefined): string {
  return typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value) ? value : "0";
}

export class PostgresMetadataRepository implements MetadataRepository {
  private readonly pool: Pool;
  private readonly manifestIndexCache: ManifestIndexCache;
  private historyRepository: PostgresHistoryRepository | undefined;
  private readonly controlWriteProbeKey = `readyz:${Math.floor(
    Math.random() * controlWriteProbeSlots
  )}`;

  constructor(config: PoolConfig | string) {
    const poolConfig: PoolConfig =
      typeof config === "string" ? { connectionString: config } : { ...config };
    poolConfig.max = Math.max(1, Math.min(poolConfig.max ?? maxPoolConnections, maxPoolConnections));
    this.pool = new Pool(poolConfig);
    this.manifestIndexCache = new ManifestIndexCache(manifestIndexCacheMaxBytesFromEnv(process.env));
  }

  /**
   * The pfh caller surface bound to this repository's pool. The volume-api
   * reaches cuts, provenance, base proofs, and object locations through this
   * property; the fenced worker surface stays exclusively with the Go
   * history worker's restricted DSN.
   */
  get history(): PostgresHistoryRepository {
    if (!this.historyRepository) {
      this.historyRepository = new PostgresHistoryRepository(this.pool);
    }
    return this.historyRepository;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // probeControlPlane is the readiness primitive: a migration lineage read
  // AND a bounded durable WRITE, both bounded by the caller's signal. It
  // reports problems instead of throwing so readiness handlers stay
  // allocation-free. pg has no per-query cancellation, so an abort abandons
  // the wait (the query settles on its own and its connection returns to the
  // pool).
  //
  // The write leg is the point. A read-only probe cannot distinguish "the
  // control store is serving" from "the control store cannot accept another
  // byte": an out-of-disk primary answers `SELECT count(*) FROM
  // portablefs_migrations` perfectly while every journal and lease write
  // fails, which is exactly how a total control-store outage once shipped as
  // a healthy deploy. The write leg performs the same class of operation the
  // failing writes performed — a real heap tuple version, a real WAL record,
  // a real commit — against a BOUNDED ring of probe rows that are updated in
  // place and never accumulate.
  async probeControlPlane(options?: { signal?: AbortSignal }): Promise<ControlPlaneProbeResult> {
    let migrationLineageComplete = false;
    try {
      const query = this.pool.query<{ applied: string }>(
        `SELECT count(*)::text AS applied FROM portablefs_migrations WHERE id = ANY($1)`,
        [[...migrationIds]]
      );
      const result = options?.signal
        ? await raceAbort(query, options.signal, "control-plane probe aborted")
        : await query;
      const applied = Number(result.rows[0]?.applied ?? 0);
      migrationLineageComplete = applied === migrationIds.length;
      if (!migrationLineageComplete) {
        // A short lineage cannot be repaired by proving writes work, and the
        // probe table may not exist yet; report the lineage gap as-is.
        return {
          ok: false,
          migrationLineageComplete,
          reachable: true,
          writable: false,
          error: `applied ${applied} of ${migrationIds.length} expected migrations`,
        };
      }
    } catch (error) {
      return {
        ok: false,
        migrationLineageComplete: false,
        reachable: false,
        writable: false,
        error: error instanceof Error ? error.message.slice(0, 256) : "control-plane probe failed",
      };
    }
    try {
      const write = this.pool.query(controlWriteProbeStatement, [this.controlWriteProbeKey]);
      await (options?.signal
        ? raceAbort(write, options.signal, "control-plane write probe aborted")
        : write);
      return { ok: true, migrationLineageComplete: true, reachable: true, writable: true };
    } catch (error) {
      // Reachable (the read succeeded moments ago) but NOT writable: the
      // honest shape of a full disk, a read-only replica, or a wedged writer.
      return {
        ok: false,
        migrationLineageComplete: true,
        reachable: true,
        writable: false,
        error:
          error instanceof Error ? error.message.slice(0, 256) : "control-plane write probe failed",
      };
    }
  }

  // controlStoreUsage reports EXACT control-store consumption. Core
  // PostgreSQL exposes no free-space primitive, so headroom cannot be
  // measured honestly from inside the database — consumption can, and it is
  // the curve that filled this database twice. Never inferred, never capped
  // by a guessed capacity: the caller owns the budget.
  async controlStoreUsage(): Promise<ControlStoreUsage> {
    const result = await this.pool.query<{
      database_bytes: string;
      journal_table_bytes: string;
      journal_records: string;
      reclaimable_journal_records: string;
    }>(controlStoreUsageStatement, []);
    const row = result.rows[0];
    return {
      databaseBytes: decimalString(row?.database_bytes),
      journalTableBytes: decimalString(row?.journal_table_bytes),
      journalRecords: decimalString(row?.journal_records),
      reclaimableJournalRecords: decimalString(row?.reclaimable_journal_records),
    };
  }

  private manifestIndexForCommit(commit: VolumeCommit): ManifestIndex {
    const cached = this.manifestIndexCache.get(commit.id);
    if (cached) {
      return cached;
    }
    const index = createManifestIndex(commit.manifest);
    this.rememberManifestIndex(commit.id, index);
    return index;
  }

  private rememberManifestIndex(commitId: string, index: ManifestIndex): void {
    this.manifestIndexCache.set(commitId, index);
  }

  // applyMigrations runs the ordered lineage on ONE dedicated advisory-locked
  // connection. The dedicated client matters twice over: BEGIN/COMMIT pairs
  // are only transactional when every statement runs on the same connection
  // (pool.query may hand each statement a different one), and concurrently
  // starting replicas must serialize on the advisory lock instead of racing
  // DDL. Migration 016 gives ordinary sessions database-owned deadlines via
  // ALTER DATABASE ... SET; this client zeroes them for the long-running
  // maintenance exception and is DISCARDED afterwards — the session that ran
  // ALTER DATABASE can never observe the new defaults itself, so returning
  // it to the pool would hand a future caller an unbounded-timeout
  // connection.
  async applyMigrations(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(
        `SELECT set_config('statement_timeout', '0', false),
                set_config('lock_timeout', '0', false),
                set_config('idle_in_transaction_session_timeout', '0', false)`
      );
      await client.query(`SELECT pg_advisory_lock($1, $2)`, [
        migrationLockClassId,
        migrationLockObjectId,
      ]);
      try {
        await client.query(
          `CREATE TABLE IF NOT EXISTS portablefs_migrations (
            id TEXT PRIMARY KEY,
            applied_at BIGINT NOT NULL
          )`
        );
        for (const migrationId of migrationIds) {
          const applied = await client.query(
            `SELECT id FROM portablefs_migrations WHERE id = $1`,
            [migrationId]
          );
          if (applied.rows[0]) {
            continue;
          }
          const sql = await readMigrationSql(migrationId);
          await client.query("BEGIN");
          try {
            await client.query(sql);
            await client.query(
              `INSERT INTO portablefs_migrations (id, applied_at)
               VALUES ($1, $2)
               ON CONFLICT (id) DO NOTHING`,
              [migrationId, Date.now()]
            );
            await client.query("COMMIT");
          } catch (error) {
            await client.query("ROLLBACK");
            throw error;
          }
        }
      } finally {
        // Unlock even on failure so a crashed migration never wedges every
        // future applyMigrations fleet-wide; the client is discarded below
        // regardless.
        await client
          .query(`SELECT pg_advisory_unlock($1, $2)`, [
            migrationLockClassId,
            migrationLockObjectId,
          ])
          .catch(() => undefined);
      }
    } finally {
      // Unconditionally destroy the connection instead of returning it to
      // the pool: its zeroed timeouts (and, on the run that first applied
      // 016, its pre-016 session defaults) must never leak to a caller.
      client.release(true);
    }
    await this.backfillBlobRefsIfEmpty();
  }

  // backfillBlobRefsIfEmpty populates blob_refs from existing commits the first
  // time the table is introduced, so blob read-authz is complete for pre-existing
  // data (going forward it is maintained per-commit). A no-op once populated.
  private async backfillBlobRefsIfEmpty(): Promise<void> {
    const existing = await this.pool.query(`SELECT 1 FROM blob_refs LIMIT 1`);
    if ((existing.rowCount ?? 0) > 0) {
      return;
    }
    await this.transaction(async (client) => {
      // PFT2 history commits carry no JSON manifest and reference pfh
      // objects, not public blobs; only manifest-bearing rows mint refs.
      const commits = await client.query(
        `SELECT * FROM commits WHERE commit_kind IS DISTINCT FROM 'pft2' ORDER BY created_at ASC, id ASC`
      );
      for (const row of commits.rows) {
        const commit = await this.commitFromRowInTx(client, row);
        await this.recordBlobRefsInTx(
          client,
          String(row.tenant_id),
          commit.volumeId,
          commit.manifest
        );
      }
    });
  }

  // Volume ids are unique within one tenant. A same-tenant duplicate is an
  // explicit 409; another tenant may independently use the same public id.
  private async insertVolumeRow(
    client: PoolClient,
    volumeId: string,
    tenantId: string,
    now: number
  ): Promise<void> {
    try {
      await client.query(
        `INSERT INTO volumes (id, tenant_id, created_at)
         VALUES ($1, $2, $3)`,
        [volumeId, tenantId, now]
      );
    } catch (error) {
      if (isUniqueViolation(error, "volumes_pkey")) {
        throw new MetadataConflictError(
          "VOLUME_ALREADY_EXISTS",
          "Volume already exists.",
          409
        );
      }
      throw error;
    }
  }

  async createVolume(input: CreateVolumeInput): Promise<CreateVolumeResult> {
    return this.transaction(async (client) => {
      const now = Date.now();
      const volumeId = input.volumeId ?? `vol_${randomUUID()}`;
      const branchId = `br_${randomUUID()}`;
      const commitId = `cmt_${randomUUID()}`;
      const manifest = emptyManifest();
      await client.query(
        `INSERT INTO tenants (id, created_at)
         VALUES ($1, $2)
         ON CONFLICT (id) DO NOTHING`,
        [input.tenantId, now]
      );
      await this.insertVolumeRow(client, volumeId, input.tenantId, now);
      await client.query(
        `INSERT INTO commits
         (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, mutation_count, byte_count, created_at)
         VALUES ($1, $2, $3, $4, NULL, $5, $6, 0, 0, $7)`,
        [commitId, input.tenantId, volumeId, branchId, manifest.treeHash, JSON.stringify(manifest), now]
      );
      if (input.managed) {
        // Authoritative managed provisioning: the branch is BORN
        // managed_journal, before any attach session, lease, or claim can
        // exist — a PFJ3 claim later requires this mode and never sets it
        // (the 013 branch guard only constrains UPDATEs; INSERT is the one
        // conversion-free journal birth).
        await client.query(
          `INSERT INTO branches
           (id, tenant_id, volume_id, name, head_commit_id, branch_mode, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, 'managed_journal', $6, $6)`,
          [branchId, input.tenantId, volumeId, input.branchName, commitId, now]
        );
      } else {
        await client.query(
          `INSERT INTO branches
           (id, tenant_id, volume_id, name, head_commit_id, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $6)`,
          [branchId, input.tenantId, volumeId, input.branchName, commitId, now]
        );
      }
      await client.query(`UPDATE volumes SET default_branch_id = $1 WHERE tenant_id = $2 AND id = $3`, [
        branchId,
        input.tenantId,
        volumeId,
      ]);
      const volume = await this.getVolume(client, input.tenantId, volumeId);
      const branch = await this.getBranchById(client, branchId);
      const head = await this.getCommitInTx(client, commitId);
      return { volume: requireRow(volume, "Volume"), branch: requireRow(branch, "Branch"), head: requireRow(head, "Commit") };
    });
  }

  async getStatus(input: VolumeStatusInput): Promise<CreateVolumeResult | null> {
    return this.transaction(async (client) => {
      const volume = await this.getVolume(client, input.tenantId, input.volumeId);
      if (!volume) {
        return null;
      }
      const branch = await this.getBranchByName(
        client,
        input.tenantId,
        input.volumeId,
        input.branchName
      );
      if (!branch) {
        return null;
      }
      const head = await this.getCommitInTx(client, branch.headCommitId);
      const activeLeases = await this.countActiveLeases(client, branch.id, Date.now());
      const activeDelegations = await this.countActiveDelegations(client, branch.id, Date.now());
      return { volume, branch, head: requireRow(head, "Commit"), activeLeases, activeDelegations };
    });
  }

  async getHead(input: VolumeStatusInput): Promise<VolumeHeadResult | null> {
    return this.transaction(async (client) => {
      const volume = await this.getVolume(client, input.tenantId, input.volumeId);
      if (!volume) {
        return null;
      }
      const branch = await this.getBranchByName(
        client,
        input.tenantId,
        input.volumeId,
        input.branchName
      );
      if (!branch) {
        return null;
      }
      const head = await this.getCommitSummaryInTx(client, branch.headCommitId);
      const activeLeases = await this.countActiveLeases(client, branch.id, Date.now());
      const activeDelegations = await this.countActiveDelegations(client, branch.id, Date.now());
      return {
        volume,
        branch,
        head: requireRow(head, "Commit"),
        activeLeases,
        activeDelegations,
      };
    });
  }

  async waitForHead(input: WaitForHeadInput): Promise<VolumeHeadResult | null> {
    const timeoutMs = Math.max(1, Math.min(input.timeoutMs, 60_000));
    throwIfWaitAborted(input.signal);
    const immediate = await this.getHead(input);
    if (!immediate || immediate.branch.headCommitId !== input.afterCommitId) {
      return immediate;
    }
    throwIfWaitAborted(input.signal);

    const listener = await this.pool.connect();
    let releaseOnExit = true;
    try {
      // The signal may have fired while the checkout was pending; the finally
      // below still releases the connection.
      throwIfWaitAborted(input.signal);
      await listener.query(`LISTEN ${headNotifyChannel}`);
      releaseOnExit = false;
      // createPostgresHeadWait owns the listener from here: every settle path
      // (notification, timeout, error, abort) runs UNLISTEN and releases it.
      const wait = createPostgresHeadWait(listener, input, timeoutMs, () => this.getHead(input));

      // Close the race where a commit lands after the first head read but before LISTEN is active.
      this.getHead(input).then(
        (afterListen) => {
          if (!afterListen || afterListen.branch.headCommitId !== input.afterCommitId) {
            wait.resolve(afterListen);
          }
        },
        (error) => wait.reject(error)
      );

      return await wait.promise;
    } finally {
      if (releaseOnExit) {
        listener.release();
      }
    }
  }

  async getManifestDiff(input: VolumeManifestDiffInput): Promise<VolumeManifestDiffResult | null> {
    return this.transaction(async (client) => {
      const volume = await this.getVolume(client, input.tenantId, input.volumeId);
      if (!volume) {
        return null;
      }
      const branch = await this.getBranchByName(
        client,
        input.tenantId,
        input.volumeId,
        input.branchName
      );
      if (!branch) {
        return null;
      }
      const base = await this.getCommitInTx(client, input.baseCommitId);
      if (!base || base.branchId !== branch.id) {
        throw new MetadataConflictError("VOLUME_BASE_COMMIT_NOT_FOUND", "Base commit was not found on this branch.", 404);
      }
      const head = requireRow(await this.getCommitInTx(client, branch.headCommitId), "Commit");
      const rootPath = normalizeVolumePath(input.rootPath);
      const baseManifest = projectManifest(base.manifest, rootPath);
      const targetManifest = projectManifest(head.manifest, rootPath);
      return {
        volume,
        branch,
        head: requireRow(await this.getCommitSummaryInTx(client, branch.headCommitId), "Commit"),
        baseCommitId: base.id,
        rootPath,
        targetTreeHash: targetManifest.treeHash,
        targetEntryCount: targetManifest.entries.length,
        diff: diffManifests(baseManifest, targetManifest),
      };
    });
  }

  async getCommit(commitId: string): Promise<VolumeCommit | null> {
    return this.transaction((client) => this.getCommitInTx(client, commitId));
  }

  async getManifest(commitId: string): Promise<TreeManifest | null> {
    const commit = await this.getCommit(commitId);
    return commit?.manifest ?? null;
  }

  async attachVolume(input: AttachVolumeInput): Promise<AttachVolumeResult> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const rootPath = normalizeVolumePath(input.rootPath);
      let requestFingerprint: string | undefined;
      if (input.operationId) {
        if (!input.tenantId) {
          throw new MetadataConflictError(
            "VOLUME_TENANT_REQUIRED",
            "Receipted attach requires a verified tenant identity.",
            403
          );
        }
        requestFingerprint = attachRequestFingerprint({
          tenantId: input.tenantId,
          volumeId: input.volumeId,
          branchName: input.branchName,
          mode: input.mode,
          shared: input.shared,
          rootPath,
          holderId: input.holderId,
          leaseTtlMs: input.leaseTtlMs,
          prefetchPaths: input.prefetchPaths,
          clientInfo: input.clientInfo,
        });
        const recorded = await this.resolveOrClaimAttachReceiptInTx(
          client,
          input.tenantId,
          input.operationId,
          requestFingerprint
        );
        if (recorded) {
          return recorded;
        }
      }
      const volume = await this.getVolume(client, input.tenantId, input.volumeId);
      if (!volume) {
        throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume not found.", 404);
      }
      const branch = await this.getBranchByNameForUpdate(
        client,
        input.tenantId,
        input.volumeId,
        input.branchName
      );
      if (!branch) {
        throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
      }
      this.assertAttachBranchMode(branch, Boolean(input.operationId));
      if ((branch.branchMode ?? "legacy_manifest") !== "legacy_manifest" && rootPath) {
        // A journal-owned branch has no manifest to project a subtree from,
        // and the authority child serves the WHOLE branch — subtree scoping
        // is a mount-time concern on live branches. Refuse typed instead of
        // silently attaching the full volume under a narrower-looking session.
        throw new MetadataConflictError(
          "VOLUME_ROOT_PATH_UNSUPPORTED",
          "Attach cannot scope a journal-owned branch to a rootPath; subtree access is a mount-time concern on live branches.",
          409
        );
      }
      if (input.mode === "write") {
        const activeLease = await client.query(
          `SELECT * FROM leases
           WHERE branch_id = $1
             AND released_at IS NULL
             AND expires_at > $2
             AND ($3::boolean = FALSE OR exclusive = TRUE)
           ORDER BY expires_at DESC
           LIMIT 1`,
          [branch.id, now, input.shared]
        );
        if (activeLease.rows[0]) {
          throw new MetadataConflictError(
            "VOLUME_WRITE_LEASE_BUSY",
            input.shared
              ? "Volume branch has an active exclusive writer."
              : "Volume branch already has an active writer.",
            423
          );
        }
      }
      const attachBase = requireRow(await this.getAttachBaseCommitInTx(client, branch), "Commit");
      const head = attachBase.head;
      const headManifest = attachBase.manifest;
      if (rootPath) {
        // A non-empty rootPath implies a legacy branch (journal-owned
        // refused above), so the manifest is present; optional chaining
        // keeps the refusal fail-closed regardless.
        const rootEntry = headManifest?.entries.find((entry) => entry.path === rootPath);
        if (!rootEntry || rootEntry.kind !== "directory") {
          throw new MetadataConflictError(
            "VOLUME_ROOT_PATH_NOT_FOUND",
            "Attach rootPath must point to an existing directory.",
            404
          );
        }
      }
      const sessionId = `att_${randomUUID()}`;
      await client.query(
        `INSERT INTO attach_sessions
         (id, tenant_id, volume_id, branch_id, mode, shared, root_path, base_commit_id, holder_id, status, client_info, attached_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'attached', $10, $11)`,
        [
          sessionId,
          input.tenantId,
          input.volumeId,
          branch.id,
          input.mode,
          input.shared,
          rootPath,
          head.id,
          input.holderId,
          JSON.stringify(input.clientInfo ?? {}),
          now,
        ]
      );
      let lease: VolumeLease | undefined;
      const delegations: PathDelegation[] = [];
      if (input.mode === "write") {
        const leaseId = `lse_${randomUUID()}`;
        const nextToken = branch.leaseCounter + 1;
        await client.query(`UPDATE branches SET lease_counter = $1 WHERE id = $2`, [
          nextToken,
          branch.id,
        ]);
        await client.query(
        `INSERT INTO leases
           (id, tenant_id, volume_id, branch_id, attach_session_id, holder_id, fencing_token, exclusive, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [
            leaseId,
            input.tenantId,
            input.volumeId,
            branch.id,
            sessionId,
            input.holderId,
            nextToken,
            !input.shared,
            now + input.leaseTtlMs,
          ]
        );
        lease = requireRow(await this.getLease(client, leaseId), "Lease");
        if (!input.shared) {
          delegations.push(
            await this.createDelegation(client, {
              tenantId: input.tenantId,
              volumeId: input.volumeId,
              branchId: branch.id,
              attachSessionId: sessionId,
              leaseId,
              holderId: input.holderId,
              path: rootPath,
              recursive: true,
              fencingToken: nextToken,
              expiresAt: now + input.leaseTtlMs,
              createdAt: now,
            })
          );
        }
      }
      const session = requireRow(await this.getSession(client, sessionId), "Attach session");
      const outcome = {
        session: lease ? { ...session, lease } : session,
        // Journal recovery starts from the generation base, which may
        // intentionally lag the materialized branch head until a history cut.
        branch: { ...branch, headCommitId: head.id },
        delegations,
      };
      // Journal-owned branches attach manifest-free: the child binds its
      // journal claim to head.id and proves the base content through
      // pfh.serving_base_prove, never through this response (the Go client
      // parses an absent manifest key as its zero value).
      const manifestFacts = headManifest
        ? { manifest: projectManifest(headManifest, rootPath) }
        : {};
      if (input.operationId && input.tenantId && requestFingerprint) {
        await this.insertAttachReceiptInTx(client, {
          tenantId: input.tenantId,
          operationId: input.operationId,
          requestFingerprint,
          volumeId: input.volumeId,
          branchId: branch.id,
          attachSessionId: sessionId,
          baseCommitId: head.id,
          outcome,
          createdAt: now,
        });
        return {
          ...outcome,
          ...manifestFacts,
          receipt: { operationId: input.operationId, replayed: false, createdAt: now },
          current: {
            observedAt: now,
            branch,
            session: outcome.session,
            activeDelegations: delegations.length,
          },
        };
      }
      return { ...outcome, ...manifestFacts };
    });
  }

  async renewLease(input: RenewLeaseInput): Promise<VolumeLease> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const lease = await this.getLeaseForUpdate(client, input.leaseId);
      if (!lease || lease.fencingToken !== input.fencingToken || lease.releasedAt) {
        throw new MetadataConflictError("VOLUME_LEASE_STALE", "Volume write lease is stale.", 409);
      }
      if (lease.expiresAt <= now) {
        throw new MetadataConflictError("VOLUME_LEASE_EXPIRED", "Volume write lease expired.", 409);
      }
      await client.query(`UPDATE leases SET expires_at = $1 WHERE id = $2`, [
        now + input.leaseTtlMs,
        input.leaseId,
      ]);
      await client.query(
        `UPDATE path_delegations
         SET expires_at = $1
         WHERE lease_id = $2 AND released_at IS NULL AND revoked_at IS NULL`,
        [now + input.leaseTtlMs, input.leaseId]
      );
      return requireRow(await this.getLease(client, input.leaseId), "Lease");
    });
  }

  async checkout(input: CheckoutInput): Promise<CheckoutResult> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const session = await this.getSessionForUpdate(client, input.attachSessionId);
      if (!session || session.mode !== "write" || session.detachedAt) {
        throw new MetadataConflictError("VOLUME_ATTACH_SESSION_CLOSED", "Attach session is not writable.", 409);
      }
      const requestedPath = input.path ?? "";
      const requestedRecursive = input.recursive ?? true;
      const lease = await this.assertWritableLease(client, {
        leaseId: input.leaseId,
        attachSessionId: input.attachSessionId,
        fencingToken: input.fencingToken,
        now,
      });
      const pathValue = joinVolumePath(session.rootPath, requestedPath);
      const branch = await this.getBranchByIdForUpdate(client, session.branchId);
      if (!branch) {
        throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
      }
      if (session.shared && !pathValue && requestedRecursive) {
        throw new MetadataConflictError(
          "VOLUME_ROOT_DELEGATION_DENIED",
          "Shared sessions cannot claim ownership of the volume root.",
          409
        );
      }
      const existing = await this.listActiveDelegationsForUpdate(client, branch.id, now);
      const conflicts = existing.filter(
        (delegation) =>
          delegation.attachSessionId !== input.attachSessionId &&
          pathDelegationsOverlap(delegation, { path: pathValue, recursive: requestedRecursive })
      );
      if (conflicts.length && !input.force) {
        throw new MetadataConflictError(
          "VOLUME_DELEGATION_BUSY",
          `Path is already checked out: ${pathValue || "/"}.`,
          423
        );
      }
      const revoked: PathDelegation[] = [];
      if (conflicts.length) {
        for (const conflict of conflicts) {
          await client.query(
            `UPDATE path_delegations
             SET revoked_at = COALESCE(revoked_at, $1)
             WHERE id = $2`,
            [now, conflict.id]
          );
          revoked.push({ ...conflict, revokedAt: conflict.revokedAt ?? now });
        }
      }
      const existingOwned = existing.find(
        (delegation) =>
          delegation.attachSessionId === input.attachSessionId &&
          !delegation.revokedAt &&
          !delegation.releasedAt &&
          delegation.path === pathValue &&
          delegation.recursive === requestedRecursive
      );
      if (existingOwned) {
        return { delegation: existingOwned, revoked };
      }
      const delegation = await this.createDelegation(client, {
        tenantId: branch.tenantId,
        volumeId: session.volumeId,
        branchId: session.branchId,
        attachSessionId: input.attachSessionId,
        leaseId: lease.id,
        holderId: lease.holderId,
        path: pathValue,
        recursive: requestedRecursive,
        fencingToken: lease.fencingToken,
        expiresAt: lease.expiresAt,
        createdAt: now,
      });
      return { delegation, revoked };
    });
  }

  async checkin(input: CheckinInput): Promise<CheckinResult> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const session = await this.getSessionForUpdate(client, input.attachSessionId);
      if (!session) {
        throw new MetadataConflictError("VOLUME_ATTACH_SESSION_NOT_FOUND", "Attach session not found.", 404);
      }
      const pathValue =
        input.path === undefined ? undefined : joinVolumePath(session.rootPath, input.path);
      const result = await client.query(
        `SELECT * FROM path_delegations
         WHERE attach_session_id = $1
           AND released_at IS NULL
           AND revoked_at IS NULL
           AND ($2::text IS NULL OR id = $2)
           AND ($3::text IS NULL OR path = $3)
         FOR UPDATE`,
        [input.attachSessionId, input.delegationId ?? null, pathValue ?? null]
      );
      const released = result.rows.map((row) => toDelegation(row));
      for (const delegation of released) {
        await client.query(
          `UPDATE path_delegations
           SET released_at = COALESCE(released_at, $1)
           WHERE id = $2`,
          [now, delegation.id]
        );
      }
      return {
        released: released.map((delegation) => ({
          ...delegation,
          releasedAt: delegation.releasedAt ?? now,
        })),
      };
    });
  }

  async listDelegations(input: ListDelegationsInput): Promise<PathDelegation[]> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      let branchId = input.branchId;
      if (!branchId && input.volumeId && input.branchName) {
        const branch = await this.getBranchByName(
          client,
          input.tenantId,
          input.volumeId,
          input.branchName
        );
        branchId = branch?.id;
      }
      const result = await client.query(
        `SELECT * FROM path_delegations
         WHERE tenant_id = $1
           AND ($2::text IS NULL OR branch_id = $2)
           AND ($3::text IS NULL OR attach_session_id = $3)
           AND ($4::boolean = TRUE OR (released_at IS NULL AND revoked_at IS NULL AND expires_at > $5))
         ORDER BY path ASC, created_at ASC, id ASC`,
        [
          input.tenantId,
          branchId ?? null,
          input.attachSessionId ?? null,
          Boolean(input.includeReleased),
          now,
        ]
      );
      return result.rows.map((row) => toDelegation(row));
    });
  }

  async commit(input: CommitVolumeInput): Promise<CommitVolumeResult> {
    return this.commitInternal(input, "full") as Promise<CommitVolumeResult>;
  }

  async commitSummary(input: CommitVolumeInput): Promise<CommitVolumeSummaryResult> {
    return this.commitInternal(input, "summary") as Promise<CommitVolumeSummaryResult>;
  }

  async commitDeltaSummary(input: CommitVolumeDeltaInput): Promise<CommitVolumeSummaryResult> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const session = await this.getSessionForUpdate(client, input.attachSessionId);
      if (!session || session.mode !== "write" || session.detachedAt) {
        throw new MetadataConflictError("VOLUME_ATTACH_SESSION_CLOSED", "Attach session is not writable.", 409);
      }
      await this.assertWritableLease(client, {
        leaseId: input.leaseId,
        attachSessionId: input.attachSessionId,
        fencingToken: input.fencingToken,
        now,
      });
      const branch = await this.getBranchByIdForUpdate(client, session.branchId);
      if (!branch) {
        throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
      }
      this.assertLegacyManifestMutation(branch);
      const parsedDiff = treeManifestDiffSchema.parse(input.diff);
      assertManifestDiffShape(parsedDiff);
      const rootPath = normalizeVolumePath(session.rootPath);
      const baseCommit = await this.getCommitInTx(client, input.expectedHeadCommitId);
      if (!baseCommit || baseCommit.branchId !== session.branchId) {
        throw new MetadataConflictError("VOLUME_BASE_COMMIT_NOT_FOUND", "Commit base was not found on this branch.", 409);
      }
      const baseCommitIndex = this.manifestIndexForCommit(baseCommit);
      const baseProjected = rootPath ? projectManifest(baseCommit.manifest, rootPath) : baseCommitIndex.manifest;
      const baseProjectedIndex = rootPath ? createManifestIndex(baseProjected) : baseCommitIndex;
      const requestedProjected = applyManifestDiffIndexed(baseProjectedIndex, parsedDiff);
      const requestedProjectedManifest = requestedProjected.manifest;
      if (requestedProjectedManifest.treeHash !== input.targetTreeHash) {
        throw new MetadataConflictError("VOLUME_TREE_HASH_MISMATCH", "Commit delta target tree hash is invalid.", 400);
      }
      const requestedDiff = canonicalizeManifestDiff(baseProjectedIndex, parsedDiff);
      assertManifestDiffShape(requestedDiff);
      if (
        requestedDiff.mutationCount !== parsedDiff.mutationCount ||
        requestedDiff.byteCount !== parsedDiff.byteCount
      ) {
        throw new MetadataConflictError("VOLUME_COMMIT_DELTA_MISMATCH", "Commit delta does not match its base.", 400);
      }
      if (session.shared) {
        await this.assertDelegationsCoverMutation(client, {
          branchId: session.branchId,
          attachSessionId: input.attachSessionId,
          mutationPaths: collectMutationPaths(requestedDiff, rootPath),
          now,
        });
      }

      let parentCommitId = branch.headCommitId;
      let parentManifestIndex = baseCommitIndex;
      let manifestToCommit: TreeManifest;
      let manifestToCommitIndex = requestedProjected.index;
      let mergedFromHeadCommitId: string | undefined;
      if (branch.headCommitId === input.expectedHeadCommitId) {
        if (rootPath) {
          const applied = applyManifestDiffIndexed(parentManifestIndex, requestedDiff, rootPath);
          manifestToCommit = applied.manifest;
          manifestToCommitIndex = applied.index;
        } else {
          manifestToCommit = requestedProjectedManifest;
        }
      } else {
        if (!session.shared) {
          throw new MetadataConflictError("VOLUME_HEAD_CHANGED", "Volume branch head changed.", 409);
        }
        const currentHead = requireRow(
          await this.getCommitInTx(client, branch.headCommitId),
          "Current head commit"
        );
        const currentHeadIndex = this.manifestIndexForCommit(currentHead);
        const currentDiff = diffManifestIndexes(
          baseProjectedIndex,
          rootPath
            ? createManifestIndex(projectManifest(currentHead.manifest, rootPath))
            : currentHeadIndex
        );
        if (diffHasPathConflict(requestedDiff, currentDiff)) {
          throw new MetadataConflictError(
            "VOLUME_MERGE_CONFLICT",
            "Shared writer changes conflict with a newer committed head.",
            409
          );
        }
        parentManifestIndex = currentHeadIndex;
        const applied = applyManifestDiffIndexed(parentManifestIndex, requestedDiff, rootPath);
        manifestToCommit = applied.manifest;
        manifestToCommitIndex = applied.index;
        mergedFromHeadCommitId = currentHead.id;
        parentCommitId = currentHead.id;
      }
      const diffToParent = diffManifestIndexes(parentManifestIndex, manifestToCommitIndex);
      const parentDiffDepth = await this.getManifestDiffChainDepthInTx(client, parentCommitId);
      const shouldMaterializeManifest = parentDiffDepth + 1 >= maxManifestDiffChainDepth;
      const commitId = `cmt_${randomUUID()}`;
      if (shouldMaterializeManifest) {
        await client.query(
          `INSERT INTO commits
           (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, manifest_base_commit_id, manifest_diff, materialized_manifest, mutation_count, byte_count, created_by_attach_session_id, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, TRUE, $8, $9, $10, $11)`,
          [
            commitId,
            branch.tenantId,
            session.volumeId,
            session.branchId,
            parentCommitId,
            manifestToCommit.treeHash,
            JSON.stringify(manifestToCommit),
            requestedDiff.mutationCount,
            requestedDiff.byteCount,
            input.attachSessionId,
            now,
          ]
        );
      } else {
        await client.query(
          `INSERT INTO commits
           (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, manifest_base_commit_id, manifest_diff, materialized_manifest, mutation_count, byte_count, created_by_attach_session_id, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, NULL, $5, $7, FALSE, $8, $9, $10, $11)`,
          [
            commitId,
            branch.tenantId,
            session.volumeId,
            session.branchId,
            parentCommitId,
            manifestToCommit.treeHash,
            JSON.stringify(diffToParent),
            requestedDiff.mutationCount,
            requestedDiff.byteCount,
            input.attachSessionId,
            now,
          ]
        );
      }
      await client.query(`UPDATE branches SET head_commit_id = $1, updated_at = $2 WHERE id = $3`, [
        commitId,
        now,
        branch.id,
      ]);
      await this.recordBlobRefsInTx(client, branch.tenantId, session.volumeId, manifestToCommit);
      const commit: VolumeCommitSummary = {
        id: commitId,
        volumeId: session.volumeId,
        branchId: session.branchId,
        parentCommitId,
        treeHash: manifestToCommit.treeHash,
        mutationCount: requestedDiff.mutationCount,
        byteCount: requestedDiff.byteCount,
        createdByAttachSessionId: input.attachSessionId,
        createdAt: now,
      };
      this.rememberManifestIndex(commitId, manifestToCommitIndex);
      const updatedBranch = requireRow(await this.getBranchById(client, branch.id), "Branch");
      await this.notifyBranchHeadInTx(client, updatedBranch, commitId);
      return Object.assign(
        { commit, branch: updatedBranch },
        mergedFromHeadCommitId ? { mergedFromHeadCommitId } : {}
      );
    });
  }

  private async commitInternal(
    input: CommitVolumeInput,
    responseMode: "full" | "summary"
  ): Promise<CommitVolumeResult | CommitVolumeSummaryResult> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const session = await this.getSessionForUpdate(client, input.attachSessionId);
      if (!session || session.mode !== "write" || session.detachedAt) {
        throw new MetadataConflictError("VOLUME_ATTACH_SESSION_CLOSED", "Attach session is not writable.", 409);
      }
      await this.assertWritableLease(client, {
        leaseId: input.leaseId,
        attachSessionId: input.attachSessionId,
        fencingToken: input.fencingToken,
        now,
      });
      const branch = await this.getBranchByIdForUpdate(client, session.branchId);
      if (!branch) {
        throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
      }
      this.assertLegacyManifestMutation(branch);
      const parsedManifest = treeManifestSchema.parse(input.manifest);
      if (parsedManifest.treeHash !== computeTreeHash(parsedManifest.entries)) {
        throw new MetadataConflictError("VOLUME_TREE_HASH_MISMATCH", "Commit manifest tree hash is invalid.", 400);
      }
      const rootPath = normalizeVolumePath(session.rootPath);
      const baseCommit = await this.getCommitInTx(client, input.expectedHeadCommitId);
      if (!baseCommit || baseCommit.branchId !== session.branchId) {
        throw new MetadataConflictError("VOLUME_BASE_COMMIT_NOT_FOUND", "Commit base was not found on this branch.", 409);
      }
      const baseCommitIndex = this.manifestIndexForCommit(baseCommit);
      const baseProjected = rootPath ? projectManifest(baseCommit.manifest, rootPath) : baseCommitIndex.manifest;
      const baseProjectedIndex = rootPath ? createManifestIndex(baseProjected) : baseCommitIndex;
      const parsedManifestIndex = createManifestIndex(parsedManifest);
      const requestedDiff = diffManifestIndexes(baseProjectedIndex, parsedManifestIndex);
      if (session.shared) {
        await this.assertDelegationsCoverMutation(client, {
          branchId: session.branchId,
          attachSessionId: input.attachSessionId,
          mutationPaths: collectMutationPaths(requestedDiff, rootPath),
          now,
        });
      }

      let parentCommitId = branch.headCommitId;
      let manifestToCommit: TreeManifest;
      let manifestToCommitIndex = parsedManifestIndex;
      let mergedFromHeadCommitId: string | undefined;
      let parentManifestIndex = baseCommitIndex;
      if (branch.headCommitId === input.expectedHeadCommitId) {
        if (rootPath) {
          const applied = applyManifestDiffIndexed(parentManifestIndex, requestedDiff, rootPath);
          manifestToCommit = applied.manifest;
          manifestToCommitIndex = applied.index;
        } else {
          manifestToCommit = parsedManifest;
        }
      } else {
        if (!session.shared) {
          throw new MetadataConflictError("VOLUME_HEAD_CHANGED", "Volume branch head changed.", 409);
        }
        const currentHead = requireRow(
          await this.getCommitInTx(client, branch.headCommitId),
          "Current head commit"
        );
        const currentHeadIndex = this.manifestIndexForCommit(currentHead);
        const currentDiff = diffManifestIndexes(
          baseProjectedIndex,
          rootPath
            ? createManifestIndex(projectManifest(currentHead.manifest, rootPath))
            : currentHeadIndex
        );
        if (diffHasPathConflict(requestedDiff, currentDiff)) {
          throw new MetadataConflictError(
            "VOLUME_MERGE_CONFLICT",
            "Shared writer changes conflict with a newer committed head.",
            409
          );
        }
        parentManifestIndex = currentHeadIndex;
        const applied = applyManifestDiffIndexed(parentManifestIndex, requestedDiff, rootPath);
        manifestToCommit = applied.manifest;
        manifestToCommitIndex = applied.index;
        mergedFromHeadCommitId = currentHead.id;
        parentCommitId = currentHead.id;
      }
      if (manifestToCommit.treeHash !== manifestToCommitIndex.manifest.treeHash) {
        throw new MetadataConflictError("VOLUME_TREE_HASH_MISMATCH", "Merged manifest tree hash is invalid.", 500);
      }
      const commitId = `cmt_${randomUUID()}`;
      await client.query(
        `INSERT INTO commits
         (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, mutation_count, byte_count, created_by_attach_session_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          commitId,
          branch.tenantId,
          session.volumeId,
          session.branchId,
          parentCommitId,
          manifestToCommit.treeHash,
          JSON.stringify(manifestToCommit),
          requestedDiff.mutationCount,
          requestedDiff.byteCount,
          input.attachSessionId,
          now,
        ]
      );
      await client.query(`UPDATE branches SET head_commit_id = $1, updated_at = $2 WHERE id = $3`, [
        commitId,
        now,
        branch.id,
      ]);
      await this.recordBlobRefsInTx(client, branch.tenantId, session.volumeId, manifestToCommit);
      const commitSummary: VolumeCommitSummary = {
        id: commitId,
        volumeId: session.volumeId,
        branchId: session.branchId,
        parentCommitId,
        treeHash: manifestToCommit.treeHash,
        mutationCount: requestedDiff.mutationCount,
        byteCount: requestedDiff.byteCount,
        createdByAttachSessionId: input.attachSessionId,
        createdAt: now,
      };
      this.rememberManifestIndex(commitId, manifestToCommitIndex);
      const commit =
        responseMode === "full"
          ? { ...commitSummary, manifest: manifestToCommit }
          : commitSummary;
      const updatedBranch = requireRow(await this.getBranchById(client, branch.id), "Branch");
      await this.notifyBranchHeadInTx(client, updatedBranch, commitId);
      return Object.assign(
        { commit, branch: updatedBranch },
        mergedFromHeadCommitId ? { mergedFromHeadCommitId } : {}
      );
    });
  }

  async detach(input: DetachVolumeInput): Promise<AttachSession> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const session = await this.getSessionForUpdate(client, input.attachSessionId);
      if (!session) {
        throw new MetadataConflictError("VOLUME_ATTACH_SESSION_NOT_FOUND", "Attach session not found.", 404);
      }
      if (input.releaseLease) {
        await client.query(
          `UPDATE leases SET released_at = COALESCE(released_at, $1)
           WHERE attach_session_id = $2 AND released_at IS NULL`,
          [now, input.attachSessionId]
        );
        await client.query(
          `UPDATE path_delegations SET released_at = COALESCE(released_at, $1)
           WHERE attach_session_id = $2 AND released_at IS NULL AND revoked_at IS NULL`,
          [now, input.attachSessionId]
        );
      }
      await client.query(
        `UPDATE attach_sessions
         SET status = 'detached', detached_at = COALESCE(detached_at, $1)
         WHERE id = $2`,
        [now, input.attachSessionId]
      );
      return requireRow(await this.getSession(client, input.attachSessionId), "Attach session");
    });
  }

  async snapshot(input: SnapshotInput): Promise<VolumeSnapshot> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const branch = await this.getBranchByName(
        client,
        input.tenantId,
        input.volumeId,
        input.branchName
      );
      if (!branch) {
        throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
      }
      // A commit-pinned snapshot captures the CURRENT manifest head; on a
      // journal-owned branch that head is stale truth — those branches
      // snapshot through the cut plane (snapshotCut).
      this.assertLegacyManifestMutation(branch);
      const snapshotId = input.snapshotId ?? `snp_${randomUUID()}`;
      await client.query(
        `INSERT INTO snapshots (id, tenant_id, volume_id, branch_id, commit_id, name, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          snapshotId,
          input.tenantId,
          input.volumeId,
          branch.id,
          branch.headCommitId,
          input.name ?? null,
          now,
        ]
      );
      return requireRow(await this.getSnapshot(client, snapshotId), "Snapshot");
    });
  }

  async listSnapshots(input: ListSnapshotsInput): Promise<VolumeSnapshot[]> {
    return this.transaction(async (client) => {
      let branchId: string | undefined;
      if (input.branchName) {
        const branch = await this.getBranchByName(
          client,
          input.tenantId,
          input.volumeId,
          input.branchName
        );
        if (!branch) {
          throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
        }
        branchId = branch.id;
      }
      const result = await client.query(
        `SELECT * FROM snapshots
         WHERE tenant_id = $1 AND volume_id = $2
           AND ($3::text IS NULL OR branch_id = $3)
         ORDER BY created_at ASC, id ASC`,
        [input.tenantId, input.volumeId, branchId ?? null]
      );
      return result.rows.map((row) => toSnapshot(row));
    });
  }

  async createBranch(input: CreateBranchInput): Promise<{ branch: VolumeBranch; head: VolumeCommit }> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const sourceBranch = await this.getBranchByName(
        client,
        input.tenantId,
        input.volumeId,
        input.fromBranch ?? "main"
      );
      if (!sourceBranch) {
        throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Source branch not found.", 404);
      }
      const snapshot = await this.findSnapshotForBranch(
        client,
        Object.assign(
          {
            tenantId: input.tenantId,
            volumeId: input.volumeId,
            branchId: sourceBranch.id,
          },
          input.fromSnapshotId ? { snapshotId: input.fromSnapshotId } : {},
          input.fromSnapshotName ? { snapshotName: input.fromSnapshotName } : {}
        )
      );
      if (!snapshot) {
        throw new MetadataConflictError("VOLUME_SNAPSHOT_NOT_FOUND", "Snapshot not found.", 404);
      }
      const branchId = `br_${randomUUID()}`;
      const branchPointCommitId = await this.createBranchPointCommitInTx(client, {
        tenantId: input.tenantId,
        volumeId: input.volumeId,
        branchId,
        fromCommitId: snapshot.commitId,
        now,
      });
      await client.query(
        `INSERT INTO branches
         (id, tenant_id, volume_id, name, parent_branch_id, forked_from_snapshot_id, head_commit_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`,
        [
          branchId,
          input.tenantId,
          input.volumeId,
          input.branchName,
          sourceBranch.id,
          snapshot.id,
          branchPointCommitId,
          now,
        ]
      );
      const branch = requireRow(await this.getBranchById(client, branchId), "Branch");
      const head = requireRow(await this.getCommitInTx(client, branchPointCommitId), "Commit");
      return { branch, head };
    });
  }

  async listBranches(input: ListBranchesInput): Promise<VolumeBranch[]> {
    const result = await this.pool.query(
      `SELECT * FROM branches
       WHERE tenant_id = $1 AND volume_id = $2
       ORDER BY created_at ASC, name ASC`,
      [input.tenantId, input.volumeId]
    );
    return result.rows.map((row) => toBranch(row));
  }

  async listVolumes(input: ListVolumesInput): Promise<VolumeListEntry[]> {
    const limit = normalizeListLimit(input.limit);
    const volumesResult = await this.pool.query(
      `SELECT * FROM volumes
       WHERE tenant_id = $1 AND retired_at IS NULL
       ORDER BY created_at ASC, id ASC
       LIMIT $2`,
      [input.tenantId, limit]
    );
    const volumes = volumesResult.rows.map((row) => toVolume(row));
    if (volumes.length === 0) {
      return [];
    }
    const branchesResult = await this.pool.query(
      `SELECT volume_id, name, head_commit_id, created_at FROM branches
       WHERE tenant_id = $1 AND volume_id = ANY($2::text[])
       ORDER BY created_at ASC, name ASC`,
      [input.tenantId, volumes.map((volume) => volume.id)]
    );
    const branchesByVolume = new Map<string, Array<{ name: string; headCommitId: string }>>();
    for (const row of branchesResult.rows) {
      const volumeId = String(row.volume_id);
      const branches = branchesByVolume.get(volumeId) ?? [];
      branches.push({ name: String(row.name), headCommitId: String(row.head_commit_id) });
      branchesByVolume.set(volumeId, branches);
    }
    return volumes.map((volume) => ({
      volume,
      branches: branchesByVolume.get(volume.id) ?? [],
    }));
  }

  // retireVolume is the receipted retirement flip (migration 021): one atomic
  // conditional UPDATE scoped to the verified tenant. A null answer means the
  // volume is unknown, foreign, or already retired — the route serves all
  // three as the same non-enumerating 404, and a concurrent second retire
  // loses this exact race. After the flip the ownership resolvers below treat
  // the volume as absent, which fences every per-volume plane; nothing is
  // deleted (storage reclamation is deferred) and live authorities are not
  // force-detached — their leases/credentials expire on their own.
  async retireVolume(input: RetireVolumeInput): Promise<RetireVolumeResult | null> {
    const result = await this.pool.query(
      `UPDATE volumes
       SET retired_at = to_timestamp($3::double precision / 1000.0)
       WHERE id = $1 AND tenant_id = $2 AND retired_at IS NULL
       RETURNING retired_at`,
      [input.volumeId, input.tenantId, input.now ?? Date.now()]
    );
    const row = result.rows[0];
    if (!row) {
      return null;
    }
    return {
      volumeId: input.volumeId,
      retiredAtMs: new Date(row.retired_at as string | Date).getTime(),
    };
  }

  // The replay half of receipted retirement: the stored receipt for the
  // verified tenant's own retired volume, never for live/unknown/foreign ids
  // (those stay on the non-enumerating 404 path).
  async retiredVolumeReceipt(input: RetireVolumeInput): Promise<RetireVolumeResult | null> {
    const result = await this.pool.query(
      `SELECT retired_at FROM volumes
       WHERE id = $1 AND tenant_id = $2 AND retired_at IS NOT NULL`,
      [input.volumeId, input.tenantId]
    );
    const row = result.rows[0];
    if (!row) {
      return null;
    }
    return {
      volumeId: input.volumeId,
      retiredAtMs: new Date(row.retired_at as string | Date).getTime(),
    };
  }

  async listCommitHistory(input: ListCommitHistoryInput): Promise<VolumeCommitSummary[] | null> {
    return this.transaction(async (client) => {
      const volume = await this.getVolume(client, input.tenantId, input.volumeId);
      if (!volume) {
        return null;
      }
      const branch = await this.getBranchByName(
        client,
        input.tenantId,
        input.volumeId,
        input.branchName
      );
      if (!branch) {
        return null;
      }
      const limit = normalizeListLimit(input.limit);
      // Journal-served branches publish committed history as PFT2 cut
      // commits; the branch row's manifest head never advances past the
      // base. Start the walk from the newest READY user cut when one exists
      // — its parent chain passes through earlier cut commits down to the
      // authored base manifest ancestry.
      const startCommitId =
        (await this.newestReadyCutCommitInTx(client, branch.id)) ?? branch.headCommitId;
      // Walk parent links from the start; each hop is a primary-key lookup.
      const result = await client.query(
        `WITH RECURSIVE history AS (
           SELECT id, volume_id, branch_id, parent_commit_id, tree_hash, mutation_count, byte_count, created_by_attach_session_id, created_at, 0 AS depth
           FROM commits
           WHERE id = $1
           UNION ALL
           SELECT commits.id, commits.volume_id, commits.branch_id, commits.parent_commit_id, commits.tree_hash, commits.mutation_count, commits.byte_count, commits.created_by_attach_session_id, commits.created_at, history.depth + 1
           FROM commits
           JOIN history ON commits.id = history.parent_commit_id
           WHERE history.depth + 1 < $2
         )
         SELECT * FROM history ORDER BY depth ASC`,
        [startCommitId, limit]
      );
      return result.rows.map((row) => toCommitSummaryRow(row));
    });
  }

  // The newest ready user cut's published commit for one branch, or null on a
  // branch with no cut history (including databases whose lineage predates
  // the pfh schema — SAVEPOINT-guarded so the probe cannot poison the
  // enclosing transaction).
  private async newestReadyCutCommitInTx(
    client: PoolClient,
    branchId: string
  ): Promise<string | null> {
    await client.query(`SAVEPOINT portablefs_cut_history_probe`);
    try {
      const result = await client.query(
        `SELECT result_commit_id FROM pfh.history_cuts
         WHERE branch_id = $1 AND kind = 'user' AND state = 'ready'
           AND result_commit_id IS NOT NULL
         ORDER BY created_db_ms DESC, id DESC
         LIMIT 1`,
        [branchId]
      );
      await client.query(`RELEASE SAVEPOINT portablefs_cut_history_probe`);
      const row = result.rows[0] as { result_commit_id?: unknown } | undefined;
      return row?.result_commit_id ? String(row.result_commit_id) : null;
    } catch (error) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? String((error as { code?: unknown }).code)
          : "";
      // 42P01 undefined_table: pre-journal lineage.
      if (code === "42P01") {
        await client.query(`ROLLBACK TO SAVEPOINT portablefs_cut_history_probe`);
        return null;
      }
      throw error;
    }
  }

  async forkSnapshot(input: ForkSnapshotInput): Promise<CreateVolumeResult> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const snapshot = await this.getSnapshot(client, input.snapshotId);
      if (!snapshot) {
        throw new MetadataConflictError("VOLUME_SNAPSHOT_NOT_FOUND", "Snapshot not found.", 404);
      }
      const volumeId = input.volumeId ?? `vol_${randomUUID()}`;
      const branchId = `br_${randomUUID()}`;
      await client.query(
        `INSERT INTO tenants (id, created_at)
         VALUES ($1, $2)
         ON CONFLICT (id) DO NOTHING`,
        [input.tenantId, now]
      );
      await this.insertVolumeRow(client, volumeId, input.tenantId, now);
      const branchPointCommitId = await this.createBranchPointCommitInTx(client, {
        tenantId: input.tenantId,
        volumeId,
        branchId,
        fromCommitId: snapshot.commitId,
        now,
      });
      await client.query(
        `INSERT INTO branches
         (id, tenant_id, volume_id, name, head_commit_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $6)`,
        [branchId, input.tenantId, volumeId, input.branchName, branchPointCommitId, now]
      );
      await client.query(`UPDATE volumes SET default_branch_id = $1 WHERE tenant_id = $2 AND id = $3`, [
        branchId,
        input.tenantId,
        volumeId,
      ]);
      const volume = requireRow(await this.getVolume(client, input.tenantId, volumeId), "Volume");
      const branch = requireRow(await this.getBranchById(client, branchId), "Branch");
      const head = requireRow(await this.getCommitInTx(client, branchPointCommitId), "Commit");
      // The fork shares the snapshot's blobs; record refs so the (possibly new)
      // tenant is authorized to read them.
      await this.recordBlobRefsInTx(client, input.tenantId, volumeId, head.manifest);
      return { volume, branch, head };
    });
  }

  async recordBlobs(blobs: Array<{ digest: string; size: number; storageKey?: string }>): Promise<void> {
    if (blobs.length === 0) {
      return;
    }
    const client = await this.pool.connect();
    try {
      const now = Date.now();
      for (const blob of blobs) {
        await client.query(
          `INSERT INTO blobs (digest, size, storage_key, created_at, last_verified_at)
           VALUES ($1, $2, $3, $4, $4)
           ON CONFLICT (digest) DO UPDATE
           SET size = EXCLUDED.size,
               storage_key = COALESCE(EXCLUDED.storage_key, blobs.storage_key),
               last_verified_at = EXCLUDED.last_verified_at`,
          [blob.digest, blob.size, blob.storageKey ?? null, now]
        );
      }
    } finally {
      client.release();
    }
  }

  async hasBlobs(digests: string[]): Promise<Set<string>> {
    const unique = [...new Set(digests)];
    if (unique.length === 0) {
      return new Set();
    }
    const result = await this.pool.query(`SELECT digest FROM blobs WHERE digest = ANY($1::text[])`, [
      unique,
    ]);
    return new Set(result.rows.map((row: Record<string, unknown>) => String(row.digest)));
  }

  async listCommits(): Promise<VolumeCommit[]> {
    return this.transaction(async (client) => {
      // Legacy-manifest listing: PFT2 history commits carry no JSON manifest
      // (their content integrity is the history worker's domain, verified
      // through the PFT2 object surface), so hydrating them here would throw
      // VOLUME_COMMIT_PFT2_NO_MANIFEST and abort consumers like the blob
      // integrity check.
      const result = await client.query(
        `SELECT * FROM commits WHERE commit_kind IS DISTINCT FROM 'pft2' ORDER BY created_at ASC, id ASC`
      );
      const commits: VolumeCommit[] = [];
      for (const row of result.rows) {
        commits.push(await this.commitFromRowInTx(client, row));
      }
      return commits;
    });
  }

  async listBlobRecords(): Promise<Array<{ digest: string; size: number; storageKey?: string }>> {
    const result = await this.pool.query(`SELECT digest, size, storage_key FROM blobs ORDER BY digest ASC`);
    return result.rows.map((row: Record<string, unknown>) => {
      const record: { digest: string; size: number; storageKey?: string } = {
        digest: String(row.digest),
        size: Number(row.size),
      };
      if (row.storage_key) {
        record.storageKey = String(row.storage_key);
      }
      return record;
    });
  }

  async deleteBlobRecord(digest: string): Promise<void> {
    await this.pool.query(`DELETE FROM blobs WHERE digest = $1`, [digest]);
  }

  // referencedDigests is the GC mark phase: every blob + chunk digest referenced
  // by ANY commit across ALL volumes (blobs are globally deduplicated, so the live
  // set is global). Diff-backed commits are materialized so their digests count.
  async referencedDigests(): Promise<Set<string>> {
    return this.transaction(async (client) => {
      // PFT2 rows reference pfh history objects (swept by the history
      // worker's fenced GC), never public blobs — and they have no manifest
      // to hydrate. Only manifest-bearing commits participate in this mark.
      const result = await client.query(
        `SELECT * FROM commits WHERE commit_kind IS DISTINCT FROM 'pft2' ORDER BY created_at ASC, id ASC`
      );
      const digests = new Set<string>();
      for (const row of result.rows) {
        const commit = await this.commitFromRowInTx(client, row);
        for (const digest of this.collectManifestDigests(commit.manifest)) {
          digests.add(digest);
        }
      }
      return digests;
    });
  }

  // listBlobsCreatedBefore returns blobs recorded before cutoffMs — GC only sweeps
  // these, so freshly uploaded (not-yet-committed) blobs are never touched.
  async listBlobsCreatedBefore(
    cutoffMs: number
  ): Promise<Array<{ digest: string; size: number; storageKey?: string; createdAt: number }>> {
    const result = await this.pool.query(
      `SELECT digest, size, storage_key, created_at FROM blobs WHERE created_at < $1 ORDER BY digest ASC`,
      [cutoffMs]
    );
    return result.rows.map((row: Record<string, unknown>) => {
      const record: { digest: string; size: number; storageKey?: string; createdAt: number } = {
        digest: String(row.digest),
        size: Number(row.size),
        createdAt: Number(row.created_at),
      };
      if (row.storage_key) {
        record.storageKey = String(row.storage_key);
      }
      return record;
    });
  }

  // --- Multi-tenant isolation ---

  async createTenant(tenantId: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO tenants (id, created_at) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`,
      [tenantId, Date.now()]
    );
  }

  async createTenantToken(input: { tenantId: string; tokenHash: string; label?: string }): Promise<void> {
    await this.createTenant(input.tenantId);
    await this.pool.query(
      `INSERT INTO tenant_tokens (token_hash, tenant_id, label, created_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (token_hash) DO NOTHING`,
      [input.tokenHash, input.tenantId, input.label ?? null, Date.now()]
    );
  }

  async resolveTenantToken(tokenHash: string): Promise<{ tenantId: string } | null> {
    const result = await this.pool.query(
      `SELECT tenant_id FROM tenant_tokens WHERE token_hash = $1`,
      [tokenHash]
    );
    const row = result.rows[0];
    return row ? { tenantId: String(row.tenant_id) } : null;
  }

  async resolveRuntimeReadCredential(credentialHash: string): Promise<{
    tenantId: string;
    volumeId: string;
    branchName: string;
    readOnly: true;
  } | null> {
    // Fail-closed inside the database: unknown, revoked, and expired
    // credentials all resolve to SQL NULL.
    const result = await this.pool.query(`SELECT public.runtime_credential_resolve($1) AS r`, [
      credentialHash,
    ]);
    const raw: unknown = result.rows[0]?.r;
    if (raw === null || raw === undefined) {
      return null;
    }
    const row = raw as { tenantId?: unknown; volumeId?: unknown; branchName?: unknown };
    if (
      typeof row.tenantId !== "string" ||
      typeof row.volumeId !== "string" ||
      typeof row.branchName !== "string"
    ) {
      return null;
    }
    return {
      tenantId: row.tenantId,
      volumeId: row.volumeId,
      branchName: row.branchName,
      readOnly: true,
    };
  }

  // Every ownership resolver treats a RETIRED volume as absent (retired_at IS
  // NULL predicates below): guardTenantAccess answers the same non-enumerating
  // 404 for a retired volume's routes — and for its sessions, leases,
  // snapshots, and commits — that it answers for a foreign or unknown id.
  // This is the single fencing point volume retirement relies on.
  async tenantOwnsVolume(input: {
    tenantId: string;
    volumeId: string;
    includeRetired?: boolean;
  }): Promise<boolean> {
    const result = await this.pool.query(
      `SELECT 1 FROM volumes
       WHERE tenant_id = $1 AND id = $2
         AND ($3::boolean OR retired_at IS NULL)
       LIMIT 1`,
      [input.tenantId, input.volumeId, input.includeRetired === true]
    );
    return (result.rowCount ?? 0) > 0;
  }

  async sessionTenant(sessionId: string): Promise<string | null> {
    return this.scalarTenant(
      `SELECT v.tenant_id FROM attach_sessions s
       JOIN volumes v
         ON v.tenant_id = s.tenant_id AND v.id = s.volume_id
        AND v.retired_at IS NULL
       WHERE s.id = $1`,
      sessionId
    );
  }

  async leaseTenant(leaseId: string): Promise<string | null> {
    return this.scalarTenant(
      `SELECT v.tenant_id FROM leases l
       JOIN volumes v
         ON v.tenant_id = l.tenant_id AND v.id = l.volume_id
        AND v.retired_at IS NULL
       WHERE l.id = $1`,
      leaseId
    );
  }

  async sessionVolume(sessionId: string): Promise<string | null> {
    const result = await this.pool.query(`SELECT volume_id FROM attach_sessions WHERE id = $1`, [
      sessionId,
    ]);
    const row = result.rows[0];
    return row ? String(row.volume_id) : null;
  }

  async leaseVolume(leaseId: string): Promise<string | null> {
    const result = await this.pool.query(`SELECT volume_id FROM leases WHERE id = $1`, [leaseId]);
    const row = result.rows[0];
    return row ? String(row.volume_id) : null;
  }

  async snapshotTenant(snapshotId: string): Promise<string | null> {
    const pinned = await this.scalarTenant(
      `SELECT v.tenant_id FROM snapshots s
       JOIN volumes v
         ON v.tenant_id = s.tenant_id AND v.id = s.volume_id
        AND v.retired_at IS NULL
       WHERE s.id = $1`,
      snapshotId
    );
    if (pinned) {
      return pinned;
    }
    // Snapshot-addressed routes also address cut-backed records (the
    // journal-era snapshot listing serves both id families). The cut arm
    // joins volumes too, so a retired volume's cuts cannot be forked or
    // branched from either.
    return this.scalarTenant(
      `SELECT c.tenant_id FROM pfh.history_cuts c
       JOIN public.volumes v
         ON v.tenant_id = c.tenant_id AND v.id = c.volume_id
        AND v.retired_at IS NULL
       WHERE c.id = $1 AND c.kind = 'user'`,
      snapshotId
    );
  }

  async commitTenant(commitId: string): Promise<string | null> {
    return this.scalarTenant(
      `SELECT v.tenant_id FROM commits c
       JOIN volumes v
         ON v.tenant_id = c.tenant_id AND v.id = c.volume_id
        AND v.retired_at IS NULL
       WHERE c.id = $1`,
      commitId
    );
  }

  async tenantReferencesBlob(tenantId: string, digest: string): Promise<boolean> {
    const result = await this.pool.query(
      `SELECT 1 FROM blob_refs WHERE tenant_id = $1 AND digest = $2 LIMIT 1`,
      [tenantId, digest]
    );
    return (result.rowCount ?? 0) > 0;
  }

  // tenantReferencesBlobs is the batched form: returns the subset of digests the
  // tenant references. Used to authorize a commit's manifest in one round-trip
  // instead of one query per file (a large manifest would otherwise be N queries).
  async tenantReferencesBlobs(tenantId: string, digests: string[]): Promise<Set<string>> {
    const unique = [...new Set(digests)].filter((d) => d);
    if (unique.length === 0) {
      return new Set();
    }
    const placeholders = unique.map((_, i) => `$${i + 2}`).join(", ");
    const result = await this.pool.query<{ digest: string }>(
      `SELECT digest FROM blob_refs WHERE tenant_id = $1 AND digest IN (${placeholders})`,
      [tenantId, ...unique]
    );
    return new Set(result.rows.map((row) => row.digest));
  }

  // filterUnreferencedBlobs answers "which of these digests must this tenant still
  // upload?" in one round-trip. It reads only blob_refs for the calling tenant —
  // the (tenant_id, digest) primary key covers the ANY() lookup, so no extra index
  // is needed. Deliberately never joined against the global blobs table: a digest
  // present globally but unreferenced by this tenant must still be reported, or
  // probing would leak other tenants' content and skip proof-of-possession.
  async filterUnreferencedBlobs(tenantId: string, digests: string[]): Promise<string[]> {
    const unique = [...new Set(digests)].filter((digest) => digest);
    if (unique.length === 0) {
      return [];
    }
    const result = await this.pool.query<{ digest: string }>(
      `SELECT digest FROM blob_refs WHERE tenant_id = $1 AND digest = ANY($2::text[])`,
      [tenantId, unique]
    );
    const referenced = new Set(result.rows.map((row) => row.digest));
    return unique.filter((digest) => !referenced.has(digest));
  }

  // addBlobRefs grants a tenant read access to blobs it has uploaded. Possession of
  // the bytes (a verified upload) is the authorization to read them later; a commit
  // may only reference digests the tenant already has a ref for (closing the
  // cross-tenant exfiltration where referencing a digest minted access to it).
  async addBlobRefs(tenantId: string, digests: string[]): Promise<void> {
    const unique = [...new Set(digests)].filter((d) => d);
    if (unique.length === 0) {
      return;
    }
    const placeholders = unique.map((_, i) => `($1, $${i + 2})`).join(", ");
    await this.pool.query(
      `INSERT INTO blob_refs (tenant_id, digest) VALUES ${placeholders} ON CONFLICT DO NOTHING`,
      [tenantId, ...unique]
    );
  }

  // --- Journal-era capabilities (migrations 009-014) ---

  async branchMode(input: VolumeStatusInput): Promise<VolumeBranchMode | null> {
    // SELECT * so schemas that predate the branch_mode column still answer:
    // absent column reads as undefined, which is the authoring/manifest mode.
    const result = await this.pool.query(
      `SELECT * FROM branches
       WHERE tenant_id = $1 AND volume_id = $2 AND name = $3`,
      [input.tenantId, input.volumeId, input.branchName]
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) {
      return null;
    }
    if (row.branch_mode === undefined || row.branch_mode === null) {
      return "legacy_manifest";
    }
    return parseStoredBranchMode(row.branch_mode);
  }

  async sessionBranchMode(attachSessionId: string): Promise<VolumeBranchMode | null> {
    const result = await this.pool.query(
      `SELECT b.* FROM branches b
       JOIN attach_sessions s ON s.branch_id = b.id
       WHERE s.id = $1`,
      [attachSessionId]
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) {
      return null;
    }
    if (row.branch_mode === undefined || row.branch_mode === null) {
      return "legacy_manifest";
    }
    return parseStoredBranchMode(row.branch_mode);
  }

  async leaseBranchMode(leaseId: string): Promise<VolumeBranchMode | null> {
    const result = await this.pool.query(
      `SELECT b.* FROM branches b
       JOIN leases l ON l.branch_id = b.id
       WHERE l.id = $1`,
      [leaseId]
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) {
      return null;
    }
    if (row.branch_mode === undefined || row.branch_mode === null) {
      return "legacy_manifest";
    }
    return parseStoredBranchMode(row.branch_mode);
  }

  private commitKindColumnKnown: boolean | undefined;

  async commitKind(commitId: string): Promise<VolumeCommitKind | null> {
    if (this.commitKindColumnKnown === undefined) {
      const probe = await this.pool.query(
        `SELECT 1 FROM information_schema.columns
         WHERE table_name = 'commits' AND column_name = 'commit_kind'`
      );
      this.commitKindColumnKnown = (probe.rowCount ?? 0) > 0;
    }
    if (!this.commitKindColumnKnown) {
      const exists = await this.pool.query(`SELECT 1 FROM commits WHERE id = $1`, [commitId]);
      return (exists.rowCount ?? 0) > 0 ? "manifest_v1" : null;
    }
    const result = await this.pool.query(`SELECT commit_kind FROM commits WHERE id = $1`, [
      commitId,
    ]);
    const row = result.rows[0] as { commit_kind?: unknown } | undefined;
    if (!row) {
      return null;
    }
    if (row.commit_kind === "manifest_v1") {
      return "manifest_v1";
    }
    if (row.commit_kind === "pft2") {
      return "pft2";
    }
    // Once the column exists, 013 guarantees NOT NULL plus the two-value
    // CHECK. NULL/undefined/unknown means schema or row corruption and must
    // never be reinterpreted as the legacy family.
    throw new Error("Invalid commit_kind value in commits row.");
  }

  async getCommitSummary(commitId: string): Promise<VolumeCommitSummary | null> {
    const result = await this.pool.query(
      `SELECT id, volume_id, branch_id, parent_commit_id, tree_hash, mutation_count, byte_count, created_by_attach_session_id, created_at
       FROM commits
       WHERE id = $1`,
      [commitId]
    );
    return result.rows[0] ? toCommitSummaryRow(result.rows[0]) : null;
  }

  // The redacted live-generation binding of one branch. Reads the pfj table
  // through the admin DSN's journal-owner membership — the same read posture
  // the attach base resolution uses; capability material never leaves the
  // row (it is not selected).
  async journalBinding(input: VolumeStatusInput): Promise<BranchJournalBinding | null> {
    const result = await this.pool.query(
      `SELECT g.id, g.branch_id, g.epoch, g.record_codec, g.control_codec,
              g.base_commit_id, g.base_seq, g.base_digest, g.next_seq,
              g.tip_digest, g.status
       FROM pfj.journal_generations g
       JOIN branches b ON b.id = g.branch_id
       WHERE b.tenant_id = $1 AND b.volume_id = $2 AND b.name = $3
         AND g.status IN ('active', 'suspended', 'retiring')
       ORDER BY g.epoch DESC
       LIMIT 1`,
      [input.tenantId, input.volumeId, input.branchName]
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) {
      return null;
    }
    if (row.record_codec !== "pfj3" || row.control_codec !== "pfc2") {
      // Unreachable behind the startup gate (countPreJournalV3Generations);
      // fail closed rather than serve a retired-codec binding.
      throw new MetadataConflictError(
        "JOURNAL_CODEC_RETIRED",
        "This branch's journal generation uses the retired pfr1/pfc1 codec pair.",
        500
      );
    }
    return {
      generationId: String(row.id),
      branchId: String(row.branch_id),
      epoch: String(row.epoch),
      recordCodec: "pfj3",
      controlCodec: "pfc2",
      baseCommitId: String(row.base_commit_id),
      baseSeq: String(row.base_seq),
      baseDigest: String(row.base_digest),
      nextSeq: String(row.next_seq),
      tipDigest: String(row.tip_digest),
      status: row.status === "suspended" ? "suspended" : row.status === "retiring" ? "retiring" : "active",
    };
  }

  // Startup data gate for the retired pfr1/pfc1 journal codec era: counts
  // generation rows predating the pfj3/pfc2 pair (migration 012). One cheap
  // query — the generations table holds a handful of rows per active branch.
  async countPreJournalV3Generations(): Promise<number> {
    const result = await this.pool.query(
      `SELECT count(*)::int AS legacy
       FROM pfj.journal_generations
       WHERE record_codec <> 'pfj3' OR control_codec <> 'pfc2'`
    );
    return Number((result.rows[0] as { legacy?: number } | undefined)?.legacy ?? 0);
  }

  async snapshotCut(input: SnapshotCutInput): Promise<SnapshotCutRecord> {
    const binding = await this.journalBinding({
      tenantId: input.tenantId,
      volumeId: input.volumeId,
      branchName: input.branchName,
    });
    if (!binding) {
      // Base-authoring (manifest-headed) branch: the pinned manifest commit
      // already IS the exact immutable revision — the record is born ready.
      // A journal-owned branch without a live generation has no capturable
      // head and the snapshot() mode assertion below refuses it typed.
      const snapshot = await this.snapshot(input);
      return {
        id: snapshot.id,
        volumeId: snapshot.volumeId,
        branchId: snapshot.branchId,
        commitId: snapshot.commitId,
        ...(snapshot.name ? { name: snapshot.name } : {}),
        createdAt: snapshot.createdAt,
        state: "ready",
      };
    }
    // Journal-served branch: record an exact HistoryCut. The database
    // captures (generation, cutSeqExclusive, cutDigest) under the append
    // lock order; the resident history worker materializes it out of
    // process. Concurrent identical captures converge on one cut row via
    // the dedup key; an explicit operationId makes retries exact-once.
    const operationId = input.operationId ?? `snapcut_${randomUUID()}`;
    const raw = (await this.history.createCut({
      tenantId: input.tenantId,
      volumeId: input.volumeId,
      branchName: input.branchName,
      kind: "user",
      operationId,
      requestCanonicalJson: JSON.stringify({
        version: "portablefs-snapshot-cut-v1",
        tenantId: input.tenantId,
        volumeId: input.volumeId,
        branchName: input.branchName,
        name: input.name ?? null,
      }),
      materializerVersion: historyMaterializerVersion,
      // Persisted on the cut row (migration 019) so status and listing reads
      // answer the name; the canonical JSON above only survives as the
      // exact-once fingerprint.
      ...(input.name !== undefined ? { userLabel: input.name } : {}),
    })) as unknown as Record<string, unknown>;
    // A replayed operation returns the permanent resource-operation
    // projection (targetIds carry the preallocated cut id), not a cut
    // status; resolve the cut it named.
    if (typeof raw.cutId === "string") {
      return cutStatusToSnapshotRecord(raw as unknown as HistoryCutStatus);
    }
    const targetIds = (raw.targetIds ?? {}) as Record<string, unknown>;
    const response = (raw.response ?? {}) as Record<string, unknown>;
    const cutId =
      typeof targetIds.cutId === "string"
        ? targetIds.cutId
        : typeof response.cutId === "string"
          ? response.cutId
          : undefined;
    if (!cutId) {
      throw new MetadataConflictError(
        "VOLUME_SNAPSHOT_CUT_INVALID",
        "Cut creation returned neither a cut projection nor a target cut id.",
        500
      );
    }
    const status = await this.history.cutStatus(input.tenantId, cutId);
    if (!status) {
      throw new MetadataConflictError(
        "VOLUME_SNAPSHOT_CUT_INVALID",
        "Replayed cut operation names a cut that no longer resolves.",
        500
      );
    }
    return cutStatusToSnapshotRecord(status);
  }

  async listSnapshotRecords(input: ListSnapshotsInput): Promise<SnapshotCutRecord[]> {
    const snapshots = await this.listSnapshots(input);
    const records: SnapshotCutRecord[] = snapshots.map((snapshot) => ({
      id: snapshot.id,
      volumeId: snapshot.volumeId,
      branchId: snapshot.branchId,
      commitId: snapshot.commitId,
      ...(snapshot.name ? { name: snapshot.name } : {}),
      createdAt: snapshot.createdAt,
      state: "ready" as const,
    }));
    // Snapshot-surfaced cuts of this volume (owner-membership read): user
    // requests plus any labeled cut — kind-agnostic dedup (migration 029)
    // can land a named snapshot on a recovery-kind row at the same
    // boundary. Unlabeled recovery/conversion machinery stays invisible.
    const cuts = await this.pool.query(
      `SELECT c.* FROM pfh.history_cuts c
       LEFT JOIN branches b ON b.id = c.branch_id
       WHERE c.tenant_id = $1 AND c.volume_id = $2
         AND (c.kind = 'user' OR c.user_label IS NOT NULL)
         AND ($3::text IS NULL OR b.name = $3)
       ORDER BY c.created_db_ms ASC, c.id ASC`,
      [input.tenantId, input.volumeId, input.branchName ?? null]
    );
    for (const row of cuts.rows as Array<Record<string, unknown>>) {
      records.push(cutRowToSnapshotRecord(row));
    }
    records.sort((left, right) =>
      left.createdAt === right.createdAt
        ? left.id < right.id
          ? -1
          : 1
        : left.createdAt - right.createdAt
    );
    return records;
  }

  /**
   * Journal activation: converge one base-authored (legacy_manifest) branch
   * into managed_journal service through the 013 conversion plane. Poll-
   * driven and idempotent — each call advances at most one step (begin →
   * final cut → finalize) and answers the current status; the resident
   * history worker materializes the conversion cut between calls. A branch
   * already in managed_journal answers "active" immediately.
   */
  async activateJournalBranch(input: {
    tenantId: string;
    volumeId: string;
    branchName: string;
  }): Promise<JournalActivationStatus> {
    const mode = await this.branchMode({
      tenantId: input.tenantId,
      volumeId: input.volumeId,
      branchName: input.branchName,
    });
    if (mode === null) {
      throw new MetadataConflictError("VOLUME_BRANCH_NOT_FOUND", "Volume branch not found.", 404);
    }
    if (mode === "managed_journal") {
      return { state: "active", branchMode: mode };
    }
    if (mode === "retiring" || mode === "retired") {
      throw new MetadataConflictError(
        "VOLUME_BRANCH_MODE_CONFLICT",
        `A ${mode} branch cannot enter journal service.`,
        409
      );
    }

    // Begin (or resolve the existing) conversion. The operation id is stable
    // per branch so lost responses replay; the database dedups on the branch
    // row anyway.
    const beginCanonicalJson = JSON.stringify({
      version: "portablefs-journal-activation-v1",
      tenantId: input.tenantId,
      volumeId: input.volumeId,
      branchName: input.branchName,
    });
    let conversion = await this.conversionFromRaw(
      input.tenantId,
      await this.wrapActivationCall(() =>
        this.history.conversionBegin({
          tenantId: input.tenantId,
          volumeId: input.volumeId,
          branchName: input.branchName,
          operationId: `pfsact-begin-${input.volumeId}-${input.branchName}`,
          requestCanonicalJson: beginCanonicalJson,
        })
      )
    );

    // A failed conversion re-queues automatically: activation is the one
    // caller-facing surface, so "retry it explicitly" happens here (bounded
    // per call; the attempt count is the database's).
    if (conversion.state === "failed") {
      conversion = await this.conversionFromRaw(
        input.tenantId,
        await this.wrapActivationCall(() =>
          this.history.conversionRetry({
            tenantId: input.tenantId,
            conversionId: conversion.conversionId,
            operationId: `pfsact-retry-${conversion.conversionId}-${conversion.attempt}`,
            requestCanonicalJson: beginCanonicalJson,
          })
        )
      );
    }

    // Ensure the conversion_final cut exists and is pinned. The operation id
    // is ATTEMPT-scoped: a retried conversion must mint a fresh cut, never
    // replay the dead-lettered one through the permanent operation receipt.
    if (conversion.state === "migrating" && !conversion.finalCutId) {
      const rawCut = (await this.wrapActivationCall(() =>
        this.history.createCut({
          tenantId: input.tenantId,
          volumeId: input.volumeId,
          branchName: input.branchName,
          kind: "conversion_final",
          operationId: `pfsact-cut-${conversion.conversionId}-${conversion.attempt}`,
          requestCanonicalJson: JSON.stringify({
            version: "portablefs-journal-activation-cut-v1",
            conversionId: conversion.conversionId,
            attempt: conversion.attempt,
          }),
          materializerVersion: historyMaterializerVersion,
          targetIds: { conversionId: conversion.conversionId },
        })
      )) as unknown as Record<string, unknown>;
      const cutId = extractIdFromOperationShape(rawCut, "cutId");
      if (!cutId) {
        throw new MetadataConflictError(
          "VOLUME_ACTIVATION_INVALID",
          "Conversion cut creation returned neither a cut projection nor a target cut id.",
          500
        );
      }
      conversion = await this.wrapActivationCall(() =>
        this.history.conversionAttachFinalCut({
          tenantId: input.tenantId,
          conversionId: conversion.conversionId,
          cutId,
        })
      );
    }

    // Finalize when the pinned cut is ready; otherwise report progress.
    let cutStatus: HistoryCutStatus | null = null;
    if (conversion.finalCutId) {
      cutStatus = await this.history.cutStatus(input.tenantId, conversion.finalCutId);
    }
    // A dead-lettered or canceled pinned cut settles only the CUT; the
    // conversion row stays 'final_cut' and would pin the failure forever.
    // Abort it into the retryable failed state — the next activation call
    // re-queues a fresh attempt through conversion_retry.
    if (
      conversion.state === "final_cut" &&
      (cutStatus?.state === "failed" || cutStatus?.state === "canceled")
    ) {
      conversion = await this.wrapActivationCall(() =>
        this.history.conversionAbort({
          tenantId: input.tenantId,
          conversionId: conversion.conversionId,
          operationId: `pfsact-abort-${conversion.conversionId}-${conversion.attempt}`,
          requestCanonicalJson: beginCanonicalJson,
          reason: {
            kind: "final-cut-failed",
            cutId: cutStatus.cutId,
            ...(cutStatus.lastError !== undefined ? { cutError: cutStatus.lastError } : {}),
          },
        })
      );
    }
    if (
      (conversion.state === "final_cut" || conversion.state === "finalizing") &&
      cutStatus?.state === "ready"
    ) {
      conversion = await this.wrapActivationCall(() =>
        this.history.conversionFinalize({
          tenantId: input.tenantId,
          conversionId: conversion.conversionId,
          operationId: `pfsact-fin-${conversion.conversionId}`,
          requestCanonicalJson: beginCanonicalJson,
        })
      );
    }

    const finalMode = await this.branchMode({
      tenantId: input.tenantId,
      volumeId: input.volumeId,
      branchName: input.branchName,
    });
    if (conversion.state === "converted" || finalMode === "managed_journal") {
      return {
        state: "active",
        branchMode: finalMode ?? "managed_journal",
        conversion: projectConversion(conversion),
      };
    }
    if (conversion.state === "failed" || cutStatus?.state === "failed") {
      return {
        state: "failed",
        branchMode: finalMode ?? mode,
        conversion: projectConversion(conversion),
        ...(cutStatus ? { cut: projectActivationCut(cutStatus) } : {}),
      };
    }
    return {
      state: "converting",
      branchMode: finalMode ?? mode,
      conversion: projectConversion(conversion),
      ...(cutStatus ? { cut: projectActivationCut(cutStatus) } : {}),
    };
  }

  // conversionFromRaw normalizes conversion_begin/retry answers: a replayed
  // resource operation returns the permanent operation projection (the
  // conversion id lives in its response), not a conversion status.
  private async conversionFromRaw(
    tenantId: string,
    raw: ConversionStatus | Record<string, unknown>
  ): Promise<ConversionStatus> {
    const candidate = raw as Record<string, unknown>;
    if (typeof candidate.conversionId === "string" && typeof candidate.branchId === "string") {
      return raw as ConversionStatus;
    }
    const conversionId = extractIdFromOperationShape(candidate, "conversionId");
    if (!conversionId) {
      throw new MetadataConflictError(
        "VOLUME_ACTIVATION_INVALID",
        "Conversion begin returned neither a conversion projection nor a conversion id.",
        500
      );
    }
    const status = await this.history.conversionStatus(tenantId, conversionId);
    if (!status) {
      throw new MetadataConflictError(
        "VOLUME_ACTIVATION_INVALID",
        "Replayed conversion operation names a conversion that no longer resolves.",
        500
      );
    }
    return status;
  }

  // wrapActivationCall maps the typed PF-class database refusals of the
  // conversion plane to caller-visible conflicts (409) instead of opaque
  // internal errors; everything else rethrows unchanged.
  private async wrapActivationCall<T>(call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (typeof code === "string" && code.startsWith("PF")) {
        throw new MetadataConflictError(
          "VOLUME_ACTIVATION_CONFLICT",
          error instanceof Error ? error.message : "Journal activation was refused.",
          409
        );
      }
      throw error;
    }
  }

  async resolveSnapshotSource(snapshotOrCutId: string): Promise<SnapshotSource | null> {
    const snapshot = await this.transaction((client) => this.getSnapshot(client, snapshotOrCutId));
    if (snapshot) {
      return { kind: "snapshot", snapshot };
    }
    // Kind-agnostic dedup (029) can answer a snapshot request with a
    // recovery-kind row at the same boundary; any cut id resolves —
    // consumability is decided by state, not by the requesting label.
    const result = await this.pool.query(
      `SELECT * FROM pfh.history_cuts WHERE id = $1`,
      [snapshotOrCutId]
    );
    const row = result.rows[0] as Record<string, unknown> | undefined;
    if (!row) {
      return null;
    }
    return { kind: "cut", record: cutRowToSnapshotRecord(row) };
  }

  async createBranchFromCut(input: CreateBranchFromCutInput): Promise<CreateBranchFromCutResult> {
    return this.transaction(async (client) => {
      const now = input.now ?? Date.now();
      const cutResult = await client.query(
        `SELECT * FROM pfh.history_cuts WHERE id = $1 AND tenant_id = $2 FOR SHARE`,
        [input.cutId, input.tenantId]
      );
      const cut = cutResult.rows[0] as Record<string, unknown> | undefined;
      if (!cut || String(cut.volume_id) !== input.volumeId) {
        throw new MetadataConflictError("VOLUME_SNAPSHOT_NOT_FOUND", "Snapshot not found.", 404);
      }
      if (cut.state !== "ready" || !cut.result_commit_id) {
        throw new MetadataConflictError(
          "HISTORY_CUT_NOT_READY",
          "Only a ready history cut can be branched.",
          409
        );
      }
      const resultCommitId = String(cut.result_commit_id);
      const branchId = `br_${randomUUID()}`;
      // Durable branch-from-cut provenance, in the SAME transaction as the
      // branch row: the cut consumer is what pfh.serving_base_prove later
      // accepts as the positive fork-base proof, and the issued namespace is
      // the branch's never-reused inode allocator.
      await client.query(`SELECT pfh.consumer_attach($1,$2,'branch',$3)`, [
        input.tenantId,
        input.cutId,
        branchId,
      ]);
      await client.query(`SELECT pfh.inode_namespace_issue($1,$2,$3,'branch')`, [
        input.tenantId,
        input.volumeId,
        branchId,
      ]);
      // Born managed: the branch head is the cut's immutable PFT2 result
      // commit and only journal-owner paths may ever move it. The first
      // journal claim starts the fresh generation from exactly this base.
      await client.query(
        `INSERT INTO branches
         (id, tenant_id, volume_id, name, parent_branch_id, head_commit_id, branch_mode, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'managed_journal', $7, $7)`,
        [
          branchId,
          input.tenantId,
          input.volumeId,
          input.branchName,
          String(cut.branch_id),
          resultCommitId,
          now,
        ]
      );
      const branch = requireRow(await this.getBranchById(client, branchId), "Branch");
      const headRow = await client.query(`SELECT * FROM commits WHERE id = $1`, [resultCommitId]);
      const head = requireRow(
        headRow.rows[0] ? toCommitSummaryRow(headRow.rows[0]) : null,
        "Commit"
      );
      return { branch, head, commitKind: "pft2" as const };
    });
  }

  /**
   * Cross-volume fork of a READY PFT2 cut into a NEW volume (migration
   * 018). The database performs the whole fork in ONE atomic SECURITY
   * DEFINER transaction — destination volume + fork-point pft2 commit +
   * managed_journal branch + fresh inode namespace + ACTIVE 'fork' cut
   * consumer (the durable GC root of the shared, never-copied history
   * objects) + the immutable provenance row — keyed exact-once by
   * (tenant, operationId) in the permanent resource-operation ledger. The
   * canonical request JSON deliberately excludes the server-minted
   * destination id, so a retry with the same operationId replays the
   * recorded destination instead of conflicting on a fresh mint.
   */
  async forkVolumeFromCut(input: ForkVolumeFromCutInput): Promise<ForkVolumeFromCutResult> {
    const operationId = input.operationId ?? `volfork_${randomUUID()}`;
    let raw: VolumeForkFromCutResult;
    try {
      raw = await this.history.forkVolumeFromCut({
        tenantId: input.tenantId,
        cutId: input.cutId,
        branchName: input.branchName,
        ...(input.volumeId ? { volumeId: input.volumeId } : {}),
        operationId,
        requestCanonicalJson: JSON.stringify({
          version: "portablefs-volume-fork-v1",
          tenantId: input.tenantId,
          cutId: input.cutId,
          branchName: input.branchName,
          volumeId: input.volumeId ?? null,
        }),
      });
    } catch (error) {
      // The database refusals are typed PF-class proofs (not-ready cut,
      // foreign tenant, destination collision, replay mismatch); surface
      // them as caller-visible conflicts instead of opaque 500s.
      const code = (error as { code?: string }).code;
      if (typeof code === "string" && code.startsWith("PF")) {
        throw new MetadataConflictError(
          "HISTORY_FORK_REJECTED",
          error instanceof Error ? error.message : "The cross-volume fork was refused.",
          code === "PF008" ? 400 : 409
        );
      }
      throw error;
    }
    return this.transaction(async (client) => {
      const volume = requireRow(
        await this.getVolume(client, input.tenantId, raw.volumeId),
        "Volume"
      );
      const branch = requireRow(await this.getBranchById(client, raw.branchId), "Branch");
      const head = requireRow(await this.getCommitSummaryInTx(client, raw.commitId), "Commit");
      return {
        volume,
        branch,
        head,
        commitKind: "pft2" as const,
        operationId: raw.operationId,
        replayed: raw.replayed,
      };
    });
  }

  private async scalarTenant(sql: string, id: string): Promise<string | null> {
    const result = await this.pool.query(sql, [id]);
    const row = result.rows[0];
    return row ? String(row.tenant_id) : null;
  }

  // collectManifestDigests returns every stored blob/chunk digest a manifest
  // references (chunked files reference their chunk digests; others the whole-file
  // blob) — the unit of both GC liveness and per-tenant blob references.
  private collectManifestDigests(manifest: TreeManifest): string[] {
    const out: string[] = [];
    for (const entry of manifest.entries) {
      if (entry.kind !== "file") {
        continue;
      }
      if (entry.chunks?.length) {
        for (const chunk of entry.chunks) {
          out.push(chunk.digest);
        }
      } else if (entry.blob) {
        out.push(entry.blob.digest);
      }
    }
    return out;
  }

  // recordBlobRefsInTx records (tenant, digest) for every digest a just-committed
  // manifest references, so the tenant is authorized to read those blobs.
  private async recordBlobRefsInTx(
    client: PoolClient,
    tenantId: string,
    volumeId: string,
    manifest: TreeManifest
  ): Promise<void> {
    const volume = await client.query(
      `SELECT 1 FROM volumes WHERE tenant_id = $1 AND id = $2`,
      [tenantId, volumeId]
    );
    if (volume.rowCount === 0) {
      return;
    }
    const digests = [...new Set(this.collectManifestDigests(manifest))];
    if (digests.length === 0) {
      return;
    }
    const placeholders = digests.map((_, i) => `($1, $${i + 2})`).join(", ");
    await client.query(
      `INSERT INTO blob_refs (tenant_id, digest) VALUES ${placeholders} ON CONFLICT DO NOTHING`,
      [tenantId, ...digests]
    );
  }

  private async notifyBranchHeadInTx(
    client: PoolClient,
    branch: DbBranch,
    headCommitId: string
  ): Promise<void> {
    await client.query(`SELECT pg_notify($1, $2)`, [
      headNotifyChannel,
      JSON.stringify({
        tenantId: branch.tenantId,
        volumeId: branch.volumeId,
        branchName: branch.name,
        headCommitId,
      }),
    ]);
  }

  private async assertWritableLease(
    client: PoolClient,
    input: {
      leaseId: string;
      attachSessionId: string;
      fencingToken: number;
      now: number;
    }
  ): Promise<VolumeLease> {
    const lease = await this.getLeaseForUpdate(client, input.leaseId);
    if (
      !lease ||
      lease.attachSessionId !== input.attachSessionId ||
      lease.fencingToken !== input.fencingToken ||
      lease.releasedAt ||
      lease.expiresAt <= input.now
    ) {
      throw new MetadataConflictError("VOLUME_LEASE_STALE", "Volume write lease is stale.", 409);
    }
    return lease;
  }

  private async assertDelegationsCoverMutation(
    client: PoolClient,
    input: {
      branchId: string;
      attachSessionId: string;
      mutationPaths: Array<{ path: string; recursive: boolean }>;
      now: number;
    }
  ): Promise<void> {
    if (input.mutationPaths.length === 0) {
      return;
    }
    const result = await client.query(
      `SELECT * FROM path_delegations
       WHERE branch_id = $1
         AND attach_session_id = $2
         AND released_at IS NULL
         AND revoked_at IS NULL
         AND expires_at > $3`,
      [input.branchId, input.attachSessionId, input.now]
    );
    const active = result.rows.map((row) => toDelegation(row));
    const uncovered = input.mutationPaths.find((mutation) => {
      const pathValue = normalizeVolumePath(mutation.path);
      return !active.some((delegation) => {
        if (mutation.recursive && !delegation.recursive) {
          return false;
        }
        if (delegation.path === pathValue) {
          return true;
        }
        return delegation.recursive && isEqualOrDescendantPath(pathValue, delegation.path);
      });
    });
    if (uncovered) {
      throw new MetadataConflictError(
        "VOLUME_DELEGATION_REQUIRED",
        `No active checkout covers ${uncovered.path || "/"}.`,
        409
      );
    }
  }

  private async listActiveDelegationsForUpdate(
    client: PoolClient,
    branchId: string,
    now: number
  ): Promise<PathDelegation[]> {
    const result = await client.query(
      `SELECT * FROM path_delegations
       WHERE branch_id = $1
         AND released_at IS NULL
         AND revoked_at IS NULL
         AND expires_at > $2
       FOR UPDATE`,
      [branchId, now]
    );
    return result.rows.map((row) => toDelegation(row));
  }

  private async createDelegation(
    client: PoolClient,
    input: {
      tenantId: string;
      volumeId: string;
      branchId: string;
      attachSessionId: string;
      leaseId: string;
      holderId: string;
      path: string;
      recursive: boolean;
      fencingToken: number;
      expiresAt: number;
      createdAt: number;
    }
  ): Promise<PathDelegation> {
    const id = `dlg_${randomUUID()}`;
    await client.query(
      `INSERT INTO path_delegations
       (id, tenant_id, volume_id, branch_id, attach_session_id, lease_id, holder_id, path, recursive, fencing_token, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        id,
        input.tenantId,
        input.volumeId,
        input.branchId,
        input.attachSessionId,
        input.leaseId,
        input.holderId,
        normalizeVolumePath(input.path),
        input.recursive,
        input.fencingToken,
        input.expiresAt,
        input.createdAt,
      ]
    );
    const result = await client.query(`SELECT * FROM path_delegations WHERE id = $1`, [id]);
    return requireRow(result.rows[0] ? toDelegation(result.rows[0]) : null, "Path delegation");
  }

  private async countActiveLeases(client: PoolClient, branchId: string, now: number): Promise<number> {
    const result = await client.query(
      `SELECT COUNT(*)::int AS count FROM leases
       WHERE branch_id = $1 AND released_at IS NULL AND expires_at > $2`,
      [branchId, now]
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  private async countActiveDelegations(client: PoolClient, branchId: string, now: number): Promise<number> {
    const result = await client.query(
      `SELECT COUNT(*)::int AS count FROM path_delegations
       WHERE branch_id = $1 AND released_at IS NULL AND revoked_at IS NULL AND expires_at > $2`,
      [branchId, now]
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  private async findSnapshotForBranch(
    client: PoolClient,
    input: {
      tenantId: string;
      volumeId: string;
      branchId: string;
      snapshotId?: string;
      snapshotName?: string;
    }
  ): Promise<VolumeSnapshot | null> {
    if (input.snapshotId) {
      const result = await client.query(
        `SELECT * FROM snapshots
         WHERE tenant_id = $1 AND volume_id = $2 AND branch_id = $3 AND id = $4`,
        [input.tenantId, input.volumeId, input.branchId, input.snapshotId]
      );
      return result.rows[0] ? toSnapshot(result.rows[0]) : null;
    }
    if (!input.snapshotName) {
      return null;
    }
    const result = await client.query(
      `SELECT * FROM snapshots
       WHERE tenant_id = $1 AND volume_id = $2 AND branch_id = $3 AND name = $4
       ORDER BY created_at DESC
       LIMIT 1`,
      [input.tenantId, input.volumeId, input.branchId, input.snapshotName]
    );
    return result.rows[0] ? toSnapshot(result.rows[0]) : null;
  }

  // resolveAttachReceiptInTx returns the recorded outcome for an attach
  // operation id, verifying the canonical request fingerprint: the same id
  // with a DIFFERENT body is a conflict, never silently honored. Returns null
  // when no receipt exists (first execution).
  private async resolveAttachReceiptInTx(
    client: PoolClient,
    tenantId: string,
    operationId: string,
    fingerprint: string
  ): Promise<AttachVolumeResult | null> {
    const result = await client.query(
      `SELECT * FROM attach_receipts WHERE tenant_id = $1 AND operation_id = $2`,
      [tenantId, operationId]
    );
    const row = result.rows[0];
    if (!row) {
      return null;
    }
    if (String(row.request_fingerprint) !== fingerprint) {
      throw new MetadataConflictError(
        "VOLUME_ATTACH_OPERATION_CONFLICT",
        "operationId was already used for a different attach request.",
        409
      );
    }
    const outcome = parseAttachOutcomeFacts(row.outcome);
    const volume = await this.getVolume(client, tenantId, String(row.volume_id));
    const branch = await this.getBranchById(client, String(row.branch_id));
    const session = await this.getSession(client, String(row.attach_session_id));
    // Summary read only: receipts exist exclusively for journal-owned
    // branches (assertAttachBranchMode), whose base is routinely a PFT2
    // commit — hydrating a manifest here would fail the replay typed.
    const base = await this.getCommitSummaryInTx(client, String(row.base_commit_id));
    if (
      !volume ||
      volume.tenantId !== tenantId ||
      !branch ||
      branch.volumeId !== volume.id ||
      !session ||
      session.volumeId !== volume.id ||
      session.branchId !== branch.id ||
      !base ||
      base.volumeId !== volume.id ||
      outcome.branch.id !== branch.id ||
      outcome.session.id !== session.id ||
      outcome.session.baseCommitId !== base.id
    ) {
      throw new MetadataConflictError(
        "VOLUME_ATTACH_COMMITTED_GONE",
        "The receipted attach committed, but its retained result prerequisites are gone.",
        410
      );
    }
    const originalLeaseId = outcome.session.lease?.id;
    const currentLease = originalLeaseId ? await this.getLease(client, originalLeaseId) : null;
    const currentSession = currentLease ? { ...session, lease: currentLease } : session;
    const observedAt = Date.now();
    const active = await client.query<{ count: number }>(
      `SELECT COUNT(*)::int AS count
       FROM path_delegations
       WHERE attach_session_id = $1
         AND released_at IS NULL
         AND revoked_at IS NULL
         AND expires_at > $2`,
      [session.id, observedAt]
    );
    // Manifest-free like the first execution: the receipted attach only ever
    // serves journal-owned branches.
    return {
      ...outcome,
      receipt: {
        operationId,
        replayed: true,
        createdAt: Number(row.created_at),
      },
      current: {
        observedAt,
        branch,
        session: currentSession,
        activeDelegations: Number(active.rows[0]?.count ?? 0),
      },
    };
  }

  private async resolveOrClaimAttachReceiptInTx(
    client: PoolClient,
    tenantId: string,
    operationId: string,
    fingerprint: string
  ): Promise<AttachVolumeResult | null> {
    const recorded = await this.resolveAttachReceiptInTx(
      client,
      tenantId,
      operationId,
      fingerprint
    );
    if (recorded) {
      return recorded;
    }
    // PostgreSQL TEXT cannot contain NUL. Encode the lock identity as a
    // canonical JSON tuple instead of joining caller-controlled components
    // with an in-band delimiter. Hash collisions can only over-serialize two
    // claims; the permanent receipt row remains the exact correctness fence.
    const lockIdentity = JSON.stringify([attachReceiptLockPrefix, tenantId, operationId]);
    await client.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [lockIdentity]);
    return this.resolveAttachReceiptInTx(client, tenantId, operationId, fingerprint);
  }

  private async insertAttachReceiptInTx(
    client: PoolClient,
    receipt: {
      tenantId: string;
      operationId: string;
      requestFingerprint: string;
      volumeId: string;
      branchId: string;
      attachSessionId: string;
      baseCommitId: string;
      outcome: Pick<AttachVolumeResult, "session" | "branch" | "delegations">;
      createdAt: number;
    }
  ): Promise<void> {
    await client.query(
      `INSERT INTO attach_receipts
       (tenant_id, operation_id, request_fingerprint, volume_id, branch_id,
        attach_session_id, base_commit_id, outcome, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`,
      [
        receipt.tenantId,
        receipt.operationId,
        receipt.requestFingerprint,
        receipt.volumeId,
        receipt.branchId,
        receipt.attachSessionId,
        receipt.baseCommitId,
        JSON.stringify(receipt.outcome),
        receipt.createdAt,
      ]
    );
  }

  // The attach base of a journal-owned branch is its live generation's base
  // commit (replay = immutable base + journal suffix), not the branch head.
  //
  // Journal-owned branches resolve MANIFEST-FREE, whatever the base's commit
  // kind or parent chain: the receipted child binds its journal claim to
  // this commit id and proves the base content through the positive
  // base-provenance proof (pfh.serving_base_prove), never through a legacy
  // JSON manifest — so no manifest shape, however projected or borrowed,
  // would be truthful here. Legacy branches keep the full manifest commit:
  // rootPath validation and the response projection are manifest surfaces.
  private async getAttachBaseCommitInTx(
    client: PoolClient,
    branch: DbBranch
  ): Promise<{ head: VolumeCommitSummary; manifest?: TreeManifest } | null> {
    if ((branch.branchMode ?? "legacy_manifest") !== "legacy_manifest") {
      const generation = await client.query<{ base_commit_id: string }>(
        `SELECT base_commit_id
         FROM pfj.journal_generations
         WHERE branch_id = $1
           AND status IN ('active', 'suspended', 'retiring')
         ORDER BY epoch DESC
         LIMIT 1`,
        [branch.id]
      );
      const baseCommitId = generation.rows[0]?.base_commit_id ?? branch.headCommitId;
      const head = await this.getCommitSummaryInTx(client, String(baseCommitId));
      return head ? { head } : null;
    }
    const commit = await this.getCommitInTx(client, branch.headCommitId);
    return commit ? { head: commit, manifest: commit.manifest } : null;
  }

  private assertAttachBranchMode(branch: DbBranch, receipted: boolean): void {
    if (branch.branchMode === undefined) {
      // Pre-012 rows carry no provisioning decision; the column (NOT NULL
      // after 012) makes every post-migration row explicit.
      return;
    }
    const mode = branch.branchMode;
    if (receipted) {
      // The receipted (exact-once) attach serves the live authority:
      // journal-owned branches only — never retiring/retired, never a
      // fresh authoring-phase generation.
      if (mode !== "managed_journal" && mode !== "migrating") {
        throw new MetadataConflictError(
          "VOLUME_BRANCH_MODE_CONFLICT",
          `Receipted attach requires a journal-owned branch (mode is ${mode}).`,
          409
        );
      }
      return;
    }
    if (mode !== "legacy_manifest") {
      throw new MetadataConflictError(
        "VOLUME_BRANCH_MODE_CONFLICT",
        `Manifest attach is disabled on a ${mode} branch; it is served by the live authority.`,
        409
      );
    }
  }

  // Manifest commits (and stale-head snapshot pins) refuse journal-owned
  // branches typed BEFORE the database guard would reject the head move.
  private assertLegacyManifestMutation(branch: DbBranch): void {
    const mode = branch.branchMode ?? "legacy_manifest";
    if (mode !== "legacy_manifest") {
      throw new MetadataConflictError(
        "VOLUME_BRANCH_MODE_CONFLICT",
        `Manifest commits cannot mutate a ${mode} branch head.`,
        409
      );
    }
  }

  private async transaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await run(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  private async getVolume(
    client: PoolClient,
    tenantId: string,
    volumeId: string
  ): Promise<Volume | null> {
    const result = await client.query(
      `SELECT * FROM volumes WHERE tenant_id = $1 AND id = $2`,
      [tenantId, volumeId]
    );
    return result.rows[0] ? toVolume(result.rows[0]) : null;
  }

  private async getBranchByName(
    client: PoolClient,
    tenantId: string,
    volumeId: string,
    branchName: string
  ): Promise<DbBranch | null> {
    const result = await client.query(
      `SELECT * FROM branches
       WHERE tenant_id = $1 AND volume_id = $2 AND name = $3`,
      [tenantId, volumeId, branchName]
    );
    return result.rows[0] ? toBranch(result.rows[0]) : null;
  }

  private async getBranchByNameForUpdate(
    client: PoolClient,
    tenantId: string,
    volumeId: string,
    branchName: string
  ): Promise<DbBranch | null> {
    const result = await client.query(
      `SELECT * FROM branches
       WHERE tenant_id = $1 AND volume_id = $2 AND name = $3
       FOR UPDATE`,
      [tenantId, volumeId, branchName]
    );
    return result.rows[0] ? toBranch(result.rows[0]) : null;
  }

  private async getBranchById(client: PoolClient, branchId: string): Promise<DbBranch | null> {
    const result = await client.query(`SELECT * FROM branches WHERE id = $1`, [branchId]);
    return result.rows[0] ? toBranch(result.rows[0]) : null;
  }

  private async getBranchByIdForUpdate(client: PoolClient, branchId: string): Promise<DbBranch | null> {
    const result = await client.query(`SELECT * FROM branches WHERE id = $1 FOR UPDATE`, [branchId]);
    return result.rows[0] ? toBranch(result.rows[0]) : null;
  }

  /**
   * Create the starting commit for a new branch/fork. It lives ON the new branch
   * (branch_id = the new branch), with its parent set to the fork-point commit and
   * an empty manifest diff against it (so it reconstructs to the exact same tree).
   *
   * This preserves the core invariant that a branch's head_commit_id always points
   * to a commit carrying that branch's branch_id. Without it, the first write to a
   * branch/fork would commit against a base that belongs to a different branch,
   * which the commit path correctly rejects. It is O(1) metadata (no manifest copy).
   */
  private async createBranchPointCommitInTx(
    client: PoolClient,
    input: {
      tenantId: string;
      volumeId: string;
      branchId: string;
      fromCommitId: string;
      now: number;
    }
  ): Promise<string> {
    const fromRow = await client.query(`SELECT tree_hash FROM commits WHERE id = $1`, [
      input.fromCommitId,
    ]);
    if (fromRow.rowCount === 0) {
      throw new MetadataConflictError(
        "VOLUME_BASE_COMMIT_NOT_FOUND",
        "Branch source commit was not found.",
        404
      );
    }
    const treeHash = String(fromRow.rows[0]!.tree_hash);
    const branchPointCommitId = `cmt_${randomUUID()}`;
    // Keep reconstruction chains bounded exactly like the write path: if the source
    // commit is already deep in a diff chain, materialize the branch point's manifest
    // so even a long succession of (no-write) nested branches cannot grow an unbounded
    // chain. The common case stays O(1) metadata (empty diff against the fork point).
    const parentDiffDepth = await this.getManifestDiffChainDepthInTx(client, input.fromCommitId);
    if (parentDiffDepth + 1 >= maxManifestDiffChainDepth) {
      const source = requireRow(await this.getCommitInTx(client, input.fromCommitId), "Commit");
      await client.query(
        `INSERT INTO commits
         (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, manifest_base_commit_id, manifest_diff, materialized_manifest, mutation_count, byte_count, created_by_attach_session_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, TRUE, 0, 0, NULL, $8)`,
        [
          branchPointCommitId,
          input.tenantId,
          input.volumeId,
          input.branchId,
          input.fromCommitId,
          treeHash,
          JSON.stringify(source.manifest),
          input.now,
        ]
      );
      return branchPointCommitId;
    }
    const emptyDiff = { added: [], changed: [], removed: [], mutationCount: 0, byteCount: 0 };
    await client.query(
      `INSERT INTO commits
       (id, tenant_id, volume_id, branch_id, parent_commit_id, tree_hash, manifest, manifest_base_commit_id, manifest_diff, materialized_manifest, mutation_count, byte_count, created_by_attach_session_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NULL, $5, $7, FALSE, 0, 0, NULL, $8)`,
      [
        branchPointCommitId,
        input.tenantId,
        input.volumeId,
        input.branchId,
        input.fromCommitId,
        treeHash,
        JSON.stringify(emptyDiff),
        input.now,
      ]
    );
    return branchPointCommitId;
  }

  private async getCommitInTx(
    client: PoolClient,
    commitId: string,
    seen = new Set<string>()
  ): Promise<VolumeCommit | null> {
    const result = await client.query(`SELECT * FROM commits WHERE id = $1`, [commitId]);
    return result.rows[0] ? this.commitFromRowInTx(client, result.rows[0], seen) : null;
  }

  private async commitFromRowInTx(
    client: PoolClient,
    row: Record<string, unknown>,
    seen = new Set<string>()
  ): Promise<VolumeCommit> {
    if (row.manifest !== null && row.manifest !== undefined) {
      return toCommit(row);
    }
    const commitId = String(row.id);
    if (row.commit_kind === "pft2") {
      // A pft2 commit carries NO manifest of any shape: its content is the
      // content-addressed PFT2 root in pfh.pft2_commits. Legacy manifest
      // materialization is a TYPED refusal, never a fallback or a guess
      // (pre-013 rows have no commit_kind column and never reach here).
      throw new MetadataConflictError(
        "VOLUME_COMMIT_PFT2_NO_MANIFEST",
        "This commit is a PFT2 history commit; it has no legacy JSON manifest. Read it through the PFT2 object surface.",
        409
      );
    }
    const cached = this.manifestIndexCache.get(commitId);
    if (cached) {
      return toCommitWithManifest(row, cached.manifest);
    }
    if (seen.has(commitId)) {
      throw new MetadataConflictError("VOLUME_COMMIT_CYCLE", "Commit manifest diff chain is cyclic.", 500);
    }
    const baseCommitId = row.manifest_base_commit_id ? String(row.manifest_base_commit_id) : "";
    if (!baseCommitId || !row.manifest_diff) {
      throw new MetadataConflictError("VOLUME_COMMIT_MANIFEST_MISSING", "Commit manifest is missing.", 500);
    }
    seen.add(commitId);
    const base = requireRow(await this.getCommitInTx(client, baseCommitId, seen), "Base commit");
    seen.delete(commitId);
    const diff = treeManifestDiffSchema.parse(row.manifest_diff);
    const applied = applyManifestDiffIndexed(this.manifestIndexForCommit(base), diff);
    const manifest = applied.manifest;
    const summary = toCommitSummaryRow(row);
    if (manifest.treeHash !== summary.treeHash) {
      throw new MetadataConflictError("VOLUME_TREE_HASH_MISMATCH", "Stored commit diff tree hash is invalid.", 500);
    }
    this.rememberManifestIndex(commitId, applied.index);
    return toCommitWithManifest(row, manifest);
  }

  private async getManifestDiffChainDepthInTx(client: PoolClient, commitId: string): Promise<number> {
    const result = await client.query(
      `WITH RECURSIVE chain AS (
         SELECT id, manifest, manifest_base_commit_id, 0 AS depth
         FROM commits
         WHERE id = $1
         UNION ALL
         SELECT commits.id, commits.manifest, commits.manifest_base_commit_id, chain.depth + 1
         FROM commits
         JOIN chain ON commits.id = chain.manifest_base_commit_id
         WHERE chain.manifest IS NULL
           AND chain.manifest_base_commit_id IS NOT NULL
           AND chain.depth < $2
       )
       SELECT COUNT(*) FILTER (WHERE manifest IS NULL) AS diff_depth
       FROM chain`,
      [commitId, maxManifestDiffChainDepth]
    );
    return Number(result.rows[0]?.diff_depth ?? 0);
  }

  private async getCommitSummaryInTx(
    client: PoolClient,
    commitId: string
  ): Promise<VolumeCommitSummary | null> {
    const result = await client.query(
      `SELECT id, volume_id, branch_id, parent_commit_id, tree_hash, mutation_count, byte_count, created_by_attach_session_id, created_at
       FROM commits
       WHERE id = $1`,
      [commitId]
    );
    return result.rows[0] ? toCommitSummaryRow(result.rows[0]) : null;
  }

  private async getLease(client: PoolClient, leaseId: string): Promise<VolumeLease | null> {
    const result = await client.query(`SELECT * FROM leases WHERE id = $1`, [leaseId]);
    return result.rows[0] ? toLease(result.rows[0]) : null;
  }

  private async getLeaseForUpdate(client: PoolClient, leaseId: string): Promise<VolumeLease | null> {
    const result = await client.query(`SELECT * FROM leases WHERE id = $1 FOR UPDATE`, [leaseId]);
    return result.rows[0] ? toLease(result.rows[0]) : null;
  }

  private async getSession(client: PoolClient, sessionId: string): Promise<AttachSession | null> {
    const result = await client.query(`SELECT * FROM attach_sessions WHERE id = $1`, [sessionId]);
    return result.rows[0] ? toSession(result.rows[0]) : null;
  }

  private async getSessionForUpdate(
    client: PoolClient,
    sessionId: string
  ): Promise<AttachSession | null> {
    const result = await client.query(`SELECT * FROM attach_sessions WHERE id = $1 FOR UPDATE`, [
      sessionId,
    ]);
    return result.rows[0] ? toSession(result.rows[0]) : null;
  }

  private async getSnapshot(client: PoolClient, snapshotId: string): Promise<VolumeSnapshot | null> {
    const result = await client.query(`SELECT * FROM snapshots WHERE id = $1`, [snapshotId]);
    return result.rows[0] ? toSnapshot(result.rows[0]) : null;
  }
}

interface DbBranch extends VolumeBranch {
  /** Internal composite volume scope (not part of the public protocol shape). */
  tenantId: string;
  leaseCounter: number;
  // The authoritative storage mode (migration 012). Absent only on rows read
  // before the journal migrations applied; the column is NOT NULL after 012.
  branchMode?: VolumeBranchMode;
}

// Validates a stored branch_mode value against the five authoritative modes
// (anything else is corruption and fails closed, never reinterpreted).
function parseStoredBranchMode(value: unknown): VolumeBranchMode {
  const mode = String(value);
  if (
    mode === "legacy_manifest" ||
    mode === "managed_journal" ||
    mode === "migrating" ||
    mode === "retiring" ||
    mode === "retired"
  ) {
    return mode;
  }
  throw new MetadataConflictError(
    "VOLUME_BRANCH_MODE_INVALID",
    "Stored branch mode is not one of the five authoritative modes.",
    500
  );
}

async function readMigrationSql(migrationId: string): Promise<string> {
  const fileName = `${migrationId}.sql`;
  return readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "migrations", fileName),
    "utf8"
  ).catch(async () =>
    readFile(
      path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "migrations", fileName),
      "utf8"
    )
  );
}

// computeMigrationLineageDigest hashes the exact ordered migration lineage this
// build ships (ids + SQL bytes, length-delimited so values cannot smear across
// boundaries). Two artifacts that would apply different schema histories can
// never present the same digest. Served by /v1/release-identity.
export async function computeMigrationLineageDigest(): Promise<string> {
  const hash = createHash("sha256");
  for (const migrationId of migrationIds) {
    const sql = await readMigrationSql(migrationId);
    const idBytes = Buffer.from(migrationId, "utf8");
    const sqlBytes = Buffer.from(sql, "utf8");
    hash.update(`${idBytes.byteLength}:`);
    hash.update(idBytes);
    hash.update(`${sqlBytes.byteLength}:`);
    hash.update(sqlBytes);
  }
  return `sha256:${hash.digest("hex")}`;
}

function parseHeadNotification(
  payload: string | undefined
): { tenantId: string; volumeId: string; branchName: string; headCommitId: string } | null {
  if (!payload) {
    return null;
  }
  try {
    const parsed = JSON.parse(payload) as Record<string, unknown>;
    if (
      typeof parsed.tenantId === "string" &&
      typeof parsed.volumeId === "string" &&
      typeof parsed.branchName === "string" &&
      typeof parsed.headCommitId === "string"
    ) {
      return {
        tenantId: parsed.tenantId,
        volumeId: parsed.volumeId,
        branchName: parsed.branchName,
        headCommitId: parsed.headCommitId,
      };
    }
  } catch {
    return null;
  }
  return null;
}

function throwIfWaitAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new DOMException("The head wait was aborted.", "AbortError");
  }
}

// raceAbort abandons the wait on abort; the underlying promise is detached
// (its rejection swallowed) because pg cannot cancel an in-flight query.
function raceAbort<T>(work: Promise<T>, signal: AbortSignal, message: string): Promise<T> {
  if (signal.aborted) {
    work.catch(() => undefined);
    return Promise.reject(new DOMException(message, "AbortError"));
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      work.catch(() => undefined);
      reject(new DOMException(message, "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      }
    );
  });
}

function createPostgresHeadWait(
  listener: PoolClient,
  input: WaitForHeadInput,
  timeoutMs: number,
  loadLatest: () => Promise<VolumeHeadResult | null>
): {
  promise: Promise<VolumeHeadResult | null>;
  resolve: (value: VolumeHeadResult | null) => void;
  reject: (error: unknown) => void;
} {
  let settled = false;
  let timer: NodeJS.Timeout | undefined;
  let resolvePromise!: (value: VolumeHeadResult | null) => void;
  let rejectPromise!: (error: unknown) => void;

  // A disconnected client or a server drain releases the LISTEN connection
  // immediately: waiting out the timeout would pin a pool connection per
  // dead waiter.
  const onAbort = () => {
    reject(new DOMException("The head wait was aborted.", "AbortError"));
  };

  const cleanup = () => {
    if (timer) {
      clearTimeout(timer);
    }
    input.signal?.removeEventListener("abort", onAbort);
    listener.off("notification", onNotification);
    listener.off("error", onError);
    void listener
      .query(`UNLISTEN ${headNotifyChannel}`)
      .catch(() => undefined)
      .finally(() => listener.release());
  };
  const resolve = (value: VolumeHeadResult | null) => {
    if (settled) {
      return;
    }
    settled = true;
    cleanup();
    resolvePromise(value);
  };
  const reject = (error: unknown) => {
    if (settled) {
      return;
    }
    settled = true;
    cleanup();
    rejectPromise(error);
  };
  const resolveLatest = () => {
    void loadLatest().then(resolve, reject);
  };
  function onNotification(message: Notification) {
    if (message.channel !== headNotifyChannel) {
      return;
    }
    const payload = parseHeadNotification(message.payload);
    if (
      payload?.tenantId === input.tenantId &&
      payload.volumeId === input.volumeId &&
      payload.branchName === input.branchName &&
      payload.headCommitId !== input.afterCommitId
    ) {
      resolveLatest();
    }
  }
  function onError(error: Error) {
    reject(error);
  }

  const promise = new Promise<VolumeHeadResult | null>((resolveInner, rejectInner) => {
    resolvePromise = resolveInner;
    rejectPromise = rejectInner;
  });
  listener.on("notification", onNotification);
  listener.on("error", onError);
  input.signal?.addEventListener("abort", onAbort, { once: true });
  if (input.signal?.aborted) {
    onAbort();
  }
  timer = setTimeout(resolveLatest, timeoutMs);

  return { promise, resolve, reject };
}

function emptyManifest(): TreeManifest {
  const entries: TreeManifest["entries"] = [];
  return {
    version: protocolVersion,
    treeHash: computeTreeHash(entries),
    entries,
  };
}

function toVolume(row: Record<string, unknown>): Volume {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    defaultBranchId: String(row.default_branch_id),
    createdAt: Number(row.created_at),
  };
}

function toBranch(row: Record<string, unknown>): DbBranch {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    volumeId: String(row.volume_id),
    name: String(row.name),
    parentBranchId: row.parent_branch_id ? String(row.parent_branch_id) : undefined,
    forkedFromSnapshotId: row.forked_from_snapshot_id
      ? String(row.forked_from_snapshot_id)
      : undefined,
    headCommitId: String(row.head_commit_id),
    leaseCounter: Number(row.lease_counter),
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at),
    ...(row.branch_mode === undefined || row.branch_mode === null
      ? {}
      : { branchMode: parseStoredBranchMode(row.branch_mode) }),
  };
}

function toCommit(row: Record<string, unknown>): VolumeCommit {
  if (row.manifest === null || row.manifest === undefined) {
    throw new MetadataConflictError("VOLUME_COMMIT_MANIFEST_MISSING", "Commit manifest is missing.", 500);
  }
  return toCommitWithManifest(row, treeManifestSchema.parse(row.manifest));
}

function toCommitWithManifest(row: Record<string, unknown>, manifest: TreeManifest): VolumeCommit {
  return {
    ...toCommitSummaryRow(row),
    manifest,
  };
}

function toCommitSummaryRow(row: Record<string, unknown>): VolumeCommitSummary {
  return {
    id: String(row.id),
    volumeId: String(row.volume_id),
    branchId: String(row.branch_id),
    parentCommitId: row.parent_commit_id ? String(row.parent_commit_id) : undefined,
    treeHash: String(row.tree_hash),
    mutationCount: Number(row.mutation_count),
    byteCount: Number(row.byte_count),
    createdByAttachSessionId: row.created_by_attach_session_id
      ? String(row.created_by_attach_session_id)
      : undefined,
    createdAt: Number(row.created_at),
  };
}

function assertManifestDiffShape(diff: TreeManifestDiff): void {
  const actualMutationCount = diff.added.length + diff.changed.length + diff.removed.length;
  if (diff.mutationCount !== actualMutationCount) {
    throw new MetadataConflictError(
      "VOLUME_COMMIT_DELTA_MISMATCH",
      "Commit delta mutation count does not match changed entries.",
      400
    );
  }
}

function toLease(row: Record<string, unknown>): VolumeLease {
  return {
    id: String(row.id),
    volumeId: String(row.volume_id),
    branchId: String(row.branch_id),
    attachSessionId: String(row.attach_session_id),
    holderId: String(row.holder_id),
    fencingToken: Number(row.fencing_token),
    exclusive: row.exclusive === undefined ? true : Boolean(row.exclusive),
    expiresAt: Number(row.expires_at),
    releasedAt: row.released_at ? Number(row.released_at) : undefined,
  };
}

function toSession(row: Record<string, unknown>): AttachSession {
  return {
    id: String(row.id),
    volumeId: String(row.volume_id),
    branchId: String(row.branch_id),
    mode: String(row.mode) as AttachMode,
    shared: Boolean(row.shared),
    rootPath: normalizeVolumePath(String(row.root_path ?? "")),
    baseCommitId: String(row.base_commit_id),
    attachedAt: Number(row.attached_at),
    detachedAt: row.detached_at ? Number(row.detached_at) : undefined,
  };
}

function toDelegation(row: Record<string, unknown>): PathDelegation {
  return {
    id: String(row.id),
    volumeId: String(row.volume_id),
    branchId: String(row.branch_id),
    attachSessionId: String(row.attach_session_id),
    holderId: String(row.holder_id),
    path: normalizeVolumePath(String(row.path ?? "")),
    recursive: Boolean(row.recursive),
    fencingToken: Number(row.fencing_token),
    expiresAt: Number(row.expires_at),
    createdAt: Number(row.created_at),
    releasedAt: row.released_at ? Number(row.released_at) : undefined,
    revokedAt: row.revoked_at ? Number(row.revoked_at) : undefined,
  };
}

function toSnapshot(row: Record<string, unknown>): VolumeSnapshot {
  return {
    id: String(row.id),
    volumeId: String(row.volume_id),
    branchId: String(row.branch_id),
    commitId: String(row.commit_id),
    name: row.name ? String(row.name) : undefined,
    createdAt: Number(row.created_at),
  };
}

function requireRow<T>(value: T | null, label: string): T {
  if (!value) {
    throw new Error(`${label} not found after metadata mutation.`);
  }
  return value;
}

// Validates the retained attach-receipt outcome facts (session, branch,
// delegations) through the wire schemas before replaying them.
function parseAttachOutcomeFacts(value: unknown): {
  session: AttachSession;
  branch: VolumeBranch;
  delegations: PathDelegation[];
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new MetadataConflictError(
      "VOLUME_ATTACH_RECEIPT_INVALID",
      "Retained attach receipt outcome is malformed.",
      500
    );
  }
  const record = value as Record<string, unknown>;
  const rawDelegations = Array.isArray(record.delegations) ? record.delegations : [];
  return {
    session: attachSessionSchema.parse(record.session),
    branch: branchSchema.parse(record.branch),
    delegations: rawDelegations.map((delegation) => pathDelegationSchema.parse(delegation)),
  };
}

// Maps one pfh cut-status projection to the snapshot wire record. commitId is
// the cut's BASE anchor commit (stable from creation); the materialized
// content commit rides in resultCommitId once ready.
// extractIdFromOperationShape pulls a named id out of either a direct
// projection ({ cutId: ... }) or a replayed permanent resource-operation
// projection (id under targetIds or the recorded response).
function extractIdFromOperationShape(
  raw: Record<string, unknown>,
  key: string
): string | undefined {
  if (typeof raw[key] === "string") {
    return raw[key] as string;
  }
  const targetIds = (raw.targetIds ?? {}) as Record<string, unknown>;
  if (typeof targetIds[key] === "string") {
    return targetIds[key] as string;
  }
  const response = (raw.response ?? {}) as Record<string, unknown>;
  if (typeof response[key] === "string") {
    return response[key] as string;
  }
  return undefined;
}

function projectConversion(conversion: ConversionStatus): JournalActivationConversion {
  return {
    conversionId: conversion.conversionId,
    state: conversion.state,
    attempt: conversion.attempt,
    ...(conversion.finalCutId ? { finalCutId: conversion.finalCutId } : {}),
    ...(conversion.lastError !== undefined ? { lastError: conversion.lastError } : {}),
  };
}

function projectActivationCut(cut: HistoryCutStatus): JournalActivationCut {
  return {
    cutId: cut.cutId,
    state: cut.state,
    attemptCount: cut.attemptCount,
    ...(cut.lastError !== undefined ? { lastError: cut.lastError } : {}),
  };
}

function cutStatusToSnapshotRecord(status: HistoryCutStatus): SnapshotCutRecord {
  const anchorCommitId = status.sourceBaseCommitId ?? status.sourceHeadCommitId ?? "";
  return {
    id: status.cutId,
    volumeId: status.volumeId,
    branchId: status.branchId,
    commitId: anchorCommitId,
    ...(status.userLabel ? { name: status.userLabel } : {}),
    createdAt: Number(status.createdDbMs),
    state: status.state,
    cutId: status.cutId,
    ...(status.resultCommitId ? { resultCommitId: status.resultCommitId } : {}),
    ...(status.cutSeqExclusive ? { cutSeqExclusive: status.cutSeqExclusive } : {}),
  };
}

// Same mapping from a raw pfh.history_cuts row (bounded listing reads).
function cutRowToSnapshotRecord(row: Record<string, unknown>): SnapshotCutRecord {
  const state = String(row.state);
  return {
    id: String(row.id),
    volumeId: String(row.volume_id),
    branchId: String(row.branch_id),
    commitId: String(row.source_base_commit_id ?? row.source_head_commit_id ?? ""),
    ...(row.user_label ? { name: String(row.user_label) } : {}),
    createdAt: Number(row.created_db_ms),
    state:
      state === "materializing" || state === "ready" || state === "failed" || state === "canceled"
        ? state
        : "pending",
    cutId: String(row.id),
    ...(row.result_commit_id ? { resultCommitId: String(row.result_commit_id) } : {}),
    ...(row.cut_seq_exclusive !== null && row.cut_seq_exclusive !== undefined
      ? { cutSeqExclusive: String(row.cut_seq_exclusive) }
      : {}),
  };
}

function normalizeListLimit(limit: number): number {
  return Number.isFinite(limit) ? Math.max(1, Math.trunc(limit)) : 1;
}

// Detects a Postgres unique-constraint violation (SQLSTATE 23505) on a specific
// constraint, as raised by node-postgres DatabaseError.
function isUniqueViolation(error: unknown, constraint: string): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }
  const candidate = error as { code?: unknown; constraint?: unknown };
  return candidate.code === "23505" && candidate.constraint === constraint;
}
