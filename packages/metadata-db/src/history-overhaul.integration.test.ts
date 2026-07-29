import { createHash, randomUUID } from "node:crypto";
import pg from "pg";
import { describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";
import type { HistoryCutStatus } from "./history.js";

// ---------------------------------------------------------------------------
// History-plane overhaul surface against real Postgres (the full migration
// lineage): chained cut capture (026), adoption against the generation's
// live base (026), W-of-N readiness (025), the O(delta) base-closure copy
// (027), retention release (028), and kind-agnostic dedup (029).
//
// The suite drives the pfh worker surface directly as the test role (a
// superuser bypasses the role split) over fixture journal generations —
// no Go worker and no object bytes participate: receipts are rows, and
// the SQL machinery never hashes payloads. Fixtures use random ids and
// are designed for a disposable database.
// ---------------------------------------------------------------------------

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/portablefs";

const zeroDigest = "0".repeat(64);

function hexOf(seed: string): string {
  return createHash("sha256").update(seed, "utf8").digest("hex");
}

async function ensureHistoryPolicy(
  pool: pg.Pool,
  metadata: PostgresMetadataRepository
): Promise<string[]> {
  const existing = await pool.query(
    `SELECT policy FROM pfh.history_policies WHERE singleton_key = 'history'`
  );
  if ((existing.rowCount ?? 0) > 0) {
    return (existing.rows[0].policy as { requiredFailureDomains: string[] })
      .requiredFailureDomains;
  }
  const domains = ["itest-a", "itest-b", "itest-c"];
  await metadata.history.installHistoryPolicy(
    JSON.stringify({
      v: "1",
      requiredFailureDomains: domains,
      maxLastVerifiedAgeMs: 3_600_000,
      maxWorkerHeartbeatAgeMs: 60_000,
    }),
    "0"
  );
  return domains;
}

interface ManagedFixture {
  tenantId: string;
  volumeId: string;
  branchId: string;
  branchName: string;
  bornCommitId: string;
  generationId: string;
}

async function managedVolumeFixture(
  pool: pg.Pool,
  metadata: PostgresMetadataRepository
): Promise<ManagedFixture> {
  const tenantId = `tenant_${randomUUID()}`;
  const volumeId = `vol_${randomUUID()}`;
  const branchName = "main";
  await metadata.createVolume({ tenantId, volumeId, branchName, managed: true });
  const branch = await pool.query(
    `SELECT id, head_commit_id FROM branches WHERE tenant_id=$1 AND volume_id=$2 AND name=$3`,
    [tenantId, volumeId, branchName]
  );
  const branchId = String(branch.rows[0].id);
  const bornCommitId = String(branch.rows[0].head_commit_id);
  const generationId = `gen_${randomUUID().replaceAll("-", "")}`;
  await pool.query(
    `INSERT INTO pfj.journal_generations (
       id, tenant_id, volume_id, branch_id, epoch, record_codec, control_codec,
       base_commit_id, base_seq, base_digest, next_seq, tip_digest,
       physical_trimmed_seq, status, backlog_bytes, backlog_records,
       quota_backlog_bytes, quota_backlog_records, created_at, updated_at)
     VALUES ($1, $2, $3, $4, 1, 'pfj3', 'pfc2', $5, 0, $6, 0, $6,
       0, 'active', 0, 0, 4294967296, 1048576, $7, $7)`,
    [generationId, tenantId, volumeId, branchId, bornCommitId, zeroDigest, Date.now()]
  );
  return { tenantId, volumeId, branchId, branchName, bornCommitId, generationId };
}

// Simulated appends: advance the head and grow the cumulative backlog
// (the freeze trigger admits both for any writer; only base moves and
// backlog shrinks demand adoption proof rows).
async function advanceHead(
  pool: pg.Pool,
  generationId: string,
  nextSeq: number,
  tipDigest: string,
  backlogBytes: number,
  backlogRecords: number
): Promise<void> {
  await pool.query(
    `UPDATE pfj.journal_generations
     SET next_seq=$2, tip_digest=$3, backlog_bytes=$4, backlog_records=$5, updated_at=$6
     WHERE id=$1`,
    [generationId, nextSeq, tipDigest, backlogBytes, backlogRecords, Date.now()]
  );
}

async function createCut(
  metadata: PostgresMetadataRepository,
  fixture: ManagedFixture,
  kind: "user" | "recovery",
  label?: string
): Promise<HistoryCutStatus> {
  return metadata.history.createCut({
    tenantId: fixture.tenantId,
    volumeId: fixture.volumeId,
    branchName: fixture.branchName,
    kind,
    operationId: `itest_${randomUUID()}`,
    requestCanonicalJson: JSON.stringify({ itest: randomUUID() }),
    materializerVersion: "pfm-itest-1",
    ...(label === undefined ? {} : { userLabel: label }),
  });
}

interface ClaimedCut {
  cutId: string;
  claimEpoch: string;
  status: HistoryCutStatus;
}

async function claimCut(pool: pg.Pool, cutId: string): Promise<ClaimedCut> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const { rows } = await pool.query(
      `SELECT pfh.cut_claim($1, 16, 60000) AS out`,
      [`itest-worker-${attempt}`]
    );
    for (const row of rows) {
      const claim = row.out as { cutId: string; claimEpoch: string };
      if (claim.cutId === cutId) {
        return {
          cutId,
          claimEpoch: claim.claimEpoch,
          status: claim as unknown as HistoryCutStatus,
        };
      }
    }
  }
  throw new Error(`cut ${cutId} was never claimable`);
}

// Simulates the worker's readiness path over fixture digests: intents,
// verified copy receipts (rows only) in the given policy domains, both
// closures, and the atomic publication.
async function materializeCut(
  pool: pg.Pool,
  fixture: ManagedFixture,
  cutId: string,
  options?: { domains?: string[]; seed?: string; fromBase?: boolean }
): Promise<HistoryCutStatus> {
  const claim = await claimCut(pool, cutId);
  const policy = (claim.status as unknown as Record<string, unknown>)
    .replicationPolicy as { requiredFailureDomains: string[] };
  const domains = options?.domains ?? policy.requiredFailureDomains;
  const seed = options?.seed ?? cutId;
  const rootHex = hexOf(`${seed}-root`);
  const recoveryHex = hexOf(`${seed}-recovery`);
  const intents = [
    { digest: `sha256:${rootHex}`, size: 100 },
    { digest: `sha256:${recoveryHex}`, size: 100 },
  ];
  const bindings = await pool.query(`SELECT pfh.object_intend($1, $2, $3::jsonb) AS out`, [
    cutId,
    claim.claimEpoch,
    JSON.stringify(intents),
  ]);
  const bound = bindings.rows[0].out as Array<{ digest: string; incarnation: string }>;
  const receipts = bound.flatMap((b) =>
    domains.map((domain) => ({
      digest: b.digest,
      incarnation: Number(b.incarnation),
      failureDomain: domain,
      storageKey: `t/${fixture.tenantId}/pft2/${b.digest.slice(7)}/i${b.incarnation}/${domain}`,
      size: 100,
    }))
  );
  await pool.query(`SELECT pfh.object_copy_receipt_batch($1, $2, $3::jsonb) AS out`, [
    cutId,
    claim.claimEpoch,
    JSON.stringify(receipts),
  ]);
  await pool.query(`SELECT pfh.cut_objects_add($1, $2, 'user', $3) AS out`, [
    cutId,
    claim.claimEpoch,
    [`sha256:${rootHex}`],
  ]);
  await pool.query(`SELECT pfh.cut_objects_add($1, $2, 'recovery', $3) AS out`, [
    cutId,
    claim.claimEpoch,
    [`sha256:${recoveryHex}`],
  ]);
  let totals = {
    userObjectCount: "1",
    userObjectBytes: "100",
    recoveryObjectCount: "1",
    recoveryObjectBytes: "100",
  };
  if (options?.fromBase) {
    // The O(delta) publication path: the adopted base cut's registered
    // closure rows are copied server-side; the publication takes its
    // totals from the copy.
    const copied = await pool.query(
      `SELECT pfh.cut_objects_add_from_base($1, $2) AS out`,
      [cutId, claim.claimEpoch]
    );
    totals = copied.rows[0].out as typeof totals;
  }
  const status = await pool.query(`SELECT pfh.cut_status($1, $2) AS out`, [
    fixture.tenantId,
    cutId,
  ]);
  const namespace = (status.rows[0].out as HistoryCutStatus).inodeNamespace;
  const ready = await pool.query(
    `SELECT pfh.cut_mark_ready($1,$2,$3,$4,$5,$6,NULL,NULL,NULL,NULL,$7,$8,$9,$10,$11,$12,$13,$14) AS out`,
    [
      cutId,
      claim.claimEpoch,
      rootHex,
      100,
      recoveryHex,
      100,
      namespace,
      1, // nextLocal
      1, // maxInoSeen
      totals.userObjectCount,
      totals.userObjectBytes,
      totals.recoveryObjectCount,
      totals.recoveryObjectBytes,
      1, // rootMaxInoSeen
    ]
  );
  return ready.rows[0].out as HistoryCutStatus;
}

describePostgres("history plane overhaul (migrations 024+)", () => {
  test("a second cut chains on the branch's newest ready cut", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedVolumeFixture(pool, metadata);

      const tip100 = hexOf(`${fixture.generationId}-tip-100`);
      await advanceHead(pool, fixture.generationId, 100, tip100, 1000, 100);
      const first = await createCut(metadata, fixture, "recovery");
      expect(first.state).toBe("pending");
      expect(first.sourceBaseSeq).toBe("0");
      expect(first.sourceBaseCommitId).toBe(fixture.bornCommitId);
      const firstReady = await materializeCut(pool, fixture, first.cutId);
      expect(firstReady.state).toBe("ready");
      const firstCommit = firstReady.result!.commitId;

      const tip200 = hexOf(`${fixture.generationId}-tip-200`);
      await advanceHead(pool, fixture.generationId, 200, tip200, 2000, 200);
      const second = await createCut(metadata, fixture, "recovery");
      // The capture based on the ready cut, not the adoption-pinned base.
      expect(second.sourceBaseCommitId).toBe(firstCommit);
      expect(second.sourceBaseSeq).toBe("100");
      expect(second.sourceBaseDigest).toBe(tip100);
      expect(second.cutSeqExclusive).toBe("200");
      // The cumulative backlog counters stay adoption-relative.
      expect(second.cutBacklogBytes).toBe("2000");
      expect(second.baseCommit?.baseMode).toBe("adopted");
      expect(second.baseCommit?.anchorId).toBe(firstReady.result!.anchorId);
      expect(second.baseCommit?.recoveryRootDigest).toBe(
        firstReady.result!.recoveryRootDigest
      );
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("adoption of a chained cut verifies the generation's live base", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedVolumeFixture(pool, metadata);

      const tip100 = hexOf(`${fixture.generationId}-tip-100`);
      await advanceHead(pool, fixture.generationId, 100, tip100, 1000, 100);
      const first = await createCut(metadata, fixture, "recovery");
      await materializeCut(pool, fixture, first.cutId);

      const tip200 = hexOf(`${fixture.generationId}-tip-200`);
      await advanceHead(pool, fixture.generationId, 200, tip200, 2000, 200);
      const second = await createCut(metadata, fixture, "recovery");
      expect(second.sourceBaseSeq).toBe("100"); // chained
      const secondReady = await materializeCut(pool, fixture, second.cutId);

      const adopted = await metadata.history.adoptCut({
        tenantId: fixture.tenantId,
        cutId: second.cutId,
        anchorId: secondReady.result!.anchorId,
        operationId: `itest_${randomUUID()}`,
        requestCanonicalJson: JSON.stringify({ adopt: second.cutId }),
        servingCapability: "pft2-base-v1",
      });
      expect(adopted.state).toBe("applied");
      expect(adopted.newBaseSeq).toBe("200");

      // The proof row recorded the GENERATION's pre-adoption base (seq 0),
      // not the cut's chained source base (seq 100), and the O(1) backlog
      // subtraction drained the cumulative counters.
      const proof = await pool.query(
        `SELECT old_base_seq::text AS old_seq, new_base_seq::text AS new_seq,
                subtract_backlog_bytes::text AS sub_bytes
         FROM pfh.adoptions WHERE id=$1`,
        [adopted.adoptionId]
      );
      expect(proof.rows[0].old_seq).toBe("0");
      expect(proof.rows[0].new_seq).toBe("200");
      expect(proof.rows[0].sub_bytes).toBe("2000");
      const generation = await pool.query(
        `SELECT base_seq::text AS base_seq, base_commit_id, backlog_bytes::text AS backlog
         FROM pfj.journal_generations WHERE id=$1`,
        [fixture.generationId]
      );
      expect(generation.rows[0].base_seq).toBe("200");
      expect(generation.rows[0].base_commit_id).toBe(secondReady.result!.commitId);
      expect(generation.rows[0].backlog).toBe("0");
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("delta publication copies the base cut's closure rows server-side", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedVolumeFixture(pool, metadata);

      await advanceHead(
        pool, fixture.generationId, 100, hexOf(`${fixture.generationId}-t100`), 1000, 100);
      const first = await createCut(metadata, fixture, "recovery");
      await materializeCut(pool, fixture, first.cutId);

      await advanceHead(
        pool, fixture.generationId, 200, hexOf(`${fixture.generationId}-t200`), 2000, 200);
      const second = await createCut(metadata, fixture, "recovery");
      const secondReady = await materializeCut(pool, fixture, second.cutId, { fromBase: true });
      expect(secondReady.state).toBe("ready");
      // Registered rows = the run's delta plus the base copy; published
      // counts reflect the union.
      expect(secondReady.result!.objectCount).toBe("2");
      expect(secondReady.result!.anchorObjectCount).toBe("2");
      const baseRows = await pool.query(
        `SELECT closure, digest FROM pfh.cut_objects WHERE cut_id=$1`,
        [first.cutId]
      );
      for (const row of baseRows.rows) {
        const copied = await pool.query(
          `SELECT 1 FROM pfh.cut_objects WHERE cut_id=$1 AND closure=$2 AND digest=$3`,
          [second.cutId, row.closure, row.digest]
        );
        expect(copied.rowCount).toBe(1);
      }
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("retention keeps named + newest-K cuts and releases the rest to GC", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedVolumeFixture(pool, metadata);

      // Ten ready cuts; the first is a named snapshot, the second is not.
      const roots: string[] = [];
      const cutIds: string[] = [];
      for (let i = 1; i <= 10; i++) {
        await advanceHead(
          pool, fixture.generationId, i * 10,
          hexOf(`${fixture.generationId}-tip-${i}`), i * 100, i * 10);
        const cut = await createCut(
          metadata, fixture, "recovery", i === 1 ? "keeper" : undefined);
        cutIds.push(cut.cutId);
        // Exact per-cut closures (no base copy): each cut registers only
        // its own unique objects, so the window predicate is observable
        // per cut.
        const ready = await materializeCut(pool, fixture, cut.cutId, {
          seed: `${fixture.generationId}-${i}`,
        });
        roots.push(`sha256:${ready.result!.rootDigest}`);
      }
      const isRoot = async (digest: string): Promise<boolean> => {
        const { rows } = await pool.query(
          `SELECT pfh.object_is_root($1, 'pft2', $2) AS out`,
          [fixture.tenantId, digest]
        );
        return rows[0].out === true;
      };
      // Cut 2 fell out of the newest-8 window with no name and no pin:
      // its unique root object is GC-eligible. Cut 1 (named) and cut 10
      // (recent) stay rooted.
      expect(await isRoot(roots[1]!)).toBe(false);
      expect(await isRoot(roots[0]!)).toBe(true);
      expect(await isRoot(roots[9]!)).toBe(true);

      // Named-snapshot deletion by name: the label clears, the cut ages
      // out, and the root predicate lets the sweep take it.
      const released = await metadata.history.releaseSnapshotCut({
        tenantId: fixture.tenantId,
        volumeId: fixture.volumeId,
        name: "keeper",
      });
      expect(released.cutIds).toEqual([cutIds[0]]);
      expect(await isRoot(roots[0]!)).toBe(false);
      await expect(
        metadata.history.releaseSnapshotCut({
          tenantId: fixture.tenantId,
          volumeId: fixture.volumeId,
          name: "keeper",
        })
      ).rejects.toThrow(/no ready snapshot/);
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("retention_release releases superseded adoption consumers only", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedVolumeFixture(pool, metadata);

      const adoptAtHead = async (seq: number) => {
        await advanceHead(
          pool, fixture.generationId, seq,
          hexOf(`${fixture.generationId}-tip-${seq}`), seq * 10, seq);
        const cut = await createCut(metadata, fixture, "recovery");
        const ready = await materializeCut(pool, fixture, cut.cutId, {
          seed: `${fixture.generationId}-${seq}`,
          fromBase: seq > 100,
        });
        const adopted = await metadata.history.adoptCut({
          tenantId: fixture.tenantId,
          cutId: cut.cutId,
          anchorId: ready.result!.anchorId,
          operationId: `itest_${randomUUID()}`,
          requestCanonicalJson: JSON.stringify({ adopt: cut.cutId }),
          servingCapability: "pft2-base-v1",
        });
        return adopted.adoptionId;
      };

      const adoption1 = await adoptAtHead(100);
      // The still-serving child acknowledges the base swap; the pin
      // releases and only the consumer remains.
      await metadata.history.ackServingPin({
        adoptionId: adoption1,
        generationId: fixture.generationId,
        writerFence: "0",
      });
      const adoption2 = await adoptAtHead(200);

      const { rows } = await pool.query(`SELECT pfh.retention_release(64) AS out`);
      const releasedTotal = Number(
        (rows[0].out as { adoptionConsumersReleased: string }).adoptionConsumersReleased
      );
      expect(releasedTotal).toBeGreaterThanOrEqual(1);
      const consumers = await pool.query(
        `SELECT consumer_id, released_db_ms FROM pfh.cut_consumers
         WHERE consumer_kind='adoption' AND consumer_id = ANY($1)`,
        [[adoption1, adoption2]]
      );
      const byId = new Map(
        consumers.rows.map((row) => [String(row.consumer_id), row.released_db_ms])
      );
      expect(byId.get(adoption1)).not.toBeNull();
      expect(byId.get(adoption2)).toBeNull();
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("user and recovery requests at one boundary converge onto one fold", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedVolumeFixture(pool, metadata);
      await advanceHead(
        pool, fixture.generationId, 100, hexOf(`${fixture.generationId}-t100`), 1000, 100);

      const recovery = await createCut(metadata, fixture, "recovery");
      expect(recovery.state).toBe("pending");
      const snapshot = await createCut(metadata, fixture, "user", "boundary-snap");
      // The snapshot converged onto the live recovery cut — one row, one
      // fold — and adopted the label.
      expect(snapshot.cutId).toBe(recovery.cutId);
      expect(snapshot.kind).toBe("recovery");
      expect(snapshot.userLabel).toBe("boundary-snap");
      const rows = await pool.query(
        `SELECT COUNT(*)::int AS n FROM pfh.history_cuts
         WHERE generation_id=$1 AND cut_seq_exclusive=100`,
        [fixture.generationId]
      );
      expect(rows.rows[0].n).toBe(1);
      // A second label never overwrites the first.
      const again = await createCut(metadata, fixture, "user", "other-name");
      expect(again.cutId).toBe(recovery.cutId);
      expect(again.userLabel).toBe("boundary-snap");
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("adoption consumes a ready user-kind cut", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      await ensureHistoryPolicy(pool, metadata);
      const fixture = await managedVolumeFixture(pool, metadata);
      await advanceHead(
        pool, fixture.generationId, 100, hexOf(`${fixture.generationId}-t100`), 1000, 100);
      const cut = await createCut(metadata, fixture, "user", "adoptable");
      const ready = await materializeCut(pool, fixture, cut.cutId);
      const adopted = await metadata.history.adoptCut({
        tenantId: fixture.tenantId,
        cutId: cut.cutId,
        anchorId: ready.result!.anchorId,
        operationId: `itest_${randomUUID()}`,
        requestCanonicalJson: JSON.stringify({ adopt: cut.cutId }),
        servingCapability: "pft2-base-v1",
      });
      expect(adopted.state).toBe("applied");
      expect(adopted.newBaseSeq).toBe("100");
    } finally {
      await pool.end();
      await metadata.close();
    }
  });

  test("readiness is W-of-N: one dark domain does not block publication", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      const domains = await ensureHistoryPolicy(pool, metadata);
      if (domains.length < 3) {
        return; // quorum below N is only observable with three or more domains
      }
      const fixture = await managedVolumeFixture(pool, metadata);
      await advanceHead(
        pool, fixture.generationId, 50, hexOf(`${fixture.generationId}-tip-50`), 500, 50);
      const cut = await createCut(metadata, fixture, "recovery");
      // Receipts land in only two of the N required domains.
      const ready = await materializeCut(pool, fixture, cut.cutId, {
        domains: domains.slice(0, 2),
      });
      expect(ready.state).toBe("ready");
    } finally {
      await pool.end();
      await metadata.close();
    }
  });
});
