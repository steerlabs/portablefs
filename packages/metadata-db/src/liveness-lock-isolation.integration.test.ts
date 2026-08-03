// Liveness must not queue behind bulk data — proven against a real postgres.
//
// ROUND 18b, THE FIFTH INSTANCE. A single-threaded 8 MiB-write flood into one
// mounted branch killed the mount in ~231 s, reproducibly. pg_stat_activity
// sampled at 1 Hz through the failure named the blocker exactly:
//
//   pid 1841 | Lock/transactionid | 1286 ms | blocked by 1674 | SELECT * FROM leases WHERE id = $1 FOR UPDATE
//   pid 1529 | Lock/transactionid | 1908 ms | blocked by 1674 | SELECT pfm.manager_renew($1,$2,$3,$4) AS r
//   pid 1674 | LWLock/WALWrite    |  433 ms | -               | SELECT pfj.journal_append_v3(...)
//
// ONE bulk append transaction, sitting in its WAL fsync, was blocking BOTH
// liveness paths of the whole system, because pfj.require_writer took FOR
// SHARE on public.leases and pfm.verify_authority_binding took FOR SHARE on
// the singleton pfm.manager_claims row, and both held those locks across the
// payload writes. Waits crossed the 5 s lock_timeout, volume-api answered the
// renew a 500, and the child's 20 s watchdog fenced the authority — which
// killed every access lease pointing at it and stranded the mount.
//
// These tests hold the locks a bulk append holds and assert the heartbeats
// still complete inside their bound. They are FAILING-FIRST against migration
// 033: the bulk-side lock mode is read out of the SHIPPED pfj.require_writer
// definition rather than hard-coded, so re-upgrading it to FOR SHARE (or
// putting a FOR UPDATE back into a renewal) reproduces the outage here
// instead of in production.
//
// Run: PORTABLEFS_TEST_POSTGRES=true VOLUME_DATABASE_URL=... vitest run
//      src/liveness-lock-isolation.integration.test.ts

import { randomUUID, createHash } from "node:crypto";
import pg from "pg";
import { afterEach, describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/portablefs";

// The bound a heartbeat must meet while a bulk append transaction is open and
// holding its validation locks. Generous by two orders of magnitude against
// the real deadlines it protects (volume-api's renew has a 10 s per-attempt
// budget inside a 20 s self-fence watchdog; the manager's claim renewal has a
// 5 s lock_timeout) and still far below anything a lock queue would produce:
// a blocked renewal waits for the append's COMMIT, which is unbounded.
const heartbeatBoundMs = 1_000;

// How long the simulated bulk append holds its locks. Longer than every
// bound under test, so "the heartbeat finished" can only mean "it did not
// wait for the append".
const bulkHoldMs = 4_000;

const created: Array<{ volumeId: string; tenantId: string }> = [];
const openClients: pg.Client[] = [];

afterEach(async () => {
  if (!runPostgresTests) {
    return;
  }
  for (const client of openClients.splice(0)) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // the test may already have ended the transaction
    }
    await client.end().catch(() => undefined);
  }
  const pool = new pg.Pool({ connectionString: databaseUrl });
  try {
    // Fixture teardown only. Order matters (FKs), and a leftover row must
    // never fail the run that produced the assertion, so each step is
    // best-effort.
    const steps = [
      `DELETE FROM path_delegations WHERE tenant_id=$1 AND volume_id=$2`,
      `DELETE FROM leases WHERE tenant_id=$1 AND volume_id=$2`,
      `DELETE FROM attach_sessions WHERE tenant_id=$1 AND volume_id=$2`,
      `UPDATE volumes SET default_branch_id=NULL WHERE tenant_id=$1 AND id=$2`,
      `DELETE FROM commits WHERE tenant_id=$1 AND volume_id=$2`,
      `DELETE FROM branches WHERE tenant_id=$1 AND volume_id=$2`,
      `DELETE FROM volumes WHERE tenant_id=$1 AND id=$2`,
    ];
    for (const { volumeId, tenantId } of created.splice(0).reverse()) {
      for (const step of steps) {
        await pool.query(step, [tenantId, volumeId]).catch(() => undefined);
      }
      await pool.query(`DELETE FROM tenants WHERE id=$1`, [tenantId]).catch(() => undefined);
    }
    // The manager claim is a fleet singleton: expire whatever this file
    // claimed so the next test can take it.
    await pool
      .query(`UPDATE pfm.manager_claims SET claimed_at = 1, renewed_at = 1, expires_at = 2 WHERE singleton_key='manager'`)
      .catch(() => undefined);
  } finally {
    await pool.end();
  }
});

/**
 * Claims the singleton manager epoch for one test. The claim row is a fleet
 * singleton, so any live claim is expired first — a fixture concern only;
 * production takeover goes through pfm.manager_claim's own TTL rules.
 */
async function claimManagerEpoch(): Promise<{
  epoch: number;
  runtimeId: string;
  capability: string;
}> {
  const runtimeId = `mgr_${randomUUID()}`;
  const capability = `cap-${randomUUID()}${randomUUID()}`;
  const capabilityHash = createHash("sha256").update(capability, "utf8").digest("hex");
  const admin = await openClient();
  await admin.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);
  await admin.query(`UPDATE pfm.manager_claims SET claimed_at = 1, renewed_at = 1, expires_at = 2 WHERE singleton_key='manager'`);
  const claimed = await admin.query<{ r: { managerEpoch: string } }>(
    `SELECT pfm.manager_claim($1,$2,$3,$4) AS r`,
    [`op_${randomUUID()}`, runtimeId, capabilityHash, 600_000]
  );
  const epoch = Number(claimed.rows[0]?.r.managerEpoch);
  if (!Number.isFinite(epoch)) {
    throw new Error(`pfm.manager_claim did not return a manager epoch: ${JSON.stringify(claimed.rows[0])}`);
  }
  return { epoch, runtimeId, capability };
}

async function openClient(): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  openClients.push(client);
  return client;
}

/**
 * The row-lock mode the SHIPPED append path takes on the writer's lease row.
 * Read from pg_get_functiondef so this test tracks the deployed SQL: if
 * pfj.require_writer is ever put back to FOR SHARE, the contention tests
 * below fail rather than silently passing against a hard-coded mode.
 */
async function appendLeaseLockMode(client: pg.Client): Promise<string> {
  const result = await client.query<{ def: string }>(
    `SELECT pg_get_functiondef(to_regprocedure(
       'pfj.require_writer(pfj.journal_generations,bigint,text,text,bigint,text,text)')) AS def`
  );
  const match = /FROM public\.leases l WHERE l\.id = g\.lease_id (FOR(?: KEY)? SHARE)/u.exec(
    result.rows[0]?.def ?? ""
  );
  if (!match) {
    throw new Error("pfj.require_writer no longer reads the lease row with a recognizable lock");
  }
  return match[1] as string;
}

async function createWriteLease(metadata: PostgresMetadataRepository): Promise<{
  tenantId: string;
  volumeId: string;
  leaseId: string;
  fencingToken: number;
  expiresAt: number;
}> {
  const tenantId = `tenant_${randomUUID()}`;
  const volumeId = `vol_${randomUUID()}`;
  created.push({ tenantId, volumeId });
  const volume = await metadata.createVolume({ tenantId, volumeId, branchName: "main" });
  const attached = await metadata.attachVolume({
    tenantId,
    volumeId: volume.volume.id,
    branchName: "main",
    mode: "write",
    shared: false,
    rootPath: "",
    holderId: `writer_${randomUUID()}`,
    leaseTtlMs: 600_000,
  });
  const lease = attached.session.lease;
  if (!lease) {
    throw new Error("Expected a write lease.");
  }
  return {
    tenantId,
    volumeId: volume.volume.id,
    leaseId: lease.id,
    fencingToken: lease.fencingToken,
    expiresAt: lease.expiresAt,
  };
}

describePostgres("liveness lock isolation (migration 034)", () => {
  test("a writer-lease renewal completes while a bulk append holds the append-path locks", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const lease = await createWriteLease(metadata);

      // THE BULK SIDE. Exactly what pfj.journal_append_v3 does to this row:
      // take the validation lock and hold it until COMMIT, which in
      // production is after up to 16 MiB of payload INSERTs and a
      // synchronous_commit fsync.
      const bulk = await openClient();
      const mode = await appendLeaseLockMode(bulk);
      await bulk.query("BEGIN");
      await bulk.query(`SELECT * FROM leases WHERE id = $1 ${mode}`, [lease.leaseId]);

      // THE LIVENESS SIDE. The heartbeat that keeps the authority serving.
      const started = Date.now();
      const renewed = await metadata.renewLease({
        leaseId: lease.leaseId,
        fencingToken: lease.fencingToken,
        leaseTtlMs: 900_000,
      });
      const elapsed = Date.now() - started;

      // Release the bulk transaction only AFTER measuring, so a pass cannot
      // come from the append happening to finish first.
      await bulk.query("COMMIT");

      expect(elapsed).toBeLessThan(heartbeatBoundMs);
      expect(renewed.expiresAt).toBeGreaterThan(lease.expiresAt);
    } finally {
      await metadata.close();
    }
  }, 30_000);

  test("the manager claim renewal completes while an append holds the singleton claim row", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();

      // pfm mutations require durable-primary evidence; a single-node test
      // container has no synchronous standby, so every connection here uses
      // the superuser-only bypass the schema itself defines
      // (pfm.durability_bypass_active).
      const { epoch, runtimeId, capability } = await claimManagerEpoch();

      // THE BULK SIDE. pfm.require_manager is the exact function every
      // journal append reaches (through pfj.require_manager_binding ->
      // pfm.verify_authority_binding) and every access-lease call reaches
      // directly. Holding its transaction open is holding the claim-row lock
      // an in-flight append holds.
      const bulk = await openClient();
      await bulk.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);
      await bulk.query("BEGIN");
      await bulk.query(`SELECT pfm.require_manager($1,$2,$3)`, [epoch, runtimeId, capability]);

      // THE LIVENESS SIDE, on its own connection, exactly as the manager's
      // dedicated heartbeat worker issues it.
      const heartbeat = await openClient();
      await heartbeat.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);
      const started = Date.now();
      const renewed = await heartbeat.query<{ r: { dbTimeMs: string; expiresAtDbMs: string } }>(
        `SELECT pfm.manager_renew($1,$2,$3,$4) AS r`,
        [epoch, runtimeId, capability, 900_000]
      );
      const elapsed = Date.now() - started;

      await bulk.query("COMMIT");

      expect(elapsed).toBeLessThan(heartbeatBoundMs);
      expect(Number(renewed.rows[0]?.r.expiresAtDbMs)).toBeGreaterThan(
        Number(renewed.rows[0]?.r.dbTimeMs)
      );
    } finally {
      await metadata.close();
    }
  }, 30_000);

  test("a fence transition still serializes against an in-flight append", async () => {
    // The safety direction. Downgrading the append's validation lock must NOT
    // let a release or a takeover commit underneath an in-flight append: a
    // FOR UPDATE still conflicts with FOR KEY SHARE.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const lease = await createWriteLease(metadata);

      const bulk = await openClient();
      const mode = await appendLeaseLockMode(bulk);
      await bulk.query("BEGIN");
      await bulk.query(`SELECT * FROM leases WHERE id = $1 ${mode}`, [lease.leaseId]);

      const fencer = await openClient();
      await fencer.query(`SET lock_timeout = '750ms'`);
      await fencer.query("BEGIN");
      // getLeaseForUpdate — the shape every release / detach / commit takes.
      await expect(
        fencer.query(`SELECT * FROM leases WHERE id = $1 FOR UPDATE`, [lease.leaseId])
      ).rejects.toThrow(/lock timeout/iu);
      await fencer.query("ROLLBACK");
      await bulk.query("COMMIT");
    } finally {
      await metadata.close();
    }
  }, 30_000);

  test("releasing a lease still serializes against an in-flight append", async () => {
    // The release path writes `released_at`, a NON-KEY column, so after the
    // KEY SHARE downgrade a plain UPDATE would no longer conflict with an
    // in-flight append. detach() therefore takes FOR UPDATE on the lease rows
    // first. This test is the guard on that: a release must still wait.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const detacher = new PostgresMetadataRepository({
      connectionString: databaseUrl,
      // Fail fast instead of hanging the suite if the release stops waiting.
      statement_timeout: 1_500,
    } as pg.PoolConfig);
    try {
      await metadata.applyMigrations();
      const lease = await createWriteLease(metadata);
      const session = await new pg.Pool({ connectionString: databaseUrl });
      const sessionId = (
        await session.query<{ attach_session_id: string }>(
          `SELECT attach_session_id FROM leases WHERE id = $1`,
          [lease.leaseId]
        )
      ).rows[0]?.attach_session_id as string;
      await session.end();

      const bulk = await openClient();
      const mode = await appendLeaseLockMode(bulk);
      await bulk.query("BEGIN");
      await bulk.query(`SELECT * FROM leases WHERE id = $1 ${mode}`, [lease.leaseId]);

      await expect(
        detacher.detach({ attachSessionId: sessionId, releaseLease: true })
      ).rejects.toThrow(/timeout/iu);
      await bulk.query("COMMIT");
    } finally {
      await detacher.close();
      await metadata.close();
    }
  }, 30_000);

  test("a manager takeover still serializes against an in-flight append", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const { epoch, runtimeId, capability } = await claimManagerEpoch();

      const bulk = await openClient();
      await bulk.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);
      await bulk.query("BEGIN");
      await bulk.query(`SELECT pfm.require_manager($1,$2,$3)`, [epoch, runtimeId, capability]);

      const successor = await openClient();
      await successor.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);
      await successor.query(`SET lock_timeout = '750ms'`);
      await expect(
        successor.query(`SELECT pfm.manager_claim($1,$2,$3,$4) AS r`, [
          `op_${randomUUID()}`,
          `mgr_${randomUUID()}`,
          createHash("sha256").update("successor", "utf8").digest("hex"),
          600_000,
        ])
      ).rejects.toThrow(/lock timeout/iu);
      await bulk.query("COMMIT");
    } finally {
      await metadata.close();
    }
  }, 30_000);

  test("renewLease still refuses a stale fence, a released lease, and an expired lease", async () => {
    // Behavioural equivalence with the FOR UPDATE + validate + UPDATE shape it
    // replaced: the preconditions moved into the WHERE clause, they did not
    // disappear.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      const lease = await createWriteLease(metadata);

      await expect(
        metadata.renewLease({
          leaseId: lease.leaseId,
          fencingToken: lease.fencingToken + 1,
          leaseTtlMs: 60_000,
        })
      ).rejects.toMatchObject({ code: "VOLUME_LEASE_STALE" });

      await expect(
        metadata.renewLease({
          leaseId: `lse_${randomUUID()}`,
          fencingToken: lease.fencingToken,
          leaseTtlMs: 60_000,
        })
      ).rejects.toMatchObject({ code: "VOLUME_LEASE_STALE" });

      // Expired at database time.
      await pool.query(`UPDATE leases SET expires_at = $1 WHERE id = $2`, [
        Date.now() - 60_000,
        lease.leaseId,
      ]);
      await expect(
        metadata.renewLease({
          leaseId: lease.leaseId,
          fencingToken: lease.fencingToken,
          leaseTtlMs: 60_000,
        })
      ).rejects.toMatchObject({ code: "VOLUME_LEASE_EXPIRED" });

      // Released.
      await pool.query(`UPDATE leases SET expires_at = $1, released_at = $2 WHERE id = $3`, [
        Date.now() + 600_000,
        Date.now(),
        lease.leaseId,
      ]);
      await expect(
        metadata.renewLease({
          leaseId: lease.leaseId,
          fencingToken: lease.fencingToken,
          leaseTtlMs: 60_000,
        })
      ).rejects.toMatchObject({ code: "VOLUME_LEASE_STALE" });
    } finally {
      await pool.end();
      await metadata.close();
    }
  }, 30_000);

  test("a renewal is monotone and extends live path delegations with the lease", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    const pool = new pg.Pool({ connectionString: databaseUrl });
    try {
      await metadata.applyMigrations();
      const lease = await createWriteLease(metadata);

      const long = await metadata.renewLease({
        leaseId: lease.leaseId,
        fencingToken: lease.fencingToken,
        leaseTtlMs: 3_600_000,
      });
      // A shorter TTL must never pull an expiry in.
      const short = await metadata.renewLease({
        leaseId: lease.leaseId,
        fencingToken: lease.fencingToken,
        leaseTtlMs: 1_000,
      });
      expect(short.expiresAt).toBe(long.expiresAt);

      const delegations = await pool.query<{ expires_at: string }>(
        `SELECT expires_at FROM path_delegations
          WHERE lease_id = $1 AND released_at IS NULL AND revoked_at IS NULL`,
        [lease.leaseId]
      );
      for (const row of delegations.rows) {
        expect(Number(row.expires_at)).toBeGreaterThanOrEqual(lease.expiresAt);
      }
    } finally {
      await pool.end();
      await metadata.close();
    }
  }, 30_000);

  test("pfm.manager_renew still answers PF001 for a superseded or expired claim", async () => {
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const first = await claimManagerEpoch();
      const heartbeat = await openClient();
      await heartbeat.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);

      // Superseded: a takeover minted a new epoch under us.
      const second = await claimManagerEpoch();
      expect(second.epoch).toBeGreaterThan(first.epoch);
      await expect(
        heartbeat.query(`SELECT pfm.manager_renew($1,$2,$3,$4) AS r`, [
          first.epoch,
          first.runtimeId,
          first.capability,
          60_000,
        ])
      ).rejects.toMatchObject({ code: "PF001" });

      // Wrong capability for the live epoch.
      await expect(
        heartbeat.query(`SELECT pfm.manager_renew($1,$2,$3,$4) AS r`, [
          second.epoch,
          second.runtimeId,
          `cap-${randomUUID()}${randomUUID()}`,
          60_000,
        ])
      ).rejects.toMatchObject({ code: "PF001" });

      // Expired at database time.
      const admin = await openClient();
      await admin.query(
        `UPDATE pfm.manager_claims SET claimed_at=1, renewed_at=1, expires_at=2
          WHERE singleton_key='manager'`
      );
      await expect(
        heartbeat.query(`SELECT pfm.manager_renew($1,$2,$3,$4) AS r`, [
          second.epoch,
          second.runtimeId,
          second.capability,
          60_000,
        ])
      ).rejects.toMatchObject({ code: "PF001" });
    } finally {
      await metadata.close();
    }
  }, 30_000);

  test("a renewal that had to wait still extends, and charges the wait to its own grant", async () => {
    // SUPERSEDED BY MIGRATION 038 (round 21c). The one thing the lock-free
    // shape gave up was the old post-lock clock sample, and 034 replaced it
    // with a FIXED 250 ms bound that rolled the whole renewal back. That guard
    // is what fenced the fleet's manager under an ordinary tenant write:
    // production logged "manager renew liveness sample went stale (1007 /
    // 1146 / 2123 / 3551 / 4174 ms > 250 ms bound)" until expires_at stopped
    // advancing and the manager fenced itself, killing every child and every
    // tenant's leases. 038 keeps the wait honest instead of fatal: the
    // reported dbTimeMs is the POST-WRITE clock, so the grant shrinks by
    // exactly the wait, and the only refusal left is the exact unsoundness
    // case (the claim's own expiry passed while the statement ran), which is
    // covered in src/manager-renew-anchored-grant.integration.test.ts.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const claim = await claimManagerEpoch();

      // A takeover-shaped exclusive hold: the ONLY thing that can still make
      // a renewal wait after migration 034.
      const fencer = await openClient();
      await fencer.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);
      await fencer.query("BEGIN");
      await fencer.query(
        `SELECT * FROM pfm.manager_claims WHERE singleton_key='manager' FOR UPDATE`
      );

      const heartbeat = await openClient();
      await heartbeat.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);
      await heartbeat.query(`SET lock_timeout = '10s'`);
      const before = await heartbeat.query<{ expires_at: string }>(
        `SELECT expires_at FROM pfm.manager_claims WHERE singleton_key='manager'`
      );
      const renewal = heartbeat.query<{ r: { dbTimeMs: string; expiresAtDbMs: string } }>(
        `SELECT pfm.manager_renew($1,$2,$3,$4) AS r`,
        [claim.epoch, claim.runtimeId, claim.capability, 900_000]
      );
      // Hold six times past the bound 034 used to enforce, then let the
      // renewal through.
      await new Promise((resolve) => setTimeout(resolve, 1_500));
      await fencer.query("ROLLBACK");

      const answer = (await renewal).rows[0]?.r;
      const remaining = Number(answer?.expiresAtDbMs) - Number(answer?.dbTimeMs);
      // A usable window, shortened by the wait, never longer than the TTL.
      expect(remaining).toBeGreaterThan(0);
      expect(remaining).toBeLessThanOrEqual(900_000);
      expect(remaining).toBeLessThan(900_000 - 1_000);

      // ...and the claim really moved.
      const after = await heartbeat.query<{ expires_at: string }>(
        `SELECT expires_at FROM pfm.manager_claims WHERE singleton_key='manager'`
      );
      expect(Number(after.rows[0]?.expires_at)).toBeGreaterThan(
        Number(before.rows[0]?.expires_at)
      );
    } finally {
      await metadata.close();
    }
  }, 30_000);

  test("the bulk hold really does outlast the heartbeat bound", async () => {
    // Guards the two contention tests above from becoming vacuous: if the
    // simulated append released its locks quickly, they would pass for the
    // wrong reason. Assert the hold a bulk transaction can impose is longer
    // than the bound a heartbeat is allowed.
    expect(bulkHoldMs).toBeGreaterThan(heartbeatBoundMs);

    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const lease = await createWriteLease(metadata);
      const bulk = await openClient();
      const mode = await appendLeaseLockMode(bulk);
      await bulk.query("BEGIN");
      await bulk.query(`SELECT * FROM leases WHERE id = $1 ${mode}`, [lease.leaseId]);

      // A FOR UPDATE waiter proves the lock is genuinely held right now.
      const waiter = await openClient();
      await waiter.query(`SET lock_timeout = '${heartbeatBoundMs}ms'`);
      await expect(
        waiter.query(`SELECT * FROM leases WHERE id = $1 FOR UPDATE`, [lease.leaseId])
      ).rejects.toThrow(/lock timeout/iu);

      // ...and the renewal, on the same still-held row, does not wait.
      const started = Date.now();
      await metadata.renewLease({
        leaseId: lease.leaseId,
        fencingToken: lease.fencingToken,
        leaseTtlMs: 900_000,
      });
      expect(Date.now() - started).toBeLessThan(heartbeatBoundMs);
      await bulk.query("COMMIT");
    } finally {
      await metadata.close();
    }
  }, 30_000);
});
