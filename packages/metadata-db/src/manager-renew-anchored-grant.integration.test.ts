// A SLOW manager claim renewal must still be a renewal (migration 038).
//
// ROUND 21c, LIVE. One tenant's ordinary single-threaded ~7 MiB/s write plus
// one concurrent cut materialization made the fleet's singleton authority
// manager fence ITSELF, killing every child and invalidating every access
// lease on the whole deployment:
//
//   21:10:58-21:57:18  manager renew liveness sample went stale
//                      (1007 / 1146 / 2123 / 3551 / 4174 ms > 250 ms bound)
//   21:57:25           [child] manager lease pipe fenced this child
//   21:57:27           manager epoch 41: the singleton claim's database-time
//                      deadline passed ... fencing this manager
//   21:57:27           manager epoch 41 fenced itself: claim-deadline-exceeded
//
// The message is 034's own guard. 034's conditional UPDATE cannot sample the
// clock after its own row wait, so it sampled before and rolled the WHOLE
// renewal back whenever more than a fixed 250 ms had elapsed by the time the
// write settled — discarding renewals PostgreSQL had executed correctly.
// Three of those inside one 30 s TTL and expires_at stops advancing; the
// manager's deadline runs out and it fences. The children fence ~2 s earlier
// for the same reason, because their own grounding probe
// (pfj.authority_lease_facts) reads that very row.
//
// MEASURED CAUSE (see the round report and migration 038's header): generic
// WAL back-pressure. Against a constrained postgres under a bulk flood, with
// pg_stat_statements.track=all, the renewal's UPDATE (max 78.85 ms) is
// indistinguishable from a trivial single-row UPDATE of an unrelated private
// table (max 64.53 ms); removing the claim row from the flood's transactions
// changes nothing; the renewal's sampled waits are IO/WALSync,
// LWLock/WALWrite, IO/WALWrite, LWLock/WALInsert and ZERO Lock/transactionid.
// A durable renewal must write WAL to the same postgres the journal
// saturates, so the coupling cannot be isolated away — only absorbed.
//
// These tests are FAILING-FIRST against migration 037: the first two fail
// with PF011 today, because a stalled-but-correct renewal is thrown away.
//
// Run: PORTABLEFS_TEST_POSTGRES=true VOLUME_DATABASE_URL=... vitest run
//      src/manager-renew-anchored-grant.integration.test.ts

import { randomUUID, createHash } from "node:crypto";
import pg from "pg";
import { afterEach, describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;

const databaseUrl =
  process.env.VOLUME_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/portablefs";

// How long a stall is held across a renewal. Chosen to be far past the fixed
// 250 ms bound 034 imposed AND past every value production observed
// (1007..4174 ms is bracketed by this and the 5 s lock_timeout
// pfm.require_txn_settings sets), while staying inside that lock_timeout so
// the stall is a wait and never an error.
const stallMs = 1_500;

// The claim TTL these tests renew with. The production default is 30 s; a
// larger value here keeps the fixture alive across a whole file without
// making the "the stall is charged against the grant" arithmetic vague.
const ttlMs = 30_000;

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
    await pool.query(`DROP TABLE IF EXISTS pfs_r21c_flood`).catch(() => undefined);
    // The manager claim is a fleet singleton: expire whatever this file
    // claimed so the next test file can take it.
    await pool
      .query(
        `UPDATE pfm.manager_claims SET claimed_at=1, renewed_at=1, expires_at=2 WHERE singleton_key='manager'`
      )
      .catch(() => undefined);
  } finally {
    await pool.end();
  }
});

async function openClient(): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  // pfm mutations require durable-primary evidence; a single-node test
  // container has no synchronous standby, so every connection here uses the
  // superuser-only bypass the schema itself defines.
  await client.query(`SET portablefs.test_allow_unsafe_durability = 'on'`);
  openClients.push(client);
  return client;
}

/** Claims the singleton manager epoch for one test, expiring any live claim. */
async function claimManagerEpoch(
  claimTtlMs = 600_000
): Promise<{ epoch: number; runtimeId: string; capability: string }> {
  const runtimeId = `mgr_${randomUUID()}`;
  const capability = `cap-${randomUUID()}${randomUUID()}`;
  const capabilityHash = createHash("sha256").update(capability, "utf8").digest("hex");
  const admin = await openClient();
  await admin.query(
    `UPDATE pfm.manager_claims SET claimed_at=1, renewed_at=1, expires_at=2 WHERE singleton_key='manager'`
  );
  const claimed = await admin.query<{ r: { managerEpoch: string } }>(
    `SELECT pfm.manager_claim($1,$2,$3,$4) AS r`,
    [`op_${randomUUID()}`, runtimeId, capabilityHash, claimTtlMs]
  );
  const epoch = Number(claimed.rows[0]?.r.managerEpoch);
  if (!Number.isFinite(epoch)) {
    throw new Error(`pfm.manager_claim did not return a manager epoch`);
  }
  return { epoch, runtimeId, capability };
}

/**
 * Opens a transaction holding `FOR UPDATE` on the singleton claim row. After
 * 034 this is the ONE thing that can still make a renewal's UPDATE wait, so it
 * is the only way to stall the shipped statement by an exact, reproducible
 * amount. The stall it produces is indistinguishable, from inside
 * pfm.manager_renew, from the WAL back-pressure production actually suffered:
 * both are "the UPDATE took N ms".
 */
async function stallTheClaimRow(): Promise<pg.Client> {
  const holder = await openClient();
  await holder.query("BEGIN");
  await holder.query(`SELECT * FROM pfm.manager_claims WHERE singleton_key='manager' FOR UPDATE`);
  return holder;
}

async function claimRow(client: pg.Client): Promise<{ expiresAt: number; renewedAt: number }> {
  const row = await client.query<{ expires_at: string; renewed_at: string }>(
    `SELECT expires_at, renewed_at FROM pfm.manager_claims WHERE singleton_key='manager'`
  );
  return {
    expiresAt: Number(row.rows[0]?.expires_at),
    renewedAt: Number(row.rows[0]?.renewed_at),
  };
}

describePostgres("the manager claim renewal absorbs a slow database (migration 038)", () => {
  test("a renewal stalled far past 034's fixed bound still extends the claim", async () => {
    // THE ROOT-CAUSE TEST. Today this rejects with PF011 and the claim is not
    // extended, which is exactly the production sequence: a correct renewal
    // discarded because the statement was slow.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      // Claimed at the same TTL these renewals ask for, so the monotone
      // GREATEST extension cannot be satisfied by an older, longer grant.
      const claim = await claimManagerEpoch(ttlMs);
      const heartbeat = await openClient();
      const before = await claimRow(heartbeat);

      const holder = await stallTheClaimRow();
      const renewal = heartbeat.query<{ r: { dbTimeMs: string; expiresAtDbMs: string } }>(
        `SELECT pfm.manager_renew($1,$2,$3,$4) AS r`,
        [claim.epoch, claim.runtimeId, claim.capability, ttlMs]
      );
      await new Promise((resolve) => setTimeout(resolve, stallMs));
      await holder.query("ROLLBACK");

      const answer = (await renewal).rows[0]?.r;
      expect(answer).toBeDefined();

      // The claim really was extended.
      const after = await claimRow(heartbeat);
      expect(after.expiresAt).toBeGreaterThan(before.expiresAt);
      expect(Number(answer?.expiresAtDbMs)).toBe(after.expiresAt);
    } finally {
      await metadata.close();
    }
  }, 60_000);

  test("the stall is charged against the grant, never against the deadline's soundness", async () => {
    // The stall costs the manager exactly the stall — not the whole renewal,
    // and not one millisecond of safety. remaining = expiresAtDbMs - dbTimeMs
    // is what the manager projects onto its own monotonic clock, so it must
    // be strictly positive, must be SHORTER than the TTL by about the stall,
    // and must never exceed the TTL.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const claim = await claimManagerEpoch(ttlMs);
      const heartbeat = await openClient();

      const holder = await stallTheClaimRow();
      const renewal = heartbeat.query<{ r: { dbTimeMs: string; expiresAtDbMs: string } }>(
        `SELECT pfm.manager_renew($1,$2,$3,$4) AS r`,
        [claim.epoch, claim.runtimeId, claim.capability, ttlMs]
      );
      await new Promise((resolve) => setTimeout(resolve, stallMs));
      await holder.query("ROLLBACK");
      const answer = (await renewal).rows[0]?.r;

      const remaining = Number(answer?.expiresAtDbMs) - Number(answer?.dbTimeMs);
      // Still a useful window: the manager keeps serving.
      expect(remaining).toBeGreaterThan(0);
      // NEVER more than the TTL that was asked for. The grant is anchored at
      // the pre-write instant, so a slow statement can only shrink it.
      expect(remaining).toBeLessThanOrEqual(ttlMs);
      // And it shrank by about the stall, which is the honest accounting.
      expect(remaining).toBeLessThanOrEqual(ttlMs - stallMs + 250);
      expect(remaining).toBeGreaterThanOrEqual(ttlMs - stallMs - 2_000);
    } finally {
      await metadata.close();
    }
  }, 60_000);

  test("SAFETY: a renewal that outlives its own claim is refused with PF001 and resurrects nothing", async () => {
    // The exact case the fixed 250 ms bound was reaching for, tested directly
    // instead of approximated by a constant: the claim's pre-existing expiry
    // passes WHILE the renewal's statement is stalled. Extending would
    // resurrect a dead claim that pfm.require_manager, pfm.verify_authority_
    // binding and every child's pfj.authority_lease_facts probe all read. It
    // must refuse, it must refuse as PF001 (provably dead -> the manager
    // fences immediately, rather than treating it as an unproven attempt),
    // and the extension must roll back so a successor can take over at once.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      // The shortest claim pfm.manager_claim accepts, so the claim genuinely
      // dies inside a stall that is still well under the 5 s lock_timeout.
      const claim = await claimManagerEpoch(1_000);
      const heartbeat = await openClient();
      const before = await claimRow(heartbeat);

      const holder = await stallTheClaimRow();
      const renewal = heartbeat.query(`SELECT pfm.manager_renew($1,$2,$3,$4) AS r`, [
        claim.epoch,
        claim.runtimeId,
        claim.capability,
        ttlMs,
      ]);
      // Longer than the claim's whole remaining life.
      await new Promise((resolve) => setTimeout(resolve, 3_000));
      await holder.query("ROLLBACK");

      await expect(renewal).rejects.toMatchObject({ code: "PF001" });

      const after = await claimRow(heartbeat);
      expect(after.expiresAt).toBe(before.expiresAt);
      expect(after.renewedAt).toBe(before.renewedAt);
    } finally {
      await metadata.close();
    }
  }, 60_000);

  test("SAFETY: a takeover that commits during a stalled renewal still supersedes it", async () => {
    // Mutual exclusion is decided by the row lock and the READ COMMITTED
    // EvalPlanQual re-check, never by a clock. pfm.manager_claim takes FOR
    // UPDATE, which conflicts with the renewal's FOR NO KEY UPDATE, so the
    // two serialize; the renewal then re-evaluates its identity predicates
    // against the LATEST committed row and finds a foreign epoch.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const first = await claimManagerEpoch();
      const heartbeat = await openClient();

      const taker = await openClient();
      await taker.query("BEGIN");
      await taker.query(`SELECT * FROM pfm.manager_claims WHERE singleton_key='manager' FOR UPDATE`);
      // Expire the old claim inside the takeover's transaction, exactly as a
      // real takeover observes it, then mint the successor epoch.
      await taker.query(
        `UPDATE pfm.manager_claims SET claimed_at=1, renewed_at=1, expires_at=2
          WHERE singleton_key='manager'`
      );

      const renewal = heartbeat.query(`SELECT pfm.manager_renew($1,$2,$3,$4) AS r`, [
        first.epoch,
        first.runtimeId,
        first.capability,
        ttlMs,
      ]);
      await new Promise((resolve) => setTimeout(resolve, 500));
      const successorRuntime = `mgr_${randomUUID()}`;
      const successorCapability = `cap-${randomUUID()}${randomUUID()}`;
      await taker.query(`SELECT pfm.manager_claim($1,$2,$3,$4) AS r`, [
        `op_${randomUUID()}`,
        successorRuntime,
        createHash("sha256").update(successorCapability, "utf8").digest("hex"),
        600_000,
      ]);
      await taker.query("COMMIT");

      await expect(renewal).rejects.toMatchObject({ code: "PF001" });

      // The successor's claim is intact — the stalled renewal wrote nothing.
      const row = await heartbeat.query<{ runtime_id: string }>(
        `SELECT runtime_id FROM pfm.manager_claims WHERE singleton_key='manager'`
      );
      expect(row.rows[0]?.runtime_id).toBe(successorRuntime);
    } finally {
      await metadata.close();
    }
  }, 60_000);

  test("SAFETY: a slow renewal never shortens the claim", async () => {
    // expires_at moves by GREATEST, so a renewal whose pre-write sample is
    // older than an existing longer grant leaves that grant alone.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const claim = await claimManagerEpoch();
      const heartbeat = await openClient();
      // A long grant first...
      await heartbeat.query(`SELECT pfm.manager_renew($1,$2,$3,$4) AS r`, [
        claim.epoch,
        claim.runtimeId,
        claim.capability,
        3_600_000,
      ]);
      const long = await claimRow(heartbeat);
      // ...then a short, stalled one.
      const holder = await stallTheClaimRow();
      const renewal = heartbeat.query(`SELECT pfm.manager_renew($1,$2,$3,$4) AS r`, [
        claim.epoch,
        claim.runtimeId,
        claim.capability,
        1_000,
      ]);
      await new Promise((resolve) => setTimeout(resolve, stallMs));
      await holder.query("ROLLBACK");
      await renewal;

      const after = await claimRow(heartbeat);
      expect(after.expiresAt).toBe(long.expiresAt);
    } finally {
      await metadata.close();
    }
  }, 60_000);

  test("the claim clock keeps advancing through a bulk write flood that saturates WAL", async () => {
    // THE LOAD-SHAPED COROLLARY. The three tests above stall the statement
    // deterministically; this one produces the real thing — many concurrent
    // large payload commits at synchronous_commit=on, each also taking the
    // append path's FOR KEY SHARE on the singleton claim row — and asserts
    // the invariant that matters: renewals at the manager's own cadence are
    // never refused, and expires_at advances strictly, for the whole flood.
    //
    // This is CORROBORATION, not the deterministic proof: whether it fails
    // under the 034 shape depends on whether the machine running it is slow
    // enough to push a single renewal's UPDATE past 250 ms (on a developer
    // box it is not; on the production instance it plainly was). The
    // deterministic failing-first proof is the stall harness above. What this
    // test adds is the shape of the real thing, and the assertion that under
    // 038 the outcome does not depend on how slow the database is at all.
    const metadata = new PostgresMetadataRepository(databaseUrl);
    try {
      await metadata.applyMigrations();
      const claim = await claimManagerEpoch(ttlMs);
      const heartbeat = await openClient();
      const admin = await openClient();
      await admin.query(
        `CREATE TABLE IF NOT EXISTS pfs_r21c_flood (id bigserial PRIMARY KEY, payload bytea)`
      );

      const floodConnections = 6;
      const payload = Buffer.alloc(4 * 1024 * 1024, 7);
      const stopAt = Date.now() + 8_000;
      const flood = Array.from({ length: floodConnections }, async () => {
        const client = await openClient();
        while (Date.now() < stopAt) {
          await client.query("BEGIN");
          // Exactly what pfj.require_manager_binding ->
          // pfm.verify_authority_binding does on every append.
          await client.query(`SELECT pfm.require_manager($1,$2,$3)`, [
            claim.epoch,
            claim.runtimeId,
            claim.capability,
          ]);
          await client.query(`INSERT INTO pfs_r21c_flood (payload) VALUES ($1)`, [payload]);
          await client.query("COMMIT");
        }
      });

      const refusals: string[] = [];
      let previousExpiry = (await claimRow(heartbeat)).expiresAt;
      let renewals = 0;
      while (Date.now() < stopAt) {
        try {
          const answer = await heartbeat.query<{ r: { dbTimeMs: string; expiresAtDbMs: string } }>(
            `SELECT pfm.manager_renew($1,$2,$3,$4) AS r`,
            [claim.epoch, claim.runtimeId, claim.capability, ttlMs]
          );
          const expiry = Number(answer.rows[0]?.r.expiresAtDbMs);
          const remaining = expiry - Number(answer.rows[0]?.r.dbTimeMs);
          // Every renewal hands back a usable window, however slow it was.
          expect(remaining).toBeGreaterThan(0);
          expect(remaining).toBeLessThanOrEqual(ttlMs);
          expect(expiry).toBeGreaterThanOrEqual(previousExpiry);
          previousExpiry = expiry;
          renewals += 1;
        } catch (error) {
          refusals.push(String((error as { code?: string }).code ?? error));
        }
        // The manager renews at TTL/3; sampling faster than that only makes
        // this a stricter test of the same invariant.
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      await Promise.all(flood);

      // THE INVARIANT: not one correct renewal was thrown away.
      expect(refusals).toEqual([]);
      expect(renewals).toBeGreaterThan(10);
    } finally {
      await metadata.close();
    }
  }, 120_000);
});
