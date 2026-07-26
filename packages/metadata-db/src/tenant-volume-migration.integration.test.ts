import { randomUUID } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { computeTreeHash } from "@portablefs/core";
import { protocolVersion } from "@portablefs/protocol";
import { describe, expect, test } from "vitest";
import { PostgresMetadataRepository } from "./postgres.js";

const runPostgresTests = process.env.PORTABLEFS_TEST_POSTGRES === "true";
const describePostgres = runPostgresTests ? describe : describe.skip;
const databaseUrl =
  process.env.VOLUME_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/portablefs";
const migrationsDirectory = fileURLToPath(new URL("../migrations/", import.meta.url));

describePostgres("023 tenant-scoped volume migration", () => {
  test("upgrades populated 022 data atomically and repeated migration startup is a no-op", async () => {
    const databaseName = `portablefs_tenant_upgrade_${randomUUID().replaceAll("-", "")}`;
    const quotedDatabaseName = `"${databaseName.replaceAll('"', '""')}"`;
    const target = new URL(databaseUrl);
    target.pathname = `/${databaseName}`;
    const admin = new pg.Pool({ connectionString: databaseUrl });
    await admin.query(`CREATE DATABASE ${quotedDatabaseName}`);

    const preUpgradePool = new pg.Pool({ connectionString: target.toString() });
    let metadata: PostgresMetadataRepository | undefined;
    try {
      await applyThrough022(preUpgradePool);
      await seedPopulated022(preUpgradePool);

      metadata = new PostgresMetadataRepository(target.toString());
      await metadata.applyMigrations();
      await metadata.applyMigrations();

      const receipt = await preUpgradePool.query(
        `SELECT count(*)::int AS count
         FROM portablefs_migrations
         WHERE id = '023_tenant_scoped_volume_identity'`
      );
      expect(receipt.rows[0]?.count).toBe(1);

      const publicChildren = [
        "commits",
        "branches",
        "attach_sessions",
        "leases",
        "snapshots",
        "packs",
        "path_delegations",
        "commit_receipts",
      ];
      for (const table of publicChildren) {
        const result = await preUpgradePool.query(
          `SELECT count(*)::int AS count
           FROM ${table}
           WHERE tenant_id = 'tenant-a' AND volume_id = 'shared-volume'`
        );
        expect(result.rows[0]?.count, table).toBe(1);
      }
      const generation = await preUpgradePool.query(
        `SELECT tenant_id, volume_id, branch_id
         FROM pfj.journal_generations
         WHERE id = 'generation-a'`
      );
      expect(generation.rows[0]).toEqual({
        tenant_id: "tenant-a",
        volume_id: "shared-volume",
        branch_id: "branch-a",
      });

      const other = await metadata.createVolume({
        tenantId: "tenant-b",
        volumeId: "shared-volume",
        branchName: "main",
      });
      expect(other.volume.tenantId).toBe("tenant-b");
      await expect(
        metadata.getStatus({
          tenantId: "tenant-a",
          volumeId: "shared-volume",
          branchName: "main",
        })
      ).resolves.toMatchObject({ volume: { tenantId: "tenant-a" } });
      await expect(
        metadata.getStatus({
          tenantId: "tenant-b",
          volumeId: "shared-volume",
          branchName: "main",
        })
      ).resolves.toMatchObject({ volume: { tenantId: "tenant-b" } });

      const mismatch = preUpgradePool.query(
        `INSERT INTO snapshots
         (id, tenant_id, volume_id, branch_id, commit_id, name, created_at)
         VALUES ('cross-tenant-snapshot', 'tenant-b', 'shared-volume',
                 'branch-a', 'commit-a', NULL, 2)`
      );
      await expect(mismatch).rejects.toMatchObject({ code: "23503" });
    } finally {
      await metadata?.close();
      await preUpgradePool.end();
      try {
        for (let attempt = 0; ; attempt += 1) {
          try {
            await admin.query(`DROP DATABASE IF EXISTS ${quotedDatabaseName}`);
            break;
          } catch (error) {
            if ((error as { code?: string }).code === "55006" && attempt < 50) {
              await new Promise((resolve) => setTimeout(resolve, 100));
              continue;
            }
            throw error;
          }
        }
      } finally {
        await admin.end();
      }
    }
  }, 240_000);
});

async function applyThrough022(pool: pg.Pool): Promise<void> {
  const files = (await readdir(migrationsDirectory))
    .filter((name) => /^\d{3}_.+\.sql$/.test(name) && name < "023_")
    .sort();
  expect(files.at(-1)).toBe("022_retire_cut_cleanup.sql");
  const client = await pool.connect();
  try {
    await client.query(
      `SELECT set_config('statement_timeout', '0', false),
              set_config('lock_timeout', '0', false),
              set_config('idle_in_transaction_session_timeout', '0', false)`
    );
    for (const file of files) {
      const id = file.slice(0, -4);
      const sql = await readFile(`${migrationsDirectory}/${file}`, "utf8");
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query(
          `INSERT INTO portablefs_migrations (id, applied_at) VALUES ($1, $2)`,
          [id, Date.now()]
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    }
  } finally {
    client.release(true);
  }
}

async function seedPopulated022(pool: pg.Pool): Promise<void> {
  const emptyManifest = {
    version: protocolVersion,
    entries: [],
    treeHash: computeTreeHash([]),
  };
  const zeroDigest = "0".repeat(64);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`INSERT INTO tenants (id, created_at) VALUES ('tenant-a', 1)`);
    await client.query(
      `INSERT INTO volumes (id, tenant_id, created_at)
       VALUES ('shared-volume', 'tenant-a', 1)`
    );
    await client.query(
      `INSERT INTO commits
       (id, volume_id, branch_id, parent_commit_id, tree_hash, manifest,
        mutation_count, byte_count, created_at, materialized_manifest,
        commit_kind)
       VALUES ('commit-a', 'shared-volume', 'branch-a', NULL, $1, $2,
               0, 0, 1, TRUE, 'manifest_v1')`,
      [emptyManifest.treeHash, JSON.stringify(emptyManifest)]
    );
    await client.query(
      `INSERT INTO branches
       (id, volume_id, name, head_commit_id, created_at, updated_at, branch_mode)
       VALUES ('branch-a', 'shared-volume', 'main', 'commit-a', 1, 1,
               'managed_journal')`
    );
    await client.query(
      `UPDATE volumes SET default_branch_id = 'branch-a'
       WHERE id = 'shared-volume'`
    );
    await client.query(
      `INSERT INTO attach_sessions
       (id, volume_id, branch_id, mode, base_commit_id, holder_id, status,
        client_info, attached_at, shared, root_path)
       VALUES ('session-a', 'shared-volume', 'branch-a', 'write', 'commit-a',
               'holder-a', 'attached', '{}'::jsonb, 1, FALSE, '')`
    );
    await client.query(
      `INSERT INTO leases
       (id, volume_id, branch_id, attach_session_id, holder_id, fencing_token,
        expires_at, exclusive)
       VALUES ('lease-a', 'shared-volume', 'branch-a', 'session-a', 'holder-a',
               1, 9999999999999, TRUE)`
    );
    await client.query(
      `INSERT INTO snapshots
       (id, volume_id, branch_id, commit_id, name, created_at)
       VALUES ('snapshot-a', 'shared-volume', 'branch-a', 'commit-a', 'base', 1)`
    );
    await client.query(
      `INSERT INTO packs
       (id, volume_id, object_key, blob_count, byte_count, created_at)
       VALUES ('pack-a', 'shared-volume', 'packs/a', 1, 1, 1)`
    );
    await client.query(
      `INSERT INTO path_delegations
       (id, volume_id, branch_id, attach_session_id, lease_id, holder_id,
        path, recursive, fencing_token, expires_at, created_at)
       VALUES ('delegation-a', 'shared-volume', 'branch-a', 'session-a',
               'lease-a', 'holder-a', '', TRUE, 1, 9999999999999, 1)`
    );
    await client.query(
      `INSERT INTO commit_receipts
       (operation_id, commit_id, volume_id, branch_id, request_fingerprint,
        created_at)
       VALUES ('operation-a', 'commit-a', 'shared-volume', 'branch-a', $1, 1)`,
      ["f".repeat(64)]
    );
    await client.query(
      `INSERT INTO pfj.journal_generations
       (id, tenant_id, volume_id, branch_id, epoch, record_codec,
        control_codec, base_commit_id, base_seq, base_digest, next_seq,
        tip_digest, physical_trimmed_seq, status, backlog_bytes,
        backlog_records, quota_backlog_bytes, quota_backlog_records,
        created_at, updated_at)
       VALUES ('generation-a', 'tenant-a', 'shared-volume', 'branch-a', 1,
               'pfj3', 'pfc2', 'commit-a', 0, $1, 0, $1, 0, 'active',
               0, 0, 1048576, 1048576, 1, 1)`,
      [zeroDigest]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
