#!/usr/bin/env node

// run-migration-gate.mjs — one-shot metadata migration gate for deploys.
//
// What this is: a standalone pre-deploy job that applies the PortableFS
// metadata migrations through the EXISTING repository code path
// (PostgresMetadataRepository.applyMigrations()) and then re-verifies the
// applied lineage against the shipped migration files: every
// packages/metadata-db/migrations/*.sql this build carries must hold a
// receipt row in public.portablefs_migrations. It exits 0 only when
// migrations applied AND the lineage is complete AND the migration-016
// timeout defaults are attested from their authoritative source
// (pg_db_role_setting database defaults — see below); any other outcome is
// a nonzero exit with a one-line error. It changes NO runtime behavior:
// volume-api and volume-worker keep running applyMigrations() at startup,
// so their startup migrations remain the safety net — this gate only moves
// the same work earlier in the deploy so a bad migration fails the deploy
// instead of the service fleet.
//
// 016 attestation model:
//   PRIMARY: pg_db_role_setting rows with setrole = 0 for the target
//     database — the literal ALTER DATABASE ... SET storage that migration
//     016 writes. Session-effective values (pg_settings) can be satisfied by
//     ALTER ROLE / DSN options= / other session sources even when the
//     database defaults are absent, so they are NOT the primary evidence.
//   SECONDARY (diagnostic only): a fresh session's effective pg_settings
//     values, printed for comparison; a divergence here with a passing
//     primary means a role/session-level source is shadowing the defaults
//     for THIS login.
//   The gate additionally scans pg_db_role_setting for role-specific
//   (setrole <> 0) overrides of the three timeouts that apply in the target
//   database. Overrides on the JOURNAL roles — the capability roles named
//   by PORTABLEFS_MIGRATION_JOURNAL_ROLES (default portablefs_authority)
//   PLUS every LOGIN role that inherits them (discovered recursively via
//   pg_auth_members; migration 009's capability/login split means the
//   production journal LOGIN is a member, and ALTER ROLE settings apply
//   only at that login's own login) — FAIL the gate when they differ from
//   the 016 targets; same-valued journal overrides and any other role's
//   overrides WARN. Empty or unknown role names fail closed.
//
// DSN requirements: PORTABLEFS_MIGRATION_DATABASE_URL must be a DIRECT
// PostgreSQL connection — NEVER a transaction-mode pooler endpoint. The
// migration runner serializes concurrent appliers with a SESSION advisory
// lock (pg_advisory_lock); a transaction pooler may execute the unlock on a
// different server session, stranding the lock and blocking every future
// applyMigrations() fleet-wide. The gate runs a BEST-EFFORT direct-endpoint
// probe before migrating (pg_backend_pid() stability + session SET
// visibility across ~20 alternating simple statements). An active
// transaction pooler usually diverges under that probe, but an IDLE pooler
// (or any session-mode pooler) can pass it — the probe is a tripwire, not a
// proof. Separately provisioned, separately NAMED direct credentials remain
// the real control.
//
// Railway usage: run as a one-shot pre-deploy job with restartPolicyType
// NEVER (a crash-looping migration job must surface as a failed deploy, not
// retry forever against a wedged advisory lock). The repo must be built
// (`pnpm build`) before invocation:
//
//   pnpm build
//   PORTABLEFS_MIGRATION_DATABASE_URL=postgres://... node scripts/run-migration-gate.mjs
//
// Environment:
//   PORTABLEFS_MIGRATION_DATABASE_URL       required direct DSN (see above).
//   PORTABLEFS_MIGRATION_APPLICATION_NAME   optional application_name
//                                           (default "portablefs-migrate").
//   PORTABLEFS_MIGRATION_CONNECT_TIMEOUT_MS optional integer 1..3600000
//                                           (default 10000).
//   PORTABLEFS_MIGRATION_JOURNAL_ROLES      optional comma list (default
//                                           portablefs_authority): journal
//                                           capability/login roles whose
//                                           divergent timeout overrides
//                                           FAIL the gate (LOGIN members
//                                           are discovered automatically;
//                                           empty/unknown names fail).
//   PORTABLEFS_MIGRATION_DEADLINE_MS        optional integer 1..86400000
//                                           (default 600000). Whole-gate
//                                           deadline: on expiry the gate
//                                           reports the advisory-lock holder
//                                           (pid / application_name / state)
//                                           and exits 1 instead of hanging a
//                                           deploy forever behind a stranded
//                                           pg_advisory_lock.
//   PORTABLEFS_MIGRATION_SSL                optional: require | no-verify.
//                                           A typo fails loudly, never
//                                           silently disables TLS (same
//                                           semantics as VOLUME_DATABASE_SSL).
//                                           Mutually exclusive with DSN ssl
//                                           parameters: node-postgres lets
//                                           sslmode/sslcert/sslkey/sslrootcert
//                                           in the connection string override
//                                           a supplied ssl object, so the
//                                           gate hard-errors on the conflict
//                                           instead of letting the DSN win
//                                           silently.

import process from "node:process";
import { createRequire } from "node:module";
import { readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

// Migration 016 (016_pooler_timeouts.sql) installs these as ALTER DATABASE
// defaults so transaction-pooled clients inherit real server-side ceilings.
const expectedTimeoutDefaults = [
  { name: "statement_timeout", ms: 30_000, human: "30s" },
  { name: "lock_timeout", ms: 5_000, human: "5s" },
  { name: "idle_in_transaction_session_timeout", ms: 60_000, human: "60s" },
];

// Advisory lock keys used by applyMigrations() — MUST match
// packages/metadata-db/src/postgres.ts (migrationLockClassId /
// migrationLockObjectId, two-key int4 form of pg_advisory_lock).
const migrationLockClassId = 0x70_66_73_21; // "pfs!"
const migrationLockObjectId = 0x6d_69_67_72; // "migr"

// The shipped lineage is enumerated from the SAME directory the built
// repository code reads: readMigrationSql() in
// packages/metadata-db/dist resolves ../migrations relative to the dist
// (i.e. packages/metadata-db/migrations, present both in the repo and in
// the volume-api runtime image), falling back to ../../migrations
// (packages/migrations, the image's second copy). The gate enumerates the
// primary location so the asserted lineage is exactly what the dist will
// apply.
const migrationsDirUrl = new URL("../packages/metadata-db/migrations/", import.meta.url);

function fail(message) {
  console.error(`migration-gate: FAILED: ${message}`);
  process.exit(1);
}

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    fail(`${name} is required.`);
  }
  return value;
}

// A typo, NaN, precision-losing, or out-of-bounds value is a startup
// failure, never a silent default: digits-only, Number.isSafeInteger, and
// explicit practical bounds.
function intEnv(name, fallback, { min, max }) {
  const raw = process.env[name]?.trim();
  if (raw === undefined || raw === "") {
    return fallback;
  }
  if (!/^[0-9]+$/.test(raw)) {
    fail(`${name} must be a positive integer, got "${raw}".`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail(`${name} must be an integer between ${min} and ${max}, got "${raw}".`);
  }
  return value;
}

const dsnSslParamNames = ["sslmode", "sslcert", "sslkey", "sslrootcert"];

// node-postgres parses connection-string SSL parameters into the final
// config, REPLACING a supplied ssl object. The gate therefore refuses to
// run when both sources are present, and states which single source is in
// effect otherwise.
function resolveSslPolicy(databaseUrl) {
  const mode = process.env.PORTABLEFS_MIGRATION_SSL?.trim();
  let dsnParams = [];
  let dsnParseable = true;
  try {
    const url = new URL(databaseUrl);
    dsnParams = dsnSslParamNames
      .filter((p) => url.searchParams.has(p))
      .map((p) => `${p}=${url.searchParams.get(p)}`);
  } catch {
    dsnParseable = false;
  }
  if (mode && dsnParams.length > 0) {
    fail(
      `TLS configuration conflict: the DSN carries ${dsnParams.join(", ")} AND ` +
        `PORTABLEFS_MIGRATION_SSL=${mode} is set. node-postgres lets DSN ssl ` +
        `parameters silently override the ssl object built from the environment, ` +
        `so these two sources cannot be combined safely. Remove the ssl ` +
        `parameters from the DSN or unset PORTABLEFS_MIGRATION_SSL.`,
    );
  }
  if (mode !== undefined && mode !== "") {
    if (mode === "require") {
      return {
        options: { ssl: { rejectUnauthorized: true } },
        sourceLine: "TLS policy source: PORTABLEFS_MIGRATION_SSL=require (verify-full semantics).",
      };
    }
    if (mode === "no-verify") {
      return {
        options: { ssl: { rejectUnauthorized: false } },
        sourceLine: "TLS policy source: PORTABLEFS_MIGRATION_SSL=no-verify (encrypted, unverified chain).",
      };
    }
    fail("PORTABLEFS_MIGRATION_SSL must be require, no-verify, or unset.");
  }
  if (dsnParams.length > 0) {
    return {
      options: {},
      sourceLine: `TLS policy source: DSN parameters (${dsnParams.join(", ")}); PORTABLEFS_MIGRATION_SSL is unset.`,
    };
  }
  return {
    options: {},
    sourceLine: dsnParseable
      ? "TLS policy source: driver defaults (no DSN ssl parameters, PORTABLEFS_MIGRATION_SSL unset)."
      : "TLS policy source: driver defaults (DSN not URL-parseable for inspection; PORTABLEFS_MIGRATION_SSL unset).",
  };
}

// The metadata-db package is consumed through its BUILT output. A missing
// dist is an explicit, actionable failure instead of a raw module-not-found
// stack.
async function loadMetadataDb() {
  try {
    return await import("../packages/metadata-db/dist/index.js");
  } catch (error) {
    fail(
      `could not load packages/metadata-db/dist — run "pnpm build" first ` +
        `(${error instanceof Error ? error.message : String(error)})`,
    );
  }
}

// pg is a dependency of @portablefs/metadata-db, not of the workspace root,
// so resolve it exactly as the built package would — the same installed
// version, without adding a duplicate root dependency.
function loadPg() {
  const requireFromMetadataDb = createRequire(
    new URL("../packages/metadata-db/dist/index.js", import.meta.url),
  );
  return requireFromMetadataDb("pg");
}

// Best-effort direct-endpoint tripwire. One client runs ~20 alternating
// simple statements; each statement outside a transaction is its own
// implicit transaction, so an ACTIVE transaction-mode pooler tends to run
// them on different server sessions — pg_backend_pid() moves, or the
// session-level SET application_name stops being visible. Honest limits: an
// idle transaction pooler can pin one server connection for the whole probe
// and pass, and a session-mode pooler always passes. This is a tripwire
// only; separately named direct credentials are the real control.
async function probeDirectEndpoint({ Client, databaseUrl, sslOptions, applicationName, connectTimeoutMs }) {
  // The marker is FULLY internal (no environment-derived prefix) and is
  // applied via a parameterized set_config() call — never interpolated into
  // SQL text. An observability label must not be able to become owner-
  // privileged SQL, so no env-controlled value participates here at all.
  const probeMarker = `pfs-gate-probe-${Math.floor(Math.random() * 1e9).toString(36)}`;
  const client = new Client({
    connectionString: databaseUrl,
    application_name: `${applicationName}-direct-probe`,
    connectionTimeoutMillis: connectTimeoutMs,
    ...sslOptions,
  });
  await client.connect();
  try {
    // Session-level set_config(..., false) (not transaction-local): must
    // remain visible in later statements on a genuinely direct session.
    await client.query(`SELECT set_config('application_name', $1, false)`, [probeMarker]);
    let basePid;
    const poolerCopy =
      "PORTABLEFS_MIGRATION_DATABASE_URL does not behave like a direct " +
      "PostgreSQL session — this is the signature of a transaction-mode " +
      "pooler handing statements to different server sessions. The gate " +
      "takes a SESSION advisory lock and MUST NOT run through a pooler: a " +
      "stranded lock would block every future applyMigrations() fleet-wide. " +
      "Point the gate at the separately named DIRECT credentials.";
    for (let i = 0; i < 20; i += 1) {
      const sql =
        i % 2 === 0
          ? "SELECT pg_backend_pid() AS pid, current_setting('application_name') AS app"
          : "SELECT current_setting('application_name') AS app, pg_backend_pid() AS pid";
      const result = await client.query(sql);
      const { pid, app } = result.rows[0];
      if (basePid === undefined) {
        basePid = pid;
      }
      if (pid !== basePid) {
        throw new Error(
          `direct-endpoint probe: pg_backend_pid() changed from ${basePid} to ${pid} ` +
            `on statement ${i + 1}/20. ${poolerCopy}`,
        );
      }
      if (app !== probeMarker) {
        throw new Error(
          `direct-endpoint probe: session-level SET application_name was not visible ` +
            `on statement ${i + 1}/20 (expected "${probeMarker}", saw "${app}"). ${poolerCopy}`,
        );
      }
    }
    console.log(
      `migration-gate: direct-endpoint probe ok (pg_backend_pid()=${basePid} stable, ` +
        `session SET visible across 20 statements). Best-effort only: an idle ` +
        `pooler can pass this probe — direct credentials remain the real control.`,
    );
  } finally {
    try {
      await client.end();
    } catch {
      // Probe connection teardown must never mask the verdict.
    }
  }
}

// Lineage verification. This repository's PostgresMetadataRepository has no
// control-plane probe, so the gate re-derives the expected lineage from the
// artifact itself: every *.sql FILE directly in the shipped migrations
// directory (subdirectories such as future/ are excluded — readMigrationSql
// only ever reads flat <id>.sql names), sorted, is asserted to hold a
// receipt row in public.portablefs_migrations (the receipts table
// applyMigrations() maintains: id TEXT PRIMARY KEY, applied_at BIGINT).
// Receipts the database carries BEYOND the shipped files only WARN: a
// database ahead of this build is the normal mid-rollback shape, and the
// runtime tolerates additive unknown receipts.
async function verifyMigrationLineage({ Pool, databaseUrl, sslOptions, applicationName, connectTimeoutMs }) {
  let entries;
  try {
    entries = await readdir(migrationsDirUrl, { withFileTypes: true });
  } catch (error) {
    throw new Error(
      `could not enumerate shipped migrations at ${fileURLToPath(migrationsDirUrl)} ` +
        `(${error instanceof Error ? error.message : String(error)}) — the gate must run ` +
        `from a checkout or image that carries packages/metadata-db/migrations.`,
    );
  }
  const shippedIds = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".sql"))
    .map((entry) => entry.name.slice(0, -".sql".length))
    .sort();
  if (shippedIds.length === 0) {
    throw new Error(
      `no *.sql migration files found in ${fileURLToPath(migrationsDirUrl)} — ` +
        `an empty lineage can never be attested; the artifact is broken.`,
    );
  }
  const lineage = new Pool({
    connectionString: databaseUrl,
    max: 1,
    application_name: `${applicationName}-lineage`,
    connectionTimeoutMillis: connectTimeoutMs,
    ...sslOptions,
  });
  try {
    const receipts = await lineage.query(`SELECT id FROM public.portablefs_migrations`);
    const receiptIds = new Set(receipts.rows.map((row) => row.id));
    const missing = shippedIds.filter((id) => !receiptIds.has(id));
    if (missing.length > 0) {
      throw new Error(
        `applied lineage is incomplete: ${missing.length} of ${shippedIds.length} shipped ` +
          `migration(s) have no receipt in public.portablefs_migrations: ` +
          `${missing.join(", ")}. applyMigrations() reported success, so a receipt this ` +
          `build ships but did not write means the shipped files and the built ` +
          `migration list have drifted — fix the artifact, do not deploy.`,
      );
    }
    const unknownReceipts = [...receiptIds].filter((id) => !shippedIds.includes(id)).sort();
    if (unknownReceipts.length > 0) {
      console.error(
        `migration-gate: WARN: the database carries ${unknownReceipts.length} receipt(s) ` +
          `beyond this build's shipped lineage (${unknownReceipts.join(", ")}) — a ` +
          `database ahead of the artifact is expected mid-rollback; verify this deploy ` +
          `is intentionally older.`,
      );
    }
    console.log(
      `migration-gate: migration lineage verified: ${shippedIds.length}/${shippedIds.length} ` +
        `shipped migrations have receipts in public.portablefs_migrations ` +
        `(${shippedIds[0]} .. ${shippedIds[shippedIds.length - 1]}).`,
    );
  } finally {
    await lineage.end();
  }
}

// Parses pg_db_role_setting setconfig values like "30s", "30000ms", "30000"
// into milliseconds. The three timeout GUCs default to milliseconds when the
// stored value carries no unit.
function timeoutSettingToMs(raw) {
  const match = /^(\d+(?:\.\d+)?)\s*(us|ms|s|min|h|d)?$/.exec(String(raw).trim());
  if (!match) {
    return undefined;
  }
  const factor = { us: 1 / 1000, ms: 1, s: 1000, min: 60_000, h: 3_600_000, d: 86_400_000 }[
    match[2] ?? "ms"
  ];
  return Number.parseFloat(match[1]) * factor;
}

// Primary attestation reads the AUTHORITATIVE storage of migration 016 —
// pg_db_role_setting rows with setrole = 0 for the target database (what
// ALTER DATABASE ... SET writes). It also scans for role-specific overrides
// that shadow those defaults, and keeps the fresh-session effective check as
// a labeled SECONDARY diagnostic.
async function verifyTimeoutAttestation({ Pool, databaseUrl, sslOptions, applicationName, connectTimeoutMs }) {
  const settingNames = expectedTimeoutDefaults.map((entry) => entry.name);
  // A dedicated single-connection pool guarantees the session was
  // established AFTER migrations ran (ALTER DATABASE affects new sessions
  // only), which also makes the secondary diagnostic meaningful.
  const attest = new Pool({
    connectionString: databaseUrl,
    max: 1,
    application_name: `${applicationName}-016-attest`,
    connectionTimeoutMillis: connectTimeoutMs,
    ...sslOptions,
  });
  try {
    // -- PRIMARY: database defaults in pg_db_role_setting (setrole = 0). --
    const defaults = await attest.query(
      `SELECT split_part(cfg, '=', 1) AS name,
              substr(cfg, strpos(cfg, '=') + 1) AS value
         FROM pg_db_role_setting s
         JOIN pg_database d ON d.oid = s.setdatabase
        CROSS JOIN LATERAL unnest(s.setconfig) AS cfg
        WHERE s.setrole = 0
          AND d.datname = current_database()
          AND split_part(cfg, '=', 1) = ANY($1)`,
      [settingNames],
    );
    const observedDefaults = new Map(defaults.rows.map((row) => [row.name, row.value]));
    let primaryError;
    const receipt = [];
    for (const expected of expectedTimeoutDefaults) {
      const value = observedDefaults.get(expected.name);
      const valueMs = value === undefined ? undefined : timeoutSettingToMs(value);
      if (valueMs !== expected.ms) {
        primaryError = new Error(
          `pg_db_role_setting has ${expected.name}=` +
            `${value === undefined ? "(no database default)" : value} for this database ` +
            `(setrole=0) but migration 016_pooler_timeouts requires ${expected.ms}ms ` +
            `(${expected.human}). The database-owned defaults from 016 are absent or ` +
            `drifted — session-effective values from other sources (ALTER ROLE, DSN ` +
            `options) do NOT count. Re-apply/repair the 016 ALTER DATABASE defaults ` +
            `before deploying pooled clients.`,
        );
        break;
      }
      receipt.push(`${expected.name}=${expected.human}`);
    }
    if (primaryError === undefined) {
      console.log(
        `migration-gate: 016 attestation receipt (SOURCE: database defaults — ` +
          `pg_db_role_setting setrole=0 for the target database): ${receipt.join(" ")}`,
      );
    }

    // -- Role-specific overrides that SHADOW the database defaults. --
    // Includes setdatabase=0 rows (ALTER ROLE ... SET without IN DATABASE):
    // both scopes take precedence over database defaults for that login.
    const overrides = await attest.query(
      `SELECT r.rolname,
              CASE WHEN s.setdatabase = 0
                   THEN 'all databases (ALTER ROLE ... SET)'
                   ELSE 'this database (ALTER ROLE ... IN DATABASE ... SET)'
              END AS scope,
              cfg
         FROM pg_db_role_setting s
         JOIN pg_roles r ON r.oid = s.setrole
        CROSS JOIN LATERAL unnest(s.setconfig) AS cfg
        WHERE s.setrole <> 0
          AND (s.setdatabase = 0
               OR s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()))
          AND split_part(cfg, '=', 1) = ANY($1)
        ORDER BY r.rolname, cfg`,
      [settingNames],
    );
    // Role overrides SHADOW the database defaults for that login's fresh
    // sessions. For the PRODUCTION JOURNAL ROLES (the logins whose pooled
    // sessions deliberately drop their client-side timeout GUCs and depend
    // entirely on these defaults), an override whose value DIFFERS from the
    // 016 target is a hard failure — a warning is not enforceable in an
    // unattended CI/Railway gate. A same-valued override is tolerated with
    // a WARN (redundant but not unsafe). Overrides on any OTHER role only
    // WARN: they never govern the journal's pooled sessions.
    // Journal-role identity resolution — FAIL CLOSED. Migration 009 defines
    // portablefs_authority as a NOLOGIN capability role: production creates
    // a separate per-environment LOGIN role and GRANTs it the capability.
    // PostgreSQL applies ALTER ROLE ... SET only when THAT role logs in —
    // a capability role's settings never reach its members' sessions — so
    // the enforced set must be the capability roles PLUS every LOGIN role
    // that inherits them (discovered recursively via pg_auth_members).
    // Explicitly named roles must exist, and an explicitly empty list is an
    // error: a typo or blank value must never silently downgrade the hard
    // check to warnings.
    const rawJournalRolesEnv = process.env.PORTABLEFS_MIGRATION_JOURNAL_ROLES;
    const explicitJournalNames = (rawJournalRolesEnv ?? "portablefs_authority")
      .split(",")
      .map((role) => role.trim())
      .filter((role) => role.length > 0);
    if (explicitJournalNames.length === 0) {
      throw new Error(
        `PORTABLEFS_MIGRATION_JOURNAL_ROLES is set but names no roles — refusing to run ` +
          `with an empty journal-role list (that would silently disable the role-override ` +
          `hard check). Unset it to use the default (portablefs_authority) or name the ` +
          `journal capability/login roles explicitly.`,
      );
    }
    const knownRoles = await attest.query(
      `SELECT rolname FROM pg_roles WHERE rolname = ANY($1)`,
      [explicitJournalNames],
    );
    const knownRoleNames = new Set(knownRoles.rows.map((row) => row.rolname));
    const unknownRoles = explicitJournalNames.filter((name) => !knownRoleNames.has(name));
    if (unknownRoles.length > 0) {
      throw new Error(
        `journal role(s) not found in pg_roles: ${unknownRoles.join(", ")}. A misspelled ` +
          `or missing role would silently exempt the real journal login from the ` +
          `override hard check — refusing to fail open. Fix ` +
          `PORTABLEFS_MIGRATION_JOURNAL_ROLES or create the role first.`,
      );
    }
    const journalLogins = await attest.query(
      `WITH RECURSIVE grantees AS (
         SELECT am.member
           FROM pg_auth_members am
           JOIN pg_roles cap ON cap.oid = am.roleid
          WHERE cap.rolname = ANY($1)
         UNION
         SELECT am.member
           FROM pg_auth_members am
           JOIN grantees g ON am.roleid = g.member
       )
       SELECT r.rolname
         FROM pg_roles r
         JOIN grantees g ON r.oid = g.member
        WHERE r.rolcanlogin`,
      [explicitJournalNames],
    );
    const journalRoles = new Set([
      ...explicitJournalNames,
      ...journalLogins.rows.map((row) => row.rolname),
    ]);
    if (journalLogins.rows.length > 0) {
      console.log(
        `migration-gate: journal override hard-check covers LOGIN member(s) ` +
          `${journalLogins.rows.map((row) => row.rolname).join(", ")} of ` +
          `${explicitJournalNames.join(", ")} (discovered via pg_auth_members).`,
      );
    } else {
      console.log(
        `migration-gate: no LOGIN members of ${explicitJournalNames.join(", ")} found — ` +
          `expected in dev/rehearsal databases. Production's journal login must be ` +
          `GRANTed the capability role (migration 009); once granted it is discovered ` +
          `and hard-checked here automatically.`,
      );
    }
    const requiredMsBySetting = new Map(
      expectedTimeoutDefaults.map((expected) => [expected.name, expected.ms]),
    );
    let overrideError;
    for (const row of overrides.rows) {
      const name = String(row.cfg).slice(0, String(row.cfg).indexOf("="));
      const value = String(row.cfg).slice(String(row.cfg).indexOf("=") + 1);
      const requiredMs = requiredMsBySetting.get(name);
      const valueMs = timeoutSettingToMs(value);
      const isJournalRole = journalRoles.has(row.rolname);
      if (isJournalRole && valueMs !== requiredMs) {
        overrideError ??= new Error(
          `journal role "${row.rolname}" carries a role-level override "${row.cfg}" ` +
            `(scoped to ${row.scope}) that DIFFERS from the 016 target of ${requiredMs}ms. ` +
            `Pooled journal sessions for that role would run with the unsafe override, ` +
            `not the database default — drop the override (ALTER ROLE ... RESET ${name}) ` +
            `or set it to the required value. Journal roles checked: ` +
            `${[...journalRoles].join(", ")} (override with PORTABLEFS_MIGRATION_JOURNAL_ROLES).`,
        );
        console.error(`migration-gate: FAILING: ${overrideError.message}`);
      } else {
        console.error(
          `migration-gate: WARN: role "${row.rolname}" carries a role-level override ` +
            `"${row.cfg}" scoped to ${row.scope}` +
            (isJournalRole
              ? ` — same value as the 016 target (redundant but tolerated).`
              : `. Role-level settings SHADOW the migration-016 database defaults for ` +
                `sessions of that role — verify this override is intentional.`),
        );
      }
    }

    // -- SECONDARY diagnostic: fresh-session effective values. --
    // pg_settings reports session-effective values in ms for these GUCs.
    // This is evidence about THIS login's sessions only — role/session
    // sources can shadow the database defaults — so a divergence here warns
    // loudly but the pg_db_role_setting check above stays authoritative.
    const effective = await attest.query(
      `SELECT name, setting, unit FROM pg_settings WHERE name = ANY($1) ORDER BY name`,
      [settingNames],
    );
    const observedEffective = new Map(effective.rows.map((row) => [row.name, row]));
    const effectiveReport = [];
    let effectiveDiverged = false;
    for (const expected of expectedTimeoutDefaults) {
      const row = observedEffective.get(expected.name);
      const ok = row !== undefined && row.setting === String(expected.ms) && row.unit === "ms";
      if (!ok) {
        effectiveDiverged = true;
      }
      effectiveReport.push(
        `${expected.name}=${row ? `${row.setting}${row.unit ?? ""}` : "(missing)"}` +
          (ok ? "" : ` (expected ${expected.ms}ms)`),
      );
    }
    console.log(
      `migration-gate: secondary diagnostic (fresh-session effective values, ` +
        `pg_settings — session-scoped evidence only): ${effectiveReport.join(" ")}`,
    );
    if (effectiveDiverged) {
      console.error(
        `migration-gate: WARN: fresh-session effective values diverge from the 016 ` +
          `targets for THIS login — a role-level or connection-level source is ` +
          `shadowing the database defaults here. Diagnostic only; the ` +
          `pg_db_role_setting attestation above is authoritative.`,
      );
    }

    if (primaryError !== undefined) {
      throw primaryError;
    }
    if (overrideError !== undefined) {
      throw overrideError;
    }
  } finally {
    await attest.end();
  }
}

// Deadline path: identify who holds (or waits on) the migration advisory
// lock so a deploy operator gets an actionable pid/application_name instead
// of a bare timeout. Strictly bounded and best-effort — diagnostics must
// never extend the hang they are diagnosing.
async function reportAdvisoryLockHolders({ databaseUrl, sslOptions, applicationName }) {
  let diag;
  try {
    const { Pool } = loadPg();
    diag = new Pool({
      connectionString: databaseUrl,
      max: 1,
      application_name: `${applicationName}-deadline-diag`,
      connectionTimeoutMillis: 5_000,
      statement_timeout: 5_000,
      query_timeout: 5_000,
      ...sslOptions,
    });
    const result = await diag.query(
      `SELECT l.pid,
              l.granted,
              coalesce(a.application_name, '(restricted or gone)') AS application_name,
              coalesce(a.state, '(restricted or gone)') AS state,
              coalesce(a.usename, '(restricted or gone)') AS usename,
              coalesce(a.backend_start::text, '(unknown)') AS backend_start
         FROM pg_locks l
         LEFT JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype = 'advisory'
          AND l.classid = $1
          AND l.objid = $2
          AND l.objsubid = 2
          AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
        ORDER BY l.granted DESC, l.pid`,
      [migrationLockClassId, migrationLockObjectId],
    );
    if (result.rows.length === 0) {
      console.error(
        "migration-gate: deadline diagnostics: no session holds or awaits the " +
          "migration advisory lock (classid=0x70667321, objid=0x6d696772) — the gate " +
          "was slow for another reason (network, long migration DDL, probe).",
      );
      return;
    }
    for (const row of result.rows) {
      console.error(
        `migration-gate: deadline diagnostics: advisory lock ` +
          `${row.granted ? "HOLDER" : "waiter"} pid=${row.pid} ` +
          `application_name=${row.application_name} state=${row.state} ` +
          `user=${row.usename} backend_start=${row.backend_start}`,
      );
    }
  } catch (error) {
    console.error(
      `migration-gate: deadline diagnostics unavailable ` +
        `(${error instanceof Error ? error.message : String(error)}).`,
    );
  } finally {
    if (diag) {
      try {
        await diag.end();
      } catch {
        // Best-effort teardown; the process exits immediately after.
      }
    }
  }
}

class GateDeadlineError extends Error {}

async function runGate({ databaseUrl, applicationName, connectTimeoutMs, ssl }) {
  const { PostgresMetadataRepository } = await loadMetadataDb();
  const pg = loadPg();

  await probeDirectEndpoint({
    Client: pg.Client,
    databaseUrl,
    sslOptions: ssl.options,
    applicationName,
    connectTimeoutMs,
  });

  // Mirrors the volume-api construction (apps/volume-api/src/main.ts) with a
  // deliberately tiny pool: the gate needs one migration session plus one
  // verification round-trip, never a serving fleet's worth.
  const metadata = new PostgresMetadataRepository({
    connectionString: databaseUrl,
    connectionTimeoutMillis: connectTimeoutMs,
    max: 2,
    application_name: applicationName,
    ...ssl.options,
  });

  try {
    console.log("migration-gate: applying metadata migrations.");
    await metadata.applyMigrations();
    console.log("migration-gate: metadata migrations are ready.");

    await verifyMigrationLineage({
      Pool: pg.Pool,
      databaseUrl,
      sslOptions: ssl.options,
      applicationName,
      connectTimeoutMs,
    });

    await verifyTimeoutAttestation({
      Pool: pg.Pool,
      databaseUrl,
      sslOptions: ssl.options,
      applicationName,
      connectTimeoutMs,
    });
    console.log("migration-gate: ok");
  } finally {
    // The repository is ALWAYS closed, success or failure — a leaked pool
    // would keep the one-shot job's process alive past its verdict.
    await metadata.close();
  }
}

// Environment parsing happens synchronously up front so a bad value fails in
// milliseconds, before the deadline race starts.
const databaseUrl = requiredEnv("PORTABLEFS_MIGRATION_DATABASE_URL");
const applicationName =
  process.env.PORTABLEFS_MIGRATION_APPLICATION_NAME?.trim() || "portablefs-migrate";
const connectTimeoutMs = intEnv("PORTABLEFS_MIGRATION_CONNECT_TIMEOUT_MS", 10_000, {
  min: 1,
  max: 3_600_000,
});
const deadlineMs = intEnv("PORTABLEFS_MIGRATION_DEADLINE_MS", 600_000, {
  min: 1,
  max: 86_400_000,
});
const ssl = resolveSslPolicy(databaseUrl);
console.log(`migration-gate: ${ssl.sourceLine}`);
console.log(`migration-gate: whole-gate deadline ${deadlineMs}ms (PORTABLEFS_MIGRATION_DEADLINE_MS).`);

// The ENTIRE gate races one deadline. On expiry: print the advisory-lock
// holder, then exit(1) unconditionally — never leave a deploy hanging behind
// a stranded pg_advisory_lock. The timer is unref'd and cleared so it can
// never keep the process alive itself, and success exits explicitly so a
// leaked handle in a dependency cannot either.
let deadlineTimer;
const deadline = new Promise((_resolve, reject) => {
  deadlineTimer = setTimeout(() => {
    reject(new GateDeadlineError(`deadline of ${deadlineMs}ms expired`));
  }, deadlineMs);
  deadlineTimer.unref?.();
});

try {
  await Promise.race([runGate({ databaseUrl, applicationName, connectTimeoutMs, ssl }), deadline]);
  clearTimeout(deadlineTimer);
  process.exit(0);
} catch (error) {
  clearTimeout(deadlineTimer);
  if (error instanceof GateDeadlineError) {
    console.error(
      `migration-gate: deadline of ${deadlineMs}ms (PORTABLEFS_MIGRATION_DEADLINE_MS) ` +
        `expired before the gate finished. Collecting advisory-lock diagnostics ` +
        `(classid=0x70667321 "pfs!", objid=0x6d696772 "migr") ...`,
    );
    await reportAdvisoryLockHolders({ databaseUrl, sslOptions: ssl.options, applicationName });
    fail(`deadline of ${deadlineMs}ms expired — failing the deploy instead of hanging.`);
  }
  fail(error instanceof Error ? error.message : String(error));
}
