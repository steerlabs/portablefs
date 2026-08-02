import { createVolumeApiServer, type HttpServerDefenses } from "./server.js";
import { intEnv as intEnvOf, semverEnv } from "./config.js";
import {
  HistoryMaintenanceLoop,
  historyMaintenanceSettingsFromEnv,
} from "./history-maintenance.js";
import { historyStoreRegistryFromEnv } from "./history-stores.js";
import { ControlReadiness } from "./readiness.js";
import { loadVolumeApiReleaseIdentity } from "./release-identity.js";
import { installSignalHandlers, VolumeApiRuntime } from "./runtime.js";
import {
  applyMigrationsUntilReady,
  startupMigrationBudgetFromEnv,
} from "./startup-migrations.js";
import { createTelemetry, stdoutTelemetrySink } from "./telemetry.js";
import type { BlobStore } from "@portablefs/core";
import { PostgresMetadataRepository } from "@portablefs/metadata-db";
import {
  FilesystemBlobStore,
  filesystemBlobStoreConfigFromEnv,
} from "@portablefs/storage-filesystem";
import { S3BlobStore, s3ConfigFromEnv } from "@portablefs/storage-s3";

const databaseUrl = requiredEnv("VOLUME_DATABASE_URL");
const port = Number(process.env.PORT || process.env.VOLUME_API_PORT || 8787);

// Journal-bounding maintenance config is parsed BEFORE anything listens:
// "off" in production is a startup failure (the loop is what keeps managed
// volumes writable), never a silently degraded deployment.
const historyMaintenance = historyMaintenanceSettingsFromEnv(process.env);

const metadata = new PostgresMetadataRepository({
  connectionString: databaseUrl,
  connectionTimeoutMillis: Number(process.env.VOLUME_DATABASE_CONNECT_TIMEOUT_MS || 10_000),
  // Bounded pool: request admission (128 active) is the concurrency control;
  // the pool is capped so the API can never stampede PostgreSQL. The
  // repository clamps this to 32 even if configured higher.
  max: intEnv("VOLUME_DATABASE_POOL_MAX", 32, 1, 32),
  ...databaseSslConfig(),
});
// Migrations run before ANYTHING listens, so a throw here is the whole
// deployment. A database that is still in crash recovery has not answered
// about the migrations at all — it has only said "not yet" — so the gate waits
// it out on a bounded budget and fails the deploy definitively if it never
// arrives. A real migration failure still propagates on the first attempt.
console.log("PortableFS API applying metadata migrations.");
await applyMigrationsUntilReady(() => metadata.applyMigrations(), {
  budget: startupMigrationBudgetFromEnv(process.env),
});
console.log("PortableFS API metadata migrations are ready.");

// Data gate for the retired pfr1/pfc1 journal codec era: serving and
// binding reads accept only pfj3/pfc2 (migration 012+), so a deployment
// still carrying a pre-012 generation row must stop HERE with a clear
// message instead of failing per-request. One cheap query at startup.
const legacyGenerations = await metadata.countPreJournalV3Generations();
if (legacyGenerations > 0) {
  throw new Error(
    `${legacyGenerations} journal generation(s) still use the retired pfr1/pfc1 codec pair. ` +
      "This volume-api serves only pfj3/pfc2 (migration 012+): retire or migrate those branches " +
      "onto new-generation journals before upgrading."
  );
}

const blobStore = createBlobStore(process.env);

// VOLUME_API_TOKEN is the admin credential: it provisions tenants + tokens
// (POST /v1/admin/tenants) and runs GC. Tenant data access uses per-tenant tokens
// issued through that endpoint. Auth is fail-closed — without an admin token AND
// with no tenant tokens yet, every request is rejected and nothing can be
// provisioned, so warn loudly rather than silently locking the deployment out.
if (!process.env.VOLUME_API_TOKEN) {
  console.warn(
    "WARNING: VOLUME_API_TOKEN (admin token) is not set. The API is fail-closed: " +
      "no admin token means tenants/tokens cannot be provisioned. Set VOLUME_API_TOKEN."
  );
}

const maxBlobBodyBytes = Number(process.env.VOLUME_API_MAX_BLOB_BODY_BYTES || 0);

// Per-tenant admission caps: unset defaults to 50% of the global budgets
// (64 requests / 128 MiB) so one tenant can never exhaust the server before
// the global limits trip; 0 disables the dimension. Strictly validated.
const tenantMaxRequests = process.env.VOLUME_API_TENANT_MAX_REQUESTS?.trim()
  ? intEnv("VOLUME_API_TENANT_MAX_REQUESTS", 0, 0)
  : undefined;
const tenantMaxReservedBytes = process.env.VOLUME_API_TENANT_MAX_RESPONSE_BYTES?.trim()
  ? intEnv("VOLUME_API_TENANT_MAX_RESPONSE_BYTES", 0, 0)
  : undefined;

// Minimum CLI version advertised on every /v1 response (the
// x-portablefs-min-cli-version header) so an outdated client can
// self-diagnose instead of failing opaquely. Optional; validated as semver
// at startup — a typo fails the boot, never ships a garbage header.
const minCliVersion = semverEnv(process.env, "PORTABLEFS_MIN_CLI_VERSION");

const releaseIdentity = await loadVolumeApiReleaseIdentity(process.env);
console.log(
  releaseIdentity
    ? `PortableFS API release identity: ${releaseIdentity.releaseId} (${releaseIdentity.sourceRevision}).`
    : "PortableFS API release identity is not configured (PORTABLEFS_RELEASE_ID + PORTABLEFS_SOURCE_REVISION); /v1/release-identity answers 404."
);

// Exact-key readers for PFT2 history objects: the SAME failure-domain map the
// Go history worker writes with. Absent, /v1/history/* answers a typed 503.
const historyStores = historyStoreRegistryFromEnv(process.env);
console.log(
  historyStores
    ? `PortableFS API history serving domains: ${historyStores.domains().join(", ")}.`
    : "PortableFS API history serving is not configured (PFH_WORKER_STORES_JSON / VOLUME_HISTORY_STORES_JSON)."
);

const telemetryHook =
  process.env.VOLUME_API_TELEMETRY?.trim() === "stdout" ? stdoutTelemetrySink() : undefined;
const runtime = new VolumeApiRuntime({ telemetry: createTelemetry(telemetryHook) });
installSignalHandlers(runtime);

// The journal-bounding maintenance loop: finds PFJ3 generations past the
// backlog threshold, drives recovery cuts to adoption (the ONLY way backlog
// shrinks), and sweeps superseded serving pins. Deterministic operation ids
// make it exact-once and safe on every replica concurrently. Its one cycle
// line always reaches stdout in the shared telemetry format — the loop is
// the writability guardian, so its heartbeat is not gated on
// VOLUME_API_TELEMETRY.
const maintenanceLoop = historyMaintenance.enabled
  ? new HistoryMaintenanceLoop({
      store: metadata.history,
      intervalMs: historyMaintenance.intervalMs,
      backlogPercent: historyMaintenance.backlogPercent,
      telemetry: createTelemetry(telemetryHook ?? stdoutTelemetrySink()),
      // Adoption is gated on THIS deployment serving exact PFT2 history
      // reads: the adopted base is what the next cold start must fetch
      // through /v1/history/*. Cut creation/materialization still runs.
      servingConfigured: historyStores !== undefined,
      // Drain invariant (runtime.ts): shutdown never blocks on history work.
      // The loop pauses at its next step boundary once draining and its
      // mid-cycle work resumes on the next process via the operation ids.
      shouldPause: () => runtime.isDraining(),
    })
  : undefined;
runtime.attachMetadataClose(() => {
  // Clear the loop timer before the pool closes; an in-flight cycle is
  // deliberately not awaited (it bails at its next pause check).
  maintenanceLoop?.stop();
  return metadata.close();
});

// Control readiness for /readyz: serving phase + bounded metadata probe
// (connectivity + migration lineage current). Never touches blob stores.
const readiness = new ControlReadiness({
  phase: () => runtime.phase,
  controlProbe: (options) => metadata.probeControlPlane(options),
});

const server = createVolumeApiServer({
  metadata,
  blobStore,
  runtime,
  readiness,
  httpDefenses: httpDefensesFromEnv(),
  // applyMigrations above applied the full ordered lineage (through the
  // journal/history migrations), so the receipted attach surface is live.
  receiptedAttachEnabled: true,
  ...(historyStores ? { historyStores } : {}),
  ...(telemetryHook ? { telemetry: telemetryHook } : {}),
  ...(process.env.VOLUME_API_TOKEN ? { authToken: process.env.VOLUME_API_TOKEN } : {}),
  ...(maxBlobBodyBytes > 0 ? { maxBlobBodyBytes } : {}),
  ...(tenantMaxRequests !== undefined ? { tenantMaxRequests } : {}),
  ...(tenantMaxReservedBytes !== undefined ? { tenantMaxReservedBytes } : {}),
  ...(releaseIdentity ? { releaseIdentity } : {}),
  ...(minCliVersion ? { minCliVersion } : {}),
});

server.listen(port, () => {
  console.log(`PortableFS API listening on :${port}`);
  if (maintenanceLoop) {
    maintenanceLoop.start();
    console.log(
      `PortableFS API history maintenance is on (interval ${historyMaintenance.intervalMs}ms, ` +
        `backlog threshold ${historyMaintenance.backlogPercent}%).`
    );
  } else {
    console.log(
      "PortableFS API history maintenance is OFF (non-production only): managed journal " +
        "backlog will grow until recovery cuts are adopted manually."
    );
  }
});

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function intEnv(name: string, fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  return intEnvOf(process.env, name, fallback, min, max);
}

// Transport defenses (see resolveHttpDefenses in server.ts): production-safe
// defaults, strictly validated when tuned.
function httpDefensesFromEnv(): HttpServerDefenses {
  return {
    headersTimeoutMs: intEnv("VOLUME_API_HEADERS_TIMEOUT_MS", 30_000, 1),
    requestTimeoutMs: intEnv("VOLUME_API_REQUEST_TIMEOUT_MS", 300_000, 1),
    keepAliveTimeoutMs: intEnv("VOLUME_API_KEEPALIVE_TIMEOUT_MS", 5_000, 1),
    maxRequestsPerSocket: intEnv("VOLUME_API_MAX_REQUESTS_PER_SOCKET", 1000, 1),
    maxConnections: intEnv("VOLUME_API_MAX_CONNECTIONS", 1024, 1),
  };
}

function createBlobStore(env: NodeJS.ProcessEnv): BlobStore {
  // Compat aliasing (one release): "railway-bucket" is the retired spelling
  // of "s3". The retired VOLUME_RAILWAY_BUCKET_* variables alias onto the
  // canonical AWS_*/VOLUME_S3_* names inside s3ConfigFromEnv.
  const kind = env.VOLUME_BLOB_STORE?.trim() || "s3";
  if (kind === "s3" || kind === "railway-bucket") {
    return new S3BlobStore(s3ConfigFromEnv(env));
  }
  if (kind === "filesystem") {
    return new FilesystemBlobStore(filesystemBlobStoreConfigFromEnv(env));
  }
  throw new Error("VOLUME_BLOB_STORE must be s3 or filesystem.");
}

function databaseSslConfig():
  | { ssl: { rejectUnauthorized: boolean } }
  | { ssl?: undefined } {
  const mode = process.env.VOLUME_DATABASE_SSL?.trim();
  if (mode === "require") {
    return { ssl: { rejectUnauthorized: true } };
  }
  if (mode === "no-verify") {
    console.warn(
      "WARNING: VOLUME_DATABASE_SSL=no-verify accepts any server certificate (MITM-able). " +
        "Use 'require' with a trusted CA for any network database."
    );
    return { ssl: { rejectUnauthorized: false } };
  }
  if (mode === "disable") {
    // Explicit opt-out for a loopback/compose database (the quickstart posture).
    return {};
  }
  // Unset: transport is governed by the URL's sslmode, if any. Warn loudly so
  // a managed/pooler Postgres reached over the network is never silently
  // spoken to in cleartext (tenant token hashes and journal material cross it).
  if (!/sslmode=/i.test(process.env.VOLUME_DATABASE_URL ?? "")) {
    console.warn(
      "WARNING: VOLUME_DATABASE_SSL is unset and VOLUME_DATABASE_URL has no sslmode; " +
        "the Postgres connection may be plaintext. Set VOLUME_DATABASE_SSL=require (or " +
        "sslmode=require) for any non-loopback database; set VOLUME_DATABASE_SSL=disable to silence this for a local one."
    );
  }
  return {};
}
