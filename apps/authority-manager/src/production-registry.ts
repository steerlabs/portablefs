import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Readable, Writable } from "node:stream";
import {
  AuthorityOperationError,
  authorityOperationErrorCodes,
  type AuthorityEndpoint,
  type AuthorityLeaseBinding,
  type AuthorityRef,
  type AuthorityRegistry,
  type AuthorityStopResult,
} from "./server.js";
import {
  ControlStoreUnavailableError,
  ManagerClaimHeldError,
  ManagerEpochSupersededError,
  managedTenantKey,
  runtimeEndOperationId,
  sha256Hex,
  type AuthorityRuntimeBeginResult,
  type AuthorityScopeRef,
  type ManagerControlStore,
  type ManagerIdentity,
} from "./manager-control-store.js";
import { ProductionAccessLeaseService } from "./production-access-leases.js";
import type { ClaimHeartbeat, ClaimRenewalFacts } from "./claim-heartbeat.js";
import { parseAccessTokenRootSecret } from "./access-tokens.js";
import type { AuthorityDataPlaneRoute } from "./data-plane-router.js";
import {
  formatAuthorityAddress,
  parseAuthorityAddress,
  type AuthorityAddress,
} from "./authority-address.js";

// ---------------------------------------------------------------------------
// ProductionAuthorityRegistry: the journal-native production registry.
//
// One singleton fenced manager (a DATABASE-TIME lease claimed against the
// remote ManagerControlStore, renewed continuously, with a LOCAL MONOTONIC
// hard deadline derived from each successful database response) plus ONE
// disposable child authority per demanded tenant/volume/branch. Journal and
// control truth is REMOTE:
//
//   - no persistent work directory (each child runs in an ephemeral temp dir
//     removed after it exits) and NO local cache directory,
//   - no local WAL and no standby pair (the child journals to the fenced
//     synchronous Postgres journal; config rejects every local-topology
//     variable),
//   - no authority.json adoption and no warm promotion (a manager restart
//     claims a NEW epoch and demand-starts fresh children that cold-replay
//     from the journal),
//   - child liveness is coupled through an inherited heartbeat pipe (fd 3):
//     the manager writes identity + remaining-DB-lease frames after every
//     successful renewal; EOF or the frame deadline fences the child before
//     it can serve past the manager's own lease.
//
// Production readiness FAILS CLOSED until a real remote ManagerControlStore
// is injected; there is deliberately no silent fallback to files.
//
// SEAM (vcs-binary integration wave): ordinary teardown currently fences
// access durably and terminates the child; once the vcs binary serves the
// managed lifecycle plane, the drain step (child-receipted exact journal
// suspension) slots between the durable access fence and terminateChild in
// stopAuthorityLocked/runIdleEviction below, recorded through the control
// store's lifecycle receipts.
// ---------------------------------------------------------------------------

const DEFAULT_READY_TIMEOUT_MS = 30_000;
// Default zero-active-lease grace before an idle demand-started per-branch
// child is evicted, applied whenever
// PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS is unset. Every resident
// child pins up to 4 Postgres journal connections (pgxpool defaultMaxConns
// in vcs/internal/remotejournal) for as long as it runs; the recorded
// production incident — 62 idle vcs-* children against a 100-connection
// Postgres ceiling, with live connection rejections — happened exactly
// because idle eviction used to default to disabled. Eviction is therefore
// tune-only: readIdleEvictionGraceMs rejects "off"/zero/negative at startup.
const DEFAULT_IDLE_EVICTION_GRACE_MS = 900_000;
// Resident-children cap: each resident child pins its journal connection
// pool for its whole lifetime, so admission — not hope — keeps the database
// connection ceiling honest. A spawn past the cap refuses typed
// AUTHORITY_AT_CAPACITY (503 + Retry-After); idle eviction frees capacity.
// Operators sizing the cap must budget up to 4 journal connections per
// resident child.
const DEFAULT_MAX_AUTHORITIES = 100;
// Global bound on CONCURRENT child cold starts (not resident children). One
// cold start is expensive — journal claim, durability probes, cold replay —
// and opens up to 4 Postgres connections before readiness, so a reconnect
// stampede after a manager restart must queue FIFO behind this bound instead
// of opening dozens of simultaneous cold starts against the journal database.
const DEFAULT_MAX_CONCURRENT_STARTS = 4;
// Advisory client backoff for the typed 503 capacity/queue refusals: long
// enough that mount clients stop hammering, short enough that a freed slot
// (an eviction, a finished cold start) is picked up promptly.
const BACKPRESSURE_RETRY_AFTER_SECONDS = 15;
const DEFAULT_READY_POLL_MS = 100;
// Per-request /readyz probe bound: one wedged socket never consumes the
// readiness window (the poll loop retries on the next tick).
const READY_PROBE_TIMEOUT_MS = 2_000;
// Grace between SIGTERM and SIGKILL. Acknowledged writes live in the remote
// journal, so termination loses nothing a successor cannot cold-replay.
const DEFAULT_PROCESS_GRACE_MS = 5_000;
const DEFAULT_CLAIM_TTL_MS = 30_000;
// Bounded bind-race mitigation: a child that dies before readiness (e.g. it
// lost a port race with an unrelated process) is retried on fresh ports.
const MAX_CHILD_START_ATTEMPTS = 3;
// Bounded durable-teardown retries: the access-fence retire (idempotent by
// its deterministic operation id) and the runtime-row end each get this many
// attempts with linear backoff before the teardown gives up fenced-open
// (runtime row live, ALL access fenced — a successor begin or the due sweep
// settles it).
const TEARDOWN_DURABLE_ATTEMPTS = 3;
const TEARDOWN_RETRY_BACKOFF_MS = 100;

/** Escapes terminal and line controls before untrusted fields enter one log record. */
export function escapeLogControls(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f-\u009f]/g, (character) => {
    return `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`;
  });
}

/** Prefixes every child-output line and strips terminal controls without hiding text. */
export function formatChildLogChunk(prefix: string, chunk: Buffer | string): string {
  const escaped = String(chunk).replace(
    /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
  );
  const lines = escaped.split("\n");
  return lines
    .map((line, index) => {
      const terminated = index < lines.length - 1;
      if (!terminated && line === "") {
        return "";
      }
      return `${prefix} ${line}${terminated ? "\n" : ""}`;
    })
    .join("");
}

// The manager pipes the child inherits (after stdin/out/err): fd 3 carries
// bounded manager→child lease frames; fd 4 carries the child's one bounded
// bootstrap frame (exact identities + self-bound listener addresses) back.
export const CHILD_HEARTBEAT_FD = 3;
export const CHILD_BOOTSTRAP_FD = 4;

// The manager↔child control protocol version (lease frames, bootstrap frame,
// readiness identity fields). The child reports it; the manager refuses any
// other version.
export const MANAGED_CHILD_PROTOCOL_VERSION = 1;

// One pipe frame (either direction) is at most 4 KiB including the newline.
const MAX_PIPE_FRAME_BYTES = 4096;

// Local-topology / manager-owned child environment that can NEVER be
// injected from outside: local durability topology, identity, scope, and
// credential variables are owned exclusively by this registry.
const FORBIDDEN_CHILD_ENV_KEYS = [
  "VCS_WAL",
  "VCS_REPLICA_ADDR",
  "VCS_REPLICA_LISTEN",
  "VCS_STANDBY",
  "VCS_STANDBY_WAL",
  "VCS_STANDBY_PROMOTION_DELAY",
  "VCS_CACHE_DIR",
] as const;

// The EXACT allowlist of optional child tuning variables an operator may pass
// through PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON. Everything else — identity,
// scope, credentials, journal wiring, durability topology — is manager-owned
// and rejected. There is deliberately no pattern matching: exact names only.
const EXTRA_CHILD_ENV_ALLOWLIST = new Set<string>([
  "VCS_CACHE_RAM_MB",
  "VCS_PREFETCH",
  "VCS_DIRTY_RSS_MAX_MB",
]);

export interface ProductionAuthorityRegistryEnvConfig {
  NODE_ENV?: string;
  PORTABLEFS_MANAGED_VCS_BIN?: string;
  PORTABLEFS_AUTHORITY_ROUTER_URL?: string;
  PORTABLEFS_AUTHORITY_PROVIDER_NAME?: string;
  PORTABLEFS_VOLUME_API_URL?: string;
  VOLUME_API_URL?: string;
  PORTABLEFS_VOLUME_API_TOKEN?: string;
  VOLUME_API_TOKEN?: string;
  // The REQUIRED remote-journal connection string for every spawned child
  // (the authority login role). Emitted verbatim as VCS_JOURNAL_DSN.
  PORTABLEFS_MANAGED_VCS_JOURNAL_DSN?: string;
  // Optional transaction-pooler topology declaration. The only accepted
  // value is "transaction"; it is emitted as VCS_JOURNAL_POOLER_MODE so the
  // Go journal omits session timeout startup parameters and relies on the
  // database defaults migration 016_pooler_timeouts installs.
  PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE?: string;
  // The REQUIRED versioned structured HA policy for the journal database
  // (JSON: {v:1, expectedSystemIdentifier, expectedDatabase,
  // minSynchronousCommit: "on"|"remote_apply", minSyncStandbys>=1,
  // standbyFailureDomains, minDistinctFailureDomains}). Emitted verbatim as
  // VCS_JOURNAL_HA_POLICY_JSON; the child verifies live durability evidence
  // against it fact by fact and reports the canonical policy hash through
  // bootstrap/readiness. Prose attestations are never a durability gate.
  PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON?: string;
  // Optional EXACT-allowlisted extra child env (VCS_CACHE_RAM_MB,
  // VCS_PREFETCH, VCS_DIRTY_RSS_MAX_MB). Any other key is a startup error.
  PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON?: string;
  // The REQUIRED stable access-token root secret (hex or base64url, >= 32
  // bytes decoded). Token keys are derived from it per (epoch, generation).
  PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET?: string;
  // Zero-active-lease grace before an idle child is evicted. Unset applies
  // DEFAULT_IDLE_EVICTION_GRACE_MS (15 minutes): idle eviction is ALWAYS
  // enabled. A positive integer re-tunes the grace; "off"/zero/negative are
  // startup errors — idle children hold Postgres journal connections, and
  // running without eviction is the recorded connection-exhaustion incident
  // shape (see readIdleEvictionGraceMs).
  PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS?: string;
  // Resident-children cap (default DEFAULT_MAX_AUTHORITIES). A spawn past
  // the cap refuses typed AUTHORITY_AT_CAPACITY; running children are never
  // affected. Malformed values are startup errors, never silent defaults.
  PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES?: string;
  // OPTIONAL per-tenant resident-children cap. Unset applies no additional
  // restriction beyond the global cap (zero behavior change for
  // single-tenant self-hosts). When set, a NEW spawn that would exceed the
  // tenant's budget refuses typed TENANT_AT_CAPACITY as 429 + Retry-After —
  // the service is healthy, the tenant is over budget, which is why it is
  // NOT the 503 AUTHORITY_AT_CAPACITY. Malformed values are startup errors.
  PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT?: string;
  // OPTIONAL per-tenant cap on concurrently ACTIVE access leases, enforced
  // by the lease service at create. Unset = off (exact current behavior).
  // Over-budget creates refuse typed TENANT_LEASE_LIMIT as 429 +
  // Retry-After; released/expired/revoked leases never count and free the
  // budget naturally. Malformed values are startup errors.
  PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT?: string;
  // Global bound on concurrent child cold starts (default
  // DEFAULT_MAX_CONCURRENT_STARTS). Waiters queue FIFO for a bounded window
  // and then refuse typed AUTHORITY_START_QUEUE_TIMEOUT.
  PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS?: string;
  PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS?: string;
  PORTABLEFS_MANAGED_VCS_PROCESS_GRACE_MS?: string;
  PORTABLEFS_MANAGED_VCS_LEASE_TTL?: string;
  PORTABLEFS_MANAGER_CLAIM_TTL_MS?: string;
  PORTABLEFS_ACCESS_LEASE_DEFAULT_TTL_MS?: string;
  PORTABLEFS_ACCESS_LEASE_MAX_TTL_MS?: string;
  // Guard: any of these present in the MANAGER's own environment indicates a
  // local topology config leaking into production; config reading rejects it.
  VCS_WAL?: string;
  VCS_REPLICA_ADDR?: string;
  VCS_STANDBY?: string;
  VCS_CACHE_DIR?: string;
}

export interface ProductionAuthorityRegistryConfig {
  vcsBin: string;
  routerUrl: string;
  routerAddress: AuthorityAddress;
  provider: string;
  volumeApiUrl: string;
  journalDsn: string;
  journalPoolerMode?: "transaction";
  journalHaPolicyJson: string;
  journalHaPolicyHash: string;
  extraChildEnv: Record<string, string>;
  accessTokenRootSecret: Buffer;
  // Always a resolved positive number: idle eviction cannot be disabled.
  idleEvictionGraceMs: number;
  maxAuthorities: number;
  // Optional per-tenant fairness caps; undefined = no per-tenant restriction.
  maxAuthoritiesPerTenant?: number;
  accessLeasesMaxPerTenant?: number;
  maxConcurrentStarts: number;
  readyTimeoutMs: number;
  processGraceMs: number;
  claimTtlMs: number;
  leaseTtlSeconds?: string;
  accessLeaseDefaultTtlMs?: number;
  accessLeaseMaxTtlMs?: number;
}

export function readProductionAuthorityRegistryConfig(
  env: ProductionAuthorityRegistryEnvConfig
): ProductionAuthorityRegistryConfig {
  const vcsBin = normalizeOptionalString(env.PORTABLEFS_MANAGED_VCS_BIN);
  if (!vcsBin) {
    throw new Error("PORTABLEFS_MANAGED_VCS_BIN is required for the production authority registry.");
  }
  const configuredRouterUrl = env.PORTABLEFS_AUTHORITY_ROUTER_URL;
  if (!configuredRouterUrl || configuredRouterUrl.trim() === "") {
    throw new Error(
      "PORTABLEFS_AUTHORITY_ROUTER_URL is required for the production authority registry."
    );
  }
  const routerAddress = parseAuthorityAddress(configuredRouterUrl, {
    label: "PORTABLEFS_AUTHORITY_ROUTER_URL",
    allowedSchemes: ["tcp", "fsproto"],
  });
  const routerUrl = formatAuthorityAddress(routerAddress);
  const volumeApiUrl =
    normalizeOptionalString(env.PORTABLEFS_VOLUME_API_URL) ??
    normalizeOptionalString(env.VOLUME_API_URL);
  if (!volumeApiUrl) {
    throw new Error("PORTABLEFS_VOLUME_API_URL or VOLUME_API_URL is required.");
  }
  // NO static child credential: production children authenticate with
  // manager-minted short-lived runtime credentials exclusively (migration
  // 015). A static token here could only ever represent ONE tenant — every
  // other tenant's volumes would be invisible to the child (the ownership
  // guard answers 404) — so the shape is refused outright rather than
  // silently narrowing the deployment to single-tenant.
  for (const key of ["PORTABLEFS_VOLUME_API_TOKEN", "VOLUME_API_TOKEN"] as const) {
    if (normalizeOptionalString((env as Record<string, string | undefined>)[key])) {
      throw new Error(
        `${key} must not be set for the production authority registry: children authenticate with manager-minted runtime credentials (public.runtime_read_credentials, migration 015), never static tokens. Remove it.`
      );
    }
  }
  for (const key of FORBIDDEN_CHILD_ENV_KEYS) {
    if (normalizeOptionalString((env as Record<string, string | undefined>)[key])) {
      throw new Error(
        `${key} must not be set for the production authority registry: production children have no local WAL, no replication pair, and no local cache directory. Remove it (the managed local-file registry is the only registry that uses local topology).`
      );
    }
  }
  const journalDsn = normalizeOptionalString(env.PORTABLEFS_MANAGED_VCS_JOURNAL_DSN);
  if (!journalDsn) {
    throw new Error(
      "PORTABLEFS_MANAGED_VCS_JOURNAL_DSN is required: production children journal to the fenced remote Postgres journal (emitted to the child as VCS_JOURNAL_DSN), never to local files."
    );
  }
  const journalPoolerMode = normalizeOptionalString(
    env.PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE
  );
  if (journalPoolerMode !== undefined && journalPoolerMode !== "transaction") {
    throw new Error(
      'PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE must be absent for a direct connection or exactly "transaction" for a transaction-mode pooler.'
    );
  }
  const journalHaPolicyJson = normalizeOptionalString(
    env.PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON
  );
  if (!journalHaPolicyJson) {
    throw new Error(
      "PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON is required: the structured versioned HA policy the child verifies against live journal durability evidence (expected database identity, minimum synchronous commit level, minimum live sync standbys). A DSN or prose attestation is never a durability gate."
    );
  }
  const journalHaPolicyHash = canonicalHaPolicyHash(journalHaPolicyJson);
  const rootSecretRaw = normalizeOptionalString(env.PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET);
  if (!rootSecretRaw) {
    throw new Error(
      "PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET is required: access tokens are deterministic HMACs under keys derived from this stable root secret plus the manager epoch and token generation (no plaintext token storage). Provide >= 32 bytes as hex or base64url."
    );
  }
  const accessTokenRootSecret = parseAccessTokenRootSecret(rootSecretRaw);
  const extraChildEnv = readExtraChildEnv(env.PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON);
  const maxAuthoritiesPerTenant = optionalPositiveInt(
    "PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT",
    env.PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT
  );
  const accessLeasesMaxPerTenant = optionalPositiveInt(
    "PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT",
    env.PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT
  );
  return {
    vcsBin,
    routerUrl,
    routerAddress,
    provider: normalizeOptionalString(env.PORTABLEFS_AUTHORITY_PROVIDER_NAME) ?? "portablefs-managed",
    volumeApiUrl,
    journalDsn,
    ...(journalPoolerMode === "transaction" ? { journalPoolerMode } : {}),
    journalHaPolicyJson,
    journalHaPolicyHash,
    extraChildEnv,
    accessTokenRootSecret,
    idleEvictionGraceMs: readIdleEvictionGraceMs(env.PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS),
    maxAuthorities: requirePositiveInt(
      "PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES",
      env.PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES,
      DEFAULT_MAX_AUTHORITIES
    ),
    ...(maxAuthoritiesPerTenant !== undefined ? { maxAuthoritiesPerTenant } : {}),
    ...(accessLeasesMaxPerTenant !== undefined ? { accessLeasesMaxPerTenant } : {}),
    maxConcurrentStarts: requirePositiveInt(
      "PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS",
      env.PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS,
      DEFAULT_MAX_CONCURRENT_STARTS
    ),
    readyTimeoutMs:
      readPositiveInt(env.PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS) ?? DEFAULT_READY_TIMEOUT_MS,
    processGraceMs:
      readPositiveInt(env.PORTABLEFS_MANAGED_VCS_PROCESS_GRACE_MS) ?? DEFAULT_PROCESS_GRACE_MS,
    claimTtlMs: readPositiveInt(env.PORTABLEFS_MANAGER_CLAIM_TTL_MS) ?? DEFAULT_CLAIM_TTL_MS,
    ...(normalizeOptionalString(env.PORTABLEFS_MANAGED_VCS_LEASE_TTL)
      ? { leaseTtlSeconds: normalizeOptionalString(env.PORTABLEFS_MANAGED_VCS_LEASE_TTL)! }
      : {}),
    ...(readPositiveInt(env.PORTABLEFS_ACCESS_LEASE_DEFAULT_TTL_MS) !== undefined
      ? { accessLeaseDefaultTtlMs: readPositiveInt(env.PORTABLEFS_ACCESS_LEASE_DEFAULT_TTL_MS)! }
      : {}),
    ...(readPositiveInt(env.PORTABLEFS_ACCESS_LEASE_MAX_TTL_MS) !== undefined
      ? { accessLeaseMaxTtlMs: readPositiveInt(env.PORTABLEFS_ACCESS_LEASE_MAX_TTL_MS)! }
      : {}),
  };
}

// canonicalHaPolicyHash validates the structured HA policy and computes the
// EXACT canonical hash the Go child reports back (vcs/internal/hapolicy
// Policy.Hash): deterministic JSON — fixed field order, the operator's
// standby→failure-domain mapping as a name-sorted array of pairs, no HTML
// escaping. String fields are restricted to printable ASCII without quotes
// or backslashes so Go json.Marshal and JSON.stringify emit identical bytes.
//
// Policy shape (version 1): expectedSystemIdentifier and expectedDatabase
// PIN the exact cluster (required); standbyFailureDomains is the OPERATOR-
// ATTESTED mapping of eligible standby application_names to failure domains
// (PostgreSQL cannot observe topology); minDistinctFailureDomains is how
// many DISTINCT attested domains the live synchronous standbys must cover.
export function canonicalHaPolicyHash(raw: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (!isRecord(parsed)) {
    throw new Error("PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON must be a JSON object.");
  }
  const knownKeys = new Set([
    "v",
    "expectedSystemIdentifier",
    "expectedDatabase",
    "minSynchronousCommit",
    "minSyncStandbys",
    "standbyFailureDomains",
    "minDistinctFailureDomains",
  ]);
  for (const key of Object.keys(parsed)) {
    if (!knownKeys.has(key)) {
      throw new Error(`PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON has unknown field ${key}.`);
    }
  }
  if (parsed.v !== 1) {
    throw new Error('PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON must be version 1 ({"v":1,...}).');
  }
  const asciiSafe = (value: unknown): value is string =>
    typeof value === "string" && /^[ -~]*$/u.test(value) && !/["\\]/u.test(value);
  const requiredAscii = (key: "expectedSystemIdentifier" | "expectedDatabase"): string => {
    const value = parsed[key];
    if (typeof value !== "string" || value === "") {
      throw new Error(
        `PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON ${key} is required: unpinned durability evidence proves nothing.`
      );
    }
    if (!asciiSafe(value)) {
      throw new Error(
        `PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON ${key} must be printable ASCII without quotes or backslashes (it participates in the cross-language canonical policy hash).`
      );
    }
    return value;
  };
  const expectedSystemIdentifier = requiredAscii("expectedSystemIdentifier");
  const expectedDatabase = requiredAscii("expectedDatabase");
  const commit = parsed.minSynchronousCommit;
  if (commit !== "on" && commit !== "remote_apply") {
    throw new Error(
      'PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON minSynchronousCommit must be "on" or "remote_apply".'
    );
  }
  const minSyncStandbys = parsed.minSyncStandbys;
  if (typeof minSyncStandbys !== "number" || !Number.isInteger(minSyncStandbys) || minSyncStandbys < 1) {
    throw new Error(
      "PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON minSyncStandbys must be an integer >= 1 (a policy accepting zero synchronous standbys is not HA)."
    );
  }
  const domains = parsed.standbyFailureDomains;
  if (!isRecord(domains) || Object.keys(domains).length === 0) {
    throw new Error(
      "PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON standbyFailureDomains is required: attest which standby application_names live in which failure domains (unattested standbys prove no distinct domain)."
    );
  }
  const pairs: Array<[string, string]> = [];
  for (const [name, domain] of Object.entries(domains)) {
    if (!name || !asciiSafe(name) || typeof domain !== "string" || !domain || !asciiSafe(domain)) {
      throw new Error(
        "PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON standbyFailureDomains entries must map nonempty printable-ASCII application_names to nonempty printable-ASCII domains."
      );
    }
    pairs.push([name, domain]);
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const minDistinctFailureDomains = parsed.minDistinctFailureDomains;
  if (
    typeof minDistinctFailureDomains !== "number" ||
    !Number.isInteger(minDistinctFailureDomains) ||
    minDistinctFailureDomains < 1
  ) {
    throw new Error(
      "PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON minDistinctFailureDomains must be an integer >= 1."
    );
  }
  if (minDistinctFailureDomains > pairs.length) {
    throw new Error(
      `PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON minDistinctFailureDomains ${minDistinctFailureDomains} exceeds the ${pairs.length} attested standby(s).`
    );
  }
  // Byte-identical to Go's canonical policy json.Marshal (fixed field order,
  // sorted pairs, no HTML escaping, validated ASCII contents).
  const canonical = JSON.stringify({
    v: 1,
    expectedSystemIdentifier,
    expectedDatabase,
    minSynchronousCommit: commit,
    minSyncStandbys,
    minDistinctFailureDomains,
    standbyFailureDomains: pairs,
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

// readExtraChildEnv parses the OPTIONAL extra child env JSON and enforces the
// exact allowlist: nothing outside EXTRA_CHILD_ENV_ALLOWLIST may pass, so no
// operator input can overwrite manager-owned identity/scope/auth/journal
// variables or reintroduce a local topology.
function readExtraChildEnv(json: string | undefined): Record<string, string> {
  const raw = normalizeOptionalString(json);
  if (!raw) {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (!isRecord(parsed)) {
    throw new Error("PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON must be a JSON object.");
  }
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed)) {
    if (typeof value !== "string") {
      throw new Error(`PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON entry ${key} must be a string.`);
    }
    if (!EXTRA_CHILD_ENV_ALLOWLIST.has(key)) {
      throw new Error(
        `PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON entry ${key} is not on the exact child-env allowlist (${[...EXTRA_CHILD_ENV_ALLOWLIST].join(", ")}); identity, scope, credentials, journal wiring, and durability topology are manager-owned.`
      );
    }
    env[key] = value;
  }
  return env;
}

export interface ProductionAuthorityRegistryDeps {
  // The REAL remote control store. REQUIRED: production fails closed without
  // one (there is no file fallback). The in-memory fake is for tests only.
  controlStore: ManagerControlStore;
  fetch?: typeof fetch;
  spawnProcess?: typeof spawn;
  localNow?: () => number;
  log?: (message: string) => void;
}

interface ProductionChild {
  key: string;
  ref: AuthorityRef;
  instanceId: string;
  // The MONOTONIC per-scope runtime sequence (pfm row) and the RANDOM runtime
  // id minted for this exact process. Both are remote facts; a receipt or
  // token fenced to sequence N can never answer for the restart N+1.
  runtimeSeq: string;
  runtimeId: string;
  tenantKey: string;
  vcsTenantId: string;
  backendAuthToken: string;
  adminToken: string;
  workDir: string;
  // The EXACT self-bound loopback addresses the child reported on its
  // bootstrap pipe. Empty until the bootstrap frame arrives; a child whose
  // frame never arrives (or lies about identity) is terminated, never adopted.
  fsAddress: string;
  metricsAddress: string;
  // The journal generation the child claimed, from the bootstrap frame;
  // readiness revalidates it.
  journalGenerationId: string;
  child: ChildProcess;
  heartbeat: Writable | null;
  // Lease-frame delivery is LATEST-VALUE and bounded: at most ONE write is
  // in flight per child (heartbeatBusy), at most ONE superseded frame waits
  // in the slot (heartbeatPending — replaced, never queued), and every
  // delivered frame carries the next monotonic heartbeatSeq. Node's internal
  // write queue therefore never accumulates a stale-lease backlog a stalled
  // child could consume later.
  heartbeatSeq: number;
  heartbeatBusy: boolean;
  heartbeatPending: HeartbeatFacts | null;
  exited: boolean;
  // Set while the manager itself tears the child down, so the exit handler
  // does not double-run the unexpected-exit fencing.
  managerTerminating: boolean;
  // The rotating DB-backed runtime read credential (migration 015): the
  // 0600 file the child re-reads, and the re-mint timer.
  volumeApiCredentialFile: string;
  credentialRotation?: NodeJS.Timeout | undefined;
}

// Runtime read credentials rotate at TTL/3; the DB caps mint TTL at 1h.
const RUNTIME_READ_CREDENTIAL_TTL_MS = 3_600_000;

interface HeartbeatFacts {
  dbTimeMs: number;
  claimExpiresAtDbMs: number;
}

export class ProductionAuthorityRegistry implements AuthorityRegistry {
  private readonly config: ProductionAuthorityRegistryConfig;
  private readonly store: ManagerControlStore;
  private readonly fetchImpl: typeof fetch;
  private readonly spawnProcess: typeof spawn;
  private readonly localNow: () => number;
  private readonly log: (message: string) => void;

  private readonly identity: ManagerIdentity;
  private claimed = true;
  private superseded = false;
  private closed = false;

  // The LOCAL MONOTONIC hard deadline of the singleton claim, derived from
  // each successful database response as PRE-CALL localNow + (expiresAtDbMs -
  // dbTimeMs). The anchor is captured BEFORE the control-store call: the
  // database evaluated the expiry at some instant AFTER the call started, so
  // start + remaining is always <= the true expiry mapped onto the local
  // clock — anchoring after the response would extend the deadline past DB
  // expiry by exactly the response delay. An ambiguous renewal (error/
  // timeout) NEVER extends it; at the deadline the manager fences itself
  // even if the store is unreachable.
  private claimDeadlineLocalMs: number;
  private deadlineTimer: NodeJS.Timeout | null = null;
  // The ISOLATED liveness channel that drives renewal (see claim-heartbeat.ts).
  // The registry never renews on its own event loop: the loop that carries the
  // data-plane router's socket callbacks is exactly the loop that must not be
  // able to delay the fencing authority's heartbeat.
  private heartbeat: ClaimHeartbeat | null = null;
  private consecutiveRenewFailures = 0;
  // Notified exactly once when this manager fences itself. The process MUST
  // exit on it: a fenced manager holds no claim, serves nothing, and produces
  // no successor — the platform restart is what mints the next epoch.
  private readonly fencedListeners = new Set<(reason: string) => void>();
  private fencedNotified = false;

  readonly leases: ProductionAccessLeaseService;

  private readonly authorities = new Map<string, ProductionChild>();
  private readonly authorityLocks = new Map<string, Promise<unknown>>();
  private readonly pendingIdleEvictions = new Map<string, NodeJS.Timeout>();
  // Scopes inside the pre-registration stretch of a start (durable runtime
  // begin, credential mint — before authorities.set), each mapped to its
  // tenant key. Counted with the resident map so concurrent starts cannot
  // slip past the global cap or a tenant's budget.
  private readonly startingKeys = new Map<string, string>();

  // Monotonic process-local observability totals (surfaced through
  // observabilitySnapshot; the /metrics endpoint renders them). The registry
  // owns every increment — the metrics module never reaches into it.
  private renewalsTotal = 0;
  private renewalFailuresTotal = 0;
  // Renewals that SUCCEEDED but whose granted window was already shorter than
  // TTL - interval: the control database is slow enough that the renewal
  // schedule no longer has headroom. See applyRenewal.
  private renewalsDegradedTotal = 0;
  // The renewal cadence the liveness channel was started with (TTL/3).
  private renewIntervalMs = 0;
  private childStartsTotal = 0;
  private childStartFailuresTotal = 0;
  private childUnexpectedExitsTotal = 0;
  private idleEvictionsTotal = 0;
  private startQueueTimeoutsTotal = 0;
  private atCapacityRefusalsTotal = 0;
  private tenantAtCapacityRefusalsTotal = 0;
  // FIFO bound on concurrent cold starts; see DEFAULT_MAX_CONCURRENT_STARTS.
  private readonly startGate: StartSemaphore;
  // Unexpected-exit teardowns in flight (durable fence → runtime end → work
  // dir removal). shutdown() joins them so their ordering completes before
  // the claim is released.
  private readonly pendingTeardowns = new Set<Promise<void>>();

  private constructor(
    config: ProductionAuthorityRegistryConfig,
    deps: ProductionAuthorityRegistryDeps,
    identity: ManagerIdentity,
    claim: { dbTimeMs: number; expiresAtDbMs: number },
    claimStartLocalMs: number
  ) {
    this.config = config;
    this.store = deps.controlStore;
    this.fetchImpl = deps.fetch ?? globalThis.fetch.bind(globalThis);
    this.spawnProcess = deps.spawnProcess ?? spawn;
    // Deadlines and readiness are MONOTONIC arithmetic: the default clock is
    // performance.now (never steps with NTP/operator wall-clock changes).
    // Wall time is metadata only.
    this.localNow = deps.localNow ?? (() => performance.now());
    const configuredLog = deps.log ?? ((message: string) => console.error(message));
    this.log = (message) => configuredLog(escapeLogControls(message));
    this.identity = identity;
    this.claimDeadlineLocalMs = claimStartLocalMs + (claim.expiresAtDbMs - claim.dbTimeMs);
    this.leases = new ProductionAccessLeaseService(
      this.store,
      identity,
      { dbTimeMs: claim.dbTimeMs },
      config.accessTokenRootSecret,
      {
        localNow: this.localNow,
        ...(config.accessLeaseDefaultTtlMs !== undefined
          ? { defaultTtlMs: config.accessLeaseDefaultTtlMs }
          : {}),
        ...(config.accessLeaseMaxTtlMs !== undefined ? { maxTtlMs: config.accessLeaseMaxTtlMs } : {}),
        ...(config.accessLeasesMaxPerTenant !== undefined
          ? { maxLeasesPerTenant: config.accessLeasesMaxPerTenant }
          : {}),
      }
    );
    this.leases.setAuthorityRouteResolver((authorityInstanceId) =>
      this.resolveDataPlaneRoute(authorityInstanceId)
    );
    // Idle eviction is ALWAYS wired: idleEvictionGraceMs is a resolved
    // positive number (readIdleEvictionGraceMs rejects "off"/zero/negative
    // at startup) — idle children hold Postgres journal connections and can
    // never be allowed to idle forever.
    this.leases.onZeroActive((refKey) => this.scheduleIdleEviction(refKey));
    this.leases.onLeaseActivity((refKey) => this.cancelIdleEviction(refKey));
    // A lease-path PF001 is the same durable proof the renewal path gets: the
    // claim is gone. Fence the WHOLE manager on it instead of leaving children
    // serving until the deadline runs out.
    this.leases.onSuperseded(() => this.fenceSelf("manager-epoch-superseded"));
    this.startGate = new StartSemaphore(config.maxConcurrentStarts);
    this.armDeadlineWatchdog();
  }

  // create claims the singleton manager role (a DATABASE-TIME lease minting
  // the next monotonic managerEpoch) and starts the renewal loop. A live
  // claim held by another runtime, or a store outage, fails closed: no
  // registry, no readiness.
  static async create(
    config: ProductionAuthorityRegistryConfig,
    deps: ProductionAuthorityRegistryDeps
  ): Promise<ProductionAuthorityRegistry> {
    // Fresh random identity per PROCESS: the runtime id and capability die
    // with the process; a restart claims a new epoch. The claim operation id
    // is derived from the runtime id, so an in-process retry replays the
    // exact same claim instead of burning epochs.
    const managerRuntimeId = `pfmgr_${randomUUID()}`;
    const managerCapability = `pfmcap_${randomBytes(32).toString("base64url")}`;
    // The deadline anchor is the local MONOTONIC clock BEFORE the claim
    // call: the database granted the TTL at some instant after this, so
    // anchor + remaining never reaches past the true DB expiry, no matter
    // how slowly the response arrives.
    const claimStartLocalMs = (deps.localNow ?? (() => performance.now()))();
    const claim = await deps.controlStore.claimManager({
      operationId: `pfclaim_${managerRuntimeId}`,
      runtimeId: managerRuntimeId,
      capabilityHash: sha256Hex(managerCapability),
      ttlMs: config.claimTtlMs,
    });
    if (!claim.current) {
      throw new ManagerClaimHeldError(
        claim.expiresAtDbMs,
        claim.dbTimeMs,
        null,
        "The replayed manager claim is no longer the live claim; start a fresh manager process."
      );
    }
    const identity: ManagerIdentity = {
      managerEpoch: claim.managerEpoch,
      managerRuntimeId,
      managerCapability,
    };
    const registry = new ProductionAuthorityRegistry(config, deps, identity, claim, claimStartLocalMs);
    try {
      await registry.startClaimHeartbeat(deps.controlStore.createClaimHeartbeat());
    } catch (error) {
      // An unproven liveness channel is a manager that cannot be trusted to
      // fence on time. Release the claim so a successor starts immediately
      // instead of waiting out the TTL, and fail the boot.
      await registry.shutdown().catch(() => undefined);
      throw error;
    }
    return registry;
  }

  /** Registered before readiness; invoked once when this manager fences itself. */
  onFenced(listener: (reason: string) => void): void {
    this.fencedListeners.add(listener);
  }

  epoch(): string {
    return this.identity.managerEpoch;
  }

  managerIdentity(): ManagerIdentity {
    return this.identity;
  }

  // ready is the honest production readiness answer: claimed, not superseded,
  // inside the DB-derived hard deadline, and the lease service healthy.
  ready(): boolean {
    return (
      this.claimed &&
      !this.superseded &&
      !this.closed &&
      this.localNow() < this.currentClaimDeadline() &&
      this.leases.healthy()
    );
  }

  // currentClaimDeadline reads the deadline the LIVENESS CHANNEL has published
  // and folds it in. The channel publishes each confirmed renewal into shared
  // memory before it posts anything, so this read sees a renewal the instant
  // the database confirms it — it never waits for the main event loop to drain
  // a message that a data-plane flood is competing with. The deadline only
  // ever moves forward, and only a confirmed renewal moves it.
  private currentClaimDeadline(): number {
    const published = this.heartbeat?.publishedDeadlineLocalMs() ?? null;
    if (published !== null && published > this.claimDeadlineLocalMs) {
      this.claimDeadlineLocalMs = published;
    }
    return this.claimDeadlineLocalMs;
  }

  // ------------------------------------------------------------------
  // Observability (additive, read-only): bounded scalar facts for the
  // manager's /metrics endpoint. No identifiers leave this surface —
  // children are counted, never named.
  // ------------------------------------------------------------------
  observabilitySnapshot(): {
    claimed: boolean;
    superseded: boolean;
    closed: boolean;
    claimRemainingMs: number;
    consecutiveRenewFailures: number;
    managerEpoch: string;
    childrenTotal: number;
    childrenStarting: number;
    childrenCap: number;
    startGateLimit: number;
    startGateHeld: number;
    startGateWaiters: number;
    renewalsTotal: number;
    renewalFailuresTotal: number;
    renewalsDegradedTotal: number;
    childStartsTotal: number;
    childStartFailuresTotal: number;
    childUnexpectedExitsTotal: number;
    idleEvictionsTotal: number;
    startQueueTimeoutsTotal: number;
    atCapacityRefusalsTotal: number;
    tenantAtCapacityRefusalsTotal: number;
  } {
    return {
      claimed: this.claimed,
      superseded: this.superseded,
      closed: this.closed,
      claimRemainingMs: Math.max(0, Math.round(this.currentClaimDeadline() - this.localNow())),
      consecutiveRenewFailures: this.consecutiveRenewFailures,
      managerEpoch: this.identity.managerEpoch,
      childrenTotal: this.authorities.size,
      childrenStarting: this.startingKeys.size,
      childrenCap: this.config.maxAuthorities,
      startGateLimit: this.config.maxConcurrentStarts,
      startGateHeld: this.startGate.heldCount(),
      startGateWaiters: this.startGate.waiterCount(),
      renewalsTotal: this.renewalsTotal,
      renewalFailuresTotal: this.renewalFailuresTotal,
      renewalsDegradedTotal: this.renewalsDegradedTotal,
      childStartsTotal: this.childStartsTotal,
      childStartFailuresTotal: this.childStartFailuresTotal,
      childUnexpectedExitsTotal: this.childUnexpectedExitsTotal,
      idleEvictionsTotal: this.idleEvictionsTotal,
      startQueueTimeoutsTotal: this.startQueueTimeoutsTotal,
      atCapacityRefusalsTotal: this.atCapacityRefusalsTotal,
      tenantAtCapacityRefusalsTotal: this.tenantAtCapacityRefusalsTotal,
    };
  }

  /** Loopback child metrics addresses for the manager-level aggregator. */
  metricsTargets(): Array<{ address: string }> {
    const targets: Array<{ address: string }> = [];
    for (const authority of this.authorities.values()) {
      if (authority.metricsAddress && !authority.exited) {
        targets.push({ address: authority.metricsAddress });
      }
    }
    return targets;
  }

  // ------------------------------------------------------------------
  // AuthorityRegistry surface.
  // ------------------------------------------------------------------

  async ensureAuthority(ref: AuthorityRef): Promise<AuthorityEndpoint> {
    const authority = await this.ensureChild(ref);
    return this.endpointFor(authority);
  }

  async inspectAuthority(ref: AuthorityRef): Promise<AuthorityEndpoint | null> {
    const authority = this.authorities.get(authorityKey(ref));
    return authority ? this.endpointFor(authority) : null;
  }

  async isHealthy(ref: AuthorityRef, _endpoint: AuthorityEndpoint): Promise<boolean> {
    const authority = this.authorities.get(authorityKey(ref));
    if (!authority || authority.exited) {
      return false;
    }
    return this.processReady(authority);
  }

  async ensureAuthorityForLease<T>(
    ref: AuthorityRef,
    create: (binding: AuthorityLeaseBinding) => Promise<T> | T
  ): Promise<{ endpoint: AuthorityEndpoint; result: T }> {
    const key = authorityKey(ref);
    return this.withAuthorityLock(key, async () => {
      const authority = await this.ensureChildLocked(ref);
      const endpoint = this.endpointFor(authority);
      const result = await create({
        endpoint,
        authorityInstanceId: authority.instanceId,
        authorityRuntimeGeneration: authority.runtimeSeq,
        authorityRuntimeId: authority.runtimeId,
      });
      return { endpoint, result };
    });
  }

  resolveDataPlaneRoute(
    authorityInstanceId: string
  ): Pick<AuthorityDataPlaneRoute, "backendAddresses" | "backendAuthToken"> | null {
    for (const authority of this.authorities.values()) {
      if (authority.instanceId === authorityInstanceId && !authority.exited) {
        return {
          backendAddresses: [authority.fsAddress],
          backendAuthToken: authority.backendAuthToken,
        };
      }
    }
    return null;
  }

  // stopAuthority is the ordinary manager-initiated teardown: durable access
  // fence FIRST (fail-closed on a store outage — nothing terminated, the
  // caller retries), then bounded process termination, then the runtime row
  // end. SEAM (vcs-binary wave): the child drain (receipted exact journal
  // suspension) slots between the fence and the termination.
  async stopAuthority(ref: AuthorityRef): Promise<AuthorityStopResult> {
    const expected =
      ref.expectedAuthority?.authorityInstanceId ?? ref.expectedAuthority?.processRef;
    if (!expected) {
      return { stopped: false, managed: true, reason: "missing_authority_instance_id" };
    }
    return this.withAuthorityLock(authorityKey(ref), async () => {
      const authority = this.authorities.get(authorityKey(ref));
      if (!authority) {
        return { stopped: false, managed: true, reason: "not_found" };
      }
      if (authority.instanceId !== expected) {
        return { stopped: false, managed: true, reason: "authority_instance_mismatch" };
      }
      this.requireCurrentEpoch();
      try {
        await this.leases.revokeAuthority(authority.instanceId);
      } catch (error) {
        throw new AuthorityOperationError(
          503,
          authorityOperationErrorCodes.controlStoreRequired,
          `The durable access fence for ${authority.instanceId} did not commit; retry the stop: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
      await this.terminateChild(authority, "stopped");
      return { stopped: true, managed: true };
    });
  }

  // shutdown terminates every child with the ordered durable teardown and
  // releases the claim afterwards so a successor need not wait out the TTL.
  async shutdown(): Promise<void> {
    this.closed = true;
    this.stopTimers();
    for (const timer of this.pendingIdleEvictions.values()) {
      clearTimeout(timer);
    }
    this.pendingIdleEvictions.clear();
    const children = [...this.authorities.values()];
    await Promise.allSettled(
      children.map((authority) =>
        this.withAuthorityLock(authority.key, async () => {
          if (!this.authorities.has(authority.key)) {
            return;
          }
          await this.terminateChild(authority, "manager-shutdown");
        })
      )
    );
    // Unexpected-exit teardowns share the durable ordering; join them so the
    // fence→runtime-end sequence completes (or gives up bounded) before the
    // claim is released.
    await Promise.allSettled([...this.pendingTeardowns]);
    this.leases.close();
    if (!this.superseded) {
      await this.store.releaseManagerClaim({ identity: this.identity }).catch(() => undefined);
    }
  }

  // ------------------------------------------------------------------
  // Singleton claim: renewal loop + local monotonic hard deadline.
  // ------------------------------------------------------------------

  // startClaimHeartbeat proves the liveness channel and starts renewal. The
  // channel runs OFF this event loop on a reserved database connection, so
  // neither a full-speed data-plane flood nor a saturated control pool can
  // delay a renewal. The cadence is TTL/3: three whole renewal windows fit
  // inside one claim lifetime, and each attempt is hard-bounded to one
  // interval by the channel itself, so two consecutive slow attempts can
  // never add up past the TTL.
  private async startClaimHeartbeat(heartbeat: ClaimHeartbeat): Promise<void> {
    if (!heartbeat.isolated) {
      this.log(
        `PortableFS manager epoch ${this.identity.managerEpoch}: the claim heartbeat is IN-PROCESS (not isolated from this event loop). This is correct only for a non-production control store.`
      );
    }
    this.heartbeat = heartbeat;
    this.renewIntervalMs = Math.max(1_000, Math.floor(this.config.claimTtlMs / 3));
    await heartbeat.start({
      identity: this.identity,
      ttlMs: this.config.claimTtlMs,
      intervalMs: this.renewIntervalMs,
      now: this.localNow,
      listeners: {
        onRenewed: (facts) => this.applyRenewal(facts),
        onSuperseded: () => this.onEpochSuperseded(),
        onFailure: (message) => this.onRenewalFailure(message),
      },
    });
  }

  /** True when renewal is driven off this event loop on a reserved connection. */
  claimHeartbeatIsolated(): boolean {
    return this.heartbeat?.isolated === true;
  }

  // applyRenewal projects a CONFIRMED database renewal onto the local
  // monotonic deadline. The anchor was captured BEFORE the statement was
  // issued (on the heartbeat's clock, proven to be this thread's clock at
  // startup), so anchor + granted-remaining can never reach past the true
  // database expiry no matter how slowly the response arrived. The deadline
  // only ever moves FORWARD.
  private applyRenewal(facts: ClaimRenewalFacts): void {
    if (this.closed || this.superseded) {
      return;
    }
    if (
      !Number.isFinite(facts.anchorLocalMs) ||
      !Number.isSafeInteger(facts.dbTimeMs) ||
      !Number.isSafeInteger(facts.claimExpiresAtDbMs)
    ) {
      this.onRenewalFailure("the claim heartbeat reported a malformed renewal");
      return;
    }
    this.renewalsTotal += 1;
    this.consecutiveRenewFailures = 0;
    // THE EARLY WARNING (round 21c). The database reports its OWN cost
    // honestly: dbTimeMs is the post-write clock (migration 038), so the
    // granted window is the TTL minus however long the renewal statement
    // actually took. That makes the schedule's stability condition directly
    // observable, and it is exact rather than tuned: an attempt that starts
    // at t and costs T yields a deadline of t + TTL - T, the next attempt
    // starts at t + interval, so the deadline stays ahead of the schedule
    // precisely while T < interval — i.e. while granted > TTL - interval.
    // Below that the manager is still serving and still correct, but it is
    // no longer self-stabilising, and THAT is the moment worth paging on.
    // Before 038 this window was invisible: a renewal that cost too much was
    // discarded outright, so the only signal was the fence itself.
    const grantedMs = facts.claimExpiresAtDbMs - facts.dbTimeMs;
    if (grantedMs < this.config.claimTtlMs - this.renewIntervalMs) {
      this.renewalsDegradedTotal += 1;
      this.log(
        `PortableFS manager epoch ${this.identity.managerEpoch}: the claim renewal cost ${
          this.config.claimTtlMs - grantedMs
        }ms of its ${this.config.claimTtlMs}ms TTL (granted ${grantedMs}ms, renewal interval ${
          this.renewIntervalMs
        }ms); the control database is slow enough that the renewal schedule is no longer self-stabilising.`
      );
    }
    // currentClaimDeadline() may already carry this renewal (an isolated
    // channel publishes to shared memory before it posts), so compare against
    // the folded value and re-arm on any forward move.
    const before = this.claimDeadlineLocalMs;
    this.currentClaimDeadline();
    const nextDeadline = facts.anchorLocalMs + (facts.claimExpiresAtDbMs - facts.dbTimeMs);
    if (nextDeadline > this.claimDeadlineLocalMs) {
      this.claimDeadlineLocalMs = nextDeadline;
    }
    if (this.claimDeadlineLocalMs > before) {
      this.armDeadlineWatchdog();
    }
    this.writeHeartbeatFrames(facts.dbTimeMs, facts.claimExpiresAtDbMs);
  }

  // An AMBIGUOUS renewal (outage/timeout/dead liveness thread) NEVER extends
  // the deadline and is NEVER silent: the failure count is logged every tick,
  // and the deadline watchdog fences the manager when the DB-time lease runs
  // out.
  private onRenewalFailure(message: string): void {
    if (this.closed || this.superseded) {
      return;
    }
    this.renewalFailuresTotal += 1;
    this.consecutiveRenewFailures += 1;
    this.log(
      `PortableFS manager epoch ${this.identity.managerEpoch}: claim renewal failed (${this.consecutiveRenewFailures} consecutive): ${message}; hard deadline in ${Math.max(
        0,
        this.currentClaimDeadline() - this.localNow()
      )}ms.`
    );
  }

  private armDeadlineWatchdog(): void {
    if (this.deadlineTimer) {
      clearTimeout(this.deadlineTimer);
      this.deadlineTimer = null;
    }
    if (this.closed || this.superseded) {
      return;
    }
    const delayMs = Math.max(0, this.currentClaimDeadline() - this.localNow());
    this.deadlineTimer = setTimeout(() => {
      this.deadlineTimer = null;
      if (this.closed || this.superseded) {
        return;
      }
      // Re-read the published deadline HERE, at the decision. A watchdog that
      // fires late (its own loop was busy) must not fence on a stale copy
      // while a confirmed renewal is already visible in shared memory.
      if (this.localNow() >= this.currentClaimDeadline()) {
        this.log(
          `PortableFS manager epoch ${this.identity.managerEpoch}: the singleton claim's database-time deadline passed without a successful renewal; fencing this manager (readiness false, admission stopped, leases invalidated, children terminated).`
        );
        this.fenceSelf("claim-deadline-exceeded");
        return;
      }
      // A successful renewal moved the deadline while this timer was queued.
      this.armDeadlineWatchdog();
    }, delayMs);
    this.deadlineTimer.unref?.();
  }

  // onEpochSuperseded: another manager claimed a newer epoch. This manager
  // stops mutating IMMEDIATELY.
  private onEpochSuperseded(): void {
    this.fenceSelf("manager-epoch-superseded");
  }

  // fenceSelf: readiness false, admission stopped, every lease/route/tunnel
  // invalidated, heartbeat pipes closed (EOF fences the children), children
  // terminated. The journal truth is remote; a successor manager demand-
  // starts replacements that cold-replay.
  //
  // A fenced manager is TERMINAL. It holds no claim, it can serve nothing, and
  // nothing in this process can ever un-fence it: only a fresh process claims
  // a fresh epoch. So the fence notifies its listeners, and the composition
  // root EXITS on that notification — a fenced manager that lingers is a
  // deployment with no live manager at all (observed: two epochs fenced and
  // then hung for 40+ minutes until a manual redeploy).
  private fenceSelf(reason: string): void {
    if (this.superseded) {
      return;
    }
    this.superseded = true;
    this.claimed = false;
    this.stopTimers();
    this.leases.supersede();
    for (const authority of [...this.authorities.values()]) {
      this.authorities.delete(authority.key);
      authority.managerTerminating = true;
      closeHeartbeat(authority);
      void terminateProcess(authority, this.config.processGraceMs).then(() =>
        rm(authority.workDir, { recursive: true, force: true }).catch(() => undefined)
      );
    }
    this.log(`PortableFS manager epoch ${this.identity.managerEpoch} fenced itself: ${reason}.`);
    this.notifyFenced(reason);
  }

  private notifyFenced(reason: string): void {
    if (this.fencedNotified) {
      return;
    }
    this.fencedNotified = true;
    for (const listener of [...this.fencedListeners]) {
      try {
        listener(reason);
      } catch (error) {
        this.log(
          `PortableFS manager epoch ${this.identity.managerEpoch}: a fence listener threw: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }
  }

  private stopTimers(): void {
    this.heartbeat?.stop();
    this.heartbeat = null;
    if (this.deadlineTimer) {
      clearTimeout(this.deadlineTimer);
      this.deadlineTimer = null;
    }
  }

  private requireCurrentEpoch(): void {
    if (!this.claimed || this.superseded || this.localNow() >= this.currentClaimDeadline()) {
      throw new AuthorityOperationError(
        503,
        authorityOperationErrorCodes.managerEpochSuperseded,
        `Manager epoch ${this.identity.managerEpoch} is superseded, unclaimed, or past its database-time lease deadline; this manager no longer mutates authorities.`
      );
    }
  }

  // ------------------------------------------------------------------
  // Child heartbeat frames (inherited pipe, fd 3).
  //
  // Delivery is LATEST-VALUE, COALESCED, and BOUNDED: at most one write per
  // child is ever in flight; while it is, newer facts REPLACE the single
  // pending slot (superseded frames are discarded, never queued), so Node's
  // writable buffer can never accumulate a backlog of stale lease frames
  // that a stalled child could consume later and mistake for freshness.
  // Every delivered frame carries the next monotonic per-child sequence;
  // the child fences on any non-increasing sequence.
  //
  // A write ERROR or a closed pipe is FATAL for that child: those are proof
  // the channel is gone. write() returning FALSE is not — it is Node's
  // documented flow-control signal ("buffered above the high-water mark,
  // wait for 'drain'"), and treating it as death made a momentarily busy
  // child indistinguishable from a dead one. Nothing is lost by respecting
  // it: coalescing already caps the buffer at one frame, the write callback
  // resumes delivery when the frame reaches the OS, and a child that truly
  // stops draining stops receiving extensions and fences ITSELF on the
  // capability-bound database deadline — the authoritative fence, which the
  // manager cannot improve on by guessing from its own send buffer.
  // ------------------------------------------------------------------

  private writeHeartbeatFrames(dbTimeMs: number, claimExpiresAtDbMs: number): void {
    for (const authority of this.authorities.values()) {
      this.writeHeartbeatFrame(authority, dbTimeMs, claimExpiresAtDbMs);
    }
  }

  private writeHeartbeatFrame(
    authority: ProductionChild,
    dbTimeMs: number,
    claimExpiresAtDbMs: number
  ): void {
    if (!authority.heartbeat || authority.exited || authority.managerTerminating) {
      return;
    }
    if (authority.heartbeatBusy) {
      // Latest value wins: replace (never enqueue behind) any frame that was
      // itself still waiting for the in-flight write to finish.
      authority.heartbeatPending = { dbTimeMs, claimExpiresAtDbMs };
      return;
    }
    this.flushHeartbeatFrame(authority, { dbTimeMs, claimExpiresAtDbMs });
  }

  private flushHeartbeatFrame(authority: ProductionChild, facts: HeartbeatFacts): void {
    if (!authority.heartbeat || authority.exited || authority.managerTerminating) {
      return;
    }
    authority.heartbeatBusy = true;
    authority.heartbeatSeq += 1;
    // WIRE CONTRACT: every millisecond fact is an INTEGER. The child's frame
    // guard rejects fractional values as malformed and FENCES the child, so
    // a locally computed remaining window (which can carry performance.now()
    // fractions) must be floored — never rounded up: a frame may understate
    // the remaining lease, never overstate it.
    const frame = {
      v: 1,
      seq: authority.heartbeatSeq,
      managerEpoch: this.identity.managerEpoch,
      managerRuntimeId: this.identity.managerRuntimeId,
      authorityInstanceId: authority.instanceId,
      authorityRuntimeSeq: authority.runtimeSeq,
      authorityRuntimeId: authority.runtimeId,
      dbTimeMs: Math.floor(facts.dbTimeMs),
      leaseRemainingMs: Math.max(0, Math.floor(facts.claimExpiresAtDbMs - facts.dbTimeMs)),
    };
    try {
      authority.heartbeat.write(`${JSON.stringify(frame)}\n`, (error) => {
        authority.heartbeatBusy = false;
        if (error) {
          this.fenceHeartbeat(authority, `lease frame write failed: ${error.message}`);
          return;
        }
        const pending = authority.heartbeatPending;
        authority.heartbeatPending = null;
        if (pending) {
          this.flushHeartbeatFrame(authority, pending);
        }
      });
    } catch (error) {
      authority.heartbeatBusy = false;
      this.fenceHeartbeat(
        authority,
        `lease frame write threw: ${error instanceof Error ? error.message : String(error)}`
      );
      return;
    }
  }

  private fenceHeartbeat(authority: ProductionChild, cause: string): void {
    if (authority.exited || authority.managerTerminating) {
      return;
    }
    this.log(
      `PortableFS VCS authority ${authority.ref.volumeId}@${authority.ref.branch} (instance ${authority.instanceId}) lease pipe fenced: ${cause}; terminating it.`
    );
    void this.terminateChild(authority, "heartbeat-pipe-fenced");
  }

  // ------------------------------------------------------------------
  // Demand-start children (no adoption, no persistence, no pair).
  // ------------------------------------------------------------------

  private async ensureChild(ref: AuthorityRef): Promise<ProductionChild> {
    return this.withAuthorityLock(authorityKey(ref), () => this.ensureChildLocked(ref));
  }

  private async ensureChildLocked(ref: AuthorityRef): Promise<ProductionChild> {
    this.requireCurrentEpoch();
    const key = authorityKey(ref);
    const existing = this.authorities.get(key);
    if (existing && !existing.exited && (await this.processReady(existing))) {
      // An already-running authority answers here — it never waits on the
      // start gate and is never touched by the resident cap.
      return existing;
    }
    if (existing) {
      // A dead or unready disposable child is REPLACED, never repaired: its
      // acknowledged writes live in the remote journal.
      await this.terminateChild(existing, "replaced-unready");
    }
    // The cap gates NET-NEW residents only (a replaced child above already
    // left the map, so its successor is not net-new). The slot is reserved
    // synchronously so concurrent starts for other scopes cannot slip past
    // the cap while this one is queued or mid-start.
    this.reserveResidentSlot(ref, key);
    let releaseStartPermit: (() => void) | null = null;
    try {
      // Cold starts are individually expensive (journal claim, durability
      // probes, cold replay; up to 4 Postgres connections each before
      // readiness): the global FIFO gate bounds how many run at once so a
      // reconnect stampede cannot exhaust the journal database. The wait is
      // bounded by the same window that bounds a child start itself.
      releaseStartPermit = await this.startGate.acquire(this.config.readyTimeoutMs, () =>
        this.startQueueTimeoutError(ref)
      );
      // The epoch may have moved while queued; never start under a stale claim.
      this.requireCurrentEpoch();
      // Bounded start attempts: a child that loses a port race (binds fail →
      // exits before readiness) is retried on fresh ports; readiness verifies
      // the exact identity so a foreign process on a stolen port can never be
      // adopted.
      let lastError: unknown = null;
      for (let attempt = 1; attempt <= MAX_CHILD_START_ATTEMPTS; attempt += 1) {
        try {
          const started = await this.startChild(ref);
          this.childStartsTotal += 1;
          return started;
        } catch (error) {
          lastError = error;
          this.childStartFailuresTotal += 1;
          if (error instanceof AuthorityOperationError) {
            throw error;
          }
        }
      }
      throw lastError instanceof Error
        ? lastError
        : new Error(`Failed to start the PortableFS VCS authority for ${ref.volumeId}@${ref.branch}.`);
    } finally {
      this.startingKeys.delete(key);
      releaseStartPermit?.();
    }
  }

  // reserveResidentSlot admits ONE net-new resident under the global cap AND
  // the tenant's budget, or refuses typed. Children in the pre-registration
  // stretch of startChild are counted through startingKeys, and the key
  // union counts a scope exactly once whichever side of authorities.set it
  // is on (the per-scope lock guarantees this scope itself is in neither map
  // here).
  private reserveResidentSlot(ref: AuthorityRef, key: string): void {
    // One key→tenant union across resident and starting scopes: the same
    // structure answers both the global count and the per-tenant count.
    const residentTenants = new Map<string, string>();
    for (const [residentKey, authority] of this.authorities) {
      residentTenants.set(residentKey, authority.tenantKey);
    }
    for (const [startingKey, startingTenant] of this.startingKeys) {
      if (!residentTenants.has(startingKey)) {
        residentTenants.set(startingKey, startingTenant);
      }
    }
    if (residentTenants.size >= this.config.maxAuthorities) {
      this.atCapacityRefusalsTotal += 1;
      throw new AuthorityOperationError(
        503,
        authorityOperationErrorCodes.atCapacity,
        `The production registry is at its resident-authority cap (${this.config.maxAuthorities}); refusing to start a new child for ${ref.volumeId}@${ref.branch}. Every resident child holds up to 4 Postgres journal connections — the recorded incident shape is 62 idle children exhausting a 100-connection ceiling. Idle eviction frees capacity; retry after backoff, or raise PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES with matching database headroom.`,
        { retryAfterSeconds: BACKPRESSURE_RETRY_AFTER_SECONDS }
      );
    }
    // The per-tenant budget gates net-new residents of ONE tenant only.
    // 429 (not 503): the service has capacity — this tenant is over its
    // fairness budget — so clients and operators can tell the two apart. A
    // scope without a teamId cannot name a tenant and is refused downstream
    // by the existing AUTHORITY_INVALID_REQUEST path in startChild.
    const tenantCap = this.config.maxAuthoritiesPerTenant;
    const tenantKey = ref.teamId?.trim() ? managedTenantKey(ref) : "";
    if (tenantCap !== undefined && tenantKey !== "") {
      let tenantResident = 0;
      for (const residentTenant of residentTenants.values()) {
        if (residentTenant === tenantKey) {
          tenantResident += 1;
        }
      }
      if (tenantResident >= tenantCap) {
        this.tenantAtCapacityRefusalsTotal += 1;
        throw new AuthorityOperationError(
          429,
          authorityOperationErrorCodes.tenantAtCapacity,
          `Tenant ${ref.teamId} is at its resident-authority budget (${tenantCap}); refusing to start a new child for ${ref.volumeId}@${ref.branch}. Other tenants are unaffected and the service has capacity — release leases or wait for idle eviction to free this tenant's budget, or raise PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT.`,
          { retryAfterSeconds: BACKPRESSURE_RETRY_AFTER_SECONDS }
        );
      }
    }
    this.startingKeys.set(key, tenantKey);
  }

  private startQueueTimeoutError(ref: AuthorityRef): AuthorityOperationError {
    // Only ever constructed when the bounded FIFO wait actually expired, so
    // the counter increments exactly once per refused start.
    this.startQueueTimeoutsTotal += 1;
    return new AuthorityOperationError(
      503,
      authorityOperationErrorCodes.startQueueTimeout,
      `Waited ${this.config.readyTimeoutMs}ms behind ${this.config.maxConcurrentStarts} concurrent child cold starts without a free slot for ${ref.volumeId}@${ref.branch}; retry after backoff. PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS bounds simultaneous cold starts because each opens up to 4 Postgres journal connections and replays from the journal.`,
      { retryAfterSeconds: BACKPRESSURE_RETRY_AFTER_SECONDS }
    );
  }

  // vcsTenantIdFor derives the child's VCS_TENANT_ID from the STRUCTURED ref.
  // In managed production the teamId IS the volume-api metadata tenant id
  // (the journal claim validates volumes.tenant_id against it); a managed
  // scope without a teamId cannot journal remotely and is refused up front.
  private vcsTenantIdFor(ref: AuthorityRef): string {
    const teamId = ref.teamId?.trim();
    if (!teamId) {
      throw new AuthorityOperationError(
        400,
        authorityOperationErrorCodes.invalidRequest,
        `Managed production scope ${ref.volumeId}@${ref.branch} has no teamId: the teamId is the volume-api tenant id and is REQUIRED (journal claims are tenant-scoped in SQL).`
      );
    }
    return teamId;
  }

  private scopeFor(ref: AuthorityRef): AuthorityScopeRef {
    return {
      tenantKey: managedTenantKey(ref),
      volumeId: ref.volumeId,
      branch: ref.branch,
    };
  }

  private async startChild(ref: AuthorityRef): Promise<ProductionChild> {
    const key = authorityKey(ref);
    const vcsTenantId = this.vcsTenantIdFor(ref);
    const instanceId = `pfvcs_${randomUUID()}`;
    const runtimeId = `pfrt_${randomUUID()}`;
    const backendAuthToken = `pfs_backend_${randomBytes(32).toString("base64url")}`;
    const adminToken = `pfs_admin_${randomBytes(32).toString("base64url")}`;
    // The 256-bit authority runtime capability is minted HERE, per runtime:
    // the receipted runtime-begin transaction stores only its hash; the raw
    // value goes to exactly one child process and binds every journal call.
    // It is never logged and never reused across runtimes.
    const authorityCapability = `pfrtcap_${randomBytes(32).toString("base64url")}`;
    const scope = this.scopeFor(ref);

    // SAFE LOCAL PREPARATION FIRST: the ephemeral work dir with private
    // HOME/TMP beneath it (the child starts in an EMPTY cwd — no inherited
    // persistent paths whatsoever). A local failure here leaves NO durable
    // runtime row to reconcile — only the directory, which is removed.
    const workDir = await mkdtemp(path.join(os.tmpdir(), "portablefs-vcs-"));
    const homeDir = path.join(workDir, "home");
    const tmpDir = path.join(workDir, "tmp");
    try {
      await mkdir(homeDir, { recursive: true });
      await mkdir(tmpDir, { recursive: true });
    } catch (error) {
      await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }

    // The runtime row is a REMOTE fact minted per child start (monotonic
    // sequence per scope + this random runtime id + the capability hash); the
    // same transaction ends any previous live runtime of the scope, and every
    // journal transaction cross-checks this row. Every failure AFTER this
    // durable begin is COMPENSATED below: the row ends, the work dir is
    // removed, and any spawned process is terminated — spawn/bootstrap/ready
    // errors can never leak runtime rows, workdirs, or leases.
    let runtime: AuthorityRuntimeBeginResult;
    try {
      runtime = await this.wrapStore(() =>
        this.store.beginAuthorityRuntime({
          identity: this.identity,
          scope,
          authorityInstanceId: instanceId,
          runtimeId,
          operationId: `pfrtbegin_${runtimeId}`,
          authorityCapability,
        })
      );
    } catch (error) {
      await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }

    // The DB-backed short-lived runtime credential is the child's ONLY
    // volume-api identity: a mint failure fails the start (typed), never
    // silently downgrades to a static token.
    let credentialFile: string;
    try {
      credentialFile = await this.mintRuntimeReadCredential({
        vcsTenantId,
        ref,
        runtimeSeq: runtime.runtimeSeq,
        runtimeId,
        workDir,
      });
    } catch (error) {
      await this.endRuntimeRow(scope, runtime.runtimeSeq, runtimeId, "start-failed");
      await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }

    let authority: ProductionChild | null = null;
    try {
      authority = this.spawnPreparedChild(ref, {
        key,
        scope,
        instanceId,
        runtimeId,
        runtime,
        vcsTenantId,
        volumeApiCredentialFile: credentialFile,
        backendAuthToken,
        adminToken,
        authorityCapability,
        workDir,
        homeDir,
        tmpDir,
      });
      const bootstrapPipe = (authority.child.stdio[CHILD_BOOTSTRAP_FD] as Readable | null) ?? null;
      const bootstrap = await this.consumeBootstrap(authority, bootstrapPipe);
      authority.fsAddress = bootstrap.fsAddr;
      authority.metricsAddress = bootstrap.metricsAddr;
      authority.journalGenerationId = bootstrap.journalGenerationId;
      await this.waitForReadiness(authority);
      const readyAuthority = authority;
      readyAuthority.credentialRotation = setInterval(() => {
        void this.rotateRuntimeReadCredential(readyAuthority);
      }, Math.max(Math.floor(RUNTIME_READ_CREDENTIAL_TTL_MS / 3), 60_000));
      readyAuthority.credentialRotation.unref?.();
      return authority;
    } catch (error) {
      if (authority) {
        // Ends the runtime row, kills the process (bounded), removes workDir.
        await this.terminateChild(authority, "failed-to-become-ready");
      } else {
        // The spawn itself threw: nothing runs, but the durable begin exists.
        await this.endRuntimeRow(scope, runtime.runtimeSeq, runtimeId, "start-failed");
        await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
      }
      throw error;
    }
  }

  // endRuntimeRow ends one durable runtime row with bounded retries. Callers
  // MUST have completed the durable access-fence retire first (an ended
  // runtime must never stand over unreconciled leases). A persistent outage
  // leaves the row for the next begin of the same scope to end
  // (beginAuthorityRuntime ends any previous live runtime in the same
  // transaction) — safe, because access is already fenced.
  private async endRuntimeRow(
    scope: AuthorityScopeRef,
    runtimeSeq: string,
    runtimeId: string,
    reason: string
  ): Promise<void> {
    // Only supersession skips (the rows die with the epoch server-side).
    // Shutdown still ends rows: the claim is held until shutdown() releases
    // it AFTER joining every teardown, so a clean shutdown settles to ZERO
    // live runtime rows instead of leaving them for the successor.
    if (this.superseded) {
      return;
    }
    // EXPLICIT deterministic id per semantic end (runtime + reason): every
    // bounded retry below replays the exact receipt; a DIFFERENT teardown
    // path racing this one (its own reason, its own id) observes the
    // already-ended row instead of colliding on shared-id content conflicts.
    const operationId = runtimeEndOperationId(runtimeId, reason);
    for (let i = 1; i <= TEARDOWN_DURABLE_ATTEMPTS; i += 1) {
      try {
        await this.store.endAuthorityRuntime({
          identity: this.identity,
          scope,
          runtimeSeq,
          runtimeId,
          reason,
          operationId,
        });
        return;
      } catch (error) {
        if (error instanceof ManagerEpochSupersededError) {
          this.onEpochSuperseded();
          return;
        }
        this.log(
          `PortableFS VCS runtime ${runtimeSeq} (${scope.volumeId}@${scope.branch}): runtime-end attempt ${i}/${TEARDOWN_DURABLE_ATTEMPTS} failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        if (i < TEARDOWN_DURABLE_ATTEMPTS) {
          await delay(TEARDOWN_RETRY_BACKOFF_MS * i);
        }
      }
    }
    this.log(
      `PortableFS VCS runtime ${runtimeSeq} (${scope.volumeId}@${scope.branch}) stays live after ${TEARDOWN_DURABLE_ATTEMPTS} runtime-end attempts; access is already fenced and the successor's begin settles the row.`
    );
  }

  // mintRuntimeReadCredential mints the DB-backed short-lived credential the
  // child presents to the volume API, and writes the raw secret to a private
  // 0600 file inside the child's ephemeral work dir. The database stores the
  // secret's SHA-256 only, bound to the exact live runtime row.
  private async mintRuntimeReadCredential(args: {
    vcsTenantId: string;
    ref: AuthorityRef;
    runtimeSeq: string;
    runtimeId: string;
    workDir: string;
  }): Promise<string> {
    const secret = `pfrc_${randomBytes(36).toString("base64url")}`;
    await this.wrapStore(() =>
      this.store.runtimeCredentialMint({
        identity: this.identity,
        credentialHash: sha256Hex(secret),
        tenantId: args.vcsTenantId,
        volumeId: args.ref.volumeId,
        branch: args.ref.branch,
        authorityRuntimeSeq: args.runtimeSeq,
        authorityRuntimeId: args.runtimeId,
        ttlMs: RUNTIME_READ_CREDENTIAL_TTL_MS,
      })
    );
    const file = path.join(args.workDir, "volume-api-credential");
    await writeFile(file, `${secret}\n`, { mode: 0o600 });
    return file;
  }

  // rotateRuntimeReadCredential re-mints and atomically replaces the child's
  // credential file. Failures keep the previous credential (it stays valid
  // until its DB-time expiry) and the next tick retries; a scope that stops
  // minting simply stops receiving fresh credentials, which IS the
  // revocation semantics.
  private async rotateRuntimeReadCredential(authority: ProductionChild): Promise<void> {
    if (authority.managerTerminating || authority.exited) {
      return;
    }
    const secret = `pfrc_${randomBytes(36).toString("base64url")}`;
    try {
      await this.wrapStore(() =>
        this.store.runtimeCredentialMint({
          identity: this.identity,
          credentialHash: sha256Hex(secret),
          tenantId: authority.vcsTenantId,
          volumeId: authority.ref.volumeId,
          branch: authority.ref.branch,
          authorityRuntimeSeq: authority.runtimeSeq,
          authorityRuntimeId: authority.runtimeId,
          ttlMs: RUNTIME_READ_CREDENTIAL_TTL_MS,
        })
      );
      const tmp = `${authority.volumeApiCredentialFile}.tmp-${randomBytes(8).toString("hex")}`;
      await writeFile(tmp, `${secret}\n`, { mode: 0o600 });
      await rename(tmp, authority.volumeApiCredentialFile);
    } catch (error) {
      this.log(
        `runtime_credential_rotation_failed ${authority.ref.volumeId}@${authority.ref.branch}: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  private spawnPreparedChild(
    ref: AuthorityRef,
    prepared: {
      key: string;
      scope: AuthorityScopeRef;
      instanceId: string;
      runtimeId: string;
      runtime: AuthorityRuntimeBeginResult;
      vcsTenantId: string;
      volumeApiCredentialFile: string;
      backendAuthToken: string;
      adminToken: string;
      authorityCapability: string;
      workDir: string;
      homeDir: string;
      tmpDir: string;
    }
  ): ProductionChild {
    const {
      key,
      scope,
      instanceId,
      runtimeId,
      runtime,
      vcsTenantId,
      volumeApiCredentialFile,
      backendAuthToken,
      adminToken,
      authorityCapability,
      workDir,
      homeDir,
      tmpDir,
    } = prepared;
    // The child environment is BUILT FROM SCRATCH under a STRICT EXACT
    // contract (never inherited beyond PATH, never pattern-copied):
    // manager-owned identity/scope/credential/journal variables first, then
    // the exact allowlisted tuning extras. No VCS_CACHE_DIR, no VCS_WAL, no
    // topology, no listener addresses (the child binds 127.0.0.1:0 itself
    // and reports the exact addresses on the bootstrap pipe).
    const env: NodeJS.ProcessEnv = {
      ...(process.env.PATH ? { PATH: process.env.PATH } : {}),
      HOME: homeDir,
      TMPDIR: tmpDir,
      ...this.config.extraChildEnv,
      VOLUME_API_URL: this.config.volumeApiUrl,
      // The rotating manager-minted runtime credential is the child's ONLY
      // volume-api identity (the Go client re-reads the file on change).
      VOLUME_API_TOKEN_FILE: volumeApiCredentialFile,
      VCS_VOLUME_ID: ref.volumeId,
      VCS_BRANCH: ref.branch,
      VCS_AUTH_TOKEN: backendAuthToken,
      VCS_ADMIN_TOKEN: adminToken,
      VCS_AUTHORITY_INSTANCE_ID: instanceId,
      VCS_WRITABLE: "1",
      VCS_PRODUCTION: "1",
      // The remote journal contract (the ONLY durability truth) plus the
      // structured HA policy the child verifies evidence against.
      VCS_JOURNAL_DSN: this.config.journalDsn,
      ...(this.config.journalPoolerMode
        ? { VCS_JOURNAL_POOLER_MODE: this.config.journalPoolerMode }
        : {}),
      VCS_TENANT_ID: vcsTenantId,
      VCS_JOURNAL_HA_POLICY_JSON: this.config.journalHaPolicyJson,
      // Exact manager/runtime facts: every journal claim/append/suspend
      // transaction presents these and the database cross-checks the live
      // pfm rows, so a stuck child cannot write past DB-time expiry. The raw
      // capability binds the calls; only its hash is stored anywhere.
      VCS_MANAGER_EPOCH: this.identity.managerEpoch,
      VCS_MANAGER_RUNTIME_ID: this.identity.managerRuntimeId,
      VCS_AUTHORITY_RUNTIME_SEQ: runtime.runtimeSeq,
      VCS_AUTHORITY_RUNTIME_ID: runtimeId,
      VCS_AUTHORITY_RUNTIME_CAPABILITY: authorityCapability,
      // The inherited pipes: EOF/malformed/stale lease frames or the frame
      // deadline fence the child before the manager's DB lease can expire;
      // the bootstrap pipe reports the exact self-bound addresses back.
      VCS_HEARTBEAT_FD: String(CHILD_HEARTBEAT_FD),
      VCS_BOOTSTRAP_FD: String(CHILD_BOOTSTRAP_FD),
      ...(this.config.leaseTtlSeconds ? { VCS_LEASE_TTL: this.config.leaseTtlSeconds } : {}),
    };

    const child = this.spawnProcess(this.config.vcsBin, [], {
      cwd: workDir,
      env,
      stdio: ["ignore", "pipe", "pipe", "pipe", "pipe"],
    });
    const heartbeat = (child.stdio[CHILD_HEARTBEAT_FD] as Writable | null) ?? null;
    const authority: ProductionChild = {
      key,
      ref: { ...ref },
      instanceId,
      runtimeSeq: runtime.runtimeSeq,
      runtimeId,
      tenantKey: scope.tenantKey,
      vcsTenantId,
      backendAuthToken,
      adminToken,
      workDir,
      fsAddress: "",
      metricsAddress: "",
      journalGenerationId: "",
      child,
      heartbeat,
      heartbeatSeq: 0,
      heartbeatBusy: false,
      heartbeatPending: null,
      exited: false,
      managerTerminating: false,
      volumeApiCredentialFile,
    };
    // EVERY child-failure listener is attached synchronously, BEFORE the
    // first await: a spawn failure (e.g. ENOENT for the binary) emits
    // 'error' — possibly with NO 'exit' ever — and an unhandled 'error'
    // event would crash the manager process.
    child.once("exit", () => {
      authority.exited = true;
      this.onChildExit(authority);
    });
    child.once("error", (error: Error) => {
      // Spawn/signal failure: treat exactly like an exit (there may never
      // be one). onChildExit is idempotent per authority.
      this.log(
        `PortableFS VCS authority ${ref.volumeId}@${ref.branch} (instance ${instanceId}) child process failed: ${error.message}`
      );
      authority.exited = true;
      this.onChildExit(authority);
    });
    // A lease pipe that errors or closes underneath us fences the child
    // (write callbacks see the same failure; the listener prevents an
    // uncaught 'error' event and covers unsolicited closes).
    heartbeat?.on("error", (error: Error) => {
      this.fenceHeartbeat(authority, `lease pipe error: ${error.message}`);
    });
    heartbeat?.on("close", () => {
      this.fenceHeartbeat(authority, "lease pipe closed");
    });
    const prefix =
      `[portablefs-vcs production ${escapeLogControls(ref.volumeId)}` +
      `@${escapeLogControls(ref.branch)}]`;
    child.stdout?.on("data", (chunk) =>
      process.stdout.write(formatChildLogChunk(prefix, chunk))
    );
    child.stderr?.on("data", (chunk) =>
      process.stderr.write(formatChildLogChunk(prefix, chunk))
    );

    this.authorities.set(key, authority);
    // First heartbeat frame immediately: the child requires one before
    // serving (it carries the exact identity + remaining DB lease).
    this.writeHeartbeatFrame(
      authority,
      runtime.dbTimeMs,
      // Approximate remaining lease from the LOCAL deadline; subsequent
      // renewals carry exact DB facts.
      runtime.dbTimeMs + Math.max(0, this.currentClaimDeadline() - this.localNow())
    );
    return authority;
  }

  // consumeBootstrap reads EXACTLY ONE bounded newline-terminated JSON frame
  // from the child's bootstrap pipe and validates every field: version,
  // identity (instance, scope, manager epoch, runtime seq/id), loopback-only
  // addresses, and the HA policy hash the child verified. A truncated,
  // oversized, foreign, or absent frame is a startup failure — the manager
  // never adopts a listener it did not receive through this exact channel.
  private consumeBootstrap(
    authority: ProductionChild,
    pipe: Readable | null
  ): Promise<{ fsAddr: string; metricsAddr: string; journalGenerationId: string }> {
    if (!pipe) {
      return Promise.reject(
        new Error("The spawned child exposes no bootstrap pipe (fd 4); refusing to adopt it.")
      );
    }
    return new Promise((resolve, reject) => {
      let buffer = Buffer.alloc(0);
      let settled = false;
      const fail = (message: string) => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(new Error(message));
        }
      };
      const timeout = setTimeout(() => {
        fail(`The child did not report its bootstrap frame within ${this.config.readyTimeoutMs}ms.`);
      }, this.config.readyTimeoutMs);
      timeout.unref?.();
      const onData = (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.byteLength > MAX_PIPE_FRAME_BYTES) {
          fail("The child's bootstrap frame exceeds the 4 KiB bound.");
          return;
        }
        const newline = buffer.indexOf(0x0a);
        if (newline === -1) {
          return;
        }
        // EXACTLY ONE frame: bytes after the newline (a second frame, or
        // garbage) mean the pipe is not speaking the one-shot protocol —
        // refuse the child rather than adopt the first frame and ignore the
        // rest.
        if (newline !== buffer.byteLength - 1) {
          fail(
            "The child's bootstrap pipe carries trailing bytes after the one-shot frame; refusing to adopt it."
          );
          return;
        }
        const line = buffer.subarray(0, newline).toString("utf8");
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        try {
          resolve(this.validateBootstrapFrame(authority, line));
        } catch (error) {
          reject(error);
        }
      };
      const onEnd = () => fail("The child's bootstrap pipe closed before a complete frame.");
      const onError = (error: Error) => fail(`The child's bootstrap pipe failed: ${error.message}`);
      // A child that dies (or never spawned: ENOENT emits 'error' with no
      // 'exit') can never report a frame; fail promptly, never wait out the
      // whole timeout.
      const onChildGone = () =>
        fail("The child exited or failed before reporting its bootstrap frame.");
      const cleanup = () => {
        clearTimeout(timeout);
        pipe.off("data", onData);
        pipe.off("end", onEnd);
        pipe.off("error", onError);
        authority.child.off("exit", onChildGone);
        authority.child.off("error", onChildGone);
      };
      pipe.on("data", onData);
      pipe.once("end", onEnd);
      pipe.once("error", onError);
      authority.child.once("exit", onChildGone);
      authority.child.once("error", onChildGone);
      if (authority.exited) {
        onChildGone();
      }
    });
  }

  private validateBootstrapFrame(
    authority: ProductionChild,
    line: string
  ): { fsAddr: string; metricsAddr: string; journalGenerationId: string } {
    let frame: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(line);
      if (!isRecord(parsed)) {
        throw new Error("not an object");
      }
      frame = parsed;
    } catch (error) {
      throw new Error(
        `The child's bootstrap frame is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    const expectEqual = (field: string, expected: string) => {
      if (frame[field] !== expected) {
        throw new Error(
          `The child's bootstrap frame names a foreign ${field} (${JSON.stringify(frame[field])}, expected ${JSON.stringify(expected)}); refusing to adopt it.`
        );
      }
    };
    if (frame.v !== 1 || frame.protocolVersion !== MANAGED_CHILD_PROTOCOL_VERSION) {
      throw new Error(
        `The child speaks bootstrap/protocol version ${String(frame.v)}/${String(frame.protocolVersion)}; this manager requires 1/${MANAGED_CHILD_PROTOCOL_VERSION}.`
      );
    }
    expectEqual("authorityInstanceId", authority.instanceId);
    expectEqual("volumeId", authority.ref.volumeId);
    expectEqual("branch", authority.ref.branch);
    expectEqual("managerEpoch", this.identity.managerEpoch);
    expectEqual("authorityRuntimeSeq", authority.runtimeSeq);
    expectEqual("authorityRuntimeId", authority.runtimeId);
    expectEqual("haPolicyHash", this.config.journalHaPolicyHash);
    const fsAddr = requireLoopbackAddress(frame.fsAddr, "fsAddr");
    const metricsAddr = requireLoopbackAddress(frame.metricsAddr, "metricsAddr");
    const journalGenerationId = frame.journalGenerationId;
    if (typeof journalGenerationId !== "string" || !journalGenerationId) {
      throw new Error("The child's bootstrap frame carries no journal generation id.");
    }
    return { fsAddr, metricsAddr, journalGenerationId };
  }

  // onChildExit fences an UNEXPECTED child exit: the LOCAL fence is
  // synchronous (routes died with the map entry; every lease projection ends
  // NOW, closing tunnels), and the durable teardown is STRICTLY ORDERED —
  // the access-fence retire must COMMIT before the runtime row ends. The
  // reverse order would let a lost retire leave active, renewable lease rows
  // behind an already-ended runtime. Crash-safe by construction: revoke-first
  // plus a crash leaves the runtime row live with ALL access fenced, and the
  // successor's begin (same scope, one transaction) or the due sweep ends it.
  // Manager-initiated teardown paths set managerTerminating and share this
  // exact ordering through terminateChild.
  private onChildExit(authority: ProductionChild): void {
    if (authority.credentialRotation) {
      clearInterval(authority.credentialRotation);
      authority.credentialRotation = undefined;
    }
    if (authority.managerTerminating) {
      return;
    }
    const current = this.authorities.get(authority.key);
    if (current !== authority) {
      return;
    }
    this.childUnexpectedExitsTotal += 1;
    this.authorities.delete(authority.key);
    closeHeartbeat(authority);
    // SYNCHRONOUS local fence; the durable retire promise is kept for the
    // ordered teardown below (never lost, never raced).
    const firstRevoke = this.leases.revokeAuthority(authority.instanceId);
    firstRevoke.catch(() => undefined);
    const teardown = this.settleTeardownDurably(authority, "child-exited", firstRevoke);
    this.pendingTeardowns.add(teardown);
    void teardown.finally(() => this.pendingTeardowns.delete(teardown));
    this.log(
      `PortableFS VCS authority ${authority.ref.volumeId}@${authority.ref.branch} (instance ${authority.instanceId}, runtime ${authority.runtimeSeq}) exited unexpectedly; access fenced locally, durable fence then runtime end in order.`
    );
  }

  // settleTeardownDurably drives the ordered durable teardown of one child:
  // (1) the access-fence retire COMMITS (bounded idempotent retries — the
  // deterministic pfretire-<instanceId> receipt makes every retry an exact
  // replay), (2) only then the runtime row ends, (3) the work dir is removed.
  // If the fence never commits, the runtime row is deliberately LEFT LIVE:
  // an ended runtime must never stand over unreconciled leases, while a live
  // runtime row over fenced access is harmless and reconciled by the
  // successor's begin or the sweep.
  private async settleTeardownDurably(
    authority: ProductionChild,
    reason: string,
    firstRevoke?: Promise<void>
  ): Promise<void> {
    const revoked = await this.revokeAuthorityDurably(authority.instanceId, firstRevoke);
    if (revoked) {
      await this.endRuntimeRow(
        this.scopeFor(authority.ref),
        authority.runtimeSeq,
        authority.runtimeId,
        reason
      );
    } else {
      this.log(
        `PortableFS VCS authority instance ${authority.instanceId}: the durable access fence did not commit within ${TEARDOWN_DURABLE_ATTEMPTS} attempts; leaving runtime ${authority.runtimeSeq} LIVE (all access is locally fenced; the successor's runtime begin or the due sweep settles both).`
      );
    }
    await rm(authority.workDir, { recursive: true, force: true }).catch(() => undefined);
  }

  // revokeAuthorityDurably awaits the durable access-fence retire with
  // bounded retries. Epoch supersession counts as settled (the rows die with
  // the epoch server-side); a store outage after every retry reports false.
  private async revokeAuthorityDurably(
    instanceId: string,
    firstAttempt?: Promise<void>
  ): Promise<boolean> {
    let attempt = firstAttempt ?? this.leases.revokeAuthority(instanceId);
    for (let i = 1; ; i += 1) {
      try {
        await attempt;
        return true;
      } catch (error) {
        this.log(
          `PortableFS VCS authority instance ${instanceId}: durable access-fence attempt ${i}/${TEARDOWN_DURABLE_ATTEMPTS} failed: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        if (i >= TEARDOWN_DURABLE_ATTEMPTS || this.superseded) {
          return false;
        }
        await delay(TEARDOWN_RETRY_BACKOFF_MS * i);
        attempt = this.leases.revokeAuthority(instanceId);
      }
    }
  }

  private endpointFor(authority: ProductionChild): AuthorityEndpoint {
    return {
      provider: this.config.provider,
      authorityUrl: this.config.routerUrl,
      host: this.config.routerAddress.host,
      port: this.config.routerAddress.port,
      authorityInstanceId: authority.instanceId,
    };
  }

  private async waitForReadiness(authority: ProductionChild): Promise<void> {
    // Readiness timeout on the injected MONOTONIC clock: a wall-clock step
    // during startup must neither instantly expire nor stretch the window.
    const deadline = this.localNow() + this.config.readyTimeoutMs;
    while (this.localNow() < deadline) {
      if (authority.exited) {
        throw new Error(
          `PortableFS VCS authority ${authority.ref.volumeId}@${authority.ref.branch} exited before becoming ready.`
        );
      }
      if (await this.processReady(authority)) {
        return;
      }
      await delay(DEFAULT_READY_POLL_MS);
    }
    throw new Error(
      `PortableFS VCS authority ${authority.ref.volumeId}@${authority.ref.branch} did not become ready in ${this.config.readyTimeoutMs}ms.`
    );
  }

  // processReady verifies the EXACT identity of the process answering the
  // readiness probe — instance, volume/branch, journal mode + generation,
  // manager epoch, runtime sequence and runtime id, protocol version, and
  // the HA policy hash the child verified — not merely ready:true. A foreign
  // process that rebound a recycled port can never be adopted.
  private async processReady(authority: ProductionChild): Promise<boolean> {
    if (!authority.metricsAddress) {
      return false;
    }
    // Per-request abort bound: one wedged /readyz socket (a stalled child, a
    // half-open connection) must never consume the whole readiness window.
    const controller = new AbortController();
    const probeTimeout = setTimeout(() => controller.abort(), READY_PROBE_TIMEOUT_MS);
    const response = await this.fetchImpl(`http://${authority.metricsAddress}/readyz`, {
      signal: controller.signal,
    })
      .catch(() => null)
      .finally(() => clearTimeout(probeTimeout));
    if (!response?.ok) {
      return false;
    }
    const body = await response.json().catch(() => null);
    if (!isRecord(body) || body.ready !== true) {
      return false;
    }
    return (
      body.authorityInstanceId === authority.instanceId &&
      body.volumeId === authority.ref.volumeId &&
      body.branch === authority.ref.branch &&
      body.journal === "remote" &&
      body.managerEpoch === this.identity.managerEpoch &&
      body.authorityRuntimeSeq === authority.runtimeSeq &&
      body.authorityRuntimeId === authority.runtimeId &&
      body.journalGenerationId === authority.journalGenerationId &&
      body.protocolVersion === MANAGED_CHILD_PROTOCOL_VERSION &&
      body.haPolicyHash === this.config.journalHaPolicyHash &&
      // Readiness must describe the ACTUAL bound listeners — the exact
      // addresses this manager adopted from the bootstrap frame.
      body.fsAddr === authority.fsAddress &&
      body.metricsAddr === authority.metricsAddress
    );
  }

  // terminateChild is the SHARED manager-initiated teardown (stop, forced,
  // heartbeat fence, replaced-unready, failed-to-become-ready, shutdown,
  // idle eviction). It enforces the same durable ordering as onChildExit:
  // local fence synchronously, kill the process (bounded), then durable
  // access-fence retire BEFORE the runtime row ends. Paths that already
  // retired durably replay the same pfretire receipt — idempotent, one
  // extra read.
  private async terminateChild(authority: ProductionChild, reason: string): Promise<void> {
    this.authorities.delete(authority.key);
    authority.managerTerminating = true;
    if (authority.credentialRotation) {
      clearInterval(authority.credentialRotation);
      authority.credentialRotation = undefined;
    }
    closeHeartbeat(authority);
    // SYNCHRONOUS local fence for any leases still projecting this instance
    // (paths that already fenced replay it as a no-op).
    const firstRevoke = this.leases.revokeAuthority(authority.instanceId);
    firstRevoke.catch(() => undefined);
    await terminateProcess(authority, this.config.processGraceMs);
    await this.settleTeardownDurably(authority, reason, firstRevoke);
  }

  private async wrapStore<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (error) {
      if (error instanceof ManagerEpochSupersededError) {
        this.onEpochSuperseded();
        throw new AuthorityOperationError(
          503,
          authorityOperationErrorCodes.managerEpochSuperseded,
          `Manager epoch ${this.identity.managerEpoch} has been superseded; this manager no longer mutates authorities.`
        );
      }
      if (error instanceof ControlStoreUnavailableError) {
        throw new AuthorityOperationError(
          503,
          authorityOperationErrorCodes.controlStoreRequired,
          `The manager control store refused the durable transition; nothing changed: ${error.message}`
        );
      }
      throw error;
    }
  }

  // ------------------------------------------------------------------
  // Per-authority serialization + idle eviction.
  // ------------------------------------------------------------------

  private withAuthorityLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.authorityLocks.get(key) ?? Promise.resolve();
    const run = previous.then(fn, fn);
    const settled = run.then(
      () => undefined,
      () => undefined
    );
    this.authorityLocks.set(key, settled);
    void settled.then(() => {
      if (this.authorityLocks.get(key) === settled) {
        this.authorityLocks.delete(key);
      }
    });
    return run;
  }

  private scheduleIdleEviction(refKey: string): void {
    // Always a resolved positive number: readIdleEvictionGraceMs rejects
    // "off"/zero/negative at startup, so idle eviction can be re-tuned but
    // never disabled.
    const graceMs = this.config.idleEvictionGraceMs;
    if (this.closed || this.superseded) {
      return;
    }
    if (!this.authorities.has(refKey) || this.pendingIdleEvictions.has(refKey)) {
      return;
    }
    const timer = setTimeout(() => {
      this.pendingIdleEvictions.delete(refKey);
      void this.runIdleEviction(refKey);
    }, graceMs);
    timer.unref?.();
    this.pendingIdleEvictions.set(refKey, timer);
  }

  private cancelIdleEviction(refKey: string): void {
    const timer = this.pendingIdleEvictions.get(refKey);
    if (timer) {
      clearTimeout(timer);
      this.pendingIdleEvictions.delete(refKey);
    }
  }

  // Idle eviction must LOSE to any concurrent create/renew: it snapshots the
  // activity version and aborts if the version moved after ANY await. The
  // teardown shares the ordered durable fence (retire commits before the
  // runtime row ends). SEAM (vcs-binary wave): the child drain slots between
  // the committed fence and terminateChild.
  private async runIdleEviction(refKey: string): Promise<void> {
    const authority = this.authorities.get(refKey);
    if (!authority || this.closed || this.superseded) {
      return;
    }
    const startVersion = this.leases.activityVersion(refKey);
    const abortIfActive = () =>
      this.leases.activityVersion(refKey) !== startVersion ||
      this.leases.activeLeaseCount(refKey) > 0;
    if (abortIfActive()) {
      return;
    }
    await this.withAuthorityLock(refKey, async () => {
      const current = this.authorities.get(refKey);
      if (!current || current.instanceId !== authority.instanceId) {
        return;
      }
      if (abortIfActive() || this.closed || this.superseded) {
        return;
      }
      try {
        await this.leases.revokeAuthority(current.instanceId);
      } catch (error) {
        // The durable fence did not commit (store outage): leave the
        // authority running and RE-ARM the grace timer ourselves. Waiting
        // for the "next zero-active signal" would wait forever — with zero
        // active leases no lease can end, so no zero-active edge ever fires
        // again and one transient outage would leak the resident child until
        // unrelated new lease activity.
        this.log(
          `PortableFS idle eviction for ${current.ref.volumeId}@${current.ref.branch} deferred (retrying after another grace period): ${
            error instanceof Error ? error.message : String(error)
          }`
        );
        this.scheduleIdleEviction(refKey);
        return;
      }
      if (abortIfActive()) {
        // A create landed between the version check and the fence commit:
        // its lease was retired by the batch, so the child no longer serves
        // an authorized lease. Proceed with the eviction; the consumer
        // reacquires against a fresh child.
        this.log(
          `PortableFS idle eviction for ${current.ref.volumeId}@${current.ref.branch} raced a new lease; the fence already committed, evicting anyway (consumers reacquire).`
        );
      }
      await this.terminateChild(current, "idle-evicted");
      this.idleEvictionsTotal += 1;
    });
  }
}

// createProductionAuthorityRegistry composes the production registry. The
// remote ManagerControlStore MUST be injected — missing injection is an
// honest readiness failure (AUTHORITY_CONTROL_STORE_REQUIRED), never a silent
// file fallback.
export async function createProductionAuthorityRegistry(
  env: ProductionAuthorityRegistryEnvConfig,
  deps: Partial<ProductionAuthorityRegistryDeps>
): Promise<ProductionAuthorityRegistry> {
  const config = readProductionAuthorityRegistryConfig(env);
  if (!deps.controlStore) {
    throw new AuthorityOperationError(
      503,
      authorityOperationErrorCodes.controlStoreRequired,
      "The production authority registry requires the remote ManagerControlStore adapter (PORTABLEFS_MANAGER_CONTROL_DATABASE_URL). Until one is injected, production readiness fails closed; there is no file fallback."
    );
  }
  return ProductionAuthorityRegistry.create(config, {
    controlStore: deps.controlStore,
    ...(deps.fetch ? { fetch: deps.fetch } : {}),
    ...(deps.spawnProcess ? { spawnProcess: deps.spawnProcess } : {}),
    ...(deps.localNow ? { localNow: deps.localNow } : {}),
    ...(deps.log ? { log: deps.log } : {}),
  });
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// Structured key (length-delimited JSON array): no colon-concatenation
// collisions between teamId/volumeId/branch values. Identical to the lease
// service's accessLeaseRefKey so idle-eviction ref keys address the same map.
function authorityKey(ref: Pick<AuthorityRef, "teamId" | "volumeId" | "branch">): string {
  return JSON.stringify([ref.teamId ?? "", ref.volumeId, ref.branch]);
}

function closeHeartbeat(authority: ProductionChild): void {
  if (!authority.heartbeat) {
    return;
  }
  try {
    authority.heartbeat.end();
  } catch {
    // Already broken: the child is gone.
  }
  authority.heartbeat = null;
}

// terminateProcess is the BOUNDED SIGTERM→SIGKILL teardown. It resolves when
// the child reports exit, close, OR error (a spawn-failed child may only
// ever emit 'error'), and after SIGKILL it waits at most one more grace
// period: a process that ignores signals (or a fake that swallows them) can
// never hang manager teardown.
async function terminateProcess(
  authority: { child: ChildProcess; exited: boolean },
  graceMs: number
): Promise<void> {
  if (authority.exited) {
    return;
  }
  const gone = new Promise<void>((resolve) => {
    if (authority.exited) {
      resolve();
      return;
    }
    const done = () => resolve();
    authority.child.once("exit", done);
    authority.child.once("close", done);
    authority.child.once("error", done);
  });
  const kill = (signal: NodeJS.Signals) => {
    try {
      authority.child.kill(signal);
    } catch {
      // An already-reaped or never-spawned process: nothing to signal.
    }
  };
  kill("SIGTERM");
  await Promise.race([gone, delay(graceMs)]);
  if (!authority.exited) {
    kill("SIGKILL");
    await Promise.race([gone, delay(graceMs)]);
  }
}

// requireLoopbackAddress validates one bootstrap-reported listener address:
// the managed data/control planes are loopback-only by contract, and the
// exact port is the child's own bind (no pre-allocation TOCTOU, no foreign
// listener adoption).
function requireLoopbackAddress(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(value)) {
    throw new Error(
      `The child's bootstrap frame reports a non-loopback or malformed ${field} (${JSON.stringify(value)}); refusing to adopt it.`
    );
  }
  const port = Number(value.slice("127.0.0.1:".length));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`The child's bootstrap frame reports an invalid ${field} port.`);
  }
  return value;
}

function normalizeOptionalString(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized ? normalized : undefined;
}

function readPositiveInt(value: string | undefined): number | undefined {
  const normalized = normalizeOptionalString(value);
  if (!normalized) {
    return undefined;
  }
  const parsed = Number(normalized);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

// readIdleEvictionGraceMs resolves PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS:
//   - unset -> DEFAULT_IDLE_EVICTION_GRACE_MS (idle eviction is ALWAYS on);
//   - a positive integer (milliseconds) -> that grace;
//   - "off", zero, or negative -> a startup error. Idle children are not
//     free: each holds up to 4 Postgres journal connections for as long as
//     it runs, and disabling eviction is exactly the recorded incident
//     shape (62 idle vcs-* children against a 100-connection ceiling, live
//     connection rejections). Eviction can be re-tuned, never turned off.
// Anything else (a float, prose) is also a startup error — no silent
// fallback to the default.
function readIdleEvictionGraceMs(value: string | undefined): number {
  const normalized = normalizeOptionalString(value);
  if (normalized === undefined) {
    return DEFAULT_IDLE_EVICTION_GRACE_MS;
  }
  const parsed = Number(normalized);
  if (normalized === "off" || (Number.isFinite(parsed) && parsed <= 0)) {
    throw new Error(
      `PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS="${normalized}" would disable idle child eviction, which cannot be disabled: every resident child holds up to 4 Postgres journal connections for as long as it runs, and running without eviction is the recorded connection-exhaustion incident shape (62 idle vcs-* children against a 100-connection ceiling). Unset it for the ${DEFAULT_IDLE_EVICTION_GRACE_MS}ms default or set a positive integer number of milliseconds.`
    );
  }
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(
      `PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS must be a positive integer number of milliseconds (got "${normalized}"); unset it for the ${DEFAULT_IDLE_EVICTION_GRACE_MS}ms default.`
    );
  }
  return parsed;
}

// requirePositiveInt reads one capacity knob fail-closed: unset applies the
// default, but a set-and-malformed value (a typo, zero, a negative) is a
// startup error — silently falling back would defeat the operator's intent
// exactly when the knob matters.
function requirePositiveInt(name: string, value: string | undefined, defaultValue: number): number {
  const normalized = normalizeOptionalString(value);
  if (normalized === undefined) {
    return defaultValue;
  }
  const parsed = Number(normalized);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(
      `${name} must be a positive integer (got "${normalized}"); unset it for the default (${defaultValue}).`
    );
  }
  return parsed;
}

// optionalPositiveInt reads one OPTIONAL fairness knob with the same
// fail-closed discipline: unset means the knob is off (no behavior change),
// while a set-and-malformed value refuses boot instead of silently running
// uncapped — the exact failure mode the knob exists to prevent.
function optionalPositiveInt(name: string, value: string | undefined): number | undefined {
  const normalized = normalizeOptionalString(value);
  if (normalized === undefined) {
    return undefined;
  }
  const parsed = Number(normalized);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(
      `${name} must be a positive integer (got "${normalized}"); unset it to disable the per-tenant cap.`
    );
  }
  return parsed;
}

// StartSemaphore bounds CONCURRENT cold starts (not resident children).
// Waiters are strictly FIFO with a bounded wait; a timed-out waiter is
// removed from the queue so a freed permit always reaches a live waiter, and
// every acquisition's release is idempotent.
class StartSemaphore {
  private held = 0;
  private readonly waiters: Array<{
    grant: (release: () => void) => void;
    cancel: () => void;
  }> = [];

  constructor(private readonly limit: number) {}

  heldCount(): number {
    return this.held;
  }

  waiterCount(): number {
    return this.waiters.length;
  }

  acquire(timeoutMs: number, timeoutError: () => Error): Promise<() => void> {
    if (this.held < this.limit) {
      this.held += 1;
      return Promise.resolve(this.releaseOnce());
    }
    return new Promise<() => void>((resolve, reject) => {
      const waiter = {
        grant: (release: () => void) => {
          clearTimeout(timer);
          resolve(release);
        },
        cancel: () => reject(timeoutError()),
      };
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) {
          this.waiters.splice(index, 1);
          waiter.cancel();
        }
      }, timeoutMs);
      timer.unref?.();
      this.waiters.push(waiter);
    });
  }

  private releaseOnce(): () => void {
    let released = false;
    return () => {
      if (released) {
        return;
      }
      released = true;
      const next = this.waiters.shift();
      if (next) {
        // The permit transfers to the FIFO head; the held count is unchanged.
        next.grant(this.releaseOnce());
        return;
      }
      this.held -= 1;
    };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
