import { createHash, createHmac } from "node:crypto";
import { Pool, type PoolConfig } from "pg";
import {
  InProcessClaimHeartbeat,
  WorkerClaimHeartbeat,
  type ClaimHeartbeat,
} from "./claim-heartbeat.js";
import {
  parseAccessLeaseControlSeq,
  parseAccessLeaseTokenGeneration,
  parseManagerEpoch,
  type AccessLeaseControlSeq,
  type AccessLeaseEndReason,
  type AccessLeaseState,
  type AccessLeaseTokenGeneration,
  type ManagerEpoch,
} from "@portablefs/protocol";

// ---------------------------------------------------------------------------
// ManagerControlStore: the narrow remote control-plane truth the singleton
// PRODUCTION authority manager runs against. Backed by the pfm schema (see
// the manager-control migration under packages/metadata-db/migrations): the
// singleton manager claim (a DB-time lease), per-scope authority runtime
// rows, access lease rows, and permanently retained operation receipts.
//
// Every mutation is ONE database transaction inside a SECURITY DEFINER
// function: receipt claim/replay, live-manager fencing at database time, row
// lock + CAS, exact bounded response facts, receipt persist. The adapter
// never reconstructs responses from mutable state and never adds host-clock
// fields — everything time-like in a response is database time.
//
// All BIGINT counters (manager epoch, authority runtime sequence, access
// control sequence, token generation) cross this interface as canonical
// decimal STRINGS. They are never coerced to JavaScript numbers.
// ---------------------------------------------------------------------------

// Managed state has one canonical namespace only: t:<metadata tenant id>.
// A volume-id fallback would create a second set of live rows for the same
// volume and make runtime verification split-brain by construction.
export function managedTenantKey(ref: { teamId?: string; volumeId: string }): string {
  const teamId = ref.teamId?.trim();
  if (!teamId) {
    throw new InvalidControlArgumentError(
      `managed scope ${ref.volumeId || "<unknown>"} requires its metadata tenant id`
    );
  }
  return `t:${teamId}`;
}

// fingerprintOfCanonicalParts is the ONE fingerprint construction used for
// every receipted control operation: sha256 over length-delimited UTF-8
// parts (`${byteLength}:${bytes}` concatenated), hex-encoded. Length
// delimiting makes the encoding injective; no delimiter can smear fields.
export function fingerprintOfCanonicalParts(parts: readonly string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) {
    const bytes = Buffer.from(part, "utf8");
    hash.update(`${bytes.byteLength}:`);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

export function sha256Hex(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

// runtimeEndOperationId derives the deterministic authority-runtime-end
// operation id for ONE SEMANTIC end: the exact runtime plus the end reason.
// A lost-response retry of the same semantic end replays byte-exact under
// this id, while DISTINCT competing end attempts for the same runtime (e.g.
// start-failure cleanup racing an unexpected child exit) carry distinct ids:
// pfm.authority_runtime_end executes the second one and OBSERVES the
// already-ended row (the first terminal reason stays stable) instead of
// tripping the same-id/different-content conflict (PF009), which remains
// fully enforced for true content divergence. Free-text reasons are folded
// in as a bounded slug plus the full SHA-256 content hash so ids stay
// deterministic, collision-resistant across reasons, and inside the
// 256-character operation-id bound even for a maximum-length runtime id.
export function runtimeEndOperationId(runtimeId: string, reason: string): string {
  const slug = reason
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, 48);
  const digest = sha256Hex(reason);
  return `pfare_${runtimeId}_${slug || "ended"}_${digest}`;
}

// Domain-separated, length-delimited HMAC for manager-issued runtime
// capabilities. The raw manager capability is the key and is never logged or
// persisted; the returned 256-bit value is handed to exactly one child.
export function hmacOfCanonicalParts(key: string, parts: readonly string[]): string {
  const hmac = createHmac("sha256", key);
  for (const part of parts) {
    const bytes = Buffer.from(part, "utf8");
    hmac.update(`${bytes.byteLength}:`);
    hmac.update(bytes);
  }
  return hmac.digest("hex");
}

// compareDecimalStrings orders two canonical positive decimal strings
// numerically without ever converting to JS numbers (counters exceed 2^53).
export function compareDecimalStrings(a: string, b: string): -1 | 0 | 1 {
  if (a.length !== b.length) {
    return a.length < b.length ? -1 : 1;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

const canonicalDecimalPattern = /^[1-9][0-9]{0,18}$/u;

// parseAuthorityRuntimeSeq validates one authority runtime sequence (the
// monotonic per-scope BIGINT) as a canonical positive decimal string. Kept
// as a plain string domain: the wire lease schemas do not carry it, so no
// protocol brand exists for it.
export function parseAuthorityRuntimeSeq(value: string): string {
  if (!canonicalDecimalPattern.test(value)) {
    throw new InvalidControlArgumentError(
      `authority runtime sequence must be a canonical positive decimal string, got ${value}`
    );
  }
  return value;
}

// ---------------------------------------------------------------------------
// Errors (mapped from pfm SQLSTATEs).
// ---------------------------------------------------------------------------

// PF001: the caller is not the live manager at database time — superseded
// epoch, wrong runtime id, wrong capability, or DB-time claim expiry. The
// manager must stop mutating and tear down.
export class ManagerEpochSupersededError extends Error {
  constructor(
    readonly staleEpoch: string,
    readonly currentEpoch: string | null,
    message?: string
  ) {
    super(
      message ??
        `managerEpoch ${staleEpoch} is no longer the live claim${
          currentEpoch !== null ? ` (current epoch ${currentEpoch})` : ""
        }; this manager lost the singleton claim.`
    );
    this.name = "ManagerEpochSupersededError";
  }
}

// PF013: a live claim is held by ANOTHER runtime; the caller must wait for
// DB-time expiry (expiresAtDbMs) — claiming never spins the epoch forward
// under a live claim.
export class ManagerClaimHeldError extends Error {
  constructor(
    readonly expiresAtDbMs: number | null,
    readonly dbTimeMs: number | null,
    readonly currentEpoch: string | null,
    message: string
  ) {
    super(message);
    this.name = "ManagerClaimHeldError";
  }
}

// PF002 / PF009: compare-and-swap mismatch, an id reused for different
// content, or an operation id replayed with a different fingerprint. When
// the conflict is a lease CAS, `leaseFacts` carries the exact current row.
export class ControlOperationConflictError extends Error {
  constructor(
    message: string,
    readonly leaseFacts: AccessLeaseFacts | null
  ) {
    super(message);
    this.name = "ControlOperationConflictError";
  }
}

// PF007
export class ControlNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ControlNotFoundError";
  }
}

// PF012: the lease exists but is not active; `leaseFacts` is its exact
// terminal state (post DB-time settle) so callers answer precisely.
export class AccessLeaseNotActiveError extends Error {
  constructor(
    message: string,
    readonly leaseFacts: AccessLeaseFacts | null
  ) {
    super(message);
    this.name = "AccessLeaseNotActiveError";
  }
}

// PF008: invalid argument (programmer error — never retried).
export class InvalidControlArgumentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidControlArgumentError";
  }
}

// PF014: a bounded high-frequency renew receipt is below the retained floor.
// The operation must never be re-executed; the caller reloads current facts
// and makes a new decision under a fresh operation id.
export class ControlReceiptEvictedError extends Error {
  constructor(
    message: string,
    readonly receiptFloorControlSeq: AccessLeaseControlSeq | null
  ) {
    super(message);
    this.name = "ControlReceiptEvictedError";
  }
}

// Anything else (connection refused, timeout, unknown SQLSTATE): the
// transition may or may not have committed. Mutations that see this must
// treat the transition as NOT KNOWN durable: no in-memory publish, no event,
// no tunnel action; retry with the SAME operation id to learn the truth.
export class ControlStoreUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ControlStoreUnavailableError";
  }
}

// PF015: deterministic, non-poisoning availability refusal. It remains a
// ControlStoreUnavailableError so HTTP/service layers map it to 503 and retry
// the identical operation while their local monotonic manager deadline holds.
export class ControlDurabilityUnavailableError extends ControlStoreUnavailableError {
  constructor(
    message: string,
    readonly evidence: Record<string, unknown> | null
  ) {
    super(message);
    this.name = "ControlDurabilityUnavailableError";
  }
}

// ---------------------------------------------------------------------------
// Facts.
// ---------------------------------------------------------------------------

// The exact manager identity every fenced call presents: the opaque decimal
// epoch, the random runtime id, and the raw unguessable capability (hashed
// and compared in the database; never stored raw).
export interface ManagerIdentity {
  managerEpoch: ManagerEpoch;
  managerRuntimeId: string;
  managerCapability: string;
}

export interface ManagerClaimResult {
  managerEpoch: ManagerEpoch;
  runtimeId: string;
  operationId: string;
  claimedAtDbMs: number;
  expiresAtDbMs: number;
  dbTimeMs: number;
  // current=false means the receipt replayed but the claim it minted is no
  // longer the live one (superseded or expired): the caller must NOT act as
  // manager under it.
  current: boolean;
  replayed: boolean;
}

export interface ManagerClaimRenewal {
  dbTimeMs: number;
  claimExpiresAtDbMs: number;
}

export interface AuthorityRuntimeBeginResult {
  runtimeSeq: string;
  runtimeId: string;
  operationId: string;
  authorityCapability: string;
  beganAtDbMs: number;
  current: boolean;
  replayed: boolean;
  dbTimeMs: number;
}

export interface AuthorityRuntimeEndResult {
  operationId: string;
  runtimeSeq: string;
  runtimeId: string;
  ended: true;
  endReason: string;
  endedAtDbMs: number;
  replayed: boolean;
  dbTimeMs: number;
}

export interface RuntimeCredentialMintResult {
  tenantId: string;
  volumeId: string;
  branchName: string;
  authEpoch: string;
  admissionEpoch: string;
  mintedDbMs: number;
  expiresDbMs: number;
}

export interface AuthorityScopeRef {
  tenantKey: string;
  volumeId: string;
  branch: string;
}

// The exact bounded fact set of one access lease row, exactly as stored (and
// as persisted inside operation receipts). All counters are canonical
// decimal strings; timestamps are database time.
export interface AccessLeaseFacts {
  leaseId: string;
  tenantKey: string;
  volumeId: string;
  branch: string;
  consumerId: string;
  authorityInstanceId: string;
  authorityRuntimeSeq: string;
  authorityRuntimeId: string;
  managerEpoch: ManagerEpoch;
  tokenGeneration: AccessLeaseTokenGeneration;
  controlSeq: AccessLeaseControlSeq;
  state: AccessLeaseState;
  endReason?: AccessLeaseEndReason;
  expiresAt: number;
  createdAtMs: number;
  endedAtMs?: number;
}

export interface AccessOperationResult extends AccessLeaseFacts {
  kind: "create" | "renew" | "release" | "revoke";
  operationId: string;
  receiptFingerprint: string;
  // Mutable current projection is separate from the immutable receipted
  // outcome so replaying an older operation can never rewind routing state.
  currentFacts: AccessLeaseFacts;
  // Whether THIS durable operation minted a token generation (create, or
  // renew with rotation). Replays repeat the recorded value.
  mintedToken: boolean;
  completedAtDbMs: number;
  replayed: boolean;
  dbTimeMs: number;
}

export interface AccessEndBatchResult {
  operationId: string;
  endReason: AccessLeaseEndReason;
  endedLeaseIds: string[];
  completedAtDbMs: number;
  replayed: boolean;
  dbTimeMs: number;
}

export interface AccessSweepResult {
  operationId: string;
  afterLeaseId: string | null;
  limit: number;
  endedLeaseIds: string[];
  nextCursor: string | null;
  hasMore: boolean;
  receiptFingerprint: string;
  completedAtDbMs: number;
  replayed: boolean;
  dbTimeMs: number;
}

export interface LifecycleReceiptPutResult {
  response: unknown;
  replayed: boolean;
  dbTimeMs: number;
}

export type LifecycleReceiptLookup =
  | { kind: "found"; response: unknown; fingerprint: string; dbTimeMs: number }
  // pfm receipts are permanent: unknown MEANS the operation never durably
  // completed (there is no pruned/evicted state to disambiguate).
  | { kind: "unknown" };

export type AccessLeaseEndBatchReason = Extract<
  AccessLeaseEndReason,
  "revoked" | "owner-revoked" | "authority-retired" | "manager-epoch-superseded" | "expired"
>;

// ---------------------------------------------------------------------------
// Interface.
// ---------------------------------------------------------------------------

export interface ManagerControlStore {
  // Claim the singleton manager role (a DATABASE-TIME lease). Exact retry
  // (same operationId + runtimeId + capabilityHash) replays the identical
  // claim; a live claim held by another runtime raises ManagerClaimHeldError
  // with the DB-time expiry to wait out.
  claimManager(args: {
    operationId: string;
    runtimeId: string;
    // sha256 hex of the raw capability; the raw secret never reaches the
    // claim receipt.
    capabilityHash: string;
    ttlMs: number;
  }): Promise<ManagerClaimResult>;

  // Renew the live claim under the EXACT identity. ManagerEpochSuperseded on
  // any mismatch or DB-time expiry — the caller tears down, never retries
  // into a fresh epoch here.
  renewManagerClaim(args: { identity: ManagerIdentity; ttlMs: number }): Promise<ManagerClaimRenewal>;

  // The liveness channel that DRIVES renewal. The adapter answers with a
  // channel whose isolation matches its own transport: the Postgres adapter
  // hands back a worker thread holding a RESERVED connection, because a
  // renewal must never queue behind bulk traffic in the shared pool nor
  // behind data-plane socket callbacks on the main event loop. Liveness is
  // the fencing authority; it is isolated by construction, not by tuning.
  createClaimHeartbeat(): ClaimHeartbeat;

  // Best-effort clean shutdown: expire the claim NOW so a successor need not
  // wait out the TTL.
  releaseManagerClaim(args: { identity: ManagerIdentity }): Promise<{ dbTimeMs: number }>;

  // The store's database clock. Every validity decision uses THIS clock.
  dbTimeMs(): Promise<number>;

  // Mint the next monotonic runtime row for a scope; ends any previous live
  // runtime of the scope in the same transaction.
  beginAuthorityRuntime(args: {
    identity: ManagerIdentity;
    scope: AuthorityScopeRef;
    authorityInstanceId: string;
    runtimeId: string;
    operationId?: string;
    authorityCapability?: string;
  }): Promise<AuthorityRuntimeBeginResult>;

  // Terminally end one exact runtime (child exited, evicted, fenced).
  endAuthorityRuntime(args: {
    identity: ManagerIdentity;
    scope: AuthorityScopeRef;
    runtimeSeq: string;
    runtimeId: string;
    reason: string;
    operationId?: string;
  }): Promise<AuthorityRuntimeEndResult>;

  // Mint one short-lived runtime READ credential (migration 015): the
  // manager generates the secret, the database stores only its SHA-256
  // bound to the LIVE authority runtime of the scope. This is the child's
  // ONLY volume-api identity — there is no static-token fallback.
  runtimeCredentialMint(args: {
    identity: ManagerIdentity;
    credentialHash: string;
    tenantId: string;
    volumeId: string;
    branch: string;
    authorityRuntimeSeq: string;
    authorityRuntimeId: string;
    ttlMs: number;
  }): Promise<RuntimeCredentialMintResult>;

  // Access lease operations: each is ONE receipted database transaction.
  accessCreate(args: {
    identity: ManagerIdentity;
    operationId: string;
    leaseId: string;
    scope: AuthorityScopeRef;
    consumerId: string;
    authorityInstanceId: string;
    authorityRuntimeSeq: string;
    authorityRuntimeId: string;
    ttlMs: number;
  }): Promise<AccessOperationResult>;

  accessRenew(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    // Exact CAS: every retry is bound to the control sequence it observed.
    expectedControlSeq: AccessLeaseControlSeq;
    ttlMs: number;
    rotate: boolean;
  }): Promise<AccessOperationResult>;

  accessRelease(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    expectedControlSeq: AccessLeaseControlSeq | null;
  }): Promise<AccessOperationResult>;

  accessRevoke(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    reason: AccessLeaseEndBatchReason;
  }): Promise<AccessOperationResult>;

  // End EVERY active lease matching the filter in one receipted transaction
  // (child exit, authority retirement, owner revoke, epoch sweep).
  accessEndBatch(args: {
    identity: ManagerIdentity;
    operationId: string;
    filter: {
      tenantKey?: string;
      volumeId?: string;
      branch?: string;
      consumerId?: string;
      authorityInstanceId?: string;
      authorityRuntimeSeq?: string;
      // End active leases whose manager_epoch < epochsBelow (supersession
      // sweep). When absent, only leases of the CURRENT epoch match.
      epochsBelow?: ManagerEpoch;
    };
    reason: AccessLeaseEndBatchReason;
  }): Promise<AccessEndBatchResult>;

  // Durably terminalize one stable, lease-id-ordered page of DB-time-expired
  // or old-manager-epoch rows. Each page is exact-receipted and retryable.
  sweepAccessLeases(args: {
    identity: ManagerIdentity;
    operationId: string;
    afterLeaseId?: string;
    limit?: number;
  }): Promise<AccessSweepResult>;

  accessGet(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    leaseId: string;
  }): Promise<(AccessLeaseFacts & { dbTimeMs: number }) | null>;

  accessListActive(args: {
    identity: ManagerIdentity;
  }): Promise<{ leases: AccessLeaseFacts[]; dbTimeMs: number }>;

  // Lifecycle receipts, keyed (tenantKey, operationId) in the permanent
  // 'lifecycle' domain.
  putLifecycleReceipt(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    operationId: string;
    response: unknown;
  }): Promise<LifecycleReceiptPutResult>;

  findLifecycleReceipt(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    operationId: string;
  }): Promise<LifecycleReceiptLookup>;

  // Bounded readiness probe: control-store reachability, pfm migration
  // lineage (the SECURITY DEFINER surface exists), AND a DURABLE WRITE.
  //
  // The write leg is not decoration. This probe used to be
  // `SELECT to_regproc('pfm.manager_renew') IS NOT NULL` — a catalog read
  // that an out-of-disk primary answers perfectly. During a total
  // control-store outage (disk full, every lease write failing) it kept
  // answering ok, /readyz kept answering 200, and the deploy gate declared
  // the release healthy. Readiness for a control plane whose only job is
  // durable transitions MUST be the ability to perform one.
  //
  // Optional — manager readiness treats absence as a failed component
  // (fail closed).
  healthProbe?(options?: { signal?: AbortSignal }): Promise<ManagerControlProbe>;

  // Exact control-store consumption for operator accounting. Optional; an
  // absent implementation simply publishes no usage gauges.
  usageProbe?(options?: { signal?: AbortSignal }): Promise<ManagerControlStoreUsage>;

  close(): Promise<void>;
}

/**
 * The coarse, stable readiness verdict. `code` is the ONLY failure detail
 * that may reach an unauthenticated /readyz payload: no driver text, no SQL,
 * no DSN fragment ever survives to it.
 *
 *   unreachable        the round-trip itself failed
 *   lineage_incomplete reachable, but the pfm surface this build needs is absent
 *   not_writable       reachable and current, but a durable write was REFUSED
 *                      (out of disk, read-only primary, wedged writer)
 */
export type ManagerControlProbeCode = "unreachable" | "lineage_incomplete" | "not_writable";

export interface ManagerControlProbe {
  ok: boolean;
  lineageComplete: boolean;
  writable: boolean;
  code?: ManagerControlProbeCode;
}

/** Canonical decimal strings: these are BIGINT byte counts. */
export interface ManagerControlStoreUsage {
  databaseBytes: string;
  planeBytes: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Response parsing (exact, fail-closed).
// ---------------------------------------------------------------------------

function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ControlStoreUnavailableError(`${what}: malformed control store response`);
  }
  return value as Record<string, unknown>;
}

function requireString(row: Record<string, unknown>, key: string): string {
  const value = row[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new ControlStoreUnavailableError(`control store response field ${key} is missing`);
  }
  return value;
}

function requireIntNumber(row: Record<string, unknown>, key: string): number {
  const value = row[key];
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw new ControlStoreUnavailableError(
      `control store response field ${key} is not a canonical decimal string`
    );
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new ControlStoreUnavailableError(
      `control store response field ${key} exceeds the safe timestamp boundary`
    );
  }
  return parsed;
}

function optionalIntNumber(row: Record<string, unknown>, key: string): number | undefined {
  return row[key] === undefined || row[key] === null ? undefined : requireIntNumber(row, key);
}

function requireBoolean(row: Record<string, unknown>, key: string): boolean {
  const value = row[key];
  if (typeof value !== "boolean") {
    throw new ControlStoreUnavailableError(`control store response field ${key} is not boolean`);
  }
  return value;
}

function requireExpectedString(
  row: Record<string, unknown>,
  key: string,
  expected: string,
  what: string
): void {
  const actual = requireString(row, key);
  if (actual !== expected) {
    throw new ControlStoreUnavailableError(
      `${what}: control store returned ${key}=${actual}, expected ${expected}`
    );
  }
}

function requireSha256Hex(row: Record<string, unknown>, key: string): string {
  const value = requireString(row, key);
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new ControlStoreUnavailableError(
      `control store response field ${key} is not canonical sha256 hex`
    );
  }
  return value;
}

const leaseStates: readonly AccessLeaseState[] = ["active", "released", "expired", "revoked"];
const leaseEndReasons: readonly AccessLeaseEndReason[] = [
  "released",
  "expired",
  "revoked",
  "owner-revoked",
  "authority-retired",
  "manager-epoch-superseded",
];

export function parseAccessLeaseFacts(value: unknown): AccessLeaseFacts {
  const row = asRecord(value, "access lease facts");
  const state = requireString(row, "state");
  if (!leaseStates.includes(state as AccessLeaseState)) {
    throw new ControlStoreUnavailableError(`unknown access lease state ${state}`);
  }
  const endReason = row["endReason"];
  if (endReason !== undefined && !leaseEndReasons.includes(endReason as AccessLeaseEndReason)) {
    throw new ControlStoreUnavailableError(`unknown access lease end reason ${String(endReason)}`);
  }
  const expiresAt = requireIntNumber(row, "expiresAt");
  const createdAtMs = requireIntNumber(row, "createdAtMs");
  const endedAtMs = optionalIntNumber(row, "endedAtMs");
  if (expiresAt < createdAtMs) {
    throw new ControlStoreUnavailableError("access lease expires before it was created");
  }
  if (endedAtMs !== undefined && endedAtMs < createdAtMs) {
    throw new ControlStoreUnavailableError("access lease ends before it was created");
  }
  if (state === "active" && (endReason !== undefined || endedAtMs !== undefined)) {
    throw new ControlStoreUnavailableError("active access lease carries terminal fields");
  }
  if (state === "released" && endReason !== "released") {
    throw new ControlStoreUnavailableError("released access lease has an incompatible end reason");
  }
  if (state === "expired" && endReason !== "expired") {
    throw new ControlStoreUnavailableError("expired access lease has an incompatible end reason");
  }
  if (
    state === "revoked" &&
    !["revoked", "owner-revoked", "authority-retired", "manager-epoch-superseded"].includes(
      endReason as string
    )
  ) {
    throw new ControlStoreUnavailableError("revoked access lease has an incompatible end reason");
  }
  return {
    leaseId: requireString(row, "leaseId"),
    tenantKey: requireString(row, "tenantKey"),
    volumeId: requireString(row, "volumeId"),
    branch: requireString(row, "branch"),
    consumerId: requireString(row, "consumerId"),
    authorityInstanceId: requireString(row, "authorityInstanceId"),
    authorityRuntimeSeq: parseAuthorityRuntimeSeq(requireString(row, "authorityRuntimeSeq")),
    authorityRuntimeId: requireString(row, "authorityRuntimeId"),
    managerEpoch: parseManagerEpoch(requireString(row, "managerEpoch")),
    tokenGeneration: parseAccessLeaseTokenGeneration(requireString(row, "tokenGeneration")),
    controlSeq: parseAccessLeaseControlSeq(requireString(row, "controlSeq")),
    state: state as AccessLeaseState,
    ...(endReason !== undefined ? { endReason: endReason as AccessLeaseEndReason } : {}),
    expiresAt,
    createdAtMs,
    ...(endedAtMs !== undefined ? { endedAtMs } : {}),
  };
}

// A receipted access result is immutable history. `currentFacts` is a
// separately-read projection of the same physical lease and may only move
// forward. Keeping this invariant at the adapter boundary prevents an old
// receipt replay from rewinding a router's live lease projection even if a
// database function is accidentally changed to return inconsistent JSON.
export function validateAccessProjection(
  receipted: AccessLeaseFacts,
  current: AccessLeaseFacts
): void {
  const immutableFields: ReadonlyArray<keyof AccessLeaseFacts> = [
    "leaseId",
    "tenantKey",
    "volumeId",
    "branch",
    "consumerId",
    "authorityInstanceId",
    "authorityRuntimeSeq",
    "authorityRuntimeId",
    "managerEpoch",
    "createdAtMs",
  ];
  for (const field of immutableFields) {
    if (current[field] !== receipted[field]) {
      throw new ControlStoreUnavailableError(
        `access operation currentFacts changed immutable ${String(field)}`
      );
    }
  }
  if (BigInt(current.controlSeq) < BigInt(receipted.controlSeq)) {
    throw new ControlStoreUnavailableError(
      "access operation currentFacts regressed the lease control sequence"
    );
  }
  if (BigInt(current.tokenGeneration) < BigInt(receipted.tokenGeneration)) {
    throw new ControlStoreUnavailableError(
      "access operation currentFacts regressed the token generation"
    );
  }
  if (current.expiresAt < receipted.expiresAt) {
    throw new ControlStoreUnavailableError(
      "access operation currentFacts regressed the lease expiry"
    );
  }
  if (receipted.state !== "active") {
    if (
      current.state !== receipted.state ||
      current.endReason !== receipted.endReason ||
      current.endedAtMs !== receipted.endedAtMs
    ) {
      throw new ControlStoreUnavailableError(
        "access operation currentFacts resurrected or rewrote a terminal lease"
      );
    }
    if (
      current.controlSeq !== receipted.controlSeq ||
      current.tokenGeneration !== receipted.tokenGeneration ||
      current.expiresAt !== receipted.expiresAt
    ) {
      throw new ControlStoreUnavailableError(
        "access operation currentFacts mutated a terminal lease"
      );
    }
  }
}

interface ExpectedAccessOperation {
  kind: AccessOperationResult["kind"];
  operationId: string;
  tenantKey: string;
  leaseId?: string;
  managerEpoch: ManagerEpoch;
  volumeId?: string;
  branch?: string;
  consumerId?: string;
  authorityInstanceId?: string;
  authorityRuntimeSeq?: string;
  authorityRuntimeId?: string;
  controlSeq?: AccessLeaseControlSeq;
}

function parseAccessOperationResult(
  value: unknown,
  expected: ExpectedAccessOperation
): AccessOperationResult {
  const row = asRecord(value, "access operation result");
  const kind = requireString(row, "kind");
  if (!["create", "renew", "release", "revoke"].includes(kind)) {
    throw new ControlStoreUnavailableError(`unknown access operation kind ${kind}`);
  }
  const parsed: AccessOperationResult = {
    ...parseAccessLeaseFacts(row),
    kind: kind as AccessOperationResult["kind"],
    operationId: requireString(row, "operationId"),
    receiptFingerprint: requireSha256Hex(row, "receiptFingerprint"),
    currentFacts: parseAccessLeaseFacts(row["currentFacts"]),
    mintedToken: requireBoolean(row, "mintedToken"),
    completedAtDbMs: requireIntNumber(row, "completedAtDbMs"),
    replayed: requireBoolean(row, "replayed"),
    dbTimeMs: requireIntNumber(row, "dbTimeMs"),
  };
  const expectedStrings: Array<[keyof AccessLeaseFacts, string | undefined]> = [
    ["volumeId", expected.volumeId],
    ["branch", expected.branch],
    ["consumerId", expected.consumerId],
    ["authorityInstanceId", expected.authorityInstanceId],
    ["authorityRuntimeSeq", expected.authorityRuntimeSeq],
    ["authorityRuntimeId", expected.authorityRuntimeId],
    ["controlSeq", expected.controlSeq],
  ];
  requireExpectedString(row, "kind", expected.kind, "access operation result");
  requireExpectedString(row, "operationId", expected.operationId, "access operation result");
  requireExpectedString(row, "tenantKey", expected.tenantKey, "access operation result");
  if (expected.leaseId !== undefined) {
    requireExpectedString(row, "leaseId", expected.leaseId, "access operation result");
  }
  validateAccessProjection(parsed, parsed.currentFacts);
  // On first execution the lease is necessarily minted by the authenticated
  // manager. A later exact receipt replay is deliberately allowed after a
  // manager takeover; its immutable managerEpoch remains the original epoch.
  if (!parsed.replayed) {
    requireExpectedString(row, "managerEpoch", expected.managerEpoch, "access operation result");
  }
  for (const [key, expectedValue] of expectedStrings) {
    if (expectedValue !== undefined) {
      requireExpectedString(row, key, expectedValue, "access operation result");
    }
  }
  return parsed;
}

interface ExpectedAccessSweep {
  operationId: string;
  afterLeaseId: string | null;
  limit: number;
}

function compareCStrings(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

export function parseAccessSweepResult(
  value: unknown,
  expected: ExpectedAccessSweep
): AccessSweepResult {
  const row = asRecord(value, "access sweep");
  requireExpectedString(row, "operationId", expected.operationId, "access sweep");
  if (row["afterLeaseId"] !== expected.afterLeaseId) {
    throw new ControlStoreUnavailableError("access sweep returned a different page cursor");
  }
  const limit = requireIntNumber(row, "limit");
  if (limit !== expected.limit) {
    throw new ControlStoreUnavailableError("access sweep returned a different page limit");
  }
  const endedRaw = row["endedLeaseIds"];
  if (!Array.isArray(endedRaw) || endedRaw.some((id) => typeof id !== "string" || id.length === 0)) {
    throw new ControlStoreUnavailableError("access sweep returned malformed lease ids");
  }
  const endedLeaseIds = endedRaw as string[];
  if (endedLeaseIds.length > limit) {
    throw new ControlStoreUnavailableError("access sweep returned more lease ids than its limit");
  }
  for (let index = 0; index < endedLeaseIds.length; index += 1) {
    const leaseId = endedLeaseIds[index]!;
    if (expected.afterLeaseId !== null && compareCStrings(leaseId, expected.afterLeaseId) <= 0) {
      throw new ControlStoreUnavailableError(
        "access sweep returned a lease id at or before its page cursor"
      );
    }
    if (index > 0 && compareCStrings(endedLeaseIds[index - 1]!, leaseId) >= 0) {
      throw new ControlStoreUnavailableError(
        "access sweep lease ids are not strictly C-sorted and unique"
      );
    }
  }
  const nextRaw = row["nextCursor"];
  if (nextRaw !== null && (typeof nextRaw !== "string" || nextRaw.length === 0)) {
    throw new ControlStoreUnavailableError("access sweep returned a malformed next cursor");
  }
  const nextCursor = nextRaw as string | null;
  const hasMore = requireBoolean(row, "hasMore");
  if (hasMore !== (nextCursor !== null)) {
    throw new ControlStoreUnavailableError("access sweep hasMore and nextCursor disagree");
  }
  if (
    hasMore &&
    (endedLeaseIds.length === 0 || nextCursor !== endedLeaseIds[endedLeaseIds.length - 1])
  ) {
    throw new ControlStoreUnavailableError(
      "access sweep continuation cursor is not its last ended lease id"
    );
  }
  const completedAtDbMs = requireIntNumber(row, "completedAtDbMs");
  const dbTimeMs = requireIntNumber(row, "dbTimeMs");
  if (completedAtDbMs > dbTimeMs) {
    throw new ControlStoreUnavailableError(
      "access sweep completion time is after the observed database time"
    );
  }
  return {
    operationId: expected.operationId,
    afterLeaseId: expected.afterLeaseId,
    limit,
    endedLeaseIds,
    nextCursor,
    hasMore,
    receiptFingerprint: requireSha256Hex(row, "receiptFingerprint"),
    completedAtDbMs,
    replayed: requireBoolean(row, "replayed"),
    dbTimeMs,
  };
}

// ---------------------------------------------------------------------------
// Postgres adapter.
// ---------------------------------------------------------------------------

export interface PostgresManagerControlStoreOptions {
  // Bounded pool defaults chosen for a singleton manager: a few connections,
  // fast fail on connect, server-enforced statement timeout.
  maxConnections?: number;
  connectTimeoutMs?: number;
  statementTimeoutMs?: number;
  // Test seam: a scripted pool double. Production constructs a real pg Pool
  // from the connection string.
  pool?: ManagerControlPool;
}

// The narrow pool surface the adapter consumes; pg.Pool satisfies it.
export interface ManagerControlPool {
  query(text: string, values: unknown[]): Promise<{ rows: unknown[] }>;
  end(): Promise<void>;
  on?(event: "error", listener: (error: Error) => void): unknown;
}

interface PgLikeError {
  code?: string;
  detail?: string;
  message?: string;
}

function detailJson(err: PgLikeError): Record<string, unknown> | null {
  if (typeof err.detail !== "string" || err.detail.length === 0) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(err.detail);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function safeIntFromDetail(value: unknown): number | null {
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return value;
  }
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
}

function leaseFromDetail(detail: Record<string, unknown> | null): AccessLeaseFacts | null {
  if (detail === null || typeof detail["leaseId"] !== "string") {
    return null;
  }
  try {
    return parseAccessLeaseFacts(detail);
  } catch {
    return null;
  }
}

export function mapManagerControlError(err: PgLikeError, staleEpoch?: string): Error {
  const code = err.code ?? "";
  const message = err.message ?? "control store error";
  const detail = detailJson(err);
  switch (code) {
    case "PF001": {
      const currentEpoch =
        detail !== null && typeof detail["currentEpoch"] === "string"
          ? (detail["currentEpoch"] as string)
          : null;
      return new ManagerEpochSupersededError(staleEpoch ?? "unknown", currentEpoch, message);
    }
    case "PF013": {
      const expires = safeIntFromDetail(detail?.["expiresAtDbMs"]);
      const dbTime = safeIntFromDetail(detail?.["dbTimeMs"]);
      const currentEpoch =
        detail !== null && typeof detail["currentEpoch"] === "string"
          ? (detail["currentEpoch"] as string)
          : null;
      return new ManagerClaimHeldError(expires, dbTime, currentEpoch, message);
    }
    case "PF002":
    case "PF009":
      return new ControlOperationConflictError(message, leaseFromDetail(detail));
    case "PF007":
      return new ControlNotFoundError(message);
    case "PF012":
      return new AccessLeaseNotActiveError(message, leaseFromDetail(detail));
    case "PF008":
      return new InvalidControlArgumentError(message);
    case "PF014": {
      const floor = detail?.["receiptFloorControlSeq"];
      let parsedFloor: AccessLeaseControlSeq | null = null;
      if (typeof floor === "string") {
        try {
          parsedFloor = parseAccessLeaseControlSeq(floor);
        } catch {
          parsedFloor = null;
        }
      }
      return new ControlReceiptEvictedError(message, parsedFloor);
    }
    case "PF015":
      return new ControlDurabilityUnavailableError(message, detail);
    default:
      return new ControlStoreUnavailableError(message);
  }
}

// The exact pfm renewal statement. It lives in ONE place because the liveness
// worker thread issues the identical call on its reserved connection.
export const MANAGER_RENEW_SQL = `SELECT pfm.manager_renew($1,$2,$3,$4) AS r`;

export function managerRenewStatement(args: {
  identity: ManagerIdentity;
  ttlMs: number;
}): { sql: string; values: unknown[] } {
  return {
    sql: MANAGER_RENEW_SQL,
    values: [
      args.identity.managerEpoch,
      args.identity.managerRuntimeId,
      args.identity.managerCapability,
      args.ttlMs,
    ],
  };
}

// The bounded readiness-probe ring, matching pfm.control_write_probe_slots().
// The SQL reduces any slot into range, so a drifted constant here can only
// cost slot spread — never unbounded rows.
const managerWriteProbeSlots = 16;

function requireDecimalString(row: Record<string, unknown>, key: string): string {
  const value = row[key];
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw new ControlStoreUnavailableError(
      `control store response field ${key} is not a canonical decimal string`
    );
  }
  return value;
}

export class PostgresManagerControlStore implements ManagerControlStore {
  private readonly pool: ManagerControlPool;
  private readonly connectionString: string;
  private readonly connectTimeoutMs: number;
  private readonly statementTimeoutMs: number;
  private readonly heartbeats: ClaimHeartbeat[] = [];
  // One slot out of the bounded probe ring, chosen once per process. N
  // manager replicas therefore do not serialize every readiness check on one
  // row lock — a lock convoy on a HEALTHY store must never read as an outage
  // — while the probe table stays bounded at the ring size forever.
  private readonly writeProbeSlot = Math.floor(Math.random() * managerWriteProbeSlots);

  constructor(connectionString: string, options: PostgresManagerControlStoreOptions = {}) {
    this.connectionString = connectionString;
    this.connectTimeoutMs = options.connectTimeoutMs ?? 5_000;
    this.statementTimeoutMs = options.statementTimeoutMs ?? 10_000;
    if (options.pool) {
      this.pool = options.pool;
    } else {
      const config: PoolConfig = {
        connectionString,
        max: options.maxConnections ?? 4,
        connectionTimeoutMillis: options.connectTimeoutMs ?? 5_000,
        // Server-side statement timeout: no control call may hang a manager
        // renewal loop indefinitely.
        statement_timeout: options.statementTimeoutMs ?? 10_000,
        query_timeout: (options.statementTimeoutMs ?? 10_000) + 5_000,
      };
      this.pool = new Pool(config);
    }
    // A destroyed idle connection must never crash the manager process.
    this.pool.on?.("error", () => {});
  }

  // createClaimHeartbeat hands back the ISOLATED liveness channel: a
  // dedicated worker thread with its own reserved connection. It shares
  // neither this pool (where a burst of client-driven lease work can hold
  // every connection and make a queued renewal time out) nor the main event
  // loop (where the data-plane router's socket callbacks live). Those two
  // shared resources are exactly how a HEALTHY manager under full-speed load
  // used to fence itself.
  createClaimHeartbeat(): ClaimHeartbeat {
    const heartbeat = new WorkerClaimHeartbeat({
      connectionString: this.connectionString,
      renewalStatement: managerRenewStatement,
      connectTimeoutMs: this.connectTimeoutMs,
      statementTimeoutMs: this.statementTimeoutMs,
    });
    this.heartbeats.push(heartbeat);
    return heartbeat;
  }

  async close(): Promise<void> {
    for (const heartbeat of this.heartbeats.splice(0)) {
      heartbeat.stop();
    }
    await this.pool.end();
  }

  // healthProbe proves, in this order:
  //   1. reachability + pfm lineage — the SECURITY DEFINER renewal function
  //      and the write probe this build needs both exist;
  //   2. WRITE CAPABILITY — pfm.control_write_probe performs the same class
  //      of durable transition a lease write performs (same SECURITY DEFINER
  //      boundary, same pfm.require_durable_primary() admission, a real heap
  //      tuple version, a real WAL record, a real synchronous commit).
  //
  // Step 2 is the whole point. Step 1 alone is a catalog read, and a Postgres
  // whose disk is full answers catalog reads perfectly while refusing every
  // lease write — which is exactly how a total control-store outage once
  // passed the deploy gate. The write target is a BOUNDED ring of rows
  // updated in place, so proving readiness never grows the control store.
  //
  // It reports instead of throwing: readiness handlers must not have to
  // catch, and no driver text may escape toward an unauthenticated payload.
  async healthProbe(options?: { signal?: AbortSignal }): Promise<ManagerControlProbe> {
    let lineageComplete = false;
    try {
      const result = await this.probeQuery(
        `SELECT to_regproc('pfm.manager_renew') IS NOT NULL
            AND to_regprocedure('pfm.control_write_probe(int)') IS NOT NULL AS lineage`,
        [],
        options?.signal
      );
      lineageComplete = Boolean((result.rows[0] as { lineage?: boolean } | undefined)?.lineage);
    } catch {
      return { ok: false, lineageComplete: false, writable: false, code: "unreachable" };
    }
    if (!lineageComplete) {
      // The write probe function may not exist yet; proving writes work
      // cannot repair a short lineage, so report the lineage gap as-is.
      return { ok: false, lineageComplete: false, writable: false, code: "lineage_incomplete" };
    }
    try {
      await this.probeQuery(
        `SELECT pfm.control_write_probe($1) AS r`,
        [this.writeProbeSlot],
        options?.signal
      );
      return { ok: true, lineageComplete: true, writable: true };
    } catch {
      // Reachable and current, but the store refused a durable transition.
      return { ok: false, lineageComplete: true, writable: false, code: "not_writable" };
    }
  }

  // usageProbe reports EXACT control-store consumption. PostgreSQL exposes no
  // free-space primitive, so honest headroom cannot be computed inside the
  // database; consumption can, and it is the curve that filled this database
  // twice. The capacity budget belongs to the deployment, never to a guess
  // made here.
  async usageProbe(options?: { signal?: AbortSignal }): Promise<ManagerControlStoreUsage> {
    const result = await this.probeQuery(
      `SELECT pfm.control_store_usage() AS r`,
      [],
      options?.signal
    );
    const row = asRecord(result.rows[0], "control store usage");
    const usage = asRecord(row["r"], "control store usage");
    const planes = usage["planeBytes"];
    const planeBytes: Record<string, string> = {};
    if (planes !== null && typeof planes === "object" && !Array.isArray(planes)) {
      for (const [plane, bytes] of Object.entries(planes as Record<string, unknown>)) {
        if (typeof bytes === "string" && /^(?:0|[1-9][0-9]*)$/u.test(bytes)) {
          planeBytes[plane] = bytes;
        }
      }
    }
    return {
      databaseBytes: requireDecimalString(usage, "databaseBytes"),
      planeBytes,
    };
  }

  // Readiness probes must be bounded by the CALLER's deadline as well as by
  // the pool's statement timeout: pg has no per-query cancellation, so an
  // abort abandons the wait while the query settles on its own.
  private async probeQuery(
    text: string,
    values: unknown[],
    signal: AbortSignal | undefined
  ): Promise<{ rows: unknown[] }> {
    const query = this.pool.query(text, values);
    if (!signal) {
      return query;
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const onAbort = (): void => {
        if (!settled) {
          settled = true;
          reject(new ControlStoreUnavailableError("control store probe aborted"));
        }
      };
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener("abort", onAbort, { once: true });
      query.then(
        (value) => {
          signal.removeEventListener("abort", onAbort);
          if (!settled) {
            settled = true;
            resolve(value);
          }
        },
        (error: unknown) => {
          signal.removeEventListener("abort", onAbort);
          if (!settled) {
            settled = true;
            reject(error instanceof Error ? error : new Error("control store probe failed"));
          }
        }
      );
    });
  }

  // call runs one pfm function invocation. Single-statement transactions:
  // the SECURITY DEFINER function forces transaction-local
  // synchronous_commit=on and lock_timeout itself.
  private async call(text: string, values: unknown[], staleEpoch?: string): Promise<unknown> {
    let rows: unknown[];
    try {
      const result = await this.pool.query(text, values);
      rows = result.rows;
    } catch (error) {
      throw mapManagerControlError(error as PgLikeError, staleEpoch);
    }
    if (rows.length !== 1) {
      throw new ControlStoreUnavailableError("control store returned an unexpected row count");
    }
    return (rows[0] as Record<string, unknown>)["r"];
  }

  async claimManager(args: {
    operationId: string;
    runtimeId: string;
    capabilityHash: string;
    ttlMs: number;
  }): Promise<ManagerClaimResult> {
    const row = asRecord(
      await this.call(`SELECT pfm.manager_claim($1,$2,$3,$4) AS r`, [
        args.operationId,
        args.runtimeId,
        args.capabilityHash,
        args.ttlMs,
      ]),
      "manager claim"
    );
    requireExpectedString(row, "runtimeId", args.runtimeId, "manager claim");
    requireExpectedString(row, "operationId", args.operationId, "manager claim");
    const current = requireBoolean(row, "current");
    return {
      managerEpoch: parseManagerEpoch(requireString(row, "managerEpoch")),
      runtimeId: requireString(row, "runtimeId"),
      operationId: requireString(row, "operationId"),
      claimedAtDbMs: requireIntNumber(row, "claimedAtDbMs"),
      expiresAtDbMs:
        current && row["currentExpiresAtDbMs"] !== undefined
          ? requireIntNumber(row, "currentExpiresAtDbMs")
          : requireIntNumber(row, "expiresAtDbMs"),
      dbTimeMs: requireIntNumber(row, "dbTimeMs"),
      current,
      replayed: requireBoolean(row, "replayed"),
    };
  }

  async renewManagerClaim(args: {
    identity: ManagerIdentity;
    ttlMs: number;
  }): Promise<ManagerClaimRenewal> {
    const statement = managerRenewStatement(args);
    const row = asRecord(
      await this.call(statement.sql, statement.values, args.identity.managerEpoch),
      "manager renew"
    );
    return {
      dbTimeMs: requireIntNumber(row, "dbTimeMs"),
      claimExpiresAtDbMs: requireIntNumber(row, "expiresAtDbMs"),
    };
  }

  async releaseManagerClaim(args: { identity: ManagerIdentity }): Promise<{ dbTimeMs: number }> {
    const row = asRecord(
      await this.call(
        `SELECT pfm.manager_release($1,$2,$3) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
        ],
        args.identity.managerEpoch
      ),
      "manager release"
    );
    return { dbTimeMs: requireIntNumber(row, "dbTimeMs") };
  }

  async dbTimeMs(): Promise<number> {
    const value = await this.call(`SELECT pfm.db_time_ms() AS r`, []);
    if (typeof value === "string" && /^[0-9]+$/u.test(value)) {
      const parsed = Number(value);
      if (Number.isSafeInteger(parsed)) {
        return parsed;
      }
    }
    if (typeof value === "number" && Number.isSafeInteger(value)) {
      return value;
    }
    throw new ControlStoreUnavailableError("control store returned a malformed database time");
  }

  async beginAuthorityRuntime(args: {
    identity: ManagerIdentity;
    scope: AuthorityScopeRef;
    authorityInstanceId: string;
    runtimeId: string;
    operationId?: string;
    authorityCapability?: string;
  }): Promise<AuthorityRuntimeBeginResult> {
    const operationId = args.operationId ?? `pfarb_${args.runtimeId}`;
    const authorityCapability =
      args.authorityCapability ??
      hmacOfCanonicalParts(args.identity.managerCapability, [
        "portablefs-authority-runtime-capability-v1",
        args.scope.tenantKey,
        args.scope.volumeId,
        args.scope.branch,
        args.authorityInstanceId,
        args.runtimeId,
      ]);
    const row = asRecord(
      await this.call(
        `SELECT pfm.authority_runtime_begin($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          operationId,
          args.scope.tenantKey,
          args.scope.volumeId,
          args.scope.branch,
          args.authorityInstanceId,
          args.runtimeId,
          authorityCapability,
        ],
        args.identity.managerEpoch
      ),
      "authority runtime begin"
    );
    requireExpectedString(row, "runtimeId", args.runtimeId, "authority runtime begin");
    requireExpectedString(row, "operationId", operationId, "authority runtime begin");
    requireExpectedString(
      row,
      "authorityInstanceId",
      args.authorityInstanceId,
      "authority runtime begin"
    );
    requireExpectedString(row, "managerEpoch", args.identity.managerEpoch, "authority runtime begin");
    return {
      runtimeSeq: parseAuthorityRuntimeSeq(requireString(row, "runtimeSeq")),
      runtimeId: requireString(row, "runtimeId"),
      operationId: requireString(row, "operationId"),
      authorityCapability,
      beganAtDbMs: requireIntNumber(row, "beganAtDbMs"),
      current: requireBoolean(row, "current"),
      replayed: requireBoolean(row, "replayed"),
      dbTimeMs: requireIntNumber(row, "dbTimeMs"),
    };
  }

  async endAuthorityRuntime(args: {
    identity: ManagerIdentity;
    scope: AuthorityScopeRef;
    runtimeSeq: string;
    runtimeId: string;
    reason: string;
    operationId?: string;
  }): Promise<AuthorityRuntimeEndResult> {
    // Deterministic PER SEMANTIC END (runtime + reason): a lost-response
    // retry of one semantic end replays byte-exact, while DISTINCT competing
    // end attempts (e.g. start-failure cleanup racing child-exit) carry
    // distinct ids — the second executes and OBSERVES the already-ended row
    // (pfm.authority_runtime_end keeps the first terminal reason) instead of
    // colliding on one shared id with different fingerprint content. Same-id
    // different-content conflicts (PF009) remain fully enforced.
    const operationId = args.operationId ?? runtimeEndOperationId(args.runtimeId, args.reason);
    const row = asRecord(
      await this.call(
        `SELECT pfm.authority_runtime_end($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          operationId,
          args.scope.tenantKey,
          args.scope.volumeId,
          args.scope.branch,
          args.runtimeSeq,
          args.runtimeId,
          args.reason,
        ],
        args.identity.managerEpoch
      ),
      "authority runtime end"
    );
    requireExpectedString(row, "operationId", operationId, "authority runtime end");
    requireExpectedString(row, "runtimeSeq", args.runtimeSeq, "authority runtime end");
    requireExpectedString(row, "runtimeId", args.runtimeId, "authority runtime end");
    if (requireBoolean(row, "ended") !== true) {
      throw new ControlStoreUnavailableError("authority runtime end did not confirm ended=true");
    }
    return {
      operationId: requireString(row, "operationId"),
      runtimeSeq: parseAuthorityRuntimeSeq(requireString(row, "runtimeSeq")),
      runtimeId: requireString(row, "runtimeId"),
      ended: true,
      endReason: requireString(row, "endReason"),
      endedAtDbMs: requireIntNumber(row, "endedAtDbMs"),
      replayed: requireBoolean(row, "replayed"),
      dbTimeMs: requireIntNumber(row, "dbTimeMs"),
    };
  }

  async runtimeCredentialMint(args: {
    identity: ManagerIdentity;
    credentialHash: string;
    tenantId: string;
    volumeId: string;
    branch: string;
    authorityRuntimeSeq: string;
    authorityRuntimeId: string;
    ttlMs: number;
  }): Promise<RuntimeCredentialMintResult> {
    const row = asRecord(
      await this.call(
        `SELECT pfm.runtime_credential_mint($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          args.credentialHash,
          args.tenantId,
          args.volumeId,
          args.branch,
          args.authorityRuntimeSeq,
          args.authorityRuntimeId,
          args.ttlMs,
        ],
        args.identity.managerEpoch
      ),
      "runtime credential mint"
    );
    return {
      tenantId: requireString(row, "tenantId"),
      volumeId: requireString(row, "volumeId"),
      branchName: requireString(row, "branchName"),
      authEpoch: requireString(row, "authEpoch"),
      admissionEpoch: requireString(row, "admissionEpoch"),
      mintedDbMs: requireIntNumber(row, "mintedDbMs"),
      expiresDbMs: requireIntNumber(row, "expiresDbMs"),
    };
  }

  async accessCreate(args: {
    identity: ManagerIdentity;
    operationId: string;
    leaseId: string;
    scope: AuthorityScopeRef;
    consumerId: string;
    authorityInstanceId: string;
    authorityRuntimeSeq: string;
    authorityRuntimeId: string;
    ttlMs: number;
  }): Promise<AccessOperationResult> {
    return parseAccessOperationResult(
      await this.call(
        `SELECT pfm.access_create($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          args.operationId,
          args.leaseId,
          args.scope.tenantKey,
          args.scope.volumeId,
          args.scope.branch,
          args.consumerId,
          args.authorityInstanceId,
          args.authorityRuntimeSeq,
          args.authorityRuntimeId,
          args.ttlMs,
        ],
        args.identity.managerEpoch
      ),
      {
        kind: "create",
        operationId: args.operationId,
        tenantKey: args.scope.tenantKey,
        managerEpoch: args.identity.managerEpoch,
        volumeId: args.scope.volumeId,
        branch: args.scope.branch,
        consumerId: args.consumerId,
        authorityInstanceId: args.authorityInstanceId,
        authorityRuntimeSeq: args.authorityRuntimeSeq,
        authorityRuntimeId: args.authorityRuntimeId,
      }
    );
  }

  async accessRenew(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    expectedControlSeq: AccessLeaseControlSeq;
    ttlMs: number;
    rotate: boolean;
  }): Promise<AccessOperationResult> {
    return parseAccessOperationResult(
      await this.call(
        `SELECT pfm.access_renew($1,$2,$3,$4,$5,$6,$7,$8,$9) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          args.operationId,
          args.tenantKey,
          args.leaseId,
          args.expectedControlSeq,
          args.ttlMs,
          args.rotate,
        ],
        args.identity.managerEpoch
      ),
      {
        kind: "renew",
        operationId: args.operationId,
        tenantKey: args.tenantKey,
        leaseId: args.leaseId,
        managerEpoch: args.identity.managerEpoch,
      }
    );
  }

  async accessRelease(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    expectedControlSeq: AccessLeaseControlSeq | null;
  }): Promise<AccessOperationResult> {
    return parseAccessOperationResult(
      await this.call(
        `SELECT pfm.access_release($1,$2,$3,$4,$5,$6,$7) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          args.operationId,
          args.tenantKey,
          args.leaseId,
          args.expectedControlSeq,
        ],
        args.identity.managerEpoch
      ),
      {
        kind: "release",
        operationId: args.operationId,
        tenantKey: args.tenantKey,
        leaseId: args.leaseId,
        managerEpoch: args.identity.managerEpoch,
      }
    );
  }

  async accessRevoke(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    reason: AccessLeaseEndBatchReason;
  }): Promise<AccessOperationResult> {
    return parseAccessOperationResult(
      await this.call(
        `SELECT pfm.access_revoke($1,$2,$3,$4,$5,$6,$7) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          args.operationId,
          args.tenantKey,
          args.leaseId,
          args.reason,
        ],
        args.identity.managerEpoch
      ),
      {
        kind: "revoke",
        operationId: args.operationId,
        tenantKey: args.tenantKey,
        leaseId: args.leaseId,
        managerEpoch: args.identity.managerEpoch,
      }
    );
  }

  async accessEndBatch(args: {
    identity: ManagerIdentity;
    operationId: string;
    filter: {
      tenantKey?: string;
      volumeId?: string;
      branch?: string;
      consumerId?: string;
      authorityInstanceId?: string;
      authorityRuntimeSeq?: string;
      epochsBelow?: ManagerEpoch;
    };
    reason: AccessLeaseEndBatchReason;
  }): Promise<AccessEndBatchResult> {
    const row = asRecord(
      await this.call(
        `SELECT pfm.access_end_batch($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          args.operationId,
          args.filter.tenantKey ?? "",
          args.filter.volumeId ?? null,
          args.filter.branch ?? null,
          args.filter.consumerId ?? null,
          args.filter.authorityInstanceId ?? null,
          args.filter.authorityRuntimeSeq ?? null,
          args.filter.epochsBelow ?? null,
          args.reason,
        ],
        args.identity.managerEpoch
      ),
      "access end batch"
    );
    const endedRaw = row["endedLeaseIds"];
    if (!Array.isArray(endedRaw) || endedRaw.some((id) => typeof id !== "string")) {
      throw new ControlStoreUnavailableError("access end batch returned malformed lease ids");
    }
    const endReason = requireString(row, "endReason");
    if (!leaseEndReasons.includes(endReason as AccessLeaseEndReason)) {
      throw new ControlStoreUnavailableError(`unknown batch end reason ${endReason}`);
    }
    requireExpectedString(row, "operationId", args.operationId, "access end batch");
    requireExpectedString(row, "endReason", args.reason, "access end batch");
    return {
      operationId: requireString(row, "operationId"),
      endReason: endReason as AccessLeaseEndReason,
      endedLeaseIds: endedRaw as string[],
      completedAtDbMs: requireIntNumber(row, "completedAtDbMs"),
      replayed: requireBoolean(row, "replayed"),
      dbTimeMs: requireIntNumber(row, "dbTimeMs"),
    };
  }

  async sweepAccessLeases(args: {
    identity: ManagerIdentity;
    operationId: string;
    afterLeaseId?: string;
    limit?: number;
  }): Promise<AccessSweepResult> {
    const afterLeaseId = args.afterLeaseId ?? null;
    const limit = args.limit ?? 256;
    if (!Number.isInteger(limit) || limit < 1 || limit > 512) {
      throw new InvalidControlArgumentError("access sweep limit must be 1..512");
    }
    return parseAccessSweepResult(
      await this.call(
        `SELECT pfm.access_sweep_due($1,$2,$3,$4,$5,$6) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          args.operationId,
          afterLeaseId,
          limit,
        ],
        args.identity.managerEpoch
      ),
      { operationId: args.operationId, afterLeaseId, limit }
    );
  }

  async accessGet(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    leaseId: string;
  }): Promise<(AccessLeaseFacts & { dbTimeMs: number }) | null> {
    const value = await this.call(
      `SELECT pfm.access_get($1,$2,$3,$4,$5) AS r`,
      [
        args.identity.managerEpoch,
        args.identity.managerRuntimeId,
        args.identity.managerCapability,
        args.tenantKey,
        args.leaseId,
      ],
      args.identity.managerEpoch
    );
    if (value === null) {
      return null;
    }
    const row = asRecord(value, "access get");
    requireExpectedString(row, "tenantKey", args.tenantKey, "access get");
    requireExpectedString(row, "leaseId", args.leaseId, "access get");
    return { ...parseAccessLeaseFacts(row), dbTimeMs: requireIntNumber(row, "dbTimeMs") };
  }

  async accessListActive(args: {
    identity: ManagerIdentity;
  }): Promise<{ leases: AccessLeaseFacts[]; dbTimeMs: number }> {
    const row = asRecord(
      await this.call(
        `SELECT pfm.access_list_active($1,$2,$3) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
        ],
        args.identity.managerEpoch
      ),
      "access list active"
    );
    const leasesRaw = row["leases"];
    if (!Array.isArray(leasesRaw)) {
      throw new ControlStoreUnavailableError("access list returned a malformed lease array");
    }
    return {
      leases: leasesRaw.map((lease) => parseAccessLeaseFacts(lease)),
      dbTimeMs: requireIntNumber(row, "dbTimeMs"),
    };
  }

  async putLifecycleReceipt(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    operationId: string;
    response: unknown;
  }): Promise<LifecycleReceiptPutResult> {
    const row = asRecord(
      await this.call(
        `SELECT pfm.lifecycle_receipt_put($1,$2,$3,$4,$5,$6::jsonb) AS r`,
        [
          args.identity.managerEpoch,
          args.identity.managerRuntimeId,
          args.identity.managerCapability,
          args.tenantKey,
          args.operationId,
          JSON.stringify(args.response),
        ],
        args.identity.managerEpoch
      ),
      "lifecycle receipt put"
    );
    return {
      response: row["response"],
      replayed: requireBoolean(row, "replayed"),
      dbTimeMs: requireIntNumber(row, "dbTimeMs"),
    };
  }

  async findLifecycleReceipt(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    operationId: string;
  }): Promise<LifecycleReceiptLookup> {
    const value = await this.call(
      `SELECT pfm.lifecycle_receipt_get($1,$2,$3,$4,$5) AS r`,
      [
        args.identity.managerEpoch,
        args.identity.managerRuntimeId,
        args.identity.managerCapability,
        args.tenantKey,
        args.operationId,
      ],
      args.identity.managerEpoch
    );
    if (value === null) {
      return { kind: "unknown" };
    }
    const row = asRecord(value, "lifecycle receipt get");
    return {
      kind: "found",
      response: row["response"],
      fingerprint: requireString(row, "fingerprint"),
      dbTimeMs: requireIntNumber(row, "dbTimeMs"),
    };
  }
}

// ---------------------------------------------------------------------------
// In-memory fake (tests and local experiments ONLY — never production).
//
// A rigorous test double reproducing the pfm SQL semantics (DB-time
// singleton claim lease, permanent namespaced receipts, runtime rows, lease
// CAS + settle) with deterministic clock control and fault injection. The
// fake is NEVER a production fallback: main.ts only ever constructs the
// Postgres adapter.
// ---------------------------------------------------------------------------

type FaultTarget =
  | "claimManager"
  | "renewManagerClaim"
  | "releaseManagerClaim"
  | "dbTimeMs"
  | "beginAuthorityRuntime"
  | "endAuthorityRuntime"
  | "runtimeCredentialMint"
  | "accessCreate"
  | "accessRenew"
  | "accessRelease"
  | "accessRevoke"
  | "accessEndBatch"
  | "sweepAccessLeases"
  | "accessGet"
  | "accessListActive"
  | "putLifecycleReceipt"
  | "findLifecycleReceipt";

interface FakeClaim {
  epoch: bigint;
  runtimeId: string;
  claimOperationId: string;
  capabilityHash: string;
  claimedAt: number;
  renewedAt: number;
  expiresAt: number;
}

interface FakeRuntime {
  runtimeSeq: bigint;
  runtimeId: string;
  authorityInstanceId: string;
  authorityCapabilityHash: string;
  managerEpoch: bigint;
  state: "live" | "ended";
  endReason?: string;
  endedAt?: number;
}

interface FakeLease {
  leaseId: string;
  tenantKey: string;
  volumeId: string;
  branch: string;
  consumerId: string;
  authorityInstanceId: string;
  authorityRuntimeSeq: bigint;
  authorityRuntimeId: string;
  managerEpoch: bigint;
  tokenGeneration: bigint;
  controlSeq: bigint;
  renewReceiptFloor: bigint;
  state: AccessLeaseState;
  endReason?: AccessLeaseEndReason;
  expiresAt: number;
  createdAt: number;
  endedAt?: number;
}

interface FakeReceipt {
  fingerprint: string;
  response: Record<string, unknown> | null;
}

interface FakeRenewReceipt extends FakeReceipt {
  tenantKey: string;
  leaseId: string;
  expectedControlSeq: bigint;
  ttlMs: number;
  rotate: boolean;
}

function sha256hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

// Structured composite map key: length-delimited JSON array (no delimiter
// collisions), mirroring the SQL structured scope keys.
function structuredKey(parts: readonly unknown[]): string {
  return JSON.stringify(parts);
}

function serverFingerprint(kind: string, parts: readonly unknown[]): string {
  return sha256hex(structuredKey([`portablefs-control-${kind}-v1`, ...parts]));
}

export interface InMemoryManagerControlStoreOptions {
  // The DATABASE clock, independent from the host clock so tests can skew
  // them apart. Defaults to Date.now.
  dbNow?: () => number;
}

export class InMemoryManagerControlStore implements ManagerControlStore {
  private readonly dbNow: () => number;

  private epochCounter = 0n;
  private claim: FakeClaim | null = null;

  private readonly runtimes = new Map<string, FakeRuntime[]>();
  private readonly leases = new Map<string, FakeLease>();
  // Receipts: (tenantKey, domain, operationId) -> permanent record.
  private readonly receipts = new Map<string, FakeReceipt>();
  private readonly renewReceipts = new Map<string, FakeRenewReceipt>();

  private closed = false;
  private readonly pendingFaults = new Map<FaultTarget, number>();
  // Optional interleaving gate: awaited before every call so tests can pause
  // the store mid-operation and race another actor against it.
  gate: ((target: FaultTarget) => Promise<void>) | null = null;

  constructor(options: InMemoryManagerControlStoreOptions = {}) {
    this.dbNow = options.dbNow ?? Date.now;
  }

  // An in-memory store has no connection to reserve and no data plane to be
  // starved by, so its liveness channel is in-process — and it reports
  // isolated=false, which is exactly what the production composition refuses.
  createClaimHeartbeat(): ClaimHeartbeat {
    return new InProcessClaimHeartbeat((args) => this.renewManagerClaim(args));
  }

  // Makes the next `count` calls to `target` fail with
  // ControlStoreUnavailableError WITHOUT applying their effects.
  failNext(target: FaultTarget, count = 1): void {
    this.pendingFaults.set(target, (this.pendingFaults.get(target) ?? 0) + count);
  }

  // Test hook: forcibly install a competing manager's claim (what a takeover
  // after DB-time expiry produces).
  supersedeEpoch(): string {
    this.epochCounter += 1n;
    const now = this.dbNow();
    this.claim = {
      epoch: this.epochCounter,
      runtimeId: `competitor-${this.epochCounter}`,
      claimOperationId: `competitor-claim-${this.epochCounter}`,
      capabilityHash: sha256hex(`competitor-capability-${this.epochCounter}`),
      claimedAt: now,
      renewedAt: now,
      expiresAt: now + 60_000,
    };
    return this.claim.epoch.toString(10);
  }

  // Test hook: expire the live claim at database time without a successor.
  expireClaim(): void {
    if (this.claim) {
      this.claim.expiresAt = this.dbNow();
    }
  }

  epoch(): string {
    return this.claim ? this.claim.epoch.toString(10) : "0";
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  async healthProbe(): Promise<ManagerControlProbe> {
    const live = !this.closed;
    return {
      ok: live,
      lineageComplete: live,
      writable: live,
      ...(live ? {} : { code: "unreachable" as const }),
    };
  }

  private async enter(target: FaultTarget): Promise<void> {
    if (this.closed) {
      throw new ControlStoreUnavailableError("control store is closed");
    }
    if (this.gate) {
      await this.gate(target);
    }
    const pending = this.pendingFaults.get(target) ?? 0;
    if (pending > 0) {
      this.pendingFaults.set(target, pending - 1);
      throw new ControlStoreUnavailableError(`Injected ${target} fault.`);
    }
  }

  // requireManager mirrors pfm.require_manager: exact epoch + runtime id +
  // capability hash + DB-time expiry.
  private requireManager(identity: ManagerIdentity): number {
    const now = this.dbNow();
    const claim = this.claim;
    if (!claim) {
      throw new ManagerEpochSupersededError(identity.managerEpoch, null, "no manager claim exists");
    }
    if (
      claim.epoch.toString(10) !== identity.managerEpoch ||
      claim.runtimeId !== identity.managerRuntimeId
    ) {
      throw new ManagerEpochSupersededError(identity.managerEpoch, claim.epoch.toString(10));
    }
    if (sha256hex(identity.managerCapability) !== claim.capabilityHash) {
      throw new ManagerEpochSupersededError(
        identity.managerEpoch,
        claim.epoch.toString(10),
        "manager capability rejected"
      );
    }
    if (claim.expiresAt <= now) {
      throw new ManagerEpochSupersededError(
        identity.managerEpoch,
        null,
        `manager claim expired at database time (${claim.expiresAt} <= ${now})`
      );
    }
    return now;
  }

  // receiptClaim mirrors pfm.receipt_claim: NULL when new; stored response
  // when replayed; conflict when the fingerprint differs.
  private receiptClaim(
    tenantKey: string,
    domain: string,
    operationId: string,
    fingerprint: string
  ): Record<string, unknown> | null {
    const stored = this.receipts.get(structuredKey([tenantKey, domain, operationId]));
    if (!stored) {
      return null;
    }
    if (stored.fingerprint !== fingerprint) {
      throw new ControlOperationConflictError(
        `operation ${operationId} replayed with different content in ${tenantKey}/${domain}`,
        null
      );
    }
    if (stored.response === null) {
      throw new ControlReceiptEvictedError("receipt body was compacted", null);
    }
    return structuredClone(stored.response);
  }

  private receiptPut(
    tenantKey: string,
    domain: string,
    operationId: string,
    fingerprint: string,
    response: Record<string, unknown>
  ): void {
    this.receipts.set(structuredKey([tenantKey, domain, operationId]), {
      fingerprint,
      response: structuredClone(response),
    });
  }

  private leaseFacts(lease: FakeLease): AccessLeaseFacts {
    return {
      leaseId: lease.leaseId,
      tenantKey: lease.tenantKey,
      volumeId: lease.volumeId,
      branch: lease.branch,
      consumerId: lease.consumerId,
      authorityInstanceId: lease.authorityInstanceId,
      authorityRuntimeSeq: lease.authorityRuntimeSeq.toString(10),
      authorityRuntimeId: lease.authorityRuntimeId,
      managerEpoch: parseManagerEpoch(lease.managerEpoch.toString(10)),
      tokenGeneration: parseAccessLeaseTokenGeneration(lease.tokenGeneration.toString(10)),
      controlSeq: parseAccessLeaseControlSeq(lease.controlSeq.toString(10)),
      state: lease.state,
      ...(lease.endReason !== undefined ? { endReason: lease.endReason } : {}),
      expiresAt: lease.expiresAt,
      createdAtMs: lease.createdAt,
      ...(lease.endedAt !== undefined ? { endedAtMs: lease.endedAt } : {}),
    };
  }

  private leaseResponseFacts(lease: FakeLease): Record<string, unknown> {
    return this.leaseFacts(lease) as unknown as Record<string, unknown>;
  }

  // settleLease mirrors the sweep's terminal settlement: DB-time expiry and
  // epoch supersession settle terminally BEFORE any state decision.
  private settleLease(lease: FakeLease, currentEpoch: bigint, now: number): void {
    if (lease.state !== "active") {
      return;
    }
    if (lease.managerEpoch !== currentEpoch) {
      lease.state = "revoked";
      lease.endReason = "manager-epoch-superseded";
      lease.endedAt = now;
      lease.controlSeq += 1n;
      return;
    }
    if (lease.expiresAt <= now) {
      lease.state = "expired";
      lease.endReason = "expired";
      lease.endedAt = now;
      lease.controlSeq += 1n;
    }
  }

  private effectiveLeaseFacts(lease: FakeLease, currentEpoch: bigint, now: number): AccessLeaseFacts {
    const facts = this.leaseFacts(lease);
    if (lease.state !== "active") return facts;
    if (lease.managerEpoch !== currentEpoch) {
      return { ...facts, state: "revoked", endReason: "manager-epoch-superseded" };
    }
    if (lease.expiresAt <= now) {
      return { ...facts, state: "expired", endReason: "expired" };
    }
    return facts;
  }

  private operationResult(
    lease: FakeLease,
    kind: AccessOperationResult["kind"],
    operationId: string,
    receiptFingerprint: string,
    mintedToken: boolean,
    now: number
  ): Record<string, unknown> {
    return {
      ...this.leaseResponseFacts(lease),
      kind,
      operationId,
      receiptFingerprint,
      mintedToken,
      completedAtDbMs: now,
    };
  }

  private toAccessOperationResult(
    response: Record<string, unknown>,
    replayed: boolean,
    dbTimeMs: number,
    currentFacts?: AccessLeaseFacts
  ): AccessOperationResult {
    const result: AccessOperationResult = {
      ...(response as unknown as AccessLeaseFacts),
      kind: response["kind"] as AccessOperationResult["kind"],
      operationId: response["operationId"] as string,
      receiptFingerprint: response["receiptFingerprint"] as string,
      currentFacts: currentFacts ?? (response as unknown as AccessLeaseFacts),
      mintedToken: response["mintedToken"] as boolean,
      completedAtDbMs: response["completedAtDbMs"] as number,
      replayed,
      dbTimeMs,
    };
    validateAccessProjection(result, result.currentFacts);
    return result;
  }

  private currentFactsForReceipt(
    identity: ManagerIdentity,
    response: Record<string, unknown>,
    now: number
  ): AccessLeaseFacts {
    const leaseId = response["leaseId"];
    const lease = typeof leaseId === "string" ? this.leases.get(leaseId) : undefined;
    if (!lease) {
      throw new ControlNotFoundError("receipted access lease is missing");
    }
    return this.effectiveLeaseFacts(lease, BigInt(identity.managerEpoch), now);
  }

  // ------------------------------------------------------------------
  // Manager claim.
  // ------------------------------------------------------------------

  async claimManager(args: {
    operationId: string;
    runtimeId: string;
    capabilityHash: string;
    ttlMs: number;
  }): Promise<ManagerClaimResult> {
    await this.enter("claimManager");
    if (args.ttlMs < 1_000 || args.ttlMs > 3_600_000) {
      throw new InvalidControlArgumentError("manager claim ttl must be 1s..1h");
    }
    const now = this.dbNow();
    const fingerprint = sha256hex(
      structuredKey(["manager-claim-v2", args.runtimeId, args.capabilityHash, String(args.ttlMs)])
    );
    const replay = this.receiptClaim("", "manager-claim", args.operationId, fingerprint);
    if (replay) {
      const current =
        this.claim !== null &&
        this.claim.claimOperationId === args.operationId &&
        this.claim.runtimeId === args.runtimeId &&
        this.claim.expiresAt > now;
      return {
        managerEpoch: parseManagerEpoch(replay["managerEpoch"] as string),
        runtimeId: replay["runtimeId"] as string,
        operationId: replay["operationId"] as string,
        claimedAtDbMs: replay["claimedAtDbMs"] as number,
        expiresAtDbMs: current ? this.claim!.expiresAt : (replay["expiresAtDbMs"] as number),
        dbTimeMs: now,
        current,
        replayed: true,
      };
    }
    if (this.claim && this.claim.expiresAt > now) {
      if (this.claim.runtimeId === args.runtimeId) {
        throw new ControlOperationConflictError(
          `runtime ${args.runtimeId} already holds the live claim under operation ${this.claim.claimOperationId}`,
          null
        );
      }
      throw new ManagerClaimHeldError(
        this.claim.expiresAt,
        now,
        this.claim.epoch.toString(10),
        `manager claim is held until ${this.claim.expiresAt} (database time ${now})`
      );
    }
    this.epochCounter += 1n;
    this.claim = {
      epoch: this.epochCounter,
      runtimeId: args.runtimeId,
      claimOperationId: args.operationId,
      capabilityHash: args.capabilityHash,
      claimedAt: now,
      renewedAt: now,
      expiresAt: now + args.ttlMs,
    };
    const response: Record<string, unknown> = {
      managerEpoch: this.claim.epoch.toString(10),
      runtimeId: args.runtimeId,
      operationId: args.operationId,
      claimedAtDbMs: now,
      expiresAtDbMs: this.claim.expiresAt,
    };
    this.receiptPut("", "manager-claim", args.operationId, fingerprint, response);
    return {
      managerEpoch: parseManagerEpoch(this.claim.epoch.toString(10)),
      runtimeId: args.runtimeId,
      operationId: args.operationId,
      claimedAtDbMs: now,
      expiresAtDbMs: this.claim.expiresAt,
      dbTimeMs: now,
      current: true,
      replayed: false,
    };
  }

  async renewManagerClaim(args: {
    identity: ManagerIdentity;
    ttlMs: number;
  }): Promise<ManagerClaimRenewal> {
    await this.enter("renewManagerClaim");
    const now = this.requireManager(args.identity);
    this.claim!.renewedAt = now;
    this.claim!.expiresAt = Math.max(this.claim!.expiresAt, now + args.ttlMs);
    return { dbTimeMs: now, claimExpiresAtDbMs: this.claim!.expiresAt };
  }

  async releaseManagerClaim(args: { identity: ManagerIdentity }): Promise<{ dbTimeMs: number }> {
    await this.enter("releaseManagerClaim");
    const now = this.requireManager(args.identity);
    this.claim!.expiresAt = now;
    return { dbTimeMs: now };
  }

  async dbTimeMs(): Promise<number> {
    await this.enter("dbTimeMs");
    return this.dbNow();
  }

  // ------------------------------------------------------------------
  // Authority runtimes.
  // ------------------------------------------------------------------

  async beginAuthorityRuntime(args: {
    identity: ManagerIdentity;
    scope: AuthorityScopeRef;
    authorityInstanceId: string;
    runtimeId: string;
    operationId?: string;
    authorityCapability?: string;
  }): Promise<AuthorityRuntimeBeginResult> {
    await this.enter("beginAuthorityRuntime");
    const now = this.requireManager(args.identity);
    const operationId = args.operationId ?? `pfarb_${args.runtimeId}`;
    const authorityCapability =
      args.authorityCapability ??
      hmacOfCanonicalParts(args.identity.managerCapability, [
        "portablefs-authority-runtime-capability-v1",
        args.scope.tenantKey,
        args.scope.volumeId,
        args.scope.branch,
        args.authorityInstanceId,
        args.runtimeId,
      ]);
    const authorityCapabilityHash = sha256Hex(authorityCapability);
    const fingerprint = serverFingerprint("authority-runtime-begin", [
      args.scope.tenantKey,
      args.scope.volumeId,
      args.scope.branch,
      args.authorityInstanceId,
      args.runtimeId,
    ]);
    const key = structuredKey([args.scope.tenantKey, args.scope.volumeId, args.scope.branch]);
    const rows = this.runtimes.get(key) ?? [];
    const replay = this.receiptClaim(
      args.scope.tenantKey,
      "authority-runtime-begin",
      operationId,
      fingerprint
    );
    if (replay) {
      const receiptedRuntime = rows.find(
        (row) =>
          row.runtimeSeq.toString(10) === replay["runtimeSeq"] && row.runtimeId === replay["runtimeId"]
      );
      if (!receiptedRuntime || receiptedRuntime.authorityCapabilityHash !== authorityCapabilityHash) {
        throw new ManagerEpochSupersededError(
          args.identity.managerEpoch,
          args.identity.managerEpoch,
          "authority runtime receipt capability rejected"
        );
      }
      const current = rows.some(
        (row) =>
          row.state === "live" &&
          row.runtimeSeq.toString(10) === replay["runtimeSeq"] &&
          row.runtimeId === replay["runtimeId"]
      );
      return {
        runtimeSeq: parseAuthorityRuntimeSeq(replay["runtimeSeq"] as string),
        runtimeId: replay["runtimeId"] as string,
        operationId,
        authorityCapability,
        beganAtDbMs: replay["beganAtDbMs"] as number,
        current,
        replayed: true,
        dbTimeMs: now,
      };
    }
    for (const row of rows) {
      if (row.state === "live") {
        row.state = "ended";
        row.endReason = "superseded";
      }
    }
    const seq = rows.length === 0 ? 1n : rows[rows.length - 1]!.runtimeSeq + 1n;
    rows.push({
      runtimeSeq: seq,
      runtimeId: args.runtimeId,
      authorityInstanceId: args.authorityInstanceId,
      authorityCapabilityHash,
      managerEpoch: BigInt(args.identity.managerEpoch),
      state: "live",
    });
    this.runtimes.set(key, rows);
    const response = {
      operationId,
      runtimeSeq: seq.toString(10),
      runtimeId: args.runtimeId,
      authorityInstanceId: args.authorityInstanceId,
      managerEpoch: args.identity.managerEpoch,
      beganAtDbMs: now,
    };
    this.receiptPut(args.scope.tenantKey, "authority-runtime-begin", operationId, fingerprint, response);
    return {
      runtimeSeq: seq.toString(10),
      runtimeId: args.runtimeId,
      operationId,
      authorityCapability,
      beganAtDbMs: now,
      current: true,
      replayed: false,
      dbTimeMs: now,
    };
  }

  async endAuthorityRuntime(args: {
    identity: ManagerIdentity;
    scope: AuthorityScopeRef;
    runtimeSeq: string;
    runtimeId: string;
    reason: string;
    operationId?: string;
  }): Promise<AuthorityRuntimeEndResult> {
    await this.enter("endAuthorityRuntime");
    const now = this.requireManager(args.identity);
    // Identical derivation to the Postgres adapter: one deterministic id per
    // SEMANTIC end (runtime + reason), so exact retries replay and distinct
    // competing reasons observe the ended row instead of colliding.
    const operationId = args.operationId ?? runtimeEndOperationId(args.runtimeId, args.reason);
    const fingerprint = serverFingerprint("authority-runtime-end", [
      args.scope.tenantKey,
      args.scope.volumeId,
      args.scope.branch,
      args.runtimeSeq,
      args.runtimeId,
      args.reason,
    ]);
    const replay = this.receiptClaim(args.scope.tenantKey, "authority-runtime-end", operationId, fingerprint);
    if (replay) {
      return {
        operationId,
        runtimeSeq: replay["runtimeSeq"] as string,
        runtimeId: replay["runtimeId"] as string,
        ended: true,
        endReason: replay["endReason"] as string,
        endedAtDbMs: replay["endedAtDbMs"] as number,
        replayed: true,
        dbTimeMs: now,
      };
    }
    const key = structuredKey([args.scope.tenantKey, args.scope.volumeId, args.scope.branch]);
    const row = (this.runtimes.get(key) ?? []).find(
      (candidate) => candidate.runtimeSeq.toString(10) === args.runtimeSeq
    );
    if (!row) {
      throw new ControlNotFoundError(`authority runtime ${key} seq ${args.runtimeSeq} not found`);
    }
    if (row.runtimeId !== args.runtimeId) {
      throw new ControlOperationConflictError(
        `authority runtime seq ${args.runtimeSeq} has a different runtime id`,
        null
      );
    }
    if (row.state === "live") {
      row.state = "ended";
      row.endReason = args.reason || "ended";
      row.endedAt = now;
    }
    const response = {
      operationId,
      runtimeSeq: args.runtimeSeq,
      runtimeId: args.runtimeId,
      ended: true,
      endReason: row.endReason ?? args.reason,
      endedAtDbMs: row.endedAt ?? now,
    };
    this.receiptPut(args.scope.tenantKey, "authority-runtime-end", operationId, fingerprint, response);
    return {
      operationId,
      runtimeSeq: args.runtimeSeq,
      runtimeId: args.runtimeId,
      ended: true,
      endReason: response.endReason,
      endedAtDbMs: response.endedAtDbMs,
      replayed: false,
      dbTimeMs: now,
    };
  }

  // Faithful to pfm.runtime_credential_mint (migration 015): requires the
  // LIVE manager claim + the exact live runtime row of the scope, and
  // answers the epoch bindings a pre-lifecycle deployment carries (auth and
  // admission epochs both 1). The registry treats the mint as LOAD-BEARING,
  // so the in-memory double implements it rather than simulating an
  // unsupported plane.
  async runtimeCredentialMint(args: {
    identity: ManagerIdentity;
    credentialHash: string;
    tenantId: string;
    volumeId: string;
    branch: string;
    authorityRuntimeSeq: string;
    authorityRuntimeId: string;
    ttlMs: number;
  }): Promise<RuntimeCredentialMintResult> {
    await this.enter("runtimeCredentialMint");
    const now = this.requireManager(args.identity);
    if (args.ttlMs < 60_000 || args.ttlMs > 3_600_000) {
      throw new InvalidControlArgumentError("runtime credential ttl must be 60s..1h");
    }
    const key = structuredKey([`t:${args.tenantId}`, args.volumeId, args.branch]);
    const row = (this.runtimes.get(key) ?? []).find(
      (candidate) =>
        candidate.state === "live" &&
        candidate.runtimeSeq.toString(10) === args.authorityRuntimeSeq &&
        candidate.runtimeId === args.authorityRuntimeId
    );
    if (!row) {
      throw new ControlNotFoundError(
        `runtime credential mint requires the live runtime ${args.authorityRuntimeSeq}/${args.authorityRuntimeId} of ${key}`
      );
    }
    this.mintedCredentialHashes.push(args.credentialHash);
    return {
      tenantId: args.tenantId,
      volumeId: args.volumeId,
      branchName: args.branch,
      authEpoch: "1",
      admissionEpoch: "1",
      mintedDbMs: now,
      expiresDbMs: now + args.ttlMs,
    };
  }

  // Test inspection: every credential hash minted, in order.
  readonly mintedCredentialHashes: string[] = [];

  // Test inspection: how many DURABLE lease rows are still state=active
  // (optionally scoped to one authority instance). Reads the raw rows — no
  // manager identity or DB-time settle involved.
  activeLeaseRows(authorityInstanceId?: string): number {
    let count = 0;
    for (const lease of this.leases.values()) {
      if (
        lease.state === "active" &&
        (authorityInstanceId === undefined || lease.authorityInstanceId === authorityInstanceId)
      ) {
        count += 1;
      }
    }
    return count;
  }

  liveRuntime(scope: AuthorityScopeRef): { runtimeSeq: string; runtimeId: string } | null {
    const rows = this.runtimes.get(structuredKey([scope.tenantKey, scope.volumeId, scope.branch]));
    const live = rows?.find((row) => row.state === "live");
    return live ? { runtimeSeq: live.runtimeSeq.toString(10), runtimeId: live.runtimeId } : null;
  }

  // ------------------------------------------------------------------
  // Access leases.
  // ------------------------------------------------------------------

  async accessCreate(args: {
    identity: ManagerIdentity;
    operationId: string;
    leaseId: string;
    scope: AuthorityScopeRef;
    consumerId: string;
    authorityInstanceId: string;
    authorityRuntimeSeq: string;
    authorityRuntimeId: string;
    ttlMs: number;
  }): Promise<AccessOperationResult> {
    await this.enter("accessCreate");
    if (args.ttlMs < 1_000 || args.ttlMs > 86_400_000) {
      throw new InvalidControlArgumentError("access lease ttl must be 1s..24h");
    }
    const now = this.requireManager(args.identity);
    const receiptFingerprint = serverFingerprint("access-create", [
      args.scope.tenantKey,
      args.scope.volumeId,
      args.scope.branch,
      args.consumerId,
      args.authorityInstanceId,
      args.authorityRuntimeSeq,
      args.authorityRuntimeId,
      args.ttlMs,
    ]);
    const replay = this.receiptClaim(args.scope.tenantKey, "access", args.operationId, receiptFingerprint);
    if (replay) {
      return this.toAccessOperationResult(
        replay,
        true,
        now,
        this.currentFactsForReceipt(args.identity, replay, now)
      );
    }
    const live = this.liveRuntime(args.scope);
    if (!live || live.runtimeSeq !== args.authorityRuntimeSeq || live.runtimeId !== args.authorityRuntimeId) {
      throw new ManagerEpochSupersededError(
        args.identity.managerEpoch,
        null,
        `access lease does not bind the live authority runtime of ${structuredKey([
          args.scope.tenantKey,
          args.scope.volumeId,
          args.scope.branch,
        ])}`
      );
    }
    if (this.leases.has(args.leaseId)) {
      throw new ControlOperationConflictError(`access lease id ${args.leaseId} already exists`, null);
    }
    const lease: FakeLease = {
      leaseId: args.leaseId,
      tenantKey: args.scope.tenantKey,
      volumeId: args.scope.volumeId,
      branch: args.scope.branch,
      consumerId: args.consumerId,
      authorityInstanceId: args.authorityInstanceId,
      authorityRuntimeSeq: BigInt(args.authorityRuntimeSeq),
      authorityRuntimeId: args.authorityRuntimeId,
      managerEpoch: BigInt(args.identity.managerEpoch),
      tokenGeneration: 1n,
      controlSeq: 1n,
      renewReceiptFloor: 1n,
      state: "active",
      expiresAt: now + args.ttlMs,
      createdAt: now,
    };
    this.leases.set(args.leaseId, lease);
    const response = this.operationResult(lease, "create", args.operationId, receiptFingerprint, true, now);
    this.receiptPut(args.scope.tenantKey, "access", args.operationId, receiptFingerprint, response);
    return this.toAccessOperationResult(response, false, now);
  }

  private requireLease(tenantKey: string, leaseId: string): FakeLease {
    const lease = this.leases.get(leaseId);
    if (!lease || lease.tenantKey !== tenantKey) {
      // Cross-tenant probing is indistinguishable from not-found.
      throw new ControlNotFoundError(`access lease ${leaseId} not found`);
    }
    return lease;
  }

  async accessRenew(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    expectedControlSeq: string;
    ttlMs: number;
    rotate: boolean;
  }): Promise<AccessOperationResult> {
    await this.enter("accessRenew");
    if (args.ttlMs < 1_000 || args.ttlMs > 86_400_000) {
      throw new InvalidControlArgumentError("access lease ttl must be 1s..24h");
    }
    const now = this.requireManager(args.identity);
    const expectedControlSeq = BigInt(args.expectedControlSeq);
    const effectiveFingerprint = serverFingerprint("access-renew", [
      args.tenantKey,
      args.leaseId,
      args.ttlMs,
      args.rotate,
    ]);
    const receiptKey = structuredKey([args.tenantKey, args.leaseId, args.operationId]);
    const replay = this.renewReceipts.get(receiptKey);
    if (replay) {
      if (
        replay.fingerprint !== effectiveFingerprint ||
        replay.ttlMs !== args.ttlMs ||
        replay.rotate !== args.rotate
      ) {
        throw new ControlOperationConflictError(
          `renew operation ${args.operationId} replayed with different content`,
          null
        );
      }
      if (replay.response === null) {
        const lease = this.leases.get(args.leaseId);
        throw new ControlReceiptEvictedError(
          "renew receipt body was compacted",
          lease ? parseAccessLeaseControlSeq(lease.renewReceiptFloor.toString(10)) : null
        );
      }
      const response = structuredClone(replay.response);
      return this.toAccessOperationResult(
        response,
        true,
        now,
        this.currentFactsForReceipt(args.identity, response, now)
      );
    }
    const lease = this.requireLease(args.tenantKey, args.leaseId);
    if (expectedControlSeq < lease.renewReceiptFloor) {
      throw new ControlReceiptEvictedError(
        `renew receipt is older than retained floor ${lease.renewReceiptFloor}`,
        parseAccessLeaseControlSeq(lease.renewReceiptFloor.toString(10))
      );
    }
    const effective = this.effectiveLeaseFacts(lease, BigInt(args.identity.managerEpoch), now);
    if (effective.state !== "active") {
      throw new AccessLeaseNotActiveError(`access lease ${args.leaseId} is ${effective.state}`, effective);
    }
    // Mirrors pfm.access_renew's PF012 runtime-liveness gate (FOR SHARE on
    // the bound runtime row): an ENDED authority runtime must never make a
    // not-yet-reconciled lease renewable — defense in depth beneath the
    // manager's revoke-before-runtime-end teardown ordering.
    const boundRuntime = (
      this.runtimes.get(structuredKey([lease.tenantKey, lease.volumeId, lease.branch])) ?? []
    ).find((row) => row.runtimeSeq === lease.authorityRuntimeSeq);
    if (
      !boundRuntime ||
      boundRuntime.state !== "live" ||
      boundRuntime.runtimeId !== lease.authorityRuntimeId ||
      boundRuntime.authorityInstanceId !== lease.authorityInstanceId ||
      boundRuntime.managerEpoch !== BigInt(args.identity.managerEpoch)
    ) {
      throw new AccessLeaseNotActiveError(
        `access lease ${args.leaseId} authority runtime is not live`,
        { ...effective, state: "revoked", endReason: "authority-retired" }
      );
    }
    if (lease.controlSeq !== expectedControlSeq) {
      throw new ControlOperationConflictError(
        `access lease ${args.leaseId} control seq is ${lease.controlSeq} (caller expected ${args.expectedControlSeq})`,
        this.leaseFacts(lease)
      );
    }
    lease.expiresAt = Math.max(lease.expiresAt, now + args.ttlMs);
    lease.controlSeq += 1n;
    if (args.rotate) {
      lease.tokenGeneration += 1n;
    }
    const response = this.operationResult(lease, "renew", args.operationId, effectiveFingerprint, args.rotate, now);
    this.renewReceipts.set(receiptKey, {
      tenantKey: args.tenantKey,
      leaseId: args.leaseId,
      fingerprint: effectiveFingerprint,
      expectedControlSeq,
      ttlMs: args.ttlMs,
      rotate: args.rotate,
      response: structuredClone(response),
    });
    const newFloor =
      lease.controlSeq - 64n > lease.renewReceiptFloor ? lease.controlSeq - 64n : lease.renewReceiptFloor;
    lease.renewReceiptFloor = newFloor;
    for (const stored of this.renewReceipts.values()) {
      if (
        stored.tenantKey === args.tenantKey &&
        stored.leaseId === args.leaseId &&
        stored.expectedControlSeq < newFloor
      ) {
        stored.response = null;
      }
    }
    return this.toAccessOperationResult(response, false, now);
  }

  async accessRelease(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    expectedControlSeq: string | null;
  }): Promise<AccessOperationResult> {
    await this.enter("accessRelease");
    const now = this.requireManager(args.identity);
    const receiptFingerprint = serverFingerprint("access-release", [args.tenantKey, args.leaseId]);
    const replay = this.receiptClaim(args.tenantKey, "access", args.operationId, receiptFingerprint);
    if (replay) {
      return this.toAccessOperationResult(
        replay,
        true,
        now,
        this.currentFactsForReceipt(args.identity, replay, now)
      );
    }
    const lease = this.requireLease(args.tenantKey, args.leaseId);
    const effective = this.effectiveLeaseFacts(lease, BigInt(args.identity.managerEpoch), now);
    if (effective.state !== "active") {
      throw new AccessLeaseNotActiveError(`access lease ${args.leaseId} is ${effective.state}`, effective);
    }
    if (args.expectedControlSeq !== null && lease.controlSeq.toString(10) !== args.expectedControlSeq) {
      throw new ControlOperationConflictError(
        `access lease ${args.leaseId} control seq is ${lease.controlSeq} (caller expected ${args.expectedControlSeq})`,
        this.leaseFacts(lease)
      );
    }
    lease.state = "released";
    lease.endReason = "released";
    lease.endedAt = now;
    lease.controlSeq += 1n;
    const response = this.operationResult(lease, "release", args.operationId, receiptFingerprint, false, now);
    this.receiptPut(args.tenantKey, "access", args.operationId, receiptFingerprint, response);
    return this.toAccessOperationResult(response, false, now);
  }

  async accessRevoke(args: {
    identity: ManagerIdentity;
    operationId: string;
    tenantKey: string;
    leaseId: string;
    reason: AccessLeaseEndBatchReason;
  }): Promise<AccessOperationResult> {
    await this.enter("accessRevoke");
    const now = this.requireManager(args.identity);
    const receiptFingerprint = serverFingerprint("access-revoke", [args.tenantKey, args.leaseId, args.reason]);
    const replay = this.receiptClaim(args.tenantKey, "access", args.operationId, receiptFingerprint);
    if (replay) {
      return this.toAccessOperationResult(
        replay,
        true,
        now,
        this.currentFactsForReceipt(args.identity, replay, now)
      );
    }
    const lease = this.requireLease(args.tenantKey, args.leaseId);
    if (lease.state === "active") {
      lease.state = args.reason === "expired" ? "expired" : "revoked";
      lease.endReason = args.reason;
      lease.endedAt = now;
      lease.controlSeq += 1n;
    }
    const response = this.operationResult(lease, "revoke", args.operationId, receiptFingerprint, false, now);
    this.receiptPut(args.tenantKey, "access", args.operationId, receiptFingerprint, response);
    return this.toAccessOperationResult(response, false, now);
  }

  async accessEndBatch(args: {
    identity: ManagerIdentity;
    operationId: string;
    filter: {
      tenantKey?: string;
      volumeId?: string;
      branch?: string;
      consumerId?: string;
      authorityInstanceId?: string;
      authorityRuntimeSeq?: string;
      epochsBelow?: string;
    };
    reason: AccessLeaseEndBatchReason;
  }): Promise<AccessEndBatchResult> {
    await this.enter("accessEndBatch");
    const now = this.requireManager(args.identity);
    const tenantKey = args.filter.tenantKey ?? "";
    const receiptFingerprint = serverFingerprint("access-end-batch", [
      tenantKey,
      args.filter.volumeId ?? null,
      args.filter.branch ?? null,
      args.filter.consumerId ?? null,
      args.filter.authorityInstanceId ?? null,
      args.filter.authorityRuntimeSeq ?? null,
      args.filter.epochsBelow ?? null,
      args.reason,
    ]);
    const replay = this.receiptClaim(tenantKey, "access-batch", args.operationId, receiptFingerprint);
    if (replay) {
      return {
        operationId: replay["operationId"] as string,
        endReason: replay["endReason"] as AccessLeaseEndReason,
        endedLeaseIds: (replay["endedLeaseIds"] as string[]) ?? [],
        completedAtDbMs: replay["completedAtDbMs"] as number,
        replayed: true,
        dbTimeMs: now,
      };
    }
    const ended: string[] = [];
    const sorted = [...this.leases.values()].sort((a, b) => (a.leaseId < b.leaseId ? -1 : 1));
    for (const lease of sorted) {
      if (lease.state !== "active") continue;
      if (tenantKey !== "" && lease.tenantKey !== tenantKey) continue;
      if (args.filter.volumeId !== undefined && lease.volumeId !== args.filter.volumeId) continue;
      if (args.filter.branch !== undefined && lease.branch !== args.filter.branch) continue;
      if (args.filter.consumerId !== undefined && lease.consumerId !== args.filter.consumerId) continue;
      if (
        args.filter.authorityInstanceId !== undefined &&
        lease.authorityInstanceId !== args.filter.authorityInstanceId
      )
        continue;
      if (
        args.filter.authorityRuntimeSeq !== undefined &&
        lease.authorityRuntimeSeq.toString(10) !== args.filter.authorityRuntimeSeq
      )
        continue;
      if (args.filter.epochsBelow === undefined) {
        if (lease.managerEpoch.toString(10) !== args.identity.managerEpoch) continue;
      } else if (lease.managerEpoch >= BigInt(args.filter.epochsBelow)) {
        continue;
      }
      lease.state = args.reason === "expired" ? "expired" : "revoked";
      lease.endReason = args.reason;
      lease.endedAt = now;
      lease.controlSeq += 1n;
      ended.push(lease.leaseId);
    }
    const response: Record<string, unknown> = {
      kind: "end-batch",
      operationId: args.operationId,
      endReason: args.reason,
      endedLeaseIds: ended,
      completedAtDbMs: now,
      receiptFingerprint,
    };
    this.receiptPut(tenantKey, "access-batch", args.operationId, receiptFingerprint, response);
    return {
      operationId: args.operationId,
      endReason: args.reason,
      endedLeaseIds: ended,
      completedAtDbMs: now,
      replayed: false,
      dbTimeMs: now,
    };
  }

  async sweepAccessLeases(args: {
    identity: ManagerIdentity;
    operationId: string;
    afterLeaseId?: string;
    limit?: number;
  }): Promise<AccessSweepResult> {
    await this.enter("sweepAccessLeases");
    const now = this.requireManager(args.identity);
    const afterLeaseId = args.afterLeaseId ?? null;
    const limit = args.limit ?? 256;
    if (!Number.isInteger(limit) || limit < 1 || limit > 512) {
      throw new InvalidControlArgumentError("access sweep limit must be 1..512");
    }
    const receiptFingerprint = serverFingerprint("access-sweep-due", [afterLeaseId, limit]);
    const replay = this.receiptClaim("", "access-batch", args.operationId, receiptFingerprint);
    if (replay) {
      return {
        operationId: replay["operationId"] as string,
        afterLeaseId: (replay["afterLeaseId"] as string | null) ?? null,
        limit: Number(replay["limit"]),
        endedLeaseIds: (replay["endedLeaseIds"] as string[]) ?? [],
        nextCursor: (replay["nextCursor"] as string | null) ?? null,
        hasMore: replay["hasMore"] === true,
        receiptFingerprint,
        completedAtDbMs: replay["completedAtDbMs"] as number,
        replayed: true,
        dbTimeMs: now,
      };
    }
    const epoch = BigInt(args.identity.managerEpoch);
    const due = [...this.leases.values()]
      .filter(
        (lease) =>
          lease.state === "active" &&
          (afterLeaseId === null || lease.leaseId > afterLeaseId) &&
          (lease.managerEpoch !== epoch || lease.expiresAt <= now)
      )
      .sort((a, b) => (a.leaseId < b.leaseId ? -1 : a.leaseId > b.leaseId ? 1 : 0));
    const selected = due.slice(0, limit);
    for (const lease of selected) {
      this.settleLease(lease, epoch, now);
    }
    const hasMore = due.length > selected.length;
    const nextCursor = hasMore && selected.length > 0 ? selected[selected.length - 1]!.leaseId : null;
    const endedLeaseIds = selected.map((lease) => lease.leaseId);
    const response: Record<string, unknown> = {
      operationId: args.operationId,
      afterLeaseId,
      limit,
      endedLeaseIds,
      nextCursor,
      hasMore,
      receiptFingerprint,
      completedAtDbMs: now,
    };
    this.receiptPut("", "access-batch", args.operationId, receiptFingerprint, response);
    return {
      operationId: args.operationId,
      afterLeaseId,
      limit,
      endedLeaseIds,
      nextCursor,
      hasMore,
      receiptFingerprint,
      completedAtDbMs: now,
      replayed: false,
      dbTimeMs: now,
    };
  }

  async accessGet(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    leaseId: string;
  }): Promise<(AccessLeaseFacts & { dbTimeMs: number }) | null> {
    await this.enter("accessGet");
    const now = this.requireManager(args.identity);
    const lease = this.leases.get(args.leaseId);
    if (!lease || lease.tenantKey !== args.tenantKey) {
      return null;
    }
    return {
      ...this.effectiveLeaseFacts(lease, BigInt(args.identity.managerEpoch), now),
      dbTimeMs: now,
    };
  }

  async accessListActive(args: {
    identity: ManagerIdentity;
  }): Promise<{ leases: AccessLeaseFacts[]; dbTimeMs: number }> {
    await this.enter("accessListActive");
    const now = this.requireManager(args.identity);
    const epoch = BigInt(args.identity.managerEpoch);
    const active = [...this.leases.values()]
      .filter((lease) => lease.state === "active" && lease.managerEpoch === epoch && lease.expiresAt > now)
      .sort((a, b) => (a.leaseId < b.leaseId ? -1 : 1))
      .map((lease) => this.leaseFacts(lease));
    return { leases: active, dbTimeMs: now };
  }

  // ------------------------------------------------------------------
  // Lifecycle receipts.
  // ------------------------------------------------------------------

  async putLifecycleReceipt(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    operationId: string;
    response: unknown;
  }): Promise<LifecycleReceiptPutResult> {
    await this.enter("putLifecycleReceipt");
    const now = this.requireManager(args.identity);
    const receiptFingerprint = serverFingerprint("lifecycle", [args.tenantKey, args.response]);
    const replay = this.receiptClaim(args.tenantKey, "lifecycle", args.operationId, receiptFingerprint);
    if (replay) {
      return { response: replay, replayed: true, dbTimeMs: now };
    }
    this.receiptPut(
      args.tenantKey,
      "lifecycle",
      args.operationId,
      receiptFingerprint,
      args.response as Record<string, unknown>
    );
    return { response: structuredClone(args.response), replayed: false, dbTimeMs: now };
  }

  async findLifecycleReceipt(args: {
    identity: ManagerIdentity;
    tenantKey: string;
    operationId: string;
  }): Promise<LifecycleReceiptLookup> {
    await this.enter("findLifecycleReceipt");
    const now = this.requireManager(args.identity);
    const stored = this.receipts.get(structuredKey([args.tenantKey, "lifecycle", args.operationId]));
    if (!stored) {
      return { kind: "unknown" };
    }
    return {
      kind: "found",
      response: structuredClone(stored.response),
      fingerprint: stored.fingerprint,
      dbTimeMs: now,
    };
  }
}
