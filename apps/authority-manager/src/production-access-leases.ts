import {
  accessLeaseErrorCodes,
  accessLeaseProtocolVersion,
  type AccessLease,
  type AccessLeaseControlSeq,
  type AccessLeaseInspectResponse,
  type AccessLeaseReceipt,
} from "@portablefs/protocol";
import {
  AccessLeaseNotActiveError,
  ControlNotFoundError,
  ControlOperationConflictError,
  ControlReceiptEvictedError,
  ControlStoreUnavailableError,
  InvalidControlArgumentError,
  ManagerEpochSupersededError,
  compareDecimalStrings,
  managedTenantKey,
  sha256Hex,
  type AccessLeaseFacts,
  type AccessOperationResult,
  type ManagerControlStore,
  type ManagerIdentity,
} from "./manager-control-store.js";
import { AccessLeaseError } from "./access-lease-error.js";
import { AuthorityOperationError, authorityOperationErrorCodes } from "./server.js";
import {
  assertCryptographicRng,
  mintAccessLeaseId,
  mintAccessToken,
  parseAccessToken,
  verifyAccessToken,
  type AccessTokenClaims,
} from "./access-tokens.js";
import type { AuthorityDataPlaneRoute, AuthorityRouteResolver } from "./data-plane-router.js";

const DEFAULT_LEASE_TTL_MS = 5 * 60 * 1000;
const MAX_LEASE_TTL_MS = 24 * 60 * 60 * 1000;
// Terminal lease projections retained in memory (for exact late lookup
// answers). The durable truth (rows + receipts) lives in the control store
// and is never pruned.
const MAX_TERMINAL_RECORDS = 4096;
// Conservative slack subtracted from every per-lease authorization deadline:
// authorization dies at least this long BEFORE the database expiry it was
// computed from. Must stay below the 1s minimum grant so a fresh lease is
// never born unauthorized.
const DEFAULT_DEADLINE_GUARD_MS = 250;
// After an ambiguous terminal-boundary recheck (store error/timeout), the
// next recheck attempt waits at least this long. Ambiguity NEVER extends
// authorization — the lease stays unauthorized throughout.
const TERMINAL_RECHECK_BACKOFF_MS = 5_000;
// Advisory client backoff for the typed 429 per-tenant lease-budget refusal:
// matches the registry's capacity Retry-After — long enough to stop
// hammering, short enough that a freed lease (release/expiry) is picked up
// promptly.
const TENANT_LEASE_BUDGET_RETRY_AFTER_SECONDS = 15;

// Structured ref key (length-delimited JSON array — no delimiter collisions).
export function accessLeaseRefKey(ref: {
  teamId?: string;
  volumeId: string;
  branch: string;
}): string {
  return JSON.stringify([ref.teamId ?? "", ref.volumeId, ref.branch]);
}

export interface ProductionAccessLeaseCreateArgs {
  operationId: string;
  teamId?: string;
  volumeId: string;
  branch: string;
  consumerId: string;
  // The exact authority binding a lease is fenced to at creation: the live
  // instance AND its runtime sequence + random runtime id, so a token minted
  // against runtime N can never authenticate against the restarted runtime
  // N+1. The registry resolves these under the per-branch authority lock.
  authorityInstanceId: string;
  authorityRuntimeGeneration?: string;
  authorityRuntimeId?: string;
  ttlMs?: number;
}

export interface ProductionAccessLeaseRenewArgs {
  operationId: string;
  accessLeaseId: string;
  accessToken: string;
  // The controlSeq observed before this operation. The caller persists it
  // with operationId and repeats both after an ambiguous/lost response.
  expectedControlSeq: AccessLeaseControlSeq;
  ttlMs?: number;
  rotateToken?: boolean;
}

export interface ProductionAccessLeaseReleaseArgs {
  operationId: string;
  accessLeaseId: string;
  accessToken: string;
}

// The epoch-local synchronous router projection of one lease. This is NEVER
// durable truth: every mutation happens in ONE control-store transaction
// first, and the projection is updated from the returned facts. It exists so
// the data-plane handshake (synchronous by contract) can resolve tokens
// without a database round trip.
interface LeaseProjection {
  facts: AccessLeaseFacts;
  teamId?: string;
  // Mint-time claims of the current token generation (HMAC recomputation is
  // the validation — no token material is stored) and of the immediately
  // previous generation.
  currentTokenClaims: AccessTokenClaims;
  previousTokenClaims?: AccessTokenClaims;
  // The exact rotation operation that minted currentTokenClaims. A previous-
  // generation token may ONLY authenticate a replay of THIS operation id
  // (lost rotation response), never any fresh mutation.
  rotationOperationId?: string;
  // The CONSERVATIVE local-monotonic authorization deadline:
  //   anchorLocalMs(captured BEFORE the store call) + (expiresAt − dbTimeMs) − guard
  // of the newest DB-CONFIRMED fact. Pure differences of one store response's
  // own database times, anchored at a local instant that provably precedes
  // the database read — a delayed response or a host wall-clock step can only
  // SHRINK the authorized window, never stretch it. Only confirmed newer
  // control facts (or a direct live-row read) advance it; ambiguity and
  // errors never do. Tunnel/read authorization and expiry consume THIS, never
  // a mutable clock offset.
  deadlineLocalMs: number;
  // End events (tunnel close, zero-active) fire exactly once per lease end;
  // a terminal-boundary revival (DB recheck proving the row still active)
  // re-arms them.
  endEventsFired: boolean;
  // Terminal-boundary recheck state: one in flight per lease, bounded backoff
  // after ambiguity.
  recheckInFlight?: boolean;
  nextRecheckLocalMs?: number;
}

export interface ProductionAccessLeaseServiceOptions {
  defaultTtlMs?: number;
  maxTtlMs?: number;
  // Local MONOTONIC clock (performance.now by default — never Date.now).
  // Authorization deadlines live entirely on this clock; wall time is
  // metadata only.
  localNow?: () => number;
  // Conservative slack subtracted from every authorization deadline. Must be
  // below the 1s minimum grant.
  deadlineGuardMs?: number;
  // Per-tenant fairness cap on concurrently ACTIVE leases
  // (PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT). Undefined = off. Over-budget
  // creates refuse typed TENANT_LEASE_LIMIT (429 + Retry-After); terminal
  // leases (released/expired/revoked) never count against the budget.
  maxLeasesPerTenant?: number;
}

export interface AccessLeaseSweepArgs {
  // Stable for one logical sweep cycle and every retry/continuation of that
  // cycle. A later cadence tick uses a fresh id so newly due rows are seen.
  sweepId: string;
  afterLeaseId?: string;
  limit?: number;
  maxPages?: number;
}

export interface AccessLeaseSweepSummary {
  endedLeaseIds: string[];
  pages: number;
  nextCursor?: string;
  hasMore: boolean;
  dbTimeMs: number;
}

/**
 * ProductionAccessLeaseService owns the canonical external access leases in
 * PRODUCTION mode. Every create/renew/release/revoke/revoke-owner/
 * revoke-authority is ONE control-store transaction (receipt claim/replay +
 * live manager check + row lock/CAS + exact persisted response facts); the
 * in-memory map is only an epoch-local synchronous router projection updated
 * from those durable facts.
 *
 * Tokens are deterministic HMACs over the recorded mint claims under a key
 * derived from the REQUIRED stable root secret + manager epoch + token
 * generation: byte-identical replay with no plaintext storage, dead on epoch
 * or runtime change.
 */
export class ProductionAccessLeaseService {
  private readonly store: ManagerControlStore;
  private readonly identity: ManagerIdentity;
  private readonly rootSecret: Buffer;
  private readonly defaultTtlMs: number;
  private readonly maxTtlMs: number;
  private readonly localNow: () => number;

  private superseded = false;
  private readonly deadlineGuardMs: number;
  // dbTimeMs - localNow() learned from store responses. METADATA ONLY: it
  // stamps wall-clock endedAtMs on locally fenced projections and converts a
  // caller-supplied absolute wall expiry into a TTL. It NEVER authorizes —
  // authorization uses each lease's own deadlineLocalMs.
  private wallClockOffsetMs = 0;

  private records = new Map<string, LeaseProjection>();
  private routeResolver: AuthorityRouteResolver = () => null;

  private readonly maxLeasesPerTenant: number | undefined;
  // Per-tenant live-lease index for the fairness budget: every lease id this
  // process has projected as active, keyed by tenant. Membership self-heals
  // at count time (terminal or pruned records drop out), so the count stays
  // O(one tenant's leases) — never a scan of every projection.
  private readonly activeLeaseIdsByTenant = new Map<string, Set<string>>();
  // Creates inside their store round-trip, reserved synchronously so two
  // concurrent creates for one tenant cannot both pass the budget check.
  private readonly pendingCreatesByTenant = new Map<string, number>();

  // Monotonic process-local observability totals (rendered by /metrics).
  private createsTotal = 0;
  private renewsTotal = 0;
  private tenantLeaseLimitRefusalsTotal = 0;

  private readonly endListeners = new Set<(event: { accessLeaseId: string }) => void>();
  private readonly rotationListeners = new Set<
    (accessLeaseId: string, tokenGeneration: string) => void
  >();
  private readonly activityListeners = new Set<(refKey: string) => void>();
  private readonly zeroActiveListeners = new Set<(refKey: string) => void>();
  private readonly supersededListeners = new Set<() => void>();
  // Monotonic per-ref activity versions: idle eviction snapshots the version,
  // and any create/renew during its awaits advances it, losing the eviction.
  private readonly activityVersions = new Map<string, number>();

  // Reschedulable earliest-expiry timer: a QUIET established tunnel closes at
  // its lease's database-time expiry without any traffic; every create/renew
  // reschedules.
  private expiryTimer: NodeJS.Timeout | null = null;
  private expiryTimerAt: number | null = null;

  constructor(
    store: ManagerControlStore,
    identity: ManagerIdentity,
    claim: { dbTimeMs: number },
    rootSecret: Buffer,
    options: ProductionAccessLeaseServiceOptions = {}
  ) {
    assertCryptographicRng();
    if (rootSecret.byteLength < 32) {
      throw new Error("Access token root secret must be at least 32 bytes.");
    }
    this.store = store;
    this.identity = identity;
    this.rootSecret = rootSecret;
    this.defaultTtlMs = options.defaultTtlMs ?? DEFAULT_LEASE_TTL_MS;
    this.maxTtlMs = options.maxTtlMs ?? MAX_LEASE_TTL_MS;
    // TRUE MONOTONIC default: authorization deadlines and expiry timers only
    // ever compare localNow against its own earlier readings, so a stepped
    // host wall clock (forward or backward) has no effect.
    this.localNow = options.localNow ?? (() => performance.now());
    this.deadlineGuardMs = options.deadlineGuardMs ?? DEFAULT_DEADLINE_GUARD_MS;
    if (this.deadlineGuardMs < 0 || this.deadlineGuardMs >= 1_000) {
      throw new Error("deadlineGuardMs must be within [0, 1000) — below the minimum grant.");
    }
    this.maxLeasesPerTenant = options.maxLeasesPerTenant;
    this.observeDbTime(claim.dbTimeMs);
  }

  healthy(): boolean {
    return !this.superseded;
  }

  epoch(): string {
    return this.identity.managerEpoch;
  }

  close(): void {
    if (this.expiryTimer) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
      this.expiryTimerAt = null;
    }
  }

  // supersede ends the local projection of every lease (reason
  // manager-epoch-superseded) and refuses all further mutations. The durable
  // rows settle server-side: every pfm read/mutation under the new epoch
  // reports them revoked. Called by the registry when the singleton claim is
  // lost — old tokens are already dead (the epoch is inside the token key
  // derivation AND validation).
  supersede(): void {
    if (this.superseded) {
      return;
    }
    this.superseded = true;
    this.close();
    for (const record of this.records.values()) {
      if (record.facts.state === "active") {
        this.endProjectionLocked(record, "manager-epoch-superseded");
      }
    }
    // A lease-path PF001 is the same durable proof the renewal path gets. The
    // registry fences the WHOLE manager on it rather than leaving children
    // serving until the claim deadline runs out.
    for (const listener of [...this.supersededListeners]) {
      listener();
    }
  }

  // Fires once, synchronously, the first time this service is superseded —
  // whether the registry drove it or a fenced store write discovered it.
  onSuperseded(listener: () => void): void {
    this.supersededListeners.add(listener);
  }

  onLeaseEnded(listener: (event: { accessLeaseId: string }) => void): void {
    this.endListeners.add(listener);
  }

  onLeaseRotated(listener: (accessLeaseId: string, tokenGeneration: string) => void): void {
    this.rotationListeners.add(listener);
  }

  // Fires synchronously inside create/renew AFTER the durable transition,
  // before the response returns: the registry cancels pending idle eviction
  // here, atomically with the lease mutation.
  onLeaseActivity(listener: (refKey: string) => void): void {
    this.activityListeners.add(listener);
  }

  onZeroActive(listener: (refKey: string) => void): void {
    this.zeroActiveListeners.add(listener);
  }

  // Every ref key (teamId/volumeId/branch triple) that currently has at least
  // one authorized live lease projection. Bounded by the projection map size.
  activeRefKeys(): string[] {
    const keys = new Set<string>();
    for (const record of this.records.values()) {
      if (this.leaseAuthorized(record)) {
        keys.add(this.projectionRefKey(record));
      }
    }
    return [...keys];
  }

  activeLeaseCount(refKey: string): number {
    let count = 0;
    for (const record of this.records.values()) {
      if (this.leaseAuthorized(record) && this.projectionRefKey(record) === refKey) {
        count += 1;
      }
    }
    return count;
  }

  activityVersion(refKey: string): number {
    return this.activityVersions.get(refKey) ?? 0;
  }

  // Bounded scalar facts for the manager's /metrics endpoint: the live
  // (non-terminal) lease projection count plus the monotonic operation
  // totals. Read-only, render-time only; no identifiers leave this surface.
  observabilitySnapshot(): {
    activeLeases: number;
    createsTotal: number;
    renewsTotal: number;
    tenantLeaseLimitRefusalsTotal: number;
  } {
    let active = 0;
    for (const record of this.records.values()) {
      if (record.facts.state === "active") {
        active += 1;
      }
    }
    return {
      activeLeases: active,
      createsTotal: this.createsTotal,
      renewsTotal: this.renewsTotal,
      tenantLeaseLimitRefusalsTotal: this.tenantLeaseLimitRefusalsTotal,
    };
  }

  /**
   * Durably converges a bounded number of expired/current-epoch and
   * superseded/old-epoch lease rows. Each page has a deterministic operation
   * id derived from (manager epoch, sweepId, cursor), so an ambiguous failure
   * can replay from the beginning or resume at nextCursor without executing a
   * page twice. A fresh periodic cycle MUST use a fresh sweepId.
   */
  async sweepDue(args: AccessLeaseSweepArgs): Promise<AccessLeaseSweepSummary> {
    this.requireCurrentEpoch();
    if (
      typeof args.sweepId !== "string" ||
      args.sweepId.length === 0 ||
      Buffer.byteLength(args.sweepId, "utf8") > 256
    ) {
      throw new AccessLeaseError(
        400,
        accessLeaseErrorCodes.invalidRequest,
        "sweepId must be a non-empty retry-stable identifier of at most 256 UTF-8 bytes."
      );
    }
    const limit = args.limit ?? 256;
    const maxPages = args.maxPages ?? 32;
    if (!Number.isInteger(limit) || limit < 1 || limit > 512) {
      throw new AccessLeaseError(
        400,
        accessLeaseErrorCodes.invalidRequest,
        "access lease sweep limit must be an integer from 1 through 512."
      );
    }
    if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 1024) {
      throw new AccessLeaseError(
        400,
        accessLeaseErrorCodes.invalidRequest,
        "access lease sweep maxPages must be an integer from 1 through 1024."
      );
    }

    let cursor = args.afterLeaseId;
    let hasMore = false;
    let dbTimeMs = 0;
    let pages = 0;
    const endedLeaseIds: string[] = [];
    const seenEnded = new Set<string>();
    for (; pages < maxPages; pages += 1) {
      const result = await this.wrapStore(() =>
        this.store.sweepAccessLeases({
          identity: this.identity,
          operationId: this.sweepPageOperationId(args.sweepId, cursor),
          ...(cursor !== undefined ? { afterLeaseId: cursor } : {}),
          limit,
        })
      );
      this.observeDbTime(result.dbTimeMs);
      dbTimeMs = result.dbTimeMs;
      for (const leaseId of result.endedLeaseIds) {
        if (!seenEnded.has(leaseId)) {
          seenEnded.add(leaseId);
          endedLeaseIds.push(leaseId);
        }
        this.settleSweptProjection(leaseId, result.completedAtDbMs);
      }
      hasMore = result.hasMore;
      if (!hasMore) {
        cursor = undefined;
        pages += 1;
        break;
      }
      if (!result.nextCursor || result.nextCursor === cursor) {
        throw new AccessLeaseError(
          503,
          accessLeaseErrorCodes.storeUnavailable,
          "The durable access-lease sweep did not advance its cursor."
        );
      }
      cursor = result.nextCursor;
    }
    this.pruneTerminalRecords();
    this.armExpiryTimer();
    return {
      endedLeaseIds,
      pages,
      ...(hasMore && cursor !== undefined ? { nextCursor: cursor } : {}),
      hasMore,
      dbTimeMs,
    };
  }

  setAuthorityRouteResolver(routeResolver: AuthorityRouteResolver): void {
    this.routeResolver = routeResolver;
  }

  // ------------------------------------------------------------------
  // Canonical operations — each is ONE control-store transaction.
  // ------------------------------------------------------------------

  async create(
    args: ProductionAccessLeaseCreateArgs
  ): Promise<{ lease: AccessLease; accessToken: string }> {
    this.requireCurrentEpoch();
    const tenantKey = this.tenantKey(args);
    // The registry resolves the fenced runtime binding under its per-branch
    // authority lock; a create reaching this service without one is a wiring
    // bug, never a caller input problem.
    const runtimeSeq = args.authorityRuntimeGeneration;
    const runtimeId = args.authorityRuntimeId;
    if (!runtimeSeq || !runtimeId) {
      throw new AccessLeaseError(
        500,
        accessLeaseErrorCodes.internal,
        "Production lease creation requires the fenced authority runtime binding (sequence + runtime id)."
      );
    }
    this.enforceTenantLeaseBudget(tenantKey, args.teamId);
    // The reservation is synchronous BEFORE the store round-trip so two
    // concurrent creates for one tenant cannot both pass the budget check.
    this.pendingCreatesByTenant.set(
      tenantKey,
      (this.pendingCreatesByTenant.get(tenantKey) ?? 0) + 1
    );
    try {
      // The authorization-deadline anchor is captured BEFORE the store call:
      // the database granted the TTL at some instant after this, so
      // anchor + (expiresAt − dbTimeMs) can only UNDERSTATE the true local
      // expiry instant, no matter how slowly the response arrives.
      const anchorLocalMs = this.localNow();
      // A fresh candidate id is minted per attempt; a REPLAY returns the
      // recorded response with the ORIGINAL lease id and this candidate is
      // discarded (the receipt claim runs first inside the transaction).
      const result = await this.wrapStore(() =>
        this.store.accessCreate({
          identity: this.identity,
          operationId: args.operationId,
          leaseId: mintAccessLeaseId(),
          scope: { tenantKey, volumeId: args.volumeId, branch: args.branch },
          consumerId: args.consumerId,
          authorityInstanceId: args.authorityInstanceId,
          authorityRuntimeSeq: runtimeSeq,
          authorityRuntimeId: runtimeId,
          ttlMs: this.grantTtl(args.ttlMs),
        })
      );
      if (!result.replayed) {
        this.createsTotal += 1;
      }
      const record = this.applyOperationResult(result, args.teamId, anchorLocalMs);
      this.emitActivity(this.projectionRefKey(record));
      this.armExpiryTimer();
      return {
        lease: this.publicLeaseFromFacts(result, args.teamId),
        accessToken: mintAccessToken(this.rootSecret, this.mintClaims(result, args.teamId)),
      };
    } finally {
      const pending = this.pendingCreatesByTenant.get(tenantKey) ?? 0;
      if (pending <= 1) {
        this.pendingCreatesByTenant.delete(tenantKey);
      } else {
        this.pendingCreatesByTenant.set(tenantKey, pending - 1);
      }
    }
  }

  // enforceTenantLeaseBudget refuses a create that would exceed the tenant's
  // concurrently-active lease budget, BEFORE any durable transition. The
  // count is this fenced singleton manager's epoch-local projection of live
  // leases (every create/renew/release/revoke flows through it), plus the
  // creates currently inside their store round-trip. Honest boundary: a
  // create whose response was lost is not counted until its retry replays,
  // and a retry REPLAY of an already-counted lease can refuse here while the
  // tenant sits exactly at its cap — releasing any lease unwedges it.
  private enforceTenantLeaseBudget(tenantKey: string, teamId: string | undefined): void {
    const cap = this.maxLeasesPerTenant;
    if (cap === undefined) {
      return;
    }
    if (this.liveLeaseCountForTenant(tenantKey) >= cap) {
      this.tenantLeaseLimitRefusalsTotal += 1;
      throw new AuthorityOperationError(
        429,
        authorityOperationErrorCodes.tenantLeaseLimit,
        `Tenant ${teamId ?? tenantKey} is at its active-access-lease budget (${cap}); refusing to create a new lease. Other tenants are unaffected — release a lease or let one expire to free the budget, or raise PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT.`,
        { retryAfterSeconds: TENANT_LEASE_BUDGET_RETRY_AFTER_SECONDS }
      );
    }
  }

  // liveLeaseCountForTenant is O(one tenant's leases): it walks the tenant's
  // live-id set, dropping ids whose projection went terminal (release,
  // expiry settle, revoke, retire, supersession) or was pruned — terminal
  // leases free budget the moment their projection settles.
  private liveLeaseCountForTenant(tenantKey: string): number {
    const ids = this.activeLeaseIdsByTenant.get(tenantKey);
    let live = 0;
    if (ids) {
      for (const leaseId of [...ids]) {
        const record = this.records.get(leaseId);
        if (record && record.facts.state === "active") {
          live += 1;
        } else {
          ids.delete(leaseId);
        }
      }
      if (ids.size === 0) {
        this.activeLeaseIdsByTenant.delete(tenantKey);
      }
    }
    return live + (this.pendingCreatesByTenant.get(tenantKey) ?? 0);
  }

  /**
   * Authenticates one exact CURRENT token against fresh database-time lease
   * truth. This is intentionally not an operation: no receipt is created, no
   * projection is folded, and no control sequence or expiry is changed.
   */
  async inspect(args: {
    accessLeaseId: string;
    accessToken: string;
  }): Promise<AccessLeaseInspectResponse> {
    this.requireCurrentEpoch();
    const record = this.records.get(args.accessLeaseId);
    if (!record) {
      throw new AccessLeaseError(
        404,
        accessLeaseErrorCodes.notFound,
        `Unknown access lease ${args.accessLeaseId} (production lease state is scoped to the current manager epoch).`
      );
    }
    // Match renew's information-ordering: a guessed token learns no state.
    if (this.authenticate(record, args.accessToken) !== "current") {
      throw this.unauthorized(record.facts.leaseId);
    }
    const row = await this.wrapStore(() =>
      this.store.accessGet({
        identity: this.identity,
        tenantKey: record.facts.tenantKey,
        leaseId: args.accessLeaseId,
      })
    );
    if (row === null) {
      throw new AccessLeaseError(
        404,
        accessLeaseErrorCodes.notFound,
        `Unknown access lease ${args.accessLeaseId}.`
      );
    }
    const { dbTimeMs, ...facts } = row;
    this.assertSameLeaseIdentity(record.facts, facts);
    // A concurrent rotation may commit between the first authentication and
    // this read. Never adopt a token from the superseded generation.
    if (
      facts.tokenGeneration !== record.facts.tokenGeneration ||
      !verifyAccessToken(this.rootSecret, record.currentTokenClaims, args.accessToken)
    ) {
      throw this.unauthorized(record.facts.leaseId);
    }
    if (facts.state !== "active" || facts.expiresAt <= dbTimeMs) {
      const terminalFacts =
        facts.state === "active"
          ? {
              ...facts,
              state: "expired" as const,
              endReason: "expired" as const,
              endedAtMs: facts.expiresAt,
            }
          : facts;
      throw this.terminalStateError({ ...record, facts: terminalFacts });
    }
    return {
      lease: this.publicLeaseFromFacts(facts, record.teamId),
      serverTimeMs: dbTimeMs,
    };
  }

  async renew(
    args: ProductionAccessLeaseRenewArgs
  ): Promise<{ lease: AccessLease; accessToken?: string }> {
    this.requireCurrentEpoch();
    const record = this.requireRecord(args.accessLeaseId);
    const auth = this.authenticate(record, args.accessToken);
    if (auth === "previous" && record.rotationOperationId !== args.operationId) {
      // A previous-generation token may only authenticate the exact recorded
      // rotation's replay — never a fresh mutation (or anyone else's op).
      throw this.unauthorized(record.facts.leaseId);
    }
    const rotate = args.rotateToken === true;
    // Pre-call monotonic anchor: only a CONFIRMED renewal moves the
    // authorization deadline forward, and only from this instant.
    const anchorLocalMs = this.localNow();
    // ONE transaction: receipt lookup/replay first, then live-manager check,
    // row lock and CAS on the caller's retry-stable original controlSeq. The
    // service must never re-derive this from its newer projection: after the
    // bounded receipt is evicted, the original value is what yields the
    // receipt-evicted refusal instead of silently executing the old
    // operation again.
    const result = await this.wrapStore(() =>
      this.store.accessRenew({
        identity: this.identity,
        operationId: args.operationId,
        tenantKey: record.facts.tenantKey,
        leaseId: args.accessLeaseId,
        expectedControlSeq: args.expectedControlSeq,
        ttlMs: this.grantTtl(args.ttlMs),
        rotate,
      })
    );
    if (auth === "previous" && !result.replayed) {
      // Unreachable by construction (the rotation op id is receipted), kept
      // as a hard stop: a fresh mutation must never answer to an old token.
      throw this.unauthorized(record.facts.leaseId);
    }
    if (!result.replayed) {
      this.renewsTotal += 1;
    }
    const updated = this.applyOperationResult(result, record.teamId, anchorLocalMs);
    if (result.mintedToken && !result.replayed) {
      this.emitRotation(updated);
    }
    this.emitActivity(this.projectionRefKey(updated));
    this.armExpiryTimer();
    return {
      lease: this.publicLeaseFromFacts(result, record.teamId),
      ...(result.mintedToken
        ? {
            accessToken: mintAccessToken(this.rootSecret, this.mintClaims(result, record.teamId)),
          }
        : {}),
    };
  }

  async release(
    args: ProductionAccessLeaseReleaseArgs
  ): Promise<{ lease: AccessLease; receipt: AccessLeaseReceipt }> {
    this.requireCurrentEpoch();
    const record = this.requireRecord(args.accessLeaseId);
    const auth = this.authenticate(record, args.accessToken);
    if (auth === "previous") {
      // Release is always a fresh mutation from the token's point of view:
      // a rotated-past token never authorizes it.
      throw this.unauthorized(record.facts.leaseId);
    }
    const result = await this.wrapStore(() =>
      this.store.accessRelease({
        identity: this.identity,
        operationId: args.operationId,
        tenantKey: record.facts.tenantKey,
        leaseId: args.accessLeaseId,
        expectedControlSeq: record.facts.state === "active" ? record.facts.controlSeq : null,
      })
    );
    this.applyOperationResult(result, record.teamId);
    return {
      lease: this.publicLeaseFromFacts(result, record.teamId),
      receipt: this.publicReceipt(result),
    };
  }

  async revoke(accessLeaseId: string): Promise<AccessLease> {
    this.requireCurrentEpoch();
    const record = this.requireRecord(accessLeaseId);
    const operationId = `pfrevoke-${accessLeaseId}-c${record.facts.controlSeq}`;
    const result = await this.wrapStore(() =>
      this.store.accessRevoke({
        identity: this.identity,
        operationId,
        tenantKey: record.facts.tenantKey,
        leaseId: accessLeaseId,
        reason: "revoked",
      })
    );
    return this.publicLease(this.applyOperationResult(result, record.teamId));
  }

  async revokeOwner(args: {
    teamId?: string;
    consumerId: string;
    volumeId?: string;
    branch?: string;
  }): Promise<string[]> {
    this.requireCurrentEpoch();
    // Owner revocation spans volumes only within ONE tenant namespace; a
    // missing teamId cannot name a tenant and refuses (production state is
    // keyed exclusively by t:<teamId>).
    if (args.teamId === undefined) {
      throw new AccessLeaseError(
        400,
        accessLeaseErrorCodes.invalidRequest,
        "revoke-owner requires teamId to scope the tenant in production mode."
      );
    }
    const tenantKey = managedTenantKey({ teamId: args.teamId, volumeId: args.volumeId ?? "" });
    const operationId = `pfrevoke-owner-${mintAccessLeaseId()}`;
    const result = await this.wrapStore(() =>
      this.store.accessEndBatch({
        identity: this.identity,
        operationId,
        filter: {
          tenantKey,
          consumerId: args.consumerId,
          ...(args.volumeId !== undefined ? { volumeId: args.volumeId } : {}),
          ...(args.branch !== undefined ? { branch: args.branch } : {}),
        },
        reason: "owner-revoked",
      })
    );
    for (const leaseId of result.endedLeaseIds) {
      const record = this.records.get(leaseId);
      if (record && record.facts.state === "active") {
        record.facts = {
          ...record.facts,
          state: "revoked",
          endReason: "owner-revoked",
          endedAtMs: result.completedAtDbMs,
        };
        this.endProjectionLocked(record, "owner-revoked");
      }
    }
    return result.endedLeaseIds;
  }

  // revokeAuthority ends every lease bound to the exact authority instance
  // (retire/evict teardown fencing). The LOCAL fence (tunnel close, route
  // removal) is SYNCHRONOUS and unconditional — fencing the data plane must
  // never be blocked, even after supersession. The returned promise is the
  // DURABLE batch: it resolves only when the retire committed (or the epoch
  // is superseded, where the rows settle server-side) and REJECTS on a store
  // outage so callers that must order runtime-end AFTER the access fence can
  // retry — the deterministic `pfretire-<instanceId>` operation id makes
  // every retry an exact receipt replay, idempotent and crash-safe.
  revokeAuthority(authorityInstanceId: string): Promise<void> {
    for (const record of this.records.values()) {
      if (
        record.facts.state !== "active" ||
        record.facts.authorityInstanceId !== authorityInstanceId
      ) {
        continue;
      }
      this.endProjectionLocked(record, "authority-retired");
    }
    if (this.superseded) {
      return Promise.resolve();
    }
    return this.store
      .accessEndBatch({
        identity: this.identity,
        operationId: `pfretire-${authorityInstanceId}`,
        filter: { authorityInstanceId },
        reason: "authority-retired",
      })
      .then(() => undefined)
      .catch((error: unknown) => {
        if (error instanceof ManagerEpochSupersededError) {
          this.supersede();
          return;
        }
        // Store outage: the local fence already closed the data plane, but
        // the durable retire did NOT commit — surface it so the caller can
        // retry and can refuse to end the runtime row before it lands.
        throw error;
      });
  }

  async lookup(accessLeaseId: string): Promise<AccessLease | null> {
    const record = this.records.get(accessLeaseId);
    if (record) {
      this.enforceDeadline(record);
      return this.publicLease(record);
    }
    return null;
  }

  // ------------------------------------------------------------------
  // Data-plane resolution (router handshake) — synchronous by contract.
  // ------------------------------------------------------------------

  resolveSessionToken(token: string): AuthorityDataPlaneRoute | null {
    if (this.superseded) {
      return null;
    }
    const parsed = parseAccessToken(token);
    if (!parsed) {
      return null;
    }
    const record = this.records.get(parsed.accessLeaseId);
    if (!record) {
      return null;
    }
    this.enforceDeadline(record);
    // Tunnel authorization consumes the conservative local-monotonic
    // deadline: past it, NOTHING resolves — even while the terminal-boundary
    // DB recheck is still settling the durable truth.
    if (!this.leaseAuthorized(record)) {
      return null;
    }
    if (parsed.tokenGeneration !== record.facts.tokenGeneration) {
      return null;
    }
    if (!verifyAccessToken(this.rootSecret, record.currentTokenClaims, token)) {
      return null;
    }
    const route = this.routeResolver(record.facts.authorityInstanceId);
    if (!route) {
      return null;
    }
    return {
      authorityInstanceId: record.facts.authorityInstanceId,
      backendAddresses: route.backendAddresses,
      backendAuthToken: route.backendAuthToken,
      accessLeaseId: record.facts.leaseId,
      tokenGeneration: record.facts.tokenGeneration,
      sessionExpiresAt: record.facts.expiresAt,
    };
  }

  // ------------------------------------------------------------------
  // Internals.
  // ------------------------------------------------------------------

  private tenantKey(ref: { teamId?: string; volumeId: string }): string {
    try {
      return managedTenantKey(ref);
    } catch (error) {
      throw new AccessLeaseError(
        400,
        accessLeaseErrorCodes.invalidRequest,
        error instanceof Error ? error.message : String(error)
      );
    }
  }

  private projectionRefKey(record: LeaseProjection): string {
    return accessLeaseRefKey({
      ...(record.teamId !== undefined ? { teamId: record.teamId } : {}),
      volumeId: record.facts.volumeId,
      branch: record.facts.branch,
    });
  }

  // wallNowMs interpolates the database wall clock for METADATA stamps
  // (endedAtMs on locally fenced projections). Never consulted for
  // authorization or expiry.
  private wallNowMs(): number {
    return this.localNow() + this.wallClockOffsetMs;
  }

  private observeDbTime(dbTimeMs: number): void {
    this.wallClockOffsetMs = dbTimeMs - this.localNow();
  }

  // leaseAuthorized is THE data-plane/read authorization predicate: durable
  // facts say active AND the lease's own conservative local-monotonic
  // deadline has not passed.
  private leaseAuthorized(record: LeaseProjection): boolean {
    return record.facts.state === "active" && this.localNow() < record.deadlineLocalMs;
  }

  // advanceDeadline installs the conservative deadline proven by one
  // DB-confirmed fact. It only ever moves FORWARD (a fresh proof of a longer
  // window); the conservative property holds because every candidate is
  // anchored before its own store call.
  private advanceDeadline(record: LeaseProjection, anchorLocalMs: number, dbTimeMs: number): void {
    const candidate = anchorLocalMs + (record.facts.expiresAt - dbTimeMs) - this.deadlineGuardMs;
    if (candidate > record.deadlineLocalMs) {
      record.deadlineLocalMs = candidate;
      if (this.leaseAuthorized(record)) {
        record.endEventsFired = false;
        delete record.nextRecheckLocalMs;
      }
    }
  }

  // mintClaims derives the deterministic mint-time token claims from the
  // exact durable operation facts — never from mutable local state.
  private mintClaims(result: AccessOperationResult, teamId: string | undefined): AccessTokenClaims {
    return this.mintClaimsFromFacts(result, teamId);
  }

  private mintClaimsFromFacts(
    facts: AccessLeaseFacts,
    teamId: string | undefined
  ): AccessTokenClaims {
    return {
      protocolVersion: accessLeaseProtocolVersion,
      managerEpoch: facts.managerEpoch,
      accessLeaseId: facts.leaseId,
      controlSeq: facts.controlSeq,
      tokenGeneration: facts.tokenGeneration,
      teamId: teamId ?? "",
      volumeId: facts.volumeId,
      branch: facts.branch,
      authorityInstanceId: facts.authorityInstanceId,
      // The REAL runtime sequence: a token minted against runtime N never
      // authenticates against the restarted runtime N+1.
      authorityRuntimeGeneration: facts.authorityRuntimeSeq,
      consumerId: facts.consumerId,
      expiresAt: facts.expiresAt,
    };
  }

  // applyOperationResult folds one durable operation's exact facts into the
  // projection (creating it if this process has never seen the lease). When
  // the caller anchored a local monotonic instant BEFORE its store call, a
  // CONFIRMED newer control fact advances the lease's authorization deadline
  // from that anchor; a replayed receipt (same controlSeq) confirms nothing
  // new and never extends.
  private applyOperationResult(
    result: AccessOperationResult,
    teamId: string | undefined,
    anchorLocalMs?: number
  ): LeaseProjection {
    this.observeDbTime(result.dbTimeMs);
    let record = this.records.get(result.leaseId);
    const facts = result.currentFacts;
    const previousControlSeq = record?.facts.controlSeq;
    if (!record) {
      record = {
        facts,
        ...(teamId !== undefined ? { teamId } : {}),
        currentTokenClaims: this.mintClaimsFromFacts(facts, teamId),
        deadlineLocalMs: Number.NEGATIVE_INFINITY,
        endEventsFired: false,
      };
      this.records.set(result.leaseId, record);
      if (anchorLocalMs !== undefined && facts.state === "active") {
        // First projection of this lease in this process: the durable
        // receipt/row IS the confirmation (a replayed create after a lost
        // response still proves the row against a fresh dbTimeMs).
        this.advanceDeadline(record, anchorLocalMs, result.dbTimeMs);
      }
    } else {
      const applied = this.applyProjectionFacts(record, facts);
      if (!applied) {
        return record;
      }
      if (
        anchorLocalMs !== undefined &&
        facts.state === "active" &&
        previousControlSeq !== undefined &&
        compareDecimalStrings(facts.controlSeq, previousControlSeq) > 0
      ) {
        // Only a CONFIRMED NEWER control fact moves authorization forward.
        this.advanceDeadline(record, anchorLocalMs, result.dbTimeMs);
      }
      if (!result.replayed && result.mintedToken && facts.tokenGeneration === result.tokenGeneration) {
        record.rotationOperationId = result.operationId;
      }
    }
    if (record.facts.state === "active") {
      // Register in the tenant's live-lease index (idempotent). Terminal
      // transitions are dropped lazily at count time — no decrement
      // discipline to get wrong across the many settle paths.
      let ids = this.activeLeaseIdsByTenant.get(record.facts.tenantKey);
      if (!ids) {
        ids = new Set();
        this.activeLeaseIdsByTenant.set(record.facts.tenantKey, ids);
      }
      ids.add(record.facts.leaseId);
    } else {
      this.pruneTerminalRecords();
    }
    return record;
  }

  private requireCurrentEpoch(): void {
    if (this.superseded) {
      throw new AccessLeaseError(
        503,
        accessLeaseErrorCodes.epochSuperseded,
        `Manager epoch ${this.identity.managerEpoch} has been superseded; this manager no longer mutates access leases.`
      );
    }
  }

  // requireRecord returns the projection. Production lease state is scoped
  // to the current manager epoch: a lease this process has never projected
  // does not answer (responses are never reconstructed from mutable state).
  private requireRecord(accessLeaseId: string): LeaseProjection {
    const record = this.records.get(accessLeaseId);
    if (record) {
      // A passed deadline does NOT block a durable mutation attempt: the
      // control store is the truth (an early-fired conservative deadline
      // must never brick a still-active row; the transaction itself refuses
      // a genuinely expired one).
      this.enforceDeadline(record);
      return record;
    }
    throw new AccessLeaseError(
      404,
      accessLeaseErrorCodes.notFound,
      `Unknown access lease ${accessLeaseId} (production lease state is scoped to the current manager epoch).`
    );
  }

  private authenticate(record: LeaseProjection, token: string): "current" | "previous" {
    if (verifyAccessToken(this.rootSecret, record.currentTokenClaims, token)) {
      return "current";
    }
    if (
      record.previousTokenClaims &&
      verifyAccessToken(this.rootSecret, record.previousTokenClaims, token)
    ) {
      return "previous";
    }
    throw this.unauthorized(record.facts.leaseId);
  }

  private unauthorized(leaseId: string): AccessLeaseError {
    return new AccessLeaseError(
      401,
      accessLeaseErrorCodes.unauthorized,
      `The presented access token does not authenticate lease ${leaseId}.`
    );
  }

  private grantTtl(ttlMs: number | undefined): number {
    return Math.max(1_000, Math.min(ttlMs ?? this.defaultTtlMs, this.maxTtlMs));
  }

  // enforceDeadline is the TERMINAL BOUNDARY: when a lease's conservative
  // local-monotonic deadline passes, authorization is already dead (every
  // authorization path checks leaseAuthorized). This fires the end events
  // (tunnel close — fail-closed, exactly once) and starts ONE fresh DB
  // recheck that SETTLES the projection from durable facts: a still-active
  // row with runway revives authorization (the conservative deadline fired
  // early); a past-expiry or terminal row settles it. Ambiguity settles
  // nothing, extends nothing, and retries after a bounded backoff.
  private enforceDeadline(record: LeaseProjection): void {
    if (record.facts.state !== "active" || this.leaseAuthorized(record)) {
      return;
    }
    if (!record.endEventsFired) {
      record.endEventsFired = true;
      this.fireEndEvents(record);
    }
    this.recheckAtTerminalBoundary(record);
  }

  private recheckAtTerminalBoundary(record: LeaseProjection): void {
    if (
      this.superseded ||
      record.recheckInFlight ||
      (record.nextRecheckLocalMs !== undefined && this.localNow() < record.nextRecheckLocalMs)
    ) {
      return;
    }
    record.recheckInFlight = true;
    const anchorLocalMs = this.localNow();
    void this.store
      .accessGet({
        identity: this.identity,
        tenantKey: record.facts.tenantKey,
        leaseId: record.facts.leaseId,
      })
      .then((row) => {
        record.recheckInFlight = false;
        if (row === null) {
          // No durable row answered: ambiguous, settles nothing.
          record.nextRecheckLocalMs = this.localNow() + TERMINAL_RECHECK_BACKOFF_MS;
          return;
        }
        this.observeDbTime(row.dbTimeMs);
        const { dbTimeMs, ...facts } = row;
        if (facts.state === "active" && facts.expiresAt <= dbTimeMs) {
          // DB-CONFIRMED expiry: the live row is past its own database
          // expiry (rows settle durably at next touch/sweep). Settle the
          // projection now.
          if (record.facts.state === "active") {
            record.facts = {
              ...record.facts,
              state: "expired",
              endReason: "expired",
              endedAtMs: facts.expiresAt,
            };
            this.pruneTerminalRecords();
          }
          return;
        }
        if (facts.state === "active") {
          // The row is genuinely still active with runway: the conservative
          // deadline fired early (guard, slow response). Fold the confirmed
          // facts and revive authorization from the pre-call anchor.
          this.applyProjectionFacts(record, facts);
          this.advanceDeadline(record, anchorLocalMs, dbTimeMs);
          this.armExpiryTimer();
          return;
        }
        // Durable terminal state: fold it exactly.
        this.applyProjectionFacts(record, facts);
        this.pruneTerminalRecords();
      })
      .catch((error: unknown) => {
        record.recheckInFlight = false;
        record.nextRecheckLocalMs = this.localNow() + TERMINAL_RECHECK_BACKOFF_MS;
        if (error instanceof ManagerEpochSupersededError) {
          this.supersede();
        }
        // Any other ambiguity extends nothing: the lease stays unauthorized
        // and the durable row settles via sweep or the next confirmed touch.
      });
  }

  // endProjectionLocked finalizes the LOCAL projection state and fires the
  // end events (tunnel close) exactly once per lease end. When `reason` is
  // provided the facts are stamped here (endedAtMs is wall metadata); when
  // undefined the facts were already settled from durable results.
  private endProjectionLocked(
    record: LeaseProjection,
    reason: "manager-epoch-superseded" | "owner-revoked" | "authority-retired" | undefined
  ): void {
    if (reason !== undefined && record.facts.state === "active") {
      record.facts = {
        ...record.facts,
        state: "revoked",
        endReason: reason,
        endedAtMs: this.wallNowMs(),
      };
    }
    if (!record.endEventsFired) {
      record.endEventsFired = true;
      this.fireEndEvents(record);
    }
  }

  private fireEndEvents(record: LeaseProjection): void {
    const refKey = this.projectionRefKey(record);
    for (const listener of this.endListeners) {
      listener({ accessLeaseId: record.facts.leaseId });
    }
    if (this.activeLeaseCount(refKey) === 0) {
      for (const listener of this.zeroActiveListeners) {
        listener(refKey);
      }
    }
  }

  private pruneTerminalRecords(): void {
    const terminal = [...this.records.values()].filter((record) => record.facts.state !== "active");
    if (terminal.length <= MAX_TERMINAL_RECORDS) {
      return;
    }
    terminal.sort((a, b) => (a.facts.endedAtMs ?? 0) - (b.facts.endedAtMs ?? 0));
    for (const record of terminal.slice(0, terminal.length - MAX_TERMINAL_RECORDS)) {
      this.records.delete(record.facts.leaseId);
    }
  }

  // armExpiryTimer (re)schedules the single timer at the EARLIEST active
  // authorization deadline (LOCAL MONOTONIC — a wall-clock step neither
  // fires it early nor stalls it) so a quiet tunnel closes on time; a
  // confirmed renew pushes it out, and a lease awaiting its terminal-boundary
  // recheck retries after its backoff.
  private armExpiryTimer(): void {
    if (this.superseded) {
      return;
    }
    let earliest: number | null = null;
    for (const record of this.records.values()) {
      if (record.facts.state !== "active") {
        continue;
      }
      const dueAt = this.leaseAuthorized(record)
        ? record.deadlineLocalMs
        : (record.nextRecheckLocalMs ?? this.localNow() + TERMINAL_RECHECK_BACKOFF_MS);
      earliest = earliest === null ? dueAt : Math.min(earliest, dueAt);
    }
    if (earliest === null) {
      this.close();
      return;
    }
    if (this.expiryTimer && this.expiryTimerAt === earliest) {
      return;
    }
    this.close();
    this.expiryTimerAt = earliest;
    const delayMs = Math.max(0, earliest - this.localNow());
    this.expiryTimer = setTimeout(() => {
      this.expiryTimer = null;
      this.expiryTimerAt = null;
      for (const record of this.records.values()) {
        this.enforceDeadline(record);
      }
      this.armExpiryTimer();
    }, delayMs);
    this.expiryTimer.unref?.();
  }

  private async wrapStore<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (error) {
      if (error instanceof ManagerEpochSupersededError) {
        this.supersede();
        throw new AccessLeaseError(
          503,
          accessLeaseErrorCodes.epochSuperseded,
          `Manager epoch ${this.identity.managerEpoch} has been superseded; reacquire against the new manager.`
        );
      }
      if (error instanceof ControlStoreUnavailableError) {
        throw new AccessLeaseError(
          503,
          accessLeaseErrorCodes.storeUnavailable,
          `The manager control store refused the durable transition; nothing changed: ${error.message}`
        );
      }
      if (error instanceof AccessLeaseNotActiveError) {
        if (error.leaseFacts) {
          this.applyFacts(error.leaseFacts);
        }
        throw new AccessLeaseError(
          409,
          error.leaseFacts?.state === "released"
            ? accessLeaseErrorCodes.released
            : error.leaseFacts?.state === "expired"
              ? accessLeaseErrorCodes.expired
              : accessLeaseErrorCodes.revoked,
          `${error.message}; create a fresh lease.`
        );
      }
      if (error instanceof ControlOperationConflictError) {
        if (error.leaseFacts) {
          this.applyFacts(error.leaseFacts);
        }
        throw new AccessLeaseError(409, accessLeaseErrorCodes.operationConflict, error.message);
      }
      if (error instanceof ControlReceiptEvictedError) {
        throw new AccessLeaseError(
          410,
          accessLeaseErrorCodes.receiptEvicted,
          `${error.message}; reload the lease and retry the intended action with a fresh operation id.`
        );
      }
      if (error instanceof ControlNotFoundError) {
        throw new AccessLeaseError(404, accessLeaseErrorCodes.notFound, error.message);
      }
      if (error instanceof InvalidControlArgumentError) {
        throw new AccessLeaseError(400, accessLeaseErrorCodes.invalidRequest, error.message);
      }
      throw error;
    }
  }

  // applyFacts settles the projection from exact durable facts carried on a
  // structured error (CAS conflict / not-active), keeping the router honest.
  private applyFacts(facts: AccessLeaseFacts): void {
    const record = this.records.get(facts.leaseId);
    if (!record) {
      return;
    }
    if (this.applyProjectionFacts(record, facts) && record.facts.state !== "active") {
      this.pruneTerminalRecords();
    }
  }

  // Concurrent store calls may resolve out of order. Fold only a compatible,
  // forward projection: stale error/currentFacts payloads can inform the
  // caller but can never rewind routing state, token generation, expiry, or a
  // terminal fence.
  private applyProjectionFacts(record: LeaseProjection, facts: AccessLeaseFacts): boolean {
    this.assertSameLeaseIdentity(record.facts, facts);
    const controlOrder = compareDecimalStrings(facts.controlSeq, record.facts.controlSeq);
    if (controlOrder < 0) {
      return false;
    }
    if (record.facts.state !== "active" && facts.state === "active") {
      return false;
    }
    const tokenOrder = compareDecimalStrings(facts.tokenGeneration, record.facts.tokenGeneration);
    if (tokenOrder < 0 || facts.expiresAt < record.facts.expiresAt) {
      throw this.invalidStoreProjection(
        `lease ${facts.leaseId} returned non-monotonic token or expiry facts`
      );
    }
    if (record.facts.state !== "active" && facts.state !== record.facts.state) {
      throw this.invalidStoreProjection(
        `lease ${facts.leaseId} changed terminal state from ${record.facts.state} to ${facts.state}`
      );
    }
    const wasActive = record.facts.state === "active";
    if (tokenOrder > 0) {
      record.previousTokenClaims = record.currentTokenClaims;
      record.currentTokenClaims = this.mintClaimsFromFacts(facts, record.teamId);
      // The exact rotating operation id is known only on its direct response.
      // A projection learned through another receipt stays fail-closed for
      // previous-token recovery until that operation itself is replayed.
      delete record.rotationOperationId;
    }
    record.facts = facts;
    if (wasActive && facts.state !== "active") {
      this.endProjectionLocked(record, undefined);
    }
    return true;
  }

  private assertSameLeaseIdentity(current: AccessLeaseFacts, incoming: AccessLeaseFacts): void {
    const immutable: Array<[string, string | number, string | number]> = [
      ["leaseId", current.leaseId, incoming.leaseId],
      ["tenantKey", current.tenantKey, incoming.tenantKey],
      ["volumeId", current.volumeId, incoming.volumeId],
      ["branch", current.branch, incoming.branch],
      ["consumerId", current.consumerId, incoming.consumerId],
      ["authorityInstanceId", current.authorityInstanceId, incoming.authorityInstanceId],
      ["authorityRuntimeSeq", current.authorityRuntimeSeq, incoming.authorityRuntimeSeq],
      ["authorityRuntimeId", current.authorityRuntimeId, incoming.authorityRuntimeId],
      ["managerEpoch", current.managerEpoch, incoming.managerEpoch],
      ["createdAtMs", current.createdAtMs, incoming.createdAtMs],
    ];
    const changed = immutable.find(([, expected, actual]) => expected !== actual);
    if (changed) {
      throw this.invalidStoreProjection(`lease ${current.leaseId} changed immutable ${changed[0]}`);
    }
  }

  private invalidStoreProjection(message: string): AccessLeaseError {
    return new AccessLeaseError(
      503,
      accessLeaseErrorCodes.storeUnavailable,
      `The manager control store returned an invalid lease projection: ${message}.`
    );
  }

  private emitRotation(record: LeaseProjection): void {
    for (const listener of this.rotationListeners) {
      listener(record.facts.leaseId, record.facts.tokenGeneration);
    }
  }

  private emitActivity(refKey: string): void {
    this.activityVersions.set(refKey, (this.activityVersions.get(refKey) ?? 0) + 1);
    for (const listener of this.activityListeners) {
      listener(refKey);
    }
  }

  private terminalStateError(record: LeaseProjection): AccessLeaseError {
    const code =
      record.facts.state === "released"
        ? accessLeaseErrorCodes.released
        : record.facts.state === "expired"
          ? accessLeaseErrorCodes.expired
          : accessLeaseErrorCodes.revoked;
    return new AccessLeaseError(
      409,
      code,
      `Access lease ${record.facts.leaseId} is ${record.facts.state}${
        record.facts.endReason ? ` (${record.facts.endReason})` : ""
      }; create a fresh lease.`
    );
  }

  private sweepPageOperationId(sweepId: string, afterLeaseId: string | undefined): string {
    return `pfsweep_${sha256Hex(
      JSON.stringify(["access-lease-sweep-v1", this.identity.managerEpoch, sweepId, afterLeaseId ?? ""])
    )}`;
  }

  private settleSweptProjection(leaseId: string, completedAtDbMs: number): void {
    const record = this.records.get(leaseId);
    if (!record || record.facts.state !== "active") {
      return;
    }
    const oldEpoch = record.facts.managerEpoch !== this.identity.managerEpoch;
    record.facts = {
      ...record.facts,
      state: oldEpoch ? "revoked" : "expired",
      endReason: oldEpoch ? "manager-epoch-superseded" : "expired",
      endedAtMs: completedAtDbMs,
    };
    this.endProjectionLocked(record, undefined);
  }

  private publicReceipt(result: AccessOperationResult): AccessLeaseReceipt {
    return {
      operationId: result.operationId,
      kind: result.kind === "revoke" ? "release" : result.kind,
      fingerprint: result.receiptFingerprint,
      accessLeaseId: result.leaseId,
      controlSeq: result.controlSeq,
      tokenGeneration: result.tokenGeneration,
      expiresAt: result.expiresAt,
      completedAtMs: result.completedAtDbMs,
    };
  }

  publicLease(record: LeaseProjection): AccessLease {
    return this.publicLeaseFromFacts(record.facts, record.teamId);
  }

  private publicLeaseFromFacts(facts: AccessLeaseFacts, teamId: string | undefined): AccessLease {
    // The wire lease is the frozen portablefs-v1 shape; the runtime sequence
    // stays internal (it fences tokens and journal claims, not the API).
    return {
      version: accessLeaseProtocolVersion,
      accessLeaseId: facts.leaseId,
      ...(teamId !== undefined && teamId !== "" ? { teamId } : {}),
      volumeId: facts.volumeId,
      branch: facts.branch,
      authorityInstanceId: facts.authorityInstanceId,
      managerEpoch: facts.managerEpoch,
      consumerId: facts.consumerId,
      tokenGeneration: facts.tokenGeneration,
      controlSeq: facts.controlSeq,
      state: facts.state,
      expiresAt: facts.expiresAt,
      createdAtMs: facts.createdAtMs,
      ...(facts.endedAtMs !== undefined ? { endedAtMs: facts.endedAtMs } : {}),
      ...(facts.endReason !== undefined ? { endReason: facts.endReason } : {}),
    };
  }
}
