import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import type { ZodType } from "zod";
import {
  accessLeaseCreateRequestSchema,
  accessLeaseErrorCodes,
  accessLeaseInspectRequestSchema,
  accessLeaseInspectResponseSchema,
  accessLeaseReleaseRequestSchema,
  accessLeaseRenewRequestSchema,
  accessLeaseRevokeOwnerRequestSchema,
  accessLeaseRevokeRequestSchema,
  type AccessLease,
  type AccessLeaseControlSeq,
  type AccessLeaseCreateResponse,
  type AccessLeaseInspectResponse,
  type AccessLeaseReceipt,
  type AccessLeaseReleaseResponse,
  type AccessLeaseRenewResponse,
  type AccessLeaseRevokeOwnerResponse,
  type AccessLeaseRevokeResponse,
  type AuthorityEndpointPayload,
  releaseIdentityErrorCode,
  type ReleaseIdentity,
} from "@portablefs/protocol";
import { AccessLeaseError } from "./access-lease-error.js";

const MAX_BODY_BYTES = 1024 * 1024;
// The inspect request is exactly one bounded id plus one bounded token. Keep a
// small byte ceiling at the transport boundary before JSON/schema parsing.
const MAX_ACCESS_LEASE_INSPECT_BODY_BYTES = 8 * 1024;
const DEFAULT_PROVIDER = "portablefs-managed";
const DEFAULT_HEALTH_TIMEOUT_MS = 2_000;

export interface AuthorityRef {
  teamId?: string;
  volumeId: string;
  branch: string;
  expectedAuthority?: AuthorityIdentity;
}

export interface AuthorityIdentity {
  provider?: string;
  authorityUrl?: string;
  host?: string;
  port?: number;
  nfsPort?: number;
  authorityInstanceId?: string;
  processRef?: string;
}

export interface AuthorityEndpoint {
  provider?: string;
  authorityUrl: string;
  host?: string;
  port?: number;
  nfsPort?: number;
  authorityInstanceId?: string;
  authToken?: string;
  expiresAt?: number;
  healthUrl?: string;
  healthToken?: string;
}

export interface AuthorityStopResult {
  stopped: boolean;
  managed: boolean;
  reason?: string;
}

// AuthorityOperationError is a machine-readable lifecycle failure thrown by
// fenced registries (production mode); the server renders it as
// { error: { code, message } } with a stable code, plus a Retry-After header
// when the failure is backpressure a client should wait out rather than
// hammer (capacity, start-queue saturation).
export class AuthorityOperationError extends Error {
  readonly retryAfterSeconds?: number;

  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    options?: { retryAfterSeconds?: number }
  ) {
    super(message);
    this.name = "AuthorityOperationError";
    if (options?.retryAfterSeconds !== undefined) {
      this.retryAfterSeconds = options.retryAfterSeconds;
    }
  }
}

export const authorityOperationErrorCodes = {
  invalidRequest: "AUTHORITY_INVALID_REQUEST",
  notFound: "AUTHORITY_NOT_FOUND",
  instanceMismatch: "AUTHORITY_INSTANCE_MISMATCH",
  // The manager lost (or never held) the live singleton epoch claim; it no
  // longer mutates authorities. Reacquire against the successor manager.
  managerEpochSuperseded: "AUTHORITY_MANAGER_EPOCH_SUPERSEDED",
  // The remote manager control store refused or could not prove the durable
  // transition; nothing changed and the operation is retryable.
  controlStoreRequired: "AUTHORITY_CONTROL_STORE_REQUIRED",
  // The registry is at its resident-children cap; the NEW spawn was refused
  // and nothing changed. Running authorities are unaffected; idle eviction
  // frees capacity. 503 + Retry-After: back off, do not hammer.
  atCapacity: "AUTHORITY_AT_CAPACITY",
  // The global cold-start queue stayed saturated for the bounded wait; the
  // start was refused before spawning anything. 503 + Retry-After.
  startQueueTimeout: "AUTHORITY_START_QUEUE_TIMEOUT",
  // ONE tenant is at its per-tenant resident-children budget
  // (PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT); the NEW spawn was
  // refused and nothing changed. 429 (not 503) + Retry-After: the service is
  // healthy and other tenants proceed — this tenant is over its fairness
  // budget, distinct from AUTHORITY_AT_CAPACITY so operators and clients can
  // tell service pressure from tenant pressure apart.
  tenantAtCapacity: "TENANT_AT_CAPACITY",
  // ONE tenant is at its per-tenant active-access-lease budget
  // (PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT); the create was refused before
  // any durable transition. 429 + Retry-After; releasing/expiring any of the
  // tenant's leases frees the budget.
  tenantLeaseLimit: "TENANT_LEASE_LIMIT",
  internal: "AUTHORITY_INTERNAL",
} as const;

export interface AuthorityRegistry {
  ensureAuthority(ref: AuthorityRef): Promise<AuthorityEndpoint>;
  createSession(ref: AuthorityRef): Promise<AuthorityEndpoint>;
  inspectAuthority?(ref: AuthorityRef): Promise<AuthorityEndpoint | null>;
  isHealthy(ref: AuthorityRef, endpoint: AuthorityEndpoint): Promise<boolean>;
  stopAuthority?(ref: AuthorityRef): Promise<AuthorityStopResult>;
  // Atomic ensure + access-lease create (fenced registries): runs `create`
  // against the resolved live authority binding WHILE HOLDING the per-ref
  // authority lock, so idle eviction (which takes the same lock and
  // re-checks activity) can never interleave between the ensure and the
  // lease create. Registries without idle eviction omit it and the plain
  // ensure-then-create path applies.
  ensureAuthorityForLease?<T>(
    ref: AuthorityRef,
    create: (binding: AuthorityLeaseBinding) => Promise<T> | T
  ): Promise<{ endpoint: AuthorityEndpoint; result: T }>;
  shutdown?(): Promise<void>;
}

// The exact live authority a new lease binds to, resolved under the lock:
// the instance and, for registries with remote runtime rows, its MONOTONIC
// runtime sequence (canonical decimal string) plus its RANDOM runtime id.
export interface AuthorityLeaseBinding {
  endpoint: AuthorityEndpoint;
  authorityInstanceId: string;
  authorityRuntimeGeneration?: string;
  authorityRuntimeId?: string;
}

export interface AccessLeaseCreation {
  lease: AccessLease;
  accessToken: string;
}

// AccessLeaseHandler is the server-facing surface of the canonical access
// lease service, satisfied by ProductionAccessLeaseService (async, remote
// pfm receipts). Route handlers await every result, so a synchronous test
// stub also satisfies it.
export interface AccessLeaseHandler {
  healthy(): boolean;
  create(args: {
    operationId: string;
    teamId?: string;
    volumeId: string;
    branch: string;
    consumerId: string;
    authorityInstanceId: string;
    // Present when the registry resolved a fenced runtime binding
    // (production); the local ledger implementation ignores them.
    authorityRuntimeGeneration?: string;
    authorityRuntimeId?: string;
    ttlMs?: number;
  }): Promise<AccessLeaseCreation> | AccessLeaseCreation;
  inspect(args: {
    accessLeaseId: string;
    accessToken: string;
  }): Promise<AccessLeaseInspectResponse> | AccessLeaseInspectResponse;
  renew(args: {
    operationId: string;
    accessLeaseId: string;
    accessToken: string;
    expectedControlSeq: AccessLeaseControlSeq;
    ttlMs?: number;
    rotateToken?: boolean;
  }):
    | Promise<{ lease: AccessLease; accessToken?: string }>
    | { lease: AccessLease; accessToken?: string };
  release(args: {
    operationId: string;
    accessLeaseId: string;
    accessToken: string;
  }):
    | Promise<{ lease: AccessLease; receipt: AccessLeaseReceipt }>
    | { lease: AccessLease; receipt: AccessLeaseReceipt };
  revoke(accessLeaseId: string): Promise<AccessLease> | AccessLease;
  revokeOwner(args: {
    teamId?: string;
    consumerId: string;
    volumeId?: string;
    branch?: string;
  }): Promise<string[]> | string[];
}

export interface AuthorityManagerServerDeps {
  authToken?: string;
  allowUnauthenticated?: boolean;
  registry: AuthorityRegistry;
  readiness?: () => boolean | Promise<boolean>;
  // Canonical access-lease service (production mode). When absent, the
  // /v1/access-leases/* routes answer ACCESS_LEASE_UNSUPPORTED.
  accessLeases?: AccessLeaseHandler;
  // Exact deployment identity served at GET /v1/release-identity (loaded once
  // at startup from release-tooling env). Absent -> the route answers 404
  // RELEASE_IDENTITY_UNAVAILABLE, the honest "unpinned dev deployment" signal.
  releaseIdentity?: Omit<ReleaseIdentity, "serverTimeMs">;
  // Operator metrics endpoint (GET /metrics): renders the manager registry
  // plus the bounded child aggregation as Prometheus text. It sits BEHIND
  // the same bearer auth as every other control route — the exposition names
  // capacity pressure and tenant refusal counts, which is operator data.
  // Absent unless wired — no default exposure.
  metricsEndpoint?: () => Promise<string>;
}

export function createAuthorityManagerServer(deps: AuthorityManagerServerDeps): Server {
  const authToken = normalizeOptionalString(deps.authToken);
  if (process.env.NODE_ENV === "production" && deps.allowUnauthenticated) {
    throw new Error(
      "PortableFS authority manager allowUnauthenticated cannot be enabled in production."
    );
  }
  if (!authToken && !deps.allowUnauthenticated) {
    throw new Error(
      "PortableFS authority manager authToken is required because session routes expose data-plane credentials. Set allowUnauthenticated only for local development."
    );
  }

  return createServer(async (req, res) => {
    try {
      const healthCheck = readHealthCheck(req);
      if (healthCheck === "healthz") {
        sendJson(res, 200, { ok: true });
        return;
      }
      if (healthCheck === "readyz") {
        const ready = deps.readiness ? await deps.readiness() : true;
        sendJson(res, ready ? 200 : 503, { ok: ready });
        return;
      }

      if (!isAuthorized(req, authToken)) {
        sendJson(res, 401, { error: "Unauthorized." });
        return;
      }

      const requestPath = new URL(req.url ?? "/", "http://authority-manager.local").pathname;
      if (req.method === "GET" && requestPath === "/v1/release-identity") {
        // Any authenticated caller may read the deployment identity; it names
        // the build, never tenant data or configuration.
        if (!deps.releaseIdentity) {
          sendJson(res, 404, {
            error: {
              code: releaseIdentityErrorCode,
              message: "Release identity is not configured for this deployment.",
            },
          });
          return;
        }
        sendJson(res, 200, { ...deps.releaseIdentity, serverTimeMs: Date.now() });
        return;
      }

      // Operator metrics: authenticated GET, bounded body, text exposition.
      // 503 (never a partial body) when rendering fails; the error body
      // carries no scrape-target detail.
      if (req.method === "GET" && requestPath === "/metrics") {
        if (!deps.metricsEndpoint) {
          sendJson(res, 404, { error: "Not found." });
          return;
        }
        try {
          const body = await deps.metricsEndpoint();
          res.writeHead(200, {
            "content-type": "text/plain; version=0.0.4; charset=utf-8",
            "content-length": String(Buffer.byteLength(body, "utf8")),
          });
          res.end(body);
        } catch {
          sendJson(res, 503, { error: "Metrics unavailable." });
        }
        return;
      }

      if (req.method !== "POST") {
        sendJson(res, 405, { error: "Method not allowed." });
        return;
      }

      const url = new URL(req.url ?? "/", "http://authority-manager.local");
      const body = await readJsonBody(
        req,
        url.pathname === "/v1/access-leases/inspect"
          ? MAX_ACCESS_LEASE_INSPECT_BODY_BYTES
          : MAX_BODY_BYTES
      );

      if (url.pathname.startsWith("/v1/access-leases/")) {
        await handleAccessLeaseRoute(res, deps, url.pathname, body);
        return;
      }

      // One-call convenience route: the same registry paths as
      // /v1/authorities/ensure followed by /v1/authorities/session. The
      // volume-scoped form is canonical (hosted control planes mirror it);
      // the flat form with volumeId in the body is kept as an alias.
      const mountSessionVolumeId = parseMountSessionPath(url.pathname);
      if (mountSessionVolumeId !== null || url.pathname === "/v1/mount-sessions") {
        const ref = readMountSessionRef(body, mountSessionVolumeId ?? undefined);
        await deps.registry.ensureAuthority(ref);
        const endpoint = await deps.registry.createSession(ref);
        sendJson(res, 200, { mountSession: toMountSessionPayload(ref, endpoint) });
        return;
      }

      const ref = readAuthorityRef(body);

      switch (url.pathname) {
        case "/v1/authorities/ensure": {
          const endpoint = await deps.registry.ensureAuthority(ref);
          sendJson(res, 200, { authority: toAuthorityPayload(endpoint, false) });
          return;
        }
        case "/v1/authorities/session": {
          const endpoint = await deps.registry.createSession(ref);
          sendJson(res, 200, { authority: toAuthorityPayload(endpoint, true) });
          return;
        }
        case "/v1/authorities/health": {
          const endpoint = deps.registry.inspectAuthority
            ? await deps.registry.inspectAuthority(ref)
            : await deps.registry.ensureAuthority(ref);
          const healthy = endpoint ? await deps.registry.isHealthy(ref, endpoint) : false;
          sendJson(res, 200, { healthy });
          return;
        }
        case "/v1/authorities/stop": {
          requireExpectedAuthorityForStop(ref);
          const result = deps.registry.stopAuthority
            ? await deps.registry.stopAuthority(ref)
            : { stopped: false, managed: false };
          sendJson(res, 200, result);
          return;
        }
        default:
          sendJson(res, 404, { error: "Not found." });
          return;
      }
    } catch (error) {
      sendError(res, error);
    }
  });
}

// ---------------------------------------------------------------------------
// Canonical access-lease routes (POST /v1/access-leases/*).
//
// These validate against the versioned @portablefs/protocol schemas and
// report structured machine-readable errors ({ error: { code, message } })
// with the stable ACCESS_LEASE_* codes. The manager bearer token has already
// authenticated the request before dispatch reaches here.
// ---------------------------------------------------------------------------

async function handleAccessLeaseRoute(
  res: ServerResponse,
  deps: AuthorityManagerServerDeps,
  pathname: string,
  body: Record<string, unknown>
): Promise<void> {
  const leases = deps.accessLeases;
  if (!leases) {
    sendJson(res, 501, {
      error: {
        code: accessLeaseErrorCodes.unsupported,
        message: "This authority manager does not manage access leases (production mode required).",
      },
    });
    return;
  }
  try {
    switch (pathname) {
      case "/v1/access-leases/create": {
        const request = parseAccessLeaseBody(accessLeaseCreateRequestSchema, body);
        const { endpoint, ...created } = await createAccessLeaseAtomically(deps, leases, {
          operationId: request.operationId,
          ...(request.teamId ? { teamId: request.teamId } : {}),
          volumeId: request.volumeId,
          branch: request.branch,
          consumerId: request.consumerId,
          ...(request.ttlMs !== undefined ? { ttlMs: request.ttlMs } : {}),
        });
        const response: AccessLeaseCreateResponse = {
          authority: toLeaseAuthorityPayload(endpoint, created.accessToken, created.lease.expiresAt),
          lease: created.lease,
          accessToken: created.accessToken,
          serverTimeMs: Date.now(),
        };
        sendJson(res, 200, response);
        return;
      }
      case "/v1/access-leases/inspect": {
        const request = parseAccessLeaseBody(accessLeaseInspectRequestSchema, body);
        // Enforce the public allowlist again at the serialization boundary so
        // a future handler regression cannot leak token or authority secrets.
        const inspected = await leases.inspect(request);
        const response = accessLeaseInspectResponseSchema.parse({
          lease: inspected.lease,
          serverTimeMs: inspected.serverTimeMs,
        });
        sendJson(res, 200, response);
        return;
      }
      case "/v1/access-leases/renew": {
        const request = parseAccessLeaseBody(accessLeaseRenewRequestSchema, body);
        const renewed = await leases.renew({
          operationId: request.operationId,
          accessLeaseId: request.accessLeaseId,
          accessToken: request.accessToken,
          expectedControlSeq: request.expectedControlSeq,
          ...(request.ttlMs !== undefined ? { ttlMs: request.ttlMs } : {}),
          ...(request.rotateToken !== undefined ? { rotateToken: request.rotateToken } : {}),
        });
        const response: AccessLeaseRenewResponse = {
          lease: renewed.lease,
          ...(renewed.accessToken !== undefined ? { accessToken: renewed.accessToken } : {}),
          serverTimeMs: Date.now(),
        };
        sendJson(res, 200, response);
        return;
      }
      case "/v1/access-leases/release": {
        const request = parseAccessLeaseBody(accessLeaseReleaseRequestSchema, body);
        const released = await leases.release({
          operationId: request.operationId,
          accessLeaseId: request.accessLeaseId,
          accessToken: request.accessToken,
        });
        const response: AccessLeaseReleaseResponse = {
          lease: released.lease,
          receipt: released.receipt,
          serverTimeMs: Date.now(),
        };
        sendJson(res, 200, response);
        return;
      }
      case "/v1/access-leases/revoke": {
        const request = parseAccessLeaseBody(accessLeaseRevokeRequestSchema, body);
        const lease = await leases.revoke(request.accessLeaseId);
        const response: AccessLeaseRevokeResponse = { lease, serverTimeMs: Date.now() };
        sendJson(res, 200, response);
        return;
      }
      case "/v1/access-leases/revoke-owner": {
        const request = parseAccessLeaseBody(accessLeaseRevokeOwnerRequestSchema, body);
        const revoked = await leases.revokeOwner({
          consumerId: request.consumerId,
          ...(request.teamId ? { teamId: request.teamId } : {}),
          ...(request.volumeId ? { volumeId: request.volumeId } : {}),
          ...(request.branch ? { branch: request.branch } : {}),
        });
        const response: AccessLeaseRevokeOwnerResponse = { revoked, serverTimeMs: Date.now() };
        sendJson(res, 200, response);
        return;
      }
      default:
        sendJson(res, 404, { error: "Not found." });
        return;
    }
  } catch (error) {
    sendAccessLeaseError(res, error);
  }
}

// Requirement: ensure + access-lease create are atomically serialized per
// branch ref when the registry supports it, so idle eviction can never
// observe the ensured authority without the lease that motivated it.
// Registries without idle eviction keep the plain ensure-then-create path
// (byte-identical to the pre-production behavior).
async function createAccessLeaseAtomically(
  deps: AuthorityManagerServerDeps,
  leases: AccessLeaseHandler,
  args: {
    operationId: string;
    teamId?: string;
    volumeId: string;
    branch: string;
    consumerId: string;
    ttlMs?: number;
  }
): Promise<AccessLeaseCreation & { endpoint: AuthorityEndpoint }> {
  const ref: AuthorityRef = {
    volumeId: args.volumeId,
    branch: args.branch,
    ...(args.teamId ? { teamId: args.teamId } : {}),
  };
  if (deps.registry.ensureAuthorityForLease) {
    const { endpoint, result } = await deps.registry.ensureAuthorityForLease(ref, (binding) =>
      leases.create({
        ...args,
        authorityInstanceId: binding.authorityInstanceId,
        ...(binding.authorityRuntimeGeneration !== undefined
          ? { authorityRuntimeGeneration: binding.authorityRuntimeGeneration }
          : {}),
        ...(binding.authorityRuntimeId !== undefined
          ? { authorityRuntimeId: binding.authorityRuntimeId }
          : {}),
      })
    );
    return { ...result, endpoint };
  }
  // The lease is hard-bound to the exact live authority instance; the
  // manager (not the caller) names it.
  const endpoint = await deps.registry.ensureAuthority(ref);
  if (!endpoint.authorityInstanceId) {
    throw new AccessLeaseError(
      501,
      accessLeaseErrorCodes.unsupported,
      "The resolved authority has no authorityInstanceId; access leases require a registry that names authority instances."
    );
  }
  const created = await leases.create({
    ...args,
    authorityInstanceId: endpoint.authorityInstanceId,
  });
  return { ...created, endpoint };
}

function parseAccessLeaseBody<T>(schema: ZodType<T>, body: Record<string, unknown>): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new AccessLeaseError(
      400,
      accessLeaseErrorCodes.invalidRequest,
      `Invalid request${issue ? `: ${issue.path.map(String).join(".")} ${issue.message}` : "."}`
    );
  }
  return parsed.data;
}

// The endpoint payload the lease caller mounts against: the same shape as the
// ensure/session authority payload, carrying the access token as the
// data-plane credential so the payload alone suffices to mount.
function toLeaseAuthorityPayload(
  endpoint: AuthorityEndpoint,
  accessToken: string,
  expiresAt: number
): AuthorityEndpointPayload {
  return {
    authorityUrl: endpoint.authorityUrl,
    ...(endpoint.provider ? { provider: endpoint.provider } : {}),
    ...(endpoint.host ? { host: endpoint.host } : {}),
    ...(endpoint.port !== undefined ? { port: endpoint.port } : {}),
    ...(endpoint.nfsPort !== undefined ? { nfsPort: endpoint.nfsPort } : {}),
    ...(endpoint.authorityInstanceId ? { authorityInstanceId: endpoint.authorityInstanceId } : {}),
    authorityAuthToken: accessToken,
    authorityExpiresAt: expiresAt,
  };
}

function sendAccessLeaseError(res: ServerResponse, error: unknown): void {
  if (error instanceof AccessLeaseError || error instanceof AuthorityOperationError) {
    sendJson(
      res,
      error.status,
      { error: { code: error.code, message: error.message } },
      retryAfterHeader(error)
    );
    return;
  }
  if (error instanceof HttpError) {
    sendJson(res, error.status, {
      error: { code: accessLeaseErrorCodes.invalidRequest, message: error.message },
    });
    return;
  }
  sendJson(res, 500, {
    error: {
      code: accessLeaseErrorCodes.internal,
      message: error instanceof Error ? error.message : "Internal error.",
    },
  });
}

// ---------------------------------------------------------------------------
// Mode selection.
//
// Two modes exist: "env" (fixed endpoints) and "production" (journal-native,
// remote control store). The retired WAL-paired "managed" mode fails startup
// by name, and the ambient variables that used to infer it
// (PORTABLEFS_MANAGED_VCS_BIN, PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR) infer
// production only when the production control store is also configured.
// ---------------------------------------------------------------------------

export type AuthorityManagerMode = "env" | "production";

export interface AuthorityManagerModeEnv {
  PORTABLEFS_AUTHORITY_MODE?: string;
  PORTABLEFS_MANAGED_VCS_BIN?: string;
  PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR?: string;
  PORTABLEFS_MANAGER_CONTROL_DATABASE_URL?: string;
}

const MANAGED_MODE_RETIRED_MESSAGE =
  "The WAL-paired managed registry was retired; production mode (PORTABLEFS_AUTHORITY_MODE=production, journal-native) is its successor. Set PORTABLEFS_AUTHORITY_MODE=production with PORTABLEFS_MANAGER_CONTROL_DATABASE_URL, PORTABLEFS_MANAGED_VCS_JOURNAL_DSN, and PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON (see docs/authority-manager.md), or PORTABLEFS_AUTHORITY_MODE=env for fixed endpoints.";

export function readAuthorityManagerMode(env: AuthorityManagerModeEnv): AuthorityManagerMode {
  const explicit = normalizeOptionalString(env.PORTABLEFS_AUTHORITY_MODE);
  if (!explicit) {
    const wantsProcessRegistry =
      normalizeOptionalString(env.PORTABLEFS_MANAGED_VCS_BIN) ??
      normalizeOptionalString(env.PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR);
    if (!wantsProcessRegistry) {
      return "env";
    }
    if (normalizeOptionalString(env.PORTABLEFS_MANAGER_CONTROL_DATABASE_URL)) {
      return "production";
    }
    throw new Error(
      `PORTABLEFS_MANAGED_VCS_BIN/PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR are set without the production control store. ${MANAGED_MODE_RETIRED_MESSAGE}`
    );
  }
  if (explicit === "env" || explicit === "production") {
    return explicit;
  }
  if (explicit === "managed") {
    throw new Error(
      `PORTABLEFS_AUTHORITY_MODE=managed is no longer supported. ${MANAGED_MODE_RETIRED_MESSAGE}`
    );
  }
  throw new Error("PORTABLEFS_AUTHORITY_MODE must be env or production.");
}

export interface EnvAuthorityRegistryConfig {
  PORTABLEFS_AUTHORITY_PROVIDER_NAME?: string;
  PORTABLEFS_AUTHORITY_URL?: string;
  PORTABLEFS_AUTHORITY_NFS_PORT?: string;
  PORTABLEFS_AUTHORITY_AUTH_TOKEN?: string;
  PORTABLEFS_AUTHORITY_EXPIRES_AT?: string;
  PORTABLEFS_AUTHORITY_HEALTH_URL?: string;
  PORTABLEFS_AUTHORITY_HEALTH_TOKEN?: string;
  PORTABLEFS_AUTHORITY_HEALTH_TIMEOUT_MS?: string;
  PORTABLEFS_AUTHORITY_MAP_JSON?: string;
  VCS_AUTH_TOKEN?: string;
}

export interface ValidateEnvAuthorityRegistryConfigOptions {
  requireHealth?: boolean;
}

export function validateEnvAuthorityRegistryConfig(
  env: EnvAuthorityRegistryConfig,
  options: ValidateEnvAuthorityRegistryConfigOptions = {}
): void {
  const provider = normalizeOptionalString(env.PORTABLEFS_AUTHORITY_PROVIDER_NAME) ?? DEFAULT_PROVIDER;
  const entries = readAuthorityEntries(env, provider);
  if (entries.size === 0) {
    throw new Error("At least one PortableFS authority endpoint must be configured.");
  }
  if (options.requireHealth) {
    const missingHealth = [...entries]
      .filter(([, endpoint]) => !endpoint.healthUrl)
      .map(([key]) => key);
    if (missingHealth.length > 0) {
      throw new Error(
        `PortableFS authority health URLs are required in production; missing healthUrl for ${missingHealth.join(", ")}.`
      );
    }
  }
}

export function createEnvAuthorityRegistry(
  env: EnvAuthorityRegistryConfig,
  fetchImpl?: typeof fetch
): AuthorityRegistry {
  const registry = new EnvAuthorityRegistry(env, fetchImpl);
  return registry;
}

class EnvAuthorityRegistry implements AuthorityRegistry {
  private readonly provider: string;
  private readonly entries: Map<string, AuthorityEndpoint>;
  private readonly fetchImpl: typeof fetch;
  private readonly healthTimeoutMs: number;

  constructor(env: EnvAuthorityRegistryConfig, fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis)) {
    this.provider = normalizeOptionalString(env.PORTABLEFS_AUTHORITY_PROVIDER_NAME) ?? DEFAULT_PROVIDER;
    this.entries = readAuthorityEntries(env, this.provider);
    this.fetchImpl = fetchImpl;
    this.healthTimeoutMs =
      readPositiveNumberFromString(env.PORTABLEFS_AUTHORITY_HEALTH_TIMEOUT_MS) ?? DEFAULT_HEALTH_TIMEOUT_MS;
  }

  async ensureAuthority(ref: AuthorityRef): Promise<AuthorityEndpoint> {
    return this.resolve(ref);
  }

  async createSession(ref: AuthorityRef): Promise<AuthorityEndpoint> {
    return this.resolve(ref);
  }

  async inspectAuthority(ref: AuthorityRef): Promise<AuthorityEndpoint | null> {
    return this.resolve(ref);
  }

  async isHealthy(ref: AuthorityRef, endpoint: AuthorityEndpoint): Promise<boolean> {
    const resolved = endpoint.authorityUrl ? endpoint : this.resolve(ref);
    if (!resolved.healthUrl) {
      return true;
    }
    const response = await fetchHealthWithTimeout(
      this.fetchImpl,
      resolved.healthUrl,
      {
        headers: resolved.healthToken ? { authorization: `Bearer ${resolved.healthToken}` } : {},
      },
      this.healthTimeoutMs
    ).catch(() => null);
    if (!response) {
      return false;
    }
    if (!response.ok) {
      return false;
    }
    const text = response.text;
    if (!text.trim()) {
      return true;
    }
    const json = tryParseJsonObject(text);
    if (!json) {
      return true;
    }
    const ready = readBoolean(json, "ready");
    const ok = readBoolean(json, "ok");
    return ready ?? ok ?? true;
  }

  private resolve(ref: AuthorityRef): AuthorityEndpoint {
    const endpoint =
      (ref.teamId ? this.entries.get(`${ref.teamId}:${ref.volumeId}:${ref.branch}`) : undefined) ??
      this.entries.get(`${ref.volumeId}:${ref.branch}`) ??
      this.entries.get(ref.volumeId) ??
      this.entries.get("default") ??
      this.entries.get("*");
    if (!endpoint) {
      throw new HttpError(
        404,
        `No PortableFS authority is registered for ${ref.volumeId}@${ref.branch}.`
      );
    }
    return endpoint;
  }
}

function readAuthorityEntries(env: EnvAuthorityRegistryConfig, provider: string): Map<string, AuthorityEndpoint> {
  const entries = new Map<string, AuthorityEndpoint>();
  const mapJson = normalizeOptionalString(env.PORTABLEFS_AUTHORITY_MAP_JSON);
  if (mapJson) {
    const parsed = parseJsonObject(mapJson);
    for (const [key, value] of Object.entries(parsed)) {
      if (!isRecord(value)) {
        throw new Error(`PortableFS authority map entry ${key} must be an object.`);
      }
      entries.set(key, normalizeEndpoint(value, provider));
    }
  }

  const defaultAuthorityUrl = normalizeOptionalString(env.PORTABLEFS_AUTHORITY_URL);
  if (defaultAuthorityUrl) {
    entries.set(
      "default",
      normalizeEndpoint(
        {
          authorityUrl: defaultAuthorityUrl,
          nfsPort: readNumberFromString(env.PORTABLEFS_AUTHORITY_NFS_PORT),
          authToken:
            normalizeOptionalString(env.PORTABLEFS_AUTHORITY_AUTH_TOKEN) ??
            normalizeOptionalString(env.VCS_AUTH_TOKEN),
          expiresAt: readNumberFromString(env.PORTABLEFS_AUTHORITY_EXPIRES_AT),
          healthUrl: normalizeOptionalString(env.PORTABLEFS_AUTHORITY_HEALTH_URL),
          healthToken: normalizeOptionalString(env.PORTABLEFS_AUTHORITY_HEALTH_TOKEN),
        },
        provider
      )
    );
  }

  return entries;
}

function normalizeEndpoint(value: Record<string, unknown>, defaultProvider: string): AuthorityEndpoint {
  const authorityUrl = readString(value, "authorityUrl");
  if (!authorityUrl) {
    throw new Error("PortableFS authority endpoint is missing authorityUrl.");
  }
  const address = parseAuthorityAddress(authorityUrl);
  const host = readString(value, "host") ?? address.host;
  const port = readNumber(value, "port") ?? address.port;
  if (!host || !port) {
    throw new Error(`PortableFS authority endpoint has an invalid authorityUrl: ${authorityUrl}`);
  }
  const endpoint: AuthorityEndpoint = {
    provider: readString(value, "provider") ?? defaultProvider,
    authorityUrl,
    host,
    port,
  };
  const nfsPort = readNumber(value, "nfsPort");
  const authToken =
    readString(value, "authToken") ??
    readString(value, "authorityAuthToken") ??
    readString(value, "mountToken");
  const expiresAt = readNumber(value, "expiresAt") ?? readNumber(value, "authorityExpiresAt");
  const healthUrl = readString(value, "healthUrl");
  const healthToken = readString(value, "healthToken");
  if (nfsPort !== undefined) endpoint.nfsPort = nfsPort;
  if (authToken) endpoint.authToken = authToken;
  if (expiresAt !== undefined) endpoint.expiresAt = expiresAt;
  if (healthUrl) endpoint.healthUrl = healthUrl;
  if (healthToken) endpoint.healthToken = healthToken;
  return endpoint;
}

function toAuthorityPayload(endpoint: AuthorityEndpoint, includeAuthToken: boolean): Record<string, unknown> {
  return omitUndefined({
    provider: endpoint.provider,
    authorityUrl: endpoint.authorityUrl,
    host: endpoint.host,
    port: endpoint.port,
    nfsPort: endpoint.nfsPort,
    authorityInstanceId: endpoint.authorityInstanceId,
    authorityAuthToken: includeAuthToken ? endpoint.authToken : undefined,
    authorityExpiresAt: includeAuthToken ? endpoint.expiresAt : undefined,
  });
}

function toMountSessionPayload(ref: AuthorityRef, endpoint: AuthorityEndpoint): Record<string, unknown> {
  return omitUndefined({
    volumeId: ref.volumeId,
    branch: ref.branch,
    endpoint: omitUndefined({
      authorityUrl: endpoint.authorityUrl,
      host: endpoint.host,
      port: endpoint.port,
      nfsPort: endpoint.nfsPort,
    }),
    token: endpoint.authToken,
    expiresAtMs: endpoint.expiresAt,
    authorityInstanceId: endpoint.authorityInstanceId,
    provider: endpoint.provider,
  });
}

function readAuthorityRef(body: Record<string, unknown>): AuthorityRef {
  const volumeId = readString(body, "volumeId");
  const branch = readString(body, "branch");
  if (!volumeId || !branch) {
    throw new HttpError(400, "volumeId and branch are required.");
  }
  const ref: AuthorityRef = {
    volumeId,
    branch,
  };
  const teamId = readString(body, "teamId");
  const expectedAuthority = readAuthorityIdentity(body, "expectedAuthority");
  if (teamId) ref.teamId = teamId;
  if (expectedAuthority) ref.expectedAuthority = expectedAuthority;
  return ref;
}

// parseMountSessionPath extracts the volume id from the canonical
// /v1/volumes/:volumeId/mount-sessions form; null = not that route.
function parseMountSessionPath(pathname: string): string | null {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 4 && parts[0] === "v1" && parts[1] === "volumes" && parts[3] === "mount-sessions") {
    return decodeURIComponent(parts[2] ?? "");
  }
  return null;
}

function readMountSessionRef(
  body: Record<string, unknown>,
  pathVolumeId?: string
): AuthorityRef {
  const bodyVolumeId = readString(body, "volumeId");
  if (pathVolumeId && bodyVolumeId && bodyVolumeId !== pathVolumeId) {
    throw new HttpError(400, "volumeId in the body does not match the URL.");
  }
  const volumeId = pathVolumeId || bodyVolumeId;
  if (!volumeId) {
    throw new HttpError(400, "volumeId is required.");
  }
  const ref: AuthorityRef = {
    volumeId,
    branch: readString(body, "branch") ?? "main",
  };
  const teamId = readString(body, "teamId");
  if (teamId) ref.teamId = teamId;
  return ref;
}

function readAuthorityIdentity(body: Record<string, unknown>, key: string): AuthorityIdentity | undefined {
  const candidate = body[key];
  if (!isRecord(candidate)) {
    return undefined;
  }
  return omitUndefined({
    provider: readString(candidate, "provider"),
    authorityUrl: readString(candidate, "authorityUrl"),
    host: readString(candidate, "host"),
    port: readNumber(candidate, "port"),
    nfsPort: readNumber(candidate, "nfsPort"),
    authorityInstanceId:
      readString(candidate, "authorityInstanceId") ?? readString(candidate, "processRef"),
    processRef: readString(candidate, "processRef"),
  }) as AuthorityIdentity;
}

function requireExpectedAuthorityForStop(ref: AuthorityRef): void {
  const expected = ref.expectedAuthority;
  if (!expected || Object.keys(expected).length === 0) {
    throw new HttpError(400, "expectedAuthority is required for stop.");
  }
  if (!expected.authorityUrl && (!expected.host || !expected.port)) {
    throw new HttpError(400, "expectedAuthority must include authorityUrl or host and port.");
  }
}

async function readJsonBody(
  req: IncomingMessage,
  maxBodyBytes: number = MAX_BODY_BYTES
): Promise<Record<string, unknown>> {
  let total = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.byteLength;
    if (total > maxBodyBytes) {
      throw new HttpError(413, "Request body is too large.");
    }
    chunks.push(buffer);
  }
  if (chunks.length === 0) {
    return {};
  }
  return parseJsonObject(Buffer.concat(chunks).toString("utf8"));
}

function readHealthCheck(req: IncomingMessage): "healthz" | "readyz" | null {
  if (req.method !== "GET") {
    return null;
  }
  const url = new URL(req.url ?? "/", "http://authority-manager.local");
  if (url.pathname === "/healthz") {
    return "healthz";
  }
  if (url.pathname === "/readyz") {
    return "readyz";
  }
  return null;
}

function isAuthorized(req: IncomingMessage, token: string | undefined): boolean {
  if (!token) {
    return true;
  }
  const header = req.headers.authorization;
  const presented = typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : "";
  return timingSafeStringEqual(presented, token);
}

function timingSafeStringEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  if (leftBytes.byteLength !== rightBytes.byteLength) {
    // Compare against self so the work — and thus the response time — does not
    // depend on the presented token's length (no length-distinguishing oracle),
    // then fail. timingSafeEqual requires equal-length buffers.
    timingSafeEqual(leftBytes, leftBytes);
    return false;
  }
  return timingSafeEqual(leftBytes, rightBytes);
}

async function fetchHealthWithTimeout(
  fetchImpl: typeof fetch,
  input: string,
  init: RequestInit,
  timeoutMs: number
): Promise<{ ok: boolean; text: string }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(input, {
      ...init,
      signal: init.signal ?? controller.signal,
    });
    if (!response.ok) {
      return { ok: false, text: "" };
    }
    return { ok: true, text: await response.text() };
  } finally {
    clearTimeout(timeout);
  }
}

function sendJson(
  res: ServerResponse,
  status: number,
  value: unknown,
  extraHeaders?: Record<string, string>
): void {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...(extraHeaders ?? {}),
  });
  res.end(body);
}

// Backpressure refusals (503 AUTHORITY_AT_CAPACITY / AUTHORITY_START_QUEUE_TIMEOUT
// and 429 TENANT_AT_CAPACITY / TENANT_LEASE_LIMIT) carry Retry-After so mount
// clients back off instead of hammering.
function retryAfterHeader(error: unknown): Record<string, string> | undefined {
  return error instanceof AuthorityOperationError && error.retryAfterSeconds !== undefined
    ? { "retry-after": String(error.retryAfterSeconds) }
    : undefined;
}

function sendError(res: ServerResponse, error: unknown): void {
  if (error instanceof HttpError) {
    sendJson(res, error.status, { error: error.message });
    return;
  }
  // Legacy session routes mint their credential through the lease service
  // (and, in production mode, the fenced registry); structured failures keep
  // their status and machine-readable code.
  if (error instanceof AccessLeaseError || error instanceof AuthorityOperationError) {
    sendJson(
      res,
      error.status,
      { error: { code: error.code, message: error.message } },
      retryAfterHeader(error)
    );
    return;
  }
  // Never reflect raw internal error text (filesystem paths, DSN fragments,
  // driver/SQL detail) to the caller. Log server-side; return a fixed message,
  // matching volume-api's sendError discipline.
  console.error("authority-manager internal error:", error);
  sendJson(res, 500, { error: "Internal error." });
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}

function parseAuthorityAddress(authorityUrl: string): { host?: string; port?: number } {
  const firstAddress = authorityUrl.split(",")[0]?.trim() ?? "";
  const stripped = firstAddress.replace(/^[a-z][a-z0-9+.-]*:\/\//iu, "");
  const [host, portText] = stripped.split(":");
  const port = portText && /^[0-9]+$/u.test(portText) ? Number(portText) : undefined;
  const result: { host?: string; port?: number } = {};
  if (host) {
    result.host = host;
  }
  if (port && port > 0 && port <= 65535) {
    result.port = port;
  }
  return result;
}

function parseJsonObject(text: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(text);
  if (!isRecord(parsed)) {
    throw new HttpError(400, "Request body must be a JSON object.");
  }
  return parsed;
}

function tryParseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(text);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function readString(value: Record<string, unknown>, key: string): string | undefined {
  const candidate = value[key];
  return typeof candidate === "string" && candidate.trim() ? candidate.trim() : undefined;
}

function readNumber(value: Record<string, unknown>, key: string): number | undefined {
  const candidate = value[key];
  return typeof candidate === "number" && Number.isFinite(candidate) ? candidate : undefined;
}

function readNumberFromString(value: string | undefined): number | undefined {
  const normalized = normalizeOptionalString(value);
  if (!normalized) {
    return undefined;
  }
  const numberValue = Number(normalized);
  return Number.isFinite(numberValue) ? numberValue : undefined;
}

function readPositiveNumberFromString(value: string | undefined): number | undefined {
  const numberValue = readNumberFromString(value);
  return numberValue !== undefined && numberValue > 0 ? numberValue : undefined;
}

function readBoolean(value: Record<string, unknown>, key: string): boolean | undefined {
  const candidate = value[key];
  return typeof candidate === "boolean" ? candidate : undefined;
}

function normalizeOptionalString(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized ? normalized : undefined;
}

function omitUndefined<T extends Record<string, unknown>>(value: T): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
