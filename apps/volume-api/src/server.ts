import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { pipeline } from "node:stream/promises";
import { URL } from "node:url";
import {
  BlobRangeNotSatisfiableError,
  normalizeVolumePath,
  openBlobByteStream,
  parentVolumePath,
  sha256Buffer,
  type BlobByteStream,
  type BlobRangeRequest,
  type BlobStore,
} from "@portablefs/core";
import {
  MetadataConflictError,
  runGc,
  type JournalActivationStatus,
  type MetadataRepository,
  type PostgresHistoryRepository,
  type SnapshotCutRecord,
} from "@portablefs/metadata-db";
import { browseVolumeTree, CommitBrowseIndexCache, serveVolumeFile } from "./browse.js";
import { runIntegrityCheck } from "./integrity.js";
import {
  activateJournalRequestSchema,
  attachVolumeRequestSchema,
  attachVolumeReceiptedRequestSchema,
  blobProbeRequestSchema,
  checkinRequestSchema,
  checkoutRequestSchema,
  commitDeltaRequestSchema,
  commitRequestSchema,
  createBranchRequestSchema,
  createVolumeRequestSchema,
  detachRequestSchema,
  forkRequestSchema,
  grepRequestSchema,
  renewLeaseRequestSchema,
  snapshotRequestSchema,
  snapshotOperationIdSchema,
  uploadBlobBatchRequestSchema,
  volumePathSchema,
  releaseIdentityErrorCode,
  type BlobDigest,
  type ReleaseIdentity,
  type TreeEntry,
  type TreeManifest,
} from "@portablefs/protocol";
import {
  assertBranchModeAllows,
  materializationRouteFor,
  type BranchModeAction,
  type MaterializationRoute,
} from "./branch-modes.js";
import { MemoryCachingBlobStore } from "./blob-cache.js";
import {
  grepPft2Commit,
  resolveCutReadSource,
  type CutFactsReader,
} from "./cut-workspace.js";
import { isAbortError, VolumeApiError } from "./errors.js";
import { BoundedGrepScanner, IsolatedRegexMatcher } from "./grep-engine.js";
import { routeAdminHistoryRequest } from "./history-routes.js";
import { routeHistoryServingRequest } from "./history-serving.js";
import type { HistoryStoreRegistry } from "./history-stores.js";
import type { ControlReadiness } from "./readiness.js";
import {
  AdmissionController,
  maxWaitHeadTimeoutMs,
  parseContentLength,
  resolveRoutePolicies,
  type AdmissionPermit,
  type RoutePolicy,
} from "./limits.js";
import { browsePft2Tree, servePft2File, type Pft2ReadContext } from "./pft2-read.js";
import { VolumeApiRuntime } from "./runtime.js";
import { createTelemetry, type VolumeApiTelemetry, type VolumeApiTelemetryEvent } from "./telemetry.js";

// Transport-level defenses applied to the Node HTTP server. All values are
// validated positive safe integers with keepAlive < headers <= request so
// slow-header/slowloris sockets, unbounded keepalive reuse, and connection
// floods are bounded at the transport before any handler runs.
export interface HttpServerDefenses {
  headersTimeoutMs?: number;
  requestTimeoutMs?: number;
  keepAliveTimeoutMs?: number;
  maxRequestsPerSocket?: number;
  maxConnections?: number;
}

export interface VolumeApiServerDeps {
  metadata: MetadataRepository;
  blobStore: BlobStore;
  // The admin credential: provisions tenants/tokens and runs GC. Tenant data
  // access uses per-tenant tokens (resolved via metadata.resolveTenantToken).
  authToken?: string;
  maxBodyBytes?: number;
  // Cap for raw blob bodies (PUT /v1/blobs/:digest and POST /v1/blobs/batch-binary),
  // separate from the general maxBodyBytes. Defaults to 64 MiB; wired from
  // VOLUME_API_MAX_BLOB_BODY_BYTES in main.ts.
  maxBlobBodyBytes?: number;
  blobCacheMaxBytes?: number;
  // Per-tenant admission caps (VOLUME_API_TENANT_MAX_REQUESTS /
  // VOLUME_API_TENANT_MAX_RESPONSE_BYTES). Unset = 50% of the global
  // budgets; 0 disables the dimension. Ignored when `admission` is injected.
  tenantMaxRequests?: number;
  tenantMaxReservedBytes?: number;
  // Exact deployment identity served at GET /v1/release-identity (loaded once
  // at startup from release-tooling env). Absent -> the route answers 404
  // RELEASE_IDENTITY_UNAVAILABLE, the honest "unpinned dev deployment" signal.
  releaseIdentity?: Omit<ReleaseIdentity, "serverTimeMs">;
  // Minimum CLI version this deployment supports. Set -> EVERY /v1 response
  // carries the x-portablefs-min-cli-version header (one transport hook, no
  // per-route wiring); unset -> no header. Validated as semver at startup
  // (PORTABLEFS_MIN_CLI_VERSION in main.ts).
  minCliVersion?: string;
  // Receipted (exact-once) attach: dormant until the deployment's migration
  // lineage is complete. Managed clients fail with 426 and never downgrade
  // when this is false.
  receiptedAttachEnabled?: boolean | undefined;
  // Process lifecycle (drain phases + effect tracking). Defaults to a local
  // runtime that never receives signals — tests and embedded servers keep
  // today's behavior.
  runtime?: VolumeApiRuntime;
  // Low-cardinality operational hook; see telemetry.ts for the event set.
  telemetry?: (event: VolumeApiTelemetryEvent) => unknown;
  // Injectable admission state (tests); production uses the defaults.
  admission?: AdmissionController;
  // Exact-key readers for HistoryCut objects. This is deliberately separate
  // from blobStore: serving must dispatch DB-recorded keys by failure domain
  // and must never fall back to digest-derived aggregate BlobStore.get().
  historyStores?: HistoryStoreRegistry | undefined;
  historyCopyTimeoutMs?: number | undefined;
  httpDefenses?: HttpServerDefenses;
  // Unauthenticated GET /readyz (control readiness: phase + bounded metadata
  // probe; never blob stores). Absent — embedded/test servers — the route
  // fails closed with 503 so a deploy gate can never pass vacuously.
  readiness?: ControlReadiness;
}

// Per-request context threaded through the router. It intentionally KEEPS the
// VolumeApiServerDeps field names (metadata, blobStore, maxBodyBytes) so
// handler bodies read identically; maxBodyBytes carries the admitted route's
// body bound for this request.
interface RequestContext {
  metadata: MetadataRepository;
  blobStore: BlobStore;
  maxBodyBytes: number;
  maxBlobBodyBytes?: number | undefined;
  receiptedAttachEnabled?: boolean | undefined;
  declaredBodyBytes: number | undefined;
  // Aborted on client disconnect and 20s into a drain. Read-only work (head
  // waits, grep, history reads, blob streams) must honor it; dispatched
  // attach/commit effects deliberately do NOT (they settle even when the
  // client is lost).
  requestSignal: AbortSignal;
  // The request's admission permit: blob downloads charge resident response
  // bytes through it at serve time (see sendBlobDownload).
  permit: AdmissionPermit;
  policy: RoutePolicy;
  events: VolumeApiTelemetry;
  runtime: VolumeApiRuntime;
  browseIndexes: CommitBrowseIndexCache;
  historyStores: HistoryStoreRegistry | undefined;
  historyCopyTimeoutMs: number | undefined;
}

export function createVolumeApiServer(deps: VolumeApiServerDeps): Server {
  const telemetry = createTelemetry(deps.telemetry);
  const runtime = deps.runtime ?? new VolumeApiRuntime({ telemetry, exit: () => undefined });
  runtime.markServing();
  const policies = resolveRoutePolicies(
    deps.maxBlobBodyBytes !== undefined ? { maxBlobBodyBytes: deps.maxBlobBodyBytes } : {}
  );
  const admission =
    deps.admission ??
    new AdmissionController({
      telemetry,
      ...(deps.tenantMaxRequests !== undefined
        ? { tenantMaxRequests: deps.tenantMaxRequests }
        : {}),
      ...(deps.tenantMaxReservedBytes !== undefined
        ? { tenantMaxReservedBytes: deps.tenantMaxReservedBytes }
        : {}),
    });
  const browseIndexes = new CommitBrowseIndexCache();
  const blobStore =
    deps.blobCacheMaxBytes === 0
      ? deps.blobStore
      : new MemoryCachingBlobStore(deps.blobStore, deps.blobCacheMaxBytes);
  // Durable-effect tracking wraps the repository ONCE here, so every handler
  // registers dispatched attach/commit/record effects with the drain runtime
  // automatically.
  const metadata = withTrackedEffects(deps.metadata, runtime);

  const server = createServer(async (req, res) => {
    const startedAt = Date.now();
    const requestId = resolveRequestId(req);
    res.setHeader("x-portablefs-request-id", requestId);
    // Set before any dispatch so every /v1 answer — routed, refused, drained,
    // or streamed — carries the advertised minimum CLI version.
    if (deps.minCliVersion && requestTargetsV1(req.url)) {
      res.setHeader("x-portablefs-min-cli-version", deps.minCliVersion);
    }
    const requestDone = runtime.requestStarted();
    let policy: RoutePolicy = policies.control;
    let finished = false;
    // finishRequest runs when HANDLER WORK completes — not when the response
    // socket closes. A lost client whose durable work is still running keeps
    // its active-request slot until that work settles.
    const finishRequest = () => {
      if (finished) {
        return;
      }
      finished = true;
      requestDone();
      telemetry.emit({
        type: "request",
        route: policy.name,
        method: normalizeTelemetryMethod(req.method),
        status: res.statusCode,
        durationMs: Date.now() - startedAt,
        aborted: !res.writableFinished,
      });
    };

    try {
      // Liveness is dependency-free and ALWAYS 200 — draining processes are
      // alive on purpose.
      if (isHealthCheck(req)) {
        sendJson(res, 200, { ok: true });
        return;
      }
      // Readiness is unauthenticated (deploy gates cannot present a bearer)
      // and evaluated BEFORE the draining short-circuit so its payload
      // reports the phase truthfully; draining is always 503-unready either
      // way. Fail-closed: no coordinator means no vacuous 200.
      if (isReadinessCheck(req)) {
        if (!deps.readiness) {
          sendJson(res, 503, {
            error: {
              code: "VOLUME_READINESS_UNCONFIGURED",
              message: "Readiness is not configured on this server.",
            },
          });
          return;
        }
        const report = await deps.readiness.evaluate();
        sendJson(res, report.status, report.body);
        return;
      }
      if (runtime.isDraining()) {
        // New work on surviving keepalive connections is refused; in-flight
        // requests admitted before the drain keep running.
        res.setHeader("connection", "close");
        sendJson(res, 503, {
          error: { code: "VOLUME_DRAINING", message: "The server is draining; retry elsewhere." },
        });
        return;
      }

      const url = new URL(req.url ?? "/", "http://volume-api.local");
      const parts = decodePathParts(url.pathname);
      policy = routePolicyFor(policies, req.method ?? "GET", parts);
      // Bodyless methods weigh zero body bytes (their policy reserve still
      // applies); for body-bearing methods an absent Content-Length (chunked)
      // reserves the route maximum.
      const method = req.method ?? "GET";
      const declaredBodyBytes =
        method === "GET" || method === "HEAD" || method === "DELETE"
          ? 0
          : parseContentLength(req.headers["content-length"]);
      // ADMISSION BEFORE AUTHENTICATION: resolving a tenant token is a
      // database query, so unauthenticated floods must consume (and be
      // refused by) the same concurrency/memory budgets as everything else —
      // otherwise they bypass every cap and stampede PostgreSQL. The body is
      // still never read before authentication succeeds.
      const permit = admission.admit(policy, declaredBodyBytes);
      // v1 all-at-once responses are serialized inside the route's audited
      // bound; overruns become typed VOLUME_RESPONSE_TOO_LARGE (see sendJson).
      responseByteBounds.set(res, policy.maxResponseBytes);

      // Client disconnect and drain both cancel READ-ONLY work through this
      // signal; dispatched durable effects ignore it and settle.
      const abort = new AbortController();
      const onClientGone = () => abort.abort();
      const onDrainAbort = () => abort.abort();
      res.once("close", onClientGone);
      runtime.drainSignal.addEventListener("abort", onDrainAbort, { once: true });

      try {
        const auth = await authenticate(req, deps);
        if (!auth) {
          sendJson(res, 401, { error: { code: "VOLUME_UNAUTHORIZED", message: "Unauthorized." } });
          return;
        }
        // The per-tenant admission dimension binds here — admission itself
        // ran before auth (unauthenticated floods must still be budgeted),
        // but tenant identity only exists once the credential resolves. The
        // admin token carries no tenant and stays outside the dimension.
        if (auth.tenantId) {
          permit.bindTenant(auth.tenantId);
        }
        const context: RequestContext = {
          metadata,
          blobStore,
          maxBodyBytes: Math.min(policy.maxBodyBytes, deps.maxBodyBytes ?? Number.MAX_SAFE_INTEGER),
          maxBlobBodyBytes: deps.maxBlobBodyBytes,
          receiptedAttachEnabled: deps.receiptedAttachEnabled,
          declaredBodyBytes,
          requestSignal: abort.signal,
          permit,
          policy,
          events: telemetry,
          runtime,
          browseIndexes,
          historyStores: deps.historyStores,
          historyCopyTimeoutMs: deps.historyCopyTimeoutMs,
        };
        await routeRequest(req, res, context, auth, url, parts, deps.releaseIdentity);
      } finally {
        // Permits release when the WORK is done (success, error, or abort-
        // unblocked), never merely because the socket closed: lost-client
        // durable work retains its permit until it settles.
        permit.release();
        runtime.drainSignal.removeEventListener("abort", onDrainAbort);
        res.removeListener("close", onClientGone);
      }
    } catch (error) {
      sendError(res, error, telemetry);
    } finally {
      finishRequest();
    }
  });
  const httpDefenses = resolveHttpDefenses(deps.httpDefenses);
  server.headersTimeout = httpDefenses.headersTimeoutMs;
  server.requestTimeout = httpDefenses.requestTimeoutMs;
  server.keepAliveTimeout = httpDefenses.keepAliveTimeoutMs;
  server.maxRequestsPerSocket = httpDefenses.maxRequestsPerSocket;
  server.maxConnections = httpDefenses.maxConnections;
  runtime.attachServer(server);
  return server;
}

// Transport defenses: bounded header/request/keepalive clocks, bounded
// requests per keepalive socket, bounded concurrent connections. Validated at
// construction so a typo can never silently disable a bound.
function resolveHttpDefenses(defenses?: HttpServerDefenses): Required<HttpServerDefenses> {
  const resolved: Required<HttpServerDefenses> = {
    headersTimeoutMs: validatedDefense(defenses?.headersTimeoutMs ?? 30_000, "headersTimeoutMs"),
    requestTimeoutMs: validatedDefense(defenses?.requestTimeoutMs ?? 300_000, "requestTimeoutMs"),
    keepAliveTimeoutMs: validatedDefense(defenses?.keepAliveTimeoutMs ?? 5_000, "keepAliveTimeoutMs"),
    maxRequestsPerSocket: validatedDefense(
      defenses?.maxRequestsPerSocket ?? 1000,
      "maxRequestsPerSocket"
    ),
    maxConnections: validatedDefense(defenses?.maxConnections ?? 1024, "maxConnections"),
  };
  if (
    !(
      resolved.keepAliveTimeoutMs < resolved.headersTimeoutMs &&
      resolved.headersTimeoutMs <= resolved.requestTimeoutMs
    )
  ) {
    throw new Error(
      "HTTP defenses must satisfy keepAliveTimeoutMs < headersTimeoutMs <= requestTimeoutMs."
    );
  }
  return resolved;
}

function validatedDefense(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`HTTP defense ${name} must be a positive safe integer.`);
  }
  return value;
}

// requestTargetsV1 matches the /v1 path prefix on the RAW request target
// (before percent-decoding or admission), so the min-CLI-version header rides
// even the responses produced before routing (draining, 401, 429).
function requestTargetsV1(url: string | undefined): boolean {
  if (!url) {
    return false;
  }
  const queryStart = url.indexOf("?");
  const pathname = queryStart === -1 ? url : url.slice(0, queryStart);
  return pathname === "/v1" || pathname.startsWith("/v1/");
}

// decodePathParts turns malformed percent-escapes into a typed 400 instead of
// letting decodeURIComponent's URIError surface as a 500 internal error.
function decodePathParts(pathname: string): string[] {
  try {
    return pathname
      .split("/")
      .filter(Boolean)
      .map((part) => decodeURIComponent(part));
  } catch {
    throw new VolumeApiError("VOLUME_PATH_INVALID", "Request path contains invalid percent-escapes.", 400);
  }
}

function normalizeTelemetryMethod(
  method: string | undefined
): "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "other" {
  switch (method) {
    case "GET":
    case "POST":
    case "PUT":
    case "DELETE":
    case "HEAD":
    case "OPTIONS":
    case "PATCH":
      return method;
    default:
      return "other";
  }
}

// routePolicyFor maps a request to its audited resource policy BEFORE any body
// byte is read. Unknown routes admit under the small control policy and then
// 404 in the dispatcher without reading a body.
function routePolicyFor(
  policies: ReturnType<typeof resolveRoutePolicies>,
  method: string,
  parts: string[]
): RoutePolicy {
  if (parts[0] !== "v1") {
    return policies.control;
  }
  const resource = parts[1];
  const action = parts[3];
  if (resource === "volumes" && method === "POST") {
    if (action === "attach" || action === "attach-receipted") {
      return policies.attach;
    }
    if (action === "grep") {
      return policies.grep;
    }
  }
  if (resource === "volumes" && method === "GET" && action === "wait-head") {
    return policies.waitHead;
  }
  if (method === "GET" && resource === "volumes") {
    if (action === "status" || action === "manifest-diff" || action === "tree" || action === "file") {
      return policies.manifestRead;
    }
  }
  if (method === "GET" && resource === "commits" && action === "manifest") {
    return policies.manifestRead;
  }
  if (resource === "attach-sessions" && method === "POST") {
    if (action === "commit" || action === "commit-summary") {
      return policies.commitFull;
    }
    if (action === "commit-delta-summary") {
      return policies.commitDelta;
    }
  }
  if (resource === "blobs") {
    if (parts.length === 3 && parts[2] === "batch") {
      return policies.blobBatchJson;
    }
    if (parts.length === 3 && parts[2] === "batch-binary") {
      return policies.blobBatchBinary;
    }
    if (method === "POST" && parts.length === 3 && parts[2] === "probe") {
      // The probe schema admits 4096 digests (~300 KiB) — more than the
      // generic control body budget.
      return policies.blobProbe;
    }
    if (method === "PUT") {
      return policies.blob;
    }
    if (method === "GET") {
      // Downloads carry the streaming charge model (window-only reserve,
      // resident responses charged at serve time), so they admit under their
      // own policy instead of sharing the upload reservation.
      return policies.blobRead;
    }
  }
  if (resource === "history" && parts[2] === "objects" && (method === "GET" || method === "HEAD")) {
    return policies.historyObject;
  }
  return policies.control;
}

// Durable effects (attach, commit, detach, blob recording, provisioning) are
// wrapped so a drain waits for anything already dispatched — a lost client
// never turns a dispatched commit into a stranded one. Reads are untouched.
const trackedEffectMethods = new Set<PropertyKey>([
  "createVolume",
  "retireVolume",
  "attachVolume",
  "renewLease",
  "checkout",
  "checkin",
  "commit",
  "commitSummary",
  "commitDeltaSummary",
  "detach",
  "snapshot",
  "snapshotCut",
  "createBranch",
  "createBranchFromCut",
  "forkSnapshot",
  "recordBlobs",
  "deleteBlobRecord",
  "createTenant",
  "createTenantToken",
  "addBlobRefs",
]);

function withTrackedEffects(metadata: MetadataRepository, runtime: VolumeApiRuntime): MetadataRepository {
  return new Proxy(metadata, {
    get(target, property) {
      const value = Reflect.get(target, property, target) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      const method = value as (...args: unknown[]) => unknown;
      if (!trackedEffectMethods.has(property)) {
        return method.bind(target);
      }
      return (...args: unknown[]) =>
        runtime.trackEffect(Promise.resolve(method.apply(target, args)));
    },
  });
}

function resolveRequestId(req: IncomingMessage): string {
  const incoming = req.headers["x-request-id"];
  const raw = Array.isArray(incoming) ? incoming[0] : incoming;
  // Bounded and sanitized: a hostile header cannot inject log/label content.
  if (raw && /^[A-Za-z0-9._-]{1,64}$/.test(raw)) {
    return raw;
  }
  return randomUUID();
}

async function routeRequest(
  req: IncomingMessage,
  res: ServerResponse,
  deps: RequestContext,
  auth: AuthContext,
  url: URL,
  parts: string[],
  releaseIdentity: Omit<ReleaseIdentity, "serverTimeMs"> | undefined
): Promise<void> {
  const method = req.method ?? "GET";
  if (parts[0] !== "v1") {
    sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Route not found." } });
    return;
  }

  if (method === "POST" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "exec") {
    // The stable route remains as an explicit retirement contract. Refuse
    // before credential-role dispatch, ownership lookup, body parsing, or
    // volume access: this process contains no command/materialization path.
    sendJson(res, 410, {
      error: {
        code: "VOLUME_EXEC_RETIRED",
        message:
          "Server-side command execution has been retired from the Volume API. Mount the volume and run the command locally.",
      },
    });
    return;
  }

  // Runtime credentials are volume-pinned child identities: tenant-scoped
  // reads (GET/HEAD) plus EXACTLY the authority lifecycle the managed vcs
  // child drives against its own volume — attach, session detach, and
  // writer-lease renewal for rows of the pinned volume. Everything else
  // refuses before the ownership guard (which still runs for tenant
  // scoping). A volume route addressing a different volume is invisible
  // (404, no cross-volume enumeration).
  if (auth.runtimeCredential) {
    if (method !== "GET" && method !== "HEAD") {
      const allowed = await runtimeCredentialLifecycleRouteAllowed(deps, auth, method, parts);
      if (!allowed) {
        sendJson(res, 403, {
          error: {
            code: "VOLUME_READ_ONLY_CREDENTIAL",
            message:
              "This runtime credential authorizes reads and its own volume's authority lifecycle only.",
          },
        });
        return;
      }
    }
    if (
      auth.credentialVolumeId &&
      parts[1] === "volumes" &&
      parts.length > 2 &&
      parts[2] !== auth.credentialVolumeId
    ) {
      sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Not found." } });
      return;
    }
  }

  // Centralised tenant authorization: every resource addressed by a route must
  // belong to the caller's tenant (admin routes require the admin token). This runs
  // before any handler, so no route can be reached without an ownership check.
  const denied = await guardTenantAccess(deps, auth, method, parts);
  if (denied) {
    sendJson(res, denied.status, denied.body);
    return;
  }

  if (method === "GET" && parts.length === 2 && parts[1] === "release-identity") {
    // Any authenticated caller (tenant or admin) may read the deployment
    // identity; it names the build, never tenant data. no-store keeps pinning
    // checks honest across intermediaries.
    res.setHeader("cache-control", "no-store");
    if (!releaseIdentity) {
      sendJson(res, 404, {
        error: {
          code: releaseIdentityErrorCode,
          message: "Release identity is not configured for this deployment.",
        },
      });
      return;
    }
    sendJson(res, 200, { ...releaseIdentity, serverTimeMs: Date.now() });
    return;
  }

  if (parts[1] === "history") {
    // Exact PFT2 history serving: DB proof first, verified object reads only.
    if (!auth.tenantId) {
      sendJson(res, 403, tenantRequired().body);
      return;
    }
    await routeHistoryServingRequest(
      req,
      res,
      {
        metadata: deps.metadata,
        stores: deps.historyStores,
        requestSignal: deps.requestSignal,
        events: deps.events,
        ...(deps.historyCopyTimeoutMs !== undefined
          ? { copyTimeoutMs: deps.historyCopyTimeoutMs }
          : {}),
      },
      auth.tenantId,
      url,
      parts
    );
    return;
  }

  if (parts[1] === "admin" && parts[2] === "history") {
    // Manual drives of the journal-bounding HistoryCut machinery (create
    // recovery cut, poll status, adopt). Admin-gated by guardTenantAccess
    // above; the database owns idempotency via caller operation ids.
    await routeAdminHistoryRequest(
      req,
      res,
      { metadata: deps.metadata, maxBodyBytes: deps.maxBodyBytes },
      url,
      parts
    );
    return;
  }

  if (method === "POST" && parts.length === 3 && parts[1] === "admin" && parts[2] === "tenants") {
    // Provision a tenant and issue a bearer token (returned once, plaintext). Only
    // the token's sha256 is stored. Admin-gated by guardTenantAccess.
    const raw = (await readJson(req, deps)) as { tenantId?: unknown; token?: unknown; label?: unknown };
    const tenantId =
      typeof raw.tenantId === "string" && raw.tenantId ? raw.tenantId : `tnt_${randomUUID()}`;
    const token =
      typeof raw.token === "string" && raw.token ? raw.token : randomBytes(32).toString("hex");
    await deps.metadata.createTenant(tenantId);
    await deps.metadata.createTenantToken(
      Object.assign(
        { tenantId, tokenHash: sha256Hex(token) },
        typeof raw.label === "string" ? { label: raw.label } : {}
      )
    );
    sendJson(res, 201, { tenantId, token });
    return;
  }

  if (method === "POST" && parts.length === 3 && parts[1] === "admin" && parts[2] === "gc") {
    const raw = (await readJson(req, deps)) as { graceMs?: unknown; dryRun?: unknown };
    const options: { graceMs?: number; dryRun?: boolean } = { dryRun: raw.dryRun === true };
    if (typeof raw.graceMs === "number") {
      options.graceMs = raw.graceMs;
    }
    const report = await runGc(deps.metadata, deps.blobStore, options);
    sendJson(res, 200, report);
    return;
  }

  if (method === "GET" && parts.length === 3 && parts[1] === "admin" && parts[2] === "integrity") {
    // Read-only referenced-blob existence walk (the retired volume-worker's
    // integrity job). Admin-gated by guardTenantAccess above.
    if (!deps.metadata.listCommits) {
      sendJson(res, 501, {
        error: {
          code: "INTEGRITY_UNSUPPORTED",
          message: "This repository does not support commit listing.",
        },
      });
      return;
    }
    const report = await runIntegrityCheck({
      metadata: deps.metadata,
      blobStore: deps.blobStore,
    });
    sendJson(res, 200, report);
    return;
  }

  if (method === "POST" && parts.length === 2 && parts[1] === "volumes") {
    const body = createVolumeRequestSchema.parse(await readJson(req, deps));
    // tenantId is derived from the authenticated credential: a tenant token may omit
    // it (defaults to its own tenant) but never names another tenant; the admin
    // token carries no tenant, so it must name one explicitly.
    let tenantId: string;
    if (auth.tenantId) {
      if (body.tenantId && body.tenantId !== auth.tenantId) {
        sendJson(res, 403, {
          error: {
            code: "VOLUME_TENANT_MISMATCH",
            message: "tenantId does not match the authenticated tenant.",
          },
        });
        return;
      }
      tenantId = auth.tenantId;
    } else {
      if (!body.tenantId) {
        sendJson(res, 400, {
          error: {
            code: "VOLUME_TENANT_ID_REQUIRED",
            message: "tenantId is required when creating a volume with the admin token.",
          },
        });
        return;
      }
      tenantId = body.tenantId;
    }
    // Two births (managed): a journal-born volume's branch is INSERTed
    // managed_journal — the managed authority's first PFJ3 claim starts the
    // journal from the empty genesis head (replay is immutable base +
    // journal suffix; no generation row exists here). The default keeps the
    // base-authoring shape: a legacy_manifest branch whose committed base is
    // authored through attach-session manifest commits (adopt) and enters
    // journal service through the 013 conversion.
    const result = await deps.metadata.createVolume(
      Object.assign(
        { tenantId, branchName: body.branchName, managed: body.managed },
        body.volumeId ? { volumeId: body.volumeId } : {}
      )
    );
    sendJson(res, 201, result);
    return;
  }

  if (method === "GET" && parts.length === 2 && parts[1] === "volumes") {
    // Tenant tokens always list their own tenant; the admin token must name one.
    const tenantId = auth.tenantId ?? url.searchParams.get("tenantId");
    if (!tenantId) {
      sendJson(res, 400, {
        error: {
          code: "VOLUME_TENANT_ID_REQUIRED",
          message: "tenantId query parameter is required when listing with the admin token.",
        },
      });
      return;
    }
    const entries = await deps.metadata.listVolumes({
      tenantId,
      limit: parseListLimit(url.searchParams.get("limit"), 100),
    });
    sendJson(res, 200, {
      volumes: entries.map((entry) => ({
        volumeId: entry.volume.id,
        tenantId: entry.volume.tenantId,
        createdAtMs: entry.volume.createdAt,
        branches: entry.branches.map((branch) => ({
          name: branch.name,
          headCommitId: branch.headCommitId,
        })),
      })),
    });
    return;
  }

  if (method === "DELETE" && parts.length === 3 && parts[1] === "volumes") {
    // Receipted volume retirement. guardTenantAccess above resolved
    // ownership: unknown and foreign ids answered the non-enumerating 404
    // before this handler ran, while the owner's LIVE and RETIRED volumes
    // both reach here (a retired one only on repositories with the receipt
    // lookup) — HTTP DELETE is idempotent, and the hosted control plane's
    // caller-keyed ledger recovers a lost/crashed response by replaying the
    // same key, so a replay must collect the original receipt instead of a
    // 404. After the flip every per-volume plane (attach, lease renewal,
    // grep, branch/snapshot create+list, commit/status/head/wait-head/
    // tree/file/manifest-diff reads, activate-journal, and forks from this
    // volume's snapshots) refuses through the same resolvers; live mounts
    // lose access as their leases and credentials expire — no authority is
    // force-detached. Storage reclamation is deliberately deferred (no GC
    // here) — but HISTORY WORK is not: once the receipt is durable,
    // pfh.volume_retire_cleanup (migration 022) releases the volume's
    // conversion/adoption consumer pins and cancels its non-terminal cuts so
    // no pending cut can retry forever against a retired volume. The cascade
    // re-runs on every replay (idempotently answering zero counts), which is
    // exactly what heals a crash between the flip and the first cleanup.
    if (!auth.tenantId) {
      sendJson(res, 403, tenantRequired().body);
      return;
    }
    if (!deps.metadata.retireVolume) {
      // Mirrors the hosted control plane's own "no retirement surface
      // upstream" answer: typed and loud, never a silent 404.
      sendJson(res, 501, {
        error: {
          code: "VOLUME_RETIREMENT_UNSUPPORTED",
          message: "Volume retirement is not supported by this repository (migration 021 required).",
        },
      });
      return;
    }
    const volumeId = parts[2] ?? "";
    const retired = await deps.metadata.retireVolume({ volumeId, tenantId: auth.tenantId });
    const receipt =
      retired ??
      (deps.metadata.retiredVolumeReceipt
        ? await deps.metadata.retiredVolumeReceipt({ volumeId, tenantId: auth.tenantId })
        : null);
    if (!receipt) {
      sendJson(res, 404, notOwned().body);
      return;
    }
    // The retirement receipt is durable once the flip (or its stored replay
    // answer) is in hand; the history cascade runs strictly AFTER it so the
    // flip is never coupled to cleanup. Tracked like every other durable
    // effect: a drain waits for a dispatched cleanup instead of stranding a
    // half-cancelled volume.
    const history = (deps.metadata as { history?: PostgresHistoryRepository }).history;
    if (history) {
      const cleanup = await deps.runtime.trackEffect(
        history.volumeRetireCleanup({
          tenantId: auth.tenantId,
          volumeId: receipt.volumeId,
        })
      );
      console.log(`volume-api: volume retirement history cleanup ${JSON.stringify(cleanup)}`);
    }
    // The response is EXACTLY the receipt the hosted control plane's ledger
    // validates and persists ({volumeId, retiredAt}) — operational detail
    // like cleanup counts lives in the log line above, never in the receipt
    // (the ledger's finalize mutation fails closed on unknown fields).
    sendJson(res, 200, {
      volumeId: receipt.volumeId,
      retiredAt: new Date(receipt.retiredAtMs).toISOString(),
    });
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "commits") {
    const commits = await deps.metadata.listCommitHistory({
      tenantId: tenantIdForScopedRoute(auth),
      volumeId: parts[2] ?? "",
      branchName: url.searchParams.get("branch") || "main",
      limit: parseListLimit(url.searchParams.get("limit"), 50),
    });
    if (!commits) {
      sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Volume not found." } });
      return;
    }
    sendJson(res, 200, {
      commits: commits.map((commit) =>
        Object.assign(
          {
            id: commit.id,
            treeHash: commit.treeHash,
            createdAtMs: commit.createdAt,
            mutationCount: commit.mutationCount,
            byteCount: commit.byteCount,
          },
          commit.parentCommitId ? { parentCommitId: commit.parentCommitId } : {},
          // Additive discriminator: pft2 history commits carry the stored
          // content-addressed root identity as their treeHash.
          commit.treeHash.startsWith("pft2:") ? { commitKind: "pft2" } : {}
        )
      ),
    });
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "status") {
    // Manifest reads answer only while the branch is manifest-headed: a
    // journal-served branch's manifest head is stale truth.
    await gateBranchAction(
      deps,
      tenantIdForScopedRoute(auth),
      "legacy_manifest_read",
      parts[2] ?? "",
      url.searchParams.get("branch") || "main"
    );
    const result = await deps.metadata.getStatus({
      tenantId: tenantIdForScopedRoute(auth),
      volumeId: parts[2] ?? "",
      branchName: url.searchParams.get("branch") || "main",
    });
    if (!result) {
      sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Volume not found." } });
      return;
    }
    sendJson(res, 200, result);
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "head") {
    await gateBranchAction(
      deps,
      tenantIdForScopedRoute(auth),
      "legacy_manifest_read",
      parts[2] ?? "",
      url.searchParams.get("branch") || "main"
    );
    const result = await deps.metadata.getHead({
      tenantId: tenantIdForScopedRoute(auth),
      volumeId: parts[2] ?? "",
      branchName: url.searchParams.get("branch") || "main",
    });
    if (!result) {
      sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Volume not found." } });
      return;
    }
    sendJson(res, 200, result);
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "wait-head") {
    const afterCommitId = url.searchParams.get("afterCommitId");
    if (!afterCommitId) {
      sendJson(res, 400, {
        error: {
          code: "VOLUME_AFTER_COMMIT_REQUIRED",
          message: "afterCommitId query parameter is required.",
        },
      });
      return;
    }
    await gateBranchAction(
      deps,
      tenantIdForScopedRoute(auth),
      "legacy_manifest_read",
      parts[2] ?? "",
      url.searchParams.get("branch") || "main"
    );
    const timeoutMs = parseWaitTimeoutMs(url.searchParams.get("timeoutMs"));
    const result = await waitForHead(deps.metadata, {
      tenantId: tenantIdForScopedRoute(auth),
      volumeId: parts[2] ?? "",
      branchName: url.searchParams.get("branch") || "main",
      afterCommitId,
      timeoutMs,
      // A disconnected client (or a drain) releases the wait immediately —
      // on Postgres that returns the LISTEN connection to the pool.
      signal: deps.requestSignal,
    });
    if (!result) {
      sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Volume not found." } });
      return;
    }
    sendJson(res, 200, {
      ...result,
      changed: result.branch.headCommitId !== afterCommitId,
    });
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "manifest-diff") {
    const baseCommitId = url.searchParams.get("baseCommitId");
    if (!baseCommitId) {
      sendJson(res, 400, {
        error: {
          code: "VOLUME_BASE_COMMIT_REQUIRED",
          message: "baseCommitId query parameter is required.",
        },
      });
      return;
    }
    await gateBranchAction(
      deps,
      tenantIdForScopedRoute(auth),
      "legacy_manifest_read",
      parts[2] ?? "",
      url.searchParams.get("branch") || "main"
    );
    const result = await deps.metadata.getManifestDiff({
      tenantId: tenantIdForScopedRoute(auth),
      volumeId: parts[2] ?? "",
      branchName: url.searchParams.get("branch") || "main",
      baseCommitId,
      rootPath: url.searchParams.get("rootPath") || "",
    });
    if (!result) {
      sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Volume not found." } });
      return;
    }
    sendJson(res, 200, result);
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "tree") {
    const pft2 = await resolvePinnedPft2Commit(deps, auth, parts[2] ?? "", url);
    if (pft2) {
      const result = await browsePft2Tree(pft2.context, {
        volumeId: parts[2] ?? "",
        branchName: pft2.branchName,
        commitId: pft2.commitId,
        treeHash: pft2.treeHash,
        path: volumePathSchema.parse(url.searchParams.get("path") ?? ""),
        url,
      });
      sendJson(res, 200, result);
      return;
    }
    // Pinned commits are immutable reads (never mode-gated); branch-head
    // browse serves the manifest head and refuses journal-served branches
    // like the other manifest head reads.
    if (!url.searchParams.get("commit")) {
      await gateBranchAction(
        deps,
        tenantIdForScopedRoute(auth),
        "legacy_manifest_read",
        parts[2] ?? "",
        url.searchParams.get("branch") || "main"
      );
    }
    const result = await browseVolumeTree(
      deps,
      tenantIdForScopedRoute(auth),
      parts[2] ?? "",
      url
    );
    sendJson(res, 200, result);
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "file") {
    const pft2 = await resolvePinnedPft2Commit(deps, auth, parts[2] ?? "", url);
    if (pft2) {
      await servePft2File(pft2.context, req, res, {
        commitId: pft2.commitId,
        path: volumePathSchema.parse(url.searchParams.get("path") ?? ""),
        url,
      });
      return;
    }
    if (!url.searchParams.get("commit")) {
      await gateBranchAction(
        deps,
        tenantIdForScopedRoute(auth),
        "legacy_manifest_read",
        parts[2] ?? "",
        url.searchParams.get("branch") || "main"
      );
    }
    await serveVolumeFile(
      deps,
      req,
      res,
      tenantIdForScopedRoute(auth),
      parts[2] ?? "",
      url
    );
    return;
  }

  if (
    method === "POST" &&
    parts.length === 4 &&
    parts[1] === "volumes" &&
    parts[3] === "attach-receipted"
  ) {
    if (deps.receiptedAttachEnabled !== true) {
      sendJson(res, 426, {
        error: {
          code: "VOLUME_ATTACH_RECEIPTS_UNAVAILABLE",
          message: "Receipted attach is not enabled on this server version.",
        },
      });
      return;
    }
    if (!auth.tenantId) {
      sendJson(res, 403, tenantRequired().body);
      return;
    }
    const body = attachVolumeReceiptedRequestSchema.parse(await readJson(req, deps));
    const result = await deps.metadata.attachVolume(
      Object.assign(
        {
          tenantId: auth.tenantId,
          volumeId: parts[2] ?? "",
          branchName: body.branch,
          mode: body.mode,
          shared: body.shared,
          rootPath: body.rootPath,
          holderId: body.holderId,
          leaseTtlMs: body.leaseTtlMs,
          prefetchPaths: body.prefetchPaths,
          operationId: body.operationId,
        },
        body.clientInfo ? { clientInfo: body.clientInfo } : {}
      )
    );
    sendJson(res, 200, result);
    return;
  }

  if (
    method === "POST" &&
    parts.length === 4 &&
    parts[1] === "volumes" &&
    parts[3] === "activate-journal"
  ) {
    // Journal activation: converge a base-authored branch into managed
    // journal service (the 013 conversion). Idempotent and poll-driven —
    // adopt calls this after its final base commit and polls until the
    // branch answers "active", after which mounting works. The response is
    // enriched with the top-level cut observability fields (cutState /
    // attemptCount / lastError — a fixed CLI contract) and a terminally
    // failed/canceled cut is answered as a terminal "failed" activation so
    // pollers stop instead of watching an eternal "converting".
    if (!auth.tenantId) {
      sendJson(res, 403, tenantRequired().body);
      return;
    }
    if (!deps.metadata.activateJournalBranch) {
      sendJson(res, 503, {
        error: {
          code: "VOLUME_ACTIVATION_UNAVAILABLE",
          message: "This metadata repository cannot drive journal activation.",
        },
      });
      return;
    }
    const body = activateJournalRequestSchema.parse(await readJson(req, deps));
    const status = await deps.metadata.activateJournalBranch({
      tenantId: auth.tenantId,
      volumeId: parts[2] ?? "",
      branchName: body.branch,
    });
    sendJson(res, 200, activationStatusResponse(status));
    return;
  }

  if (method === "POST" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "attach") {
    const body = attachVolumeRequestSchema.parse(await readJson(req, deps));
    // Route-level matrix gate in ADDITION to the repository's own
    // authoring-only enforcement for non-receipted attach: defense in depth,
    // typed early.
    await gateBranchAction(
      deps,
      tenantIdForScopedRoute(auth),
      "legacy_attach",
      parts[2] ?? "",
      body.branch
    );
    const result = await deps.metadata.attachVolume(
      Object.assign(
        {
          tenantId: tenantIdForScopedRoute(auth),
          volumeId: parts[2] ?? "",
          branchName: body.branch,
          mode: body.mode,
          shared: body.shared,
          rootPath: body.rootPath,
          holderId: body.holderId,
          leaseTtlMs: body.leaseTtlMs,
          prefetchPaths: body.prefetchPaths,
        },
        body.clientInfo ? { clientInfo: body.clientInfo } : {}
      )
    );
    sendJson(res, 200, result);
    return;
  }

  if (
    method === "POST" &&
    parts.length === 4 &&
    parts[1] === "attach-sessions" &&
    parts[3] === "commit"
  ) {
    await gateSessionAction(deps, "legacy_manifest_mutation", parts[2] ?? "");
    const body = commitRequestSchema.parse(await readJson(req, deps));
    await assertManifestBlobsExist(deps, body.manifest.entries, auth.tenantId);
    const result = await deps.metadata.commit({
      attachSessionId: parts[2] ?? "",
      ...body,
    });
    sendJson(res, 200, result);
    return;
  }

  if (
    method === "POST" &&
    parts.length === 4 &&
    parts[1] === "attach-sessions" &&
    parts[3] === "commit-summary"
  ) {
    await gateSessionAction(deps, "legacy_manifest_mutation", parts[2] ?? "");
    const body = commitRequestSchema.parse(await readJson(req, deps));
    await assertManifestBlobsExist(deps, body.manifest.entries, auth.tenantId);
    const result = await deps.metadata.commitSummary({
      attachSessionId: parts[2] ?? "",
      ...body,
    });
    sendJson(res, 200, result);
    return;
  }

  if (
    method === "POST" &&
    parts.length === 4 &&
    parts[1] === "attach-sessions" &&
    parts[3] === "commit-delta-summary"
  ) {
    await gateSessionAction(deps, "legacy_manifest_mutation", parts[2] ?? "");
    const body = commitDeltaRequestSchema.parse(await readJson(req, deps));
    await assertManifestBlobsExist(
      deps,
      [...body.diff.added, ...body.diff.changed],
      auth.tenantId
    );
    const result = await deps.metadata.commitDeltaSummary({
      attachSessionId: parts[2] ?? "",
      ...body,
    });
    sendJson(res, 200, result);
    return;
  }

  if (
    method === "POST" &&
    parts.length === 4 &&
    parts[1] === "attach-sessions" &&
    parts[3] === "checkout"
  ) {
    await gateSessionAction(deps, "legacy_manifest_mutation", parts[2] ?? "");
    const body = checkoutRequestSchema.parse(await readJson(req, deps));
    const result = await deps.metadata.checkout({
      attachSessionId: parts[2] ?? "",
      leaseId: body.leaseId,
      fencingToken: body.fencingToken,
      path: body.path,
      recursive: body.recursive,
      force: body.force,
    });
    sendJson(res, 200, result);
    return;
  }

  if (
    method === "POST" &&
    parts.length === 4 &&
    parts[1] === "attach-sessions" &&
    parts[3] === "checkin"
  ) {
    await gateSessionAction(deps, "legacy_manifest_mutation", parts[2] ?? "");
    const body = checkinRequestSchema.parse(await readJson(req, deps));
    const result = await deps.metadata.checkin({
      attachSessionId: parts[2] ?? "",
      ...(body.delegationId ? { delegationId: body.delegationId } : {}),
      ...(body.path !== undefined ? { path: body.path } : {}),
    });
    sendJson(res, 200, result);
    return;
  }

  if (
    method === "GET" &&
    parts.length === 4 &&
    parts[1] === "attach-sessions" &&
    parts[3] === "delegations"
  ) {
    const delegations = await deps.metadata.listDelegations({
      tenantId: tenantIdForScopedRoute(auth),
      attachSessionId: parts[2] ?? "",
      includeReleased: url.searchParams.get("includeReleased") === "true",
    });
    sendJson(res, 200, { delegations });
    return;
  }

  if (
    method === "POST" &&
    parts.length === 4 &&
    parts[1] === "attach-sessions" &&
    parts[3] === "detach"
  ) {
    // Teardown is allowed in EVERY mode: refusing detach would leak
    // sessions/leases on journal-served branches.
    const body = detachRequestSchema.parse(await readJson(req, deps));
    const session = await deps.metadata.detach({
      attachSessionId: parts[2] ?? "",
      releaseLease: body.releaseLease,
    });
    sendJson(res, 200, { session });
    return;
  }

  if (method === "POST" && parts.length === 4 && parts[1] === "leases" && parts[3] === "renew") {
    // Lease renewal is required by both authoring mounts and the receipted
    // exact surface, so every mode allows it; the gated commit routes keep a
    // renewed authoring lease from minting writes on a journal-served branch.
    const body = renewLeaseRequestSchema.parse(await readJson(req, deps));
    const lease = await deps.metadata.renewLease({
      leaseId: parts[2] ?? "",
      fencingToken: body.fencingToken,
      leaseTtlMs: body.leaseTtlMs,
    });
    sendJson(res, 200, { lease });
    return;
  }

  if (method === "POST" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "snapshots") {
    const raw = await readJson(req, deps);
    const body = snapshotRequestSchema.parse(raw);
    // Additive optional field (the frozen schema strips unknown keys):
    // an explicit operationId makes cut-request retries exact-once.
    const rawOperationId = (raw as Record<string, unknown>).operationId;
    const operationId =
      rawOperationId !== undefined ? snapshotOperationIdSchema.parse(rawOperationId) : undefined;
    if (deps.metadata.snapshotCut && auth.tenantId) {
      // Cut-based capture: journal-served branches record an exact async
      // HistoryCut (state pending until the worker materializes it);
      // manifest-headed branches answer a born-ready commit-pinned record.
      const snapshot = await deps.metadata.snapshotCut(
        Object.assign(
          { volumeId: parts[2] ?? "", branchName: body.branch, tenantId: auth.tenantId },
          body.name ? { name: body.name } : {},
          operationId ? { operationId } : {}
        )
      );
      sendJson(res, 201, { snapshot });
      return;
    }
    const snapshot = await deps.metadata.snapshot(
      Object.assign(
        {
          tenantId: tenantIdForScopedRoute(auth),
          volumeId: parts[2] ?? "",
          branchName: body.branch,
        },
        body.name ? { name: body.name } : {}
      )
    );
    sendJson(res, 201, { snapshot });
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "snapshots") {
    const branchName = url.searchParams.get("branch") || undefined;
    if (deps.metadata.listSnapshotRecords) {
      const snapshots = await deps.metadata.listSnapshotRecords(
        Object.assign(
          { tenantId: tenantIdForScopedRoute(auth), volumeId: parts[2] ?? "" },
          branchName ? { branchName } : {}
        )
      );
      sendJson(res, 200, { snapshots });
      return;
    }
    const snapshots = await deps.metadata.listSnapshots(
      Object.assign(
        { tenantId: tenantIdForScopedRoute(auth), volumeId: parts[2] ?? "" },
        branchName ? { branchName } : {}
      )
    );
    sendJson(res, 200, { snapshots });
    return;
  }

  if (method === "DELETE" && parts.length === 5 && parts[1] === "volumes" && parts[3] === "snapshots") {
    // Named-snapshot release (migration 028): clears the label of this
    // volume's named READY cuts (releasing their snapshot consumers), so
    // they age out of the retention window and the ordinary GC sweep
    // collects their objects. The name segment arrives percent-decoded
    // (decodePathParts). Non-enumerating by construction: a repository
    // without the history surface, a name that cannot exist, and an
    // unknown name (PF007) all answer exactly the ownership guard's 404 —
    // deletion reveals nothing the guard does not.
    const history = (deps.metadata as { history?: PostgresHistoryRepository }).history;
    const name = parts[4] ?? "";
    if (!history || name.length === 0 || name.length > 256) {
      sendJson(res, 404, notOwned().body);
      return;
    }
    try {
      // Tracked like every other durable effect: a drain waits for a
      // dispatched release instead of stranding a half-cleared label.
      const released = await deps.runtime.trackEffect(
        history.releaseSnapshotCut({
          tenantId: tenantIdForScopedRoute(auth),
          volumeId: parts[2] ?? "",
          name,
        })
      );
      sendJson(res, 200, { released });
    } catch (error) {
      if ((error as { code?: unknown }).code === "PF007") {
        sendJson(res, 404, notOwned().body);
        return;
      }
      throw error;
    }
    return;
  }

  if (method === "POST" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "branches") {
    const body = createBranchRequestSchema.parse(await readJson(req, deps));
    if (body.fromSnapshotId && deps.metadata.resolveSnapshotSource) {
      const source = await deps.metadata.resolveSnapshotSource(body.fromSnapshotId);
      if (source?.kind === "cut") {
        assertCutBranchable(source.record);
        if (!deps.metadata.createBranchFromCut || !auth.tenantId) {
          sendJson(res, 403, tenantRequired().body);
          return;
        }
        const result = await deps.metadata.createBranchFromCut({
          volumeId: parts[2] ?? "",
          branchName: body.branchName,
          cutId: source.record.cutId ?? source.record.id,
          tenantId: auth.tenantId,
        });
        // Branch-from-cut heads are PFT2 commits: content-addressed roots
        // with no JSON manifest, so the head is a summary plus its kind.
        sendJson(res, 201, result);
        return;
      }
    }
    if (!body.fromSnapshotId && !body.fromSnapshotName) {
      // Branching from a LIVE manifest head requires an authoring branch.
      await gateBranchAction(
        deps,
        tenantIdForScopedRoute(auth),
        "legacy_manifest_mutation",
        parts[2] ?? "",
        body.fromBranch
      );
    }
    // An explicitly named snapshot is an immutable, commit-pinned root. Its
    // reachability is resolved inside createBranch against this exact volume
    // and source branch; the source branch's later live mode is irrelevant.
    const result = await deps.metadata.createBranch({
      tenantId: tenantIdForScopedRoute(auth),
      volumeId: parts[2] ?? "",
      branchName: body.branchName,
      ...(body.fromSnapshotId ? { fromSnapshotId: body.fromSnapshotId } : {}),
      ...(body.fromSnapshotName ? { fromSnapshotName: body.fromSnapshotName } : {}),
      fromBranch: body.fromBranch,
    });
    sendJson(res, 201, result);
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "branches") {
    const branches = await deps.metadata.listBranches({
      tenantId: tenantIdForScopedRoute(auth),
      volumeId: parts[2] ?? "",
    });
    sendJson(res, 200, { branches });
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "delegations") {
    const delegations = await deps.metadata.listDelegations({
      tenantId: tenantIdForScopedRoute(auth),
      volumeId: parts[2] ?? "",
      branchName: url.searchParams.get("branch") || "main",
      includeReleased: url.searchParams.get("includeReleased") === "true",
    });
    sendJson(res, 200, { delegations });
    return;
  }

  if (method === "POST" && parts.length === 4 && parts[1] === "volumes" && parts[3] === "grep") {
    const body = grepRequestSchema.parse(await readJson(req, deps));
    const volumeId = parts[2] ?? "";
    const tenantId = tenantIdForScopedRoute(auth);
    const dispatch = await resolveMaterializationDispatch(deps, tenantId, volumeId, body.branch);
    if (dispatch === "legacy_manifest") {
      const result = await grepVolume(deps, tenantId, volumeId, body);
      sendJson(res, 200, result);
      return;
    }
    if (!auth.tenantId) {
      sendJson(res, 403, tenantRequired().body);
      return;
    }
    const result = await grepOnCutBranch(deps, auth.tenantId, volumeId, body, dispatch);
    sendJson(res, 200, result);
    return;
  }

  if (method === "POST" && parts.length === 4 && parts[1] === "snapshots" && parts[3] === "fork") {
    const raw = await readJson(req, deps);
    const body = forkRequestSchema.parse(raw);
    // Additive optional field (the frozen schema strips unknown keys): an
    // explicit operationId makes fork retries exact-once.
    const rawOperationId = (raw as Record<string, unknown>).operationId;
    const operationId =
      rawOperationId !== undefined ? snapshotOperationIdSchema.parse(rawOperationId) : undefined;
    const tenantId = auth.tenantId;
    if (!tenantId) {
      sendJson(res, 403, tenantRequired().body);
      return;
    }
    if (deps.metadata.resolveSnapshotSource) {
      const source = await deps.metadata.resolveSnapshotSource(parts[2] ?? "");
      if (source?.kind === "cut") {
        assertCutBranchable(source.record);
        if (!deps.metadata.forkVolumeFromCut) {
          // A repository without the fork-provenance migration (018) cannot
          // birth a destination the serving proof can open; refusing typed
          // here is honest — the alternative would be a bricked volume.
          sendJson(res, 409, {
            error: {
              code: "HISTORY_FORK_UNSUPPORTED",
              message:
                "Cross-volume fork of a journal-era cut is not supported by this repository; branch from the cut within its volume instead.",
            },
          });
          return;
        }
        // Cross-volume, zero-copy fork of the READY cut (migration 018):
        // the destination volume is born managed (journal-native), its
        // default branch serving the cut's immutable PFT2 root, with the
        // shared history objects GC-pinned by the destination's fork cut
        // consumer. The head is a manifest-free PFT2 summary plus its kind,
        // exactly like branch-from-cut answers; the first authority claim
        // proves the base through pfh.serving_base_prove's fork branch.
        const result = await deps.metadata.forkVolumeFromCut({
          cutId: source.record.cutId ?? source.record.id,
          tenantId,
          branchName: body.branchName,
          ...(body.volumeId ? { volumeId: body.volumeId } : {}),
          ...(operationId ? { operationId } : {}),
        });
        sendJson(res, 201, result);
        return;
      }
    }
    // The fork's new volume belongs to the authenticated tenant (the source
    // snapshot's ownership was already verified by the guard). The
    // destination is journal-born: its branch starts at the snapshot's
    // pinned manifest commit — the committed base its journal generation
    // starts from at first claim.
    const result = await deps.metadata.forkSnapshot(
      Object.assign(
        {
          snapshotId: parts[2] ?? "",
          tenantId,
          branchName: body.branchName,
        },
        body.volumeId ? { volumeId: body.volumeId } : {}
      )
    );
    sendJson(res, 201, result);
    return;
  }

  if (method === "GET" && parts.length === 4 && parts[1] === "commits" && parts[3] === "manifest") {
    const manifest = await deps.metadata.getManifest(parts[2] ?? "");
    if (!manifest) {
      sendJson(res, 404, { error: { code: "VOLUME_COMMIT_NOT_FOUND", message: "Commit not found." } });
      return;
    }
    sendJson(res, 200, { manifest });
    return;
  }

  if (method === "PUT" && parts.length === 3 && parts[1] === "blobs") {
    const digest = parts[2] as BlobDigest;
    const body = await readRaw(req, deps, blobBodyLimit(deps));
    const actualDigest = sha256Buffer(body);
    if (actualDigest !== digest) {
      sendJson(res, 400, {
        error: {
          code: "VOLUME_BLOB_DIGEST_MISMATCH",
          message: `Expected ${digest}, received ${actualDigest}.`,
        },
      });
      return;
    }
    const uploaded = await deps.blobStore.put(body, {
      digest,
      checkExisting: false,
      signal: deps.requestSignal,
    });
    await deps.metadata.recordBlobs([
      Object.assign(
        {
          digest,
          size: uploaded.blob.size,
        },
        uploaded.blob.storageKey ? { storageKey: uploaded.blob.storageKey } : {}
      ),
    ]);
    // Proof of possession: uploading the verified bytes grants this tenant a
    // reference, which is what later authorizes reads and commits referencing it.
    if (auth.tenantId) {
      await deps.metadata.addBlobRefs(auth.tenantId, [digest]);
    }
    sendJson(res, 201, { blob: uploaded.blob });
    return;
  }

  if (method === "POST" && parts.length === 3 && parts[1] === "blobs" && parts[2] === "batch") {
    const body = uploadBlobBatchRequestSchema.parse(await readJson(req, deps));
    const blobs = await uploadBlobBatchEntries(
      deps,
      body.blobs.map((entry) => ({
        digest: entry.digest,
        bytes: Buffer.from(entry.bytesBase64, "base64"),
      })),
      auth.tenantId
    );
    sendBlobBatchResponse(res, url, blobs);
    return;
  }

  if (method === "POST" && parts.length === 3 && parts[1] === "blobs" && parts[2] === "batch-binary") {
    const blobs = await uploadBlobBatchEntries(
      deps,
      parseBlobBatchBinary(await readRaw(req, deps, blobBodyLimit(deps))),
      auth.tenantId
    );
    sendBlobBatchResponse(res, url, blobs);
    return;
  }

  if (method === "POST" && parts.length === 3 && parts[1] === "blobs" && parts[2] === "probe") {
    // Upload probe: which of these digests must the caller still upload? Consults
    // only the calling tenant's blob references (filterUnreferencedBlobs), never
    // global blob existence — a digest another tenant stored is still "missing",
    // so probing neither leaks cross-tenant content existence nor lets a caller
    // skip the proof-of-possession upload. The admin token carries no tenant and
    // references nothing, so every digest is missing.
    const body = blobProbeRequestSchema.parse(await readJson(req, deps));
    const missing = auth.tenantId
      ? await deps.metadata.filterUnreferencedBlobs(auth.tenantId, body.digests)
      : [...new Set(body.digests)];
    sendJson(res, 200, { missing });
    return;
  }

  if (method === "GET" && parts.length === 3 && parts[1] === "blobs") {
    const digest = parts[2] as BlobDigest;
    // Reference-checked read: a globally-deduplicated blob is readable only by a
    // tenant one of whose commits references it — possessing the digest is not
    // authorization. 404 (not 403) so cross-tenant existence is not revealed.
    if (!auth.tenantId || !(await deps.metadata.tenantReferencesBlob(auth.tenantId, digest))) {
      sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Not found." } });
      return;
    }
    await sendBlobDownload(req, res, deps, digest);
    return;
  }

  sendJson(res, 404, { error: { code: "VOLUME_NOT_FOUND", message: "Route not found." } });
}

// ---------------------------------------------------------------------------
// Blob downloads: the cold-replay feed for managed children and the mount
// read-miss path. Hot small blobs answer buffered from the memory cache;
// everything else streams from the store with backpressure, so a 64 MiB blob
// costs the fixed pipe window (blobStreamWindowBytes) instead of a resident
// copy per reader.
//
// Range policy (documented choice): only single byte ranges are served.
// bytes=a-b / bytes=a- / bytes=-n answer 206 with Content-Range; anything
// else carrying a Range header — multi-range, other units, malformed syntax —
// answers 416 like the browse file route (never ignored-as-200: a typo'd
// header silently downloading 64 MiB helps nobody). Unsatisfiable ranges
// carry `Content-Range: bytes */<total>`; malformed ones omit it because the
// total is unknown without opening the store.
// ---------------------------------------------------------------------------
async function sendBlobDownload(
  req: IncomingMessage,
  res: ServerResponse,
  deps: RequestContext,
  digest: BlobDigest
): Promise<void> {
  const range = parseBlobRangeHeader(req.headers.range);
  if (range === "invalid") {
    res.statusCode = 416;
    res.setHeader("content-length", "0");
    res.end();
    return;
  }

  let opened: BlobByteStream;
  try {
    opened = await openBlobByteStream(deps.blobStore, digest, {
      ...(range ? { range } : {}),
      signal: deps.requestSignal,
    });
  } catch (error) {
    if (error instanceof BlobRangeNotSatisfiableError) {
      res.statusCode = 416;
      res.setHeader("content-range", `bytes */${error.totalLength}`);
      res.setHeader("content-length", "0");
      res.end();
      return;
    }
    throw error;
  }

  try {
    // Blobs are immutable content-addressed bytes: the digest IS the entity
    // tag, and any HTTP cache between a mount/console and this origin may
    // hold them forever. Private (not public): the route is authenticated,
    // so shared caches must not serve one tenant's bytes to another —
    // browser and per-client caches still get the full year.
    const entityTag = `"${digest}"`;
    res.setHeader("etag", entityTag);
    res.setHeader("cache-control", "private, max-age=31536000, immutable");
    if (!range && req.headers["if-none-match"] === entityTag) {
      // Revalidation hit: no body, no resident-byte charge.
      res.statusCode = 304;
      res.end();
      opened.stream.destroy();
      return;
    }
    // Honest admission: a response that is RESIDENT in memory (cache hit or
    // buffered fallback) charges its actual byte length before headers go
    // out; a true stream is already covered by the policy's fixed window.
    if (opened.buffered) {
      deps.permit.chargeResponseBytes(opened.totalLength);
    }
    res.statusCode = range ? 206 : 200;
    res.setHeader("content-type", "application/octet-stream");
    res.setHeader("accept-ranges", "bytes");
    res.setHeader("content-length", String(Math.max(0, opened.end - opened.start + 1)));
    if (range) {
      res.setHeader("content-range", `bytes ${opened.start}-${opened.end}/${opened.totalLength}`);
    }
    // Status and headers go out immediately: a slow store must not delay the
    // client's view of the response shape (and every failure past this point
    // is a destroyed connection by design).
    res.flushHeaders();
    // pipeline owns backpressure AND teardown: a slow client parks the
    // transfer at the pipe window, a lost client destroys the source, and the
    // drain abort (requestSignal, the same point every read-only wait dies)
    // destroys the in-flight stream mid-transfer. A post-header failure
    // destroys the connection — the truthful incomplete-body signal.
    await pipeline(opened.stream, res, { signal: deps.requestSignal });
  } catch (error) {
    opened.stream.destroy();
    throw error;
  }
}

// Syntax-only single-range parser (RFC 9110). Resolution against the blob's
// size happens in the store (which is what knows the size); this stage only
// decides "no header" / "one well-formed range" / "416 material". The browse
// route's parser is not reused because it needs the size up front.
function parseBlobRangeHeader(
  header: string | undefined
): BlobRangeRequest | "invalid" | null {
  if (header === undefined) {
    return null;
  }
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!match) {
    return "invalid";
  }
  const [, rawStart, rawEnd] = match;
  if (rawStart === "" && rawEnd === "") {
    return "invalid";
  }
  if (rawStart === "") {
    const length = Number(rawEnd);
    if (!Number.isSafeInteger(length) || length <= 0) {
      return "invalid";
    }
    return { kind: "suffix", length };
  }
  const start = Number(rawStart);
  if (!Number.isSafeInteger(start)) {
    return "invalid";
  }
  if (rawEnd === "") {
    return { kind: "open", start };
  }
  const end = Number(rawEnd);
  if (!Number.isSafeInteger(end) || end < start) {
    return "invalid";
  }
  return { kind: "bounded", start, end };
}

// ---------------------------------------------------------------------------
// Branch-mode gates. Journal-capable repositories (those that resolve modes)
// gate every mutable manifest route through THE action matrix; a repository
// without mode resolution AND without journal capability is a pure manifest
// world where every branch is authoring-phase by construction. A repository
// that exposes journal state but cannot resolve modes fails closed.
// ---------------------------------------------------------------------------
async function gateBranchAction(
  deps: RequestContext,
  tenantId: string,
  action: BranchModeAction,
  volumeId: string,
  branchName: string
): Promise<void> {
  if (!deps.metadata.branchMode) {
    if (journalCapable(deps.metadata)) {
      throw branchModeCapabilityError();
    }
    return;
  }
  assertBranchModeAllows(
    action,
    await deps.metadata.branchMode({ tenantId, volumeId, branchName })
  );
}

// Session-addressed operations resolve their branch FIRST: an authoring
// session that predates a branch's journal birth must fail typed BEFORE
// possession reads or ref minting.
async function gateSessionAction(
  deps: RequestContext,
  action: BranchModeAction,
  attachSessionId: string
): Promise<void> {
  if (!deps.metadata.sessionBranchMode) {
    if (journalCapable(deps.metadata)) {
      throw branchModeCapabilityError();
    }
    return;
  }
  assertBranchModeAllows(action, await deps.metadata.sessionBranchMode(attachSessionId));
}

// Exact grep dispatch: resolves the authoritative branch mode and picks the
// immutable source through the materialization matrix.
// Same fail-closed capability rules as gateBranchAction: a pure-manifest
// repository serves the legacy path; a journal-capable repository without
// mode resolution refuses.
async function resolveMaterializationDispatch(
  deps: RequestContext,
  tenantId: string,
  volumeId: string,
  branchName: string
): Promise<MaterializationRoute> {
  if (!deps.metadata.branchMode) {
    if (journalCapable(deps.metadata)) {
      throw branchModeCapabilityError();
    }
    return "legacy_manifest";
  }
  return materializationRouteFor(
    await deps.metadata.branchMode({ tenantId, volumeId, branchName })
  );
}

function journalCapable(metadata: MetadataRepository): boolean {
  return typeof metadata.journalBinding === "function" || typeof metadata.snapshotCut === "function";
}

function branchModeCapabilityError(): VolumeApiError {
  return new VolumeApiError(
    "VOLUME_BRANCH_MODE_UNAVAILABLE",
    "This metadata repository cannot resolve authoritative branch modes; the route fails closed.",
    503
  );
}

// Pending and failed cuts cannot be branched, forked, or published.
function assertCutBranchable(record: SnapshotCutRecord): void {
  if (record.state === "ready") {
    return;
  }
  if (record.state === "failed" || record.state === "canceled") {
    throw new VolumeApiError(
      "HISTORY_CUT_FAILED",
      `This history cut is ${record.state} and can never be branched or forked.`,
      409
    );
  }
  throw new VolumeApiError(
    "HISTORY_CUT_NOT_READY",
    "This history cut has not materialized yet; retry once it is ready.",
    409
  );
}

interface ResolvedPft2Browse {
  context: Pft2ReadContext;
  commitId: string;
  branchName: string;
  treeHash: string;
}

// Browse dispatch for pft2 commits: only PINNED (?commit=) reads can name a
// pft2 commit — branch-head browse serves manifest heads (journal-served
// branches answer their committed history through pinned commits and cut
// records instead). Returns null for manifest commits so the existing browse
// path serves them unchanged.
async function resolvePinnedPft2Commit(
  deps: RequestContext,
  auth: AuthContext,
  volumeId: string,
  url: URL
): Promise<ResolvedPft2Browse | null> {
  const commitParam = url.searchParams.get("commit");
  if (!commitParam || !deps.metadata.commitKind || !deps.metadata.getCommitSummary || !auth.tenantId) {
    return null;
  }
  const history = (deps.metadata as { history?: PostgresHistoryRepository }).history;
  if (!history || !deps.historyStores) {
    return null;
  }
  const kind = await deps.metadata.commitKind(commitParam);
  if (kind !== "pft2") {
    return null;
  }
  // Volume scoping: a pinned commit must belong to the addressed volume —
  // the tenant guard proved volume ownership; this stops a commit id from
  // another of the same tenant's volumes being read through this URL. The
  // provenance read inside the pft2 path re-proves tenant scope in SQL.
  const summary = await deps.metadata.getCommitSummary(commitParam);
  if (!summary || summary.volumeId !== volumeId) {
    throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume, branch, or commit not found.", 404);
  }
  const branches = await deps.metadata.listBranches({ tenantId: auth.tenantId, volumeId });
  const branch = branches.find((candidate) => candidate.id === summary.branchId);
  return {
    context: {
      history,
      stores: deps.historyStores,
      tenantId: auth.tenantId,
      requestSignal: deps.requestSignal,
      events: deps.events,
      copyTimeoutMs: deps.historyCopyTimeoutMs ?? 15_000,
    },
    commitId: commitParam,
    branchName: branch?.name ?? (url.searchParams.get("branch") || "main"),
    treeHash: summary.treeHash,
  };
}

async function uploadBlobBatchEntries(
  deps: RequestContext,
  entries: Array<{ digest: BlobDigest; bytes: Buffer }>,
  tenantId: string | null | undefined
) {
  // Each worker catches its own failure so one bad entry (e.g. a digest mismatch)
  // does not abort the whole batch before its siblings' already-stored blobs are
  // recorded — an unrecorded-but-stored blob is invisible to GC and leaks forever.
  const outcomes = await runWithConcurrency(entries, 16, async (entry) => {
    try {
      const actualDigest = sha256Buffer(entry.bytes);
      if (actualDigest !== entry.digest) {
        throw new MetadataConflictError(
          "VOLUME_BLOB_DIGEST_MISMATCH",
          `Expected ${entry.digest}, received ${actualDigest}.`,
          400
        );
      }
      const result = await deps.blobStore.put(entry.bytes, {
        digest: entry.digest,
        checkExisting: false,
        signal: deps.requestSignal,
      });
      return { result };
    } catch (error) {
      return { error };
    }
  });
  const stored = outcomes.flatMap((outcome) => (outcome.result ? [outcome.result] : []));
  if (stored.length > 0) {
    await deps.metadata.recordBlobs(
      stored.map((result) =>
        Object.assign(
          {
            digest: result.blob.digest,
            size: result.blob.size,
          },
          result.blob.storageKey ? { storageKey: result.blob.storageKey } : {}
        )
      )
    );
    // Proof of possession: every verified-and-stored blob grants the uploading
    // tenant a reference (the authorization later checked at read and commit time).
    if (tenantId) {
      await deps.metadata.addBlobRefs(
        tenantId,
        stored.map((result) => result.blob.digest)
      );
    }
  }
  const failure = outcomes.find((outcome) => outcome.error);
  if (failure?.error) {
    throw failure.error;
  }
  return stored.map((result) => result.blob);
}

function sendBlobBatchResponse(
  res: ServerResponse,
  url: URL,
  blobs: Array<{ size: number }>
): void {
  if (url.searchParams.get("response") === "ack") {
    sendJson(res, 201, {
      count: blobs.length,
      bytes: blobs.reduce((total, blob) => total + blob.size, 0),
    });
    return;
  }
  sendJson(res, 201, { blobs });
}

function parseBlobBatchBinary(body: Buffer): Array<{ digest: BlobDigest; bytes: Buffer }> {
  if (body.byteLength < 8 || body.toString("ascii", 0, 4) !== "OSVB") {
    throw new MetadataConflictError("VOLUME_BLOB_BATCH_INVALID", "Blob batch binary header is invalid.", 400);
  }
  const version = body.readUInt16BE(4);
  const count = body.readUInt16BE(6);
  if (version !== 1) {
    throw new MetadataConflictError("VOLUME_BLOB_BATCH_UNSUPPORTED", "Blob batch binary version is unsupported.", 415);
  }
  if (count < 1 || count > 1024) {
    throw new MetadataConflictError("VOLUME_BLOB_BATCH_INVALID", "Blob batch binary count is invalid.", 400);
  }
  let offset = 8;
  const entries: Array<{ digest: BlobDigest; bytes: Buffer }> = [];
  for (let index = 0; index < count; index += 1) {
    if (offset + 6 > body.byteLength) {
      throw new MetadataConflictError("VOLUME_BLOB_BATCH_INVALID", "Blob batch binary entry is truncated.", 400);
    }
    const digestBytes = body.readUInt16BE(offset);
    const size = body.readUInt32BE(offset + 2);
    offset += 6;
    if (digestBytes < 1 || offset + digestBytes + size > body.byteLength) {
      throw new MetadataConflictError("VOLUME_BLOB_BATCH_INVALID", "Blob batch binary entry length is invalid.", 400);
    }
    const digest = body.toString("utf8", offset, offset + digestBytes) as BlobDigest;
    offset += digestBytes;
    const bytes = body.subarray(offset, offset + size);
    offset += size;
    entries.push({ digest, bytes });
  }
  if (offset !== body.byteLength) {
    throw new MetadataConflictError("VOLUME_BLOB_BATCH_INVALID", "Blob batch binary body has trailing bytes.", 400);
  }
  return entries;
}

async function assertManifestBlobsExist(
  deps: RequestContext,
  entries: Array<{
    kind: string;
    path: string;
    blob?: { digest: BlobDigest } | undefined;
    chunks?: Array<{ digest: BlobDigest }> | undefined;
  }>,
  tenantId: string | null | undefined
): Promise<void> {
  if (!tenantId) {
    // Defensive: the route guard already requires a tenant for every commit path.
    throw new MetadataConflictError(
      "VOLUME_TENANT_REQUIRED",
      "Tenant authentication is required to commit.",
      403
    );
  }
  const digests = new Set<BlobDigest>();
  for (const entry of entries) {
    if (entry.kind !== "file") {
      continue;
    }
    if (entry.chunks?.length) {
      for (const chunk of entry.chunks) {
        digests.add(chunk.digest);
      }
      continue;
    }
    if (entry.blob) {
      digests.add(entry.blob.digest);
    }
  }
  if (digests.size === 0) {
    return;
  }
  // Authorization BEFORE existence. A tenant may only commit a manifest that
  // references blobs it possesses — ones it uploaded (proof of possession) or
  // inherited via a prior commit/fork. Blobs are globally content-addressed and
  // deduplicated, and a tree hash needs no bytes, so without this check a tenant
  // could commit a manifest referencing another tenant's digest and be minted a
  // reference to it — then read those bytes. Checking the per-tenant reference
  // before global existence also avoids leaking which digests exist globally.
  const referenced = await deps.metadata.tenantReferencesBlobs(tenantId, [...digests]);
  for (const digest of digests) {
    if (!referenced.has(digest)) {
      throw new MetadataConflictError(
        "VOLUME_BLOB_MISSING",
        `Commit references blob ${digest} not uploaded by this tenant.`,
        400
      );
    }
  }
  // Defensive durability check: a reference implies the bytes were stored, but
  // verify they are still present so a commit never points at a swept blob.
  const known = deps.metadata.hasBlobs ? await deps.metadata.hasBlobs([...digests]) : new Set<string>();
  const pending = deps.metadata.hasBlobs
    ? new Set([...digests].filter((digest) => !known.has(digest)))
    : digests;
  for (const digest of pending) {
    if (!(await deps.blobStore.has(digest))) {
      throw new MetadataConflictError(
        "VOLUME_BLOB_MISSING",
        `Commit references missing blob ${digest}.`,
        400
      );
    }
  }
}

async function waitForHead(
  metadata: MetadataRepository,
  input: {
    tenantId: string;
    volumeId: string;
    branchName: string;
    afterCommitId: string;
    timeoutMs: number;
    signal?: AbortSignal;
  }
) {
  if (metadata.waitForHead) {
    return metadata.waitForHead(input);
  }
  const deadline = Date.now() + input.timeoutMs;
  let current = await metadata.getHead(input);
  while (current && current.branch.headCommitId === input.afterCommitId && Date.now() < deadline) {
    if (input.signal?.aborted) {
      throw new DOMException("The head wait was aborted.", "AbortError");
    }
    await sleep(Math.min(100, Math.max(1, deadline - Date.now())));
    current = await metadata.getHead(input);
  }
  return current;
}

function parseWaitTimeoutMs(raw: string | null): number {
  const parsed = raw ? Number(raw) : 25_000;
  if (!Number.isFinite(parsed)) {
    return 25_000;
  }
  return Math.max(1, Math.min(Math.trunc(parsed), maxWaitHeadTimeoutMs));
}

function parseListLimit(raw: string | null, defaultLimit: number): number {
  const parsed = raw ? Number(raw) : defaultLimit;
  if (!Number.isFinite(parsed)) {
    return defaultLimit;
  }
  return Math.max(1, Math.min(Math.trunc(parsed), 500));
}

// The pfh.history_cuts terminal states that can never make progress again:
// cut_claim only hands out pending/materializing rows, so a failed/canceled
// cut left "converting" would poll forever.
const terminalActivationCutStates = new Set(["failed", "canceled"]);

// Bounded, human-readable cut error for CLIENT status responses: the errDoc's
// message string only — never the raw document (which may carry nested error
// chains, stack traces, or storage keys).
const activationLastErrorMaxChars = 300;

function activationCutLastError(lastError: unknown): string | undefined {
  const message =
    typeof lastError === "string"
      ? lastError
      : typeof (lastError as { message?: unknown } | null)?.message === "string"
        ? (lastError as { message: string }).message
        : undefined;
  return message ? message.slice(0, activationLastErrorMaxChars) : undefined;
}

/**
 * Shapes the activation status answer: additive top-level cut observability
 * (cutState, attemptCount, lastError — a fixed contract with the CLI) plus
 * the explicit terminal mapping — a terminally failed/canceled cut answers a
 * terminal "failed" activation, never an eternal "converting". The nested
 * conversion/cut objects are passed through unchanged for compatibility.
 */
function activationStatusResponse(
  status: JournalActivationStatus
): JournalActivationStatus & { cutState?: string; attemptCount?: number; lastError?: string } {
  const cut = status.cut;
  if (!cut) {
    return status;
  }
  const lastError = activationCutLastError(cut.lastError);
  const cutIsTerminal = terminalActivationCutStates.has(cut.state);
  return {
    ...status,
    state: cutIsTerminal && status.state === "converting" ? "failed" : status.state,
    cutState: cut.state,
    attemptCount: cut.attemptCount,
    ...(lastError !== undefined ? { lastError } : {}),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// The exact-read context for cut-based materialization. Fails closed when
// exact history serving is not wired: the cut path must never fall back to
// digest-derived aggregate blob-store reads.
function requireCutServing(
  deps: RequestContext,
  tenantId: string
): { context: Pft2ReadContext; cutFacts: CutFactsReader } {
  const history = (deps.metadata as { history?: PostgresHistoryRepository }).history;
  if (!history || !deps.historyStores) {
    throw new VolumeApiError(
      "HISTORY_SERVING_UNAVAILABLE",
      "Exact history serving is not configured on this deployment.",
      503
    );
  }
  return {
    context: {
      history,
      stores: deps.historyStores,
      tenantId,
      requestSignal: deps.requestSignal,
      events: deps.events,
      copyTimeoutMs: deps.historyCopyTimeoutMs ?? 15_000,
    },
    cutFacts: history,
  };
}

// The cut-readiness share of the request budget: at most half of the
// caller's timeout (the scan must keep a real share) and never beyond 20s —
// typical readiness on the quickstart stack is 1-4s.
function setupShareMs(timeoutMs: number): number {
  return Math.min(Math.max(Math.floor(timeoutMs / 2), 250), 20_000);
}

// Read-only grep against a journal-served branch: resolves an immutable cut
// source, then a bounded scan directly over the PFT2 tree (no workspace).
//
// BOUNDED STALENESS: a live branch serves its newest READY cut whenever one
// exists (a fresh cut is minted only when the branch has none), so the
// answer is an exact immutable state at most as old as the last ready cut —
// with chained/rolling cuts that staleness is seconds. Snapshot-then-grep is
// the path for callers that need the exact current journal position.
async function grepOnCutBranch(
  deps: RequestContext,
  tenantId: string,
  volumeId: string,
  input: {
    branch: string;
    directory: string;
    pattern: string;
    recursive: boolean;
    maxResults: number;
    deadlineMs: number;
  },
  route: "live_cut" | "latest_ready_cut"
): Promise<{
  matches: Array<{ file: string; line: number; text: string }>;
  stoppedReason: "completed" | "max_results" | "deadline";
  durationMs: number;
  headCommitId: string;
  cutId?: string;
}> {
  const started = Date.now();
  const deadlineAt = started + input.deadlineMs;
  // Syntax is compiled in the worker before a cut is minted. Matching also
  // stays in that killable worker; the API event loop never evaluates tenant
  // regex bytecode.
  const matcher = await IsolatedRegexMatcher.create(
    input.pattern,
    deadlineAt,
    deps.requestSignal
  );
  try {
    const serving = requireCutServing(deps, tenantId);
    const source = await resolveCutReadSource({
      metadata: deps.metadata,
      cutFacts: serving.cutFacts,
      tenantId,
      volumeId,
      branchName: input.branch,
      route,
      readyDeadlineAt: started + setupShareMs(input.deadlineMs),
      signal: deps.requestSignal,
    });
    const scanner = new BoundedGrepScanner(matcher, {
      maxResults: input.maxResults,
      deadlineAt,
      signal: deps.requestSignal,
    });
    const directory = normalizeVolumePath(input.directory);
    if (source.kind === "pft2") {
      const scan = await grepPft2Commit(serving.context, source.commitId, {
        directory,
        recursive: input.recursive,
        signal: deps.requestSignal,
        scanner,
      });
      return {
        matches: scan.matches,
        stoppedReason: scan.stoppedReason,
        durationMs: Date.now() - started,
        headCommitId: source.commitId,
        ...(source.cutId ? { cutId: source.cutId } : {}),
      };
    }
    const manifest = await deps.metadata.getManifest(source.commitId);
    if (!manifest) {
      throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume not found.", 404);
    }
    const scan = await scanManifestEntries(deps, manifest, {
      directory,
      recursive: input.recursive,
      scanner,
    });
    return {
      matches: scan.matches,
      stoppedReason: scan.stoppedReason,
      durationMs: Date.now() - started,
      headCommitId: source.commitId,
    };
  } finally {
    await matcher.close();
  }
}

async function grepVolume(
  deps: RequestContext,
  tenantId: string,
  volumeId: string,
  input: {
    branch: string;
    directory: string;
    pattern: string;
    recursive: boolean;
    maxResults: number;
    deadlineMs: number;
  }
): Promise<{
  matches: Array<{ file: string; line: number; text: string }>;
  stoppedReason: "completed" | "max_results" | "deadline";
  durationMs: number;
  headCommitId: string;
}> {
  const started = Date.now();
  const deadlineAt = started + input.deadlineMs;
  const matcher = await IsolatedRegexMatcher.create(
    input.pattern,
    deadlineAt,
    deps.requestSignal
  );
  try {
    const status = await deps.metadata.getStatus({
      tenantId,
      volumeId,
      branchName: input.branch,
    });
    if (!status) {
      throw new MetadataConflictError("VOLUME_NOT_FOUND", "Volume not found.", 404);
    }
    const scanner = new BoundedGrepScanner(matcher, {
      maxResults: input.maxResults,
      deadlineAt,
      signal: deps.requestSignal,
    });
    const scan = await scanManifestEntries(deps, status.head.manifest, {
      directory: normalizeVolumePath(input.directory),
      recursive: input.recursive,
      scanner,
    });
    return {
      matches: scan.matches,
      stoppedReason: scan.stoppedReason,
      durationMs: Date.now() - started,
      headCommitId: status.branch.headCommitId,
    };
  } finally {
    await matcher.close();
  }
}

// The manifest grep engine, shared by the live manifest head (grepVolume)
// and the pinned-manifest cut source (grepOnCutBranch).
async function scanManifestEntries(
  deps: RequestContext,
  manifest: TreeManifest,
  input: {
    directory: string;
    recursive: boolean;
    scanner: BoundedGrepScanner;
  }
): Promise<{
  matches: Array<{ file: string; line: number; text: string }>;
  stoppedReason: "completed" | "max_results" | "deadline";
}> {
  const entries = manifest.entries
    .filter((entry) => entry.kind === "file" && isEntryInDirectory(entry.path, input.directory, input.recursive))
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  for (const entry of entries) {
    if (!input.scanner.checkpoint()) {
      break;
    }
    if (
      !(await input.scanner.scanFile(
        entry.path,
        entry.size,
        manifestEntryByteSource(deps.blobStore, entry, deps.requestSignal)
      ))
    ) {
      break;
    }
  }
  return { matches: input.scanner.matches, stoppedReason: input.scanner.stoppedReason };
}

async function runWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await worker(items[index] as T, index);
    }
  });
  await Promise.all(workers);
  return results;
}

async function* manifestEntryByteSource(
  blobStore: BlobStore,
  entry: TreeEntry,
  signal: AbortSignal
): AsyncGenerator<Buffer> {
  if (entry.kind !== "file" || !entry.blob) {
    return;
  }
  if (entry.chunks?.length) {
    const hash = createHash("sha256");
    let expectedOffset = 0;
    let total = 0;
    for (const chunk of [...entry.chunks].sort((left, right) => left.offset - right.offset)) {
      if (chunk.offset !== expectedOffset) {
        throw new MetadataConflictError(
          "VOLUME_BLOB_DIGEST_MISMATCH",
          `Chunk offsets are not contiguous for ${entry.path}.`,
          500
        );
      }
      const opened = await openBlobByteStream(blobStore, chunk.digest, { signal });
      if (opened.totalLength !== chunk.size) {
        opened.stream.destroy();
        throw new MetadataConflictError(
          "VOLUME_BLOB_DIGEST_MISMATCH",
          `Chunk size mismatch for ${entry.path}.`,
          500
        );
      }
      for await (const raw of opened.stream) {
        const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
        hash.update(bytes);
        total += bytes.byteLength;
        yield bytes;
      }
      expectedOffset += chunk.size;
    }
    const actual = `sha256:${hash.digest("hex")}`;
    if (actual !== entry.blob.digest) {
      throw new MetadataConflictError(
        "VOLUME_BLOB_DIGEST_MISMATCH",
        `Chunked file digest mismatch for ${entry.path}.`,
        500
      );
    }
    if (total !== entry.size) {
      throw new MetadataConflictError(
        "VOLUME_BLOB_DIGEST_MISMATCH",
        `Chunked file size mismatch for ${entry.path}.`,
        500
      );
    }
    return;
  }
  const opened = await openBlobByteStream(blobStore, entry.blob.digest, { signal });
  if (opened.totalLength !== entry.size) {
    opened.stream.destroy();
    throw new MetadataConflictError(
      "VOLUME_BLOB_DIGEST_MISMATCH",
      `File size mismatch for ${entry.path}.`,
      500
    );
  }
  for await (const raw of opened.stream) {
    yield Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
  }
}

function isEntryInDirectory(entryPath: string, directory: string, recursive: boolean): boolean {
  if (!directory) {
    return recursive || !entryPath.includes("/");
  }
  if (entryPath === directory) {
    return true;
  }
  if (recursive) {
    return entryPath.startsWith(`${directory}/`);
  }
  return parentVolumePath(entryPath) === directory;
}

async function readJson(req: IncomingMessage, deps: RequestContext): Promise<unknown> {
  const raw = await readRaw(req, deps);
  if (raw.byteLength === 0) {
    return {};
  }
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    // A malformed body is a client error (400), not a server fault (500). Don't echo
    // the parser's message — it can reflect raw body bytes back to the caller.
    throw new MetadataConflictError("VOLUME_INVALID_JSON", "Request body is not valid JSON.", 400);
  }
}

// blobBodyLimit caps raw blob bodies (PUT /v1/blobs/:digest, POST /v1/blobs/batch-binary)
// independently of the general JSON body limit. Wired from VOLUME_API_MAX_BLOB_BODY_BYTES.
function blobBodyLimit(deps: RequestContext): number {
  return deps.maxBlobBodyBytes ?? 64 * 1024 * 1024;
}

async function readRaw(
  req: IncomingMessage,
  deps: RequestContext,
  maxBytes?: number
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  const max = maxBytes ?? deps.maxBodyBytes ?? 512 * 1024 * 1024;
  const signal = deps.requestSignal;
  if (signal?.aborted) {
    throw new DOMException("The request body read was aborted.", "AbortError");
  }
  // Destroying the request stream on abort makes the for-await below settle
  // promptly even when the (dead or draining) client would keep trickling.
  const onAbort = () => {
    req.destroy(new DOMException("The request body read was aborted.", "AbortError"));
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    for await (const chunk of req) {
      if (signal?.aborted) {
        throw new DOMException("The request body read was aborted.", "AbortError");
      }
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buffer.byteLength;
      if (total > max) {
        throw new MetadataConflictError("VOLUME_BODY_TOO_LARGE", "Request body is too large.", 413);
      }
      chunks.push(buffer);
    }
    if (signal?.aborted) {
      throw new DOMException("The request body read was aborted.", "AbortError");
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
  }
  return Buffer.concat(chunks);
}

// Per-response serialized-size bound, set by the pipeline from the admitted
// route policy. A WeakMap keeps the bound out of handler signatures so every
// sendJson call site is covered automatically.
const responseByteBounds = new WeakMap<ServerResponse, number>();

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = Buffer.from(`${JSON.stringify(payload)}\n`);
  // Success payloads are bounded by the route's audited serialization budget;
  // beyond it the CALLER receives a typed error instead of an unbounded body
  // (v1 shapes are never silently altered). Error payloads are tiny and pass
  // through so this check cannot recurse.
  const bound = responseByteBounds.get(res);
  if (bound !== undefined && status < 400 && body.byteLength > bound) {
    sendJson(res, 413, {
      error: {
        code: "VOLUME_RESPONSE_TOO_LARGE",
        message: `The response is ${body.byteLength} bytes, above this route's ${bound}-byte serialization bound.`,
      },
    });
    return;
  }
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("content-length", String(body.byteLength));
  res.end(body);
}

// Client-visible request-validation detail is opt-in (local development only):
// a generic message is the safe default so the public schema is not probeable
// through error responses. An explicit env opt-in — never NODE_ENV — keeps the
// deployment posture unambiguous.
const exposeValidationDetail = process.env.PORTABLEFS_API_EXPOSE_VALIDATION_DETAIL === "1";

function sendError(res: ServerResponse, error: unknown, telemetry?: VolumeApiTelemetry): void {
  // A failure after headers were sent cannot be retracted into a clean error
  // response — destroying the connection is the only truthful signal that the
  // (possibly streaming) body is incomplete.
  if (res.headersSent) {
    res.destroy();
    return;
  }
  if (error instanceof VolumeApiError) {
    // Typed errors may carry response headers (e.g. Retry-After on the
    // per-tenant 429) so clients can back off correctly.
    for (const [name, value] of Object.entries(error.headers ?? {})) {
      res.setHeader(name, value);
    }
    sendJson(res, error.status, {
      error: {
        code: error.code,
        message: error.message,
      },
    });
    return;
  }
  if (error instanceof MetadataConflictError) {
    sendJson(res, error.status, {
      error: {
        code: error.code,
        message: error.message,
      },
    });
    return;
  }
  if (error && typeof error === "object" && "issues" in error) {
    // Field-level Zod issues are a developer convenience but, with the source
    // public, they also hand an attacker the exact schema shape (field names,
    // enums, bounds) for probing. Default to a generic message and keep the
    // detail server-side; opt into client-visible detail explicitly for local
    // development. Deliberately NOT gated on NODE_ENV.
    const issues = (error as { issues: unknown }).issues;
    if (!exposeValidationDetail) {
      console.error("volume-api request validation failed:", issues);
    }
    sendJson(res, 400, {
      error: {
        code: "VOLUME_VALIDATION_FAILED",
        message: "Request validation failed.",
        ...(exposeValidationDetail ? { issues } : {}),
      },
    });
    return;
  }
  if (isAbortError(error)) {
    // The wait/transfer was cancelled (client disconnect or server drain).
    // If the socket is still up — a drain abort — 503 tells it to retry
    // against another instance.
    res.setHeader("connection", "close");
    sendJson(res, 503, {
      error: {
        code: "VOLUME_REQUEST_CANCELLED",
        message: "The request was cancelled before completion.",
      },
    });
    return;
  }
  telemetry?.emit({ type: "request_error", code: "VOLUME_INTERNAL" });
  // Never reflect raw internal error text to the client: Postgres messages
  // leak table/constraint names, storage errors leak bucket names and object
  // keys, and connection faults leak internal hostnames/ports. Log the real
  // error server-side for diagnosis (the response already carries
  // x-portablefs-request-id for correlation) and return a fixed message.
  console.error("volume-api internal error:", error);
  sendJson(res, 500, {
    error: {
      code: "VOLUME_INTERNAL",
      message: "An internal error occurred.",
    },
  });
}

interface AuthContext {
  // The authenticated tenant; null for an admin token (provisioning + GC only).
  tenantId: string | null;
  isAdmin: boolean;
  // Manager-minted runtime credential (migration 015): tenant-scoped reads
  // plus the pinned volume's own authority lifecycle (attach, detach, lease
  // renew) — nothing else, and volume-scoped routes must address exactly
  // this volume. Resolution already proved liveness (expiry, revocation)
  // inside the database.
  runtimeCredential?: boolean;
  credentialVolumeId?: string;
}

// authenticate resolves the bearer token to a tenant (or admin). Fail-closed: a
// request with no valid admin/tenant token is rejected. Tenant identity is derived
// from the credential server-side and never trusted from the request body.
async function authenticate(
  req: IncomingMessage,
  deps: VolumeApiServerDeps
): Promise<AuthContext | null> {
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  if (!token) {
    return null;
  }
  if (deps.authToken && timingSafeEqualStr(token, deps.authToken)) {
    return { tenantId: null, isAdmin: true };
  }
  const tokenHash = sha256Hex(token);
  const resolved = await deps.metadata.resolveTenantToken(tokenHash);
  if (resolved) {
    return { tenantId: resolved.tenantId, isAdmin: false };
  }
  if (token.startsWith("pfrc_")) {
    const credential = await deps.metadata.resolveRuntimeReadCredential(tokenHash);
    if (credential) {
      return {
        tenantId: credential.tenantId,
        isAdmin: false,
        runtimeCredential: true,
        credentialVolumeId: credential.volumeId,
      };
    }
  }
  return null;
}

// The EXACT mutating surface a manager-minted runtime credential may drive,
// every row pinned to the credential's volume: the managed child's
// write-authority admission (attach/attach-receipted), its session
// lifecycle (detach), and its writer-lease renewal. Commit routes are
// deliberately absent — a managed child journals through PostgreSQL, never
// through legacy manifest commits.
async function runtimeCredentialLifecycleRouteAllowed(
  deps: RequestContext,
  auth: AuthContext,
  method: string,
  parts: string[]
): Promise<boolean> {
  const pinned = auth.credentialVolumeId;
  if (!pinned || method !== "POST") {
    return false;
  }
  if (
    parts.length === 4 &&
    parts[1] === "volumes" &&
    parts[2] === pinned &&
    (parts[3] === "attach" || parts[3] === "attach-receipted")
  ) {
    return true;
  }
  if (parts.length === 4 && parts[1] === "attach-sessions" && parts[3] === "detach") {
    const volume = await deps.metadata.sessionVolume(parts[2] ?? "");
    return volume === pinned;
  }
  if (parts.length === 4 && parts[1] === "leases" && parts[3] === "renew") {
    const volume = await deps.metadata.leaseVolume(parts[2] ?? "");
    return volume === pinned;
  }
  return false;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    timingSafeEqual(ab, ab); // keep timing independent of length, then fail
    return false;
  }
  return timingSafeEqual(ab, bb);
}

type GuardDenial = { status: number; body: unknown };

function tenantRequired(): GuardDenial {
  return {
    status: 403,
    body: { error: { code: "VOLUME_TENANT_REQUIRED", message: "A tenant credential is required." } },
  };
}

function tenantIdForScopedRoute(auth: AuthContext): string {
  if (!auth.tenantId) {
    // The centralized guard rejects this before dispatch. Keep the invariant
    // explicit at repository call sites so no future route can issue an
    // unqualified tenant-local volume lookup.
    throw new VolumeApiError(
      "VOLUME_TENANT_REQUIRED",
      "A tenant credential is required.",
      403
    );
  }
  return auth.tenantId;
}
function adminRequired(): GuardDenial {
  return {
    status: 403,
    body: { error: { code: "VOLUME_ADMIN_REQUIRED", message: "Admin credential required." } },
  };
}
function notOwned(): GuardDenial {
  // 404, not 403, so a resource's existence is not revealed across tenants.
  return { status: 404, body: { error: { code: "VOLUME_NOT_FOUND", message: "Not found." } } };
}

// guardTenantAccess enforces that the caller's tenant owns the resource a route
// addresses (admin routes require the admin token). Runs before any handler, so no
// route can be reached without an ownership check.
async function guardTenantAccess(
  deps: RequestContext,
  auth: AuthContext,
  method: string,
  parts: string[]
): Promise<GuardDenial | null> {
  const resource = parts[1];
  const id = parts[2] ?? "";

  if (resource === "admin") {
    return auth.isAdmin ? null : adminRequired();
  }

  const ownedBy = async (ownerPromise: Promise<string | null>): Promise<GuardDenial | null> => {
    if (!auth.tenantId) {
      return tenantRequired();
    }
    const tenant = await ownerPromise;
    if (!tenant || tenant !== auth.tenantId) {
      return notOwned();
    }
    return null;
  };

  switch (resource) {
    case "volumes":
      if (parts.length === 2 && (method === "POST" || method === "GET")) {
        // create/list: a tenant acts on its own tenant; the admin token names one
        // explicitly (enforced in the handlers).
        return auth.isAdmin || auth.tenantId ? null : tenantRequired();
      }
      if (method === "DELETE" && parts.length === 3 && deps.metadata.retiredVolumeReceipt) {
        // Receipted retirement is replayable by its owner: a DELETE passes
        // the guard when the tenant owns the volume live OR retired, so the
        // handler can answer the stored receipt on a replay (caller-keyed
        // ledger recovery after a lost response). Unknown and foreign ids
        // fall through to the same non-enumerating 404 — that property
        // protects against cross-tenant probing, not the owner's own
        // tombstones. Repositories without the receipt lookup keep the
        // original live-only guard.
        if (!auth.tenantId) {
          return tenantRequired();
        }
        const ownsLiveVolume = await deps.metadata.tenantOwnsVolume({
          tenantId: auth.tenantId,
          volumeId: id,
        });
        if (ownsLiveVolume) {
          return null;
        }
        const receipt = await deps.metadata.retiredVolumeReceipt({
          volumeId: id,
          tenantId: auth.tenantId,
        });
        return receipt ? null : notOwned();
      }
      if (!auth.tenantId) {
        return tenantRequired();
      }
      return (await deps.metadata.tenantOwnsVolume({
        tenantId: auth.tenantId,
        volumeId: id,
      }))
        ? null
        : notOwned();
    case "attach-sessions":
      return ownedBy(deps.metadata.sessionTenant(id));
    case "leases":
      return ownedBy(deps.metadata.leaseTenant(id));
    case "snapshots":
      return ownedBy(deps.metadata.snapshotTenant(id));
    case "commits":
      return ownedBy(deps.metadata.commitTenant(id));
    case "history":
      // Tenant identity is the only scope accepted by the immutable history
      // routes; an admin token is never silently treated as a tenant.
      return auth.tenantId ? null : tenantRequired();
    case "blobs":
      if (method === "POST" && parts.length === 3 && parts[2] === "probe") {
        // Probe reports the caller's own possession only. The admin token has no
        // tenant, references nothing, and receives every digest back as missing.
        return null;
      }
      // Uploads: any authenticated tenant. Reads: the handler verifies the tenant
      // references the digest (reference-checked read).
      return auth.tenantId ? null : tenantRequired();
    default:
      return null; // unknown route -> 404 in the dispatcher
  }
}

function isHealthCheck(req: IncomingMessage): boolean {
  return req.method === "GET" && (req.url ?? "/").split("?")[0] === "/healthz";
}

function isReadinessCheck(req: IncomingMessage): boolean {
  return req.method === "GET" && (req.url ?? "/").split("?")[0] === "/readyz";
}
