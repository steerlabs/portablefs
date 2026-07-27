import { VolumeApiError } from "./errors.js";
import type { VolumeApiTelemetry } from "./telemetry.js";

// ---------------------------------------------------------------------------
// Route resource policies (from the per-route audit).
//
// Every request is admitted against THREE independent budgets before its body
// is read: the global active-request cap, the per-route concurrency cap, and
// the weighted transient-memory budget. All three fail fast with a typed 429 —
// nothing queues, because a queued request holds client sockets and memory
// while the server is already saturated.
//
// The transient-memory weight is the request's declared Content-Length when
// present (rejected early if above the route bound) or the ROUTE MAXIMUM for
// chunked bodies — a chunked request must prepay the worst case because the
// server cannot know its size until it has already buffered it.
// ---------------------------------------------------------------------------

export interface RoutePolicy {
  /** Low-cardinality route label (also the telemetry dimension). */
  readonly name: string;
  /** Transport body bound in bytes; 0 for bodyless routes. */
  readonly maxBodyBytes: number;
  /** Per-route concurrent request cap (fail-fast, no queue). */
  readonly concurrency?: number;
  /**
   * Audited JSON parse/decode amplification: parsed object graphs and base64
   * decoding cost multiples of the wire bytes. The admission weight charges
   * body bytes at this multiplier, not raw wire size.
   */
  readonly parseAmplification: number;
  /**
   * Audited fixed WORKING-SET reservation for building and serializing the
   * response (response objects + JSON.stringify buffer). Charged against the
   * transient-memory budget for the request's whole lifetime.
   */
  readonly responseReserveBytes: number;
  /**
   * Hard bound on a serialized v1 JSON response. Larger results are a typed
   * VOLUME_RESPONSE_TOO_LARGE — v1 shapes are never silently changed.
   */
  readonly maxResponseBytes: number;
}

const KiB = 1024;
const MiB = 1024 * 1024;

/**
 * The audited transient-memory window of ONE streamed blob response: the
 * source stream's high-water mark (64 KiB for filesystem reads and typical
 * fetch bodies) plus the response socket buffer (16 KiB), rounded up to
 * 256 KiB for one in-flight chunk of headroom on each side. pipeline()
 * applies backpressure, so a slow client parks the transfer at this window
 * instead of buffering the blob.
 */
export const blobStreamWindowBytes = 256 * KiB;

export const routePolicies = {
  // Small JSON control/metadata operations (head, leases, checkout/checkin,
  // detach, snapshots, branches, forks, admin, probes).
  control: {
    name: "control",
    maxBodyBytes: 64 * KiB,
    parseAmplification: 2,
    responseReserveBytes: 4 * MiB,
    maxResponseBytes: 4 * MiB,
  },
  // Blob possession probes: the schema admits up to 4096 digests per request
  // (~300 KiB of JSON), which the CLI's adopt batching sends as full chunks.
  // The generic 64 KiB control cap would reject the schema's own maximum, so
  // probes carry their own body budget; responses echo at most the same
  // digest list back.
  blobProbe: {
    name: "blob_probe",
    maxBodyBytes: 1 * MiB,
    parseAmplification: 2,
    responseReserveBytes: 4 * MiB,
    maxResponseBytes: 4 * MiB,
  },
  // Manifest-bearing v1 reads (status, manifest diff, commit manifest, tree/
  // file browse): the response (or the server-side working set) can be a
  // whole manifest, so these carry the large reservation and their own
  // concurrency bound.
  manifestRead: {
    name: "manifest_read",
    maxBodyBytes: 0,
    concurrency: 8,
    parseAmplification: 1,
    responseReserveBytes: 64 * MiB,
    maxResponseBytes: 64 * MiB,
  },
  // Attach carries prefetch paths and client info in, but a whole manifest out.
  attach: {
    name: "attach",
    maxBodyBytes: 1 * MiB,
    parseAmplification: 2,
    responseReserveBytes: 64 * MiB,
    maxResponseBytes: 64 * MiB,
  },
  // Full-manifest commit: the largest accepted JSON body (parse
  // amplification x2) AND a possible full-manifest response (v1 commit echo).
  commitFull: {
    name: "commit_full",
    maxBodyBytes: 64 * MiB,
    concurrency: 4,
    parseAmplification: 2,
    responseReserveBytes: 64 * MiB,
    maxResponseBytes: 64 * MiB,
  },
  // Delta commits carry only changed entries and return summaries.
  commitDelta: {
    name: "commit_delta",
    maxBodyBytes: 32 * MiB,
    concurrency: 4,
    parseAmplification: 2,
    responseReserveBytes: 8 * MiB,
    maxResponseBytes: 8 * MiB,
  },
  // Single-blob upload. Bodies are binary (no parse amplification); the
  // reserve covers the JSON receipt working set.
  blob: {
    name: "blob",
    maxBodyBytes: 64 * MiB,
    concurrency: 8,
    parseAmplification: 1,
    responseReserveBytes: 8 * MiB,
    maxResponseBytes: 4 * MiB, // JSON responses only (upload receipts)
  },
  // Single-blob download. The old flat 8 MiB reserve was dishonest in both
  // directions: a 64 MiB buffered body under-accounted 8x, and a streamed
  // body that never materializes over-accounted 32x. The reserve here is the
  // STREAM WINDOW only; a served response that IS resident in memory (cache
  // hit or buffered fallback) additionally charges its actual byte length
  // through the permit's response charge before headers are sent.
  blobRead: {
    name: "blob_read",
    maxBodyBytes: 0,
    concurrency: 8,
    parseAmplification: 1,
    responseReserveBytes: blobStreamWindowBytes,
    maxResponseBytes: 4 * MiB, // JSON error envelopes only; blob bytes bypass sendJson
  },
  // Exact immutable PFT2 object read. The object is bounded by the frozen
  // 4 MiB PFT2 pack ceiling and must be fully verified before exposure.
  historyObject: {
    name: "history_object",
    maxBodyBytes: 0,
    concurrency: 8,
    parseAmplification: 1,
    responseReserveBytes: 5 * MiB,
    maxResponseBytes: 4 * MiB,
  },
  // JSON batch: base64 wire -> decoded buffers -> parsed JSON graph.
  blobBatchJson: {
    name: "blob_batch_json",
    maxBodyBytes: 24 * MiB,
    concurrency: 2,
    parseAmplification: 3,
    responseReserveBytes: 4 * MiB,
    maxResponseBytes: 4 * MiB,
  },
  // Compact binary batch (one parse copy).
  blobBatchBinary: {
    name: "blob_batch_binary",
    maxBodyBytes: 64 * MiB,
    concurrency: 2,
    parseAmplification: 2,
    responseReserveBytes: 4 * MiB,
    maxResponseBytes: 4 * MiB,
  },
  // Long-poll head waits hold a request slot (and on Postgres a LISTEN
  // connection) each; both are bounded here. Responses are summaries.
  waitHead: {
    name: "wait_head",
    maxBodyBytes: 0,
    concurrency: 16,
    parseAmplification: 1,
    responseReserveBytes: 1 * MiB,
    maxResponseBytes: 4 * MiB,
  },
  // Grep's scanner independently caps files, source bytes, line bytes and
  // matched-output bytes. The reserve covers its 8 MiB result cap, JSON
  // serialization, the resource-limited regex worker and one read window.
  grep: {
    name: "grep",
    maxBodyBytes: 64 * KiB,
    concurrency: 4,
    parseAmplification: 2,
    responseReserveBytes: 48 * MiB,
    maxResponseBytes: 16 * MiB,
  },
  // Retired exec endpoint: a single small retirement envelope, with a
  // one-at-a-time admission cap so floods cannot amplify auth work.
  exec: {
    name: "exec",
    maxBodyBytes: 64 * KiB,
    concurrency: 1,
    parseAmplification: 2,
    responseReserveBytes: 1 * MiB,
    maxResponseBytes: 1 * MiB,
  },
} as const satisfies Record<string, RoutePolicy>;

export type RoutePolicyName = keyof typeof routePolicies;

export const globalRequestLimit = 128;
export const globalTransientMemoryBytes = 256 * MiB;

/** Wait-head timeout ceiling (milliseconds). */
export const maxWaitHeadTimeoutMs = 60_000;

/**
 * VOLUME_API_MAX_BLOB_BODY_BYTES keeps its frozen meaning: it overrides the
 * raw-blob transport bound (single upload and binary batch) on top of the
 * audited defaults. The derived table is otherwise identical.
 */
export function resolveRoutePolicies(options?: {
  maxBlobBodyBytes?: number;
}): Record<RoutePolicyName, RoutePolicy> {
  const blobBodyBytes = options?.maxBlobBodyBytes;
  if (blobBodyBytes === undefined) {
    return routePolicies;
  }
  return {
    ...routePolicies,
    blob: { ...routePolicies.blob, maxBodyBytes: blobBodyBytes },
    blobBatchBinary: { ...routePolicies.blobBatchBinary, maxBodyBytes: blobBodyBytes },
  };
}

export interface AdmissionPermit {
  /** Idempotent: safe to call from success, error, AND abort paths. */
  release(): void;
  /**
   * Binds the authenticated tenant to this request for the per-tenant
   * admission dimension (called once, after authentication — admission
   * itself deliberately runs before auth). Throws the typed 429
   * VOLUME_TENANT_OVERLOADED (with Retry-After) when THIS tenant is at its
   * concurrency or reserved-byte cap while the rest of the server admits
   * normally; the caller's finally still releases the global reservation.
   */
  bindTenant(tenantId: string): void;
  /**
   * Charges transient bytes whose size is only known at serve time — a blob
   * response that IS resident in memory (cache hit or buffered fallback)
   * charges its actual byte length here before headers are sent; a true
   * stream charges nothing beyond the policy's fixed window. Counted against
   * the global budget and the bound tenant's; released with the permit.
   * Throws the same typed 429s as admission when a budget cannot take it.
   */
  chargeResponseBytes(bytes: number): void;
}

export interface AdmissionControllerOptions {
  maxActiveRequests?: number;
  maxTransientBytes?: number;
  /**
   * Per-tenant caps (VOLUME_API_TENANT_MAX_REQUESTS /
   * VOLUME_API_TENANT_MAX_RESPONSE_BYTES). Unset defaults to 50% of the
   * global budget so no single tenant can exhaust the server before the
   * global limit trips; 0 disables the dimension.
   */
  tenantMaxRequests?: number;
  tenantMaxReservedBytes?: number;
  telemetry?: VolumeApiTelemetry;
}

type AdmissionRejectionReason =
  | "global_concurrency"
  | "route_concurrency"
  | "transient_memory"
  | "tenant_concurrency"
  | "tenant_memory";

export class AdmissionController {
  private readonly maxActiveRequests: number;
  private readonly maxTransientBytes: number;
  private readonly tenantMaxRequests: number;
  private readonly tenantMaxReservedBytes: number;
  private readonly telemetry: VolumeApiTelemetry | undefined;
  private active = 0;
  private transientBytes = 0;
  private readonly routeActive = new Map<string, number>();
  private readonly tenantActive = new Map<string, number>();
  private readonly tenantReservedBytes = new Map<string, number>();

  constructor(options: AdmissionControllerOptions = {}) {
    this.maxActiveRequests = options.maxActiveRequests ?? globalRequestLimit;
    this.maxTransientBytes = options.maxTransientBytes ?? globalTransientMemoryBytes;
    this.tenantMaxRequests = validatedTenantCap(
      options.tenantMaxRequests ?? Math.floor(this.maxActiveRequests / 2),
      "tenantMaxRequests"
    );
    this.tenantMaxReservedBytes = validatedTenantCap(
      options.tenantMaxReservedBytes ?? Math.floor(this.maxTransientBytes / 2),
      "tenantMaxReservedBytes"
    );
    this.telemetry = options.telemetry;
  }

  get activeRequests(): number {
    return this.active;
  }

  get reservedTransientBytes(): number {
    return this.transientBytes;
  }

  tenantActiveRequests(tenantId: string): number {
    return this.tenantActive.get(tenantId) ?? 0;
  }

  tenantReserved(tenantId: string): number {
    return this.tenantReservedBytes.get(tenantId) ?? 0;
  }

  /**
   * Admits one request or throws a typed 429/413. `declaredBodyBytes` is the
   * parsed Content-Length; undefined means chunked (reserves the route max).
   * The transient weight charges the body at the route's audited parse
   * amplification PLUS the fixed response working-set reservation — request
   * wire bytes alone are not memory accounting.
   */
  admit(policy: RoutePolicy, declaredBodyBytes: number | undefined): AdmissionPermit {
    if (declaredBodyBytes !== undefined && declaredBodyBytes > policy.maxBodyBytes) {
      // Early Content-Length rejection: the body is never read.
      throw new VolumeApiError(
        "VOLUME_BODY_TOO_LARGE",
        `Request body of ${declaredBodyBytes} bytes exceeds the ${policy.maxBodyBytes}-byte limit for this route.`,
        413
      );
    }
    const bodyBytes = declaredBodyBytes ?? policy.maxBodyBytes;
    const weight = bodyBytes * policy.parseAmplification + policy.responseReserveBytes;

    if (this.active >= this.maxActiveRequests) {
      this.rejected(policy, "global_concurrency");
    }
    const routeInFlight = this.routeActive.get(policy.name) ?? 0;
    if (policy.concurrency !== undefined && routeInFlight >= policy.concurrency) {
      this.rejected(policy, "route_concurrency");
    }
    if (this.transientBytes + weight > this.maxTransientBytes) {
      this.rejected(policy, "transient_memory");
    }

    this.active += 1;
    this.routeActive.set(policy.name, routeInFlight + 1);
    this.transientBytes += weight;
    this.telemetry?.emit({
      type: "admission",
      route: policy.name,
      outcome: "admitted",
      activeRequests: this.active,
      transientBytes: this.transientBytes,
    });

    // reservedBytes tracks the request's WHOLE reservation (admission weight
    // plus later response charges) so release returns exactly what was taken;
    // tenant accounting mirrors the same number under the bound tenant key.
    let reservedBytes = weight;
    let boundTenant: string | undefined;
    let released = false;
    return {
      bindTenant: (tenantId: string) => {
        if (released || boundTenant !== undefined) {
          return;
        }
        const tenantInFlight = this.tenantActive.get(tenantId) ?? 0;
        if (this.tenantMaxRequests !== 0 && tenantInFlight >= this.tenantMaxRequests) {
          this.rejectedTenant(policy, "tenant_concurrency");
        }
        // PROGRESS GUARANTEE: the byte cap bounds ACCUMULATION across a
        // tenant's concurrent requests, so a tenant with nothing in flight is
        // never refused by it — the largest single legal request (a maximal
        // full-manifest commit outweighs 50% of the global budget) keeps
        // working exactly as before the per-tenant dimension existed.
        const tenantBytes = this.tenantReservedBytes.get(tenantId) ?? 0;
        if (
          this.tenantMaxReservedBytes !== 0 &&
          tenantInFlight > 0 &&
          tenantBytes + reservedBytes > this.tenantMaxReservedBytes
        ) {
          this.rejectedTenant(policy, "tenant_memory");
        }
        boundTenant = tenantId;
        this.tenantActive.set(tenantId, tenantInFlight + 1);
        this.tenantReservedBytes.set(tenantId, tenantBytes + reservedBytes);
      },
      chargeResponseBytes: (bytes: number) => {
        if (released || !Number.isSafeInteger(bytes) || bytes <= 0) {
          return;
        }
        if (this.transientBytes + bytes > this.maxTransientBytes) {
          this.rejected(policy, "transient_memory");
        }
        if (boundTenant !== undefined && this.tenantMaxReservedBytes !== 0) {
          const tenantBytes = this.tenantReservedBytes.get(boundTenant) ?? 0;
          // The same progress guarantee as bindTenant: a tenant's ONLY
          // in-flight request may charge past the accumulation cap.
          if (
            (this.tenantActive.get(boundTenant) ?? 0) > 1 &&
            tenantBytes + bytes > this.tenantMaxReservedBytes
          ) {
            this.rejectedTenant(policy, "tenant_memory");
          }
          this.tenantReservedBytes.set(boundTenant, tenantBytes + bytes);
        }
        reservedBytes += bytes;
        this.transientBytes += bytes;
      },
      release: () => {
        if (released) {
          return;
        }
        released = true;
        this.active -= 1;
        const current = this.routeActive.get(policy.name) ?? 1;
        if (current <= 1) {
          this.routeActive.delete(policy.name);
        } else {
          this.routeActive.set(policy.name, current - 1);
        }
        this.transientBytes -= reservedBytes;
        if (boundTenant !== undefined) {
          decrementCount(this.tenantActive, boundTenant, 1);
          decrementCount(this.tenantReservedBytes, boundTenant, reservedBytes);
        }
        this.telemetry?.emit({
          type: "transient_memory",
          reservedBytes,
          totalBytes: this.transientBytes,
          direction: "release",
        });
      },
    };
  }

  private rejected(policy: RoutePolicy, reason: AdmissionRejectionReason): never {
    this.emitRejected(policy, reason);
    throw new VolumeApiError(
      "VOLUME_OVERLOADED",
      reason === "transient_memory"
        ? "The server is at its transient memory budget; retry with backoff."
        : "The server is at its concurrency limit for this route; retry with backoff.",
      429
    );
  }

  // Distinct from the global refusal so operators can tell "the server is
  // full" apart from "THIS tenant is using more than its share": the caps
  // exist precisely so one tenant cannot consume the whole budget before any
  // global limit trips.
  private rejectedTenant(
    policy: RoutePolicy,
    reason: "tenant_concurrency" | "tenant_memory"
  ): never {
    this.emitRejected(policy, reason);
    throw new VolumeApiError(
      "VOLUME_TENANT_OVERLOADED",
      reason === "tenant_memory"
        ? "This tenant is at its reserved-memory budget; retry with backoff."
        : "This tenant is at its concurrent-request limit; retry with backoff.",
      429,
      { "retry-after": "1" }
    );
  }

  private emitRejected(policy: RoutePolicy, reason: AdmissionRejectionReason): void {
    this.telemetry?.emit({
      type: "admission",
      route: policy.name,
      outcome: "rejected",
      reason,
      activeRequests: this.active,
      transientBytes: this.transientBytes,
    });
  }
}

function decrementCount(counts: Map<string, number>, key: string, by: number): void {
  const next = (counts.get(key) ?? 0) - by;
  if (next <= 0) {
    counts.delete(key); // tenants at zero leave no residue in the maps
  } else {
    counts.set(key, next);
  }
}

function validatedTenantCap(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`AdmissionController ${name} must be a non-negative safe integer (0 disables).`);
  }
  return value;
}

/**
 * Parses a Content-Length header. Absent means chunked/empty (undefined);
 * malformed is a typed 400 so the weight can never be spoofed.
 */
export function parseContentLength(header: string | string[] | undefined): number | undefined {
  if (header === undefined) {
    return undefined;
  }
  const value = Array.isArray(header) ? header[0] : header;
  if (value === undefined || value === "") {
    return undefined;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new VolumeApiError("VOLUME_INVALID_CONTENT_LENGTH", "Content-Length header is invalid.", 400);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new VolumeApiError("VOLUME_INVALID_CONTENT_LENGTH", "Content-Length header is invalid.", 400);
  }
  return parsed;
}
