// Dependency-free operational telemetry for the Volume API.
//
// Events are LOW-CARDINALITY by construction: the only string dimensions are
// static route/policy names and coarse outcome classes. Tenant ids, volume
// ids, digests, tokens, patterns, and commands must never appear in an event
// — hooks often fan out to shared metrics systems where unbounded labels are
// both a cost and a data-exfiltration hazard.

/** Fixed method dimension: unknown verbs collapse to "other". */
export type TelemetryHttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "DELETE"
  | "HEAD"
  | "OPTIONS"
  | "PATCH"
  | "other";

export type VolumeApiTelemetryEvent =
  | {
      type: "request";
      /** One of the fixed route-policy names (see limits.ts routePolicies). */
      route: string;
      method: TelemetryHttpMethod;
      status: number;
      durationMs: number;
      aborted: boolean;
    }
  | {
      type: "request_error";
      code: "VOLUME_INTERNAL";
    }
  | {
      type: "admission";
      route: string;
      outcome: "admitted" | "rejected";
      /** tenant_* reasons refuse ONE tenant's overuse; no tenant id is ever emitted. */
      reason?:
        | "global_concurrency"
        | "route_concurrency"
        | "transient_memory"
        | "tenant_concurrency"
        | "tenant_memory"
        | "draining";
      activeRequests: number;
      transientBytes: number;
    }
  | {
      type: "transient_memory";
      reservedBytes: number;
      totalBytes: number;
      direction: "reserve" | "release";
    }
  | {
      type: "history_copy";
      /** No tenant, digest, storage key, or failure-domain label. */
      outcome: "ok" | "failover" | "missing" | "corrupt" | "unreachable" | "unavailable";
    }
  | {
      type: "shutdown";
      phase:
        | "draining"
        | "effects_settled"
        | "aborting_reads"
        | "forcing_connections"
        | "closed"
        | "hard_timeout";
      pendingEffects: number;
      activeRequests: number;
    }
  | {
      /** One line per journal-bounding maintenance cycle. Counters only. */
      type: "history_maintenance";
      generationsScanned: number;
      cutsCreated: number;
      cutsPending: number;
      cutsFailed: number;
      adoptionsApplied: number;
      adoptionsBlocked: number;
      pinsScanned: number;
      pinsReleased: number;
      benignRefusals: number;
      failures: number;
      topBacklogPercent: number;
    };

export interface VolumeApiTelemetry {
  emit(event: VolumeApiTelemetryEvent): void;
}

/**
 * Wraps an optional user hook so instrumentation can never break request
 * handling: throwing hooks are swallowed, async hooks are detached, and a
 * missing hook costs one branch.
 */
export function createTelemetry(
  hook?: (event: VolumeApiTelemetryEvent) => unknown
): VolumeApiTelemetry {
  if (!hook) {
    return { emit: () => undefined };
  }
  return {
    emit(event) {
      try {
        const result = hook(event);
        if (result && typeof (result as PromiseLike<void>).then === "function") {
          void Promise.resolve(result).catch(() => undefined);
        }
      } catch {
        // Telemetry must never change API behaviour.
      }
    },
  };
}

/**
 * Production stdout sink: one JSON line per event on stdout, prefixed so log
 * pipelines can route it. Every field is already low-cardinality by the
 * VolumeApiTelemetryEvent construction (fixed route/method/outcome enums,
 * numeric measurements) — no digest, tenant, failure-domain, or message text
 * exists in the event set, so nothing here needs redaction.
 */
export function stdoutTelemetrySink(): (event: VolumeApiTelemetryEvent) => void {
  return (event) => {
    process.stdout.write(`portablefs_telemetry ${JSON.stringify(event)}\n`);
  };
}
