// Composition of the manager's GET /metrics body: fixed-name manager gauges
// refreshed at render time from the registry/lease/router snapshots, plus
// the bounded closed-allowlist child aggregation. Kept out of main.ts so the
// production tests exercise the exact assembly the deployed endpoint serves.
//
// Naming: the pfm_* scheme (pfm_manager_*, pfm_children_*, pfm_child_*,
// pfm_access_lease*, pfm_router_*) is the hosted manager's established
// metric namespace, kept byte-compatible here for ecosystem dashboards;
// aggregated child metrics render as pfm_child_<child metric name>.
import type { ChildMetricsCollector } from "./child-metrics.js";
import type { LeaseTunnelRegistry } from "./data-plane-router.js";
import type { ManagerMetrics } from "./manager-metrics.js";
import type { ProductionAuthorityRegistry } from "./production-registry.js";

export interface ManagerMetricsEndpointDeps {
  metrics: ManagerMetrics;
  // Absent in env mode: the endpoint then renders manager-process metrics
  // only (no children, no leases, no capacity state to report).
  registry?: ProductionAuthorityRegistry;
  childMetrics?: ChildMetricsCollector;
  tunnels?: LeaseTunnelRegistry;
}

export function createManagerMetricsEndpoint(
  deps: ManagerMetricsEndpointDeps
): () => Promise<string> {
  return async () => {
    const metrics = deps.metrics;
    if (deps.registry) {
      const snapshot = deps.registry.observabilitySnapshot();
      metrics.setGauge("pfm_manager_claimed", snapshot.claimed ? 1 : 0);
      metrics.setGauge("pfm_manager_superseded", snapshot.superseded ? 1 : 0);
      metrics.setGauge("pfm_manager_claim_remaining_ms", snapshot.claimRemainingMs);
      metrics.setGauge(
        "pfm_manager_consecutive_renew_failures",
        snapshot.consecutiveRenewFailures
      );
      // The epoch is a canonical decimal string (BIGINT); it is only
      // rendered while it fits a double exactly — never approximated.
      const epoch = Number(snapshot.managerEpoch);
      if (Number.isSafeInteger(epoch)) {
        metrics.setGauge("pfm_manager_epoch", epoch);
      }
      // Resident children vs the admission cap, plus cold-start gate depth.
      metrics.setGauge("pfm_children_total", snapshot.childrenTotal);
      metrics.setGauge("pfm_children_starting", snapshot.childrenStarting);
      metrics.setGauge("pfm_children_cap", snapshot.childrenCap);
      metrics.setGauge("pfm_child_start_gate_limit", snapshot.startGateLimit);
      metrics.setGauge("pfm_child_start_gate_held", snapshot.startGateHeld);
      metrics.setGauge("pfm_child_start_gate_waiters", snapshot.startGateWaiters);
      // SLO counters: monotonic process-local totals surfaced as lines of a
      // counter (the registry owns every increment).
      metrics.setGauge("pfm_manager_renewals_total", snapshot.renewalsTotal);
      metrics.setGauge("pfm_manager_renewal_failures_total", snapshot.renewalFailuresTotal);
      metrics.setGauge("pfm_child_starts_total", snapshot.childStartsTotal);
      metrics.setGauge("pfm_child_start_failures_total", snapshot.childStartFailuresTotal);
      metrics.setGauge("pfm_child_unexpected_exits_total", snapshot.childUnexpectedExitsTotal);
      metrics.setGauge("pfm_child_idle_evictions_total", snapshot.idleEvictionsTotal);
      metrics.setGauge("pfm_child_start_queue_timeouts_total", snapshot.startQueueTimeoutsTotal);
      // Typed refusal counters, one fixed name per stable code: capacity
      // pressure (503s) and per-tenant fairness refusals (429s) stay
      // distinguishable on a dashboard exactly like they are on the wire.
      metrics.setGauge(
        "pfm_authority_at_capacity_refusals_total",
        snapshot.atCapacityRefusalsTotal
      );
      metrics.setGauge(
        "pfm_tenant_at_capacity_refusals_total",
        snapshot.tenantAtCapacityRefusalsTotal
      );
      const leases = deps.registry.leases.observabilitySnapshot();
      metrics.setGauge("pfm_access_leases_active", leases.activeLeases);
      metrics.setGauge("pfm_access_lease_creates_total", leases.createsTotal);
      metrics.setGauge("pfm_access_lease_renews_total", leases.renewsTotal);
      metrics.setGauge(
        "pfm_tenant_lease_limit_refusals_total",
        leases.tenantLeaseLimitRefusalsTotal
      );
    }
    if (deps.tunnels) {
      metrics.setGauge("pfm_router_open_tunnels", deps.tunnels.totalOpenTunnels());
    }
    const childLines = deps.childMetrics ? (await deps.childMetrics.collect()).lines : [];
    return (
      metrics.renderPrometheus() + childLines.join("\n") + (childLines.length > 0 ? "\n" : "")
    );
  };
}
