import {
  assertProductionAuthorityManagerMode,
  createAuthorityManagerServer,
} from "./server.js";
import {
  authorityDataPlaneRouterLimitsFromEnv,
  createAuthorityDataPlaneRouterServer,
  LeaseTunnelRegistry,
  preflightAuthorityDataPlaneRouterTLS,
  resolveRouterTlsMaterial,
  validateAuthorityDataPlaneRouterConfig,
} from "./data-plane-router.js";
import {
  createProductionAuthorityRegistry,
  type ProductionAuthorityRegistry,
} from "./production-registry.js";
import {
  PostgresManagerControlStore,
  type ManagerControlStore,
  type ManagerControlStoreUsage,
} from "./manager-control-store.js";
import { ManagerControlReadiness } from "./control-readiness.js";
import { ChildMetricsCollector } from "./child-metrics.js";
import { ManagerMetrics } from "./manager-metrics.js";
import { createManagerMetricsEndpoint } from "./metrics-endpoint.js";
import { loadAuthorityManagerReleaseIdentity } from "./release-identity.js";
import type { AccessLeaseHandler } from "./server.js";
import { parseAuthorityAddress } from "./authority-address.js";

const port = Number(process.env.PORT || process.env.AUTHORITY_MANAGER_PORT || 8788);
// Bound on the fenced-exit teardown. Short: nothing this process still holds
// is worth keeping a fenced manager alive for.
const FENCE_EXIT_GRACE_MS = 5_000;
// Readiness probe bounds. The probe now WRITES, so both bounds matter: the
// timeout keeps a wedged control store from holding the endpoint open, and
// the cache TTL keeps readiness traffic from turning into a write stream.
const controlReadinessProbeTimeoutMs = positiveIntFromEnv(
  process.env.PORTABLEFS_MANAGER_READINESS_TIMEOUT_MS,
  2_000,
  "PORTABLEFS_MANAGER_READINESS_TIMEOUT_MS"
);
const controlReadinessCacheTtlMs = positiveIntFromEnv(
  process.env.PORTABLEFS_MANAGER_READINESS_CACHE_MS,
  5_000,
  "PORTABLEFS_MANAGER_READINESS_CACHE_MS"
);

function positiveIntFromEnv(raw: string | undefined, fallback: number, name: string): number {
  const trimmed = raw?.trim();
  if (!trimmed) {
    return fallback;
  }
  const parsed = Number(trimmed);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer of milliseconds.`);
  }
  return parsed;
}
const authToken = process.env.PORTABLEFS_AUTHORITY_MANAGER_TOKEN?.trim();
const allowUnauthenticated =
  process.env.PORTABLEFS_AUTHORITY_MANAGER_ALLOW_UNAUTHENTICATED === "1";
assertProductionAuthorityManagerMode(process.env);

// Unauthenticated session minting hands out data-plane mount credentials, so
// it is honored ONLY in an explicit local-development environment. Keying it
// off "not production" would leave it open when NODE_ENV is unset (the default
// in many production containers) or "staging" — fail closed on anything that
// is not explicitly development.
if (allowUnauthenticated && process.env.NODE_ENV !== "development") {
  throw new Error(
    "PORTABLEFS_AUTHORITY_MANAGER_ALLOW_UNAUTHENTICATED is honored only when NODE_ENV=development. Set PORTABLEFS_AUTHORITY_MANAGER_TOKEN for any non-development deployment."
  );
}

if (!authToken && !allowUnauthenticated) {
  throw new Error(
    "PORTABLEFS_AUTHORITY_MANAGER_TOKEN is required because authority sessions expose data-plane credentials. Set PORTABLEFS_AUTHORITY_MANAGER_ALLOW_UNAUTHENTICATED=1 only for local development."
  );
}

// Manager metrics registry: fixed-name scalars only (strongest cardinality
// bound); GET /metrics renders it plus the bounded, allowlisted child
// aggregation, behind the same bearer auth as every other control route.
const managerMetrics = new ManagerMetrics();

// PRODUCTION (journal-native): singleton fenced manager + one disposable
// child per active branch, remote journal/control truth. No persistent
// work directory, no local WAL, no standby pair, no file ledger.
const routerConfig = loadRouterConfig();
const routerTLSMaterial = resolveRouterTlsMaterial(routerConfig);
const dataPlaneTransport = Object.freeze(validateAuthorityDataPlaneRouterConfig(routerConfig));
await preflightAuthorityDataPlaneRouterTLS(routerTLSMaterial, dataPlaneTransport);
const managerControlStore: ManagerControlStore = loadManagerControlStore();
const productionRegistry: ProductionAuthorityRegistry = await createProductionAuthorityRegistry(
  process.env,
  { controlStore: managerControlStore }
);
// The claim heartbeat MUST be isolated from this process's event loop and
// from the shared control pool. It is the fencing authority: if its renewal
// can queue behind data-plane traffic, a HEALTHY manager under full-speed
// load fences itself and strands every client's backlog. Verified here rather
// than assumed, because the composition is what makes it true.
if (!productionRegistry.claimHeartbeatIsolated()) {
  throw new Error(
    "The production authority manager's singleton-claim heartbeat is not isolated from this event loop and its control pool. Production requires the worker-thread heartbeat with a reserved database connection."
  );
}

// A self-fenced manager is TERMINAL: it holds no claim, serves nothing, and
// cannot mint a successor epoch from inside this process. It must EXIT so the
// platform restarts it into a fresh epoch. (Recorded incident: two consecutive
// epochs fenced themselves and then hung fenced for 40+ minutes with no
// successor until a manual redeploy.)
productionRegistry.onFenced((reason) => {
  void exitAfterFence(reason);
});

const accessLeases: AccessLeaseHandler = productionRegistry.leases;
// Lease lifecycle fences live tunnels: end closes them, rotation closes
// older-generation ones.
const routerLimits = authorityDataPlaneRouterLimitsFromEnv(process.env);
const leaseTunnelRegistry = new LeaseTunnelRegistry(routerLimits);
productionRegistry.leases.onLeaseEnded((event) =>
  leaseTunnelRegistry.closeLease(event.accessLeaseId)
);
productionRegistry.leases.onLeaseRotated((accessLeaseId, tokenGeneration) =>
  leaseTunnelRegistry.closeSupersededGenerations(accessLeaseId, tokenGeneration)
);
const dataPlaneRouter = createAuthorityDataPlaneRouterServer(productionRegistry.leases, {
  tlsMaterial: routerTLSMaterial,
  dataPlaneTransport,
  maxPendingConnections: routerLimits.maxPendingConnections,
  maxConnections: routerLimits.maxConnections,
  tunnelRegistry: leaseTunnelRegistry,
});
listenTcp(dataPlaneRouter, process.env.PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR!);
const registry = productionRegistry;

// Child metrics aggregation: the manager is the ONLY scraper of the
// children's loopback /metrics; the collector enforces loopback targets,
// per-child + overall deadlines, byte caps, single-flight and TTL cache.
const childMetricsCollector = new ChildMetricsCollector({
  targets: () => productionRegistry.metricsTargets(),
  metrics: managerMetrics,
});

const releaseIdentity = loadAuthorityManagerReleaseIdentity(process.env);
console.log(
  releaseIdentity
    ? `PortableFS authority manager release identity: ${releaseIdentity.releaseId} (${releaseIdentity.sourceRevision}).`
    : "PortableFS authority manager release identity is not configured (PORTABLEFS_RELEASE_ID + PORTABLEFS_SOURCE_REVISION); /v1/release-identity answers 404."
);

// Production readiness: the process components (router listening, lease
// service healthy, live epoch claim inside its DB-derived monotonic
// deadline) AND a bounded DURABLE WRITE against the control store. Fail
// closed on any of them.
//
// The write leg is what this endpoint was missing. The control-store probe
// used to be `SELECT to_regproc('pfm.manager_renew') IS NOT NULL`, and an
// out-of-disk Postgres answers that perfectly: during a total control-store
// outage /readyz stayed 200 and the deploy gate declared the release
// healthy while every lease write was failing. The coordinator caches the
// verdict for a short TTL and keeps at most ONE probe outstanding, so
// readiness traffic never maps one-to-one onto control-store transactions.
const readiness = new ManagerControlReadiness({
  components: () =>
    dataPlaneRouter.listening && accessLeases.healthy() && productionRegistry.ready(),
  controlProbe: async (options) => {
    const probe = await managerControlStore.healthProbe?.(options);
    return (
      probe ?? {
        // A control store with no probe surface cannot prove a durable
        // transition, so it is not ready. There is no optimistic default.
        ok: false,
        lineageComplete: false,
        writable: false,
        code: "unreachable" as const,
      }
    );
  },
  probeTimeoutMs: controlReadinessProbeTimeoutMs,
  cacheTtlMs: controlReadinessCacheTtlMs,
});

// Control-store consumption for GET /metrics. pg_database_size and
// pg_total_relation_size are NOT cheap on a large cluster, so this is
// single-flight and TTL-cached: a scrape storm must never turn capacity
// reporting into control-store load. Failures render no usage gauges rather
// than failing the scrape.
const CONTROL_STORE_USAGE_TTL_MS = 60_000;
let usageCache: { at: number; value: ManagerControlStoreUsage } | undefined;
let usageFlight: Promise<ManagerControlStoreUsage | null> | undefined;

async function readControlStoreUsage(): Promise<ManagerControlStoreUsage | null> {
  if (usageCache && Date.now() - usageCache.at < CONTROL_STORE_USAGE_TTL_MS) {
    return usageCache.value;
  }
  if (!managerControlStore.usageProbe) {
    return null;
  }
  if (!usageFlight) {
    const probe = managerControlStore.usageProbe.bind(managerControlStore);
    const flight = Promise.resolve()
      .then(() => probe())
      .then(
        (value) => {
          usageCache = { at: Date.now(), value };
          return value;
        },
        () => null
      )
      .finally(() => {
        if (usageFlight === flight) {
          usageFlight = undefined;
        }
      });
    usageFlight = flight;
  }
  return usageFlight;
}

const server = createAuthorityManagerServer({
  ...(authToken ? { authToken } : {}),
  ...(allowUnauthenticated ? { allowUnauthenticated: true } : {}),
  registry,
  ...(accessLeases ? { accessLeases } : {}),
  dataPlaneTransport,
  ...(releaseIdentity ? { releaseIdentity } : {}),
  metricsEndpoint: createManagerMetricsEndpoint({
    metrics: managerMetrics,
    ...(productionRegistry ? { registry: productionRegistry } : {}),
    ...(childMetricsCollector ? { childMetrics: childMetricsCollector } : {}),
    ...(leaseTunnelRegistry ? { tunnels: leaseTunnelRegistry } : {}),
    controlStoreUsage: readControlStoreUsage,
  }),
  readiness: () => readiness.evaluate(),
});

server.listen(port, () => {
  console.log(`PortableFS authority manager listening on :${port} (production)`);
});

let shuttingDown = false;
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    void shutdown(signal);
  });
}

// exitAfterFence stops accepting anything and leaves the process, bounded.
// Exit code 1 marks it as an abnormal termination so the platform's restart
// policy applies and the restart is visible in the deploy log. The registry
// has ALREADY invalidated every lease and terminated every child by the time
// this runs; closing the listeners is only about not accepting new work
// during the exit, and it is bounded so a wedged socket cannot hold the
// process fenced-and-alive — which is the exact failure this exists to end.
let fenceExiting = false;
async function exitAfterFence(reason: string): Promise<void> {
  if (fenceExiting || shuttingDown) {
    return;
  }
  fenceExiting = true;
  console.error(
    `PortableFS authority manager fenced itself (${reason}); exiting so the platform restarts it into a fresh epoch.`
  );
  const forceExit = setTimeout(() => process.exit(1), FENCE_EXIT_GRACE_MS);
  forceExit.unref?.();
  await Promise.allSettled([
    closeServer(server).catch(() => undefined),
    closeServer(dataPlaneRouter).catch(() => undefined),
  ]);
  await managerControlStore.close().catch(() => undefined);
  clearTimeout(forceExit);
  process.exit(1);
}

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  console.log(`PortableFS authority manager shutting down after ${signal}.`);
  const forceExit = setTimeout(() => {
    console.error("PortableFS authority manager shutdown timed out.");
    process.exit(1);
  }, 30_000);
  forceExit.unref?.();
  await Promise.allSettled([
    closeServer(server),
    closeServer(dataPlaneRouter),
    registry.shutdown(),
  ]);
  await managerControlStore.close().catch(() => undefined);
  clearTimeout(forceExit);
  process.exit(0);
}

// loadManagerControlStore builds the Postgres pfm control-store adapter from
// the REQUIRED PORTABLEFS_MANAGER_CONTROL_DATABASE_URL. There is no dynamic
// module injection and no file fallback: production without the control
// database is an honest startup failure.
function loadManagerControlStore(): ManagerControlStore {
  const connectionString = process.env.PORTABLEFS_MANAGER_CONTROL_DATABASE_URL?.trim();
  if (connectionString) {
    return new PostgresManagerControlStore(connectionString);
  }
  throw new Error(
    "AUTHORITY_CONTROL_STORE_REQUIRED: PORTABLEFS_AUTHORITY_MODE=production requires PORTABLEFS_MANAGER_CONTROL_DATABASE_URL (the pfm manager-control database, portablefs_manager role). There is no file fallback; readiness fails closed until it is set."
  );
}

function loadRouterConfig() {
  return {
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR
      ? { listenAddr: process.env.PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_URL
      ? { publicUrl: process.env.PORTABLEFS_AUTHORITY_ROUTER_URL }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH
      ? { tlsCertPath: process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PATH
      ? { tlsKeyPath: process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PATH }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PEM
      ? { tlsCertPem: process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PEM }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PEM
      ? { tlsKeyPem: process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PEM }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE
      ? { transportMode: process.env.PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_SERVER_NAME
      ? { tlsServerName: process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_SERVER_NAME }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PATH
      ? { tlsCaPath: process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PATH }
      : {}),
    ...(process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PEM
      ? { tlsCaPem: process.env.PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PEM }
      : {}),
    allowPlaintextProduction:
      process.env.PORTABLEFS_AUTHORITY_ROUTER_ALLOW_PLAINTEXT_PRODUCTION === "1",
  };
}

function listenTcp(
  server: { listen(port: number, host: string, callback: () => void): unknown },
  addr: string
): void {
  const { host, port: listenPort } = parseAuthorityAddress(addr, {
    label: "PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR",
  });
  server.listen(listenPort, host, () => {
    const displayHost = host.includes(":") ? `[${host}]` : host;
    console.log(`PortableFS authority data-plane router listening on ${displayHost}:${listenPort}`);
  });
}

function closeServer(serverToClose: { close(callback: (error?: Error) => void): unknown }): Promise<void> {
  return new Promise((resolve) => {
    serverToClose.close(() => resolve());
  });
}
