import { afterEach, describe, expect, test } from "vitest";
import { createHash } from "node:crypto";
import { connect, createServer, type AddressInfo, type Socket } from "node:net";
import { rootCertificates } from "node:tls";
import { accessLeaseErrorCodes } from "@portablefs/protocol";
import {
  assertProductionAuthorityManagerMode,
  AuthorityOperationError,
  authorityOperationErrorCodes,
  createAuthorityManagerServer,
  type AccessLeaseHandler,
  type AuthorityRegistry,
  type ReadinessAnswer,
} from "./server.js";
import {
  AckCode,
  type AckCodeValue,
  authorityDataPlaneRouterLimitsFromEnv,
  createAuthorityDataPlaneRouterServer,
  InMemoryAuthorityDataPlaneRouteTable,
  LeaseTunnelRegistry,
  preflightAuthorityDataPlaneRouterTLS,
  resolveDataPlaneTransportContract,
  resolveRouterTlsMaterial,
  validateRouterTLSIdentity,
  validateAuthorityDataPlaneRouterConfig,
} from "./data-plane-router.js";
import { mintRootSecret } from "./access-tokens.js";
import { ManagerMetrics } from "./manager-metrics.js";
import {
  InMemoryManagerControlStore,
  sha256Hex,
  type ManagerIdentity,
} from "./manager-control-store.js";
import { ProductionAccessLeaseService } from "./production-access-leases.js";
import {
  testTLSCNOnlyLeaf,
  testTLSIntermediateCA,
  testTLSLeaf,
  testTLSLeafKey,
  testTLSOtherRootCA,
  testTLSPartialWildcardLeaf,
  testTLSRootCA,
  testTLSWrongKey,
} from "./test-tls-fixtures.js";

const servers: Array<ReturnType<typeof createAuthorityManagerServer>> = [];
const tcpServers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
        })
    )
  );
  await Promise.all(
    tcpServers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
        })
    )
  );
});

describe("createAuthorityManagerServer", () => {
  test("requires explicit unauthenticated mode for credential-bearing routes", () => {
    expect(() =>
      createAuthorityManagerServer({
        registry: fixedEndpointRegistry(),
      })
    ).toThrow(/authToken is required/);
  });

  test("rejects unauthenticated mode in production", () => {
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      expect(() =>
        createAuthorityManagerServer({
          allowUnauthenticated: true,
          registry: fixedEndpointRegistry(),
        })
      ).toThrow(/allowUnauthenticated cannot be enabled in production/);
    } finally {
      if (originalNodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = originalNodeEnv;
      }
    }
  });

  test("allows health checks while protecting authority routes", async () => {
    const baseUrl = await startServer("manager-token");

    const health = await fetch(`${baseUrl}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true });

    const unauthorized = await fetch(`${baseUrl}/v1/authorities/ensure`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });
    expect(unauthorized.status).toBe(401);
    expect(await unauthorized.json()).toEqual({ error: "Unauthorized." });
  });

  test("ready checks can fail independently from liveness", async () => {
    const baseUrl = await startCustomServer({
      ensureAuthority: async () => ({ authorityUrl: "router.example:2050" }),
      isHealthy: async () => true,
    }, undefined, () => false);

    const health = await fetch(`${baseUrl}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true });

    // /livez is the conventional spelling of the same dependency-free check.
    // Restarting a manager whose DATABASE is sick fixes nothing and throws
    // away its epoch claim, so a sick control store must fail /readyz only.
    const live = await fetch(`${baseUrl}/livez`);
    expect(live.status).toBe(200);
    expect(await live.json()).toEqual({ ok: true });

    const ready = await fetch(`${baseUrl}/readyz`);
    expect(ready.status).toBe(503);
    expect(await ready.json()).toEqual({ ok: false });
  });

  test("/readyz names the coarse reason on failure and stays exactly {ok:true} when ready", async () => {
    const registry = {
      ensureAuthority: async () => ({ authorityUrl: "router.example:2050" }),
      isHealthy: async () => true,
    };
    // The incident's shape: the control store answers reads but refuses a
    // durable write. `unreachable` would be a lie and `ok` was the lie that
    // shipped a healthy deploy.
    const unreadyUrl = await startCustomServer(registry, undefined, () => ({
      ok: false,
      code: "not_writable",
    }));
    const unready = await fetch(`${unreadyUrl}/readyz`);
    expect(unready.status).toBe(503);
    expect(await unready.json()).toEqual({ ok: false, code: "not_writable" });

    // A ready manager's body is byte-identical to what it always was: no
    // code, and nothing that could leak database detail to this
    // UNAUTHENTICATED route.
    const readyUrl = await startCustomServer(registry, undefined, () => ({ ok: true }));
    const ready = await fetch(`${readyUrl}/readyz`);
    expect(ready.status).toBe(200);
    expect(await ready.json()).toEqual({ ok: true });
  });

  test("typed backpressure refusals render 503 with a Retry-After header so mount clients back off", async () => {
    const refuse = (code: string) => {
      throw new AuthorityOperationError(503, code, "the registry refused the new spawn", {
        retryAfterSeconds: 15,
      });
    };
    const headers = {
      authorization: "Bearer manager-token",
      "content-type": "application/json",
    };

    for (const code of [
      authorityOperationErrorCodes.atCapacity,
      authorityOperationErrorCodes.startQueueTimeout,
    ]) {
      const baseUrl = await startCustomServer(
        {
          ensureAuthority: async () => refuse(code),
          isHealthy: async () => true,
        },
        "manager-token"
      );
      const response = await fetch(`${baseUrl}/v1/authorities/ensure`, {
        method: "POST",
        headers,
        body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
      });
      expect(response.status).toBe(503);
      expect(response.headers.get("retry-after")).toBe("15");
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe(code);
    }
  });

  test("typed per-tenant fairness refusals render 429 with Retry-After, distinct from the 503 capacity codes", async () => {
    const refuse = (code: string) => {
      throw new AuthorityOperationError(429, code, "the tenant is over its fairness budget", {
        retryAfterSeconds: 15,
      });
    };
    const headers = {
      authorization: "Bearer manager-token",
      "content-type": "application/json",
    };

    for (const code of [
      authorityOperationErrorCodes.tenantAtCapacity,
      authorityOperationErrorCodes.tenantLeaseLimit,
    ]) {
      const baseUrl = await startCustomServer(
        {
          ensureAuthority: async () => refuse(code),
          isHealthy: async () => true,
        },
        "manager-token"
      );
      const response = await fetch(`${baseUrl}/v1/authorities/ensure`, {
        method: "POST",
        headers,
        body: JSON.stringify({ teamId: "team_1", volumeId: "vol_1", branch: "main" }),
      });
      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toBe("15");
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe(code);
    }
  });

  test("GET /metrics requires the manager bearer token and renders bounded text", async () => {
    const metrics = new ManagerMetrics();
    metrics.counter("pfm_child_scrape_errors_total").add(2);
    metrics.setGauge("pfm_manager_claimed", 1);
    const baseUrl = await startCustomServer(
      {
        ensureAuthority: async () => ({ authorityUrl: "router.example:2050" }),
        isHealthy: async () => true,
      },
      "manager-token",
      undefined,
      undefined,
      async () => metrics.renderPrometheus()
    );

    // The exposition names capacity/tenant pressure — operator data — so the
    // route sits behind the SAME bearer gate as every other control route.
    const unauthenticated = await fetch(`${baseUrl}/metrics`);
    expect(unauthenticated.status).toBe(401);
    const wrongToken = await fetch(`${baseUrl}/metrics`, {
      headers: { authorization: "Bearer wrong-token" },
    });
    expect(wrongToken.status).toBe(401);

    const authenticated = await fetch(`${baseUrl}/metrics`, {
      headers: { authorization: "Bearer manager-token" },
    });
    expect(authenticated.status).toBe(200);
    expect(String(authenticated.headers.get("content-type"))).toContain("text/plain");
    const body = await authenticated.text();
    expect(body).toContain("pfm_child_scrape_errors_total 2");
    expect(body).toContain("pfm_manager_claimed 1");
    expect(body).not.toMatch(/volume|branch|session|token|digest/);
  });

  test("GET /metrics is 404 when unwired and 503 when rendering fails, never a partial body or a leaked target", async () => {
    const unwired = await startServer("manager-token");
    const missing = await fetch(`${unwired}/metrics`, {
      headers: { authorization: "Bearer manager-token" },
    });
    expect(missing.status).toBe(404);

    const failing = await startCustomServer(
      {
        ensureAuthority: async () => ({ authorityUrl: "router.example:2050" }),
        isHealthy: async () => true,
      },
      "manager-token",
      undefined,
      undefined,
      async () => {
        throw new Error("scrape pipeline exploded at http://127.0.0.1:9999/metrics");
      }
    );
    const failed = await fetch(`${failing}/metrics`, {
      headers: { authorization: "Bearer manager-token" },
    });
    expect(failed.status).toBe(503);
    const failedBody = await failed.text();
    expect(failedBody).not.toContain("127.0.0.1:9999"); // target URLs never leak
    expect(failedBody).toContain("Metrics unavailable.");
  });

  test("ensure returns authority routing without exposing the data-plane token", async () => {
    const baseUrl = await startServer("manager-token");

    const response = await fetch(`${baseUrl}/v1/authorities/ensure`, {
      method: "POST",
      headers: {
        authorization: "Bearer manager-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        teamId: "team_1",
        volumeId: "vol_1",
        branch: "main",
      }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      authority: {
        provider: "portablefs-managed",
        authorityUrl: "vcs.example:2050",
        host: "vcs.example",
        port: 2050,
      },
    });
  });

  test("the retired session route answers a typed 410 without touching the registry", async () => {
    const baseUrl = await startCustomServer(unreachableRegistry(), "manager-token");

    const response = await fetch(`${baseUrl}/v1/authorities/session`, {
      method: "POST",
      headers: {
        authorization: "Bearer manager-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });

    expect(response.status).toBe(410);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("AUTHORITY_SESSION_RETIRED");
    expect(body.error.message).toContain("/v1/access-leases/create");
  });

  test("the retired mount-session routes answer a typed 410 without touching the registry", async () => {
    const baseUrl = await startCustomServer(unreachableRegistry(), "manager-token");

    for (const path of ["/v1/mount-sessions", "/v1/volumes/vol_1/mount-sessions"]) {
      const response = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: {
          authorization: "Bearer manager-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({ volumeId: "vol_1" }),
      });

      expect(response.status).toBe(410);
      const body = (await response.json()) as { error: { code: string; message: string } };
      expect(body.error.code).toBe("MOUNT_SESSION_RETIRED");
      expect(body.error.message).toContain("/v1/access-leases/create");
    }
  });

  test("the retired routes still require the manager bearer token", async () => {
    const baseUrl = await startCustomServer(unreachableRegistry(), "manager-token");

    const response = await fetch(`${baseUrl}/v1/mount-sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1" }),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "Unauthorized." });
  });

  test("health delegates to the registry", async () => {
    const baseUrl = await startCustomServer({
      ensureAuthority: async () => ({ authorityUrl: "vcs.example:2050" }),
      isHealthy: async () => false,
    });

    const response = await fetch(`${baseUrl}/v1/authorities/health`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ healthy: false });
  });

  test("health uses side-effect-free inspection when the registry supports it", async () => {
    let ensureCalls = 0;
    let inspectCalls = 0;
    const baseUrl = await startCustomServer({
      ensureAuthority: async () => {
        ensureCalls += 1;
        return { authorityUrl: "router.example:2050" };
      },
      inspectAuthority: async () => {
        inspectCalls += 1;
        return { authorityUrl: "router.example:2050", authorityInstanceId: "pfai_1" };
      },
      isHealthy: async (_ref, endpoint) => endpoint.authorityInstanceId === "pfai_1",
    });

    const response = await fetch(`${baseUrl}/v1/authorities/health`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ healthy: true });
    expect(inspectCalls).toBe(1);
    expect(ensureCalls).toBe(0);
  });

  test("stop validates expected authority identity and returns the advisory no-op result", async () => {
    const baseUrl = await startServer();

    const response = await fetch(`${baseUrl}/v1/authorities/stop`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        teamId: "team_1",
        volumeId: "vol_1",
        branch: "main",
        expectedAuthority: {
          provider: "portablefs-managed",
          authorityUrl: "vcs.example:2050",
          host: "vcs.example",
          port: 2050,
        },
      }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ stopped: false, managed: false });
  });

  test("stop delegates to managed registries with the expected authority identity", async () => {
    const stopCalls: unknown[] = [];
    const baseUrl = await startCustomServer({
      ensureAuthority: async () => ({ authorityUrl: "router.example:2050" }),
      isHealthy: async () => true,
      stopAuthority: async (ref) => {
        stopCalls.push(ref);
        return { stopped: true, managed: true };
      },
    });

    const response = await fetch(`${baseUrl}/v1/authorities/stop`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        teamId: "team_1",
        volumeId: "vol_1",
        branch: "main",
        expectedAuthority: {
          authorityUrl: "router.example:2050",
          authorityInstanceId: "pfai_1",
        },
      }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ stopped: true, managed: true });
    expect(stopCalls).toHaveLength(1);
    expect(stopCalls[0]).toMatchObject({
      volumeId: "vol_1",
      expectedAuthority: { authorityInstanceId: "pfai_1" },
    });
  });

  test("stop requires expected authority identity", async () => {
    const baseUrl = await startServer();

    const response = await fetch(`${baseUrl}/v1/authorities/stop`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        volumeId: "vol_1",
        branch: "main",
      }),
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "expectedAuthority is required for stop." });
  });

  test("mode selection refuses the retired managed and env modes by name and names production as the only mode", () => {
    expect(() => assertProductionAuthorityManagerMode({})).not.toThrow();
    expect(() =>
      assertProductionAuthorityManagerMode({ PORTABLEFS_AUTHORITY_MODE: "production" })
    ).not.toThrow();

    expect(() =>
      assertProductionAuthorityManagerMode({ PORTABLEFS_AUTHORITY_MODE: "managed" })
    ).toThrow(/managed is no longer supported[\s\S]*Production mode/);
    expect(() =>
      assertProductionAuthorityManagerMode({ PORTABLEFS_AUTHORITY_MODE: "env" })
    ).toThrow(/env is no longer supported[\s\S]*Production mode/);
    expect(() =>
      assertProductionAuthorityManagerMode({ PORTABLEFS_AUTHORITY_MODE: "paired" })
    ).toThrow(/must be production/);
  });

  test("retired env-registry variables are rejected by name", () => {
    expect(() =>
      assertProductionAuthorityManagerMode({ PORTABLEFS_AUTHORITY_URL: "vcs.example:2050" })
    ).toThrow(/PORTABLEFS_AUTHORITY_URL[\s\S]*retired env registry/);
    expect(() =>
      assertProductionAuthorityManagerMode({
        PORTABLEFS_AUTHORITY_MAP_JSON: JSON.stringify({ "vol_1:main": {} }),
      })
    ).toThrow(/PORTABLEFS_AUTHORITY_MAP_JSON[\s\S]*retired env registry/);
  });
});

describe("authority data-plane router", () => {
  test("parses bounded router limits and rejects invalid or contradictory values", () => {
    expect(authorityDataPlaneRouterLimitsFromEnv({})).toEqual({
      maxPendingConnections: 256,
      maxOpenTunnels: 4096,
      maxTunnelsPerLease: 64,
      maxConnections: 4352,
    });
    expect(
      authorityDataPlaneRouterLimitsFromEnv({
        PORTABLEFS_AUTHORITY_ROUTER_MAX_PENDING_CONNECTIONS: "12",
        PORTABLEFS_AUTHORITY_ROUTER_MAX_OPEN_TUNNELS: "100",
        PORTABLEFS_AUTHORITY_ROUTER_MAX_TUNNELS_PER_LEASE: "20",
      })
    ).toEqual({
      maxPendingConnections: 12,
      maxOpenTunnels: 100,
      maxTunnelsPerLease: 20,
      maxConnections: 112,
    });
    expect(() =>
      authorityDataPlaneRouterLimitsFromEnv({
        PORTABLEFS_AUTHORITY_ROUTER_MAX_PENDING_CONNECTIONS: "0",
      })
    ).toThrow(/positive safe integer/);
    expect(() =>
      authorityDataPlaneRouterLimitsFromEnv({
        PORTABLEFS_AUTHORITY_ROUTER_MAX_OPEN_TUNNELS: "10",
        PORTABLEFS_AUTHORITY_ROUTER_MAX_TUNNELS_PER_LEASE: "11",
      })
    ).toThrow(/must not exceed/);
  });

  test("reservations enforce per-lease and global tunnel limits and release capacity", () => {
    const registry = new LeaseTunnelRegistry({
      maxOpenTunnels: 2,
      maxTunnelsPerLease: 1,
    });
    const first = registry.reserve("lease-1", "1");
    expect(first).not.toBeNull();
    expect(registry.reserve("lease-1", "1")).toBeNull();
    const second = registry.reserve("lease-2", "1");
    expect(second).not.toBeNull();
    expect(registry.reserve("lease-3", "1")).toBeNull();
    expect(registry.pendingTunnelCount()).toBe(2);

    registry.releaseReservation(first!);
    expect(registry.pendingTunnelCount()).toBe(1);
    expect(registry.reserve("lease-3", "1")).not.toBeNull();
  });

  test("refuses handshakes above the pending-connection cap", async () => {
    const routeTable = new InMemoryAuthorityDataPlaneRouteTable();
    const router = createAuthorityDataPlaneRouterServer(routeTable, {
      maxPendingConnections: 1,
      maxConnections: 2,
      handshakeTimeoutMs: 5_000,
    });
    tcpServers.push(router);
    const routerAddress = await listenTcp(router);

    const parked = await connectClient(routerAddress);
    const excess = await connectClient(routerAddress);
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error("excess pending connection was not closed")),
        1_000
      );
      excess.once("close", () => {
        clearTimeout(timeout);
        resolve();
      });
    });
    expect(excess.destroyed).toBe(true);
    parked.destroy();
  });

  test("routes a scoped session token to the backend using the internal backend token", async () => {
    const backend = await startTokenBackend("backend-token");
    const routeTable = new InMemoryAuthorityDataPlaneRouteTable();
    const session = routeTable.createSession({
      authorityInstanceId: "pfai_1",
      backendAddresses: [backend.address],
      backendAuthToken: "backend-token",
    });
    const router = createAuthorityDataPlaneRouterServer(routeTable);
    tcpServers.push(router);
    const routerAddress = await listenTcp(router);

    const client = await connectClient(routerAddress);
    await writeTokenFrame(client, session.token);
    const ack = await readExactly(client, 1);
    expect(ack[0]).toBe(0);
    client.write("ping");
    const echo = await readExactly(client, 4);
    expect(echo.toString("utf8")).toBe("ping");
    client.destroy();
  });

  test("closes a backend that rejects router auth before falling back", async () => {
    let closeRejectedBackend!: () => void;
    const rejectedBackendClosed = new Promise<void>((resolve) => {
      closeRejectedBackend = resolve;
    });
    let rejectedBackendWasClosed = false;
    const rejectedBackend = createServer((socket) => {
      const cleanupTimer = setTimeout(() => socket.destroy(), 1_000);
      cleanupTimer.unref?.();
      socket.once("close", () => {
        clearTimeout(cleanupTimer);
        rejectedBackendWasClosed = true;
        closeRejectedBackend();
      });
      void readTokenFrame(socket)
        .then(() => {
          socket.write(Buffer.from([1]));
        })
        .catch(() => socket.destroy());
    });
    tcpServers.push(rejectedBackend);
    const rejectedAddress = await listenTcp(rejectedBackend);

    const fallbackBackend = createServer((socket) => {
      void (async () => {
        await readTokenFrame(socket);
        await rejectedBackendClosed;
        socket.write(Buffer.from([0]));
        socket.pipe(socket);
      })().catch(() => socket.destroy());
    });
    tcpServers.push(fallbackBackend);
    const fallbackAddress = await listenTcp(fallbackBackend);

    const routeTable = new InMemoryAuthorityDataPlaneRouteTable();
    const session = routeTable.createSession({
      authorityInstanceId: "pfai_1",
      backendAddresses: [
        `${rejectedAddress.host}:${rejectedAddress.port}`,
        `${fallbackAddress.host}:${fallbackAddress.port}`,
      ],
      backendAuthToken: "backend-token",
    });
    const router = createAuthorityDataPlaneRouterServer(routeTable, {
      handshakeTimeoutMs: 250,
    });
    tcpServers.push(router);
    const routerAddress = await listenTcp(router);

    const client = await connectClient(routerAddress);
    await writeTokenFrame(client, session.token);
    const ack = await readExactly(client, 1);
    expect(ack[0]).toBe(0);
    expect(rejectedBackendWasClosed).toBe(true);
    client.destroy();
  });

  test("rejects unknown session tokens before reaching a backend", async () => {
    const routeTable = new InMemoryAuthorityDataPlaneRouteTable();
    const router = createAuthorityDataPlaneRouterServer(routeTable);
    tcpServers.push(router);
    const routerAddress = await listenTcp(router);

    const client = await connectClient(routerAddress);
    await writeTokenFrame(client, "missing-token");
    const ack = await readExactly(client, 1);
    // A token that resolves to nothing IS a credential verdict — the one
    // condition ack 1 is entitled to mean.
    expect(ack[0]).toBe(AckCode.CredentialRejected);
    client.destroy();
  });

  // AN AUTHORITY OUTAGE IS NOT A DEAD CREDENTIAL. The router used to close
  // this connection with no ack at all, leaving the client to guess; guessing
  // "the credential is dead" over an authority that is merely down sends the
  // operator to re-authenticate through an outage they cannot affect.
  test("answers an authority-side outage as its own condition, not as a credential refusal", async () => {
    // A listener that is bound and then closed gives a deterministic ECONNREFUSED.
    const dead = createServer(() => undefined);
    const deadAddress = await listenTcp(dead);
    await new Promise<void>((resolve) => dead.close(() => resolve()));

    const routeTable = new InMemoryAuthorityDataPlaneRouteTable();
    const session = routeTable.createSession({
      authorityInstanceId: "pfai_1",
      backendAddresses: [`${deadAddress.host}:${deadAddress.port}`],
      backendAuthToken: "backend-token",
    });
    const router = createAuthorityDataPlaneRouterServer(routeTable, {
      backendConnectTimeoutMs: 250,
      handshakeTimeoutMs: 250,
    });
    tcpServers.push(router);
    const routerAddress = await listenTcp(router);

    const client = await connectClient(routerAddress);
    await writeTokenFrame(client, session.token);
    const ack = await readExactly(client, 1);
    expect(ack[0]).toBe(AckCode.AuthorityUnavailable);
    expect(ack[0]).not.toBe(AckCode.CredentialRejected);
    client.destroy();
  });

  test("router TLS material resolves from exactly one source and validation covers every half-configured shape", () => {
    // Inline PEMs (sealed env vars on platforms without file mounts).
    const pem = resolveRouterTlsMaterial({ tlsCertPem: "CERT-PEM", tlsKeyPem: "KEY-PEM" });
    expect(pem?.cert.toString("utf8")).toBe("CERT-PEM");
    expect(pem?.key.toString("utf8")).toBe("KEY-PEM");
    // No TLS configured.
    expect(resolveRouterTlsMaterial({})).toBeNull();
    // Half-configured shapes refuse.
    expect(() => resolveRouterTlsMaterial({ tlsCertPem: "CERT-PEM" })).toThrow(
      /TLS_KEY_PEM/
    );
    expect(() => resolveRouterTlsMaterial({ tlsCertPath: "/etc/cert.pem" })).toThrow(
      /TLS_KEY_PATH/
    );
    // Mixing sources is ambiguous and refuses.
    expect(() =>
      resolveRouterTlsMaterial({
        tlsCertPath: "/etc/cert.pem",
        tlsKeyPath: "/etc/key.pem",
        tlsCertPem: "CERT-PEM",
        tlsKeyPem: "KEY-PEM",
      })
    ).toThrow(/never both/);

    // The router accepts either full TLS source and refuses plaintext
    // regardless of NODE_ENV (often unset in bare-node and Kubernetes
    // deployments) unless the explicit tunnel escape hatch is set.
    const base = {
      listenAddr: "0.0.0.0:2050",
      publicUrl: "vcs.example:2050",
    };
    expect(
      validateAuthorityDataPlaneRouterConfig({
        ...base,
        tlsCertPem: "C",
        tlsKeyPem: "K",
        transportMode: "tls-system-pki",
        tlsServerName: "router.example",
      })
    ).toEqual({ mode: "tls-system-pki", serverName: "router.example" });
    expect(() => validateAuthorityDataPlaneRouterConfig(base)).toThrow(
      /TRANSPORT_MODE/
    );
    expect(
      validateAuthorityDataPlaneRouterConfig({
        ...base,
        transportMode: "plaintext",
        allowPlaintextProduction: true,
      })
    ).toEqual({ mode: "plaintext" });
    expect(() =>
      validateAuthorityDataPlaneRouterConfig({ ...base, tlsCertPem: "C" })
    ).toThrow(/TLS_KEY_PEM/);
    expect(() =>
      resolveDataPlaneTransportContract({
        transportMode: "plaintext",
        allowPlaintextProduction: false,
      })
    ).toThrow(/ALLOW_PLAINTEXT/);
    expect(() =>
      resolveDataPlaneTransportContract({
        transportMode: "tls-system-pki",
      })
    ).toThrow(/TLS_SERVER_NAME/);
    expect(() =>
      resolveDataPlaneTransportContract({
        transportMode: "tls-system-pki",
        tlsServerName: "router.example:2050",
      })
    ).toThrow(/valid DNS name or IP address/);
    expect(
      resolveDataPlaneTransportContract({
        transportMode: "tls-system-pki",
        tlsServerName: "2001:db8::1",
      })
    ).toEqual({ mode: "tls-system-pki", serverName: "2001:db8::1" });
    expect(() =>
      resolveDataPlaneTransportContract({
        transportMode: "tls-system-pki",
        tlsServerName: "fe80::1%en0",
      })
    ).toThrow(/valid DNS name or IP address/);
    expect(() =>
      resolveDataPlaneTransportContract({
        transportMode: "tls-private-ca",
        tlsServerName: "router.example",
        tlsCaPem: "not a certificate",
      })
    ).toThrow(/no certificates/);
    const privateCA = rootCertificates[0]!;
    expect(
      resolveDataPlaneTransportContract({
        transportMode: "tls-private-ca",
        tlsServerName: "router.example",
        tlsCaPem: privateCA,
      })
    ).toEqual({
      mode: "tls-private-ca",
      serverName: "router.example",
      caPem: privateCA,
      caSha256: createHash("sha256").update(privateCA).digest("hex"),
    });
    expect(() =>
      resolveDataPlaneTransportContract({
        transportMode: "tls-private-ca",
        tlsServerName: "router.example",
        tlsCaPem: testTLSLeaf,
      })
    ).toThrow(/not a CA certificate/);
    expect(() =>
      resolveDataPlaneTransportContract({
        transportMode: "tls-private-ca",
        tlsServerName: "router.example",
        tlsCaPem: testTLSRootCA + testTLSRootCA,
      })
    ).toThrow(/repeats certificate/);
    expect(() =>
      validateAuthorityDataPlaneRouterConfig({
        ...base,
        transportMode: "plaintext",
        allowPlaintextProduction: true,
        tlsCertPem: "C",
        tlsKeyPem: "K",
      })
    ).toThrow(/must not configure router TLS/);
    expect(() =>
      validateAuthorityDataPlaneRouterConfig({
        ...base,
        transportMode: "tls-system-pki",
        tlsServerName: "router.example",
      })
    ).toThrow(/requires router TLS certificate/);
  });

  test("startup preflight proves a complete private-CA chain and exact DNS/IP identity", async () => {
    const tls = {
      cert: Buffer.from(testTLSLeaf + testTLSIntermediateCA),
      key: Buffer.from(testTLSLeafKey),
    };
    const dnsTransport = resolveDataPlaneTransportContract({
      transportMode: "tls-private-ca",
      tlsServerName: "router.example",
      tlsCaPem: testTLSRootCA,
    });
    const ipTransport = resolveDataPlaneTransportContract({
      transportMode: "tls-private-ca",
      tlsServerName: "2001:db8::1",
      tlsCaPem: testTLSRootCA,
    });
    await expect(preflightAuthorityDataPlaneRouterTLS(tls, dnsTransport)).resolves.toBeUndefined();
    await expect(preflightAuthorityDataPlaneRouterTLS(tls, ipTransport)).resolves.toBeUndefined();
  });

  test("startup preflight rejects key, name, chain, trust, and PEM ambiguity", async () => {
    const privateTransport = resolveDataPlaneTransportContract({
      transportMode: "tls-private-ca",
      tlsServerName: "router.example",
      tlsCaPem: testTLSRootCA,
    });
    const chain = Buffer.from(testTLSLeaf + testTLSIntermediateCA);

    await expect(
      preflightAuthorityDataPlaneRouterTLS(
        { cert: chain, key: Buffer.from(testTLSWrongKey) },
        privateTransport
      )
    ).rejects.toThrow(/does not match/);
    await expect(
      preflightAuthorityDataPlaneRouterTLS(
        { cert: chain, key: Buffer.from(testTLSLeafKey + testTLSWrongKey) },
        privateTransport
      )
    ).rejects.toThrow(/exactly one/);

    const wrongName = resolveDataPlaneTransportContract({
      transportMode: "tls-private-ca",
      tlsServerName: "wrong.example",
      tlsCaPem: testTLSRootCA,
    });
    await expect(
      preflightAuthorityDataPlaneRouterTLS(
        { cert: chain, key: Buffer.from(testTLSLeafKey) },
        wrongName
      )
    ).rejects.toThrow(/does not match advertised serverName/);

    await expect(
      preflightAuthorityDataPlaneRouterTLS(
        {
          cert: Buffer.from(testTLSIntermediateCA + testTLSLeaf),
          key: Buffer.from(testTLSLeafKey),
        },
        privateTransport
      )
    ).rejects.toThrow(/non-CA serving leaf/);
    await expect(
      preflightAuthorityDataPlaneRouterTLS(
        { cert: Buffer.from(testTLSLeaf), key: Buffer.from(testTLSLeafKey) },
        privateTransport
      )
    ).rejects.toThrow(/private-CA trust preflight failed/);

    const wrongTrust = resolveDataPlaneTransportContract({
      transportMode: "tls-private-ca",
      tlsServerName: "router.example",
      tlsCaPem: testTLSOtherRootCA,
    });
    await expect(
      preflightAuthorityDataPlaneRouterTLS(
        { cert: chain, key: Buffer.from(testTLSLeafKey) },
        wrongTrust
      )
    ).rejects.toThrow(/private-CA trust preflight failed/);

    await expect(
      preflightAuthorityDataPlaneRouterTLS(
        {
          cert: Buffer.from(testTLSLeaf + testTLSIntermediateCA + testTLSIntermediateCA),
          key: Buffer.from(testTLSLeafKey),
        },
        privateTransport
      )
    ).rejects.toThrow(/repeats certificate/);
  });

  test("system-PKI startup also refuses a chain absent from the manager's default roots", async () => {
    const tls = {
      cert: Buffer.from(testTLSLeaf + testTLSIntermediateCA),
      key: Buffer.from(testTLSLeafKey),
    };
    const transport = {
      mode: "tls-system-pki" as const,
      serverName: "router.example",
    };
    // The fixture identity is otherwise valid, but its private root is absent
    // from Node's default roots. Publishing it as system-PKI would make every
    // default client fail, so startup refuses before the real listener.
    expect(() => validateRouterTLSIdentity(tls, transport)).not.toThrow();
    await expect(preflightAuthorityDataPlaneRouterTLS(tls, transport)).rejects.toThrow(
      /system-PKI trust preflight failed/
    );
  });

  test("hostname proof is SAN-only and disables Node-only partial wildcard behavior", () => {
    const tls = {
      cert: Buffer.from(testTLSLeaf + testTLSIntermediateCA),
      key: Buffer.from(testTLSLeafKey),
    };
    expect(() =>
      validateRouterTLSIdentity(tls, {
        mode: "tls-system-pki",
        serverName: "router.example",
      })
    ).not.toThrow();
    expect(() =>
      validateRouterTLSIdentity(tls, {
        mode: "tls-system-pki",
        serverName: "prefix.router.example",
      })
    ).toThrow(/does not match/);
    expect(() =>
      validateRouterTLSIdentity(
        {
          cert: Buffer.from(testTLSCNOnlyLeaf + testTLSIntermediateCA),
          key: Buffer.from(testTLSLeafKey),
        },
        {
          mode: "tls-system-pki",
          serverName: "cn-only.example",
        }
      )
    ).toThrow(/does not match/);
    expect(() =>
      validateRouterTLSIdentity(
        {
          cert: Buffer.from(testTLSPartialWildcardLeaf + testTLSIntermediateCA),
          key: Buffer.from(testTLSLeafKey),
        },
        {
          mode: "tls-system-pki",
          serverName: "prefix123.example.com",
        }
      )
    ).toThrow(/does not match/);
  });
});

// ---------------------------------------------------------------------------
// Canonical access-lease routes (POST /v1/access-leases/*).
//
// The full route lifecycle over the production lease service (create/inspect/
// renew/release/revoke/revoke-owner, replays, conflicts, epoch supersession,
// store outages) is covered in production.test.ts. These tests cover the
// server's own gating, which no lease service ever sees.
// ---------------------------------------------------------------------------

describe("access-lease routes", () => {
  function leaseStubRegistry(instanceId?: string): AuthorityRegistry {
    return {
      ensureAuthority: async () => ({
        provider: "portablefs-managed",
        authorityUrl: "router.example:2050",
        host: "router.example",
        port: 2050,
        ...(instanceId ? { authorityInstanceId: instanceId } : {}),
      }),
      isHealthy: async () => true,
    };
  }

  // A healthy lease handler that must never be dispatched to: every test
  // here exercises a refusal the server issues before touching the service.
  function unreachableLeaseHandler(): AccessLeaseHandler {
    const refuse = () => {
      throw new Error("the lease service must not be reached");
    };
    return {
      healthy: () => true,
      create: refuse,
      inspect: refuse,
      renew: refuse,
      release: refuse,
      revoke: refuse,
      revokeOwner: refuse,
    };
  }

  async function postJson(
    baseUrl: string,
    path: string,
    body: unknown,
    bearer = "manager-token"
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const response = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: (await response.json()) as Record<string, unknown> };
  }

  test("managers without a lease service answer 501 unsupported", async () => {
    const baseUrl = await startCustomServer(leaseStubRegistry("pfai_lease"), "manager-token");

    const { status, body } = await postJson(baseUrl, "/v1/access-leases/create", {
      operationId: "op-unsupported-1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "worker-1",
    });
    expect(status).toBe(501);
    expect(body.error).toMatchObject({ code: accessLeaseErrorCodes.unsupported });
  });

  test("a wrong manager bearer is rejected before any lease dispatch", async () => {
    const baseUrl = await startCustomServer(
      leaseStubRegistry("pfai_lease"),
      "manager-token",
      undefined,
      unreachableLeaseHandler()
    );

    const { status, body } = await postJson(
      baseUrl,
      "/v1/access-leases/create",
      {
        operationId: "op-bearer-1",
        volumeId: "vol_1",
        branch: "main",
        consumerId: "worker-1",
      },
      "wrong-token"
    );
    expect(status).toBe(401);
    expect(body).toEqual({ error: "Unauthorized." });
  });

  test("an authority without an instance id cannot back a lease", async () => {
    const baseUrl = await startCustomServer(
      leaseStubRegistry(),
      "manager-token",
      () => true,
      unreachableLeaseHandler()
    );

    const { status, body } = await postJson(baseUrl, "/v1/access-leases/create", {
      operationId: "op-no-instance-1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "worker-1",
    });
    expect(status).toBe(501);
    expect(body.error).toMatchObject({ code: accessLeaseErrorCodes.unsupported });
  });
});

// ---------------------------------------------------------------------------
// Lease-scoped data-plane tunnel lifecycle.
// ---------------------------------------------------------------------------

describe("access-lease data-plane tunnels", () => {
  const leaseServices: ProductionAccessLeaseService[] = [];

  afterEach(() => {
    for (const service of leaseServices.splice(0)) {
      service.close();
    }
  });

  interface LeaseRouterHarness {
    service: ProductionAccessLeaseService;
    tunnelRegistry: LeaseTunnelRegistry;
    routerAddress: { host: string; port: number };
    backendSockets: Socket[];
  }

  // The same wiring main.ts performs in production mode: the lease service
  // IS the router's route table, and lease end/rotation events close
  // registered tunnels through the LeaseTunnelRegistry.
  async function startLeaseRouter(limits?: {
    maxOpenTunnels: number;
    maxTunnelsPerLease: number;
  }): Promise<LeaseRouterHarness> {
    const backend = await startTrackingBackend("backend-token");
    const store = new InMemoryManagerControlStore();
    const claim = await store.claimManager({
      operationId: `claim-router-${Math.random().toString(36).slice(2)}`,
      runtimeId: "manager-router",
      capabilityHash: sha256Hex("capability-router"),
      ttlMs: 300_000,
    });
    const identity: ManagerIdentity = {
      managerEpoch: claim.managerEpoch,
      managerRuntimeId: "manager-router",
      managerCapability: "capability-router",
    };
    await store.beginAuthorityRuntime({
      identity,
      scope: { tenantKey: "t:team_1", volumeId: "vol_1", branch: "main" },
      authorityInstanceId: "pfai_1",
      runtimeId: "runtime-1",
    });
    const service = new ProductionAccessLeaseService(
      store,
      identity,
      { dbTimeMs: claim.dbTimeMs },
      mintRootSecret()
    );
    leaseServices.push(service);
    service.setAuthorityRouteResolver((authorityInstanceId) =>
      authorityInstanceId === "pfai_1"
        ? { backendAddresses: [backend.address], backendAuthToken: "backend-token" }
        : null
    );
    const tunnelRegistry = new LeaseTunnelRegistry(limits);
    service.onLeaseEnded((event) => tunnelRegistry.closeLease(event.accessLeaseId));
    service.onLeaseRotated((accessLeaseId, tokenGeneration) =>
      tunnelRegistry.closeSupersededGenerations(accessLeaseId, tokenGeneration)
    );
    const router = createAuthorityDataPlaneRouterServer(service, {
      tunnelRegistry,
      ...(limits
        ? { maxConnections: limits.maxOpenTunnels + 16, maxPendingConnections: 16 }
        : {}),
    });
    tcpServers.push(router);
    const routerAddress = await listenTcp(router);
    return {
      service,
      tunnelRegistry,
      routerAddress,
      backendSockets: backend.sockets,
    };
  }

  function createLease(service: ProductionAccessLeaseService, ttlMs = 60_000) {
    return service.create({
      operationId: `router-op-${Math.random().toString(36).slice(2)}`,
      teamId: "team_1",
      volumeId: "vol_1",
      branch: "main",
      consumerId: "worker-1",
      authorityInstanceId: "pfai_1",
      authorityRuntimeGeneration: "1",
      authorityRuntimeId: "runtime-1",
      ttlMs,
    });
  }

  async function openTunnel(
    routerAddress: { host: string; port: number },
    token: string
  ): Promise<Socket> {
    const client = await connectClient(routerAddress);
    await writeTokenFrame(client, token);
    const ack = await readExactly(client, 1);
    expect(ack[0]).toBe(0);
    return client;
  }

  // THE REFUSAL CODE IS THE POINT. A client that cannot tell a full lease from
  // a dead credential latches a terminal credential verdict over a lease that
  // is perfectly alive, and tells its operator to run `portablefs login`.
  async function expectHandshakeRefused(
    routerAddress: { host: string; port: number },
    token: string,
    expected: AckCodeValue
  ): Promise<void> {
    const client = await connectClient(routerAddress);
    await writeTokenFrame(client, token);
    const ack = await readExactly(client, 1);
    client.destroy();
    expect(ack[0]).toBe(expected);
  }

  function waitForClose(socket: Socket): Promise<void> {
    if (socket.destroyed) {
      return Promise.resolve();
    }
    return new Promise((resolve) => socket.once("close", () => resolve()));
  }

  test("a lease token handshakes and tunnels to the backend", async () => {
    const harness = await startLeaseRouter();
    const { lease, accessToken } = await createLease(harness.service);

    const client = await openTunnel(harness.routerAddress, accessToken);
    expect(harness.tunnelRegistry.openTunnelCount(lease.accessLeaseId)).toBe(1);
    client.write("ping");
    const echo = await readExactly(client, 4);
    expect(echo.toString("utf8")).toBe("ping");
    client.destroy();
  });

  test("refuses only excess per-lease tunnels and restores capacity after close", async () => {
    const harness = await startLeaseRouter({
      maxOpenTunnels: 4,
      maxTunnelsPerLease: 2,
    });
    const { lease, accessToken } = await createLease(harness.service);
    const first = await openTunnel(harness.routerAddress, accessToken);
    const second = await openTunnel(harness.routerAddress, accessToken);
    // A FULL LEASE IS NOT A DEAD CREDENTIAL. accessToken is the same token the
    // two live tunnels were admitted with; the only thing wrong is that there
    // is no slot. Answering AckCode.CredentialRejected here is what made a
    // mount latch "lease expired or revoked; run `portablefs login`" over a
    // lease with minutes of validity left.
    await expectHandshakeRefused(harness.routerAddress, accessToken, AckCode.AtCapacity);
    expect(harness.tunnelRegistry.openTunnelCount(lease.accessLeaseId)).toBe(2);

    second.write("still-live");
    expect((await readExactly(second, 10)).toString("utf8")).toBe("still-live");
    const firstClosed = waitForClose(first);
    first.destroy();
    await firstClosed;

    const replacement = await openTunnel(harness.routerAddress, accessToken);
    expect(harness.tunnelRegistry.openTunnelCount(lease.accessLeaseId)).toBe(2);
    replacement.destroy();
    second.destroy();
  });

  test("rotation closes superseded-generation tunnels in both directions", async () => {
    const harness = await startLeaseRouter();
    const { lease, accessToken } = await createLease(harness.service);
    const client = await openTunnel(harness.routerAddress, accessToken);
    const backendSocket = harness.backendSockets[0]!;

    const rotated = await harness.service.renew({
      operationId: "router-rotate-1",
      accessLeaseId: lease.accessLeaseId,
      accessToken,
      expectedControlSeq: lease.controlSeq,
      rotateToken: true,
    });

    await waitForClose(client);
    await waitForClose(backendSocket);
    expect(harness.tunnelRegistry.openTunnelCount(lease.accessLeaseId)).toBe(0);

    // The superseded token no longer handshakes; the rotated one does.
    await expectHandshakeRefused(harness.routerAddress, accessToken, AckCode.CredentialRejected);
    const fresh = await openTunnel(harness.routerAddress, rotated.accessToken!);
    fresh.write("ping");
    expect((await readExactly(fresh, 4)).toString("utf8")).toBe("ping");
    fresh.destroy();
  });

  test("release closes live tunnels in both directions", async () => {
    const harness = await startLeaseRouter();
    const { lease, accessToken } = await createLease(harness.service);
    const client = await openTunnel(harness.routerAddress, accessToken);
    const backendSocket = harness.backendSockets[0]!;

    await harness.service.release({
      operationId: "router-release-1",
      accessLeaseId: lease.accessLeaseId,
      accessToken,
    });

    await waitForClose(client);
    await waitForClose(backendSocket);
    await expectHandshakeRefused(harness.routerAddress, accessToken, AckCode.CredentialRejected);
  });

  test("administrative revocation closes live tunnels", async () => {
    const harness = await startLeaseRouter();
    const { lease, accessToken } = await createLease(harness.service);
    const client = await openTunnel(harness.routerAddress, accessToken);

    await harness.service.revoke(lease.accessLeaseId);

    await waitForClose(client);
    await expectHandshakeRefused(harness.routerAddress, accessToken, AckCode.CredentialRejected);
  });

  test("authority retirement closes live tunnels", async () => {
    const harness = await startLeaseRouter();
    const { accessToken } = await createLease(harness.service);
    const client = await openTunnel(harness.routerAddress, accessToken);

    await harness.service.revokeAuthority("pfai_1");

    await waitForClose(client);
    await expectHandshakeRefused(harness.routerAddress, accessToken, AckCode.CredentialRejected);
  });

  test("the expiry sweep closes live tunnels without any caller action", async () => {
    const harness = await startLeaseRouter();
    const { lease, accessToken } = await createLease(harness.service, 1_000);
    const client = await openTunnel(harness.routerAddress, accessToken);

    // The single unref'd expiry timer reaches the conservative authorization
    // deadline and closes the registered tunnel with no request touching the
    // lease. A database recheck may prove that the row still has runway and
    // briefly reauthorize it; that never revives the already-closed tunnel.
    await waitForClose(client);

    // Once the database expiry returned by create is in the past, the next
    // handshake must remain rejected. Waiting for that exact durable boundary
    // avoids confusing the intentional pre-expiry guard with final expiry.
    const untilDurableExpiryMs = Math.max(0, lease.expiresAt - Date.now());
    await new Promise((resolve) => setTimeout(resolve, untilDurableExpiryMs + 50));
    await expectHandshakeRefused(harness.routerAddress, accessToken, AckCode.CredentialRejected);
  });
});

async function startTrackingBackend(
  expectedToken: string
): Promise<{ address: string; sockets: Socket[] }> {
  const sockets: Socket[] = [];
  const server = createServer((socket) => {
    sockets.push(socket);
    void (async () => {
      const token = await readTokenFrame(socket);
      socket.write(Buffer.from([token === expectedToken ? 0 : 1]));
      if (token !== expectedToken) {
        socket.destroy();
        return;
      }
      socket.pipe(socket);
    })().catch(() => socket.destroy());
  });
  tcpServers.push(server);
  const address = await listenTcp(server);
  return { address: `${address.host}:${address.port}`, sockets };
}

// A fixed-endpoint stub registry standing in for a fenced production
// registry: ensure resolves routing, health is delegated, stop is absent.
function fixedEndpointRegistry(): AuthorityRegistry {
  return {
    ensureAuthority: async () => ({
      provider: "portablefs-managed",
      authorityUrl: "vcs.example:2050",
      host: "vcs.example",
      port: 2050,
    }),
    isHealthy: async () => true,
  };
}

// Registries backing tombstoned routes must never be dispatched to.
function unreachableRegistry(): AuthorityRegistry {
  return {
    ensureAuthority: async () => {
      throw new Error("the registry must not be reached");
    },
    isHealthy: async () => {
      throw new Error("the registry must not be reached");
    },
  };
}

async function startServer(authToken?: string): Promise<string> {
  return startCustomServer(fixedEndpointRegistry(), authToken);
}

async function startCustomServer(
  registry: AuthorityRegistry,
  authToken?: string,
  readiness?: () => ReadinessAnswer | Promise<ReadinessAnswer>,
  accessLeases?: AccessLeaseHandler,
  metricsEndpoint?: () => Promise<string>
): Promise<string> {
  const server = createAuthorityManagerServer({
    registry,
    ...(authToken ? { authToken } : { allowUnauthenticated: true }),
    ...(readiness ? { readiness } : {}),
    ...(accessLeases ? { accessLeases } : {}),
    ...(metricsEndpoint ? { metricsEndpoint } : {}),
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

async function startTokenBackend(expectedToken: string): Promise<{ address: string }> {
  const server = createServer((socket) => {
    void (async () => {
      const token = await readTokenFrame(socket);
      socket.write(Buffer.from([token === expectedToken ? 0 : 1]));
      if (token !== expectedToken) {
        socket.destroy();
        return;
      }
      socket.pipe(socket);
    })().catch(() => socket.destroy());
  });
  tcpServers.push(server);
  const address = await listenTcp(server);
  return { address: `${address.host}:${address.port}` };
}

async function listenTcp(server: ReturnType<typeof createServer>): Promise<{ host: string; port: number }> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return { host: "127.0.0.1", port: address.port };
}

async function writeTokenFrame(socket: Socket, token: string): Promise<void> {
  const tokenBytes = Buffer.from(token);
  const header = Buffer.alloc(2);
  header.writeUInt16BE(tokenBytes.byteLength, 0);
  await new Promise<void>((resolve, reject) => {
    socket.write(Buffer.concat([header, tokenBytes]), (error) =>
      error ? reject(error) : resolve()
    );
  });
}

async function readTokenFrame(socket: Socket): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    function cleanup() {
      socket.off("data", onData);
      socket.off("error", onError);
    }
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength < 2) {
        return;
      }
      const length = buffer.readUInt16BE(0);
      if (buffer.byteLength < 2 + length) {
        return;
      }
      const token = buffer.subarray(2, 2 + length).toString("utf8");
      const extra = buffer.subarray(2 + length);
      cleanup();
      if (extra.byteLength > 0) {
        socket.unshift(extra);
      }
      resolve(token);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    socket.on("data", onData);
    socket.once("error", onError);
  });
}

async function readExactly(socket: Socket, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const cleanup = () => {
      socket.off("data", onData);
      socket.off("error", onError);
    };
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength < length) {
        return;
      }
      const result = buffer.subarray(0, length);
      const extra = buffer.subarray(length);
      cleanup();
      if (extra.byteLength > 0) {
        socket.unshift(extra);
      }
      resolve(result);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    socket.on("data", onData);
    socket.once("error", onError);
  });
}

function connectClient(address: { host: string; port: number }): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(address.port, address.host, () => resolve(socket));
    socket.once("error", reject);
  });
}
