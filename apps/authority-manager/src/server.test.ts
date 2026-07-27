import { afterEach, describe, expect, test } from "vitest";
import { connect, createServer, type AddressInfo, type Socket } from "node:net";
import { accessLeaseErrorCodes } from "@portablefs/protocol";
import {
  AuthorityOperationError,
  authorityOperationErrorCodes,
  createAuthorityManagerServer,
  createEnvAuthorityRegistry,
  readAuthorityManagerMode,
  validateEnvAuthorityRegistryConfig,
  type AccessLeaseHandler,
  type AuthorityRegistry,
} from "./server.js";
import {
  createAuthorityDataPlaneRouterServer,
  InMemoryAuthorityDataPlaneRouteTable,
  LeaseTunnelRegistry,
  resolveRouterTlsMaterial,
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
    const registry = createEnvAuthorityRegistry({
      PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
    });

    expect(() =>
      createAuthorityManagerServer({
        registry,
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
          registry: createEnvAuthorityRegistry({
            PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
          }),
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

    const unauthorized = await fetch(`${baseUrl}/v1/authorities/session`, {
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
      createSession: async () => ({ authorityUrl: "router.example:2050" }),
      isHealthy: async () => true,
    }, undefined, () => false);

    const health = await fetch(`${baseUrl}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true });

    const ready = await fetch(`${baseUrl}/readyz`);
    expect(ready.status).toBe(503);
    expect(await ready.json()).toEqual({ ok: false });
  });

  test("typed backpressure refusals render 503 with a Retry-After header so mount clients back off", async () => {
    const refuse = (code: string) => {
      throw new AuthorityOperationError(503, code, "the registry refused the new spawn", {
        retryAfterSeconds: 15,
      });
    };
    const baseUrl = await startCustomServer(
      {
        ensureAuthority: async () => refuse(authorityOperationErrorCodes.atCapacity),
        createSession: async () => refuse(authorityOperationErrorCodes.startQueueTimeout),
        isHealthy: async () => true,
      },
      "manager-token"
    );
    const headers = {
      authorization: "Bearer manager-token",
      "content-type": "application/json",
    };

    const atCapacity = await fetch(`${baseUrl}/v1/authorities/ensure`, {
      method: "POST",
      headers,
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });
    expect(atCapacity.status).toBe(503);
    expect(atCapacity.headers.get("retry-after")).toBe("15");
    const atCapacityBody = (await atCapacity.json()) as { error: { code: string } };
    expect(atCapacityBody.error.code).toBe(authorityOperationErrorCodes.atCapacity);

    const queueTimeout = await fetch(`${baseUrl}/v1/authorities/session`, {
      method: "POST",
      headers,
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });
    expect(queueTimeout.status).toBe(503);
    expect(queueTimeout.headers.get("retry-after")).toBe("15");
    const queueTimeoutBody = (await queueTimeout.json()) as { error: { code: string } };
    expect(queueTimeoutBody.error.code).toBe(authorityOperationErrorCodes.startQueueTimeout);
  });

  test("typed per-tenant fairness refusals render 429 with Retry-After, distinct from the 503 capacity codes", async () => {
    const refuse = (code: string) => {
      throw new AuthorityOperationError(429, code, "the tenant is over its fairness budget", {
        retryAfterSeconds: 15,
      });
    };
    const baseUrl = await startCustomServer(
      {
        ensureAuthority: async () => refuse(authorityOperationErrorCodes.tenantAtCapacity),
        createSession: async () => refuse(authorityOperationErrorCodes.tenantLeaseLimit),
        isHealthy: async () => true,
      },
      "manager-token"
    );
    const headers = {
      authorization: "Bearer manager-token",
      "content-type": "application/json",
    };

    const tenantAtCapacity = await fetch(`${baseUrl}/v1/authorities/ensure`, {
      method: "POST",
      headers,
      body: JSON.stringify({ teamId: "team_1", volumeId: "vol_1", branch: "main" }),
    });
    expect(tenantAtCapacity.status).toBe(429);
    expect(tenantAtCapacity.headers.get("retry-after")).toBe("15");
    const tenantAtCapacityBody = (await tenantAtCapacity.json()) as { error: { code: string } };
    expect(tenantAtCapacityBody.error.code).toBe(authorityOperationErrorCodes.tenantAtCapacity);

    const leaseLimit = await fetch(`${baseUrl}/v1/authorities/session`, {
      method: "POST",
      headers,
      body: JSON.stringify({ teamId: "team_1", volumeId: "vol_1", branch: "main" }),
    });
    expect(leaseLimit.status).toBe(429);
    expect(leaseLimit.headers.get("retry-after")).toBe("15");
    const leaseLimitBody = (await leaseLimit.json()) as { error: { code: string } };
    expect(leaseLimitBody.error.code).toBe(authorityOperationErrorCodes.tenantLeaseLimit);
  });

  test("GET /metrics requires the manager bearer token and renders bounded text", async () => {
    const metrics = new ManagerMetrics();
    metrics.counter("pfm_child_scrape_errors_total").add(2);
    metrics.setGauge("pfm_manager_claimed", 1);
    const baseUrl = await startCustomServer(
      {
        ensureAuthority: async () => ({ authorityUrl: "router.example:2050" }),
        createSession: async () => ({ authorityUrl: "router.example:2050" }),
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
        createSession: async () => ({ authorityUrl: "router.example:2050" }),
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
        nfsPort: 2049,
      },
    });
  });

  test("session returns the current data-plane token", async () => {
    const baseUrl = await startServer("manager-token");

    const response = await fetch(`${baseUrl}/v1/authorities/session`, {
      method: "POST",
      headers: {
        authorization: "Bearer manager-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      authority: {
        provider: "portablefs-managed",
        authorityUrl: "vcs.example:2050",
        host: "vcs.example",
        port: 2050,
        nfsPort: 2049,
        authorityAuthToken: "vcs-token",
      },
    });
  });

  test("mount-sessions returns endpoint and token in one call, defaulting branch to main", async () => {
    const baseUrl = await startServer("manager-token");

    const response = await fetch(`${baseUrl}/v1/mount-sessions`, {
      method: "POST",
      headers: {
        authorization: "Bearer manager-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ volumeId: "vol_1" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      mountSession: {
        volumeId: "vol_1",
        branch: "main",
        endpoint: {
          authorityUrl: "vcs.example:2050",
          host: "vcs.example",
          port: 2050,
          nfsPort: 2049,
        },
        token: "vcs-token",
        provider: "portablefs-managed",
      },
    });
  });

  test("mount-sessions accepts the canonical volume-scoped route", async () => {
    const baseUrl = await startServer("manager-token");

    const response = await fetch(`${baseUrl}/v1/volumes/vol_1/mount-sessions`, {
      method: "POST",
      headers: {
        authorization: "Bearer manager-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({}),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { mountSession: { volumeId: string; branch: string } };
    expect(body.mountSession.volumeId).toBe("vol_1");
    expect(body.mountSession.branch).toBe("main");
  });

  test("mount-sessions rejects a body volumeId that contradicts the URL", async () => {
    const baseUrl = await startServer("manager-token");

    const response = await fetch(`${baseUrl}/v1/volumes/vol_1/mount-sessions`, {
      method: "POST",
      headers: {
        authorization: "Bearer manager-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ volumeId: "vol_other" }),
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "volumeId in the body does not match the URL.",
    });
  });

  test("mount-sessions rejects unauthenticated callers like the authority routes", async () => {
    const baseUrl = await startServer("manager-token");

    const response = await fetch(`${baseUrl}/v1/mount-sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1" }),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "Unauthorized." });
  });

  test("mount-sessions requires volumeId", async () => {
    const baseUrl = await startServer();

    const response = await fetch(`${baseUrl}/v1/mount-sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ branch: "main" }),
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "volumeId is required." });
  });

  test("mount-sessions maps unknown volumes to the session route's 404", async () => {
    const baseUrl = await startCustomServer(
      createEnvAuthorityRegistry({
        PORTABLEFS_AUTHORITY_MAP_JSON: JSON.stringify({
          "vol_known:main": { authorityUrl: "vcs.example:2050" },
        }),
      })
    );

    const response = await fetch(`${baseUrl}/v1/mount-sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_missing" }),
    });

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      error: "No PortableFS authority is registered for vol_missing@main.",
    });
  });

  test("mount-sessions omits the token when the environment endpoint has no credential", async () => {
    const baseUrl = await startCustomServer(
      createEnvAuthorityRegistry({
        PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
      })
    );

    const response = await fetch(`${baseUrl}/v1/mount-sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1", branch: "dev", teamId: "team_1" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      mountSession: {
        volumeId: "vol_1",
        branch: "dev",
        endpoint: {
          authorityUrl: "vcs.example:2050",
          host: "vcs.example",
          port: 2050,
        },
        provider: "portablefs-managed",
      },
    });
  });

  test("mount-sessions returns the session token and TTL-derived expiry from the registry", async () => {
    const expiresAt = Date.now() + 300_000;
    const baseUrl = await startCustomServer(
      {
        ensureAuthority: async () => ({
          provider: "portablefs-managed",
          authorityUrl: "router.example:2050",
          host: "router.example",
          port: 2050,
          authorityInstanceId: "pfai_1",
        }),
        createSession: async () => ({
          provider: "portablefs-managed",
          authorityUrl: "router.example:2050",
          host: "router.example",
          port: 2050,
          authorityInstanceId: "pfai_1",
          authToken: "pfs_sess_scoped",
          expiresAt,
        }),
        isHealthy: async () => true,
      },
      "manager-token"
    );

    const response = await fetch(`${baseUrl}/v1/mount-sessions`, {
      method: "POST",
      headers: {
        authorization: "Bearer manager-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ teamId: "team_1", volumeId: "vol_1" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      mountSession: {
        volumeId: "vol_1",
        branch: "main",
        endpoint: {
          authorityUrl: "router.example:2050",
          host: "router.example",
          port: 2050,
        },
        token: "pfs_sess_scoped",
        expiresAtMs: expiresAt,
        authorityInstanceId: "pfai_1",
        provider: "portablefs-managed",
      },
    });
  });

  test("health delegates to the registry", async () => {
    const registry = createEnvAuthorityRegistry({
      PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
    });
    const baseUrl = await startCustomServer({
      ensureAuthority: registry.ensureAuthority.bind(registry),
      createSession: registry.createSession.bind(registry),
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
      createSession: async () => ({ authorityUrl: "router.example:2050" }),
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

  test("environment health accepts plain 200 health endpoints", async () => {
    const baseUrl = await startCustomServer(
      createEnvAuthorityRegistry(
        {
          PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
          PORTABLEFS_AUTHORITY_HEALTH_URL: "https://vcs.example/healthz",
        },
        (async () => new Response("ok\n", { status: 200 })) as typeof fetch
      )
    );
    const response = await fetch(`${baseUrl}/v1/authorities/health`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ healthy: true });
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
          nfsPort: 2049,
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
      createSession: async () => ({ authorityUrl: "router.example:2050" }),
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

  test("environment health treats unreachable endpoints as unhealthy", async () => {
    const baseUrl = await startCustomServer(
      createEnvAuthorityRegistry(
        {
          PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
          PORTABLEFS_AUTHORITY_HEALTH_URL: "https://vcs.example/healthz",
        },
        (async () => {
          throw new Error("connection reset");
        }) as typeof fetch
      )
    );
    const response = await fetch(`${baseUrl}/v1/authorities/health`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ healthy: false });
  });

  test("environment health bounds stalled endpoint checks", async () => {
    const baseUrl = await startCustomServer(
      createEnvAuthorityRegistry(
        {
          PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
          PORTABLEFS_AUTHORITY_HEALTH_URL: "https://vcs.example/healthz",
          PORTABLEFS_AUTHORITY_HEALTH_TIMEOUT_MS: "1",
        },
        (async (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
          })) as typeof fetch
      )
    );
    const response = await fetch(`${baseUrl}/v1/authorities/health`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ healthy: false });
  });

  test("environment health bounds stalled response bodies", async () => {
    const baseUrl = await startCustomServer(
      createEnvAuthorityRegistry(
        {
          PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
          PORTABLEFS_AUTHORITY_HEALTH_URL: "https://vcs.example/healthz",
          PORTABLEFS_AUTHORITY_HEALTH_TIMEOUT_MS: "1",
        },
        (async (_input, init) =>
          ({
            ok: true,
            text: async () =>
              new Promise<string>((_resolve, reject) => {
                init?.signal?.addEventListener("abort", () => reject(new Error("body aborted")));
              }),
          }) as Response) as typeof fetch
      )
    );
    const response = await fetch(`${baseUrl}/v1/authorities/health`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_1", branch: "main" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ healthy: false });
  });

  test("volume-specific mappings override default mappings", async () => {
    const baseUrl = await startCustomServer(
      createEnvAuthorityRegistry({
        PORTABLEFS_AUTHORITY_URL: "default.example:2050",
        PORTABLEFS_AUTHORITY_MAP_JSON: JSON.stringify({
          "vol_2:main": {
            authorityUrl: "specific.example:3050",
            authToken: "specific-token",
          },
        }),
      })
    );

    const response = await fetch(`${baseUrl}/v1/authorities/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ volumeId: "vol_2", branch: "main" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      authority: {
        provider: "portablefs-managed",
        authorityUrl: "specific.example:3050",
        host: "specific.example",
        port: 3050,
        authorityAuthToken: "specific-token",
      },
    });
  });

  test("environment registry validation requires at least one endpoint", () => {
    expect(() => validateEnvAuthorityRegistryConfig({})).toThrow(
      /At least one PortableFS authority endpoint/
    );
  });

  test("environment registry validation can require health URLs", () => {
    expect(() =>
      validateEnvAuthorityRegistryConfig(
        {
          PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
        },
        { requireHealth: true }
      )
    ).toThrow(/health URLs are required/);

    expect(() =>
      validateEnvAuthorityRegistryConfig(
        {
          PORTABLEFS_AUTHORITY_MAP_JSON: JSON.stringify({
            "vol_1:main": {
              authorityUrl: "vcs.example:2050",
              healthUrl: "https://vcs.example/readyz",
            },
          }),
        },
        { requireHealth: true }
      )
    ).not.toThrow();
  });

  test("mode selection refuses the retired managed mode by name and names production as the successor", () => {
    expect(readAuthorityManagerMode({})).toBe("env");
    expect(readAuthorityManagerMode({ PORTABLEFS_AUTHORITY_MODE: "env" })).toBe("env");
    expect(readAuthorityManagerMode({ PORTABLEFS_AUTHORITY_MODE: "production" })).toBe(
      "production"
    );

    expect(() => readAuthorityManagerMode({ PORTABLEFS_AUTHORITY_MODE: "managed" })).toThrow(
      /managed is no longer supported[\s\S]*PORTABLEFS_AUTHORITY_MODE=production/
    );
    expect(() => readAuthorityManagerMode({ PORTABLEFS_AUTHORITY_MODE: "paired" })).toThrow(
      /must be env or production/
    );
  });

  test("mode inference from process-registry variables requires the production control store", () => {
    expect(
      readAuthorityManagerMode({
        PORTABLEFS_MANAGED_VCS_BIN: "/usr/local/bin/vcs",
        PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR: "0.0.0.0:2050",
        PORTABLEFS_MANAGER_CONTROL_DATABASE_URL: "postgres://portablefs_manager@db/portablefs",
      })
    ).toBe("production");

    expect(() =>
      readAuthorityManagerMode({ PORTABLEFS_MANAGED_VCS_BIN: "/usr/local/bin/vcs" })
    ).toThrow(/retired[\s\S]*PORTABLEFS_AUTHORITY_MODE=production/);
    expect(() =>
      readAuthorityManagerMode({ PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR: "127.0.0.1:2050" })
    ).toThrow(/retired[\s\S]*PORTABLEFS_AUTHORITY_MODE=production/);
  });
});

describe("authority data-plane router", () => {
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

  test("rejects unknown session tokens before reaching a backend", async () => {
    const routeTable = new InMemoryAuthorityDataPlaneRouteTable();
    const router = createAuthorityDataPlaneRouterServer(routeTable);
    tcpServers.push(router);
    const routerAddress = await listenTcp(router);

    const client = await connectClient(routerAddress);
    await writeTokenFrame(client, "missing-token");
    const ack = await readExactly(client, 1);
    expect(ack[0]).toBe(1);
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

    // Production authority mode accepts either full source and refuses
    // plaintext regardless of NODE_ENV (often unset in bare-node and
    // Kubernetes deployments).
    const base = {
      authorityMode: "production" as const,
      listenAddr: "0.0.0.0:2050",
      publicUrl: "vcs.example:2050",
    };
    expect(() =>
      validateAuthorityDataPlaneRouterConfig({ ...base, tlsCertPem: "C", tlsKeyPem: "K" })
    ).not.toThrow();
    expect(() =>
      validateAuthorityDataPlaneRouterConfig({ ...base, tlsCertPath: "/c", tlsKeyPath: "/k" })
    ).not.toThrow();
    expect(() => validateAuthorityDataPlaneRouterConfig(base)).toThrow(
      /Router TLS/
    );
    expect(() =>
      validateAuthorityDataPlaneRouterConfig({ ...base, allowPlaintextProduction: true })
    ).not.toThrow();
    expect(() =>
      validateAuthorityDataPlaneRouterConfig({ ...base, tlsCertPem: "C" })
    ).toThrow(/TLS_KEY_PEM/);
    expect(() =>
      validateAuthorityDataPlaneRouterConfig({
        authorityMode: "env",
        listenAddr: "127.0.0.1:2050",
        publicUrl: "127.0.0.1:2050",
      })
    ).not.toThrow();
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
        nfsPort: 2049,
        ...(instanceId ? { authorityInstanceId: instanceId } : {}),
      }),
      createSession: async () => ({ authorityUrl: "router.example:2050" }),
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
  async function startLeaseRouter(): Promise<LeaseRouterHarness> {
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
    const tunnelRegistry = new LeaseTunnelRegistry();
    service.onLeaseEnded((event) => tunnelRegistry.closeLease(event.accessLeaseId));
    service.onLeaseRotated((accessLeaseId, tokenGeneration) =>
      tunnelRegistry.closeSupersededGenerations(accessLeaseId, tokenGeneration)
    );
    const router = createAuthorityDataPlaneRouterServer(service, { tunnelRegistry });
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

  async function expectHandshakeRejected(
    routerAddress: { host: string; port: number },
    token: string
  ): Promise<void> {
    const client = await connectClient(routerAddress);
    await writeTokenFrame(client, token);
    const ack = await readExactly(client, 1);
    expect(ack[0]).toBe(1);
    client.destroy();
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
    await expectHandshakeRejected(harness.routerAddress, accessToken);
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
    await expectHandshakeRejected(harness.routerAddress, accessToken);
  });

  test("administrative revocation closes live tunnels", async () => {
    const harness = await startLeaseRouter();
    const { lease, accessToken } = await createLease(harness.service);
    const client = await openTunnel(harness.routerAddress, accessToken);

    await harness.service.revoke(lease.accessLeaseId);

    await waitForClose(client);
    await expectHandshakeRejected(harness.routerAddress, accessToken);
  });

  test("authority retirement closes live tunnels", async () => {
    const harness = await startLeaseRouter();
    const { accessToken } = await createLease(harness.service);
    const client = await openTunnel(harness.routerAddress, accessToken);

    await harness.service.revokeAuthority("pfai_1");

    await waitForClose(client);
    await expectHandshakeRejected(harness.routerAddress, accessToken);
  });

  test("the expiry sweep closes live tunnels without any caller action", async () => {
    const harness = await startLeaseRouter();
    const { accessToken } = await createLease(harness.service, 1_000);
    const client = await openTunnel(harness.routerAddress, accessToken);

    // The single unref'd expiry timer ends the lease projection, which
    // closes the registered tunnel with no request touching the lease.
    await waitForClose(client);
    await expectHandshakeRejected(harness.routerAddress, accessToken);
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

async function startServer(authToken?: string): Promise<string> {
  return startCustomServer(
    createEnvAuthorityRegistry({
      PORTABLEFS_AUTHORITY_URL: "vcs.example:2050",
      PORTABLEFS_AUTHORITY_NFS_PORT: "2049",
      PORTABLEFS_AUTHORITY_AUTH_TOKEN: "vcs-token",
    }),
    authToken
  );
}

async function startCustomServer(
  registry: AuthorityRegistry,
  authToken?: string,
  readiness?: () => boolean | Promise<boolean>,
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
