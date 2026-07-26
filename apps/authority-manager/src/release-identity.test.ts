import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { releaseIdentitySchema } from "@portablefs/protocol";
import {
  createAuthorityManagerServer,
  type AuthorityEndpoint,
  type AuthorityRef,
  type AuthorityRegistry,
} from "./server.js";
import {
  authorityManagerCapabilities,
  loadAuthorityManagerReleaseIdentity,
} from "./release-identity.js";

const servers: Array<ReturnType<typeof createAuthorityManagerServer>> = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
        })
    )
  );
});

describe("GET /v1/release-identity", () => {
  test("serves the configured identity with a fresh serverTimeMs", async () => {
    const identity = loadAuthorityManagerReleaseIdentity({
      PORTABLEFS_RELEASE_ID: "v0.2.0",
      PORTABLEFS_SOURCE_REVISION: "0123456789abcdef0123456789abcdef01234567",
    });
    expect(identity).not.toBeNull();
    const baseUrl = await startServer(identity!);

    const before = Date.now();
    const response = await fetch(`${baseUrl}/v1/release-identity`, {
      headers: { authorization: "Bearer manager-token" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = releaseIdentitySchema.parse(await response.json());
    expect(body.service).toBe("authority-manager");
    expect(body.releaseId).toBe("v0.2.0");
    expect(body.capabilities).toEqual([...authorityManagerCapabilities]);
    expect(body.migrationLineageDigest).toBeUndefined();
    expect(body.serverTimeMs).toBeGreaterThanOrEqual(before);
  });

  test("answers 404 RELEASE_IDENTITY_UNAVAILABLE when unconfigured", async () => {
    const baseUrl = await startServer(undefined);
    const response = await fetch(`${baseUrl}/v1/release-identity`, {
      headers: { authorization: "Bearer manager-token" },
    });
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      error: {
        code: "RELEASE_IDENTITY_UNAVAILABLE",
        message: "Release identity is not configured for this deployment.",
      },
    });
  });

  test("requires the manager bearer token", async () => {
    const identity = loadAuthorityManagerReleaseIdentity({
      PORTABLEFS_RELEASE_ID: "v0.2.0",
      PORTABLEFS_SOURCE_REVISION: "abc123",
    });
    const baseUrl = await startServer(identity!);
    const unauthenticated = await fetch(`${baseUrl}/v1/release-identity`);
    expect(unauthenticated.status).toBe(401);
    const wrongToken = await fetch(`${baseUrl}/v1/release-identity`, {
      headers: { authorization: "Bearer wrong" },
    });
    expect(wrongToken.status).toBe(401);
  });

  test("loader requires both env values together", () => {
    expect(loadAuthorityManagerReleaseIdentity({})).toBeNull();
    expect(loadAuthorityManagerReleaseIdentity({ PORTABLEFS_RELEASE_ID: "v1" })).toBeNull();
    expect(
      loadAuthorityManagerReleaseIdentity({ PORTABLEFS_SOURCE_REVISION: "abc" })
    ).toBeNull();
  });
});

async function startServer(
  releaseIdentity: ReturnType<typeof loadAuthorityManagerReleaseIdentity> | undefined
): Promise<string> {
  const server = createAuthorityManagerServer({
    authToken: "manager-token",
    registry: unusedRegistry(),
    ...(releaseIdentity ? { releaseIdentity } : {}),
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

// The release-identity route never touches the registry; every call is a bug.
function unusedRegistry(): AuthorityRegistry {
  const fail = (): Promise<AuthorityEndpoint> => {
    throw new Error("Unexpected registry call.");
  };
  return {
    ensureAuthority: (ref: AuthorityRef) => fail(),
    createSession: (ref: AuthorityRef) => fail(),
    isHealthy: async () => {
      throw new Error("Unexpected registry call.");
    },
  };
}
