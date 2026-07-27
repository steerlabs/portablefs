import { afterEach, describe, expect, test } from "vitest";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import type { BlobStore } from "@portablefs/core";
import type { MetadataRepository } from "@portablefs/metadata-db";
import { computeMigrationLineageDigest } from "@portablefs/metadata-db";
import { releaseIdentitySchema } from "@portablefs/protocol";
import { createVolumeApiServer, type VolumeApiServerDeps } from "./server.js";
import { loadVolumeApiReleaseIdentity, volumeApiCapabilities } from "./release-identity.js";

const servers: Array<ReturnType<typeof createVolumeApiServer>> = [];

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
  test("serves the configured identity with a fresh serverTimeMs and no-store", async () => {
    const identity = await loadVolumeApiReleaseIdentity({
      PORTABLEFS_RELEASE_ID: "v0.2.0",
      PORTABLEFS_SOURCE_REVISION: "0123456789abcdef0123456789abcdef01234567",
    });
    expect(identity).not.toBeNull();
    const baseUrl = await startServer({ releaseIdentity: identity! });

    const before = Date.now();
    const response = await fetch(`${baseUrl}/v1/release-identity`, {
      headers: { authorization: "Bearer admin-token" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = releaseIdentitySchema.parse(await response.json());
    expect(body.service).toBe("volume-api");
    expect(body.releaseId).toBe("v0.2.0");
    expect(body.sourceRevision).toBe("0123456789abcdef0123456789abcdef01234567");
    expect(body.capabilities).toEqual([...volumeApiCapabilities]);
    expect(body.migrationLineageDigest).toBe(await computeMigrationLineageDigest());
    expect(body.serverTimeMs).toBeGreaterThanOrEqual(before);
  });

  test("answers 404 RELEASE_IDENTITY_UNAVAILABLE when unconfigured", async () => {
    const baseUrl = await startServer({});
    const response = await fetch(`${baseUrl}/v1/release-identity`, {
      headers: { authorization: "Bearer admin-token" },
    });
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      error: {
        code: "RELEASE_IDENTITY_UNAVAILABLE",
        message: "Release identity is not configured for this deployment.",
      },
    });
  });

  test("requires authentication", async () => {
    const identity = await loadVolumeApiReleaseIdentity({
      PORTABLEFS_RELEASE_ID: "v0.2.0",
      PORTABLEFS_SOURCE_REVISION: "0123456789abcdef0123456789abcdef01234567",
    });
    const baseUrl = await startServer({ releaseIdentity: identity! });
    const response = await fetch(`${baseUrl}/v1/release-identity`);
    expect(response.status).toBe(401);
  });

  test("loadVolumeApiReleaseIdentity requires both env values together", async () => {
    expect(await loadVolumeApiReleaseIdentity({})).toBeNull();
    expect(await loadVolumeApiReleaseIdentity({ PORTABLEFS_RELEASE_ID: "v1" })).toBeNull();
    expect(
      await loadVolumeApiReleaseIdentity({ PORTABLEFS_SOURCE_REVISION: "abc" })
    ).toBeNull();
  });

  test("migration lineage digest is stable across calls", async () => {
    const first = await computeMigrationLineageDigest();
    const second = await computeMigrationLineageDigest();
    expect(first).toBe(second);
    expect(first).toMatch(/^sha256:[a-f0-9]{64}$/u);
  });
});

async function startServer(
  extra: Partial<VolumeApiServerDeps>
): Promise<string> {
  const server = createVolumeApiServer({
    authToken: "admin-token",
    metadata: unusedMetadata(),
    blobStore: unusedBlobStore(),
    ...extra,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

// The release-identity route touches neither store; every access is a bug.
function unusedMetadata(): MetadataRepository {
  return new Proxy({} as MetadataRepository, {
    get(_target, property) {
      if (property === "resolveTenantToken") {
        return async () => null;
      }
      return () => {
        throw new Error(`Unexpected metadata call: ${String(property)}`);
      };
    },
  });
}

function unusedBlobStore(): BlobStore {
  return new Proxy({} as BlobStore, {
    get(_target, property) {
      return () => {
        throw new Error(`Unexpected blob store call: ${String(property)}`);
      };
    },
  });
}
