import { once } from "node:events";
import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import { createVolumeApiServer } from "@portablefs/volume-api";
import { VolumeClient } from "@portablefs/client-ts";
import type { BlobStore } from "@portablefs/core";
import type { MetadataRepository } from "@portablefs/metadata-db";
import { FakeBlobStore } from "./fake-blob-store.js";
import { InMemoryMetadataRepository } from "./in-memory-metadata.js";

// The tenant the test API authenticates as. createTestVolumeApi provisions a token
// for it and points the client at it, so the harness exercises the real multi-tenant
// auth path (every request carries a tenant credential).
export const testTenantId = "tenant_test";
const testTenantToken = "test-tenant-token";

export interface TestVolumeApi {
  baseUrl: string;
  client: VolumeClient;
  metadata: MetadataRepository;
  blobStore: BlobStore;
  tenantId: string;
  tenantToken: string;
  close(): Promise<void>;
}

export async function createTestVolumeApi(args?: {
  metadata?: MetadataRepository;
  blobStore?: BlobStore;
  blobCacheMaxBytes?: number;
}): Promise<TestVolumeApi> {
  const metadata = args?.metadata ?? new InMemoryMetadataRepository();
  const blobStore = args?.blobStore ?? new FakeBlobStore();
  await metadata.createTenantToken({
    tenantId: testTenantId,
    tokenHash: createHash("sha256").update(testTenantToken).digest("hex"),
  });
  const server = createVolumeApiServer(
    Object.assign(
      { metadata, blobStore },
      args?.blobCacheMaxBytes === undefined ? {} : { blobCacheMaxBytes: args.blobCacheMaxBytes }
    )
  );
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  return {
    baseUrl,
    metadata,
    blobStore,
    tenantId: testTenantId,
    tenantToken: testTenantToken,
    client: new VolumeClient({ baseUrl, token: testTenantToken }),
    close: async () => {
      server.close();
      await once(server, "close");
    },
  };
}
