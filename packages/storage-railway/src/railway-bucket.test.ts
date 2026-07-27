import { describe, expect, test } from "vitest";
import {
  S3BlobStore,
  s3ConfigFromAnyEnv,
  s3ConfigFromAwsEnv,
  s3ConfigFromEnv,
  type S3BlobStoreConfig,
} from "@portablefs/storage-s3";
import {
  RailwayBucketBlobStore,
  railwayBucketConfigFromAnyEnv,
  railwayBucketConfigFromEnv,
  railwayBucketConfigFromRailwayCliEnv,
  type RailwayBucketBlobStoreConfig,
} from "./index.js";

describe("storage-railway aliases", () => {
  test("re-exports the storage-s3 implementation as identical references", () => {
    expect(RailwayBucketBlobStore).toBe(S3BlobStore);
    expect(railwayBucketConfigFromEnv).toBe(s3ConfigFromEnv);
    expect(railwayBucketConfigFromAnyEnv).toBe(s3ConfigFromAnyEnv);
    expect(railwayBucketConfigFromRailwayCliEnv).toBe(s3ConfigFromAwsEnv);
  });

  test("the aliased config type stays assignable in both directions", () => {
    const config: RailwayBucketBlobStoreConfig = {
      endpoint: "https://t3.storageapi.dev",
      bucket: "bucket-test",
      region: "auto",
      urlStyle: "virtual-host",
      accessKeyId: "access",
      secretAccessKey: "secret",
    };
    const generic: S3BlobStoreConfig = config;
    expect(new RailwayBucketBlobStore(generic)).toBeInstanceOf(S3BlobStore);
  });
});
