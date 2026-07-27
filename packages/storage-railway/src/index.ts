// Compatibility aliases: the generic S3 SigV4 blob store now lives in
// @portablefs/storage-s3. Every existing Railway-named import keeps working and
// resolves to the exact same implementation (env var names are unchanged).
export {
  S3BlobStore as RailwayBucketBlobStore,
  s3ConfigFromEnv as railwayBucketConfigFromEnv,
  s3ConfigFromAnyEnv as railwayBucketConfigFromAnyEnv,
  s3ConfigFromAwsEnv as railwayBucketConfigFromRailwayCliEnv,
  type S3BlobStoreConfig as RailwayBucketBlobStoreConfig,
  type S3UrlStyle as RailwayBucketUrlStyle,
} from "@portablefs/storage-s3";
