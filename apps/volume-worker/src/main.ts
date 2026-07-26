import type { BlobStore } from "@portablefs/core";
import { PostgresMetadataRepository, runGc } from "@portablefs/metadata-db";
import {
  FilesystemBlobStore,
  filesystemBlobStoreConfigFromEnv,
} from "@portablefs/storage-filesystem";
import { S3BlobStore, s3ConfigFromAnyEnv } from "@portablefs/storage-s3";
import { runIntegrityCheck } from "./worker.js";

const metadata = new PostgresMetadataRepository({
  connectionString: requiredEnv("VOLUME_DATABASE_URL"),
  connectionTimeoutMillis: Number(process.env.VOLUME_DATABASE_CONNECT_TIMEOUT_MS || 10_000),
  ...databaseSslConfig(),
});
await metadata.applyMigrations();
const blobStore = createBlobStore(process.env);

const command = process.argv[2] || "integrity";
if (command === "integrity") {
  console.log(JSON.stringify(await runIntegrityCheck({ metadata, blobStore }), null, 2));
} else if (command === "gc") {
  // Safe mark-and-sweep: grace window protects in-flight uploads; --dry-run previews.
  const graceMs = Number(process.env.VOLUME_GC_GRACE_MS || 60 * 60 * 1000);
  const dryRun = process.argv.includes("--dry-run");
  console.log(JSON.stringify(await runGc(metadata, blobStore, { graceMs, dryRun }), null, 2));
} else {
  throw new Error(`Unknown worker command: ${command}`);
}
await metadata.close();

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function createBlobStore(env: NodeJS.ProcessEnv): BlobStore {
  // "railway-bucket" is the legacy alias for "s3" and stays the default when unset.
  const kind = env.VOLUME_BLOB_STORE?.trim() || "railway-bucket";
  if (kind === "s3" || kind === "railway-bucket") {
    return new S3BlobStore(s3ConfigFromAnyEnv(env));
  }
  if (kind === "filesystem") {
    return new FilesystemBlobStore(filesystemBlobStoreConfigFromEnv(env));
  }
  throw new Error("VOLUME_BLOB_STORE must be s3, railway-bucket, or filesystem.");
}

function databaseSslConfig():
  | { ssl: { rejectUnauthorized: boolean } }
  | { ssl?: undefined } {
  const mode = process.env.VOLUME_DATABASE_SSL?.trim();
  if (mode === "require") {
    return { ssl: { rejectUnauthorized: true } };
  }
  if (mode === "no-verify") {
    console.warn(
      "WARNING: VOLUME_DATABASE_SSL=no-verify accepts any server certificate (MITM-able). " +
        "Use 'require' with a trusted CA for any network database."
    );
    return { ssl: { rejectUnauthorized: false } };
  }
  if (mode === "disable") {
    return {};
  }
  if (!/sslmode=/i.test(process.env.VOLUME_DATABASE_URL ?? "")) {
    console.warn(
      "WARNING: VOLUME_DATABASE_SSL is unset and VOLUME_DATABASE_URL has no sslmode; " +
        "the Postgres connection may be plaintext. Set VOLUME_DATABASE_SSL=require for any non-loopback database."
    );
  }
  return {};
}
