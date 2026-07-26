import { createHmac, createHash } from "node:crypto";
import { Readable, pipeline } from "node:stream";
import { createGunzip, gzipSync, gunzipSync } from "node:zlib";
import type {
  BlobByteStream,
  BlobStore,
  BlobStorePutOptions,
  BlobStorePutResult,
  OpenBlobStreamOptions,
} from "@portablefs/core";
import { resolveBlobRange, sha256Buffer, sliceByteStream, verifyBlobStreamTrailing } from "@portablefs/core";
import type { BlobDigest, BlobRef } from "@portablefs/protocol";

// Content-addressed digest shape ("sha256:" + 64 lowercase hex); validated
// before an object key is derived from it.
const BLOB_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

export type S3UrlStyle = "virtual-host" | "path";

export interface S3BlobStoreConfig {
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  urlStyle: S3UrlStyle;
  prefix?: string;
  // Server-side-encryption algorithm to request on upload (e.g. "AES256" for
  // SSE-S3, or "aws:kms"). Encryption is at rest in the bucket; the digest is over
  // the plaintext, so content-addressed dedup is unaffected. Unset = no header.
  serverSideEncryption?: string;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}

export class S3BlobStore implements BlobStore {
  private readonly config: S3BlobStoreConfig;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;

  constructor(config: S3BlobStoreConfig) {
    this.config = config;
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.now = config.now ?? (() => new Date());
  }

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    const digest = options?.digest ?? sha256Buffer(buffer);
    if (digest !== sha256Buffer(buffer)) {
      throw new Error(`Blob digest mismatch while uploading ${digest}.`);
    }
    const storageKey = this.keyForDigest(digest);
    if ((options?.checkExisting ?? true) && await this.has(digest)) {
      return {
        blob: {
          digest,
          size: buffer.byteLength,
          storageKey,
          compression: "none",
          packed: false,
        },
      };
    }
    const prepared = prepareStorageBody(buffer);

    await this.request("PUT", storageKey, prepared.body, {
      "content-type": "application/octet-stream",
      "x-amz-meta-digest": digest,
      "x-amz-meta-size": String(buffer.byteLength),
      "x-amz-meta-stored-size": String(prepared.body.byteLength),
      "x-amz-meta-compression": prepared.compression,
      ...(this.config.serverSideEncryption
        ? { "x-amz-server-side-encryption": this.config.serverSideEncryption }
        : {}),
    });
    return {
      blob: {
        digest,
        size: buffer.byteLength,
        storageKey,
        compression: prepared.compression,
        packed: false,
      },
    };
  }

  async get(digest: BlobDigest): Promise<Buffer> {
    const response = await this.request("GET", this.keyForDigest(digest));
    const stored = Buffer.from(await response.arrayBuffer());
    const compression = response.headers.get("x-amz-meta-compression");
    const buffer = compression === "gzip" ? gunzipSync(stored) : stored;
    const actual = sha256Buffer(buffer);
    if (actual !== digest) {
      throw new Error(`S3 blob checksum mismatch for ${digest}: ${actual}`);
    }
    return buffer;
  }

  /**
   * Streaming read. Full reads stream the object body (decompressing
   * gzip-stored payloads) through trailing digest verification: the final
   * chunk is withheld until the content address proves out, so bucket
   * corruption becomes a stream error, never a completed body. Ranged reads
   * resolve the plaintext size from object metadata first, then fetch the
   * narrowest representation: uncompressed objects use an S3 Range request;
   * gzip-stored objects must decompress from byte zero, so the plaintext
   * window is sliced out of the decompressed stream. Ranged reads cannot
   * re-verify the whole-blob digest by construction.
   */
  async openBlobStream(digest: BlobDigest, options?: OpenBlobStreamOptions): Promise<BlobByteStream> {
    throwIfAborted(options?.signal);
    const key = this.keyForDigest(digest);
    const requestOptions = options?.signal ? { signal: options.signal } : {};

    if (!options?.range) {
      const response = await this.request("GET", key, undefined, undefined, requestOptions);
      const compression = storedCompression(response.headers);
      const totalLength = plaintextObjectSize(digest, response.headers, compression);
      const stored = responseBodyChunks(response);
      const plain = compression === "gzip" ? gunzipChunks(stored) : stored;
      return {
        totalLength,
        start: 0,
        end: totalLength - 1,
        buffered: false,
        stream: Readable.from(verifyBlobStreamTrailing(plain, digest, totalLength), {
          objectMode: false,
        }),
      };
    }

    // Ranged read: plaintext size and storage encoding come from metadata
    // BEFORE any body byte moves, so unsatisfiable ranges refuse without a
    // download and satisfiable ones fetch only what they must.
    const head = await this.request("HEAD", key, undefined, undefined, requestOptions);
    const compression = storedCompression(head.headers);
    const totalLength = plaintextObjectSize(digest, head.headers, compression);
    const resolved = resolveBlobRange(options.range, digest, totalLength);

    if (compression === "none") {
      const response = await this.request(
        "GET",
        key,
        undefined,
        { range: `bytes=${resolved.start}-${resolved.end}` },
        requestOptions
      );
      const body = responseBodyChunks(response);
      // A backend that ignores Range answers 200 with the whole object; the
      // requested window is sliced out so callers always get exact bytes.
      const stream =
        response.status === 206 ? body : sliceByteStream(body, resolved.start, resolved.end);
      return {
        totalLength,
        start: resolved.start,
        end: resolved.end,
        buffered: false,
        stream: Readable.from(stream, { objectMode: false }),
      };
    }

    const response = await this.request("GET", key, undefined, undefined, requestOptions);
    return {
      totalLength,
      start: resolved.start,
      end: resolved.end,
      buffered: false,
      stream: Readable.from(
        sliceByteStream(gunzipChunks(responseBodyChunks(response)), resolved.start, resolved.end),
        { objectMode: false }
      ),
    };
  }

  async has(digest: BlobDigest): Promise<boolean> {
    const response = await this.request("HEAD", this.keyForDigest(digest), undefined, undefined, {
      allowNotFound: true,
    });
    return response.status !== 404;
  }

  async delete(digest: BlobDigest): Promise<void> {
    // Idempotent: a 404 means the object is already gone, which is success for GC.
    await this.request("DELETE", this.keyForDigest(digest), undefined, undefined, {
      allowNotFound: true,
    });
  }

  keyForDigest(digest: BlobDigest): string {
    // Content-addressed digests are "sha256:" + 64 lowercase hex. Validate
    // before building an object key so a malformed digest can never inject
    // path segments; callers verify content hashes, so this only rejects
    // corrupt/hostile input (defense in depth).
    if (!BLOB_DIGEST_PATTERN.test(digest)) {
      throw new Error("Invalid blob digest.");
    }
    const hex = digest.slice("sha256:".length);
    return [trimPrefix(this.config.prefix ?? ""), "blobs", "sha256", hex.slice(0, 2), hex]
      .filter(Boolean)
      .join("/");
  }

  private async request(
    method: string,
    key: string,
    body?: Buffer,
    headers?: Record<string, string>,
    options?: { allowNotFound?: boolean; signal?: AbortSignal }
  ): Promise<Response> {
    const url = objectUrl(this.config, key);
    const signInput: SignRequestInput = {
      method,
      url,
      region: this.config.region,
      accessKeyId: this.config.accessKeyId,
      secretAccessKey: this.config.secretAccessKey,
      now: this.now(),
    };
    if (body) {
      signInput.body = body;
    }
    if (headers) {
      signInput.headers = headers;
    }
    const requestHeaders = signedHeaders(signInput);
    const response = await this.fetchImpl(url, {
      method,
      headers: requestHeaders,
      ...(body ? { body: new Uint8Array(body) } : {}),
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    if (options?.allowNotFound && response.status === 404) {
      return response;
    }
    if (!response.ok) {
      throw new Error(
        `S3 ${method} ${key} failed with ${response.status}: ${await response.text()}`
      );
    }
    return response;
  }
}

function storedCompression(headers: Headers): "gzip" | "none" {
  return headers.get("x-amz-meta-compression") === "gzip" ? "gzip" : "none";
}

// The plaintext (decompressed) size of a stored object: the digest, ranges,
// and Content-Range totals are all over plaintext bytes. Every object this
// store writes carries x-amz-meta-size; an uncompressed object without it
// (written by another tool) still resolves through Content-Length, but a
// gzip-stored object without it cannot be streamed honestly and fails closed.
function plaintextObjectSize(digest: BlobDigest, headers: Headers, compression: "gzip" | "none"): number {
  const meta = headers.get("x-amz-meta-size");
  if (meta !== null && /^(0|[1-9][0-9]*)$/.test(meta)) {
    const size = Number(meta);
    if (Number.isSafeInteger(size)) {
      return size;
    }
  }
  if (compression === "none") {
    const contentLength = headers.get("content-length");
    if (contentLength !== null && /^(0|[1-9][0-9]*)$/.test(contentLength)) {
      const size = Number(contentLength);
      if (Number.isSafeInteger(size)) {
        return size;
      }
    }
  }
  throw new Error(`S3 object for ${digest} does not declare a usable plaintext size.`);
}

async function* responseBodyChunks(response: Response): AsyncGenerator<Buffer> {
  const body = response.body;
  if (!body) {
    return;
  }
  const reader = body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        return;
      }
      yield Buffer.from(value);
    }
  } finally {
    reader.releaseLock();
    // Abandoned early (range slice satisfied, consumer destroyed): release the
    // transport instead of draining the rest of the object.
    await body.cancel().catch(() => undefined);
  }
}

function gunzipChunks(source: AsyncIterable<Buffer>): Readable {
  const gunzip = createGunzip();
  // pipeline owns teardown in both directions: a source failure errors the
  // gunzip stream, and destroying the gunzip stream stops the source pull.
  pipeline(Readable.from(source), gunzip, () => undefined);
  return gunzip;
}

function prepareStorageBody(buffer: Buffer): { body: Buffer; compression: BlobRef["compression"] } {
  if (buffer.byteLength < 1024) {
    return { body: buffer, compression: "none" };
  }
  const compressed = gzipSync(buffer, { level: 6 });
  if (compressed.byteLength + 32 >= buffer.byteLength) {
    return { body: buffer, compression: "none" };
  }
  return { body: compressed, compression: "gzip" };
}

export function s3ConfigFromEnv(
  env: NodeJS.ProcessEnv
): S3BlobStoreConfig {
  const urlStyle = optionalEnv(env, "VOLUME_RAILWAY_BUCKET_URL_STYLE") ?? "virtual-host";
  if (urlStyle !== "virtual-host" && urlStyle !== "path") {
    throw new Error("VOLUME_RAILWAY_BUCKET_URL_STYLE must be virtual-host or path.");
  }
  return {
    endpoint: requiredEnv(env, "VOLUME_RAILWAY_BUCKET_ENDPOINT"),
    bucket: requiredEnv(env, "VOLUME_RAILWAY_BUCKET_NAME"),
    region: optionalEnv(env, "VOLUME_RAILWAY_BUCKET_REGION") ?? "auto",
    urlStyle,
    accessKeyId: requiredEnv(env, "VOLUME_RAILWAY_BUCKET_ACCESS_KEY_ID"),
    secretAccessKey: requiredEnv(env, "VOLUME_RAILWAY_BUCKET_SECRET_ACCESS_KEY"),
    prefix: optionalEnv(env, "VOLUME_RAILWAY_BUCKET_PREFIX") ?? "portablefs",
    ...sseConfig(env),
  };
}

// sseConfig reads the optional server-side-encryption algorithm (VOLUME_RAILWAY_BUCKET_SSE),
// e.g. "AES256". Unset = no SSE header (unchanged behaviour).
function sseConfig(env: NodeJS.ProcessEnv): { serverSideEncryption?: string } {
  const sse = optionalEnv(env, "VOLUME_RAILWAY_BUCKET_SSE");
  return sse ? { serverSideEncryption: sse } : {};
}

export function s3ConfigFromAnyEnv(
  env: NodeJS.ProcessEnv
): S3BlobStoreConfig {
  if (optionalEnv(env, "VOLUME_RAILWAY_BUCKET_ENDPOINT")) {
    return s3ConfigFromEnv(env);
  }
  return s3ConfigFromAwsEnv(env);
}

export function s3ConfigFromAwsEnv(
  env: NodeJS.ProcessEnv
): S3BlobStoreConfig {
  const urlStyle = optionalEnv(env, "AWS_S3_URL_STYLE") ?? "virtual-host";
  return {
    endpoint: requiredEnv(env, "AWS_ENDPOINT_URL"),
    bucket: requiredEnv(env, "AWS_S3_BUCKET_NAME"),
    region: optionalEnv(env, "AWS_DEFAULT_REGION") ?? "auto",
    urlStyle: urlStyle === "path" ? "path" : "virtual-host",
    accessKeyId: requiredEnv(env, "AWS_ACCESS_KEY_ID"),
    secretAccessKey: requiredEnv(env, "AWS_SECRET_ACCESS_KEY"),
    prefix: optionalEnv(env, "VOLUME_RAILWAY_BUCKET_PREFIX") ?? "portablefs",
    ...sseConfig(env),
  };
}

interface SignRequestInput {
  method: string;
  url: URL;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  body?: Buffer;
  headers?: Record<string, string>;
  now: Date;
}

function signedHeaders(input: SignRequestInput): Record<string, string> {
  const amzDate = timestamp(input.now);
  const shortDate = amzDate.slice(0, 8);
  const payloadHash = hexSha256(input.body ?? Buffer.alloc(0));
  const headers: Record<string, string> = {
    host: input.url.host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
    ...(input.headers ?? {}),
  };
  const canonicalHeaders = Object.entries(headers)
    .map(([key, value]) => [key.toLowerCase(), normalizeHeaderValue(value)] as const)
    // AWS SigV4 requires canonical headers sorted by byte (code-unit) order of the
    // lowercased name. Collation-based ordering is locale-sensitive and could reorder
    // headers under some locales, producing a SignatureDoesNotMatch failure.
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  const signedHeaderNames = canonicalHeaders.map(([key]) => key).join(";");
  const canonicalRequest = [
    input.method,
    input.url.pathname || "/",
    input.url.searchParams.toString(),
    canonicalHeaders.map(([key, value]) => `${key}:${value}\n`).join(""),
    signedHeaderNames,
    payloadHash,
  ].join("\n");
  const credentialScope = `${shortDate}/${input.region}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    hexSha256(Buffer.from(canonicalRequest)),
  ].join("\n");
  const signature = hmacHex(signingKey(input.secretAccessKey, shortDate, input.region), stringToSign);
  return {
    ...headers,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaderNames}, Signature=${signature}`,
  };
}

function objectUrl(config: S3BlobStoreConfig, key: string): URL {
  const endpoint = new URL(config.endpoint);
  const encodedKey = encodeKey(key);
  if (config.urlStyle === "path") {
    endpoint.pathname = joinPath(endpoint.pathname, config.bucket, encodedKey);
    return endpoint;
  }
  endpoint.hostname = `${config.bucket}.${endpoint.hostname}`;
  endpoint.pathname = joinPath(endpoint.pathname, encodedKey);
  return endpoint;
}

function signingKey(secretAccessKey: string, shortDate: string, region: string): Buffer {
  const dateKey = hmac(Buffer.from(`AWS4${secretAccessKey}`), shortDate);
  const dateRegionKey = hmac(dateKey, region);
  const dateRegionServiceKey = hmac(dateRegionKey, "s3");
  return hmac(dateRegionServiceKey, "aws4_request");
}

function timestamp(date: Date): string {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

function hmac(key: Buffer, value: string): Buffer {
  return createHmac("sha256", key).update(value).digest();
}

function hmacHex(key: Buffer, value: string): string {
  return createHmac("sha256", key).update(value).digest("hex");
}

function hexSha256(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}

function encodeKey(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}

function joinPath(...parts: string[]): string {
  return `/${parts
    .flatMap((part) => part.split("/"))
    .filter(Boolean)
    .join("/")}`;
}

function normalizeHeaderValue(value: string): string {
  return value.trim().replace(/\s+/g, " ");
}

function trimPrefix(prefix: string): string {
  return prefix.trim().replace(/^\/+|\/+$/g, "");
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new DOMException("The blob stream open was aborted.", "AbortError");
  }
}

function requiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = optionalEnv(env, name);
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function optionalEnv(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name]?.trim();
  return value ? value : undefined;
}
