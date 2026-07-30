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
const DEFAULT_S3_REQUEST_TIMEOUT_MS = 300_000;
const MIN_S3_REQUEST_TIMEOUT_MS = 1_000;
const MAX_S3_REQUEST_TIMEOUT_MS = 10 * 60_000;
const S3_ERROR_BODY_MAX_BYTES = 8 * 1024;

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
  /** Whole-operation deadline for buffered/control requests; headers-only for streams. */
  requestTimeoutMs?: number;
  /** Permits HTTP only for an explicitly configured loopback development endpoint. */
  allowInsecureEndpoint?: boolean;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}

export class S3BlobStore implements BlobStore {
  private readonly config: S3BlobStoreConfig;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;
  private readonly requestTimeoutMs: number;

  constructor(config: S3BlobStoreConfig) {
    validateS3Endpoint(config.endpoint, config.allowInsecureEndpoint === true);
    this.config = config;
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.now = config.now ?? (() => new Date());
    this.requestTimeoutMs = normalizeRequestTimeout(config.requestTimeoutMs);
  }

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    const digest = options?.digest ?? sha256Buffer(buffer);
    if (digest !== sha256Buffer(buffer)) {
      throw new Error(`Blob digest mismatch while uploading ${digest}.`);
    }
    const storageKey = this.keyForDigest(digest);
    if ((options?.checkExisting ?? true) && await this.has(digest, options?.signal)) {
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

    const response = await this.request("PUT", storageKey, prepared.body, {
      "content-type": "application/octet-stream",
      "x-amz-meta-digest": digest,
      "x-amz-meta-size": String(buffer.byteLength),
      "x-amz-meta-stored-size": String(prepared.body.byteLength),
      "x-amz-meta-compression": prepared.compression,
      ...(this.config.serverSideEncryption
        ? { "x-amz-server-side-encryption": this.config.serverSideEncryption }
        : {}),
    }, options?.signal ? { signal: options.signal } : undefined);
    await response.body?.cancel();
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
      const response = await this.request("GET", key, undefined, undefined, {
        ...requestOptions,
        streamingBody: true,
      });
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
        { ...requestOptions, streamingBody: true }
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

    const response = await this.request("GET", key, undefined, undefined, {
      ...requestOptions,
      streamingBody: true,
    });
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

  async has(digest: BlobDigest, signal?: AbortSignal): Promise<boolean> {
    const response = await this.request("HEAD", this.keyForDigest(digest), undefined, undefined, {
      allowNotFound: true,
      ...(signal ? { signal } : {}),
    });
    return response.status !== 404;
  }

  async delete(digest: BlobDigest): Promise<void> {
    // Idempotent: a 404 means the object is already gone, which is success for GC.
    const response = await this.request("DELETE", this.keyForDigest(digest), undefined, undefined, {
      allowNotFound: true,
    });
    await response.body?.cancel();
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
    options?: { allowNotFound?: boolean; signal?: AbortSignal; streamingBody?: boolean }
  ): Promise<Response> {
    const url = objectUrl(this.config, key);
    const signInput: SignS3RequestInput = {
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
    const requestHeaders = signS3RequestHeaders(signInput);
    const deadline = new AbortController();
    const timer = setTimeout(
      () => deadline.abort(new DOMException("S3 request timed out.", "TimeoutError")),
      this.requestTimeoutMs
    );
    timer.unref?.();
    const signal = options?.signal
      ? AbortSignal.any([options.signal, deadline.signal])
      : deadline.signal;
    const cleanup = () => clearTimeout(timer);
    try {
      const response = await this.fetchImpl(url, {
        method,
        headers: requestHeaders,
        ...(body ? { body: new Uint8Array(body) } : {}),
        signal,
      });
      if (options?.allowNotFound && response.status === 404) {
        cleanup();
        return response;
      }
      if (!response.ok) {
        const detail = await readErrorBodySnippet(response);
        cleanup();
        throw new Error(`S3 ${method} ${key} failed with ${response.status}: ${detail}`);
      }
      if (options?.streamingBody) {
        // Streaming reads retain caller-abort propagation but have no wall
        // clock once response headers arrive.
        cleanup();
        return response;
      }
      return responseWithDeadline(response, signal, cleanup);
    } catch (error) {
      cleanup();
      throw error;
    }
  }
}

function responseWithDeadline(
  response: Response,
  signal: AbortSignal,
  cleanup: () => void
): Response {
  if (response.body === null) {
    cleanup();
    return response;
  }
  const reader = response.body.getReader();
  let settled = false;
  let streamController: ReadableStreamDefaultController<Uint8Array> | undefined;
  const finish = () => {
    if (settled) {
      return;
    }
    settled = true;
    signal.removeEventListener("abort", onAbort);
    cleanup();
  };
  const onAbort = () => {
    if (settled) {
      return;
    }
    const reason = signal.reason ?? new DOMException("S3 request aborted.", "AbortError");
    finish();
    void reader.cancel(reason).catch(() => undefined);
    streamController?.error(reason);
  };
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      streamController = controller;
    },
    async pull(controller) {
      try {
        const chunk = await reader.read();
        if (chunk.done) {
          finish();
          controller.close();
          return;
        }
        controller.enqueue(chunk.value);
      } catch (error) {
        finish();
        controller.error(error);
      }
    },
    async cancel(reason) {
      finish();
      await reader.cancel(reason).catch(() => undefined);
    },
  });
  signal.addEventListener("abort", onAbort, { once: true });
  if (signal.aborted) {
    onAbort();
  }
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

async function readErrorBodySnippet(response: Response): Promise<string> {
  if (response.body === null) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      const remaining = S3_ERROR_BODY_MAX_BYTES - total;
      if (remaining <= 0) {
        await reader.cancel().catch(() => undefined);
        break;
      }
      const kept = chunk.value.subarray(0, remaining);
      chunks.push(kept);
      total += kept.byteLength;
      if (kept.byteLength < chunk.value.byteLength || total === S3_ERROR_BODY_MAX_BYTES) {
        await reader.cancel().catch(() => undefined);
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
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

/**
 * Reads the canonical S3 configuration: the `AWS_*` credential family
 * (endpoint, bucket, region, url style, key pair) plus the PortableFS extras
 * `VOLUME_S3_PREFIX` (default "portablefs") and `VOLUME_S3_SSE`. The retired
 * Railway-era spellings are accepted through the compat alias mapping below.
 */
export function s3ConfigFromEnv(
  env: NodeJS.ProcessEnv
): S3BlobStoreConfig {
  const resolved = applyRailwayCompatAliases(env);
  const urlStyle = optionalEnv(resolved, "AWS_S3_URL_STYLE") ?? "virtual-host";
  if (urlStyle !== "virtual-host" && urlStyle !== "path") {
    throw new Error("AWS_S3_URL_STYLE must be virtual-host or path.");
  }
  const sse = optionalEnv(resolved, "VOLUME_S3_SSE");
  const requestTimeout = optionalEnv(resolved, "VOLUME_S3_REQUEST_TIMEOUT_MS");
  const allowInsecure = optionalEnv(resolved, "VOLUME_S3_ALLOW_INSECURE_ENDPOINT");
  if (allowInsecure !== undefined && allowInsecure !== "0" && allowInsecure !== "1") {
    throw new Error("VOLUME_S3_ALLOW_INSECURE_ENDPOINT must be 0 or 1.");
  }
  return {
    endpoint: requiredEnv(resolved, "AWS_ENDPOINT_URL"),
    bucket: requiredEnv(resolved, "AWS_S3_BUCKET_NAME"),
    region: optionalEnv(resolved, "AWS_DEFAULT_REGION") ?? "auto",
    urlStyle,
    accessKeyId: requiredEnv(resolved, "AWS_ACCESS_KEY_ID"),
    secretAccessKey: requiredEnv(resolved, "AWS_SECRET_ACCESS_KEY"),
    prefix: optionalEnv(resolved, "VOLUME_S3_PREFIX") ?? "portablefs",
    ...(sse ? { serverSideEncryption: sse } : {}),
    ...(requestTimeout ? { requestTimeoutMs: parseRequestTimeout(requestTimeout) } : {}),
    ...(allowInsecure === "1" ? { allowInsecureEndpoint: true } : {}),
  };
}

// Compat aliasing (one release): the retired VOLUME_RAILWAY_BUCKET_* spellings
// map onto the canonical AWS_*/VOLUME_S3_* names. The endpoint/credential
// family is all-or-nothing, keyed on VOLUME_RAILWAY_BUCKET_ENDPOINT (matching
// the retired spelling-selection behavior, so a deployment carrying both
// spellings keeps resolving exactly as before); prefix and SSE alias
// independently because both spellings read the Railway names for them.
function applyRailwayCompatAliases(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const aliased: NodeJS.ProcessEnv = { ...env };
  if (optionalEnv(env, "VOLUME_RAILWAY_BUCKET_ENDPOINT")) {
    aliased.AWS_ENDPOINT_URL = env.VOLUME_RAILWAY_BUCKET_ENDPOINT;
    aliased.AWS_S3_BUCKET_NAME = env.VOLUME_RAILWAY_BUCKET_NAME;
    aliased.AWS_DEFAULT_REGION = env.VOLUME_RAILWAY_BUCKET_REGION;
    aliased.AWS_S3_URL_STYLE = env.VOLUME_RAILWAY_BUCKET_URL_STYLE;
    aliased.AWS_ACCESS_KEY_ID = env.VOLUME_RAILWAY_BUCKET_ACCESS_KEY_ID;
    aliased.AWS_SECRET_ACCESS_KEY = env.VOLUME_RAILWAY_BUCKET_SECRET_ACCESS_KEY;
  }
  if (!optionalEnv(env, "VOLUME_S3_PREFIX")) {
    aliased.VOLUME_S3_PREFIX = env.VOLUME_RAILWAY_BUCKET_PREFIX;
  }
  if (!optionalEnv(env, "VOLUME_S3_SSE")) {
    aliased.VOLUME_S3_SSE = env.VOLUME_RAILWAY_BUCKET_SSE;
  }
  return aliased;
}

export interface SignS3RequestInput {
  method: string;
  url: URL;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  body?: Buffer;
  headers?: Record<string, string>;
  now: Date;
}

// SigV4 canonical query string: RFC 3986 percent-encoding (space as %20, the
// encodeURIComponent extras !'()* escaped), pairs sorted by encoded name then
// encoded value. URLSearchParams.toString() is NOT canonical (unsorted, '+'
// for space) and would produce SignatureDoesNotMatch on any signed URL that
// carries query parameters.
function canonicalQueryString(params: URLSearchParams): string {
  const encode = (value: string) =>
    encodeURIComponent(value).replace(
      /[!'()*]/g,
      (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`
    );
  return [...params]
    .map(([name, value]) => [encode(name), encode(value)] as const)
    .sort(([ln, lv], [rn, rv]) => (ln < rn ? -1 : ln > rn ? 1 : lv < rv ? -1 : lv > rv ? 1 : 0))
    .map(([name, value]) => `${name}=${value}`)
    .join("&");
}

/**
 * AWS SigV4 request signing for S3-compatible stores: returns the request
 * headers (host, x-amz-content-sha256, x-amz-date, any extras, authorization)
 * for the given method/url/credentials. This is the ONE signer in the
 * TypeScript services; exact-key history readers import it rather than
 * carrying a private copy.
 */
export function signS3RequestHeaders(input: SignS3RequestInput): Record<string, string> {
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
    canonicalQueryString(input.url.searchParams),
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

function normalizeRequestTimeout(value: number | undefined): number {
  if (value === undefined) {
    return DEFAULT_S3_REQUEST_TIMEOUT_MS;
  }
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_S3_REQUEST_TIMEOUT_MS ||
    value > MAX_S3_REQUEST_TIMEOUT_MS
  ) {
    throw new Error(
      `S3 request timeout must be an integer from ${MIN_S3_REQUEST_TIMEOUT_MS} to ${MAX_S3_REQUEST_TIMEOUT_MS} ms.`
    );
  }
  return value;
}

function parseRequestTimeout(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error("VOLUME_S3_REQUEST_TIMEOUT_MS must be a decimal integer.");
  }
  return normalizeRequestTimeout(Number(value));
}

function validateS3Endpoint(endpoint: string, allowInsecure: boolean): void {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error("AWS_ENDPOINT_URL must be an absolute URL.");
  }
  if (url.protocol === "https:") {
    return;
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (url.protocol === "http:" && allowInsecure && loopback) {
    return;
  }
  throw new Error(
    "AWS_ENDPOINT_URL must use HTTPS; loopback HTTP requires VOLUME_S3_ALLOW_INSECURE_ENDPOINT=1."
  );
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
