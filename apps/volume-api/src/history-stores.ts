import { open } from "node:fs/promises";
import path from "node:path";
import { signS3RequestHeaders } from "@portablefs/storage-s3";

// ---------------------------------------------------------------------------
// Exact-key readers for HistoryCut objects.
//
// This is deliberately separate from the aggregate BlobStore: history serving
// must dispatch DATABASE-RECORDED exact storage keys by failure domain and
// must never fall back to digest-derived BlobStore.get(). The declarations
// mirror PFH_WORKER_STORES_JSON — the single logical-domain map the Go
// history worker writes with — so reader domains can never drift from the
// writer's. Both backends verify nothing themselves beyond size bounds; the
// caller hashes every byte before exposure (history-serving.ts).
// ---------------------------------------------------------------------------

export class ExactKeyReadError extends Error {
  constructor(
    readonly code: "not_found" | "invalid_key" | "size_mismatch" | "unreachable",
    message: string
  ) {
    super(message);
    this.name = "ExactKeyReadError";
  }
}

export interface ExactKeyReadOptions {
  expectedSize: number;
  maxBytes: number;
  signal?: AbortSignal;
}

export interface ExactKeyReader {
  readExactKey(storageKey: string, options: ExactKeyReadOptions): Promise<Buffer>;
}

export interface HistoryStoreDomain {
  failureDomain: string;
  reader: ExactKeyReader;
}

/**
 * Storage keys are worker-recorded relative object paths: bounded segments,
 * no traversal, no absolute/URL forms. Anything else is a recorded-data
 * fault and fails closed before touching a backend.
 */
export function validateExactStorageKey(storageKey: string): void {
  if (
    storageKey.length < 1 ||
    storageKey.length > 1024 ||
    storageKey.startsWith("/") ||
    storageKey.endsWith("/") ||
    storageKey.includes("//") ||
    storageKey.includes("\0")
  ) {
    throw new ExactKeyReadError("invalid_key", "History storage key shape is invalid.");
  }
  for (const segment of storageKey.split("/")) {
    if (segment === "" || segment === "." || segment === "..") {
      throw new ExactKeyReadError("invalid_key", "History storage key contains traversal segments.");
    }
    if (!/^[A-Za-z0-9._-]{1,256}$/u.test(segment)) {
      throw new ExactKeyReadError("invalid_key", "History storage key segment charset is invalid.");
    }
  }
}

/** Immutable operator-declared failure-domain to exact-key reader mapping. */
export class HistoryStoreRegistry {
  private readonly byDomain = new Map<string, HistoryStoreDomain>();
  private readonly ordered: HistoryStoreDomain[];

  constructor(domains: HistoryStoreDomain[]) {
    if (domains.length < 1 || domains.length > 16) {
      throw new Error("History store registry must declare 1..16 failure domains.");
    }
    for (const domain of domains) {
      if (!/^[A-Za-z0-9._-]{1,64}$/u.test(domain.failureDomain)) {
        throw new Error("History failure-domain ids must match [A-Za-z0-9._-]{1,64}.");
      }
      if (this.byDomain.has(domain.failureDomain)) {
        throw new Error(`History failure domain ${domain.failureDomain} is declared twice.`);
      }
      this.byDomain.set(domain.failureDomain, domain);
    }
    this.ordered = [...domains];
  }

  get(failureDomain: string): HistoryStoreDomain | undefined {
    return this.byDomain.get(failureDomain);
  }

  domains(): string[] {
    return this.ordered.map((entry) => entry.failureDomain);
  }
}

/**
 * Confined filesystem exact-key reader: the recorded key resolves strictly
 * under one root directory (validated segment-by-segment above, re-proven by
 * prefix check after resolution) and the read is bounded BEFORE allocation.
 */
export class FilesystemExactKeyReader implements ExactKeyReader {
  private readonly rootDir: string;

  constructor(config: { rootDir: string }) {
    if (!path.isAbsolute(config.rootDir)) {
      throw new Error("History filesystem reader rootDir must be absolute.");
    }
    this.rootDir = path.resolve(config.rootDir);
  }

  async readExactKey(storageKey: string, options: ExactKeyReadOptions): Promise<Buffer> {
    validateExactStorageKey(storageKey);
    if (options.expectedSize < 0 || options.expectedSize > options.maxBytes) {
      throw new ExactKeyReadError("size_mismatch", "Recorded object size exceeds the read bound.");
    }
    const resolved = path.resolve(this.rootDir, storageKey);
    if (resolved !== this.rootDir && !resolved.startsWith(`${this.rootDir}${path.sep}`)) {
      throw new ExactKeyReadError("invalid_key", "History storage key escapes the store root.");
    }
    if (options.signal?.aborted) {
      throw new DOMException("History object read aborted.", "AbortError");
    }
    let handle;
    try {
      handle = await open(resolved, "r");
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      if (code === "ENOENT" || code === "ENOTDIR") {
        throw new ExactKeyReadError("not_found", "History object copy is missing.");
      }
      throw new ExactKeyReadError("unreachable", "History object copy is unreachable.");
    }
    try {
      const stat = await handle.stat();
      // The size proof happens BEFORE the allocation: a corrupt (grown) copy
      // can never make the reader buffer past the recorded bound.
      if (stat.size !== options.expectedSize) {
        throw new ExactKeyReadError("size_mismatch", "History object copy size mismatch.");
      }
      const buffer = Buffer.allocUnsafe(options.expectedSize);
      let readOffset = 0;
      while (readOffset < options.expectedSize) {
        if (options.signal?.aborted) {
          throw new DOMException("History object read aborted.", "AbortError");
        }
        const result = await handle.read(
          buffer,
          readOffset,
          options.expectedSize - readOffset,
          readOffset
        );
        if (result.bytesRead === 0) {
          throw new ExactKeyReadError("size_mismatch", "History object copy truncated mid-read.");
        }
        readOffset += result.bytesRead;
      }
      return buffer;
    } finally {
      await handle.close();
    }
  }
}

export interface S3ExactKeyReaderConfig {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  pathStyle?: boolean;
  operationTimeoutMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}

/**
 * S3-compatible exact-key reader. Requests are SigV4-signed with the shared
 * @portablefs/storage-s3 signer; the recorded key is presented verbatim (it
 * is already the store's fully prefixed exact key) and the body is bounded
 * by the recorded size before buffering completes.
 */
export class S3ExactKeyReader implements ExactKeyReader {
  private readonly config: S3ExactKeyReaderConfig;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;

  constructor(config: S3ExactKeyReaderConfig) {
    this.config = config;
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.now = config.now ?? (() => new Date());
  }

  async readExactKey(storageKey: string, options: ExactKeyReadOptions): Promise<Buffer> {
    validateExactStorageKey(storageKey);
    if (options.expectedSize < 0 || options.expectedSize > options.maxBytes) {
      throw new ExactKeyReadError("size_mismatch", "Recorded object size exceeds the read bound.");
    }
    // The recorded key is already the store's fully prefixed exact key (the
    // Go worker records Store.ExactKey = prefix + relative key, and every
    // reader presents recorded keys verbatim). Re-applying the declared
    // prefix here would double it and miss every copy.
    const url = this.objectUrl(storageKey);
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    if (options.signal?.aborted) {
      controller.abort();
    }
    const timeoutMs = this.config.operationTimeoutMs ?? 15_000;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref?.();
    try {
      const headers = signS3RequestHeaders({
        method: "GET",
        url,
        region: this.config.region,
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey,
        now: this.now(),
      });
      let response: Response;
      try {
        response = await this.fetchImpl(url, {
          method: "GET",
          headers,
          signal: controller.signal,
        });
      } catch (error) {
        if (options.signal?.aborted) {
          throw new DOMException("History object read aborted.", "AbortError");
        }
        throw new ExactKeyReadError(
          "unreachable",
          `History store request failed: ${(error as Error).name ?? "fetch error"}.`
        );
      }
      if (response.status === 404) {
        throw new ExactKeyReadError("not_found", "History object copy is missing.");
      }
      if (!response.ok) {
        throw new ExactKeyReadError(
          "unreachable",
          `History store answered status ${response.status}.`
        );
      }
      const body = Buffer.from(await response.arrayBuffer());
      if (body.byteLength !== options.expectedSize) {
        throw new ExactKeyReadError("size_mismatch", "History object copy size mismatch.");
      }
      return body;
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
    }
  }

  private objectUrl(key: string): URL {
    const endpoint = new URL(this.config.endpoint);
    const encodedKey = key.split("/").map(encodeURIComponent).join("/");
    if (this.config.pathStyle === true) {
      endpoint.pathname = joinUrlPath(endpoint.pathname, this.config.bucket, encodedKey);
      return endpoint;
    }
    endpoint.hostname = `${this.config.bucket}.${endpoint.hostname}`;
    endpoint.pathname = joinUrlPath(endpoint.pathname, encodedKey);
    return endpoint;
  }
}

interface StoreDeclaration {
  failureDomain: string;
  kind: "fs" | "s3";
  rootDir?: string;
  endpoint?: string;
  region?: string;
  bucket?: string;
  pathStyle?: boolean;
  accessKeyId?: string;
  secretAccessKey?: string;
  prefix?: string;
  operationTimeoutMs?: number;
}

const allowedStoreFields = new Set([
  "failureDomain",
  "kind",
  "rootDir",
  "endpoint",
  "region",
  "bucket",
  "pathStyle",
  "accessKeyId",
  "secretAccessKey",
  "prefix",
  "operationTimeoutMs",
]);

/**
 * Reads the SAME PFH_WORKER_STORES_JSON declaration consumed by the Go
 * history worker, so serving reads and worker writes can never disagree on
 * the failure-domain map. VOLUME_HISTORY_STORES_JSON exists for deployments
 * that split the two processes' environments; when both are set they must be
 * canonically identical.
 */
export function historyStoreRegistryFromEnv(
  env: NodeJS.ProcessEnv
): HistoryStoreRegistry | undefined {
  const workerRaw = env.PFH_WORKER_STORES_JSON?.trim();
  const volumeRaw = env.VOLUME_HISTORY_STORES_JSON?.trim();
  const workerDeclarations = workerRaw ? parseDeclarations(workerRaw) : undefined;
  const volumeDeclarations = volumeRaw ? parseDeclarations(volumeRaw) : undefined;
  if (
    workerDeclarations &&
    volumeDeclarations &&
    canonicalDeclarations(workerDeclarations) !== canonicalDeclarations(volumeDeclarations)
  ) {
    throw new Error("History serving stores do not match PFH_WORKER_STORES_JSON.");
  }
  const declarations = workerDeclarations ?? volumeDeclarations;
  if (!declarations) {
    return undefined;
  }

  const physicalTargets = new Set<string>();
  const domains = declarations.map((decl, index): HistoryStoreDomain => {
    const prefix = decl.prefix ?? "";
    if (prefix !== "") {
      validateExactStorageKey(prefix);
    }
    if (decl.kind === "fs") {
      if (!decl.rootDir || !path.isAbsolute(decl.rootDir)) {
        throw new Error(`History store ${index} filesystem rootDir must be absolute.`);
      }
      const target = `fs:${path.resolve(decl.rootDir)}:${prefix}`;
      if (physicalTargets.has(target)) {
        throw new Error("History store declarations repeat one physical filesystem target.");
      }
      physicalTargets.add(target);
      // The declared prefix is part of the physical-target identity only:
      // recorded storage keys already carry it (the Go worker records
      // Store.ExactKey = prefix + relative key), so the reader confines to
      // the plain root and presents recorded keys verbatim.
      return {
        failureDomain: decl.failureDomain,
        reader: new FilesystemExactKeyReader({ rootDir: path.resolve(decl.rootDir) }),
      };
    }

    if (
      !decl.endpoint ||
      !decl.region ||
      !decl.bucket ||
      !decl.accessKeyId ||
      !decl.secretAccessKey
    ) {
      throw new Error(`History store ${index} S3 declaration is incomplete.`);
    }
    let endpoint: URL;
    try {
      endpoint = new URL(decl.endpoint);
    } catch {
      throw new Error(`History store ${index} S3 endpoint is invalid.`);
    }
    if (!/^https?:$/u.test(endpoint.protocol) || endpoint.username || endpoint.password) {
      throw new Error(`History store ${index} S3 endpoint must be an http(s) URL without userinfo.`);
    }
    const target = `s3:${endpoint.origin}${endpoint.pathname}:${decl.bucket}:${prefix}:${decl.pathStyle === true}`;
    if (physicalTargets.has(target)) {
      throw new Error("History store declarations repeat one physical S3 target.");
    }
    physicalTargets.add(target);
    return {
      failureDomain: decl.failureDomain,
      reader: new S3ExactKeyReader({
        endpoint: decl.endpoint,
        region: decl.region,
        bucket: decl.bucket,
        accessKeyId: decl.accessKeyId,
        secretAccessKey: decl.secretAccessKey,
        ...(decl.pathStyle === true ? { pathStyle: true } : {}),
        ...(decl.operationTimeoutMs !== undefined
          ? { operationTimeoutMs: decl.operationTimeoutMs }
          : {}),
      }),
    };
  });
  return new HistoryStoreRegistry(domains);
}

function parseDeclarations(raw: string): StoreDeclaration[] {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("History store declaration must be valid JSON.");
  }
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
    throw new Error("History store declaration must be an array of 1..16 stores.");
  }
  const seen = new Set<string>();
  return value.map((item, index) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`History store ${index} must be an object.`);
    }
    const row = item as Record<string, unknown>;
    for (const key of Object.keys(row)) {
      if (!allowedStoreFields.has(key)) {
        throw new Error(`History store ${index} has an unknown field.`);
      }
    }
    if (
      typeof row.failureDomain !== "string" ||
      !/^[A-Za-z0-9._-]{1,64}$/u.test(row.failureDomain) ||
      (row.kind !== "fs" && row.kind !== "s3")
    ) {
      throw new Error(`History store ${index} has an invalid domain or kind.`);
    }
    if (seen.has(row.failureDomain)) {
      throw new Error(`History failure domain ${row.failureDomain} is declared twice.`);
    }
    seen.add(row.failureDomain);
    const optionalStrings = [
      "rootDir",
      "endpoint",
      "region",
      "bucket",
      "accessKeyId",
      "secretAccessKey",
      "prefix",
    ] as const;
    for (const key of optionalStrings) {
      if (row[key] !== undefined && (typeof row[key] !== "string" || row[key].length === 0)) {
        throw new Error(`History store ${index} has an invalid ${key}.`);
      }
    }
    if (row.pathStyle !== undefined && typeof row.pathStyle !== "boolean") {
      throw new Error(`History store ${index} has an invalid pathStyle.`);
    }
    if (
      row.operationTimeoutMs !== undefined &&
      (!Number.isSafeInteger(row.operationTimeoutMs) ||
        (row.operationTimeoutMs as number) < 100 ||
        (row.operationTimeoutMs as number) > 300_000)
    ) {
      throw new Error(`History store ${index} has an invalid operationTimeoutMs.`);
    }
    return row as unknown as StoreDeclaration;
  });
}

function canonicalDeclarations(declarations: StoreDeclaration[]): string {
  return stableJson(
    [...declarations].sort((a, b) =>
      a.failureDomain < b.failureDomain ? -1 : a.failureDomain > b.failureDomain ? 1 : 0
    )
  );
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function joinUrlPath(...parts: string[]): string {
  return `/${parts
    .flatMap((part) => part.split("/"))
    .filter(Boolean)
    .join("/")}`;
}
