import { constants, createReadStream } from "node:fs";
import { access, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { Readable } from "node:stream";
import {
  resolveBlobRange,
  sha256Buffer,
  verifyBlobStreamTrailing,
  type BlobByteStream,
  type BlobStore,
  type BlobStorePutOptions,
  type BlobStorePutResult,
  type OpenBlobStreamOptions,
} from "@portablefs/core";
import type { BlobDigest } from "@portablefs/protocol";

export interface FilesystemBlobStoreConfig {
  rootDir: string;
}

// A blob digest is content-addressed as "sha256:" + 64 lowercase hex. Validate
// before deriving any filesystem path: `path.join` normalizes "..", so a
// malformed digest that ever reached delete()/get() could otherwise escape the
// blob root. Callers verify content hashes, so this only ever rejects corrupt
// or hostile input — defense in depth, never a legitimate blob.
const BLOB_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

export class FilesystemBlobStore implements BlobStore {
  private readonly rootDir: string;

  constructor(config: FilesystemBlobStoreConfig) {
    if (!path.isAbsolute(config.rootDir)) {
      throw new Error("FilesystemBlobStore rootDir must be absolute.");
    }
    this.rootDir = config.rootDir;
  }

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    const digest = options?.digest ?? sha256Buffer(buffer);
    if (digest !== sha256Buffer(buffer)) {
      throw new Error(`Filesystem blob digest mismatch for ${digest}.`);
    }
    const filePath = this.pathForDigest(digest);
    if ((options?.checkExisting ?? true) && (await this.has(digest))) {
      return { blob: this.blobRef(digest, buffer.byteLength) };
    }

    await mkdir(path.dirname(filePath), { recursive: true });
    const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tempPath, buffer, { flag: "wx" });
    await rename(tempPath, filePath).catch(async (error: unknown) => {
      await rm(tempPath, { force: true });
      const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
      if (code === "EEXIST") {
        return;
      }
      throw error;
    });
    return { blob: this.blobRef(digest, buffer.byteLength) };
  }

  async get(digest: BlobDigest): Promise<Buffer> {
    const bytes = await readFile(this.pathForDigest(digest));
    const actual = sha256Buffer(bytes);
    if (actual !== digest) {
      throw new Error(`Filesystem blob checksum mismatch for ${digest}: ${actual}`);
    }
    return bytes;
  }

  /**
   * Streaming read straight off the file. Published objects are immutable
   * (temp+rename), so a full read hashes inline and withholds the final chunk
   * until the digest proves out — corruption becomes a stream error, never a
   * completed body. Range reads seek with createReadStream and cannot
   * re-verify the whole-blob digest by construction.
   */
  async openBlobStream(digest: BlobDigest, options?: OpenBlobStreamOptions): Promise<BlobByteStream> {
    throwIfAborted(options?.signal);
    const filePath = this.pathForDigest(digest);
    const info = await stat(filePath);
    const totalLength = info.size;
    const resolved = resolveBlobRange(options?.range, digest, totalLength);
    const fullRead = resolved.start === 0 && resolved.end === totalLength - 1;
    const source: Readable =
      resolved.end < resolved.start
        ? Readable.from([]) // full read of an empty blob
        : createReadStream(filePath, {
            start: resolved.start,
            end: resolved.end,
            ...(options?.signal ? { signal: options.signal } : {}),
          });
    return {
      totalLength,
      start: resolved.start,
      end: resolved.end,
      buffered: false,
      // objectMode false keeps the wrapper's read-ahead at the byte
      // high-water mark instead of 16 whole chunks.
      stream: fullRead
        ? Readable.from(verifyBlobStreamTrailing(source, digest, totalLength), { objectMode: false })
        : source,
    };
  }

  async has(digest: BlobDigest): Promise<boolean> {
    try {
      await access(this.pathForDigest(digest), constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  async delete(digest: BlobDigest): Promise<void> {
    await rm(this.pathForDigest(digest), { force: true });
  }

  pathForDigest(digest: BlobDigest): string {
    if (!BLOB_DIGEST_PATTERN.test(digest)) {
      throw new Error("Invalid blob digest.");
    }
    const hex = digest.slice("sha256:".length);
    return path.join(this.rootDir, "blobs", "sha256", hex.slice(0, 2), hex);
  }

  private blobRef(digest: BlobDigest, size: number) {
    return {
      digest,
      size,
      storageKey: `file://${this.pathForDigest(digest)}`,
      compression: "none" as const,
      packed: false,
    };
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new DOMException("The blob stream open was aborted.", "AbortError");
  }
}

export function filesystemBlobStoreConfigFromEnv(env: NodeJS.ProcessEnv): FilesystemBlobStoreConfig {
  const rootDir = env.VOLUME_FILESYSTEM_BLOB_ROOT?.trim();
  if (!rootDir) {
    throw new Error("VOLUME_FILESYSTEM_BLOB_ROOT is required when VOLUME_BLOB_STORE=filesystem.");
  }
  return { rootDir: path.resolve(rootDir) };
}
