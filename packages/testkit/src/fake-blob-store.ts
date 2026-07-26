import { sha256Buffer, type BlobStore, type BlobStorePutOptions, type BlobStorePutResult } from "@portablefs/core";
import type { BlobDigest } from "@portablefs/protocol";

export class FakeBlobStore implements BlobStore {
  readonly blobs = new Map<BlobDigest, Buffer>();

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    const digest = options?.digest ?? sha256Buffer(buffer);
    if (digest !== sha256Buffer(buffer)) {
      throw new Error(`Fake blob digest mismatch for ${digest}.`);
    }
    this.blobs.set(digest, Buffer.from(buffer));
    return {
      blob: {
        digest,
        size: buffer.byteLength,
        storageKey: `fake://${digest}`,
        compression: "none",
        packed: false,
      },
    };
  }

  async get(digest: BlobDigest): Promise<Buffer> {
    const blob = this.blobs.get(digest);
    if (!blob) {
      throw new Error(`Fake blob not found: ${digest}`);
    }
    return Buffer.from(blob);
  }

  async has(digest: BlobDigest): Promise<boolean> {
    return this.blobs.has(digest);
  }

  async delete(digest: BlobDigest): Promise<void> {
    this.blobs.delete(digest);
  }
}

export class FaultInjectingBlobStore implements BlobStore {
  private putCount = 0;
  failNextPut = false;
  failNextGet = false;
  failPutAfter: number | null = null;

  constructor(private readonly inner: BlobStore) {}

  async put(buffer: Buffer, options?: BlobStorePutOptions): Promise<BlobStorePutResult> {
    this.putCount += 1;
    if (this.failNextPut || (this.failPutAfter !== null && this.putCount > this.failPutAfter)) {
      this.failNextPut = false;
      throw new Error("Injected blob put failure.");
    }
    return this.inner.put(buffer, options);
  }

  async get(digest: BlobDigest): Promise<Buffer> {
    if (this.failNextGet) {
      this.failNextGet = false;
      throw new Error("Injected blob get failure.");
    }
    return this.inner.get(digest);
  }

  async has(digest: BlobDigest): Promise<boolean> {
    return this.inner.has(digest);
  }

  async delete(digest: BlobDigest): Promise<void> {
    await this.inner.delete?.(digest);
  }
}
