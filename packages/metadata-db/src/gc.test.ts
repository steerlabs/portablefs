import { describe, it, expect } from "vitest";
import type { MetadataRepository } from "./types.js";
import { runGc, type BlobDeleter } from "./gc.js";

interface Blob {
  digest: string;
  size: number;
  createdAt: number;
}

function fakeMetadata(referenced: Set<string>, blobs: Blob[]) {
  const deletedRows: string[] = [];
  const metadata = {
    async referencedDigests() {
      return referenced;
    },
    async listBlobsCreatedBefore(cutoffMs: number) {
      return blobs.filter((b) => b.createdAt < cutoffMs);
    },
    async deleteBlobRecord(digest: string) {
      deletedRows.push(digest);
    },
  } as unknown as MetadataRepository;
  return { metadata, deletedRows };
}

function fakeBlobStore(failDelete = false) {
  const deletedObjects: string[] = [];
  const blobStore: BlobDeleter = {
    async delete(digest: string) {
      if (failDelete) {
        throw new Error("storage unavailable");
      }
      deletedObjects.push(digest);
    },
  };
  return { blobStore, deletedObjects };
}

describe("runGc", () => {
  it("sweeps old unreferenced blobs, keeps referenced and keeps fresh ones", async () => {
    const now = 10_000_000;
    const graceMs = 1000;
    const blobs: Blob[] = [
      { digest: "sha256:live", size: 100, createdAt: 0 }, // old + referenced -> keep
      { digest: "sha256:garbage", size: 200, createdAt: 0 }, // old + unreferenced -> sweep
      { digest: "sha256:fresh", size: 50, createdAt: now }, // unreferenced but within grace -> keep
    ];
    const { metadata, deletedRows } = fakeMetadata(new Set(["sha256:live"]), blobs);
    const { blobStore, deletedObjects } = fakeBlobStore();

    const report = await runGc(metadata, blobStore, { now, graceMs });

    expect(report.deletedBlobs).toBe(1);
    expect(report.reclaimedBytes).toBe(200);
    expect(report.candidateBlobs).toBe(1);
    expect(report.liveDigests).toBe(1);
    expect(deletedObjects).toEqual(["sha256:garbage"]);
    expect(deletedRows).toEqual(["sha256:garbage"]);
  });

  it("dry-run reports candidates but deletes nothing", async () => {
    const now = 10_000_000;
    const blobs: Blob[] = [{ digest: "sha256:garbage", size: 200, createdAt: 0 }];
    const { metadata, deletedRows } = fakeMetadata(new Set(), blobs);
    const { blobStore, deletedObjects } = fakeBlobStore();

    const report = await runGc(metadata, blobStore, { now, graceMs: 1000, dryRun: true });

    expect(report.candidateBlobs).toBe(1);
    expect(report.deletedBlobs).toBe(0);
    expect(report.reclaimedBytes).toBe(0);
    expect(deletedObjects).toEqual([]);
    expect(deletedRows).toEqual([]);
  });

  it("enforces a minimum grace window (no aggressive sweeps)", async () => {
    const { metadata } = fakeMetadata(new Set(), []);
    const { blobStore } = fakeBlobStore();
    const report = await runGc(metadata, blobStore, { graceMs: 0 });
    expect(report.graceMs).toBeGreaterThanOrEqual(60_000);
  });

  it("keeps the metadata row when storage deletion fails, so the next sweep retries", async () => {
    const now = 10_000_000;
    const blobs: Blob[] = [{ digest: "sha256:garbage", size: 200, createdAt: 0 }];
    const { metadata, deletedRows } = fakeMetadata(new Set(), blobs);
    const { blobStore } = fakeBlobStore(true);

    const report = await runGc(metadata, blobStore, { now, graceMs: 1000 });

    expect(report.deletedBlobs).toBe(0);
    expect(report.failedBlobs).toBe(1);
    expect(deletedRows).toEqual([]); // row preserved
  });
});
