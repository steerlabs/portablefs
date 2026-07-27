import type { MetadataRepository } from "./types.js";

/** The slice of a blob store GC needs (any BlobStore satisfies it structurally). */
export interface BlobDeleter {
  delete?(digest: string): Promise<void>;
}

export interface GcOptions {
  /** Only sweep blobs older than this (protects the upload→commit gap). */
  graceMs?: number;
  /** Report what would be deleted without deleting anything. */
  dryRun?: boolean;
  now?: number;
}

export interface GcReport {
  liveDigests: number;
  candidateBlobs: number;
  deletedBlobs: number;
  failedBlobs: number;
  reclaimedBytes: number;
  graceMs: number;
  dryRun: boolean;
}

export const defaultGcGraceMs = 60 * 60 * 1000; // 1 hour
// Never sweep blobs younger than this. The floor must comfortably exceed the
// longest plausible upload→commit gap (a large checkpoint uploads many blobs, then
// commits), so an in-flight blob is never swept before its commit lands. 60s was
// too tight for multi-GB checkpoints; 10 minutes covers them with margin.
export const minGcGraceMs = 10 * 60 * 1000;

/**
 * runGc performs a global mark-and-sweep of the content-addressed blob store.
 *
 * Mark: collect every blob AND chunk digest referenced by any commit across all
 * volumes (blobs are globally deduplicated, so the live set is global; chunked
 * files reference their chunk digests, which must be kept).
 *
 * Sweep: delete blobs that are referenced by no commit AND older than the grace
 * window. The grace window is the safety mechanism — the writer uploads blobs
 * seconds before committing, so an in-flight (not-yet-committed) blob is always
 * younger than the window and is never swept. A rare new reference to an
 * already-swept blob simply fails commit validation (the client re-uploads); it
 * never corrupts live data, because nothing reachable references a swept blob.
 *
 * Deletion removes the storage object first, then the metadata row; if storage
 * deletion fails the row is left so the next sweep retries (no leaked rows).
 */
export async function runGc(
  metadata: MetadataRepository,
  blobStore: BlobDeleter,
  options: GcOptions = {}
): Promise<GcReport> {
  if (!metadata.referencedDigests || !metadata.listBlobsCreatedBefore || !metadata.deleteBlobRecord) {
    throw new Error("metadata repository does not support garbage collection");
  }
  const now = options.now ?? Date.now();
  const graceMs = Math.max(options.graceMs ?? defaultGcGraceMs, minGcGraceMs);
  const dryRun = options.dryRun ?? false;

  const live = await metadata.referencedDigests();
  const candidates = (await metadata.listBlobsCreatedBefore(now - graceMs)).filter(
    (blob) => !live.has(blob.digest)
  );

  let deletedBlobs = 0;
  let failedBlobs = 0;
  let reclaimedBytes = 0;
  if (!dryRun && candidates.length > 0) {
    // Re-mark immediately before deleting: a commit may have referenced a candidate
    // since the first mark — most plausibly via dedup (a new commit reusing an old,
    // about-to-be-swept digest), which the age-based grace window cannot protect.
    // This collapses the mark→sweep race to a tiny window; the commit path's
    // assertManifestBlobsExist is the final backstop (a commit that references a
    // just-deleted blob fails and re-uploads rather than corrupting history).
    const liveNow = await metadata.referencedDigests();
    for (const blob of candidates) {
      if (liveNow.has(blob.digest)) {
        continue; // became referenced after the first mark — keep it
      }
      try {
        if (blobStore.delete) {
          await blobStore.delete(blob.digest);
        }
      } catch {
        failedBlobs++; // leave the metadata row so the next sweep retries
        continue;
      }
      await metadata.deleteBlobRecord(blob.digest);
      deletedBlobs++;
      reclaimedBytes += blob.size;
    }
  }

  return {
    liveDigests: live.size,
    candidateBlobs: candidates.length,
    deletedBlobs,
    failedBlobs,
    reclaimedBytes,
    graceMs,
    dryRun,
  };
}
