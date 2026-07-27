import type { BlobStore } from "@portablefs/core";
import type { MetadataRepository } from "@portablefs/metadata-db";

export interface IntegrityCheckResult {
  commitsChecked: number;
  blobsChecked: number;
  missingBlobs: string[];
}

// runIntegrityCheck verifies that every blob AND chunk referenced by a committed
// manifest actually exists in the blob store (chunked files reference chunk
// digests, not a single blob — both must be checked).
export async function runIntegrityCheck(args: {
  metadata: MetadataRepository;
  blobStore: BlobStore;
}): Promise<IntegrityCheckResult> {
  const commits = await requireListCommits(args.metadata);
  const missingBlobs: string[] = [];
  const checked = new Set<string>();
  for (const commit of commits) {
    for (const entry of commit.manifest.entries) {
      if (entry.kind !== "file") {
        continue;
      }
      const digests = entry.chunks?.length
        ? entry.chunks.map((chunk) => chunk.digest)
        : entry.blob
          ? [entry.blob.digest]
          : [];
      for (const digest of digests) {
        if (checked.has(digest)) {
          continue;
        }
        checked.add(digest);
        if (!(await args.blobStore.has(digest))) {
          missingBlobs.push(digest);
        }
      }
    }
  }
  return {
    commitsChecked: commits.length,
    blobsChecked: checked.size,
    missingBlobs,
  };
}

async function requireListCommits(metadata: MetadataRepository) {
  if (!metadata.listCommits) {
    throw new Error("Metadata repository does not support commit listing.");
  }
  return metadata.listCommits();
}
