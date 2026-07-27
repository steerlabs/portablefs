import { computeMigrationLineageDigest } from "@portablefs/metadata-db";
import { releaseIdentitySchema, type ReleaseIdentity } from "@portablefs/protocol";

// Additive surfaces this build of volume-api serves. Retired routes are not
// capabilities: consumers can feature-detect without probing them.
export const volumeApiCapabilities = [
  "tenants",
  "volume-listing",
  "commit-history",
  "tree-browse",
  "blob-probe",
  "manifest-diff",
  "wait-head",
  "grep",
] as const;

export type VolumeApiReleaseIdentity = Omit<ReleaseIdentity, "serverTimeMs">;

// loadVolumeApiReleaseIdentity assembles the exact deployment identity from
// release-tooling environment (PORTABLEFS_RELEASE_ID + PORTABLEFS_SOURCE_REVISION,
// baked into images as build args) plus the runtime-computed migration lineage
// digest. Both env values are required together: a release id with an unknown
// source revision is not an exact identity. Returns null when unconfigured —
// the route then answers 404 RELEASE_IDENTITY_UNAVAILABLE, which is the honest
// "unpinned dev deployment" signal.
export async function loadVolumeApiReleaseIdentity(
  env: Record<string, string | undefined>
): Promise<VolumeApiReleaseIdentity | null> {
  const releaseId = env.PORTABLEFS_RELEASE_ID?.trim();
  const sourceRevision = env.PORTABLEFS_SOURCE_REVISION?.trim();
  if (!releaseId || !sourceRevision) {
    return null;
  }
  const migrationLineageDigest = await computeMigrationLineageDigest();
  const identity: VolumeApiReleaseIdentity = {
    schemaVersion: 1,
    service: "volume-api",
    releaseId,
    sourceRevision,
    migrationLineageDigest,
    capabilities: [...volumeApiCapabilities],
  };
  // Parse-validate at composition time so a malformed identity fails startup,
  // never a serving request.
  releaseIdentitySchema.omit({ serverTimeMs: true }).parse(identity);
  return identity;
}
