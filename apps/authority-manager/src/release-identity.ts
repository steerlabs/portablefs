import { releaseIdentitySchema, type ReleaseIdentity } from "@portablefs/protocol";

// Additive surfaces this build of the authority manager serves. Deployment
// policy does not belong here: the list describes what the code can do, so
// consumers can feature-detect (for example "access-leases") without probing
// routes for 404s.
export const authorityManagerCapabilities = [
  "authorities",
  "mount-sessions",
  "access-leases",
  "data-plane-router",
  "managed-vcs",
  // The journal-native production registry: database-fenced singleton epoch,
  // remote pfm control store, disposable journal children.
  "production-authorities",
] as const;

export type AuthorityManagerReleaseIdentity = Omit<ReleaseIdentity, "serverTimeMs">;

// loadAuthorityManagerReleaseIdentity assembles the exact deployment identity
// from release-tooling environment (PORTABLEFS_RELEASE_ID +
// PORTABLEFS_SOURCE_REVISION, baked into images as build args). Both values
// are required together: a release id with an unknown source revision is not
// an exact identity. Returns null when unconfigured — the route then answers
// 404 RELEASE_IDENTITY_UNAVAILABLE, the honest "unpinned dev deployment"
// signal. The manager owns no migrations, so migrationLineageDigest is absent.
export function loadAuthorityManagerReleaseIdentity(
  env: Record<string, string | undefined>
): AuthorityManagerReleaseIdentity | null {
  const releaseId = env.PORTABLEFS_RELEASE_ID?.trim();
  const sourceRevision = env.PORTABLEFS_SOURCE_REVISION?.trim();
  if (!releaseId || !sourceRevision) {
    return null;
  }
  const identity: AuthorityManagerReleaseIdentity = {
    schemaVersion: 1,
    service: "authority-manager",
    releaseId,
    sourceRevision,
    capabilities: [...authorityManagerCapabilities],
  };
  // Parse-validate at composition time so a malformed identity fails startup,
  // never a serving request.
  releaseIdentitySchema.omit({ serverTimeMs: true }).parse(identity);
  return identity;
}
