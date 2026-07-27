import { z } from "zod";

// ---------------------------------------------------------------------------
// Release identity (GET /v1/release-identity).
//
// An exact, read-only deployment identity served by volume-api and
// authority-manager. Consumers pin releaseId + sourceRevision to verify what
// is actually serving before upgrades, rollbacks, and cutovers, and read
// capabilities to feature-detect additive surfaces instead of probing routes
// for 404s.
//
// The identity is configured by release tooling (environment or image build
// args) — the runtime never invents these values. A deployment without a
// configured identity answers 404 RELEASE_IDENTITY_UNAVAILABLE, which is
// itself meaningful: "unpinned dev deployment".
// ---------------------------------------------------------------------------

// Local copy of the sha256 shape (index.ts re-exports this module, so
// importing from the index here would be circular).
const sha256DigestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/u);

export const releaseIdentityServiceSchema = z.enum(["volume-api", "authority-manager"]);
export type ReleaseIdentityService = z.infer<typeof releaseIdentityServiceSchema>;

export const releaseIdentitySchema = z.object({
  schemaVersion: z.literal(1),
  service: releaseIdentityServiceSchema,
  // Exact release string from release tooling (tag or image identity).
  releaseId: z.string().min(1).max(128),
  // Exact source revision (git commit SHA) the artifact was built from.
  sourceRevision: z.string().min(1).max(128),
  // sha256 over the ordered Postgres migration lineage (names + bytes).
  // volume-api only: two builds serving different lineages can never present
  // the same digest. Absent on services that own no migrations.
  migrationLineageDigest: sha256DigestSchema.optional(),
  // Additive feature flags for capability discovery (e.g. "tree-browse",
  // "access-leases"). Consumers must ignore unknown capabilities.
  capabilities: z.array(z.string().min(1).max(128)).max(64),
  serverTimeMs: z.number().int().nonnegative(),
});
export type ReleaseIdentity = z.infer<typeof releaseIdentitySchema>;

export const releaseIdentityErrorCode = "RELEASE_IDENTITY_UNAVAILABLE" as const;
