# Release Identity

`GET /v1/release-identity` is an authenticated, read-only endpoint on the volume
API and the authority manager that names the exact build serving requests.
Control planes and deployment tooling pin it to verify upgrades, rollbacks, and
cutovers — "is the artifact I promoted actually the one serving?" — and use its
capability list to feature-detect additive surfaces instead of probing routes
for 404s.

## Response

```json
{
  "schemaVersion": 1,
  "service": "volume-api",
  "releaseId": "v0.2.0",
  "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
  "migrationLineageDigest": "sha256:…",
  "capabilities": ["tenants", "volume-listing", "tree-browse", "…"],
  "serverTimeMs": 1789000000000
}
```

- `releaseId` and `sourceRevision` come from release tooling — the runtime
  never invents them. The published Docker images bake them as build args
  (`PORTABLEFS_RELEASE_ID` = the git tag, `PORTABLEFS_SOURCE_REVISION` = the
  commit SHA); self-hosters building from source can set the same environment
  variables.
- `migrationLineageDigest` (volume-api only) is a SHA-256 over the ordered
  Postgres migration lineage this artifact ships (ids + SQL bytes). Two builds
  that would apply different schema histories can never present the same
  digest. The authority manager owns no migrations and omits the field.
- `capabilities` lists the additive surfaces this build serves (for example
  `tree-browse`, `access-leases`). Consumers must ignore unknown entries.
- The response is `cache-control: no-store`, so a pinning check never trusts an
  intermediary's stale answer.

## Unconfigured deployments

A deployment without both env values answers:

```json
{ "error": { "code": "RELEASE_IDENTITY_UNAVAILABLE", "message": "…" } }
```

with status 404. That is deliberate and honest: an unpinned dev stack (the
quickstart, `pnpm dev`) has no exact release identity, and tooling that
requires one should fail closed rather than trust a guess.

## Consuming it

- Deployment gates: after promoting an artifact, poll `/v1/release-identity`
  until `releaseId` matches the promoted tag before shifting traffic or running
  migrations that assume the new code.
- Rollback verification: the same check proves the rollback target is serving.
- Feature detection: hosted control planes check `capabilities` (for example
  `access-leases`) instead of interpreting route 404s, which cannot distinguish
  "old build" from "wrong URL".

The identity names the build only. It carries no tenant data, no configuration,
and no secrets; it still sits behind the ordinary bearer authentication because
build provenance is nobody else's business.
