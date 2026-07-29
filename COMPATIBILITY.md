# Compatibility

This is the PortableFS v2 stability contract. v2 is a deliberate
compatibility reset: the previous contract froze package paths, Docker
images, every environment variable name, and both product generations so
broadly that meaningful deletion was impossible. v2 freezes the product —
what deployments and clients depend on — and unfreezes the implementation.
Names retired at the boundary keep typed tombstones for exactly one
release.

The reset includes the mount wire. Released v0.1 clients speak `fsproto` v3;
the first v2 authority speaks v6 and intentionally refuses that older
protocol rather than silently weakening exact-session semantics. Upgrade
clients before (or atomically with) the authority. The one-release-skew
promise below begins with the v2 release line; it does not promise
v0.1↔v2 interoperability.

Every surface is in one of four tiers: **frozen**, **tombstoned**,
**deprecated for removal**, or **internal**. If a surface is not listed,
treat it as internal.

## Frozen

Breaking changes are prohibited. Deployments and clients may pin against
these.

- **Journal-born volumes.** Every volume is journal-native: the fenced
  Postgres journal (PFJ3 records, PFC2 controls) is the authority durability
  layer. Authority-lane replies and successful mount `fsync` barriers are
  journal-durable; delegated `write(2)` uses standard filesystem semantics
  and may return before local physical sync. Committed history keeps its
  content-addressed identity forever.
- **The Volume API `/v1` surface** as documented in
  [docs/api.md](./docs/api.md): request/response shapes, error codes, and
  the token semantics (admin provisioning token, per-tenant bearer tokens,
  volume-pinned runtime read credentials) — minus the tombstoned routes
  below. Existing fields are never removed or repurposed; new optional
  fields may appear and consumers must ignore unknown fields.
- **The authority manager `/v1` control surface** (ensure/health/stop and
  the access-lease family) with its fencing semantics
  (`authorityInstanceId`, manager epochs), plus `/healthz` and `/readyz`
  on both services. See
  [docs/authority-manager.md](./docs/authority-manager.md).
- **Mount transports: Linux FUSE and macOS FSKit.** `portablefs mount`
  (FUSE through portablefsd) and `swift/PortableFSKit` (FSKit) are the two
  supported clients. Wire-visible changes ship only behind `fsproto`
  protocol version negotiation and the versioned `pfslocal`
  `Hello`/`HelloReply` handshake; a client and authority one release apart
  interoperate.
- **PFT2**, the immutable content-addressed base format: the strict
  canonical object encoding, the digest scheme, and the node kinds. A
  committed PFT2 object keeps its exact bytes and digest forever. Postgres
  metadata migrations remain append-only — a released migration file is
  never edited or reordered.
- **Postgres 16 or newer is the deployment requirement** for metadata and
  the journal, self-hosted or managed (synchronous replication for
  production durability). There is no supported deployment without it.

## Tombstones (one release)

Retired at the v2 boundary. Each keeps a stable, typed refusal for exactly
one release and then disappears entirely:

- `POST /v1/volumes/:id/exec` (volume API): `410 VOLUME_EXEC_RETIRED`; the
  body is never parsed and no volume state is read. Mount the volume and
  run commands locally.
- `POST /v1/mount-sessions` and `POST /v1/volumes/:id/mount-sessions`
  (authority manager): `410 MOUNT_SESSION_RETIRED`. Successor:
  `POST /v1/access-leases/create`.
- `POST /v1/authorities/session` (authority manager):
  `410 AUTHORITY_SESSION_RETIRED`. Same successor.
- Manager registry modes: `PORTABLEFS_AUTHORITY_MODE=env` and `=managed`
  refuse startup by name (as do the retired `PORTABLEFS_AUTHORITY_URL` and
  `PORTABLEFS_AUTHORITY_MAP_JSON` variables); `production` is the only
  mode.
- The Railway storage spelling: the `railway-bucket` store kind and the
  `VOLUME_RAILWAY_BUCKET_*` variables alias onto the `s3` store
  configuration for one release, then disappear.
- The volume-worker image: `Dockerfile.volume-worker` is gone. Integrity
  and GC live on the volume API admin surface (`GET /v1/admin/integrity`,
  `POST /v1/admin/gc`).

## Deprecated for removal (the legacy generation)

The pre-journal product generation is deprecated and will be deleted in
the next release. These surfaces accept no new work, new volumes never use
them, and remaining legacy volumes must be imported (legacy→managed
conversion) inside this release window:

- **File-WAL authority mode** — the file-log single-node authority as a
  supported production topology, with its checkpoint and standby
  machinery. Deployment requires Postgres (see Frozen); the file log
  survives only as an internal test harness.
- **NFSv3 serving** (`vcs/internal/server`, `cmd/nfsio`).
- **The manifest commit plane** — attach-session manifest authoring
  (attach/checkout/checkin/commit/commit-summary/commit-delta-summary over
  manifest heads), manifest head/status/diff/wait-head/tree/file reads,
  manifest blob authoring, and the legacy→managed conversion pipeline
  itself once the remaining volumes are imported.
- **The raw `cmd/mount` FUSE client** — `portablefs mount` is the one
  Linux frontend.

Removal follows the process below; during the window these surfaces answer
typed refusals or deprecation warnings, never silence.

## Evolvable

Additive evolution with versioning; consumers tolerate additions.

- New `/v1` routes and new optional request/response fields.
- New environment variables (unset must preserve previous behavior).
- New `fsproto` operations and feature bits behind version negotiation;
  `pfslocal` minor version bumps.
- Telemetry and metrics: new series and events may appear; a shipped name
  keeps its meaning or follows the deprecation path.

## Internal

No stability promise, including in patch releases: Go package paths and
layout (everything under `vcs/`), TypeScript package internals and
inter-workspace import shapes, Dockerfile internals and build layout,
environment knobs not documented in [docs/](./docs/) (operator budgets
replace toggles over time), test helpers and `packages/testkit`, scripts,
benchmark harnesses, and documentation wording.

## Changing A Frozen Surface

Frozen does not mean immortal; changes are deliberate and staged:

1. Propose the change in an issue explaining why additive evolution cannot
   work.
2. Ship the replacement additively while the old surface keeps working,
   and mark the old surface deprecated in docs and release notes.
3. Keep the deprecated surface for at least one minor release line with a
   typed warning or refusal where feasible.
4. Remove it only in the next major version.

PRs that touch a frozen surface must say so explicitly and explain the
compatibility story. Reviewers should reject silent changes to anything in
the frozen list.
