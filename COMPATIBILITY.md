# Compatibility

This is the stability contract for PortableFS. Every surface in this repository is in
exactly one of three tiers: **frozen**, **evolvable**, or **internal**. If a surface is
not listed as frozen or evolvable, treat it as internal.

## Frozen

Breaking changes are prohibited. External consumers (build scripts, deployment
automation, mount clients, SDKs) may pin against these surfaces.

### Repository layout consumed by external build scripts

- `vcs/cmd/vcs`, `vcs/cmd/mount`, `vcs/cmd/nfsio`, `vcs/cmd/fsio`,
  `vcs/cmd/portablefsd`: these package paths keep their names and stay buildable with a
  plain `go build` (no code generation, no cgo requirement, no build tags needed for a
  default build).
- `swift/PortableFSKit`: the macOS FSKit client package stays at this path.
- `Dockerfile.volume-api`, `Dockerfile.volume-worker`, `Dockerfile.authority-manager`:
  these files stay at the repository root, build from the repository root as context,
  and keep producing the same three services. `Dockerfile.history-worker` (the Go
  HistoryCut worker, `vcs/cmd/history-worker`) is an additive fourth member of the
  same set under the same rules.

### Environment variables

All `VCS_*`, `VOLUME_*`, and `PORTABLEFS_*` environment variable names and their
semantics are frozen. A variable may gain a new optional value, but an existing
name/value combination keeps its meaning, and defaults do not change in ways that
break a working deployment. Removing or renaming a variable is a breaking change.

Recorded default evolutions (existing name/value combinations keep their meaning;
only the unset behavior changed, in a coherence-preserving direction):

- `PORTABLEFS_NEGATIVE_CACHE`: `"1"` still forces the version-gated negative
  dentry cache on and `"0"` still forces it off. UNSET is now capability-auto:
  the cache turns on iff the connected authority advertises `FeatParentVersion`
  in the protocol handshake (it stamps every lookup miss with the parent
  directory version and bumps that version on every name mutation — the
  property that makes a cached negative invalidation-coherent). Against an
  authority that does not advertise the capability, unset behaves exactly as
  before (off). See `docs/performance.md`.
- `PORTABLEFS_OPEN_RETENTION_ENTRIES` (additive): bounds the mount's retained
  open registrations (closed-but-still-registered inodes reused by later opens
  without a `MarkOpen` round-trip). Unset = default (65536), `0` = disable
  retention (the previous mark-per-open/unmark-per-close behavior), `N > 0` =
  LRU cap. Only effective against authorities advertising
  `FeatOpenRegistration`; see `docs/open-after-unlink.md`.

One pre-launch exception, recorded honestly: the WAL-paired standby architecture
was removed before launch.

- The `vcs` process-pair standby serving mode is gone, and with it the
  `VCS_STANDBY`, `VCS_REPLICA_ADDR`, `VCS_REPLICA_LISTEN`, `VCS_STANDBY_WAL`, and
  `VCS_STANDBY_PROMOTION_DELAY` variables. The binary refuses to start when one of
  them is set, so a stale deployment stops loudly instead of silently serving a
  different role.
- The authority manager's `managed` mode (the local WAL-paired registry) is gone:
  `PORTABLEFS_AUTHORITY_MODE=managed` fails startup naming production mode as its
  successor, and the retired registry's variables — `PORTABLEFS_MANAGED_VCS_MODE`,
  `PORTABLEFS_MANAGED_VCS_WORK_DIR`, `PORTABLEFS_MANAGED_VCS_SESSION_TTL_MS`,
  `PORTABLEFS_MANAGED_VCS_CHECKPOINT_INTERVAL`,
  `PORTABLEFS_MANAGED_VCS_FAILOVER_POLL`, `PORTABLEFS_MANAGED_VCS_CACHE_DISK_MB`,
  `PORTABLEFS_MANAGED_VCS_CACHE_RAM_MB`, `PORTABLEFS_MANAGED_VCS_PREFETCH`, and
  `PORTABLEFS_MANAGED_VCS_ENCRYPTION_KEY` — are ignored (child cache tuning
  survives only through the exact `PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON`
  allowlist). `PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES` is the one name the
  production registry re-adopted, as its resident-children cap (see the
  Evolvable section). Its work-dir records (`authority.json`, `process.json`,
  `sessions.json`) are no longer read or written.

None of these names are part of the frozen set. Production HA is the fenced remote
journal ([docs/journal.md](./docs/journal.md)); failover is claim-fencing plus cold
replay, not standby promotion.

### HTTP APIs

- Volume API `/v1` routes: request/response shapes, error codes, and the token
  semantics — `VOLUME_API_TOKEN` is the admin credential (tenant provisioning and GC
  only); tenant data access uses per-tenant bearer tokens issued through
  `POST /v1/admin/tenants`. Admin tokens cannot read tenant data; tenant tokens cannot
  reach `/v1/admin/*`. See [docs/api.md](./docs/api.md).
- Authority manager `/v1` routes (`ensure`, `session`, `health`, `stop`) and their
  fencing semantics (`authorityInstanceId`), plus `/healthz` and `/readyz`. Mount
  credentials are only returned by session-minting routes. See
  [docs/authority-manager.md](./docs/authority-manager.md).

Existing fields are never removed or repurposed; new response fields may be added
(consumers must ignore unknown fields).

### Wire protocols

- `fsproto` (the custom mount protocol between `cmd/mount`/`portablefsd` and the VCS):
  wire-visible changes ship only behind the protocol version negotiation
  (`OpProtocolVersion`). Additive fields that old decoders ignore do not require a
  bump; anything else gates on the negotiated version.
- `pfslocal` (the local daemon-to-frontend protocol, `pfslocal/pfslocal.proto`):
  versioned by the `Hello`/`HelloReply` `{major, minor}` handshake. Same major is wire
  compatible; breaking changes bump the major and the daemon serves both majors during
  a deprecation window.

### Persisted formats

- Postgres metadata migrations are append-only. A released migration file is never
  edited or reordered; schema changes are new migrations. This covers the journal
  schemas (`pfj`/`pfm`/`pfh`) the same way: the fenced SQL functions evolve only
  through new migrations.
- The VCS WAL file format (development/self-host single node): a WAL written by
  release N must be replayable by release N+1.
- The canonical tree hash: byte-identical between the Go (`vcs/internal/treehash`) and
  TypeScript implementations, and stable across releases — a committed tree keeps its
  hash forever.
- The tree manifest format and the chunk/blob digest scheme (`sha256:<hex>` over
  plaintext content, 4 MiB block addressing, streamed chunk format for large files).
  Changing any of these would orphan existing committed history and is prohibited.

## Evolvable

Additive evolution is allowed with versioning. Consumers should tolerate additions.

- New HTTP routes under `/v1` (for example `POST /v1/mount-sessions`,
  `GET /v1/volumes`, `GET /v1/volumes/:id/commits`) and new optional request fields.
- `GET /v1/release-identity` (volume-api and authority-manager) and the
  `PORTABLEFS_RELEASE_ID` / `PORTABLEFS_SOURCE_REVISION` release-tooling
  variables: the response is additive — new fields and new `capabilities`
  entries may appear, and consumers must ignore unknown ones. See
  [docs/release-identity.md](./docs/release-identity.md).
- Authority manager access leases: `POST /v1/access-leases/create`, `inspect`,
  `renew`, `release`, `revoke`, and `revoke-owner`, plus the
  `PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET`, `PORTABLEFS_ACCESS_LEASE_DEFAULT_TTL_MS`,
  and `PORTABLEFS_ACCESS_LEASE_MAX_TTL_MS` variables. The response contract is
  additive — new fields may appear and consumers must ignore unknown ones — and
  the `ACCESS_LEASE_*` error codes keep their meanings. See
  [docs/authority-manager.md](./docs/authority-manager.md).
- Authority manager production mode: the `production` value of
  `PORTABLEFS_AUTHORITY_MODE`, plus the `PORTABLEFS_MANAGER_CONTROL_DATABASE_URL`,
  `PORTABLEFS_MANAGER_CLAIM_TTL_MS`, `PORTABLEFS_MANAGED_VCS_JOURNAL_DSN`,
  `PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON`, and
  `PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON` variables. `env` mode is unchanged;
  the retired `managed` value fails startup (see the removed-variables note
  above). See [docs/authority-manager.md](./docs/authority-manager.md).
- Authority manager production capacity guardrails: always-on idle child
  eviction (`PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS`, default 900000 ms,
  tune-only — `off`/zero/negative refuse startup), the resident-children cap
  (`PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES`, default 100; the name is
  re-adopted from the retired local registry with production semantics), and
  the global cold-start bound (`PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS`,
  default 4). The default grace, cap, and concurrency values may be re-tuned
  in a release; the typed refusals are frozen — `AUTHORITY_AT_CAPACITY` and
  `AUTHORITY_START_QUEUE_TIMEOUT` keep their meanings and their
  503-plus-`Retry-After` shape. See
  [docs/authority-manager.md](./docs/authority-manager.md).
- Authority manager per-tenant fairness caps:
  `PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT` (resident children per
  tenant) and `PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT` (concurrently active
  access leases per tenant). Both default to unset = off, preserving previous
  behavior exactly; set-and-malformed values refuse startup. The typed
  refusals are frozen — `TENANT_AT_CAPACITY` and `TENANT_LEASE_LIMIT` keep
  their meanings and their 429-plus-`Retry-After` shape (429, not 503:
  distinct from the service-pressure codes above by design). See
  [docs/authority-manager.md](./docs/authority-manager.md).
- Authority manager operator metrics: `GET /metrics` on the manager control
  port (Prometheus text exposition, authenticated by the manager bearer token
  like every other control route; absent/404 when unwired). The exposition is
  telemetry, evolvable with care: new series may appear and consumers must
  tolerate additions and absences, while a shipped metric name keeps its
  meaning (renames follow the deprecation path rather than silent
  repurposing). Manager-own series use the `pfm_manager_*`/`pfm_children_*`/
  `pfm_child_*`/`pfm_access_lease*`/`pfm_router_*` names; aggregated child
  series render as `pfm_child_<child metric>` through a closed allowlist —
  no per-volume/branch/tenant labels exist on any series. See
  [docs/authority-manager.md](./docs/authority-manager.md).
- The managed journal child (`vcs` under `VCS_JOURNAL_DSN`): the
  `VCS_JOURNAL_DSN`, `VCS_TENANT_ID`, `VCS_JOURNAL_HA_POLICY_JSON`,
  `VCS_MANAGER_EPOCH`, `VCS_MANAGER_RUNTIME_ID`, `VCS_AUTHORITY_RUNTIME_SEQ`,
  `VCS_AUTHORITY_RUNTIME_ID`, `VCS_AUTHORITY_RUNTIME_CAPABILITY`,
  `VCS_ADMIN_TOKEN`, and `VCS_SUSPEND_DEADLINE_MS` variables, and the manager
  pipe contract (`VCS_HEARTBEAT_FD`/`VCS_BOOTSTRAP_FD`: bounded newline-delimited
  JSON v1 frames, versioned by the frame `v` field and the bootstrap/readiness
  `protocolVersion`). Frame evolution is additive behind those version fields.
- Dirty-block memory guardrail (`VCS_DIRTY_RSS_MAX_MB`, every writable `vcs`
  role, default 2048; also passable to managed children through the
  `PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON` allowlist): bounds the resident
  bytes of uncommitted dirty file blocks, which materialise at 4 MiB
  granularity and otherwise grow without limit on a managed child (it never
  checkpoints in-process). Always on, tune-only — zero/negative/garbage
  values refuse startup. Writes past the bound refuse with `ENOSPC` (the
  frozen capacity errno); releases and reads keep working. The default value
  may be re-tuned in a release.
- Runtime read credentials (migration 015): `VOLUME_API_TOKEN_FILE` on the
  managed child (the rotating manager-minted credential file; the static
  `VOLUME_API_TOKEN` remains for unmanaged development runs), `pfrc_`-prefixed
  bearer tokens on the volume API (tenant-scoped reads plus the pinned
  volume's own attach/detach/lease-renew), and the manager's refusal of any
  static `PORTABLEFS_VOLUME_API_TOKEN` / `VOLUME_API_TOKEN` configuration in
  production mode. See [docs/authority-manager.md](./docs/authority-manager.md).
- Journal birth and activation: the optional `managed` field of
  `POST /v1/volumes` (branch born `managed_journal`; absent keeps the
  base-authoring birth), `POST /v1/volumes/:volumeId/activate-journal` (the
  idempotent poll-driven legacy→managed conversion adopt drives), and the
  history worker's `PFH_WORKER_LEGACY_STORE_JSON` variable (the legacy
  digest-addressed blob store conversions read adopted content from). The
  activation response contract is additive — new fields may appear and
  consumers must ignore unknown ones. See [docs/api.md](./docs/api.md).
- Transaction-pooler topology: `PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE`
  on the manager and `VCS_JOURNAL_POOLER_MODE` on the child (the only value
  is `transaction`; absence means a direct connection). Pooled journal
  connections omit the session timeout startup parameters and rely on the
  database defaults migration 016_pooler_timeouts installs
  (statement 30s / lock 5s / idle-in-transaction 60s). Unset, connection
  behavior is byte-for-byte unchanged.
  Unset, the binary keeps the file-WAL development behavior. The fenced lifecycle
  admin API on the metrics listener (`/v1/ops/checkpoint`, `/v1/ops/evict`,
  `/v1/ops/quiesce`, `/v1/ops/release-lease`; `VCS_ADMIN_TOKEN` bearer;
  `VCS_*` error codes) is additive the same way — new response fields may
  appear and consumers must ignore unknown ones.
- New binaries under `vcs/cmd/` (for example `cmd/portablefs`, the user-facing CLI).
- New environment variables (they must default to the previous behavior when unset).
- New protocol operations added behind `fsproto` version negotiation or a `pfslocal`
  minor version bump.
- Exact mount sessions: the negotiated `fsproto` protocol version (version 3 = the
  session ops, exact-once mutation envelopes, and the probe's feature bits; version 4
  is advertised with `FeatJournaledCoordination` by a journaled session store) and the
  two posture variables. `VCS_REQUIRE_EXACT_SESSIONS=1` makes the authority refuse
  envelope-less mutations (default permissive); `VCS_CLIENT_DISABLE_EXACT_SESSIONS=1`
  keeps a mount on plain v1 behavior (default: sessions negotiate automatically).
  Unset, both preserve the previous behavior.
- New optional response fields on existing routes.
- Native extended attributes (`FeatXattrs`): the four xattr protocol ops
  (`OpGetxattr`/`OpSetxattr`/`OpListxattr`/`OpRemovexattr`) ride the probe's
  feature bits — a client sends them only to an authority that advertises the
  bit and reports ENOTSUP locally otherwise, so old servers and old clients
  interoperate unchanged (macOS keeps its AppleDouble fallback against an old
  authority). The durable formats evolve by the sanctioned appended-op
  discipline: PFR1 appends `Setxattr=16`/`Removexattr=17` plus the frozen
  field 27 (`xattr_name`) and field 28 (`xattr_flags`); PFT2 appends node
  kind 14 (`XATTR_LEAF`), RecoveryRoot field 8 (`xattr_leaves`), and Root
  field 8 (`xattr_leaves`). Release N+1 replays release N's
  logs/anchors byte-identically; an OLD decoder rejects a NEW log or anchor
  that actually carries xattr state (unknown op / unknown field — the frozen
  formats' explicit fencing, never silent loss). The pfslocal xattr frames
  and the `ResolveReply.Capabilities.Xattrs` flag are per-attach: the daemon
  answers natively iff the attached authority advertises `FeatXattrs`.
  Semantics and bounds are specified in
  [docs/consistency-model.md](./docs/consistency-model.md); PFT2 snapshots
  and forks preserve filesystem-homed xattrs, while recovery additionally
  preserves orphan-only rows.
- Conditional extended-attribute sets (`FeatAtomicXattrFlags`):
  `Request.XattrFlags` is additive and is sent only when the authority
  advertises this separate feature. This split is required for rolling
  upgrades: an older `FeatXattrs` authority would otherwise gob-ignore the
  new field and turn `XATTR_CREATE`/`XATTR_REPLACE` into an unconditional
  overwrite. Current clients fail closed with `EOPNOTSUPP` and make no
  mutation round-trip when the bit is absent.
- Atomic append (`FeatAtomicAppend`): `Request.Append` and `Response.Offset`
  are additive fsproto fields. A current Linux FUSE/core client sends one
  append mutation only when the authority advertises the feature; against an
  older authority it keeps using the kernel-resolved absolute-offset write.
  PFR1 field 21 (`append`) remains the durable intent and replay resolves EOF
  in journal order. FSKit currently does not expose `O_APPEND` intent to its
  write callback; that platform boundary is documented in
  [docs/consistency-model.md](./docs/consistency-model.md).
- Native non-directory hard links (`FeatHardLinks`): `OpLink` is appended to
  fsproto and sent only after feature negotiation. A new client connected to
  an older authority reports hard-link capability false and answers link
  locally with `EOPNOTSUPP`; existing operations and wire values are
  unchanged. The existing pfslocal hard-link frames remain shape-compatible,
  and `ResolveReply.Capabilities.HardLinks` now reflects each attached
  authority. Link-count, unlink/reap, open-handle, rename-over, and graft
  boundary semantics are specified in
  [docs/consistency-model.md](./docs/consistency-model.md).
- Machine-local dirs (grafts): the `portablefs mount --local-dir <rel>` /
  `--no-local-dirs` flags, the in-volume `.portablefs/local-dirs` declaration
  file (one workspace-relative path per line, `#` comments), the
  `PORTABLEFS_LOCAL_DIRS` / `PORTABLEFS_LOCAL_DIRS_STATE` variables read by
  `cmd/mount`, and portablefsd's `AttachOptions.localDirs` plus additive
  `AttachOptions.volumeLocalDirs` attach options and the
  `POST /v1/attaches/{ref}/local-dirs` control route. Absent
  `volumeLocalDirs` retains the old false meaning for direct API callers;
  current CLI clients set it explicitly. Unset/absent means no grafts (the
  previous behavior); the graft contract itself is specified in
  [docs/architecture.md](./docs/architecture.md). Native Linux grafts require
  an `openat2(2)` kernel (Linux 5.6 or later) and fail closed when the syscall
  or its confinement flags are unavailable; this is an explicit host-platform
  floor, not an insecure path-resolution fallback.
- The CLI's per-mount state records (`~/.local/state/portablefs/mounts/*.json`,
  read by `portablefs mounts`/`umount`): the format evolves additively — new
  optional fields may appear and absent fields keep the previous meaning. The
  additive `status` / `statusChangedAtMs` fields record mount health beyond
  pid-liveness (today's only value: `credential-expired`, set when the control
  plane definitively rejects the mount daemon's credentials and cleared on
  recovery); records without them read as healthy, exactly as before.
- Journal-era volume API serving (all additive; see [docs/api.md](./docs/api.md)):
  - New routes `POST /v1/volumes/:id/attach-receipted` (exact-once attach with
    `receipt`/`current` response facts and the `VOLUME_ATTACH_RECEIPTS_UNAVAILABLE`,
    `VOLUME_ATTACH_OPERATION_CONFLICT`, `VOLUME_ATTACH_COMMITTED_GONE` codes),
    `GET /v1/history/base-provenance/:commitId`, and `GET|HEAD /v1/history/objects/:digest`
    (the `HISTORY_*` error codes).
  - Receipted attach on a journal-served branch is manifest-free: the session
    base may be a content-addressed PFT2 commit that carries no JSON manifest
    (branches born from cuts, forks of live branches), and the response then
    omits the manifest projection — the claimant resolves its base through the
    base-provenance proof. Every existing field keeps its meaning; consumers
    of journal-branch attaches must not require a manifest.
  - `POST /v1/volumes/:id/snapshots` keeps its wire shape and gains additive
    snapshot-record fields (`state`, `cutId`, `resultCommitId`, `cutSeqExclusive`)
    plus the optional `operationId` request field; `GET .../snapshots` lists the
    same records. `commitId` keeps its frozen meaning on commit-pinned records;
    on cut-backed records (which only journal-era servers emit) it names the
    cut's base anchor commit and stays stable. Cut-backed records persist the
    caller's optional `name` exactly like commit-pinned records (the field was
    always in the record shape; earlier journal-era servers dropped it on
    live-branch snapshots).
  - `GET /v1/volumes/:id/commits` entries gain the optional `commitKind`
    discriminator; PFT2 entries carry their stored `pft2:<hex>` tree identity.
  - Branch/fork creation from a cut record answers typed
    `HISTORY_CUT_NOT_READY` / `HISTORY_CUT_FAILED` / `HISTORY_FORK_UNSUPPORTED`
    conflicts; branch-from-ready-cut responses carry a manifest-free `head`
    summary plus `commitKind`.
  - Cross-volume fork of a READY cut record (migration
    `018_managed_volume_fork`, additive): `POST /v1/snapshots/:cutId/fork`
    creates a new managed (journal-native) volume zero-copy — the response
    keeps the frozen `volume`/`branch`/`head` fork shape and gains the
    additive `commitKind` (the head is a manifest-free PFT2 summary),
    `operationId`, and `replayed` fields, plus the optional exact-once
    `operationId` request field. Genuinely unsupported cases stay typed:
    lineages without 018 keep answering `HISTORY_FORK_UNSUPPORTED`, not-ready
    sources keep `HISTORY_CUT_NOT_READY` / `HISTORY_CUT_FAILED`, and refused
    forks (replayed id with a changed payload, destination id collision,
    source not provable) answer the new `409 HISTORY_FORK_REJECTED`.
    Commit-pinned snapshot forks are byte-identical to before.
  - Journal-served branches answer manifest head/status/wait-head/diff/attach
    routes with typed `409 LIVE_AUTHORITY_ROUTE_REQUIRED` /
    `HISTORY_CUT_REQUIRED` conflicts (base-authoring branches are unchanged).
  - `POST /v1/volumes/:id/grep` serves journal-served (live) branches from an
    exact immutable HistoryCut of the live state, minted or reused per call.
    Responses may gain additive optional fields naming the cut consumed (for
    example `cutId`); consumers must ignore unknown fields.
  - Pre-launch security retirement: `POST /v1/volumes/:id/exec` remains
    addressable but always answers `410 VOLUME_EXEC_RETIRED` without parsing
    the body or reading volume state. `VOLUME_API_TENANT_EXEC=1` refuses
    startup rather than restoring in-process host execution.
  - Admission/overload codes `VOLUME_OVERLOADED`, `VOLUME_RESPONSE_TOO_LARGE`,
    `VOLUME_INVALID_CONTENT_LENGTH`, `VOLUME_PATH_INVALID`, `VOLUME_DRAINING`,
    and `VOLUME_REQUEST_CANCELLED`, plus the `x-portablefs-request-id`
    response header.
  - `VOLUME_HISTORY_STORES_JSON` (self-host convenience alias of the
    `PFH_WORKER_STORES_JSON` failure-domain store map) and
    `VOLUME_API_TELEMETRY=stdout`. Unset preserves previous behavior.
- Volume API production hardening and journal-bounding maintenance (all additive;
  see [docs/self-hosting.md](./docs/self-hosting.md) and
  [docs/history.md](./docs/history.md)):
  - `GET /readyz` on the volume API (unauthenticated control readiness: serving
    phase + metadata connectivity + current migration lineage; coarse codes only,
    never blob-store probes). `GET /healthz` keeps its frozen dependency-free
    liveness meaning.
  - Admin history routes `POST /v1/admin/history/cuts`,
    `GET /v1/admin/history/cuts/:cutId`, and
    `POST /v1/admin/history/cuts/:cutId/adopt` (admin token; typed
    `HISTORY_*` error codes including the `HISTORY_PF0xx` conflict mapping).
    Responses are additive — consumers must ignore unknown fields.
  - The journal-bounding maintenance loop and its variables
    `PORTABLEFS_HISTORY_MAINTENANCE` (default `on`; `off` is refused in
    production `NODE_ENV` because adoption is what keeps managed volumes
    writable), `PORTABLEFS_HISTORY_MAINTENANCE_INTERVAL_MS` (default 60000),
    and `PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT` (default 70), plus
    the `history_maintenance` telemetry event on the stdout sink.
  - Bounded-resource tuning: `VOLUME_DATABASE_POOL_MAX` (default 32, strict
    1..32), `VOLUME_API_HEADERS_TIMEOUT_MS`, `VOLUME_API_REQUEST_TIMEOUT_MS`,
    `VOLUME_API_KEEPALIVE_TIMEOUT_MS`, `VOLUME_API_MAX_REQUESTS_PER_SOCKET`,
    and `VOLUME_API_MAX_CONNECTIONS`. Unset, defaults are production-safe and
    previous deployments keep working.
- Volume API blob-plane performance (all additive; see
  [docs/self-hosting.md](./docs/self-hosting.md)):
  - `GET /v1/blobs/:digest` streams its body with backpressure and now
    supports single-range HTTP `Range` requests (`bytes=a-b`, `bytes=a-`,
    `bytes=-n`): `206 Partial Content` with `Content-Range` for satisfiable
    ranges, `416` for unsatisfiable, multi-range, or malformed ones (a
    malformed header is never silently ignored), and the additive
    `Accept-Ranges: bytes` response header. Full (non-range) reads keep the
    content-address guarantee: the body can only COMPLETE if the bytes
    verified against the digest — a store fault surfaces as a destroyed
    connection, never a clean corrupt download. Requests without a `Range`
    header receive the same 200-with-body response as before.
  - Per-tenant admission: `VOLUME_API_TENANT_MAX_REQUESTS` and
    `VOLUME_API_TENANT_MAX_RESPONSE_BYTES` (defaults 50% of the global
    128-request / 256 MiB budgets; `0` disables) bound one tenant's
    concurrent requests and reserved transient bytes, refusing with the new
    typed `429 VOLUME_TENANT_OVERLOADED` plus `Retry-After` — distinct from
    the global `VOLUME_OVERLOADED`. A tenant's only in-flight request is
    never refused by the byte cap, so single-tenant deployments under the
    defaults behave as before outside genuine saturation (where some
    refusals that were `VOLUME_OVERLOADED` may now be the more precise
    tenant code). The `blob_read` route label joins the telemetry dimension
    set, and uploads/downloads no longer share one route-concurrency bucket.
  - `VOLUME_MANIFEST_INDEX_CACHE_MB` (default 256) byte-bounds the commit
    manifest index cache using a documented per-entry estimate; the previous
    128-entry cap remains as a secondary bound. Unset preserves defaults.

## Internal

No stability promise. These change without notice, including in patch releases.

- Everything under `vcs/internal/` (Go packages are enforced-internal by the compiler).
- TypeScript module internals: anything not exported from a package's public entry
  point, including the shapes of `packages/*` inter-workspace imports.
- Test helpers, fixtures, and `packages/testkit`.
- Documentation wording, scripts under `scripts/`, and benchmark harnesses.
- The `vcs/cmd/treehashcheck` development tool.

## Changing A Frozen Surface

Frozen does not mean immortal; it means changes are deliberate and staged:

1. Propose the change in an issue explaining why additive evolution cannot work.
2. Ship the replacement additively (new route, new variable, new protocol version)
   while the old surface keeps working, and mark the old surface deprecated in docs
   and release notes.
3. Keep the deprecated surface for a published deprecation window of at least one
   minor release line, with a warning where feasible (startup log, response header).
4. Remove it only in the next major version.

PRs that touch a frozen surface must say so explicitly and explain the compatibility
story. Reviewers should reject silent changes to anything in the frozen list.
