# Self-Hosting

Production deployment guide for a self-hosted PortableFS. For a laptop-local stack,
use `./scripts/quickstart.sh` instead; nothing in the quickstart compose file is
production-safe.

## What You Deploy

Three stateful pieces plus one disposable manager:

| Piece | Role | Image / binary |
| --- | --- | --- |
| Postgres | Metadata AND the live journal: volumes, branches, commits, tenants, plus the fenced `pfj`/`pfm`/`pfh` schemas ([journal.md](./journal.md)) | your own (Postgres 16+, synchronous replication for production durability) |
| Blob store | Content-addressed durable bytes | S3-compatible bucket, or a filesystem directory for a single node |
| volume-api | Control and history API (`/v1`) | `Dockerfile.volume-api` |
| authority-manager | Resolves `teamId + volumeId + branch` to a live VCS authority; production mode spawns one journal child per active branch behind one TCP/TLS router | `Dockerfile.authority-manager` (bundles the Go `vcs` binary) |
| volume-worker | GC, compaction, integrity checks (one-shot jobs) | `Dockerfile.volume-worker` |
| history-worker | Resident Go worker that materializes journal cuts into immutable history and services recovery-cut adoption; required in production (see below) | `Dockerfile.history-worker` |

Build the images from source with the Dockerfiles at the repo root (the
quickstart compose file does exactly this). The release workflow additionally
publishes prebuilt images to
`ghcr.io/steerlabs/portablefs-{volume-api,volume-worker,authority-manager,history-worker}`
once it has run for a given version.

## Volume API

```bash
VOLUME_DATABASE_URL=postgres://...          # required; migrations apply on startup
VOLUME_API_TOKEN=<admin-token>              # admin credential: tenant provisioning + GC only
# S3-compatible blob storage (the default backend; VOLUME_BLOB_STORE=s3 is the
# canonical name, railway-bucket a legacy alias):
VOLUME_RAILWAY_BUCKET_ENDPOINT=https://...
VOLUME_RAILWAY_BUCKET_NAME=portablefs-blobs
VOLUME_RAILWAY_BUCKET_REGION=...
VOLUME_RAILWAY_BUCKET_ACCESS_KEY_ID=...
VOLUME_RAILWAY_BUCKET_SECRET_ACCESS_KEY=...
VOLUME_RAILWAY_BUCKET_PREFIX=portablefs/prod
# or, single-node filesystem blobs on a durable volume:
# VOLUME_BLOB_STORE=filesystem
# VOLUME_FILESYSTEM_BLOB_ROOT=/data/blobs
```

The storage package also reads standard `AWS_*` names; see
[railway-buckets.md](./railway-buckets.md). The API listens on `PORT` (default 8787)
and answers `GET /healthz` (dependency-free liveness; the quickstart compose probes
it) plus `GET /readyz` (control readiness: serving phase + a bounded metadata probe
proving connectivity and a current migration lineage — blob stores are never
touched). Gate deploys on `/readyz`; keep orchestrator liveness on `/healthz` so a
draining process is not killed early.

Token model: `VOLUME_API_TOKEN` is the admin credential. Provision per-tenant bearer
tokens through `POST /v1/admin/tenants` and hand those to VCS authorities, CLIs, and
agents. Admin tokens cannot read tenant data; tenant tokens cannot provision or GC.

Connection and transport bounds (all optional; production-safe defaults):

```bash
VOLUME_DATABASE_POOL_MAX=32              # Postgres pool ceiling, 1..32 (strictly validated)
VOLUME_API_HEADERS_TIMEOUT_MS=30000      # slow-header (slowloris) bound
VOLUME_API_REQUEST_TIMEOUT_MS=300000     # whole-request clock
VOLUME_API_KEEPALIVE_TIMEOUT_MS=5000     # idle keepalive close
VOLUME_API_MAX_REQUESTS_PER_SOCKET=1000  # bounded keepalive reuse
VOLUME_API_MAX_CONNECTIONS=1024          # concurrent socket ceiling
VOLUME_API_TENANT_MAX_REQUESTS=64        # per-tenant concurrent requests (default 50% of global; 0 disables)
VOLUME_API_TENANT_MAX_RESPONSE_BYTES=134217728  # per-tenant reserved transient bytes (default 50% of global; 0 disables)
VOLUME_MANIFEST_INDEX_CACHE_MB=256       # manifest index cache byte budget (128-entry cap stays as a secondary bound)
```

Request admission (128 concurrent requests / 256 MiB transient memory) is the
concurrency control; the pool cap keeps the API from stampeding PostgreSQL, and the
transport bounds close slowloris/socket-exhaustion exposure before any handler runs.

The per-tenant caps stop one tenant from consuming the whole budget before any
global limit trips: a tenant at its cap receives a typed `429
VOLUME_TENANT_OVERLOADED` with `Retry-After` (distinct from the global
`VOLUME_OVERLOADED`) while every other tenant admits normally. A tenant's ONLY
in-flight request is never refused by the byte cap — the caps bound accumulation
across concurrent requests, so single-tenant self-hosts under the defaults keep
working unchanged unless one credential genuinely saturates the server. Blob
downloads (`GET /v1/blobs/:digest`) stream with backpressure and support single
HTTP `Range` requests; a streamed response reserves only a fixed 256 KiB pipe
window against the transient budget, while a response served from the in-memory
blob cache (blobs up to 8 MiB) reserves its actual byte length.

### Journal-bounding maintenance (keep it on)

Managed branches journal every acknowledged write into a PFJ3 generation that is
admission-bounded (4 GiB / 1,048,576 records per generation by default) and
resumed — never rotated — across child restarts. The ONLY way that backlog shrinks
is history-cut adoption: a ready recovery cut of the journal is adopted, which
advances the generation's base and subtracts the captured backlog. The volume-api
runs a maintenance loop that drives this automatically; without it, every managed
branch's backlog grows until the quota bricks its writes.

Each cycle the loop scans for generations past a backlog threshold, creates a
recovery cut per backlogged generation (deterministic operation ids make this
exact-once and safe with any number of API replicas), adopts cuts as the history
worker materializes them, and releases superseded serving pins. One structured
`portablefs_telemetry {"type":"history_maintenance",...}` line per cycle reports
generations scanned, cuts created, adoptions, pins released, and the top backlog
percent.

Adoption is held (and reported as `adoptionsBlocked`) until exact history
serving is configured (`PFH_WORKER_STORES_JSON` / `VOLUME_HISTORY_STORES_JSON`):
an adopted PFT2 base is what the next authority cold start must fetch through
`/v1/history/*`. Expect one bounded authority restart per adoption on a branch
with a live writer — the child's fail-closed journal mirror refuses an unproven
base move, steps down, and the replacement cold-starts from the freshly adopted
base (see [history.md](./history.md)).

```bash
PORTABLEFS_HISTORY_MAINTENANCE=on                    # default on; "off" is REFUSED in production
PORTABLEFS_HISTORY_MAINTENANCE_INTERVAL_MS=60000     # cycle interval (min 1000)
PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT=70    # 1..100, percent of the generation quota
```

`PORTABLEFS_HISTORY_MAINTENANCE=off` is allowed only outside production `NODE_ENV`
(local debugging); a production process refuses to start with it because the loop is
what keeps volumes writable. Adoption requires the resident Go history worker
(`Dockerfile.history-worker`) to materialize recovery cuts — deploy it alongside the
API with an installed replication policy, or backlog can only be observed, never cut.

Operators can drive and inspect the same machinery manually under the admin token:
`POST /v1/admin/history/cuts` (create a cut; supply an `operationId`),
`GET /v1/admin/history/cuts/:cutId?tenantId=...` (status), and
`POST /v1/admin/history/cuts/:cutId/adopt` (adopt a ready recovery cut). See
[history.md](./history.md) for the mechanism.

## Authority Manager (Production Mode)

Production is the manager's journal-native production mode: one public TCP/TLS
router address, one disposable journal child per active `teamId + volumeId +
branch`, session-token routing, and fenced lifecycle calls. Product workers and
sandboxes never see loopback ports or spawn VCS processes, and no durable fact
lives on the manager host — the children journal to the fenced `pfj` schema over
`VCS_JOURNAL_DSN`, and manager/runtime/lease control state lives in the `pfm`
schema.

```bash
NODE_ENV=production
PORTABLEFS_AUTHORITY_MODE=production
PORTABLEFS_AUTHORITY_MANAGER_TOKEN=<manager-api-token>
PORTABLEFS_MANAGER_CONTROL_DATABASE_URL=postgres://portablefs_manager@db.internal/portablefs
PORTABLEFS_MANAGED_VCS_BIN=/usr/local/bin/vcs
PORTABLEFS_MANAGED_VCS_JOURNAL_DSN=postgres://portablefs_authority@db.internal/portablefs
PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON='{"v":1,"expectedSystemIdentifier":"...","expectedDatabase":"portablefs","minSynchronousCommit":"on","minSyncStandbys":1,"standbyFailureDomains":{"pg-standby-a":"zone-a"},"minDistinctFailureDomains":1}'
PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET=<64 hex chars>
PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR=0.0.0.0:2050
PORTABLEFS_AUTHORITY_ROUTER_URL=portablefs-vcs.example.com:2050
PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH=/etc/portablefs/router.crt
PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PATH=/etc/portablefs/router.key
PORTABLEFS_VOLUME_API_URL=https://volume-api.example.com
```

There is deliberately NO static child credential: the manager mints short-lived
per-child runtime read credentials in the database (migration 015) and each
spawned authority presents its own rotating credential to the volume API as the
tenant that owns its volume — so one manager serves every tenant's volumes.
Setting `PORTABLEFS_VOLUME_API_TOKEN` (or `VOLUME_API_TOKEN`) on the manager is
a startup error.

The manager fails closed: the `pfm` control database, the VCS binary, the journal
DSN, the versioned structured HA policy (verified fact-by-fact by every child
against `pfj.durability_facts()` — a prose attestation is never a durability
gate), the access-token root secret, a public router URL/listen address, and
router TLS are all required. Plaintext is only possible with
`PORTABLEFS_AUTHORITY_ROUTER_ALLOW_PLAINTEXT_PRODUCTION=1` behind an
authenticated private tunnel (WireGuard or equivalent) — never on the public
internet. This gate follows `PORTABLEFS_AUTHORITY_MODE=production` directly;
it does not depend on `NODE_ENV`.

The children run with `VCS_PRODUCTION=1`, bind loopback listeners themselves, and
report the exact addresses back on the inherited bootstrap pipe; the manager
routes to a child only after its bootstrap and `/readyz` identity checks pass. A
manager restart is an epoch handoff, not a recovery: the new process claims a
fresh `pfm` epoch and demand-starts fresh children that cold-replay from the
journal. There is no work-dir volume to attach and nothing manager-local to back
up.

The manager API listens on `PORT` (default 8788; `/healthz`, `/readyz`, and a
bearer-authenticated Prometheus `GET /metrics` covering child memory, lease
counts, capacity pressure, and eviction activity); expose only the router port
(2050) to mount clients. Multi-tenant deployments can additionally set the
per-tenant fairness budgets `PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT`
and `PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT` (unset = off; over-budget
requests refuse 429 `TENANT_AT_CAPACITY` / `TENANT_LEASE_LIMIT` with
`Retry-After`). Full route semantics, the metric inventory, and the complete
child environment/pipe contract: [authority-manager.md](./authority-manager.md).

The journal database is the durability layer, so its PostgreSQL must be deployed
with synchronous replication matching the HA policy you configure (the children
refuse to serve when the live evidence is weaker). Single-node PostgreSQL is the
explicit development posture — equal to a local disk's durability.

Behind a transaction-mode pooler (PgBouncer/pgcat — common on managed
platforms with low connection ceilings), set
`PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE=transaction` on the manager. The
journal children then omit the session timeout startup parameters a pooler
cannot preserve; migration 016_pooler_timeouts installs the equivalent
database-owned deadlines (statement 30s / lock 5s / idle-in-transaction 60s).
Apply the migration and recycle pooler server connections before enabling
pooled children. The TypeScript services (volume API, manager control store)
keep their own driver-level timeouts and may share the pooler.

The history worker needs the legacy blob store configured to activate adopted
volumes (`portablefs adopt` authors its base as manifest commits, and the
activation conversion reads that content by its recorded storage keys):

```bash
PFH_WORKER_LEGACY_STORE_JSON='{"kind":"fs","rootDir":"/data/blobs"}'   # or kind "s3"
```

Point it at the same store the volume API writes blobs to. Without it,
`portablefs adopt` / `portablefs activate` fail typed at the conversion step.

### Live branches and the CLI

Once a branch is journal-served (every created-managed or adopted volume), its
manifest head routes answer typed conflicts (`LIVE_AUTHORITY_ROUTE_REQUIRED`)
by design. The CLI works with live branches through mode-agnostic metadata
instead:

- `portablefs status` reads the branch listing (which carries the branch
  mode), the latest committed revision, and the snapshot-cut lifecycle, and
  reports live branches as live — including this machine's mounts and their
  health.
- `portablefs snapshot` on a live branch records an asynchronous history cut
  (`pending` until the history worker materializes it; the listing shows the
  state).
- `portablefs fork` and `portablefs branch` snapshot the live state when
  needed, wait for the cut to become ready (with progress), and then fork or
  branch from the ready record. Cross-volume fork of a ready cut is zero-copy
  (migration 018) and the forked volume mounts normally. On a repository whose
  migration lineage predates 018 the fork route refuses typed, and the CLI
  hands you the same-volume equivalent
  (`portablefs branch <vol> <name> --from-snapshot <cutId>`).
- `portablefs grep` on a live branch scans an exact immutable history cut of
  the live state, minted (or reused) per call. Commands run through a mount;
  the Volume API does not execute tenant processes.

Mount daemons watch their credentials: when the control plane definitively
rejects a mount's key (revocation, expiry), the daemon logs one line in its
mount log, `portablefs mounts` reports the mount `credential-expired` instead
of `live`, and recovery (a new key) clears both. The lease-TTL grace between
revocation and enforcement is unchanged.

## Standalone VCS (Without The Manager)

A single writable VCS with a local file WAL remains the explicit self-host
single-node shape (run WITHOUT `VCS_PRODUCTION`):

```bash
VCS_WRITABLE=1
VCS_WAL=/var/lib/portablefs/vol_123.wal
VCS_FS_ADDR=<custom-protocol-listen-addr>       # optional FUSE data plane
VCS_TLS_CERT=... VCS_TLS_KEY=...                # for a network-reachable listener
VCS_AUTH_TOKEN=<data-plane-token>               # or mTLS via VCS_TLS_CLIENT_CA
VOLUME_API_URL=... VOLUME_API_TOKEN=... VCS_VOLUME_ID=vol_...
```

Durability equals that one disk plus the periodic checkpoints to the blob store.
Optional hardening: `VCS_ENCRYPTION_KEY` seals the WAL and disk cache with
AES-256-GCM. See [../vcs/README.md](../vcs/README.md) for cache tuning and metrics
(`VCS_METRICS_ADDR` serves `/healthz`, `/readyz`, `/metrics`).

Memory tuning: `VCS_CACHE_RAM_MB` (default 256) sizes the read cache, and
`VCS_DIRTY_RSS_MAX_MB` (default 2048; must be a positive integer) bounds the
resident memory of uncommitted dirty file blocks — dirty blocks materialise at
4 MiB granularity, so unbounded they are the process's dominant RAM cost.
Writes past the bound refuse with `ENOSPC` until a truncate/remove releases
memory or a checkpoint folds the blocks out; reads, deletes, and metadata
operations always keep working. Both knobs also pass to managed children
through the manager's `PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON` allowlist — the
managed child never checkpoints in-process, so its dirty blocks live for the
whole generation and the bound is what keeps one tenant's write pattern from
exhausting the shared host's memory.

## Volume Worker

Run `volume-worker` jobs on a schedule with the same database and bucket
credentials as the API: `integrity` (default command), `gc --dry-run`, then `gc`.
GC is global mark-and-sweep over content-addressed blobs with a grace window that
protects the upload-before-commit gap; run `--dry-run` and review counts before the
first real sweep.

## Backup And Restore

Production state lives in exactly two places:

- **Postgres.** Committed history metadata AND the live journal (`pfj`), the
  manager control plane (`pfm`), and the history plane (`pfh`). Back it up with
  WAL archiving or scheduled dumps and run it with the synchronous replication
  your HA policy attests. Restoring Postgres restores both committed history and
  every acknowledged-but-uncut live write.
- **The bucket.** Content-addressed blobs for committed history. These backups
  are consistent with Postgres by construction: commits reference
  content-addressed blobs, and the API validates referenced blobs before
  advancing a branch head, so a restored Postgres never points at bytes the
  bucket cannot serve (do not GC between a Postgres restore point and now —
  pause GC while restoring).

There is no manager-local live state to back up in production. A standalone dev
or single-node VCS additionally has its local WAL file: losing that disk loses
only the last uncheckpointed seconds, and the volume reopens from its last
committed head.

## Upgrades

- **Migrations are append-only.** The volume-api applies pending migrations on
  startup; released migration files are never edited. Upgrade the API first (old
  workers and VCS binaries keep working against the additively-migrated schema),
  then the worker, then the manager.
- **Manager restarts are epoch handoffs.** A restarted production manager claims
  a fresh epoch and demand-starts fresh children that cold-replay from the
  journal; mounts reacquire leases and reconnect. Still, upgrade it during a
  quiet window rather than under heavy mount churn.
- **Mount clients and authorities negotiate protocol versions** (`fsproto`), so
  client and server release trains may skew. Consult [../COMPATIBILITY.md](../COMPATIBILITY.md)
  for what each release is allowed to change.
- **Verify what is serving with `GET /v1/release-identity`.** The published
  images bake the exact release id and source revision; deployment tooling
  should poll the endpoint after promoting (and after rolling back) instead of
  assuming the platform switched artifacts. See
  [release-identity.md](./release-identity.md).
