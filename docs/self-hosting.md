# Self-Hosting

> **Frozen v2 document.** These instructions deploy the retired v2 stack, not
> PortableFS v3. The v3 launch topology is documented in
> [the authoritative-XFS runbook](./xfs-authority-deployment.md).

Production deployment guide for a self-hosted PortableFS. For a laptop-local stack,
use `./scripts/quickstart.sh` instead; nothing in the quickstart compose file is
production-safe.

## What You Deploy

Three stateful pieces plus one disposable manager:

| Piece | Role | Image / binary |
| --- | --- | --- |
| Postgres | Metadata AND the live journal: volumes, branches, commits, tenants, plus the fenced `pfj`/`pfm`/`pfh` schemas ([journal.md](./journal.md)) | your own (Postgres 16+, synchronous replication for production durability) |
| Blob store | Content-addressed durable bytes | S3-compatible bucket, or a filesystem directory for a single node |
| volume-api | Control and history API (`/v1`), including the admin GC/integrity endpoints | `Dockerfile.volume-api` |
| authority-manager | Resolves `teamId + volumeId + branch` to a live VCS authority; production mode spawns one journal child per active branch behind one TCP/TLS router | `Dockerfile.authority-manager` (bundles the Go `vcs` binary) |
| history-worker | Resident Go worker that materializes journal cuts into immutable history and services recovery-cut adoption; required in production (see below) | `Dockerfile.history-worker` |

Build the images from source with the Dockerfiles at the repo root (the
quickstart compose file does exactly this). The release workflow additionally
publishes prebuilt images to
`ghcr.io/steerlabs/portablefs-{volume-api,authority-manager,history-worker}`
once it has run for a given version.

## Volume API

```bash
VOLUME_DATABASE_URL=postgres://...          # required; migrations apply on startup
VOLUME_API_TOKEN=<admin-token>              # admin credential: tenant provisioning + GC only
# S3-compatible blob storage (the default backend, VOLUME_BLOB_STORE=s3):
AWS_ENDPOINT_URL=https://...
AWS_S3_BUCKET_NAME=portablefs-blobs
AWS_DEFAULT_REGION=auto
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
VOLUME_S3_PREFIX=portablefs/prod            # optional; default "portablefs"
# VOLUME_S3_SSE=AES256                      # optional server-side encryption header
# VOLUME_S3_REQUEST_TIMEOUT_MS=300000        # optional; 1s..10m
# or, single-node filesystem blobs on a durable volume:
# VOLUME_BLOB_STORE=filesystem
# VOLUME_FILESYSTEM_BLOB_ROOT=/data/blobs
```

`AWS_ENDPOINT_URL` must use HTTPS. Loopback-only development stores may opt
into HTTP with `VOLUME_S3_ALLOW_INSECURE_ENDPOINT=1`; the flag never permits a
plaintext non-loopback endpoint. The request timeout covers uploads and
buffered/control responses, while streaming reads use it only for response
headers and remain caller-abortable afterward.

The retired Railway-era spellings are accepted as compat aliases for one
release, so existing deployments keep working without config changes:

| Retired name | Canonical name |
| --- | --- |
| `VOLUME_BLOB_STORE=railway-bucket` | `VOLUME_BLOB_STORE=s3` |
| `VOLUME_RAILWAY_BUCKET_ENDPOINT` | `AWS_ENDPOINT_URL` |
| `VOLUME_RAILWAY_BUCKET_NAME` | `AWS_S3_BUCKET_NAME` |
| `VOLUME_RAILWAY_BUCKET_REGION` | `AWS_DEFAULT_REGION` |
| `VOLUME_RAILWAY_BUCKET_URL_STYLE` | `AWS_S3_URL_STYLE` |
| `VOLUME_RAILWAY_BUCKET_ACCESS_KEY_ID` | `AWS_ACCESS_KEY_ID` |
| `VOLUME_RAILWAY_BUCKET_SECRET_ACCESS_KEY` | `AWS_SECRET_ACCESS_KEY` |
| `VOLUME_RAILWAY_BUCKET_PREFIX` | `VOLUME_S3_PREFIX` |
| `VOLUME_RAILWAY_BUCKET_SSE` | `VOLUME_S3_SSE` |

The endpoint/credential family aliases all-or-nothing, keyed on
`VOLUME_RAILWAY_BUCKET_ENDPOINT` being set (a deployment carrying both
spellings resolves exactly as before); prefix and SSE alias independently.
The API listens on `PORT` (default 8787)
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

Managed branches journal every authority-applied write into a PFJ3 generation that is
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

### Journal storage reclamation

Cutting and adopting bounds the **logical** backlog: it advances the
generation's base and subtracts the backlog counters, but every journal record
payload below that base stays in `pfj.journal_records`. Migration 031 adds the
physical half — the maintenance loop deletes those rows in bounded pages, and
volume retirement (`portablefs rm`) drives the volume's generations terminal so
its whole journal becomes reclaimable.

```bash
PORTABLEFS_JOURNAL_RETENTION_MS=604800000   # 7d; a SUSPENDED generation idle this long is
                                            # cut on AGE, not on backlog size (min 3600000)
PORTABLEFS_JOURNAL_RECLAIM_BATCH=512        # rows deleted per bounded reclaim transaction
PORTABLEFS_JOURNAL_RECLAIM_MAX_PAGES=64     # reclaim transactions per maintenance cycle
```

The retention knob exists because a percent-of-quota threshold can never reach
an abandoned branch: it is suspended, small, and therefore never cut, never
adopted, and never reclaimable. Reclamation only ever deletes below a horizon
proven by rows — never at or above a generation's base, never below a
pending/materializing cut's read window, and for PFJ3 never without a ready cut
carrying a materialized recovery anchor.

**What reclamation does and does not give back.** Deleting rows returns their
space to the table's free space map once (auto)vacuum runs, so the journal
stops growing and new records reuse the space — verified: re-inserting 190k
records after reclaiming 190k grew the table by 13 MB instead of ~100 MB. It
does **not** shrink the files on disk. Returning bytes to the operating system
needs `VACUUM FULL` or `pg_repack`, and `VACUUM FULL` rewrites the whole table,
so it needs free space equal to the table's size — the one thing a full disk
does not have. On a control store that is already full, reclaim first, let
autovacuum settle, and only then consider a rewrite.

Accounting: `GET /v1/admin/control-store/usage` (admin token) reports journal
record counts, the reclaimable subset, and relation/database bytes. Sizes come
from `pg_total_relation_size` (heap + indexes + TOAST + bloat) rather than a
sum of row payloads: it is both the number that matches the disk and O(1),
where summing payloads costs a full scan that slows down exactly as the
backlog it reports grows. The
authority manager publishes the same consumption on its authenticated
`/metrics` as `pfm_control_store_database_bytes` and
`pfm_control_store_{pfj,pfm,pfh,public}_bytes`. Each maintenance cycle's
telemetry line carries `recordsReclaimed`, `bytesReclaimed`,
`reclaimCandidates`, and `agedGenerationsForced`.

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
PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE=tls-system-pki
PORTABLEFS_AUTHORITY_ROUTER_TLS_SERVER_NAME=portablefs-vcs.example.com
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
an explicit router transport are all required. `tls-system-pki` uses the
system roots and exact configured server name. For a private CA, select
`tls-private-ca` and configure exactly one `PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PATH`
or `_PEM`; its strict PEM and SHA-256 ride in every access lease. Plaintext is
only possible with `PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE=plaintext` and
`PORTABLEFS_AUTHORITY_ROUTER_ALLOW_PLAINTEXT_PRODUCTION=1` behind an
authenticated private tunnel (WireGuard or equivalent) — never on the public
internet. This gate follows `PORTABLEFS_AUTHORITY_MODE=production` directly;
it does not depend on `NODE_ENV`.

Router startup fails before publishing its listener unless the serving leaf
matches the private key and advertised SAN/IP, the served intermediates form
one ordered signature-valid chain, and every certificate is currently valid
for TLS server use. Private-CA mode additionally completes a local TLS 1.3
handshake against the exact advertised trust bundle. System-PKI mode cannot
completes the same handshake against the manager runtime's default roots,
rejecting private/self-signed chains, but cannot prove that all remote client
platforms have refreshed to the identical public root set. Retain an
end-to-end lease-and-dial readiness check across the supported platform matrix.

Use `host:port` for DNS/IPv4 router addresses and `[address]:port` for IPv6.
The manager rejects unbracketed IPv6, URL paths/userinfo/query strings,
ambiguous numeric IPv4 forms, and noncanonical ports. Supported `tcp://` or
`fsproto://` public inputs are normalized once to a scheme-free dial address
before any lease is emitted.

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

## Memory Tuning

Memory tuning: `VCS_CACHE_RAM_MB` (default 256) sizes the read cache, and
`VCS_DIRTY_RSS_MAX_MB` (default 2048; must be a positive integer) bounds the
resident memory of uncommitted dirty file blocks — dirty blocks materialise at
4 MiB granularity, so unbounded they are the process's dominant RAM cost.
Writes past the bound refuse with `ENOSPC`; reads, truncates, and metadata
operations always keep working. That is a mount-level guarantee and not a
description of intent: a capacity refusal from the authority freezes the mount's
DATA CREDIT gate and nothing else, so a write gets a definite `ENOSPC` before it
takes a lock while `read`, `stat`, `ls`, `mkdir`, `chmod` and — critically —
`truncate` are never consulted against it. Truncate is the remedy for this
condition (it is what hands the authority's resident dirty blocks back), so it
must not be refused BY the condition. Note that `rm` is not the remedy on a
managed authority: an unlinked inode parks until reap and releases nothing.

The refusal is also relievable rather than terminal. It is a statement about the
authority's occupancy at one instant, so the mount keeps re-offering the refused
batch on a slow probe; the first batch the authority applies clears the refusal
and re-admits writes with no remount. `portablefs mounts --json` reports it as
`capacityRefused` — distinct from a degraded mount (a far end that stopped
answering) and from a parked stream (a proven contradiction that fences the
mount until remount). Both knobs pass to managed children through
the manager's `PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON` allowlist. The manager +
PostgreSQL journal is the ONLY authority shape: there is no standalone
file-WAL VCS.

**How the bound is relieved, and why it is not a ceiling on lifetime writes.**
The managed child never checkpoints in-process, so for a long time nothing
released these blocks at all: adoption of a history cut advanced the journal
base without rebinding the child's inodes to it, and the counter only ever
grew. A branch therefore stopped accepting writes after roughly
`VCS_DIRTY_RSS_MAX_MB` of CUMULATIVE writes, whatever the rate.

Cut adoption now folds them. When the maintenance loop's recovery cut is
adopted, the child re-proves the adopted base and releases the resident copy
of every block that base contains — per block, and only where the journal
position the block was last written at proves the cut already materialised it,
so a block written since the cut keeps its in-memory copy and keeps overriding
the base. Resident memory is therefore bounded by the part of the journal that
has NOT yet been cut, not by the branch's history.

That makes the two bounds one question of ordering, so they can be coordinated
rather than tuned independently. With
`PORTABLEFS_HISTORY_COORDINATE_DIRTY_BOUND=on`, the Volume API clamps
`PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT` so the cut is triggered at
half the dirty bound expressed as a fraction of the journal quota — 25% with
the shipped defaults (a 2048 MiB RAM bound against a 4096 MiB journal quota),
where the default of 70% fills RAM twenty points before the loop looks. Tell
the Volume API what the children are sized at with `PORTABLEFS_DIRTY_RSS_MAX_MB`
(same value, same default) if you change `VCS_DIRTY_RSS_MAX_MB`. Raising the
RAM bound raises the clamp; that is the intended lever. `vcs` prints the
number it derives in its own startup record either way, so the two sides stay
checkable against each other.

> **This coordination is OFF by default and should stay off for now.** Cutting
> at 25% instead of 70% means recovery cuts are adopted while a writer is
> attached, and a PFJ3 authority does not currently survive that: the journal
> client requires the append response to carry a landed *legacy* checkpoint cut
> whenever the base commit changes, while migrations 013/031 forbid those
> columns from ever being set on a PFJ3 generation (PF005) and authorize the
> advance with a `pfh.adoptions` proof row instead. The client's check is
> therefore unsatisfiable, and the writer responds by poisoning its journal and
> fencing its data plane — the mount takes EIO. Until the append response
> carries the adoption proof the database actually issues, and the client
> checks that, a deployment is better off reaching the dirty bound (a definite,
> recoverable `ENOSPC`) than losing its authority.

Two limits worth knowing. The clamp bounds the trigger POINT, while
`PORTABLEFS_HISTORY_MAINTENANCE_INTERVAL_MS` (default 60 s) bounds the
overshoot between scans: a branch can add `write-rate x interval` of backlog
before the loop next looks, so a deployment with very fast writers relative to
its child RAM should shorten the interval. And neither bounds write
AMPLIFICATION: one byte written into each 4 MiB region materialises a whole
block per ~40 journal bytes, which no fraction of a journal quota can track.
For that shape the fold still recovers the memory at each adoption, and a
burst that outruns any cut cadence still lands on the definite `ENOSPC`.

## Unmount Recovery (When `--force` Refuses)

A mount's unshipped tail lives in a local write-back store as a RECOVERY JOB.
Almost every job needs nothing from you: the next attach of the same
volume+branch verifies and replays it. Two states do not — `conflict` and
`corrupt` — and a job in either of them blocks `portablefs umount --force` and
every future attach until an operator resolves it.

```
portablefs umount <path>                          # clean drain; refuses if it cannot drain
portablefs umount --force <path>                  # detach now; the tail parks as a recovery job
portablefs recovery list <path>                   # what the local store holds, and what is blocking
portablefs recovery resolve <path> --all-terminal # resolve the terminal jobs
portablefs umount --discard-record <path>         # end the bookkeeping once nothing owns the path
```

`recovery list` takes no lock and changes nothing, so it answers while a daemon
still owns the store. `recovery resolve` NEVER deletes: a terminal job's bytes
are the only remaining copy of what was acknowledged, so it moves them to
`<store>/unreplayable/`, reports exactly how many acknowledged records and bytes
never reached the authority and under which scopes, and leaves that verdict on
disk so it is re-reported on every later attach. It refuses any job that is not
proven terminal, any store a live engine still owns, and any stream whose
recorded identity does not match the store. Name the job with `--job` or say
`--all-terminal`; there is no default, because quarantining acknowledged bytes is
a data decision.

Never move or delete anything under the state directory by hand. If a refusal
names a command, that command exists and can make progress.

## Maintenance Jobs (GC And Integrity)

The retired volume-worker image's jobs are volume-api admin endpoints,
authenticated with the admin token (`VOLUME_API_TOKEN`):

- `POST /v1/admin/gc` with `{ "dryRun": true }` previews, `{}` sweeps, and an
  optional `graceMs` overrides the one-hour default grace window. GC is global
  mark-and-sweep over content-addressed blobs; the grace window protects the
  upload-before-commit gap. Review the dry-run counts before the first real
  sweep.
- `GET /v1/admin/integrity` is a read-only walk verifying every blob and chunk
  referenced by a committed manifest exists in the blob store.

Schedule them with any cron that can curl, for example:

```bash
# nightly GC preview + sweep, weekly integrity
0 4 * * *  curl -fsS -X POST -H "authorization: Bearer $VOLUME_API_TOKEN" \
  -H "content-type: application/json" -d '{}' https://volume-api.internal/v1/admin/gc
0 5 * * 0  curl -fsS -H "authorization: Bearer $VOLUME_API_TOKEN" \
  https://volume-api.internal/v1/admin/integrity
```

## Backup And Restore

Production state lives in exactly two places:

- **Postgres.** Committed history metadata AND the live journal (`pfj`), the
  manager control plane (`pfm`), and the history plane (`pfh`). Back it up with
  WAL archiving or scheduled dumps and run it with the synchronous replication
  your HA policy attests. Restoring Postgres restores both committed history and
  every authority-durable but uncut live write.
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
  then the history worker, then the manager.
- **Manager restarts are epoch handoffs.** A restarted production manager claims
  a fresh epoch and demand-starts fresh children that cold-replay from the
  journal. Existing mounts fail closed; remount explicitly against the new
  epoch. Upgrade it during a quiet window.
- **Mount clients and authorities negotiate exact protocol versions** (`fsproto`);
  incompatible versions fail closed and must be upgraded together. Consult
  [../COMPATIBILITY.md](../COMPATIBILITY.md)
  for what each release is allowed to change.
- **Verify what is serving with `GET /v1/release-identity`.** The published
  images bake the exact release id and source revision; deployment tooling
  should poll the endpoint after promoting (and after rolling back) instead of
  assuming the platform switched artifacts. See
  [release-identity.md](./release-identity.md).
