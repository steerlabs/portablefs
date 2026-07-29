# Authority Manager

The authority manager is the PortableFS control-plane boundary for hosted mounts.
Applications should not start VCS processes inside their product workers. They
should call this service to resolve a `volumeId` + `branch` into the current
routable VCS authority endpoint and mount credential.

```text
product worker / CLI
        |
        | POST /v1/authorities/ensure
        | POST /v1/access-leases/create
        v
PortableFS authority manager
        |
        | production (journal) registry / router
        v
one VCS authority instance for volume@branch
        |
        | custom FUSE protocol
        v
agent sandbox mount
```

The manager has one mode: **production** (the journal-native registry — spawns
one disposable journal child per active branch behind one TCP/TLS data-plane
router). The retired WAL-paired `managed` mode and the retired fixed-endpoint
`env` mode fail startup by name and point at production as the successor, as
do the retired env-registry variables (`PORTABLEFS_AUTHORITY_URL`,
`PORTABLEFS_AUTHORITY_MAP_JSON`).

## Contract

All API routes except `/healthz` and `/readyz` are protected with
`PORTABLEFS_AUTHORITY_MANAGER_TOKEN`; every route is HTTP `POST` except the
authenticated `GET /v1/release-identity` and `GET /metrics`
([Metrics](#metrics)).
The packaged server fails closed when the token is absent unless
`PORTABLEFS_AUTHORITY_MANAGER_ALLOW_UNAUTHENTICATED=1` is explicitly set for local
development; `NODE_ENV=production` rejects that unauthenticated bypass.

Request body:

```json
{
  "teamId": "optional-tenant-scope",
  "volumeId": "vol_123",
  "branch": "main"
}
```

Routes:

- `POST /v1/authorities/ensure` returns the current routable authority address.
- `POST /v1/authorities/health` returns `{ "healthy": true }` when the authority is ready.
- `POST /v1/authorities/stop` is a fenced lifecycle hook. The request must include
  `expectedAuthority` with the `authorityInstanceId` returned by `ensure`.
  Production mode stops only when that opaque instance id still matches the live
  authority.
- `POST /v1/access-leases/*` is the canonical lease API. See
  [Access Leases](#access-leases).

`teamId` is the volume's metadata tenant id. Production mode requires it on
every authority/lease request — every authority, runtime row, and lease is
keyed by the tenant namespace in SQL. The `portablefs` CLI resolves it from
the volume API automatically before dialing the manager. No caller ever
supplies a volume-api credential: the registry mints each spawned authority
its own short-lived runtime read credential in the database (migration 015),
scoped to the volume's owning tenant.

`ensure` response shape (the mount credential is only ever minted through
`/v1/access-leases/create`):

```json
{
  "authority": {
    "provider": "portablefs-managed",
    "authorityUrl": "vcs.example.com:2050",
    "host": "vcs.example.com",
    "port": 2050,
    "authorityInstanceId": "pfai_..."
  }
}
```

## Retired session routes

The legacy session-minting family — `POST /v1/mount-sessions`,
`POST /v1/volumes/:volumeId/mount-sessions`, and `POST /v1/authorities/session`
— is retired. For one release the routes remain as explicit tombstones: they
answer `410 { "error": { "code": "MOUNT_SESSION_RETIRED" | "AUTHORITY_SESSION_RETIRED" } }`
before any body parsing or registry dispatch. `POST /v1/access-leases/create`
is the successor; it ensures the authority and mints the mount credential in
one call.

## The Data-Plane Router

Production mode spawns its VCS children behind one public TCP/TLS router
address, so product workers and sandboxes never see loopback ports or spawn
VCS processes:

```text
Daytona / remote mount
        |
        | TLS TCP to one public router address
        v
authority-manager data-plane router
        |
        | session token -> local backend route
        v
loopback VCS authority for volume@branch
```

`ensure` is idempotent for `teamId + volumeId + branch`. It starts or reuses one
single-volume VCS authority instance, returns the stable public router address, and
includes an opaque `authorityInstanceId`. `session` starts/reuses the same authority
and mints the scoped router token required by mounts. `health` is inspection-only: it
does not start replacement authorities as a side effect. The router consumes the
session token as the first VCS auth frame, dials the selected loopback VCS using a
separate internal backend token, then pipes the filesystem protocol. Loopback VCS
ports and backend tokens never leak to product workers or sandboxes.

The public data-plane router terminates TLS; the VCS children listen only on
`127.0.0.1`, so they do not need public TLS. The router's route table IS the
access-lease service: a token resolves exactly while its lease is active on
the admitted generation, and lease end or rotation closes live tunnels.

The repository ships deployable Dockerfiles for the hosted PortableFS
services:

- `Dockerfile.volume-api` runs `@portablefs/volume-api`, applies metadata
  migrations on startup, and serves the lease/commit/blob/history API plus
  the admin GC/integrity endpoints.
- `Dockerfile.authority-manager` runs this manager plus the bundled Go `vcs`
  binary. No durable service volume is needed: production mode keeps no
  manager-local state.
- `Dockerfile.history-worker` runs the Go `vcs/cmd/history-worker` that
  materializes HistoryCuts ([history.md](./history.md)).

## Production Mode (Journal)

Production mode is the journal-native registry for stateless manager
deployments. Children journal to a fenced
remote Postgres journal instead of local WAL files, and manager, runtime, and
lease control state lives in the `pfm` manager-control database
(`PORTABLEFS_MANAGER_CONTROL_DATABASE_URL`). There is no persistent work
directory, no local WAL, no standby pair, and no file ledger: a production
manager host is disposable, and the local-topology variables (`VCS_WAL`,
`VCS_REPLICA_ADDR`, `VCS_REPLICA_LISTEN`, `VCS_STANDBY`, `VCS_STANDBY_WAL`,
`VCS_STANDBY_PROMOTION_DELAY`, `VCS_CACHE_DIR`) are rejected by name at
startup.

Mode selection is fail-closed. `PORTABLEFS_AUTHORITY_MODE=managed` (the
retired WAL-paired local registry) and `PORTABLEFS_AUTHORITY_MODE=env` (the
retired fixed-endpoint registry) refuse startup and name production as the
successor. `PORTABLEFS_AUTHORITY_MODE=production` remains accepted; an unset
mode is production.

### Singleton manager and the epoch model

The manager role is a database-fenced singleton. On startup the manager claims
the `pfm` manager row, which mints the next monotonic manager epoch under a
database-time lease (`PORTABLEFS_MANAGER_CLAIM_TTL_MS`, default 30000). The
manager renews the claim continuously; every control-store mutation presents
the epoch, the manager runtime id, and the manager capability, and the
database refuses anything that is not the live claim. Two managers can never
both mutate — the older epoch is superseded. Locally the manager keeps a
monotonic hard deadline derived from each successful renewal response; an
ambiguous renewal (outage, timeout) never extends it, and when it passes the
manager fences itself even if the store is unreachable.

Losing the epoch — a competitor claimed a newer one, or the deadline passed —
stops all mutation: readiness fails, every local lease projection ends and its
router tunnels close (the durable lease rows settle server-side under the new
epoch), the children are terminated, and the manager never writes through the
store again. Lease routes answer 503 `ACCESS_LEASE_EPOCH_SUPERSEDED` and
authority operations answer the equivalent supersession code. Access-token
keys are derived from the root secret plus the manager epoch and token
generation, so every predecessor token dies with its epoch.

### Child contract (environment + inherited pipes)

Each demanded `teamId + volumeId + branch` gets one disposable child process.
The child environment is built from scratch (only `PATH` is inherited; `HOME`
and `TMPDIR` point beneath the child's ephemeral temp cwd, which is removed
after teardown):

- Scope and identity: `VCS_VOLUME_ID`, `VCS_BRANCH`, `VCS_TENANT_ID` (the
  `teamId`, which is the volume-api tenant id), `VCS_AUTHORITY_INSTANCE_ID`,
  `VCS_WRITABLE=1`, `VCS_PRODUCTION=1`.
- Remote journal: `VCS_JOURNAL_DSN` (verbatim from
  `PORTABLEFS_MANAGED_VCS_JOURNAL_DSN`) and `VCS_JOURNAL_HA_POLICY_JSON`
  (verbatim from `PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON`); the child
  verifies live durability evidence against the policy and reports the
  canonical policy hash back.
- Fencing facts: `VCS_MANAGER_EPOCH`, `VCS_MANAGER_RUNTIME_ID`,
  `VCS_AUTHORITY_RUNTIME_SEQ` (the monotonic per-scope runtime row),
  `VCS_AUTHORITY_RUNTIME_ID`, and the per-runtime 256-bit
  `VCS_AUTHORITY_RUNTIME_CAPABILITY` (only its hash is stored; every journal
  transaction presents it and the database cross-checks the live `pfm` rows).
- Credentials: `VOLUME_API_URL`, `VOLUME_API_TOKEN_FILE` (a private 0600 file
  inside the child's work dir holding the manager-minted short-lived runtime
  read credential; the manager re-mints on a timer and atomically replaces the
  file, and the child re-reads it on change — the database stores only the
  credential's SHA-256, bound to the live `pfm` runtime row, and the volume
  API restricts it to tenant-scoped reads plus the pinned volume's own
  attach/detach/lease-renew), `VCS_AUTH_TOKEN` (the internal backend token the
  router dials with), `VCS_ADMIN_TOKEN`, and optionally `VCS_LEASE_TTL` from
  `PORTABLEFS_MANAGED_VCS_LEASE_TTL`.
- Inherited pipes: `VCS_HEARTBEAT_FD=3` and `VCS_BOOTSTRAP_FD=4`.

There are no listener addresses in the environment. The child binds
`127.0.0.1:0` itself and reports the exact bound addresses in one bounded
newline-terminated JSON bootstrap frame (at most 4 KiB) on fd 4, carrying its
full identity: protocol version, instance id, volume/branch, manager epoch,
runtime seq/id, HA policy hash, `fsAddr`, `metricsAddr`, and the journal
generation id. The frame is one-shot — trailing bytes, truncation, a foreign
identity, or a non-loopback address refuse the child rather than adopt it, and
`/readyz` re-verifies the same identity fields afterwards.

Fd 3 carries manager-to-child lease frames: after every successful claim
renewal the manager writes the identity plus the remaining database lease.
Delivery is latest-value and bounded (one write in flight, superseded frames
replaced, strictly monotonic sequence); EOF, backpressure, or a stale frame
deadline fences the child before it could serve past the manager's own lease.
Old children therefore self-fence on epoch loss even if the old manager
process is gone.

### Manager restarts and handoff

A manager restart is an epoch handoff, not a recovery. The new process claims
a fresh epoch (waiting out the previous claim's database TTL if it was not
released), demand-starts fresh children that cold-replay from the remote
journal, and never adopts a predecessor's process, listener, or token. Existing
mount leases fail closed; an operator starts a new mount session against the
new epoch. Filesystem state survives in the journal. Child teardown is always ordered: the durable
access-lease fence commits first, then the process terminates, then the
runtime row ends — on supersession the runtime rows are deliberately left for
the successor's begin to settle.

The router's one-byte rejection ack tells a mount its token is dead. The mount
surfaces that terminal condition and never re-resolves or reacquires behind the
operator's back. See docs/failure-modes.md "Manager Restart (Session Token
Rejection)".

### Configuration

```bash
PORTABLEFS_AUTHORITY_MANAGER_TOKEN=<manager-api-token>
PORTABLEFS_MANAGER_CONTROL_DATABASE_URL=postgres://portablefs_manager@db.internal/pfm
PORTABLEFS_MANAGED_VCS_BIN=/usr/local/bin/vcs
PORTABLEFS_MANAGED_VCS_JOURNAL_DSN=postgres://portablefs_authority@db.internal/journal
PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON='{"v":1,"expectedSystemIdentifier":"7301...","expectedDatabase":"journal","minSynchronousCommit":"remote_apply","minSyncStandbys":1,"standbyFailureDomains":{"standby-a":"zone-a"},"minDistinctFailureDomains":1}'
PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET=<64 hex chars>
PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR=0.0.0.0:2050
PORTABLEFS_AUTHORITY_ROUTER_URL=portablefs-vcs.example.com:2050
PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PATH=/etc/portablefs/router.crt
PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PATH=/etc/portablefs/router.key
PORTABLEFS_VOLUME_API_URL=https://volume-api.example.com
```

Required: the control database URL (there is no file fallback — without it
startup fails with `AUTHORITY_CONTROL_STORE_REQUIRED`), the VCS binary, the
journal DSN, the versioned structured HA policy JSON, the access-token root
secret, the router URL/listen address (with router TLS unless
`PORTABLEFS_AUTHORITY_ROUTER_ALLOW_PLAINTEXT_PRODUCTION=1` is set behind an
authenticated private tunnel), and the volume-api URL. There is deliberately
NO static child volume-api credential: setting `PORTABLEFS_VOLUME_API_TOKEN`
(or `VOLUME_API_TOKEN`) is a startup error — children authenticate with
manager-minted runtime read credentials (below).

The TLS requirement is unconditional (never keyed to `NODE_ENV`); an unset or
nonstandard Node environment can never weaken a production authority router.

Optional: `PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE=transaction` when the
journal DSN reaches a transaction-mode pooler (PgBouncer/pgcat) — the manager
passes it to every child as `VCS_JOURNAL_POOLER_MODE`, whose connections then
omit the session timeout startup parameters a pooler cannot preserve and rely
on the database defaults migration 016_pooler_timeouts installs. Also
optional: `PORTABLEFS_MANAGER_CLAIM_TTL_MS` (default 30000),
`PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS` (default 30000),
`PORTABLEFS_MANAGED_VCS_PROCESS_GRACE_MS` (SIGTERM to SIGKILL, default 5000),
`PORTABLEFS_MANAGED_VCS_LEASE_TTL`, `PORTABLEFS_ACCESS_LEASE_DEFAULT_TTL_MS`,
`PORTABLEFS_ACCESS_LEASE_MAX_TTL_MS`, and
`PORTABLEFS_AUTHORITY_PROVIDER_NAME`. The capacity guardrail variables
(idle eviction grace, resident cap, concurrent-start bound) are described in
[Capacity guardrails](#capacity-guardrails-idle-eviction-resident-cap-start-gate),
and the optional per-tenant budgets
(`PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT`,
`PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT`) in
[Per-tenant fairness caps](#per-tenant-fairness-caps).

`PORTABLEFS_MANAGED_VCS_EXTRA_ENV_JSON` may pass extra child tuning variables
through an exact allowlist — `VCS_CACHE_RAM_MB`, `VCS_PREFETCH`, and
`VCS_DIRTY_RSS_MAX_MB` only. Any other key is a startup error: identity,
scope, credentials, journal wiring, and durability topology are
manager-owned and can never be injected.

### Capacity guardrails (idle eviction, resident cap, start gate)

Every resident child holds up to 4 Postgres journal connections for as long
as it runs, and one cold start (journal claim, durability probes, cold
replay) opens those connections before the child is even ready. Three
always-on guardrails keep the journal database's connection ceiling honest.
The failure shape they close is on record: 62 idle per-branch children
accumulated against a 100-connection Postgres ceiling and caused live
connection rejections, because idle eviction used to default to disabled.

| Variable | Default | Semantics |
| --- | --- | --- |
| `PORTABLEFS_MANAGED_VCS_IDLE_EVICTION_GRACE_MS` | `900000` (15 minutes) | Zero-active-lease grace before an idle child is torn down (durable access fence first, then the process, then the runtime row). Always on: a positive integer re-tunes the grace; `off`, `0`, and negative values refuse startup — idle eviction can never be disabled in production. |
| `PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES` | `100` | Cap on resident children. When serving a request would start a NEW child past the cap, the request refuses with 503 `AUTHORITY_AT_CAPACITY` plus a `Retry-After` header (15 seconds). Running authorities and existing children are never affected — the cap gates new spawns only, and idle eviction is what frees capacity. Budget up to 4 journal connections per resident child when raising it. |
| `PORTABLEFS_MANAGED_VCS_MAX_CONCURRENT_STARTS` | `4` | Global bound on concurrent child cold starts (not resident children). Excess starts queue FIFO for at most the ready-timeout window (`PORTABLEFS_MANAGED_VCS_READY_TIMEOUT_MS`, default 30000 ms); a start still queued at the deadline refuses with 503 `AUTHORITY_START_QUEUE_TIMEOUT` plus `Retry-After`, without having spawned anything. Requests for already-running authorities never wait on this gate. |

All refusal codes are machine-readable and retryable: mount clients should
back off for the `Retry-After` interval instead of hammering. Malformed
values for any of the three variables (zero, negative, non-integer, `off`)
are startup errors, never silent fallbacks to the defaults.

### Per-tenant fairness caps

The capacity guardrails above protect the SERVICE; two optional per-tenant
budgets additionally protect tenants from each other on multi-tenant
deployments. Both default to unset — no additional restriction, zero behavior
change for single-tenant self-hosts — and both refuse with **429** (not 503)
plus `Retry-After` when a tenant is over budget, because the service is
healthy and other tenants proceed: operators and clients can tell service
pressure (`AUTHORITY_AT_CAPACITY`, `AUTHORITY_START_QUEUE_TIMEOUT`, 503) from
tenant pressure at a glance.

| Variable | Default | Semantics |
| --- | --- | --- |
| `PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES_PER_TENANT` | unset (off) | Cap on resident children per tenant (`teamId`). A NEW spawn that would exceed the tenant's budget refuses with 429 `TENANT_AT_CAPACITY` plus `Retry-After` (15 seconds); the tenant's running authorities and every other tenant are unaffected. Idle eviction and fenced stops free the budget naturally. The global cap is checked first: a registry at `PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES` refuses 503 `AUTHORITY_AT_CAPACITY` regardless of tenant budgets. |
| `PORTABLEFS_ACCESS_LEASES_MAX_PER_TENANT` | unset (off) | Cap on concurrently ACTIVE access leases per tenant, enforced at lease create before any durable transition. Over-budget creates refuse with 429 `TENANT_LEASE_LIMIT` plus `Retry-After`. Only live leases count: released, expired, and revoked leases free the budget the moment they settle. |

Like every guardrail knob, a set-and-malformed value (zero, negative,
non-integer) refuses startup instead of silently running uncapped. The lease
budget is enforced against the fenced singleton manager's live-lease
projection (every lease mutation flows through it); a create retry whose
original response was lost replays through the same check, so a tenant
sitting exactly at its cap can see a replayed create refused until a lease is
released.

### Metrics

`GET /metrics` on the manager control port (`PORT`, default 8788) renders a
Prometheus text exposition. The route is authenticated by the same manager
bearer token as every other control route — the exposition names capacity
pressure and per-tenant refusal counts, which is operator data. (The hosted
manager also serves its `/metrics` behind bearer auth; the OSS manager keeps
the stricter-or-equal posture and documents it here.) The implementation is
dependency-free — a bounded hand-rolled registry, no Prometheus client
library — with fixed metric names only: no labels anywhere, which is the
strongest possible cardinality bound. For Prometheus scrapers, set
`authorization: Bearer <PORTABLEFS_AUTHORITY_MANAGER_TOKEN>` via
`authorization.credentials`.

Manager-own series (refreshed at render time; `*_total` series are monotonic
process-local counters):

| Metric | Meaning |
| --- | --- |
| `pfm_manager_claimed`, `pfm_manager_superseded` | Singleton-claim state booleans (0/1). |
| `pfm_manager_claim_remaining_ms` | Remaining database-time lease window on the local monotonic clock. |
| `pfm_manager_consecutive_renew_failures` | Consecutive failed claim renewals (0 when healthy). |
| `pfm_manager_epoch` | The live manager epoch (rendered only while it fits a double exactly). |
| `pfm_manager_renewals_total`, `pfm_manager_renewal_failures_total` | Claim renewal outcomes. |
| `pfm_children_total`, `pfm_children_starting`, `pfm_children_cap` | Resident journal children, starts in flight, and the `PORTABLEFS_MANAGED_VCS_MAX_AUTHORITIES` cap — capacity pressure is `pfm_children_total` vs `pfm_children_cap`. |
| `pfm_child_start_gate_limit`, `pfm_child_start_gate_held`, `pfm_child_start_gate_waiters` | Cold-start semaphore: configured bound, permits held, FIFO queue depth. |
| `pfm_child_starts_total`, `pfm_child_start_failures_total`, `pfm_child_unexpected_exits_total`, `pfm_child_idle_evictions_total` | Child lifecycle totals. |
| `pfm_child_start_queue_timeouts_total` | `AUTHORITY_START_QUEUE_TIMEOUT` refusals. |
| `pfm_authority_at_capacity_refusals_total` | `AUTHORITY_AT_CAPACITY` refusals (503, service pressure). |
| `pfm_tenant_at_capacity_refusals_total` | `TENANT_AT_CAPACITY` refusals (429, per-tenant child budget). |
| `pfm_access_leases_active` | Live (non-terminal) access-lease projections. |
| `pfm_access_lease_creates_total`, `pfm_access_lease_renews_total` | Successful durable lease operations (replays excluded). |
| `pfm_tenant_lease_limit_refusals_total` | `TENANT_LEASE_LIMIT` refusals (429, per-tenant lease budget). |
| `pfm_router_open_tunnels` | Live lease-scoped data-plane tunnels. |
| `pfm_child_scrape_targets`, `pfm_child_scrape_aggregated`, `pfm_child_scrape_malformed_total`, `pfm_child_scrape_refused_total`, `pfm_child_scrape_errors_total` | Child-scrape pipeline health (below). |

The same body carries the aggregated CHILD metrics as `pfm_child_<name>`
series (for example `pfm_child_vcs_dirty_block_bytes`, the fleet-wide
resident dirty-block bytes from the journal children's dirty-RSS accounting).
The manager is the only scraper of the children's loopback `/metrics`
listeners — each managed child self-binds `127.0.0.1:0` and reports the exact
address on its bootstrap pipe, and child listeners are never exposed off the
host. Aggregation is fail-closed through a CLOSED ALLOWLIST: every child
metric name is declared with an explicit aggregator (counters and additive
gauges sum; the `vcs_ready` boolean takes the minimum, so one unready child
reports 0; latency summaries sum `_count`/`_sum` and DROP precomputed
quantiles — no fake fleet percentile is ever derived). Unknown names, unknown
labels, HELP/TYPE lines, non-finite values, or oversized bodies mark that
child's whole scrape malformed and drop its entire contribution — one
misbehaving child can never pollute the aggregate — visible as
`pfm_child_scrape_malformed_total`. Scrapes are bounded (256 KiB per child,
per-child and overall deadlines, loopback-literal targets only) and cached
for one second with single-flight collection. There are no per-child,
per-volume, or per-branch labels: children are counted and summed, never
named.

The metric NAMES follow the hosted manager's established `pfm_*` scheme
byte-for-byte (`pfm_manager_*`, `pfm_children_*`, `pfm_child_*`) so existing
ecosystem dashboards apply unchanged; names are evolvable-with-care per
[COMPATIBILITY.md](../COMPATIBILITY.md).

### Readiness

`/readyz` answers ready only when all of the following hold, and fails closed
otherwise: the data-plane router is listening; the manager holds the live
epoch claim inside its database-derived local monotonic deadline (claimed, not
superseded, not shut down); the production lease service is healthy (not
epoch-superseded); and a bounded control-store health probe succeeds.
Readiness going false stops admission — mutations refuse rather than guess.

## Access Leases

Production mode serves the canonical access-lease API. An access lease is the
external credential a consumer (control-plane worker, sandbox, device) holds
against the data-plane router for one `volumeId + branch` authority. It is
explicitly not the internal filesystem session: losing a lease token never
loses filesystem state — the caller creates a fresh lease and reconnects. The
wire contract (route names, shapes, `ACCESS_LEASE_*` error codes) is shared
with hosted PortableFS stacks, so a consumer built against one works against
the other.

All six routes are `POST`, authenticated by the manager bearer token, and
report failures as `{ "error": { "code": "ACCESS_LEASE_...", "message": "..." } }`:

| Route | Purpose |
| --- | --- |
| `/v1/access-leases/create` | Ensure the authority and mint a lease. Returns `{ authority, lease, accessToken, serverTimeMs }`; `authority` carries `authorityUrl`, `host`, `port`, `authorityInstanceId`, and `provider`, with the access token as the mount credential. |
| `/v1/access-leases/inspect` | Authenticate the exact current token and return the lease. Read-only; changes nothing. |
| `/v1/access-leases/renew` | Extend the lease under a `expectedControlSeq` CAS; `rotateToken: true` also rotates the token. |
| `/v1/access-leases/release` | Consumer-initiated end. Returns `{ lease, receipt, serverTimeMs }`. |
| `/v1/access-leases/revoke` | Administrative end of one lease. Manager bearer only; no access token required. |
| `/v1/access-leases/revoke-owner` | Administrative batch end by `consumerId`, scoped by at least `teamId` or `volumeId`, optionally narrowed by `branch`. |

Semantics:

- `controlSeq` advances by exactly one per accepted control mutation;
  `tokenGeneration` increments only on explicit rotation. Both cross the wire
  as canonical positive decimal strings, never JSON numbers.
- Every create/renew/release carries a caller-chosen `operationId`. Retrying
  the same operation replays the recorded response byte-identically — a create
  replay returns the identical `accessToken` string — while reusing an
  operationId with different content answers 409
  `ACCESS_LEASE_OPERATION_CONFLICT`. Receipts are retained in a bounded window:
  an operation older than the window answers 410
  `ACCESS_LEASE_RECEIPT_EVICTED` and is never silently re-executed.
- `renew` requires the `expectedControlSeq` the caller observed before the
  operation. A stale value on a fresh operation answers 409; a retained receipt
  replay wins first, stale CAS and all.
- Rotation mints the new token only in the rotating renew's response. The
  superseded token stops resolving on the data plane immediately, live tunnels
  admitted under older generations are closed in both directions, and the old
  token thereafter authenticates exactly one thing: the byte-identical replay
  of the rotation that superseded it.
- `release`, `revoke`, `revoke-owner`, expiry (a single unref'd sweep timer,
  rescheduled on create/renew), and authority retirement all end leases and
  immediately close their live router tunnels. A renew or release against an
  ended lease answers the terminal code (`ACCESS_LEASE_RELEASED`,
  `ACCESS_LEASE_EXPIRED`, `ACCESS_LEASE_REVOKED`) and never mints a
  replacement.
- TTL grants clamp to a 1 second floor and the
  `PORTABLEFS_ACCESS_LEASE_MAX_TTL_MS` ceiling (default 24 hours); requests
  without `ttlMs` use `PORTABLEFS_ACCESS_LEASE_DEFAULT_TTL_MS` (default 5
  minutes).

Tokens are deterministic HMACs derived from
`PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET` (32 bytes as 64 hex chars or base64,
always required in production mode) plus the manager epoch and token
generation. Tokens are never stored anywhere; verification and lost-response
replays recompute them from the recorded claims, and every predecessor
epoch's tokens die with its epoch.

Lease state lives in the `pfm` control database: every
create/renew/release/revoke is one receipted control-store transaction, and
the manager's in-memory map is only a synchronous router projection of those
durable facts. A control-store outage answers lease routes with 503
`ACCESS_LEASE_STORE_UNAVAILABLE` (nothing changed; the identical retry
succeeds) rather than guessing lease state.

The legacy session-minting routes (`/v1/mount-sessions`,
`/v1/volumes/:id/mount-sessions`, `/v1/authorities/session`) are retired and
answer 410 tombstones ([Retired session routes](#retired-session-routes)).

## Security Notes

The manager token protects the control plane. Access-lease tokens protect the
public data plane and are scoped in the router to one authority instance. The
router does not forward that public token to VCS; it authenticates to the loopback VCS
with a separate internal backend token.

Production deployments should expose only the custom FUSE protocol router to sandboxes
through a reachable, authenticated TLS address. NFS remains compatibility-only and
should not be the production coherence path.
