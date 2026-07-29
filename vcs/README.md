# vcs — Volume Cache Service (live mount)

The VCS serves a PortableFS volume as the live filesystem authority over one data
plane: fsproto v6, the custom protocol spoken by the product FUSE/FSKit mounts.
Every mutation rides a journaled exact session; durability and coordination are
the fenced PostgreSQL journal's.

Built and verified so far:

- **One mount path** — the product mount (`portablefs mount`: FSKit on macOS,
  FUSE on Linux) over `internal/fsproto` (protocol v5). The bench harness mounts
  the same protocol via `bench/cmd/benchmount`.
- **Local-cache reads + push invalidation (FUSE)** — the FUSE client caches file data in
  the kernel page cache (hot reads are **local-speed, ~GB/s**), while the VCS — the single
  authority that sees every write — pushes **invalidations** so other clients evict exactly
  the changed files. So reads are fast *and* coherent (live cross-machine read-after-write),
  without stale cache reads. Attributes stay fresh (so same-client read-after-write is exact)
  and the client skips invalidating its own in-flight writes (no mmap races). Connections
  re-dial, so a mount rides through a VCS restart/failover.
- **Read path** — lazily fetch + cache file content (per-chunk for large files).
- **Writable mount (write-back)** — a mutable working tree whose acknowledged mutations
  are durable in the fenced journal before the client hears "done". Client mounts buffer
  writes in a local session WAL (crash-replayable) and flush them as journaled batches.
- **Block-level I/O** — file content is addressed in 4 MiB blocks: a write to a backed
  file fetches only the blocks it touches (never the whole file), resident memory is
  bounded by dirty blocks rather than file size, and holes read as zeros (sparse files).
- **POSIX metadata + coordination** — `chmod`/`chtimes`/`chown` persist; ownership
  (uid/gid) flows through the working tree → journal → manifest → tree hash
  (Go↔TS byte-identical, omitted when root so existing volumes are unchanged) and is
  reported on `stat`. `rename` enforces POSIX semantics — it never silently clobbers a
  non-empty directory or crosses a type boundary (`ENOTEMPTY`/`EISDIR`/`ENOTDIR`), and
  refuses to move a directory into its own subtree. `fsync` is acknowledged (writes are
  already durable on ack). Checkouts, locks, and open pins are **journaled coordination**:
  PFC2 control rows in the same total order as tree mutations. Writes retry transparently
  across a reconnect (exact sessions dedupe), so a mount rides through failover.
- **Single authority + multi-client coherence** — a VCS holds one fenced, exclusive
  lease for the volume (renewed for its lifetime, released on shutdown), so the backend
  rejects any second VCS (no split-brain). Multiple clients mounting one VCS share the
  working tree and see each other's writes (read-after-write across mounts).
- **The remote journal** — durability is a fenced PostgreSQL journal (see
  [../docs/journal.md](../docs/journal.md)): every acknowledged write commits to the
  journal before the client hears "done", the claim/append/suspend transactions are
  fenced by the live manager/runtime binding, and the process itself is a disposable
  cache — kill it at any moment and a replacement claims the journal, cold-replays the
  immutable base plus the journal suffix, and continues exactly where things left off.
  There is no local WAL, no checkpoint loop, and no secondary serving mode.
- **Data-plane fencing** — a primary that loses its lease, its manager lease pipe, or its
  journal fencing **stops serving immediately** (`/readyz` flips to 503), so a deposed
  primary never serves stale reads. Recovery is a fresh claim + cold replay by a
  replacement child, bounded by the lease TTL (default 30s).
- **Read-path integrity** — every blob/chunk is verified against its content address on read,
  in both the bucket fetch and the persistent disk cache (which also fsyncs before rename). Bit-rot
  or a torn cache file is caught and re-fetched, never served as silently-wrong file content.

Still to come for full managed-service polish: broader cross-client POSIX lock
coverage and packaged WireGuard/CSI/FSKit deployment surfaces.

## Layout

```
cmd/vcs               the managed authority child binary (fenced journal required)
cmd/portablefs        the product CLI: login, attach, mount (FSKit/FUSE), doctor
cmd/portablefsd       the mount daemon (frontend + control sockets)
bench/cmd/benchmount  bench-only raw FUSE mount of a plain fsproto authority
bench/cmd/pfsbench    the benchmark harness (in-process managed authority)
bench/cmd/pfstorture  the crash/fault torture harness
internal/backend      volume-api HTTP client (manifest, blobs, attach/commit, base provenance, history objects)
internal/content      shared lazy, cached blob/chunk reader + byte-bounded cache
internal/workfs       read-write working tree (block-level I/O over the managed journal store)
internal/wal          crash-safe local log: client session WALs + the bench/test entry-log backend
internal/pfj3         the journal entry codec + the file-backed test/bench entry log
internal/pfc2         the deterministic control reducer (sessions, locks, checkouts, pins)
internal/remotejournal the managed-production journal client (fenced PostgreSQL, claim/append/suspend)
internal/managerlease manager pipe frames: lease-frame guard (fd 3) + one-shot bootstrap frame (fd 4)
internal/lifecycle    fenced idempotent admin operations + the graceful eviction drain
internal/hapolicy     the structured journal HA policy (canonical hash shared with the TS manager)
internal/secure       TLS configs + data-plane/admin tokens (opt-in via env)
internal/metrics      dependency-free counters/gauges/latency-histograms registry
internal/fsproto      the v5 protocol: exact sessions, journaled coordination, push invalidations
internal/treehash     Go port of the canonical tree hash (byte-identical to TS)
internal/authority    held exclusive lease (single writer) + commit + failover acquire
```

## Run

`cmd/vcs` is the managed authority child: the authority manager spawns one
disposable child per active volume branch. It requires the fenced journal —
there is no local-WAL or read-only serving arm.

### Managed journal child (production)

`VCS_PRODUCTION=1` is managed production and fails closed on anything else: it requires
`VCS_JOURNAL_DSN` (the restricted `portablefs_authority` login), `VCS_TENANT_ID`,
`VCS_AUTHORITY_INSTANCE_ID`, the exact manager/runtime binding (`VCS_MANAGER_EPOCH`,
`VCS_MANAGER_RUNTIME_ID`, `VCS_AUTHORITY_RUNTIME_SEQ`, `VCS_AUTHORITY_RUNTIME_ID`,
`VCS_AUTHORITY_RUNTIME_CAPABILITY`), the structured `VCS_JOURNAL_HA_POLICY_JSON` the child
verifies against `pfj.durability_facts()`, per-instance `VCS_AUTH_TOKEN` and
`VCS_ADMIN_TOKEN` (authenticated even on loopback), and both inherited manager pipes. It
rejects removed local-durability settings by name (`VCS_JOURNAL_DSN` absent, or
`VCS_FS_ADDR`/`VCS_METRICS_ADDR` set — the child binds its own listeners).

**The FD/bootstrap contract with the manager:**

- `VCS_HEARTBEAT_FD=3` — bounded (≤ 4 KiB) newline-delimited JSON v1 lease frames,
  manager → child, carrying the exact identity plus the manager claim's database-time
  facts. Every deadline extension is grounded in a capability-bound
  `pfj.authority_lease_facts` read; pipe EOF, a malformed/foreign/stale frame, or the
  armed deadline passing fences the child before the manager's own database lease can
  expire. Serving never begins before the first grounded frame.
- `VCS_BOOTSTRAP_FD=4` — the child binds fsproto and metrics on `127.0.0.1:0` ITSELF,
  then emits exactly ONE bounded JSON frame reporting the exact bound addresses, its full
  identity (instance, volume/branch, manager epoch, runtime seq/id), the claimed journal
  generation, the protocol version, and the canonical HA-policy hash — then the
  descriptor closes. The manager never adopts a listener it did not receive through this
  frame, and `/readyz` re-verifies the same identity.

**Readiness ordering:** HA policy verified against `pfj.durability_facts()` → journal
claim binds under the exact manager/runtime binding → cold replay (immutable base +
journal suffix) completes → the first lease deadline grounds in capability-bound
`pfj.authority_lease_facts` (a lease frame alone never authorizes serving) → listeners
bound → bootstrap frame emitted → ready.

**Teardown:** ordinary eviction (SIGTERM or the fenced `/v1/ops/evict` admin call) seals
admission, drains admitted appends through their durable acknowledgement, executes the
receipted exact journal suspension (immutable per-runtime operation id, bounded by
`VCS_SUSPEND_DEADLINE_MS`, default 30s), and exits. An unresolved suspension exits
non-zero with admission sealed and the writer lease unreleased — database-time expiry
fences it, and the immutable suspend operation replays its receipt on the next attempt.
Recovery (claim + cold replay) is canceled by SIGTERM, definitive lease loss, or a
manager pipe fence.

`VCS_LEASE_TTL` (seconds) bounds how long a crashed authority's lease fences its
successor; lower it for faster takeover. TLS knobs (`VCS_TLS_CERT`/`VCS_TLS_KEY`,
client `VCS_TLS_CA`, mTLS `VCS_TLS_CLIENT_CA`) apply to network-reachable custom-protocol
listeners; the managed child serves loopback only.

## Mount

The product mount is the CLI: `portablefs mount <volume>` (FSKit on macOS, FUSE
on Linux — see the top-level docs). It resolves the volume's endpoint through
the manager's access-lease API and speaks fsproto v6.

For benchmarking against a plain authority address (no control plane), the
bench harness's raw FUSE mount is `bench/cmd/benchmount`:

```bash
go build -C vcs -o benchmount-bin ./bench/cmd/benchmount
./benchmount-bin -addr <authority-host>:2050 -mount /mnt/bench [-writeback]
```

## Tests

```bash
go -C vcs test ./...          # unit + protocol e2e (no infra, no sudo)
go -C vcs test -race ./...    # race-clean

# real backend (manifest + bucket blobs + commit round-trip), gated:
VOLUME_API_URL=... VOLUME_API_TOKEN=... [VCS_E2E_VOLUME_ID=vol_... VCS_E2E_BIG_SHA=...] go -C vcs test ./...
```

The suite drives fsproto v6 end-to-end in-process (exact sessions, journaled
coordination, write-back flushes, failover replay), plus multi-client coherence
and the managed parity suite. The tree hash is cross-checked against the TS
implementation (`internal/treehash` golden + `.volume-cache/treehash-crosscheck.mjs`).

The **FUSE path** is verified end-to-end on Linux with a real kernel mount
(privileged container, `/dev/fuse`): basic POSIX ops, a 10 MiB block-level file,
live coherence across two mounts, and a **cross-machine `git clone` + commit through the
mount** (`git fsck` clean) that persists to the backend and reads back identically from a
fresh VCS. Stable path-derived inodes (`st_ino`==`d_ino`) make `getcwd`/`git` work. The
**cache + invalidation** layer is verified too: an update on mount A is seen on mount B
(invalidation evicts the stale page cache), and reads run at local-cache speed.

**Performance** (FUSE mount, Linux container, data resident in the VCS):

| op | throughput |
| --- | --- |
| warm read (page cache) | ~3–6 GB/s |
| cold read from the VCS | ~4 GB/s |
| write | ~1.3 GB/s |
| stat (single process) | ~µs/file |

Levers: 1 MiB reads + readahead over a 16-connection pool (vs the kernel's 128 KiB default →
~8× fewer round-trips), parallel chunk fetch (`content.Whole`), and **adaptive attribute
caching** — a file this client just wrote stays fresh (correct read-after-write, so `git`
works) while stable files cache their attrs (no getattr round-trip; matters over WAN). A
true cold read from the *bucket* is network-bound.

**Local disk-cache tier** — set `VCS_CACHE_DIR` + `VCS_CACHE_DISK_MB` (dev/bench harnesses)
and the read cache gains a persistent NVMe tier (RAM → disk → bucket), so the working set
can far exceed RAM and a restart starts warm. Verified end-to-end: a cold read from the
bucket populates the local disk cache.

**Encrypted transport** — set `VCS_TLS_CERT`/`VCS_TLS_KEY` (server) and `VCS_TLS_CA` (client,
or `VCS_TLS_INSECURE=1`) to run the custom protocol over TLS 1.3 (mutual TLS with
`VCS_TLS_CLIENT_CA`).

**Data-plane authentication** — set `VCS_AUTH_TOKEN` to require a constant-time token handshake
before the custom FUSE protocol will serve any op (the FUSE client presents the same token).
**Fail-closed:** binding a data port to a non-loopback address with neither TLS nor a token
configured is a fatal startup error — a network-reachable data port must be authenticated or
encrypted, not open. The managed child is authenticated even on loopback, and its lifecycle
admin API (`/v1/ops/*` on the metrics listener) requires the separate `VCS_ADMIN_TOKEN` —
a mount credential can never evict the volume, and the admin credential can never mount.

**Encryption at rest** — set `VCS_ENCRYPTION_KEY` (64 hex chars = a 32-byte key) and the
client session WAL and the NVMe blob cache are sealed with **AES-256-GCM** on disk: a stolen
disk reveals neither unflushed write payloads (session WAL) nor cached file content.
Authenticated encryption also catches silent bit-rot, and a wrong key fails loudly rather
than dropping records. Opt-in — unset, the on-disk format is byte-for-byte unchanged. The
managed child keeps no local files; its durability is the journal database's.
Bucket objects use server-side encryption when `VOLUME_S3_SSE` (e.g. `AES256`) is set;
the digest is over the plaintext, so dedup is unaffected.

**Prefetch / cache warming** — `VCS_PREFETCH=1` warms the cache with the volume's blobs in the
background on startup (deduped, parallel, bounded by cache capacity), so reads are fast from
first touch.

**Observability** — the managed child binds its own metrics listener exposing `/stats`
(JSON), `/metrics` (Prometheus), `/healthz` (liveness), `/readyz` (readiness), and the
fenced lifecycle admin API (`/v1/ops/evict`; `VCS_ADMIN_TOKEN` bearer). Instrumented
end-to-end: cache hit-rate per tier, protocol op count + latency percentiles, bucket
fetch count/bytes/latency, mutations, and eviction drains. Verified live: e.g.
`fsproto_op_latency` p50/p90/p99 = 500µs/1ms/5ms.

**Readiness vs liveness** — `/healthz` is liveness (the process is up; restart only if it stops
answering); `/readyz` is readiness (this node is *serving* the volume). A managed child answers
`/readyz` with its exact identity — instance, scope, manager epoch, runtime binding, journal
generation, protocol version, HA-policy hash, and the actual bound listener addresses — so the
manager can validate the process answering the probe is the process it spawned. An orchestrator
routes traffic on readiness and replaces an authority the moment it stops being ready.

Failover is covered end-to-end by the managed parity suite (`internal/workfs`:
claim → sessions → mutations → cut → suspend → cold-replay-identical) and
`TestAcquireWhenFree*` (the takeover poll waits while busy, claims when free,
fails hard otherwise).
