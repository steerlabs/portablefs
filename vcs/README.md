# vcs — Volume Cache Service (live mount)

The VCS serves a PortableFS volume as the live filesystem authority. The production
data plane is the custom protocol used by the FUSE client; NFSv3 remains a compatibility
mount path for local and zero-install workflows.

Built and verified so far:

- **Two mount paths** — a **FUSE client over a custom protocol**
  (`cmd/mount` ↔ `internal/fsproto`) — the delegation-based path. The VCS serves both over
  the same working tree. The in-kernel **NFSv3** server is also available for zero-install
  compatibility, but the custom protocol is the production path.
- **Local-cache reads + push invalidation (FUSE)** — the FUSE client caches file data in
  the kernel page cache (hot reads are **local-speed, ~GB/s**), while the VCS — the single
  authority that sees every write — pushes **invalidations** so other clients evict exactly
  the changed files. So reads are fast *and* coherent (live cross-machine read-after-write),
  without stale cache reads. Attributes stay fresh (so same-client read-after-write is exact)
  and the client skips invalidating its own in-flight writes (no mmap races). Connections
  re-dial, so a mount rides through a VCS restart/failover.
- **Read path** — lazily fetch + cache file content (per-chunk for large files).
- **Writable mount (write-back)** — a mutable working tree journalled to a crash-safe
  **WAL** (every mutation fsync'd before ack, replayed on restart), with a periodic
  **checkpoint** that uploads dirty files as content-addressed blobs and commits a
  full manifest to the Volume API. Edit files through the mount; checkpoints persist them
  to the configured backend automatically.
- **Block-level I/O** — file content is addressed in 4 MiB blocks: a write to a backed
  file fetches only the blocks it touches (never the whole file), resident memory is
  bounded by dirty blocks rather than file size, and holes read as zeros (sparse files).
  Files ≥ 8 MiB **checkpoint as streamed 4 MiB chunks** (bounded memory, API-compatible
  chunk format) — verified persisting + reading back a 10 MiB file via a fresh VCS.
- **POSIX metadata + coordination** — `chmod`/`chtimes`/`chown` persist (over the custom
  protocol, via `billy.Change`); ownership (uid/gid) flows through the working tree → WAL →
  manifest → tree hash (Go↔TS byte-identical, omitted when root so existing volumes are
  unchanged) and is reported on `stat`. `rename` enforces POSIX semantics — it never silently
  clobbers a non-empty directory or crosses a type boundary (`ENOTEMPTY`/`EISDIR`/`ENOTDIR`),
  and refuses to move a directory into its own subtree. `fsync` is acknowledged (writes are
  already durable on ack). **Delegations** (`internal/delegation`) give delegation-based
  `checkout`/`checkin` exclusive write coordination over subtrees, exposed via
  `fsio checkout|checkin`. Writes retry transparently across a reconnect (idempotent ops), so
  a mount rides through failover.
- **Atomic checkpoints (no lost writes, dev file-WAL mode)** — a checkpoint commits an
  as-of-snapshot view, then compacts away only the WAL prefix it committed and rebinds only
  the files it committed (per-file mutation epochs). A write that races an in-flight
  checkpoint stays in the live tree and the WAL, so it survives — the durability guarantee
  holds even under concurrent writes + checkpoint. A managed journal child never
  checkpoints in-process: history materialization is the external HistoryCut service's job
  (see [../docs/history.md](../docs/history.md)).
- **Single authority + multi-client coherence** — a VCS holds one fenced, exclusive
  lease for the volume (renewed for its lifetime, released on shutdown), so the backend
  rejects any second VCS (no split-brain). Multiple clients mounting one VCS share the
  working tree and see each other's writes (read-after-write across mounts).
- **Managed production: the remote journal** — with `VCS_JOURNAL_DSN` set, durability is a
  fenced PostgreSQL journal (see [../docs/journal.md](../docs/journal.md)): every acknowledged
  write commits to the journal before the client hears "done", the claim/append/suspend
  transactions are fenced by the live manager/runtime binding, and the process itself is a
  disposable cache — kill it at any moment and a replacement claims the journal, cold-replays
  the immutable base plus the journal suffix, and continues exactly where things left off.
  There is no local WAL, no opstate file, no checkpoint loop, and no NFS in this mode.
- **Data-plane fencing** — a primary that loses its lease, its manager lease pipe, or its
  journal fencing **stops serving immediately** (`/readyz` flips to 503), so a deposed
  primary never serves stale reads. Recovery is a fresh claim + cold replay by a
  replacement child, bounded by the lease TTL (default 30s).
- **Read-path integrity** — every blob/chunk is verified against its content address on read,
  in both the bucket fetch and the persistent disk cache (which also fsyncs before rename). Bit-rot
  or a torn cache file is caught and re-fetched, never served as silently-wrong file content.

Still to come for full managed-service polish: NFSv4 compatibility, broader cross-client
POSIX lock coverage, and packaged WireGuard/CSI/FSKit deployment surfaces.

## Layout

```
cmd/vcs               the server binary (read-only | writable dev primary | managed journal child)
cmd/mount             the FUSE client: mounts a volume via the custom protocol
cmd/fsio              custom-protocol read/write of one file (scripting/smoke tests)
cmd/nfsio             userspace NFSv3 read/write of one file (scripting, no sudo)
cmd/treehashcheck     cross-check the Go tree hash vs the TS implementation
internal/backend      volume-api HTTP client (manifest, blobs, attach/commit, base provenance, history objects)
internal/content      shared lazy, cached blob/chunk reader + byte-bounded cache
internal/volfs        read-only billy.Filesystem over a manifest
internal/workfs       read-write working tree (block-level I/O, file-WAL and managed journal stores)
internal/wal          crash-safe local write-ahead log (dev/self-host durability + DurableLog contract)
internal/remotejournal the managed-production journal client (fenced PostgreSQL, claim/append/suspend)
internal/managerlease manager pipe frames: lease-frame guard (fd 3) + one-shot bootstrap frame (fd 4)
internal/lifecycle    fenced idempotent admin operations + the graceful eviction drain
internal/hapolicy     the structured journal HA policy (canonical hash shared with the TS manager)
internal/secure       TLS configs + data-plane/admin tokens (opt-in via env)
internal/metrics      dependency-free counters/gauges/latency-histograms registry
internal/fsproto      custom FS protocol: serves a billy.Filesystem to FUSE clients (+ invalidations, delegations)
internal/delegation   checkout/checkin exclusive write coordination over subtrees
internal/treehash     Go port of the canonical tree hash (byte-identical to TS)
internal/authority    held exclusive lease (single writer) + commit + failover acquire
internal/checkpoint   dev-mode working tree -> blob upload + manifest commit (never runs managed)
internal/server       wires a filesystem into go-nfs; clean ctx shutdown
```

## Run

The binary serves one of two writable modes plus read-only serving:

- **Dev file-WAL mode** (no `VCS_JOURNAL_DSN`): a single writable node journalling to a
  local crash-safe WAL, checkpointing to the backend every `VCS_CHECKPOINT_INTERVAL`
  seconds, serving NFSv3 and (optionally) the custom protocol. This is the development,
  self-host single-node, and fault-test shape.
- **Managed journal child** (`VCS_JOURNAL_DSN` set): the production shape. Durability is
  the fenced remote PostgreSQL journal ([../docs/journal.md](../docs/journal.md)); the
  authority manager spawns one disposable child per active volume branch.

```bash
go build -C vcs -o ../vcs-bin ./cmd/vcs

# read-only:
VOLUME_API_URL=... VOLUME_API_TOKEN=<token> VCS_VOLUME_ID=vol_... VCS_ADDR=127.0.0.1:2049 ./vcs-bin

# writable dev (mount, edit, auto-checkpoint every 5s):
VCS_WRITABLE=1 VOLUME_API_URL=... VOLUME_API_TOKEN=<token> VCS_VOLUME_ID=vol_... VCS_ADDR=127.0.0.1:2049 ./vcs-bin
```

### Managed journal child (production)

`VCS_PRODUCTION=1` is managed production and fails closed on anything else: it requires
`VCS_JOURNAL_DSN` (the restricted `portablefs_authority` login), `VCS_TENANT_ID`,
`VCS_AUTHORITY_INSTANCE_ID`, the exact manager/runtime binding (`VCS_MANAGER_EPOCH`,
`VCS_MANAGER_RUNTIME_ID`, `VCS_AUTHORITY_RUNTIME_SEQ`, `VCS_AUTHORITY_RUNTIME_ID`,
`VCS_AUTHORITY_RUNTIME_CAPABILITY`), the structured `VCS_JOURNAL_HA_POLICY_JSON` the child
verifies against `pfj.durability_facts()`, per-instance `VCS_AUTH_TOKEN` and
`VCS_ADMIN_TOKEN` (authenticated even on loopback), and both inherited manager pipes. It
rejects every local-durability setting by name: `VCS_WAL`, `VCS_CACHE_DIR`, `VCS_ADDR`
(no NFS), `VCS_FS_ADDR`/`VCS_METRICS_ADDR` (the child binds its own listeners), and
`VCS_ALLOW_LEGACY_WRITES`.

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
listeners in dev/self-host; the managed child serves loopback only.

## Mount (needs sudo — kernel NFS client)

macOS:
```bash
mkdir -p /tmp/vcsmnt
sudo mount -o vers=3,tcp,port=2049,mountport=2049,noacl,noresvport 127.0.0.1:/ /tmp/vcsmnt
# read, and (writable mode) write — edits checkpoint to the backend automatically
echo "edited in the mount" > /tmp/vcsmnt/notes.txt
sudo umount /tmp/vcsmnt
```

Linux: `-t nfs -o vers=3,tcp,port=2049,mountport=2049,nolock`.

## Mount via FUSE (custom protocol — live coherence)

Start the VCS with the custom protocol enabled, then run the low-level FUSE
client (`cmd/mount`), a Linux developer tool that needs `fuse`/`fusermount3`.
It can run on a different machine from the VCS. This is the raw protocol
harness; the product mount path is `portablefs mount` (FSKit on macOS, FUSE on
Linux — see the top-level docs).

```bash
# VCS: serve NFS + the custom protocol
VCS_WRITABLE=1 VCS_FS_ADDR=0.0.0.0:2050 VOLUME_API_URL=... VOLUME_API_TOKEN=<token> VCS_VOLUME_ID=vol_... ./vcs-bin

# FUSE client (on the agent's machine):
go build -C vcs -o ../mount-bin ./cmd/mount
mkdir -p /mnt/vol
./mount-bin -addr <vcs-host>:2050 -mount /mnt/vol
# /mnt/vol is now the live volume; reads reach the authority (no stale cache).
```

For a production, network-reachable VCS, the mount client should present the same data-plane
token and verify the VCS certificate:

```bash
VCS_TLS_CA=/etc/portablefs/ca.crt \
VCS_AUTH_TOKEN=<data-plane-token> \
./mount-bin -addr <vcs-host>:2050 -mount /mnt/vol
```

## Tests

```bash
go -C vcs test ./...          # unit + NFS-protocol read/write e2e (no infra, no sudo)
go -C vcs test -race ./...    # race-clean

# real backend (manifest + bucket blobs + commit round-trip), gated:
VOLUME_API_URL=... VOLUME_API_TOKEN=... [VCS_E2E_VOLUME_ID=vol_... VCS_E2E_BIG_SHA=...] go -C vcs test ./...
```

The suite drives the real NFSv3 wire protocol via a userspace client (no root):
read (`TestE2EReadThroughNFSProtocol`), write (`TestE2EWriteThroughNFSProtocol`),
multi-client coherence (`TestMultiClientCoherence`), and a real-backend capstone
(`TestRealWritableMountE2E`: NFS write -> checkpoint -> commit -> durable). The tree
hash is cross-checked against the TS implementation (`internal/treehash` golden +
`.volume-cache/treehash-crosscheck.mjs`).

The **FUSE + custom-protocol path** is verified end-to-end on Linux with a real kernel
mount (privileged container, `/dev/fuse`): basic POSIX ops, a 10 MiB block-level file,
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
true cold read from the *bucket* is network-bound. `PORTABLEFS_CACHE` selects the mode.

**Local disk-cache tier** — set `VCS_CACHE_DIR` + `VCS_CACHE_DISK_MB` and the read cache gains
a persistent NVMe tier (RAM → disk → bucket), so the working set can far exceed RAM and a
restart starts warm. Verified end-to-end: a cold read from the bucket populates the local
disk cache.

**Encrypted transport** — set `VCS_TLS_CERT`/`VCS_TLS_KEY` (server) and `VCS_TLS_CA` (client,
or `VCS_TLS_INSECURE=1`) to run the custom protocol over TLS 1.3 (mutual TLS with
`VCS_TLS_CLIENT_CA`). Off by default (trusted LAN / WireGuard); the in-kernel NFS path stays
plaintext and is secured at the network layer.

**Data-plane authentication** — set `VCS_AUTH_TOKEN` to require a constant-time token handshake
before the custom FUSE protocol will serve any op (the FUSE client presents the same token).
**Fail-closed:** binding `VCS_FS_ADDR` to a non-loopback address with neither TLS nor a token
configured is a fatal startup error — a network-reachable data port must be authenticated or
encrypted, not open. The managed child is authenticated even on loopback, and its lifecycle
admin API (`/v1/ops/*` on the metrics listener) requires the separate `VCS_ADMIN_TOKEN` —
a mount credential can never evict the volume, and the admin credential can never mount.

**Encryption at rest** — set `VCS_ENCRYPTION_KEY` (64 hex chars = a 32-byte key) and the dev
file WAL and the NVMe blob cache are sealed with **AES-256-GCM** on disk: a stolen disk reveals
neither uncommitted write payloads (WAL) nor cached file content. Authenticated encryption also
catches silent bit-rot, and a wrong key fails loudly rather than dropping records. Opt-in —
unset, the on-disk format is byte-for-byte unchanged. The managed child keeps no local files;
its durability is the journal database's.
Bucket objects use server-side encryption when `VOLUME_RAILWAY_BUCKET_SSE` (e.g. `AES256`) is set;
the digest is over the plaintext, so dedup is unaffected.

**Prefetch / cache warming** — `VCS_PREFETCH=1` warms the cache with the volume's blobs in the
background on startup (deduped, parallel, bounded by cache capacity), so reads are fast from
first touch.

**Observability** — set `VCS_METRICS_ADDR` (dev; the managed child binds its own metrics
listener) to expose `/stats` (JSON), `/metrics` (Prometheus), `/healthz` (liveness),
`/readyz` (readiness), and the fenced lifecycle admin API (`/v1/ops/checkpoint`,
`/v1/ops/evict`, `/v1/ops/quiesce`, `/v1/ops/release-lease`; `VCS_ADMIN_TOKEN` bearer).
Instrumented end-to-end: cache hit-rate per tier, protocol op count + latency percentiles,
bucket fetch count/bytes/latency, checkpoint count/bytes/duration, mutations, and eviction
drains. Verified live: e.g. `fsproto_op_latency` p50/p90/p99 = 500µs/1ms/5ms.

**Readiness vs liveness** — `/healthz` is liveness (the process is up; restart only if it stops
answering); `/readyz` is readiness (this node is *serving* the volume). A managed child answers
`/readyz` with its exact identity — instance, scope, manager epoch, runtime binding, journal
generation, protocol version, HA-policy hash, and the actual bound listener addresses — so the
manager can validate the process answering the probe is the process it spawned. An orchestrator
routes traffic on readiness and replaces an authority the moment it stops being ready.

Failover is covered end-to-end by the managed parity suite (`internal/workfs`:
claim → sessions → mutations → cut → suspend → cold-replay-identical), the journal
attach/reconcile suites in `internal/wal`, and `TestAcquireWhenFree*` (the takeover
poll waits while busy, claims when free, fails hard otherwise).
