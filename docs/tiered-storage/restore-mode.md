# Tiered storage: restore mode, archiver, and hydrator

Status: **Phase 0 contract, revision 3 — incorporates both adversarial
reviews; frozen before implementation**

Restore mode is the serving state between wake and convergence: the volume's
namespace is fully materialized in XFS, content drains in from the sealed
archive, and reads of not-yet-hydrated chunks recall on demand. It is bounded
by four hard constraints of the current implementation:

1. The authority cannot reach the network: `PrivateNetwork=yes` +
   `RestrictAddressFamilies=AF_UNIX`
   (`deploy/systemd/portablefs-authority@.service:14,29`). All archive-store
   I/O lives in sibling per-volume processes; the authority speaks to its
   hydrator over one AF_UNIX socket in its bind-mounted namespace.
2. The server RPC path has two lanes and a connection-level guillotine: a
   request that waits longer than `WriteTimeout` (default 30 s) for a lane
   permit tears down the whole TLS connection
   (`authorityrpc/server.go:250-267`). Recall must never park a connection.
3. `EIO`/`EUCLEAN`/`ESHUTDOWN`/`ENOTRECOVERABLE` fence the store and end the
   epoch (`volume_handler_linux.go:2145`). A hydration failure must never
   surface as one of them.
4. The authority is the only writer to the volume tree
   (`xfs-authority-architecture.md:135-137`). Hydrated bytes are therefore
   written by the authority itself; the hydrator fetches, verifies, and
   decompresses, but never touches XFS.

## Components

**Archiver** (`portablefs-archiver`): per-volume process, own systemd unit,
same service UID as the authority, network access (its own unit does NOT set
`PrivateNetwork`), archive-store *write* credentials from root-provisioned
cell configuration, no listener. Runs only while the volume is quiesced
(authority absent). Reads the volume tree read-only, builds pack + manifest
(pack-format.md), uploads, verifies every digest by read-back, reports the
seal through the helper observation. It is the "future backup controller
with its own narrow identity" that `hosted-control-plane.md:342-346`
reserves; it adds no file-copy semantics to the authority.

**Restorer / hydrator** (`portablefs-hydrator`): per-volume process, same
unit shape, archive-store *read* credentials. Two modes:

- `restore-namespace`: with the authority still absent, downloads and
  verifies the manifest, materializes the complete namespace (directories,
  files at full logical size — allocated as sparse, correct extents marked
  hole vs data pending hydration — symlinks, hardlink groups, modes,
  uid/gid, ns-times), fsyncs, and reports namespace-ready. This is
  provisioning-time writing, like the helper's own provisioning writes; the
  single-writer rule concerns a serving authority.
- `serve`: after the authority starts, listens on one AF_UNIX socket inside
  the volume's state namespace. The authority requests chunks; the hydrator
  fetches ranges, verifies the chunk digest, decompresses, and streams
  plaintext bytes back. The authority `pwrite`s them into XFS and marks the
  hydration map. During RESTORING the hydrator is a formal serving
  dependency: absent ⇒ the volume is RESTORE_BLOCKED, volume-wide.

Both are started/stopped by the helper via plan phases (`ARCHIVE`,
`RESTORE`); their unit templates are installed like the authority's and give
them the volume data dir (archiver: read-only; hydrator serve mode: no
data-dir access at all — it never touches XFS; hydrator namespace-restore
mode: a data-dir bind added by the helper's per-phase drop-in) plus network
and the root-provisioned credentials file.

Pinned launch configuration (helper-written, strict JSON ≤ 4 KiB, root
owned, group-readable by the service GID, atomic write):

- `ConfigRoot/<vol>/archiver.json`: `{"version":1,"volume_id","cell_id",
  "authority_epoch":N,"placement_sequence":N,"attempt":"<uuid>",
  "key_version","chunk_size_bytes":N}`.
- `ConfigRoot/<vol>/hydrator.json`: `{"version":1,"volume_id","cell_id",
  "sealed_epoch":N,"attempt":"<uuid>","mode":"restore-namespace"|"serve",
  "manifest_sha256","manifest_size_bytes":N,"manifest_crc64nvme",
  "chunk_size_bytes":N}`.

Pinned result records (written by the processes into their StateRoot-backed
result bind at `/var/lib/portablefs-volume-archive/`, i.e.
`StateRoot/<vol>/archive/` on the host; strict JSON, atomic write + fsync;
the helper reads them durably before observing):

- `archive-sealed.json` — the `ArchiveSealed` record (attempt, manifest
  ObjectRef, pack ObjectRefs, root digest, logical + sealed totals),
  written only after the archiver's complete read-back verification.
- `restore-namespace-ready.json` — `{"version":1,"volume_id",
  "sealed_epoch":N,"attempt","entries":N,"written_unix":N}`, written after
  the namespace is fully materialized and fsynced, beside the
  `restore-bindings` table.

Authority-written status records in StateRoot (strict JSON, atomic):

- `restore-progress.json` — `{"version":1,"progress_permille":0..1000,
  "state":""|"blocked"|"corrupt","recalled_bytes":N,"drained_bytes":N,
  "updated_unix":N}`, rewritten at most every few seconds; the helper's
  Observe reads it into the observation.
- `restore-converged.json` — the durable convergence record (§Drain).

**Restore-mode activation is state-driven, not flag-driven**: the authority
enters restore mode iff `restore-namespace-ready.json` is present and
`restore-converged.json` is absent in its StateRoot at startup — no new
launcher argv, and `SERVE` can never re-enable base replay because the
converged record gates before the hydrator socket is even dialed.

## Authority ↔ hydrator socket protocol (pinned)

One AF_UNIX stream socket at `StateRoot/<vol>/hydrator.sock` (inside the
authority's state bind at `/var/lib/portablefs-volume`), owned by the
service UID, mode 0600. The hydrator listens; the authority connects with a
small pool (one in-flight request per connection; drain parallelism =
pool size). Length-prefixed frames: `u32 LE length | u8 type | payload`;
frame ≤ 16 MiB + 64 KiB. Types:

- `INFO` (1) → reply `INFO_OK` (2): format version, volume ID, sealed
  epoch, attempt, chunk size, entry/chunk counts, sealed totals, priority
  boundary, and the **drain order**: the sequence of `(entryIndex u32,
  chunkIndex u32)` pairs in pack order (streamed in bounded pages via
  `INFO_NEXT`).
- `FETCH` (3) `{entryIndex u32, chunkIndex u32}` → reply `CHUNK` (4)
  `{extentCount u32, extents (offsetInChunk u64, length u64)..., data}` —
  plaintext, digest-verified by the hydrator before sending; or `ERR` (5)
  `{class u8 (blocked=1, corrupt=2, invalid=3), message}`.
- `HEALTH` (6) → `HEALTH_OK` (7) or `ERR{blocked}`.

The hydrator is a stateless fetch/verify/decode oracle over the sealed
manifest; the authority owns the hydration map, the drain loop (pack-order
sweep over the drain order, preempted by demand recall with ~5 s
hysteresis), all XFS writes, and convergence. The manifest-entry → inode
binding is written by the restorer into `StateRoot/<vol>/restore-bindings`
(compact binary: entryIndex u32 → 16-byte inode identity, in entry order;
sealed with a trailing SHA-256), which the authority loads at restore-mode
start. `ERR{blocked}` from the hydrator, connect failure, or a dead socket
⇒ RESTORE_BLOCKED; `ERR{corrupt}` ⇒ RESTORE_CORRUPT for that chunk,
surfaced volume-wide.

## Hydration map

- Lives in the per-volume StateRoot (outside the user tree and the project
  quota; StateRoot capacity is added to cell sizing), beside the strict
  membership file, owned and written only by the authority.
- Keyed by **restored-inode identity** (the XFS export handle used for
  `StableIdentity`), not path — renames don't move chunk state, and
  hardlink aliases share one inode and therefore exactly one map entry by
  construction. The restorer records the manifest-entry → inode-identity
  binding as it materializes the namespace. Three identities stay
  distinct: the *archive content object* (frame slice — may be shared by
  dedup between unrelated files), the *restored inode* (owns hydration
  state), and the *logical chunk* (one bit). Dedup shares only the fetch
  source: hydrating or overwriting one file never marks another file's
  chunks — each inode's bits are its own.
- One bit per logical chunk (size-banded per pack-format.md), plus a
  per-file all-hydrated bit. Monotone: bits only ever set. Whole-hole
  chunks are born hydrated.
- **Ordering contract (the two-line invariant, made precise):**
  1. *Recall for read*: fetch → verify slice digest → authority `pwrite`s
     base bytes → serve the read. Marking is lazy and needs no barrier:
     re-fetching sealed bytes is idempotent.
  2. *Recall for write* (partial chunk overwrite, shortening truncate
     boundary, RMW): fetch → verify → `pwrite` base bytes →
     `fdatasync` the file → set the map bit → `fsync` the map → apply the
     user mutation → acknowledge it. Base-byte durability strictly
     precedes mark durability, which strictly precedes the user write:
     a durable mark therefore always covers durable base bytes, and an
     acknowledged user write is never applied to a chunk whose mark could
     be lost.
  3. *Whole-chunk-aligned overwrite* and *O_TRUNC to zero*: no fetch —
     but the mark may only become durable once the replacement bytes are:
     apply the mutation (`pwrite` the full replacement / `ftruncate`) →
     `fdatasync` the file → set the map bit(s) → `fsync` the map →
     acknowledge. Marking before the mutation is durable would let a crash
     leave a marked chunk whose XFS bytes are still the sparse restore
     placeholder — a false canonical claim that would silently serve
     zeros. The durable mark always covers durable replacement bytes.
  Crash recovery is then exactly two lines: durably marked ⇒ XFS canonical
  for that chunk; unmarked ⇒ re-fetch from the sealed base. A crash
  between content durability and map `fsync` re-runs an idempotent step
  (re-fetch, or the client's ordinary unacknowledged-write semantics); a
  crash after map `fsync` but before the acknowledgement loses only an
  unacknowledged mutation — ordinary filesystem semantics.
- **One chunk state machine, one lock.** Recall, drain, user writes, and
  truncates all serialize per (inode, chunk) through one lock and re-check
  the hydration bit after acquiring it: a drain fetch that loses the race
  to a user write finds the bit set and discards its bytes — a late drain
  `pwrite` can never overwrite user data. "Single-flight per chunk" means
  this state machine, not merely fetch dedup.
- **mtime preservation across hydration.** The restorer materializes every
  inode with its manifest ns-mtime. A hydration write (recall or drain) is
  invisible base-bytes movement, not a user mutation, so it must not
  change the observed mtime: on an inode the user has not yet mutated, the
  authority performs `pwrite` + `utimensat`(manifest mtime) as one
  sequence under the inode's hydration lock, and attribute reads of
  RESTORING inodes take that lock, so no reader observes the transient
  bump. The first user mutation of an inode sets a per-inode
  user-modified bit in the hydration map; from then on mtime behaves
  ordinarily and hydration writes stop restoring it (the user's own mtime
  is newer and must win). This is what keeps `make` from rebuilding and
  `git status` clean across a wake. ctime is explicitly outside the
  contract (pack-format.md).
- Extending truncate marks the new tail hydrated (zeros are canonical);
  shortening truncate recalls the new-boundary chunk first (rule 2), then
  truncates and marks all beyond-EOF chunks hydrated. Unlink of a cold
  file fetches nothing; an unlinked-but-open file keeps its binding and
  can still recall until final close, after which its state is discarded.
  The drain skips unlinked files. Rename never touches hydration state.

## Recall semantics

- The gate inserts exactly where the `stabilize*` visibility gates already
  sit — between capability resolution and the XFS syscall:
  `stabilizeItem`/`stabilizeOpen`/`lookupForSession`/`stabilizeDirectoryPage`
  (`authorityrpc/visibility_linux.go:56,69,116,155`) and their call sites
  (Read `:977`, GetAttr `:1958/:1967`, Readlink `:868`, Lookup `:411`,
  Write prepare, SetAttr{size}). Namespace and attribute operations never
  recall — the namespace is fully materialized; only content does.
- Single-flight per chunk. `O_TRUNC` to zero skips the fetch and marks the
  chunk range hydrated; unlink of a fully-cold file fetches nothing; a
  partial write or shortening truncate recalls the affected chunks first;
  a whole-chunk-aligned overwrite marks without fetching.
- `fsync` on a partially hydrated file is already honest: hydrated chunks
  are durable in XFS, unhydrated chunks are durable in the sealed archive.
  fsync fsyncs XFS; nothing more is needed.
- **Blocking discipline:** a read of unhydrated content blocks until
  hydrated with a hard per-recall deadline well under the connection
  `WriteTimeout`, failing with a named, non-fatal error — never parking a
  connection past the admission guillotine. Concurrent in-recall requests
  are capped at a small fraction of the ordinary lane (~16 of 64); at the
  cap, further cold reads fail fast with the same named error and the
  client retries. CI proves the session lease and keepalive survive recall
  saturation. This keeps the v3 wire protocol unchanged — no new lanes, no
  frozen-surface touch.
- Hydration failures map to a new additive failure class
  (`FAILURE_CLASS_RESTORE`), reported like the admission `EAGAIN` precedent
  (`failure-modes.md:210-222`) — never `EIO`, never fatal-storage.

## Drain

- Full-bandwidth background sweep in pack order (one contiguous ranged GET
  from offset 0 to the priority boundary first, then the remainder),
  concurrency sized to the cell NIC (~1 stream per 85–90 MB/s), driven by
  the hydrator and written through the authority's same write path.
- Demand recall preempts drain (cancelled drain fetches resume) with ~5 s
  hysteresis. Drain bypasses hot caches.
- Completion: every chunk marked. Verification is per-fetch, not
  post-hoc: every recalled or drained chunk was digest-verified at fetch
  time, and every unfetched chunk was made canonical by a user mutation —
  so "drain complete" needs no extra digest pass over a tree the user has
  legitimately been mutating. Drained byte totals are reconciled against
  the manifest exactly.
- **Convergence commit protocol** (crash-defined, in order):
  1. The authority writes a durable convergence record in StateRoot
     (`restore-converged`: volume, epoch, attempt, drained totals) and
     fsyncs it **before** reporting convergence in its status surface.
  2. Once written, the authority never again consults the hydration map
     or hydrator: restore mode is off for this and every later process
     start (the record outlives restarts).
  3. The helper observation carries the convergence record; the Manager
     durably commits `READY` (cursor `converged`), and the next signed
     plan is plain `SERVE` with no restore configuration.
  4. The helper stops the hydrator unit (absence-proved) and removes the
     hydration map; the convergence record is retained for audit.
  5. Archive-object GC becomes eligible only after step 3's durable
     Manager commit. A crash at any point re-runs from the durable
     cursor: before 1, restore mode simply continues; between 1 and 3,
     the observation re-reports the record; after 3, the plan already
     says SERVE and a re-started authority reads the record and serves
     plainly. `SERVE` can never re-enable base replay — the record is
     checked before the hydrator socket is even opened.
- The volume is then behaviorally identical to never-archived (tested).
- Convergence is a design rule, not a physics claim: the system never
  chooses lazy-forever; interruptions are the named states below. Drain
  rate is an SLO by workload class, observed and alerted — not a
  correctness condition.
- Hydration-storm detector: per-mount recall counters and a fetch-heavy
  alarm (a workload walking cold files faster than drain). Alarm only in
  v1 — no dynamic priority system.

## Named degraded states (honest failure modeling, not fallbacks)

- **RESTORE_BLOCKED** — archive store unreachable, credentials invalid, or
  hydrator down: volume-wide and uniform. ALL content reads fail with one
  named error (no hydrated-vs-cold roulette); namespace and attribute
  operations continue; mounts and sessions stay alive; drain retries with
  backoff; the state auto-clears when fetches succeed again.
- **RESTORE_CORRUPT** — a chunk fails digest verification: a data-integrity
  event, surfaced immediately as a volume-level state with affected paths
  enumerable from the manifest; never silently skipped, never served
  unverified.

Both are surfaced in the volume observation and the Manager volume view, so
the product can display them.

## Quiesce (archive step 1) — Files gateway teardown

The `portablefs-files` gateway holds real authority sessions invisible to
the Manager's enrollment table. Quiesce adds `DELETE
/v1/volumes/{id}/session` to the gateway (evict + close the session,
idempotent, same signed-token authorization with operation
`session.delete`); the product driver calls it for every configured gateway
before the Manager stops the authority.

The delete carries a monotonically increasing per-volume **fence value**
(the product uses its backing generation). The gateway durably-enough
(in-memory per volume, convergent because deletes are retried) records the
floor, and `PUT session` re-checks the floor **after** dialing the
authority and immediately before installing — closing the race where a
pre-issued grant installs a session between a DELETE and the authority
stop. A PUT below the floor is refused `session_fenced`. Defense in depth,
not the primary guarantee: the authority stop itself kills any surviving
session (keepalive fails, `client.Err()` turns terminal), and the Manager
refuses new read grants for ARCHIVING volumes, so the fence only has to
cover grants issued before quiesce began, whose 10-minute life bounds the
window. The gateway's archived mode (below) is unaffected — it holds no
authority session.

## Files-gateway archived mode

For an ARCHIVED volume the gateway serves list/preview/download directly
from the sealed archive: it downloads and caches the manifest (bounded LRU),
answers directory listings from manifest entries, and serves previews and
downloads with ranged GETs of the exact chunks, decompressed with the shared
format library. Same bounded pages, cursors, and byte limits as live mode;
same signed-token authorization; archive-store read credentials are the
gateway's own configuration. Browsing never wakes a volume. Symlinks and
opaque kinds are listed but not opened, as in live mode.

## Observability (day one)

- Per-file hydration state queryable (admin surface on the authority);
  volume progress % + honest ETA in the observation; a completion event.
- Metrics: `mount_to_last_on_demand_fetch`, recalled-vs-drained byte ratio
  (SLO: drain must win), p95/p99 first-use latency (cold-file open→data) by
  workload class, drain throughput, recall depth, RESTORE_BLOCKED seconds.

## Doc amendments this contract requires

- `docs/architecture.md` invariant 3 and "What not to build": the sealed
  archive of an ARCHIVED/RESTORING volume becomes the second named durable
  exception, stated per-state (the canonical-representation table in
  identity-lifecycle-and-capacity.md §2).
- `docs/xfs-authority-architecture.md:93-96, 135-137, 519-526` and the
  proof ledger (new Open items for archive round-trip, recall saturation,
  convergence identity).
- `docs/failure-modes.md`: new failure scope `restore` with
  `FAILURE_CLASS_RESTORE`; RESTORE_BLOCKED/RESTORE_CORRUPT rows.
- `docs/consistency-model.md:74-81`: a not-yet-hydrated read blocks until
  hydrated or fails with the named restore error; it never returns stale or
  partial data.
- `docs/hosted-control-plane.md:342-346`: the archiver/hydrator are the
  narrow-identity controllers this paragraph reserved; the helper still
  accepts no remote snapshot command — archive phases are typed plan
  phases, and credentials are root-provisioned cell configuration.
- `docs/hosted-cell-deployment.md`: unit inventory gains the archiver and
  hydrator templates; the authority keeps exactly its three bind mounts
  plus the hydrator socket directory.
