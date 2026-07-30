# Consistency Model

PortableFS separates write acceptance from two linked durability layers:

- **Local write acceptance:** under an active delegation, `write(2)` returns
  after the mutation is appended to the mount WAL file descriptor and
  published in the local overlay. The group-sync runs at 5 ms / 4 MiB; until
  it or an explicit barrier completes, an immediate whole-machine power loss
  may lose that recent accepted tail.
- **Authority durability:** a write-through mutation is committed to the
  authority journal before its reply. A delegated mutation reaches this layer
  asynchronously, or synchronously when `fsync`, synchronize, explicit
  flush, or clean unmount drains it. `close(2)` is not a durability barrier.
- **Checkpoint durability:** the Volume API has accepted a commit whose referenced blobs exist
  in the blob store and whose metadata transaction advanced the branch head.

The live mounted filesystem is the source of truth while a volume is active. The committed branch
history is the immutable record used for snapshots, forks, cold starts, server-side reads, and
recovery.

## Active Volume Rule

One active volume has one logical VCS authority at a time. That authority owns the writable working tree,
holds a fenced lease against the API, and serves every live mount for that volume.

Multiple machines can mount the same volume, but they are not independent sources of truth. They
all talk to the same VCS authority through the custom mount protocol. This is the architectural
reason live read-after-write can work without merging separate local folders.

If the authority loses its claim, its readiness flips false and it must stop serving the data
plane. A replacement authority claims the journal under a newer fencing generation, cold-replays
the committed state plus the journaled tail, and becomes the new authority
([journal.md](./journal.md)). The product contract is one filesystem; the implementation can move
the authority between machines.

## Write And Fsync Rule

A writable operation takes one lane chosen before execution:

- The shared authority lane appends to the fenced, synchronously replicated
  Postgres journal before replying.
- The delegated lane appends to the mount's segmented local WAL and publishes
  its overlay before replying. It does not wait for physical local sync on
  every `write(2)`.

`fsync(2)` first forces the local WAL, then drains the captured dense stream
tail until it is durably committed and applied at the authority, then waits
for the subscriber visibility barrier. Any stage that cannot complete returns
an error. Clean unmount and explicit synchronize use the same durability
boundary.

If local WAL establishment or persistence fails, the engine latches a
terminal mount error and every later mutation fails until remount. It never
substitutes a write-through operation. A remote delegation-acquire error also
fails the operation; only an explicit authority policy denial selects the
shared lane.

After authority durability, a replacement authority rebuilds the working
tree from the immutable base plus journal replay.

## Mount Visibility

Mount clients connected to the same VCS authority share one live working tree — never separate
per-machine folder snapshots. Reads resolve against the authority's current state through
version-gated caches, kept coherent by the push-invalidation stream. Under an adaptive
write-back delegation, the holder acknowledges mutations locally; a peer operation overlapping
the delegated scope waits for its recall and drain, so a peer is never answered from stale
pre-delegation state.

The exact cross-machine guarantee is barrier-shaped at the protocol/frontend
invalidation boundary:

- **A completed `fsync`/`synchronize` is durable and applied at the
  authority.** It also waits for every live protocol subscriber to
  acknowledge its covering invalidations. Linux FUSE acknowledges only after
  its kernel invalidation hook returns, so subsequent FUSE reads are exact.
  `portablefsd` acknowledges after its user-space caches are invalidated and
  the event is delivered to the local frontend stream.
- **Plain un-fsynced writes normally propagate to peers within bounded
  asynchronous invalidation** (the flush batching window plus one
  invalidation push), like a local page cache. This is a visibility schedule,
  not a power-loss durability promise.

macOS 26 FSKit is an explicit framework boundary: the current FSKit API does
not provide PortableFS a kernel-cache invalidation primitive, and its
invalidation events are therefore advisory. `fsync`, synchronize, and
clean unmount still have the exact authority-durability contract above, but a
read FSKit satisfies wholly from its kernel cache is outside the
cross-machine visibility acknowledgment. Applications that require an exact
handoff on macOS must reopen/re-resolve the file or coordinate at the
application layer until the SDK exposes a cache invalidation hook.

## Checkpoint Visibility

Checkpoints freeze an as-of view of the VCS working tree, upload dirty file content as
content-addressed blobs or chunks, and commit a manifest through the Volume API.

Readers of committed history see a new tree only after the metadata transaction advances the
branch head. They never see partially uploaded blobs or an uncommitted manifest.

Snapshots and forks consume exact immutable states. On a base-authoring branch a snapshot pins
the committed head. On a live (journal-served) branch a snapshot records a HistoryCut at the
current journal position — every authority-durable write up to the cut is captured — and materializes
asynchronously; forks and branches consume the cut once it is ready.

## Writer Coordination

The VCS authority coordinates writes for mounted clients. The current implementation has subtree
delegations for exclusive write ownership, force checkout/fencing for stale holders, and
idempotent retry behavior across reconnects.

Direct API clients that bypass VCS must still obey API lease and delegation rules. New agent
runtime code should not bypass VCS for live filesystem writes.

## Exact-Once Mount Sessions

Every mount instance negotiates an exact-once session with the authority (protocol version 8;
exact sessions are baseline, not a capability). The client mints a random session identity and an
opaque token once per mount, establishes the session durably, and stamps every write-through
mutation with an identity: `(session, generation, slot, slot sequence)`. The authority computes a
canonical request fingerprint server-side, embeds the identity in the same durable record as the
mutation itself, and records the essential outcome (status, count, version, ino, orphan ino) in a
replicated slot table. Exactness therefore has exactly the durability of the mutation.

The invariants:

- **A retry never re-executes.** A replayed identity whose fingerprint matches the recorded one
  returns the stored outcome byte-for-byte, flagged `Duplicate`. This holds across reconnects,
  authority restarts, and failover to a replacement authority, because the slot table is rebuilt
  from the same durable log the mutations rode.
- **A definite reply always consumes the identity.** Grants and deterministic rejections alike
  (ENOENT, EEXIST, EAGAIN, ENAMETOOLONG, ...) are durably recorded before they are answered, so
  the slot sequence advances and the client's next mutation uses a fresh identity. There is no
  unrecorded definite reply: when the authority cannot record durably, it drops the connection
  instead of answering.
- **An UNKNOWN outcome parks.** If the connection dies after the request may have been durably
  prepared, the client parks the identity and a background replayer resends the identical bytes
  until a definite answer arrives. The identity is never reused for different content.
- **State corruption fences.** Reusing an identity with different content, or skipping/rewinding
  the slot sequence, proves the client lost state. The authority durably fences the whole session
  generation; every further mutation from it fails ESTALE, and the mount surfaces a hard error.
  Remount recovers; a fenced mount never mints a fresh generation by itself.
- **Sessions own liveness.** Coordination state (advisory locks, delegations, open pins) is
  released on durable lease expiry or voluntary session expire — never on a socket flap. There
  is no reclaim grace and no wall-time pruning: a cold replay of the journal already contains
  authoritative coordination, so a replacement authority admits or refuses exactly what the
  journal says.

Write-back flush batches compose with sessions: flush exactness is the journaled per-session
flush ledger (advanced in the same fenced journal rows as the mutations it covers), and a flush
must arrive on a connection whose authenticated mount session is still current.

Open registration is baseline: the fused create+open (the kernel CREATE is create+open, so the
open hold rides the create RPC), batched last-close unmarks, and client-side registration
retention. Open pins are durable journaled rows: the fused create ensures its pin row before the
reply leaves the server (a lost-reply replay of the create re-ensures the same pin, never a
second one), and one batched unmark journals all of its releases as one exact row, replayed —
not re-applied — on an identical resend.

A delegation handoff freezes only new opens and namespace rebindings in the
released subtree; closes and unrelated subtrees remain live. Before Checkin,
the authority resolves every barrier-stable open path under the still-held
grant and durably installs any missing session pins. The client adopts the
aligned inode identities with the exact live-handle counts, records its
drained watermark plus local release in one WAL sync, and keeps the barrier
through the replay-exact Checkin. Thus a peer unlink after handoff either sees
an open pin and parks the inode or sees no live handle—never an unprotected
open created in the release gap.

## Commit Rule

The API accepts a checkpoint commit only when:

- the session is writable;
- the lease id and fencing token match;
- the lease is not expired or released;
- every referenced blob or chunk exists;
- the manifest tree hash matches its entries.

Exclusive commits require the expected head to equal the current branch head. Shared/delta commit
routes can merge disjoint delegated changes onto a newer head and reject overlapping changes with
`VOLUME_MERGE_CONFLICT`.

Postgres may store a checkpoint as a parent-relative manifest diff instead of a fully materialized
manifest. Reads reconstruct and verify the manifest against the commit tree hash. Automatic
materialized checkpoints bound the diff chain length.

## Cache Rule

VCS caches content in memory and, when configured, on local disk. Cache hits never change
correctness: blobs and chunks are verified against their content digest, and corrupt cache entries
are discarded and fetched again.

The Volume API also keeps a bounded hot blob cache in front of Railway Buckets for server-side
`grep` and downloads. Railway Bucket storage may compress blobs at rest, but reads
decompress and verify the original content-addressed digest before returning bytes.

### Existence vs. attributes

Existence — whether a name resolves, and to which inode — is coherent **by version, never by time**.
Every shared-path lookup carries entry-timeout 0, so the kernel revalidates each name lookup against
the authority and a peer's create/remove/rename is reflected immediately, with no per-name TTL. Only a
path a mount **exclusively holds** (a write-back checkout) caches positive existence, since nothing
else can change it. NON-existence (a repeat ENOENT probe) is served from the version-gated negative
dentry cache when the authority stamps misses with the parent directory version (`ParentVersion`,
default-on then): the cached negative is ordered against that version, which every name mutation in
the directory advances — invalidation-driven, still never a TTL. The `keepcache` /
`PORTABLEFS_TTL_MS` knobs extend only **attribute/content** caching; they never introduce a positive
existence TTL.

Invalidation distinguishes an **in-place** change (write/truncate/chmod/chtimes/chown/setxattr/
removexattr — same name→inode binding) from a **name change** (create/remove/rename). A name change
drops the kernel dentry so the stale name is re-resolved; an in-place change does **not** — dropping
the dentry of a directory a process holds as its CWD would disconnect it, so a concurrent `getcwd()`
(e.g. SQLite resolving a relative database path) would fail with ENOENT and surface as
`SQLITE_CANTOPEN`. A record that changes nothing (idempotent, or a rejected remove of a
non-empty/missing path) publishes no invalidation at all.

## Extended Attributes (xattrs)

Extended attributes are native **LIVE volume state** in the fsproto v8 baseline. They exist
so macOS FSKit mounts stop generating AppleDouble `._` sidecar files: the FSKit extension
forwards xattr operations over pfslocal and portablefsd answers them natively. Authorities
that do not speak the v8 baseline are rejected at mount-time protocol negotiation; a mount
never silently drops xattr operations or changes their semantics.

Semantics (Linux `setxattr`/`removexattr` as the reference):

- Names are raw case-sensitive bytes (1..255, NUL-free UTF-8); values are raw bytes up to
  64 KiB (`E2BIG` beyond; `ERANGE` for an over-long name). One inode's total xattr bytes
  (names + values) are bounded at 128 KiB (`ENOSPC` beyond, decided deterministically at the
  record's ordered apply position).
- Set is create-or-overwrite (last writer wins). `removexattr`/`getxattr` of a missing name
  is `ENODATA` (Darwin frontends translate to `ENOATTR`), never a silent no-op.
  `XATTR_CREATE`/`XATTR_REPLACE` (and FSKit's mustCreate/mustReplace policies) are one atomic
  mutation with no preflight read or TOCTOU window. The authority evaluates them for shared
  objects. A delegation holder evaluates them from the complete xattr map of a locally-born
  object before appending the same conditional record to its WAL; exclusive scope ownership
  prevents a peer from racing that decision.
- Xattrs are keyed by stable inode: rename and open-after-unlink parking keep them; true inode
  destruction (remove of a not-open file, reap of an orphan) drops them.
- Xattr mutations never touch file timestamps (the same discipline as chmod).

Coherence follows the same delegated boundary as file data. An object created under a
delegation starts with a complete empty xattr map, so get/list/set/remove stay in that
scope's local WAL and preserve immediate read-after-write; fsync/flush/unmount carries the
file and its xattrs through the same authority barrier. This is important on macOS, which
normally attaches an Apple xattr to each newly-created file. Existing authority objects do
not receive an unbounded xattr snapshot with the delegation: their reads remain
read-through, and their mutations conservatively use the authority lane unless the client
can prove the complete xattr map. That proof boundary preserves conditional flags and the
128 KiB per-inode limit before any local acknowledgement. Remote xattr mutations publish an
in-place (attr-level) invalidation, keeping version-gated attribute caches honest. Delegated
xattr batches are an optional v8 optimization advertised by `FeatureDelegatedXattrs`; a
client connected to a v8 authority without that feature selects the shared xattr lane from
the initial probe, never after a failed operation.

Durability across compaction — the load-bearing part:

- **Managed (journal-native) generation:** live state periodically rebuilds from a HistoryCut
  base (PFT2) plus the retained journal suffix. Ordered `XATTR_LEAF` objects for
  filesystem-homed inodes ride appended `Root.xattr_leaves` and therefore the user closure;
  snapshots and forks preserve them. `RecoveryRoot.xattr_leaves` carries the complete state,
  including parked open-after-unlink orphans, for same-branch adoption. The materializer builds
  both projections in O(number of xattrs), and trimming the journal below the cut cannot lose
  either.
- **Legacy (WAL + manifest) generation:** the checkpoint manifest cannot carry xattrs, so
  `CompactWAL`/`ResetWAL` re-append the live xattr state as ordinary path-addressed records at
  or above the compaction cut (the same discipline as the control-state snapshot); replay
  re-applies them idempotently. Parked orphans' xattrs share the orphans' own documented fate
  on this generation (legacy orphans do not survive a restart).

**PFT2 snapshots carry xattrs.** A fork adopts only the immutable user root and never reads
the source branch's recovery anchor; its named files still retain their xattrs because those
leaves are in the user closure. Orphan-only attributes remain recovery-only and cannot leak
into a fork.

## POSIX Boundary

The core path is now a real mount rather than a folder scanner. The custom mount protocol is
the one target for coherent agent filesystems.

### Concurrent appends

Authorities resolve append EOF at the write's serialized journal
position. Linux FUSE retains `O_APPEND` on the open-file description and sends one append
mutation—no getattr/size preflight—so concurrent append records across machines occupy distinct,
non-overlapping ranges. Exact-session retries replay both the original count and selected offset;
WAL replay resolves the same offsets in record order. A new client connected to an older authority
uses the kernel-provided absolute offset, preserving the prior behavior.

Apple's current FSKit write callback supplies an item, data, and already-resolved offset but does
not expose the originating open flags or `O_APPEND` intent. PortableFS therefore cannot safely
distinguish append from `pwrite` at EOF in the FSKit adapter: guessing would corrupt legitimate
positional writes. Cross-machine atomic append is consequently guaranteed on negotiated FUSE/core
paths, while macOS FSKit append retains kernel-local serialization. Applications requiring a
shared cross-machine append log on FSKit must coordinate with PortableFS advisory locks or use
per-writer files until FSKit exposes append intent.

### Hard links

Non-directory hard links are native across the authority, exact-session journal,
Linux FUSE, and macOS FSKit paths. All names share one stable inode and content;
`st_nlink` is authoritative, unlink removes one name and only reaps storage after
the final link and final open handle are gone, and rename-over preserves open
handles to the displaced inode. Linking a directory is refused with `EPERM`.
Machine-local-dir grafts support links inside one graft, while a link between
the volume and a graft or between two graft roots returns `EXDEV`.

Authorities advertise `FeatHardLinks`. A new client connected to an older
authority does not send `OpLink`, reports the mount capability as unavailable,
and answers locally with `EOPNOTSUPP`; ordinary operations are unchanged.
Write-back remains the fast path for singly linked files. Once an inode has more
than one name, its mutations use the authority's inode-aware write-through lane
so path-keyed overlays cannot diverge between aliases.

## Restart-stable inode identity

The legacy WAL checkpoint sidecar persists the inode allocator namespace, next-local cursor,
observed high-water, and durable floor even when no sessions exist. Deleting the highest inode
before compaction/reset therefore cannot make its stable identity reusable after restart.

## Known limitations

Broader cross-client POSIX lock coverage and stronger sub-flush demand-coherence are
follow-on work.
