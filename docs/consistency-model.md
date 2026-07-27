# Consistency Model

PortableFS has two linked sources of durability:

- **Live durability:** the active VCS authority has acknowledged the filesystem mutation after
  writing it to the WAL. In production mode, the mutation is replicated before acknowledgement.
- **Checkpoint durability:** the Volume API has accepted a commit whose referenced blobs exist
  in the blob store and whose metadata transaction advanced the branch head.

The live mounted filesystem is the source of truth while a volume is active. The committed branch
history is the immutable record used for snapshots, forks, cold starts, server-side reads, and
recovery.

## Active Volume Rule

One active volume has one logical VCS authority at a time. That authority owns the writable working tree,
holds a fenced lease against the API, and serves every live mount for that volume.

Multiple machines can mount the same volume, but they are not independent sources of truth. They
all talk to the same VCS authority through FUSE/custom protocol or NFS. This is the architectural
reason live read-after-write can work without merging separate local folders.

If the authority loses its claim, its readiness flips false and it must stop serving the data
plane. A replacement authority claims the journal under a newer fencing generation, cold-replays
the committed state plus the journaled tail, and becomes the new authority
([journal.md](./journal.md)). The product contract is one filesystem; the implementation can move
the authority between machines.

## Write Rule

A writable filesystem operation mutates the VCS working tree and is appended to the durable log
before it is acknowledged. With `VCS_PRODUCTION=1` that log is the fenced, synchronously
replicated Postgres journal; in development it is the crash-safe local file WAL.

This makes acknowledged writes live-durable even before they are checkpointed. If the
process restarts, the VCS rebuilds the working tree from the last committed manifest plus WAL
replay.

## Mount Visibility

Mount clients connected to the same VCS authority share one live working tree. Reads go through
the authority and its cache hierarchy, not through separate per-machine folder snapshots.

The custom FUSE protocol includes push invalidation so client kernel caches evict changed files.
The NFS path is useful for zero-install access, but the custom FUSE path is the higher-fidelity
agent filesystem path because it supports explicit invalidation, reconnect behavior, and richer
coordination.

## Checkpoint Visibility

Checkpoints freeze an as-of view of the VCS working tree, upload dirty file content as
content-addressed blobs or chunks, and commit a manifest through the Volume API.

Readers of committed history see a new tree only after the metadata transaction advances the
branch head. They never see partially uploaded blobs or an uncommitted manifest.

Snapshots and forks consume exact immutable states. On a base-authoring branch a snapshot pins
the committed head. On a live (journal-served) branch a snapshot records a HistoryCut at the
current journal position — every acknowledged write up to the cut is captured — and materializes
asynchronously; forks and branches consume the cut once it is ready.

## Writer Coordination

The VCS authority coordinates writes for mounted clients. The current implementation has subtree
delegations for exclusive write ownership, force checkout/fencing for stale holders, and
idempotent retry behavior across reconnects.

Direct API clients that bypass VCS must still obey API lease and delegation rules. New agent
runtime code should not bypass VCS for live filesystem writes.

## Exact-Once Mount Sessions

Every mount instance negotiates an exact-once session with the authority (protocol version 3,
`OpProtocolVersion` + `FeatExactSessions`). The client mints a random session identity and an
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
  released on durable lease expiry or voluntary session expire — never on a socket flap. After an
  authority restart or replacement, token-proven prior sessions get a bounded reclaim window to
  re-assert their coordination state before conflicting acquisitions are admitted.

Write-back flush batches compose with sessions: flush exactness is a replicated per-session
watermark (a control record advanced in the same atomic batch as the mutations it covers), and
under the fail-closed posture a flush must arrive on a connection whose authenticated mount
session is still current.

The durable journaled session store — `Managed()` stores negotiating protocol version 4 with
`FeatJournaledCoordination`, no reclaim grace, and no wall-time outcome pruning — wires up with
the journal integration.

Open registration (`FeatOpenRegistration`) — the fused create+open (the kernel CREATE is
create+open, so the open hold rides the create RPC), batched last-close unmarks, and client-side
registration retention — applies to **both** server generations. The legacy generation records
holds in its in-memory, lease-renewed open table; the managed generation records the same surface
as durable journaled open-pin rows: the fused create ensures its pin row before the reply leaves
the server (a lost-reply replay of the create re-ensures the same pin, never a second one), and
one batched unmark journals all of its releases as one exact row, replayed — not re-applied — on
an identical resend.

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
dentry cache when the authority stamps misses with the parent directory version (`FeatParentVersion`,
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

Extended attributes are native **LIVE volume state**, capability-gated on `FeatXattrs`
(advertised by both server generations). They exist so macOS FSKit mounts stop generating
AppleDouble `._` sidecar files: the FSKit extension already forwards xattr operations over
pfslocal, and portablefsd answers natively whenever the attached authority advertises the
feature. Against an older authority every xattr op reports ENOTSUP locally (no wire attempt)
and kernels keep today's fallback behavior.

Semantics (Linux `setxattr`/`removexattr` as the reference):

- Names are raw case-sensitive bytes (1..255, NUL-free UTF-8); values are raw bytes up to
  64 KiB (`E2BIG` beyond; `ERANGE` for an over-long name). One inode's total xattr bytes
  (names + values) are bounded at 128 KiB (`ENOSPC` beyond, decided deterministically at the
  record's ordered apply position).
- Set is create-or-overwrite (last writer wins). `removexattr`/`getxattr` of a missing name
  is `ENODATA` (Darwin frontends translate to `ENOATTR`), never a silent no-op.
  `XATTR_CREATE`/`XATTR_REPLACE` (and FSKit's mustCreate/mustReplace policies) are enforced by
  the authority at the mutation's ordered WAL/journal position. The existence test and update
  are one durable operation across every mount; no client-side preflight read or TOCTOU window
  exists. Conditional policies require the separately negotiated `FeatAtomicXattrFlags`;
  clients fail closed with `EOPNOTSUPP` against an older basic-xattr authority rather than let
  that authority ignore the additive flag.
- Xattrs are keyed by stable inode: rename and open-after-unlink parking keep them; true inode
  destruction (remove of a not-open file, reap of an orphan) drops them.
- Xattr mutations never touch file timestamps (the same discipline as chmod).

Coherence: xattr **reads are pure read-through** — every getxattr/listxattr reaches the
authority, nothing caches xattr bytes client-side — so a mount observes its own writes
read-after-write and remote writes as soon as the authority applies them. A remote xattr
mutation additionally publishes an in-place (attr-level) invalidation, keeping version-gated
attribute caches honest. Xattr **mutations are write-through even on write-back mounts**:
sessions never buffer xattr intents at this stage. On a write-back-covered path the covering
session is flushed first (so a locally buffered create exists at the authority before its
xattr lands); the extra flush round-trip is the documented cost of the simpler, honest model.

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

The core path is now a real mount rather than a folder scanner. The custom FUSE protocol is the
primary target for coherent agent filesystems. NFSv3 remains useful where zero-install mounting is
more important than the richest coherence semantics.

### Concurrent appends

Authorities advertising `FeatAtomicAppend` resolve EOF at the write's serialized WAL/journal
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

NFSv4, broader cross-client POSIX lock coverage, and stronger sub-flush demand-coherence are
follow-on work.
