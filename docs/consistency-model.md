# Consistency model

Status: **v3 application-visible contract**

PortableFS v3 has one source of truth per volume: the mounted XFS instance the
authority addresses. Everything the authority itself holds — sessions, open
file descriptions, advisory locks, same-epoch replay slots, cancellation state
— is disposable epoch state. There is no second inode tree, no mutation log, no
PortableFS-managed or offline write-back cache, and no history. Ordinary kernel
page caches still exist. The architectural decision behind that is in
[xfs-authority-architecture.md](./xfs-authority-architecture.md).

This document states what an application may rely on.

## Where truth lives

For a live volume the source of truth is exactly the mounted XFS instance: its
VFS and page-cache state, its metadata journal, and the persisted device state
beneath it. Unflushed page-cache data is authoritative *current* state but is
not durable across power loss; `fsync` is the boundary that asks XFS and the
device to persist it. XFS's own journal is an internal crash-recovery
mechanism, not a PortableFS history.

One volume has one active authority epoch. Every mount of that volume talks to
that one authority over mutually authenticated TLS 1.3, which is why
cross-machine read-after-write is possible at all without merging separate
local folders. Mounts are not independent sources of truth and never reconcile
with each other.

One naming trap is worth stating plainly: the data-plane wire version is
`ProtocolMajor = 5` and its ALPN identifier is `portablefs-authority-v5`
(`vcs/internal/authorityrpc/protocol.go`). That is the *protocol's* major
version, not the product's. It is unrelated to the retired v2 architecture, and
a v2 client and a v3 authority fail their handshake rather than enter a mixed
mode. Protocol 5 requires one authenticated DATA transport and one authenticated
CONTROL transport in the same connection set. Attach creates only a provisional
credential; Activate publishes the root and makes the session usable only after
both binding generations are proven. Abort names the exact provisional attach
attempt. There is no single-transport or direct-active-attach path.

Protocol 5 retains protocol 4's exact replay for Lookup and every other resource
acquisition, so a lost successful reply cannot allocate an unreachable second
capability on retry. A mutation carries only its client-owned replay slot and
sequence; the authority binds that identity to the exact canonical mutation
body with a secret keyed fingerprint scoped to the same authority epoch. The
fingerprint is never trusted from, or returned to, a client. Protocol 5
transports write and read bytes as the frame's single schema-checked bulk body
rather than copying them through nested protobuf allocations. This is one exact
wire format, not an optional fast path.

## Write acceptance and durability

The data-plane acknowledgement and authority application are the same event.
The application syscall boundary depends on the frontend kernel contract.

- **Linux direct-I/O `write(2)` returns only after authority application.**
  There is no PortableFS write-back engine or local mutation log.
- **In the separately build-stamped macOS qualification policy, macOS may first
  accept bytes into its kernel page cache.** Application
  `write(2)` can return before FSKit submits those bytes. Every FSKit write
  callback is still authority-through, and `fsync`/synchronize waits for the
  authority. An application that needs a cross-machine completion boundary on
  macOS must use `fsync`; `close` alone is not that boundary.
- **`fsync`/`fdatasync` wait on the authoritative server file description.** A
  successful return means the authority completed `fsync(2)` or `fdatasync(2)`
  against that descriptor, with the ordinary
  [Linux durability contract](https://man7.org/linux/man-pages/man2/fsync.2.html).
- **`close` is not an implicit `fsync`.** It is not a remote durability or
  cross-machine completion boundary on either frontend.
- **`syncfs(2)` is forwarded by the pinned strict kernel.** It always issues
  mandatory `FUSE_SYNCFS` after draining local writes; a successful return
  means the authority completed its volume sync, and an ordinary authority
  durability errno propagates. ENOSYS, malformed replies, and transport loss
  fence the strict connection instead of caching a local-success fallback.
  Stock regular-FUSE kernels that do not provide this path fail INIT.
- **A namespace operation is atomically visible when its XFS syscall
  completes.** Making it durable across power loss is the caller's ordinary
  file-and-directory `fsync` discipline.
- **Two whole-file replacements are ordered atomic renames.** The later ordered
  rename wins. PortableFS never merges file contents.

Because there is no client-side durability debt, `umount --force` has nothing
to park and nothing to replay: it only gives up on proving the drain.

## Cross-mount visibility

Protocol 5 has one coherent mount profile. If a mutation `M` returned success
before an operation `R` began on any mount of the same volume, `R` does not
observe namespace, attributes, size, or data older than `M`, unless something
ordered after `M` changed them again. An operation that overlaps `M` may observe
either side, as it could between two processes on one machine.

Every active filesystem mount participates, including read-only mounts that can
cache what a peer writes. Names and attributes may be cached only under this
synchronous contract: for a cache-visible mutation, the initiating frontend
first closes and drains an exact item-and-namespace publication gate for the
footprint its callback may publish. The authority independently
derives and validates that declaration; then every *other* affected participant
receives PREPARE, the XFS syscall runs, and those peers repair and acknowledge
COMPLETE *before* the mutation's reply is returned to its caller. The source
receives neither phase. On Linux its local gate remains closed through the
operation-specific kernel/VFS postprocessing and the physical ACK of the
forced `FUSE_PFS_PUBLISH`; returning from the daemon's ordinary `/dev/fuse`
reply write is too early. A qualification frontend must provide an equally
explicit framework publication verdict. A post-apply publication failure ends
that mount rather than serving through unproven state.

Visibility polling and acknowledgements use the CONTROL transport so events
cannot queue behind bulk DATA frames. On Linux, each successful repair
atomically acknowledges its exact cursor and waits for the next phase in one
request. This removes empty control round trips and source self-round trips
without moving peer acknowledgment ahead of repair or XFS ahead of PREPARE.
There is no non-participating filesystem session and no no-participant execution
path: a visible mutation from a session that was not installed in this runtime
is refused before XFS.

`--coherence strict` names this sole contract and remains the CLI default.
`uncached` is a retired value; the CLI and authority client reject it before
Attach rather than aliasing it to `strict` or falling back to weaker semantics.
The black-box `scripts/coherence-matrix-linux.sh` therefore exercises one
contract through two real mountpoints. It compares content against the bytes a
descriptor actually returns when read to EOF rather than against `stat.Size`,
compares the namespace against the entries `readdir` actually enumerates,
compares an atomic replacement against the inode number the *other* mount
resolves, and never polls or retries. It also proves a red result is reachable
before reporting a green one. See
[cross-mount-coherence-matrix.md](./cross-mount-coherence-matrix.md).

### macOS

Shipping macOS 26 builds admit the named
`macos26-synchronous-vfs-repair-v2` best-effort policy. The Mac owns an
exclusive compatibility writer lease while mounted; Linux peers may read but
receive `EBUSY` for visible mutations, and another Mac writer is refused. A
clean unmount transfers ownership. Authority ordering, terminal delivery,
durability, and fail-closed repair remain exact, while FSKit's missing exact
peer namespace/attribute invalidation is an explicit platform limit. There is
no runtime opt-in, `uncached` mode, hidden retry, or fallback. A separately
build-stamped macOS 27 artifact may exercise the candidate native-revocation
policy, but that artifact is not product support. The evidence and remaining
platform gates are in
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md).

### Shared file-backed mmap is unsupported, not incoherent

PortableFS does not advertise `CAP_DIRECT_IO_ALLOW_MMAP`, so Linux refuses both
writable and read-only `MAP_SHARED` mappings of a volume file rather than
creating mapped pages the authority cannot revoke coherently. `MAP_PRIVATE`
remains available: it is a process-local copy-on-write view that never writes
through, and POSIX leaves its visibility of later external changes unspecified.
That is ordinary filesystem behaviour, not a distributed coherence promise.
See the kernel's
[FUSE cached/direct/write-back distinction](https://cdn.kernel.org/doc/html/latest/filesystems/fuse/fuse-io.html)
and the [`MAP_PRIVATE` contract](https://man7.org/linux/man-pages/man2/mmap.2.html).

If measurement or compatibility later demands shared mappings, the only
acceptable extension is a synchronous lease protocol in which a writer waits
until every live holder has flushed any authorized dirty mapping and completed
kernel invalidation, or an external proof fences the exact kernel mount. Lease
expiry alone is not fencing, and an asynchronous event stream alone is
insufficient because a peer could read stale pages before processing the event.

## Ordering and retry

Linux VFS and XFS supply each syscall's atomicity. The authority adds only:
validate the TLS peer, capability, session, epoch and operation identity;
execute the descriptor-relative XFS operation; retain the exact reply in that
session's same-epoch replay slot; return. Different replay slots execute
concurrently.

There is no honest way to atomically commit an arbitrary XFS syscall together
with a separate durable reply record, so the boundary is made explicit rather
than hidden:

- **Duplicate delivery inside a live epoch returns the cached outcome.** The
  authority recomputes its private fingerprint over the replayed body; an exact
  match returns the stored outcome and never re-executes
  (`ExecuteMutation`, `vcs/internal/volumeserver`).
- **A client state defect fences the session.** Reusing a slot identity with a
  different request, or gapping the slot sequence, proves the client lost
  state; the authority ends that session rather than interleaving with unknown
  history.
- **No request is silently continued across an epoch.** Side-effect-free calls
  may reconnect and retry inside the same epoch. A mutation may not.
- **A mutation whose reply is lost across authority death is `UNCERTAIN`.** The
  response carries that marker explicitly, the client never auto-retries it,
  and the application inspects current state and decides. Append offsets and
  namespace outcomes are never guessed.

This gives session-exact execution without inventing a second durable truth.
**Transparent exactly-once semantics across server death are not claimed.**

## Locks

POSIX record locks and BSD `flock` locks are authority-epoch runtime state
(`vcs/internal/volumeserver`). The Linux frontend refuses to mount if the
kernel does not forward both, because partial forwarding would silently remove
cross-machine exclusion.

- `FLUSH` removes a closing process owner's POSIX locks.
- The final `RELEASE` removes an open-file-description `flock`.
- Session expiry, fencing, or epoch end removes everything that session held.

The two namespaces stay independent, as on local Linux. A blocking request that
would close a cycle in the wait-for graph is refused with `EDEADLK` rather than
hanging.

## Extended attributes

`setxattr` is not exposed at launch. XFS attribute-fork blocks are
[not charged to project quotas](https://www.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf),
so project quotas cannot isolate user-xattr writes on a shared cell and a
PortableFS-side counter could not commit atomically with XFS. Both the Linux
frontend and a direct authority request return `EOPNOTSUPP`. Authority protocol
5 requires `user-xattr-readonly` at Activate, so Linux returns that fixed verdict
locally after validating the FUSE flags; it does not consume a mutation replay
sequence or visibility work for an operation the authority can never accept.
Read, list and remove of pre-existing portable `user.*` attributes remain
available; `vcs/internal/xfsstore` (`ValidateXattr`) admits only the `user.`
namespace and excludes the reserved `user.portablefs.` prefix, so internal
metadata, `security.*`, ACL internals and `trusted.*` never cross the remote
boundary.

The production v3 resolve contract carries both `xattrs=true` and
`xattr_set_supported=false`. FSKit first validates the target item and xattr
name, then refuses set/create/replace/upsert locally, before any daemon request
or ordered mutation exists. Its internal refusal is Darwin `ENOTSUP` (45), but
the FSKit boundary returns Darwin's distinct `EOPNOTSUPP` (102): XNU treats 45
as a request to fall back to an AppleDouble `._*` file. This prevents a second
durable xattr representation from appearing beside XFS. Read, list, and
removal of a pre-existing portable attribute continue to forward normally.

Writable xattrs require a substrate with one kernel-enforced aggregate capacity
boundary. They will not be enabled by a per-inode limit or an in-memory
counter.

## Ownership

The volume model is deliberately single-principal — an agent's private
workspace, not a multi-user Unix server. Every XFS inode is owned by the volume
worker's stable unprivileged service UID/GID, each mount projects that
principal to its local mounting user, and a `chown` to a different principal
fails `EPERM`. Modes, sticky and set-ID bits, timestamps and pre-existing
portable user xattrs remain ordinary XFS state.

The coherence matrix's `remote_chown_visible` case therefore skips on v3: there
is no ownership change to observe. If multiple POSIX principals are ever
supported it becomes assertable and must be enabled. Supporting them requires an
explicit portable identity-mapping design and will not be approximated with host
IDs.

## Application compatibility

SQLite in rollback-journal mode is inside the tested compatibility contract.
SQLite WAL mode is not: its wal-index requires a shared `-shm` mapping, and
SQLite itself requires every WAL participant to be on the same host. Presenting
WAL as safe across mounts on different machines would be a false guarantee, not
ordinary shared-filesystem behaviour. Keep WAL databases local or use a
database service. See SQLite's [WAL limitations](https://www.sqlite.org/wal.html)
and [rollback-locking protocol](https://www.sqlite.org/lockingv3.html).

An open descriptor remains usable after unlink until final close; the mechanism
and its one boundary are in [open-after-unlink.md](./open-after-unlink.md).

Machine-local routes are a deliberate hole in the shared namespace: paths a
volume declares in `.portablefs/local-dirs` are served from per-machine disk and
carry no cross-mount coherence at all, by design. They are Linux-only, declared
volume-wide, and pinned to a revision the authority compares at attach. See
[graft-security.md](./graft-security.md).

## What is not claimed

- Transparent exactly-once mutation across authority death.
- Shared file-backed `mmap`.
- `syncfs(2)` on a stock ordinary-FUSE kernel; only the pinned strict kernel's
  mandatory forwarded `FUSE_SYNCFS` is a remote volume durability barrier.
- Multiple POSIX principals inside one volume.
- Writable extended attributes.
- Read caching beyond the two declared profiles. Any future caching must be a
  synchronous lease protocol, never hidden baseline behaviour.

Failure behaviour — what fences a session, what fences the store, and what an
epoch change costs — is in [failure-modes.md](./failure-modes.md).
