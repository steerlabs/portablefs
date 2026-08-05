# Consistency model

Status: **v3 application-visible contract**

PortableFS v3 has one source of truth per volume: the mounted XFS instance the
authority addresses. Everything the authority itself holds — sessions, open
file descriptions, advisory locks, same-epoch replay slots, cancellation state
— is disposable epoch state. There is no second inode tree, no mutation log, no
client write-back cache, and no history. The architectural decision behind that
is in [xfs-authority-architecture.md](./xfs-authority-architecture.md).

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
`ProtocolMajor = 2` and its ALPN identifier is `portablefs-authority-v2`
(`vcs/internal/authorityrpc/protocol.go`). That is the *protocol's* major
version, not the product's. It is unrelated to the retired v2 architecture, and
a v2 client and a v3 authority fail their handshake rather than enter a mixed
mode.

## Write acceptance and durability

There are no layers here. Acceptance and application are the same event.

- **`write(2)` returns only after the authority has applied the bytes to XFS.**
  There is no client write-back engine, no local mutation log, and therefore no
  local durability debt. An acknowledged byte never exists only in an unsent
  client buffer.
- **`fsync`/`fdatasync` wait on the authoritative server file description.** A
  successful return means the authority completed `fsync(2)` or `fdatasync(2)`
  against that descriptor, with the ordinary
  [Linux durability contract](https://man7.org/linux/man-pages/man2/fsync.2.html).
- **`close` is not an implicit `fsync`.** It never has been on Linux and it is
  not here.
- **`syncfs(2)` is not a remote durability boundary on ordinary FUSE.** The
  kernel currently issues `FUSE_SYNCFS` only for `fuseblk` mounts, so a
  `syncfs` completion on a PortableFS mount says nothing about XFS on the
  authority. Applications use file `fsync` plus `fsync` of the changed parent
  directory or directories, exactly as on local Linux. PortableFS does not
  pretend otherwise; see the
  [current kernel implementation](https://github.com/torvalds/linux/blob/master/fs/fuse/inode.c#L721-L759).
- **A namespace operation is atomically visible when its XFS syscall
  completes.** Making it durable across power loss is the caller's ordinary
  file-and-directory `fsync` discipline.
- **Two whole-file replacements are ordered atomic renames.** The later ordered
  rename wins. PortableFS never merges file contents.

Because there is no client-side durability debt, `umount --force` has nothing
to park and nothing to replay: it only gives up on proving the drain.

## Cross-mount visibility

The application-visible boundary is the same on both Linux profiles: if a
mutation `M` returned success before an operation `R` began on any mount of the
same volume, `R` does not observe namespace, attributes, size, or data older
than `M`, unless something ordered after `M` changed them again. An operation
that overlaps `M` may observe either side, as it could between two processes on
one machine.

Two profiles reach that boundary by opposite means, and `--coherence` selects
between them (`vcs/internal/fusev3`):

- **`uncached`** (Linux only) caches nothing, so there is nothing to
  invalidate. Entry and attribute timeouts are zero on every reply, regular
  files open with `FOPEN_DIRECT_IO`, and every `read(2)`, `stat(2)` and path
  resolution reaches the authority. There is no invalidation schedule that can
  be late, because there is no cached answer to be stale. The cost is that a
  repeated read cannot be served without a round trip.
- **`strict`** (the default) caches names and attributes in the kernel and pays
  for them by executing the authority's visibility barrier synchronously: for a
  cache-visible mutation, every strict participant receives PREPARE, the XFS
  syscall runs, and peers repair and acknowledge COMPLETE *before* the
  mutation's reply is returned to its caller. The initiating mount receives a
  deferred COMPLETE and must acknowledge its own kernel publication before its
  next mutation. Visibility polling and acknowledgements use a reserved client
  lane so the event stream cannot consume the last ordinary request slot.

Both profiles are held to the same contract and are run against the same case
list by `scripts/coherence-matrix-linux.sh`
(`PORTABLEFS_COHERENCE=strict|uncached`), because the entire point is that an
application cannot tell them apart. That matrix is black box: it drives two
real mountpoints through ordinary syscalls, compares content against the bytes
a descriptor actually returns when read to EOF rather than against `stat.Size`,
compares the namespace against the entries `readdir` actually enumerates,
compares an atomic replacement against the inode number the *other* mount
resolves, and never polls or retries. It also proves a red result is reachable
before reporting a green one. See
[cross-mount-coherence-matrix.md](./cross-mount-coherence-matrix.md).

When no strict participant is attached, the volume-wide visibility ticket is
absent entirely and ordinary XFS concurrency is unchanged. The serialization
exists only to close kernel publication gates, not to serialize the filesystem.

### macOS

`portablefs mount` on macOS runs the portablefsd v3 data plane plus the FSKit
extension under the declared compatibility cache policy
`macos26-synchronous-vfs-repair-v1`. FSKit requires `--coherence strict`;
`uncached` is Linux-only and the CLI says so rather than silently downgrading.
That policy's bounded semantics, its unmet gates, and the reasons it must not
be treated as a silent fallback are in
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

- **Duplicate delivery inside a live epoch returns the cached outcome.** A
  replayed identity whose request hash matches the recorded one returns the
  stored outcome and never re-executes
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
frontend and a direct authority request return `EOPNOTSUPP`. Read, list and
remove of pre-existing portable `user.*` attributes remain available;
`vcs/internal/xfsstore` (`ValidateXattr`) admits only the `user.` namespace and
excludes the reserved `user.portablefs.` prefix, so internal metadata,
`security.*`, ACL internals and `trusted.*` never cross the remote boundary.

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
- `syncfs(2)` as a remote durability barrier on ordinary FUSE.
- Multiple POSIX principals inside one volume.
- Writable extended attributes.
- Read caching beyond the two declared profiles. Any future caching must be a
  synchronous lease protocol, never hidden baseline behaviour.

Failure behaviour — what fences a session, what fences the store, and what an
epoch change costs — is in [failure-modes.md](./failure-modes.md).
