# PortableFS authoritative-XFS architecture

Status: **v3 architecture decision and implementation contract**

PortableFS v3 is a remote gateway to ordinary, authoritative directories on
XFS. XFS and the block device beneath it are the only durable filesystem
state. PortableFS does not maintain a second inode tree, content index,
permanent operation history, branch graph, or write-back overlay.

This is a deliberate v3 compatibility reset. It does not silently change the
frozen v2 contract in `COMPATIBILITY.md`; v2 clients and v3 authorities fail
their version handshake rather than enter a mixed mode.

## Root design

```text
Linux FUSE mount     future verified FSKit mount     another mount
       |                       |                    |
       +---------- authenticated TLS RPC ----------+
                               |
                     volume routing endpoint
                               |
                    one active authority epoch
                               |
                descriptor-relative Linux syscalls
                               |
                   /srv/portablefs/<volume-id>
                       XFS project directory
                               |
                    encrypted SSD / AWS EBS
```

The data plane has one active authority for a volume. Many volumes may share a
storage cell, but every request is bound to exactly one volume capability and
one authority epoch. Clients never mount or attach the block device.

The control plane stores identity, organization membership, volume placement,
policy, quota entitlements, billing metadata, and short-lived credentials. It
does not store file bytes, inode metadata, directory entries, locks, or the
current filesystem tree and is not on the per-operation data path.

## Source of truth

For a live volume, the source of truth is exactly the mounted XFS instance:
its server-side VFS/page-cache state, metadata journal, and persisted device
state. Unflushed page-cache data is authoritative current state but is not
durable across power loss; `fsync` is the boundary that asks XFS and the device
to persist it.

Runtime authority state is disposable: connections, open file descriptors,
advisory locks, cancellation state, and bounded reply slots for the current
epoch. Losing that RAM interrupts mounts, but cannot roll the durable
filesystem back to a different logical tree.

There is no PortableFS checkpoint, manifest head, custom mutation log,
segmented store, Pebble index, or garbage collector. EBS snapshots are
operator backups and never participate in reads, writes, cache coherence, or
the user-visible namespace.

## Ordinary filesystem semantics

The authority translates one RPC into the corresponding Linux operation. XFS
supplies inode allocation, directory structure, hard links, symlinks, sparse
files, timestamps, atomic rename, allocation accounting, metadata
journaling, and crash replay. Its journal is an internal crash-recovery
mechanism, not PortableFS history; see the
[kernel XFS logging design](https://docs.kernel.org/5.17/filesystems/xfs-delayed-logging-design.html).

PortableFS preserves these boundaries:

- A successful `write` means server `pwrite`/`write` accepted the reported
  bytes into authoritative XFS state. No acknowledged bytes exist only in an
  unsent client cache.
- A successful `fsync` means the authority successfully completed `fsync(2)`
  or `fdatasync(2)` on the authoritative open file description, with the normal
  [Linux durability contract](https://man7.org/linux/man-pages/man2/fsync.2.html).
- `close` is not an implicit `fsync`.
- On the current regular-FUSE Linux interface, `syncfs(2)` does not issue a
  userspace `FUSE_SYNCFS` request (the kernel currently enables that request
  only for `fuseblk`). Applications must use file and directory `fsync` for a
  remote durability boundary. PortableFS does not pretend the local-only
  `syncfs` completion flushed XFS on the authority; this follows the
  [current kernel implementation](https://github.com/torvalds/linux/blob/master/fs/fuse/inode.c#L721-L759).
- A namespace operation is atomically visible when the XFS syscall completes.
  An application that needs it durable across power loss syncs the changed
  file and affected parent directory or directories, as on local Linux.
- An open descriptor remains usable after unlink until final close. The
  authority retains the real server descriptor; there is no orphan table.
- Two whole-file replacements are ordered atomic renames. The later ordered
  rename is visible. PortableFS does not merge file contents.
- POSIX record locks and BSD `flock` locks are authority-epoch runtime state.
  `FLUSH` removes a closing process owner's POSIX locks, final `RELEASE`
  removes an open-description flock, and session expiry/restart removes every
  remaining lock. The two lock namespaces remain independent, as on local
  Linux.

The server is the only supported writer to a volume tree. Operators, sidecars,
and backup agents must not mutate it behind the authority because those writes
cannot participate in authorization or cache coherence.

## Object identity and confinement

Requests are object-relative, not path-relative. Attach returns an opaque root
token. Lookup accepts a parent token and one raw filename component. Later
operations use object or open-handle tokens.

The Linux frontend owns the FUSE `NodeID` table and kernel lookup reference
counts directly. A successful authority lookup returns a fresh object
capability. Under one frontend mutex, the client either installs it as a new
`NodeID`, or increments the already-known inode's lookup count and reclaims the
duplicate capability. `FORGET` decrements that same table and queues the exact
capability for reclamation only when the final lookup reference disappears.
This avoids both an O_PATH descriptor leak and a stale-token race during
concurrent lookup/forget; it is why v3 uses the raw FUSE interface instead of a
high-level inode wrapper that can discard a candidate only after the callback
returns. A full bounded reclaim queue is a fatal mount/session condition, never
permission to drop ownership records.

The authority:

- opens the volume root once and treats its descriptor as the capability root;
- rejects empty names, NUL, `/`, `.`, `..`, and components over `NAME_MAX`;
- uses `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, and
  `RESOLVE_NO_XDEV`, plus `O_NOFOLLOW` when addressing a symlink itself;
- uses descriptor-relative `*at` syscalls for namespace changes;
- verifies every object is on the expected device;
- never accepts a host path or client-supplied inode number;
- binds each token to volume ID, epoch, kind, and a random server table entry;
- rejects cross-volume link and rename by construction; and
- invalidates all tokens on epoch change.

Symlink contents are stored and returned exactly, including absolute or
escaping targets. The mounting kernel performs normal symlink traversal; the
authority never follows client-controlled symlinks while addressing XFS.

Only regular files, directories, and symlinks may be created. Device nodes,
FIFOs, sockets, setuid execution, user-xattr writes, privileged xattrs,
cross-filesystem mount traversal, and exported kernel handles are denied.
Storage is mounted `nodev,nosuid,noexec`; encryption at rest and in transit is
mandatory.

## Ordering and retry semantics

Linux VFS/XFS provides each syscall's atomicity. The authority adds only:

1. validate the TLS peer, volume access claim, session, epoch, capability, and
   operation identity;
2. execute the descriptor-relative XFS operation;
3. retain the bounded exact reply in that session's replay slot; and
4. return the result.

Different replay slots may execute concurrently. XFS supplies the same
operation atomicity and locking it supplies to local processes; PortableFS does
not serialize an entire volume behind a userspace global mutex.

There is no honest way to atomically commit an arbitrary XFS syscall and a
separate durable reply record. PortableFS makes the boundary explicit:

- Duplicate delivery inside a live epoch returns the cached outcome and never
  re-executes the operation.
- A client never automatically replays an uncertain mutation across an epoch.
- If an authority dies after XFS applies a mutation but before its reply is
  received, that request has an `UNCERTAIN` transport outcome and the mount is
  re-established. The application may inspect current state and decide.
- Side-effect-free calls may reconnect and retry only inside the same authority
  epoch. No request—read or mutation—is silently continued across an epoch.
  Mutations use exact same-epoch replay slots; append and namespace outcomes are
  never guessed.

This gives session-exact execution without inventing a second durable truth.
Transparent exactly-once semantics across server death are not claimed.

## Cache coherence

The exact Linux baseline has no distributed cache protocol. Regular files open
with FUSE direct I/O, attributes and positive/negative dentries have zero TTL,
and write-back caching is disabled. Every completed read and write therefore
crosses the authority; there is no stale client page that an asynchronous
notification must race.

Shared file-backed `mmap` is deliberately unsupported in this baseline.
PortableFS does not advertise `FUSE_DIRECT_IO_ALLOW_MMAP`, so Linux rejects
both writable and read-only `MAP_SHARED` mappings instead of creating mapped
pages that the authority cannot revoke coherently. `MAP_PRIVATE` remains
available: it is a process-local copy-on-write view, never writes through to
the underlying file, and POSIX leaves visibility of later external file changes
unspecified. That is ordinary filesystem behavior rather than a distributed
coherence promise. This follows the kernel's documented [distinction between
FUSE cached, direct, and write-back modes](https://cdn.kernel.org/doc/html/latest/filesystems/fuse/fuse-io.html)
and the [`MAP_PRIVATE` contract](https://man7.org/linux/man-pages/man2/mmap.2.html).

SQLite rollback-journal mode is part of the tested Linux compatibility
contract. SQLite WAL mode is not: its wal-index requires a shared `-shm`
mapping, and SQLite itself requires every WAL participant to be on the same
host. Presenting WAL as safe across PortableFS mounts on different machines
would be a false guarantee, not ordinary shared-filesystem behavior. Workloads
that require SQLite WAL must keep that database local or use a database service.
See SQLite's [WAL limitations](https://www.sqlite.org/wal.html) and
[rollback-locking protocol](https://www.sqlite.org/lockingv3.html).

This is intentionally less complex and may be slower over a high-RTT network.
Read caching is a future measured optimization, not hidden baseline behavior.
If measurements or application compatibility require caching or shared
file-backed mapping, the only acceptable extension is a synchronous lease protocol: a
writer waits until every live holder has flushed any authorized dirty mapping
and completed kernel invalidation, or fences an expired holder, before changing
XFS. An asynchronous event stream by itself is insufficient because a peer
could read stale pages before processing the event. Ordinary client dirty
write-back remains out of scope.

Apple's June 2026 FSKit beta adds `DataCacheHandler`, `noCache`, synchronous
cache-state changes, invalidate, and revoke. The locally installed Xcode 26.6 /
macOS 26.5 SDK does not contain those APIs. macOS production support therefore
remains gated on a selected non-beta minimum OS plus direct tests for data,
attributes, positive and negative dentries, rename, unlink, writable mappings,
and failed revocation. There is no legacy refresh workaround in v3.
The platform gate is tracked against Apple's
[FSKit updates](https://developer.apple.com/documentation/updates/fskit) and
[`DataCacheHandler`](https://developer.apple.com/documentation/fskit/fsvolume/datacachehandler),
not inferred from asynchronous notifications.

## Multi-tenancy and quotas

Each volume is an XFS project directory with `PROJINHERIT`. Project block and
inode quotas come from the customer's entitlement. PortableFS has no universal
one-GiB memory or volume limit. Cell admission follows measured SSD capacity,
IOPS, throughput, memory, descriptors, and recovery SLO.

Short-lived capability claims include subject, volume, read/write access,
credential validity, peer-certificate identity, and a nonce. Authorization
precedes handle resolution. Capability expiry is an absolute session deadline,
not something keepalive can renew. Per-tenant concurrency and I/O scheduling
protect unrelated volumes; quota errors remain the kernel's `EDQUOT`/`ENOSPC`
outcomes.

The unprivileged request process verifies the root's project ID and
`PROJINHERIT` flag but deliberately has no quota-administration capability.
Privileged provisioning and monitoring attest each project's block/inode hard
limits; XFS enforces them. `statfs` retains the ordinary local-XFS meaning of
cell-wide physical capacity, while quota/billing APIs report the purchased
per-volume entitlement. Granting the authority `CAP_SYS_ADMIN` merely to query
quota records would weaken the tenant boundary.

XFS attribute-fork blocks are
[not charged to project quotas](https://www.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf).
Project quotas therefore cannot isolate user-xattr writes on a shared cell, and
a PortableFS counter could not commit atomically with XFS. Launch does not
expose `setxattr`: the Linux frontend and direct authority requests return
`EOPNOTSUPP`. Read, list, and removal remain available for pre-existing
portable `user.*` attributes. Writable xattrs require a future substrate with
one kernel-enforced aggregate capacity boundary; they are not enabled by a
per-inode limit or an in-memory counter.

The initial volume model is deliberately single-principal, like an agent's
private workspace rather than a multi-user Unix server. Every XFS inode must be
owned by the volume worker's stable, unprivileged service UID/GID. Each mount
projects that principal to its local mounting user; a request to chown to a
different principal fails `EPERM`. Modes, sticky/set-ID bits, timestamps, and
pre-existing portable user xattrs remain XFS state. Supporting multiple
independent POSIX principals inside one volume would require an explicit
portable identity-mapping design and is not silently approximated with host
IDs.

Every worker also has explicit deployment-sized bounds for live sessions,
same-epoch replay slots, held/waiting lock records, in-flight requests, frame
allocations, descriptors, tasks, and process memory. These are denial-of-service
admission controls, not universal volume-size or product-memory limits. Because
launch isolates one worker per volume, exhausting them can fail that volume but
cannot consume another tenant's worker state.

The request-serving process refuses to run as root. Provisioning assigns the
project directory to its stable service UID/GID before startup. Production
runs it in a private mount/user namespace with a syscall allowlist and access
only to that volume root. Volume roots are not exposed to agent containers or
sandboxes.

## Launch topology and failure model

Launch uses one Nitro EC2 instance and one encrypted, non-Multi-Attach EBS
volume formatted XFS. The EBS volume outlives the instance
(`DeleteOnTermination=false`). Same-AZ instance replacement is: fence the old
process, detach, attach, mount/replay XFS, increment epoch, accept clients.

This is single-AZ durable storage, not cross-AZ HA. EBS replicates within one
AZ. SLOs must use those facts rather than call one volume a replica set.

Optional active-passive HA is a separate topology, never another write path. It
requires independent fencing, one-writer enforcement, epoch advancement, and
destructive split-brain tests:

- Same-AZ compute HA may use Multi-Attach io2, NVMe reservations, and external
  STONITH, with XFS mounted read-write on exactly one host.
- Cross-AZ HA needs two devices plus synchronous replication, quorum, and
  fencing, or a separately validated managed multi-AZ filesystem.

Heartbeats, DNS, and leases do not fence an old writer. Force-detach is an
emergency action, not a promotion protocol.

After restart/failover, sessions, locks, tokens, and open handles are
stale. Unlinked-but-open files cannot be recovered after their last server fd
is lost; affected applications receive `ESTALE`/`EIO`.

Any storage `EIO` permanently fences the active store and terminates that
authority epoch. It never remains ready and attempts more mutations against a
possibly shut-down or detached filesystem.

## Backups

Backups protect against deletion, bugs, compromised credentials, and operator
error that a live replica would faithfully copy. They are outside filesystem
semantics. The backup controller freezes or syncs XFS, takes an
application-consistent EBS snapshot, unfreezes promptly, locks/copies it per DR
policy, and exercises restores. Users see no snapshot, commit, branch, or
historical namespace.

## Deliberate boundaries

- One volume has one active server and one machine's throughput ceiling.
- Cross-region syscall latency is not hidden; place authority near clients.
- Memory scales with active sessions, handles, locks, and bounded retry
  slots—not stored files or keys.
- Unsupported FUSE/FSKit operations fail explicitly; they are not emulated with
  divergent semantics.

Scale comes from placing volumes across cells and moving hot volumes to a
dedicated cell. A measured need for one volume to exceed one cell is a decision
to adopt a distributed filesystem, not to grow a custom inode database here.

## Proof required before production

1. XFS comparison on repositories, package installs, compilers, metadata
   storms, large I/O, sparse files, and concurrent mounts.
2. FUSE and target-version FSKit coherence tests for data, attributes,
   positive/negative dentries, rename-over, unlink, rejection of unsupported
   mappings, and any future synchronously leased mappings.
3. Confinement fuzzing for symlink races, mount grafts, hard links, rename
   exchange, malformed names, stale tokens, and cross-volume attempts.
4. File/directory sync fault tests over process kill, kernel crash, detach,
   full disk, quota exhaustion, short writes, and injected `EIO`.
5. Multi-tenant saturation tests proving bounded RAM/descriptors and fair
   progress for unrelated volumes.
6. Recovery drills from live EBS and locked backup with measured RTO/RPO.

The segmented-log experiment remains evidence about append-only write
amplification. It is not a production dependency and did not compare the
prototype with XFS on PortableFS workloads.
