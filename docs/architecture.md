# Architecture

Status: **protocol 8, specified and not yet qualified.** The open gates are
listed in [COMPATIBILITY.md](../COMPATIBILITY.md#qualification-status); results
from earlier protocols are not evidence for this one.

PortableFS exposes one serving XFS project directory through multiple Linux
mounts, at most one macOS mount at a time as the sole writer, and an
authenticated cacheless gateway. A volume has one canonical representation selected by `(State,
ArchiveCycleStep)`: READY uses XFS, ARCHIVED uses one sealed immutable archive,
and RESTORING composes that sealed base, a monotone hydration map, and XFS.
PortableFS adds authentication, object capabilities, replay protection,
distributed locks, subscription-governed caching, and volatile delegated file
write-back. It adds no second namespace, durable mutation journal, or offline
reconciliation. XFS remains the durable truth.

```text
stock Linux FUSE 7.31+ mounts      macOS FSKit mount      files gateway
             |                    (exclusive writer)   (cacheless reader)
             +------------------------+---------------------+
                                      |
                       mutually authenticated TLS 1.3
                        DATA + CONTROL connection pair
                                      |
                     portablefs-authority (one per volume)
                                      |
                      descriptor-relative Linux syscalls
                                      |
                   one XFS project directory (PROJINHERIT)
```

## Product invariants

1. **The state selects one authority.** READY and RESTORING volumes have exactly
   one authority over one provisioned XFS subtree. An ARCHIVED volume has no XFS
   placement or authority and is represented by its sealed archive. During
   RESTORING, a hydration mark selects XFS for that chunk; otherwise the sealed
   base is authoritative. No state has two writable truths.
2. **Namespace and data have distinct acceptance boundaries.** Namespace
   mutations execute at the Authority. Uncontended file delegations permit
   daemon-buffered data and attributes; fsync/O_SYNC wait for durability.
   A run opens the mount root at start and fsyncs that handle at completion.
   FSKit has no fsync callback, so every successful macOS mutation reply is
   itself durable on the authority.
3. **Cache permission excludes a peer's buffered writes.** A volume subscription
   covers undelegated identities. Granting a delegation first withdraws peer
   cache permission; a peer data/attribute read breaks the holder for read.
   A pre-existing cache-capable peer handle forces write-through.
4. **Visibility follows the acceptance boundary.** Namespace and synchronous
   mutations establish peer visibility before returning. Delegated writes are
   visible through a successful break-for-read while the holder survives; an
   accepted non-durable tail can be lost under the declared failure rules.
   An overlapping operation may linearize on either side.
5. **The wire is exact.** Authority protocol 8 uses ALPN
   `portablefs-authority-v8`, paired authenticated transports, an immutable
   frontend profile, and session-bound replay. There are no feature strings;
   an unequal major is refused at the handshake.
6. **The kernel interface is upstream FUSE.** Linux requires FUSE protocol 7.31
   or newer and uses no PortableFS capability bit, opcode, notification, cache
   stamp, completion ring, or publication receipt.
7. **Failure is scoped.** A broken session is fenced without converting an
   already-applied mutation into a weaker answer. Storage failure fences the
   volume epoch. Unknown outcomes across authority death are reported as
   uncertain, never guessed or replayed automatically.
8. **Unsupported is explicit.** Shared writable file-backed `mmap`, user xattr writes,
   device nodes, FIFOs, sockets, and cross-volume rename are refused with a real
   errno rather than emulated with divergent semantics.
9. **Lifecycle control stays outside ordinary I/O.** The manager records
   placement, entitlement, PKI, authorization, desired state, and observations;
   it never stores filesystem bytes. The hydrator is a serving dependency only
   while one volume is RESTORING. The manager never enters that data path.
10. **A storage cell is one durability domain.** Volumes in one XFS cell share
    its superblock: a writeback or log failure from any project can fence any
    volume at its next filesystem-wide barrier, and other projects' dirty data
    lengthens that barrier. Isolation requires separate filesystems; see
    [COMPATIBILITY.md](../COMPATIBILITY.md#two-limits-that-apply-to-every-deployment).

## Linux cache and I/O profile

The volume subscription lasts ten seconds on the Authority clock and renews
every three. The client anchors its horizon before request queueing and begins
cache withdrawal early. Linux uses suspend-inclusive `CLOCK_BOOTTIME` for
subscription anchors, receipt/renewal validation, every cache/delegation admission,
and authority subscription/delegation and session/lock deadlines. Each admission
checks the horizon even before CONTROL or timers run after resume; expiry closes
permission and requires cold withdrawal. Timers only wake workers. Replies carry
served versions and drain through exact identity/name publication gates before
acknowledgment. Shared kernel names
have zero validity; the daemon caches their bindings. Inode notifications
withdraw clean pages and attributes. Directory iteration continues from XFS
cookies across mutation, returning every unmodified entry once without ESTALE.

Write-capable handles use direct I/O and kernel write-back stays off. The daemon
buffer is bounded at 64 MiB and 10,000 entries; producer/completion events, cap
pressure, recall, fsync, namespace dependencies, and root-directory barriers
trigger flushing. Entries
remain until durability is confirmed. A missed recall advances loss and stales
the affected handles instead of aborting the mount. An epoch change stales all
old handles; cold reattachment permits new opens, not recovery of old handles.

The namespace contract covers forward pathname resolution and enumeration.
Reverse rendering of retained dentries (`getcwd`, `/proc/*/fd`, and `d_path`)
is outside it. Append uses the Authority's true EOF; stock FUSE does not expose
per-call RWF_APPEND/RWF_NOAPPEND, which remain disclosed deviations.

The normative model and verbatim design residuals are in
[portable-coherence.md](./portable-coherence.md). Application behavior is in
[consistency-model.md](./consistency-model.md).

## Platform status

| Platform | Profile and status |
| --- | --- |
| Linux FUSE 7.31+ | `FRONTEND_PROFILE_LINUX`: subscriptions and file write delegations. Protocol-8 real-mount qualification pending. |
| macOS 26/27 FSKit | `FRONTEND_PROFILE_FSKIT_EXCLUSIVE`: the volume's only writer while mounted; Linux peers read; a second Mac is refused. Successful mutation replies are durable on authority storage; no kernel cache revocation, append intent, or advisory locks. Native qualification pending. |
| Files gateway | `FRONTEND_PROFILE_CACHELESS_READER`: authenticated read-only peer; breaks delegated files for read and does not exclude writers. |
| Windows | No declared transport or production frontend. |

A TTL, polling loop, or policy label cannot supply missing host-filesystem
primitives. No FSKit or Windows qualification is inferred from the Linux gates.
The macOS contract, including why the Mac is an exclusive writer and what
terminal enforcement cannot withdraw from the kernel, is in
[fskit-mount.md](./fskit-mount.md).

## Security and routing

Authority requests are object-relative and confined beneath a pre-opened volume
root. The authority runs as the volume's unprivileged service identity; project
quotas and pinned mount topology bound the XFS subtree. Each volume is currently
single-principal. User xattr writes are refused because XFS attribute-fork blocks
are not charged to project quota.

`.portablefs/local-dirs` is the one deliberate exception to shared namespace:
matched subtrees live on each Linux machine and never reach the authority. Its
canonical rule revision is authority-controlled and must match at Attach.
Route CAS uses a separate admin-only session purpose. It has no filesystem
root, subscriptions, delegations, or durable mount membership and is authority-enforced to
route/session operations. ApplyRoutes still returns `EBUSY` while any active,
fenced, or durably unproven mount may retain an older LOCAL topology.

## Hosted lifecycle

The optional manager, cell agent, and root helper allocate and supervise
authorities but are not on filesystem I/O. The authority data plane remains a
direct mutually authenticated connection from mount to volume. Client keys are
generated on the mount host and are never delivered by the manager.

Archive and wake are typed lifecycle transitions. The archiver reads a quiesced
volume and seals an immutable attempt-addressed manifest and packs; a RESTORING
volume serves through the hydrator until all sealed chunks converge into XFS.
Neither mechanism creates a live mutation log or a second writable truth.

## Contract map

| Subject | Document |
| --- | --- |
| Launch contract: versions, profiles, frozen surfaces, qualification status | [COMPATIBILITY.md](../COMPATIBILITY.md) |
| Authority wire encoding and handshake | [coherence-v2/wire.md](./coherence-v2/wire.md) |
| Subscription/delegation protocol and stock-FUSE proofs | [portable-coherence.md](./portable-coherence.md) |
| macOS FSKit mount | [fskit-mount.md](./fskit-mount.md) |
| Visibility, durability, replay, locks, mmap, and xattrs | [consistency-model.md](./consistency-model.md) |
| Failure and fencing | [failure-modes.md](./failure-modes.md) |
| XFS confinement and storage implementation | [xfs-authority-architecture.md](./xfs-authority-architecture.md) |
| Deployment | [xfs-authority-deployment.md](./xfs-authority-deployment.md) |
| Hosted placement, credentials, reauthorization, and fencing | [hosted-control-plane.md](./hosted-control-plane.md) |
| Deploying a hosted XFS cell | [hosted-cell-deployment.md](./hosted-cell-deployment.md) |
| Archive identity, lifecycle, capacity, and restore ordering | [tiered-storage/identity-lifecycle-and-capacity.md](./tiered-storage/identity-lifecycle-and-capacity.md) |
| Promoting one matched release to OpenSteer | [opensteer-production-deployment.md](./opensteer-production-deployment.md) |
| Machine-local routing | [graft-security.md](./graft-security.md) |
| Black-box qualification | [cross-mount-coherence-matrix.md](./cross-mount-coherence-matrix.md) |
| Power-cut durability evidence | [power-loss-testing.md](./power-loss-testing.md) |
| Measurement method and the LAN target | [performance.md](./performance.md) |

Superseded designs, dated qualification receipts, and earlier protocol
generations live only in git history.
