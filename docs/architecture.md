# Architecture

Status: **protocol-7 local full-gate qualified on stock Linux FUSE; detailed
results and production qualification boundaries are recorded in
[coherence-v2/integration.md](./coherence-v2/integration.md).**

PortableFS exposes one serving XFS project directory through multiple Linux
mounts. A volume has one canonical representation selected by `(State,
ArchiveCycleStep)`: READY uses XFS, ARCHIVED uses one sealed immutable archive,
and RESTORING composes that sealed base, a monotone hydration map, and XFS.
PortableFS adds authentication, object capabilities, replay protection,
distributed locks, subscription-governed caching, and volatile delegated file
write-back. It adds no second namespace, durable mutation journal, or offline
reconciliation. XFS remains the durable truth.

```text
stock Linux FUSE 7.31+ mounts
             |
    portablefs-mount-v3
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
3. **Cache permission excludes a peer's buffered writes.** A volume subscription
   covers undelegated identities. Granting a delegation first withdraws peer
   cache permission; a peer data/attribute read breaks the holder for read.
   A pre-existing cache-capable peer handle forces write-through.
4. **Visibility follows the acceptance boundary.** Namespace and synchronous
   mutations establish peer visibility before returning. Delegated writes are
   visible through a successful break-for-read while the holder survives; an
   accepted non-durable tail can be lost under the declared failure rules.
   An overlapping operation may linearize on either side.
5. **The wire is exact.** Authority protocol 7 uses ALPN
   `portablefs-authority-v7`, paired authenticated transports, exact feature
   assertions, and session-bound replay. Protocol 6 is refused; there is no
   compatibility path.
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

## Linux cache and I/O profile

The volume subscription lasts ten seconds on the Authority clock and renews
every three. The client anchors its horizon at request start and begins cache
withdrawal early. Replies carry served versions and drain through exact
identity/name publication gates before acknowledgment. Shared kernel names
have zero validity; the daemon caches their bindings. Inode notifications
withdraw clean pages and attributes. Directory iteration continues from XFS
cookies across mutation, returning every unmodified entry once without ESTALE.

Write-capable handles use direct I/O and kernel write-back stays off. The daemon
buffer is bounded at 64 MiB and 10,000 entries; timer, cap, recall, fsync,
namespace dependencies, and root-directory barriers trigger flushing. Entries
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

| Platform | Status |
| --- | --- |
| Linux FUSE 7.31+ | Protocol-7 local real-mount qualification; broader kernel and deployed-runner qualification remain separate. |
| macOS 26/27 FSKit | Explicit `FSKIT_SYNC_REPAIR` profile with compatibility-writer exclusion for every attached Mac mount. Host cache, append, and lock edges remain weaker than Linux. |
| Files gateway | Authenticated cacheless peer reader; breaks delegated files for read and does not exclude Linux writers. |
| Windows | No declared transport or production frontend. |

A TTL, polling loop, or policy label cannot supply missing host-filesystem
primitives. No FSKit or Windows production qualification is inferred from the
Linux gates.

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
| Frozen wire, CLI, routing, and release surfaces | [COMPATIBILITY.md](../COMPATIBILITY.md) |
| Subscription/delegation protocol and stock-FUSE proofs | [portable-coherence.md](./portable-coherence.md) |
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

Protocol-5 qualification receipts, the Linux 6.12.100 private ABI description,
and the private-kernel vNext specification are retained as historical
implementation records; the ABI's kernel patch series itself is only in git
history. None of them defines the protocol-7 product.
