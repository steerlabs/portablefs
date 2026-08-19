# Architecture

Status: **protocol-6 target contract; writable Linux is blocked from production
by unobservable `RWF_APPEND`, while FSKit remains supported under an explicitly
weaker synchronous-repair profile**

PortableFS exposes one authoritative XFS project directory through multiple
Linux mounts. XFS is the only durable filesystem truth. PortableFS adds
authentication, object capabilities, replay protection, distributed locks, and
lease-governed caching; it does not add a second inode tree, a mutation journal,
or client write-back storage.

```text
stock Linux FUSE 7.31+ mounts
             |
        portablefsd
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

1. **XFS is authoritative.** Files, directories, attributes, open handles, and
   rename/unlink semantics are executed against the provisioned XFS subtree.
2. **Mutations are write-through.** A successful Linux mutation response means
   the authority applied the operation to XFS and discharged every conflicting
   peer cache lease. `fsync` and `fdatasync` remain the durability barriers.
3. **Caching is a revocable right.** The authority grants TTL-bounded leases for
   a name binding N(parent,name), attributes A(inode), clean whole-file data
   D(inode), and complete directory enumeration E(directory). A cache entry
   without a live covering lease is not served.
4. **The syscall response is the visibility boundary.** An acquisition that
   begins after a successful mutation returns observes that mutation or a later
   one. An overlapping operation may linearize on either side.
5. **The wire is exact.** Authority protocol 6 uses ALPN
   `portablefs-authority-v6`, paired authenticated transports, exact feature
   assertions, and session-bound replay. Protocol 5 is refused; there is no
   compatibility path.
6. **The kernel interface is upstream FUSE.** Linux requires FUSE protocol 7.31
   or newer and uses no PortableFS capability bit, opcode, notification, cache
   stamp, completion ring, or publication receipt.
7. **Failure is scoped.** A broken session is fenced without converting an
   already-applied mutation into a weaker answer. Storage failure fences the
   volume epoch. Unknown outcomes across authority death are reported as
   uncertain, never guessed or replayed automatically.

## Linux cache and I/O profile

Kernel name validity is always zero. Attribute validity ends at a conservative
cache deadline computed from the authority TTL minus the frozen five-second
withdrawal interval and anchored at the client request start, so time spent in
flight can only shorten the installed validity. The
daemon may retain a name answer under its N lease. Plain READDIR is cached by the daemon
only under an E lease; kernel directory caching and READDIRPLUS are not used. Read-only file
opens may preserve clean kernel pages under a D lease. Write-capable opens use
direct I/O, writeback caching is disabled, and shared writable mappings are
refused.

The daemon orders cache-installing replies and invalidation notifications per
coordinate. Metadata replies may use a separate zero-validity lane. Buffered
READ has no validity field: an already-admitted reply drains before recall
acknowledgment, while a new request at a closed cut receives `EAGAIN` without
parking behind invalidation. A peer discharges a recall only after a full
whole-file purge. Range-successor continuity is not part of v1. The mutating
mount purges A/D/E and daemon N state before its reply. Kernel entry validity is
always zero, including under N-R, so stock rename cannot transplant an old
leased timeout and no post-write namespace receipt is required.

The namespace contract covers forward pathname resolution and directory
enumeration. Reverse rendering of an already-held dentry (`getcwd`,
`/proc/*/fd`, and other `d_path` users) is not coherent across remote renames:
stock Linux does not revalidate that observation and exposes no FUSE completion
receipt for it. This boundary is explicit rather than inferred from a zero
entry timeout.

Stock FUSE preserves enough open intent to refuse `O_APPEND`, but does not
forward `RWF_APPEND` at all. That path cannot be detected or refused by the
daemon. It is a hard correctness blocker for declaring the writable protocol-6
profile production-ready; an upstream ABI or different proven architecture is
required.

The complete normative model, including the two disclosed stock-FUSE data-cache
residuals, is [portable-coherence.md](./portable-coherence.md). Filesystem-level
semantics are summarized in [consistency-model.md](./consistency-model.md).

## Platform status

| Platform | Status |
| --- | --- |
| Linux FUSE 7.31+ | The protocol-6 implementation target. Read-only/metadata work remains under qualification; the writable profile is blocked from production by unobservable `RWF_APPEND`. |
| macOS 26/27 FSKit | Supported through the explicit protocol-6 `FSKIT_SYNC_REPAIR` profile. It uses ordered PREPARE/COMPLETE repair rather than N/A/D/E grants and is intentionally weaker at host-cache, append, and lock edges. |
| Windows | No declared transport. A future frontend must prove the same locks, invalidation, and lease-discharge contract before admission. |

The FSKit profile is not silently promoted to Linux semantics. A TTL, polling
loop, or policy label cannot manufacture a missing host-filesystem primitive;
the differences are part of the declared platform contract.

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
root, leases, or durable mount membership and is authority-enforced to
route/session operations. ApplyRoutes still returns `EBUSY` while any active,
fenced, or durably unproven mount may retain an older LOCAL topology.

## Hosted lifecycle

The optional manager, cell agent, and root helper allocate and supervise
authorities but are not on filesystem I/O. The authority data plane remains a
direct mutually authenticated connection from mount to volume. Client keys are
generated on the mount host and are never delivered by the manager.

## Contract map

| Subject | Document |
| --- | --- |
| Frozen wire, CLI, routing, and release surfaces | [COMPATIBILITY.md](../COMPATIBILITY.md) |
| Lease protocol and stock-FUSE proof obligations | [portable-coherence.md](./portable-coherence.md) |
| Visibility, durability, replay, locks, mmap, and xattrs | [consistency-model.md](./consistency-model.md) |
| Failure and fencing | [failure-modes.md](./failure-modes.md) |
| XFS confinement and storage implementation | [xfs-authority-architecture.md](./xfs-authority-architecture.md) |
| Deployment | [xfs-authority-deployment.md](./xfs-authority-deployment.md) |
| Machine-local routing | [graft-security.md](./graft-security.md) |
| Black-box qualification | [cross-mount-coherence-matrix.md](./cross-mount-coherence-matrix.md) |

Protocol-5 qualification receipts, the Linux 6.12.100 private ABI, and the
private-kernel vNext specification are retained as historical implementation
records. They do not define the protocol-6 product.
