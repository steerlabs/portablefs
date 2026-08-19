# Consistency model

PortableFS v3 has one production consistency profile: authority protocol 6 on
stock Linux FUSE protocol 7.31 or newer. There is no uncached profile, private
kernel dialect, macOS compatibility-writer mode, or negotiated downgrade.

The normative lease and invalidation algorithm is
[portable-coherence.md](./portable-coherence.md). This document states the
filesystem behavior applications may rely on.

## Truth and operation ordering

One provisioned XFS project directory is the only durable truth. The authority
executes object-relative Linux syscalls beneath a pre-opened root. PortableFS
does not keep a second namespace, mutation journal, or client write-back log.

Filesystem operations are linearizable. A mutation linearizes after its
authoritative XFS apply and before its response, at a point consistent with
overlapping observations. The response is the external completion/visibility
boundary, not necessarily the exact linearization instant. Before the daemon
permits it, every conflicting peer cache lease has been discharged. An
operation whose relevant cache acquisition begins after that response observes
the mutation or something ordered later. An overlapping operation may observe
either side; if it observes new state, the mutation linearizes before that
observation.

The authority's internal COMPLETE result is an ordering barrier, not an
externally visible linearization receipt. Stock FUSE completes the source mount's normal
VFS reply processing before the syscall returns. No kernel publication receipt
or PortableFS-private opcode participates.

## Write acceptance and durability

- Linux write-capable opens use direct I/O and writeback caching is disabled.
  A successful `write(2)` means the authority applied the accepted bytes to XFS
  and discharged conflicting D leases. No dirty client data remains to flush.
- `fsync(2)` and `fdatasync(2)` run on the authoritative open file description
  and are the durability barriers. `close(2)` is not an implicit `fsync`.
- Namespace atomicity comes from the authoritative XFS syscall. Durable rename,
  replacement, or creation still requires the application's ordinary
  file-and-directory fsync discipline.
- Protocol 6 uses FUSE `SYNCFS` when the stock kernel advertises it. FUSE 7.31
  predates that request, so `syncfs(2)` is not a PortableFS remote-volume
  durability promise on every supported kernel. The absence is not emulated.

## Cache leases

Caching is allowed only under an authority lease:

| Coordinate | Covered state |
| --- | --- |
| N(parent stable ID, raw name) | one positive or negative name binding |
| A(stable ID) | the complete attribute record |
| D(stable ID, whole file) | clean file data and read-ahead |
| E(directory stable ID) | a complete directory membership enumeration |

Kernel entry validity is always zero. Attribute validity is a conservative
duration derived from the authority TTL and anchored at the client's
request-start time. Network and processing delay can only reduce the installed
duration; the client does not compare an authority absolute timestamp against
its own wall clock. Daemon cache hits check the same request-anchored deadline
and coordinate cursor. A reply without a covering lease carries zero validity.

A conflicting mutation closes grant admission, recalls the conflicting rights,
applies to XFS, sends exact post-state, and waits for peer discharge before the
source response. Because D leases cover the whole file in v1, D recall always
purges the whole file and returns the lease to none. Range purge and successor
continuity are future protocol work, not a v1 discharge mode.

The daemon has an ordered installing lane for cache-bearing replies and
invalidations, plus a non-installing metadata lane for zero-validity replies.
Buffered READ is different: an already-admitted writer drains before recall
acknowledgment, and a new request at a closed cut receives `EAGAIN` rather than
waiting while it may hold a folio lock.

The mutating mount uses a source obligation rather than a self-recall. Its
daemon purges A/D/E and daemon N state before replying. Kernel entry validity
is always zero, so `d_move`/`d_exchange` cannot transplant an old leased name
timeout and source discharge needs no undocumented namespace-notification
receipt.

This guarantee is for forward pathname resolution. Reverse rendering of an
already-retained dentry (`getcwd`, `/proc/*/fd`, and other `d_path` users) does
not revalidate and is outside the cross-mount coherence contract. Directory
enumeration remains covered by E.

## Names, attributes, and directories

Positive and negative name bindings are cached by the daemon only under N
leases; kernel entry validity remains zero. A creation recalls the negative
binding it fills; unlink or rename recalls the positive binding it removes.
Attribute replies are cached only under A leases.

Directory enumeration uses plain READDIR. The daemon may cache a complete,
possibly paginated enumeration only under E. Any namespace mutation touching
the directory recalls E. Kernel directory caching and READDIRPLUS are not used,
so there is no untracked membership or post-reply entry installation.

Machine-local routes are outside this rule by design. A name matched by the
volume's `.portablefs/local-dirs` declaration is served from that machine's
local backing tree and has no cross-mount coherence.

## File data and mappings

Read-only opens may use the clean kernel page cache under D-R. Write-capable
opens use direct I/O; the daemon may cache their clean reads under the same lease
clock. Shared writable mappings and every path that could create dirty client
pages are refused. Read-only and private mappings are supported under the clean
data regime.

Stock FUSE does not expose whether a data invalidation internally failed with
`EBUSY`, and a notification need not finish before the authority horizon. The
client starts withdrawal at its earlier cache deadline and terminalizes the
mount if withdrawal is not proved in time. Channel abort prevents new FUSE work
but does not erase resident folios: a preexisting read-only file descriptor or
private mapping can therefore retain old clean bytes for its lifetime. No new
open, cache miss, metadata answer, accepted write, or durability result is
authorized after terminalization. This is an explicit exception, not described
as a transient window. Removing it requires a bounded, result-bearing kernel
invalidation or cache-generation primitive.

A stopped-but-not-dead daemon creates a second disclosed residual: it cannot run
the expiry purge for kernel-held clean pages after the authority fences it.
Stale data then requires the conjunction of daemon wedge, fencing, peer
mutation, and a cached read-only page. Metadata and writes are not affected.

## Append

Stock FUSE lets PortableFS refuse `O_APPEND` at OPEN and reject it if the open
intent remains observable at WRITE. It does not forward `RWF_APPEND` at all, so
the daemon cannot distinguish that request from an ordinary positioned write
and cannot reliably refuse or place it. The system does not reinterpret offsets
or serialize an inexact path behind D-X. Unobservable `RWF_APPEND` is a hard
correctness blocker: the writable protocol-6 profile is not production-ready
until upstream ABI support or a different proven architecture closes it.

## Replay and uncertain outcomes

Protocol 6 is session-exact within one authority epoch. Each mutation carries a
daemon-owned operation identity; exact replay returns the retained outcome and
does not re-execute. Identity reuse with a different canonical request or a
sequence gap fences the session.

There is no honest atomic transaction spanning an arbitrary XFS syscall and a
separate durable replay database. A mutation whose reply is lost across
authority death is reported `UNCERTAIN`; it is never silently retried in a new
epoch. The application inspects current state and decides.

## Locks and open handles

The authority implements independent POSIX record-lock and BSD `flock`
namespaces. Linux forwards both; a kernel or frontend that cannot provide both
is refused. Session expiry, fencing, or epoch end releases its locks.

An open file description remains usable after unlink until final close. Rename
and unlink operate on namespace bindings, not on the lifetime of an already-open
authority handle. See [open-after-unlink.md](./open-after-unlink.md).

## Extended attributes and ownership

Writable xattrs are refused. XFS attribute-fork blocks are not charged to
project quota, so an in-memory or per-inode approximation would violate storage
isolation. Portable `user.*` reads, lists, and removals remain available; the
reserved `user.portablefs.*` prefix and non-user namespaces do not cross the
remote boundary.

Each volume is single-principal. XFS inodes are owned by the volume service
UID/GID and mounts project that principal to the local mounting user. A change
to another principal fails rather than creating a host-ID mapping by accident.

## Platform boundary

Current FSKit cannot discharge protocol 6 N, A, and E leases, control
per-reply metadata installation, or expose exact append intent or distributed
lock callbacks. macOS therefore uses the explicit `FSKIT_SYNC_REPAIR` profile:
mutations retain ordered PREPARE/COMPLETE repair, while those host-cache,
append, and lock edges remain best-effort rather than Linux-equivalent.

Windows has no admitted transport. A future frontend must prove exact lease
discharge, lock forwarding, and cache behavior before it can participate.

## What is not claimed

- Transparent exactly-once mutation across authority death.
- Shared writable file-backed `mmap`.
- Remote-volume `syncfs(2)` on a kernel that does not advertise FUSE SYNCFS.
- Multiple POSIX principals inside one volume.
- Writable extended attributes.
- Production FSKit or Windows mounts.
- Elimination of the two stock-FUSE read-cache residuals described above.

SQLite rollback-journal mode is inside the tested Linux compatibility contract.
SQLite WAL is not: its shared-memory protocol requires all participants on one
host. Keep WAL databases local or use a database service.

Failure scope and fencing are specified in
[failure-modes.md](./failure-modes.md).
