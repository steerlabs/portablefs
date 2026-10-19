# Consistency model

PortableFS v3 uses authority protocol 8. On stock Linux FUSE 7.31 or newer a
volume subscription controls caching and identity-scoped file delegations
permit daemon write-back; the normative algorithm and accepted residuals are in
[portable-coherence.md](./portable-coherence.md). macOS mounts as the volume's
exclusive writer ([fskit-mount.md](./fskit-mount.md)). There is no downgrade.

## Truth and operation ordering

A volume has one canonical durable representation selected by
`(State, ArchiveCycleStep)`: READY uses XFS; ARCHIVED uses its sealed archive;
RESTORING combines verified sealed base, monotone hydration map, and XFS.
There is no second namespace, durable client journal, or offline reconciliation.
A delegated owner may hold accepted bytes that are not yet applied or durable.
While the holder survives, peer reads reach those bytes by breaking its
delegation for read before the Authority answers. A lost non-durable tail
advances loss and fails the affected run barrier; a peer may then observe the
older durable state. Mounts never merge divergent local trees.

The Authority orders namespace mutations by exact identities and bindings.
A successful namespace response follows XFS application and peer withdrawal.
An acquisition beginning after a completed namespace or synchronous mutation
observes that mutation or something ordered later; an overlapping operation
may observe either side.
For delegated writes, acceptance into the sole holder's buffer precedes the
response; a successful break-for-read flushes that accepted cut before
answering. A missed recall budget instead follows the loss rule above.
Visibility does not imply power-loss durability.

## Write acceptance and durability

- Write-capable Linux handles use direct I/O. Kernel write-back is disabled;
  the daemon owns the bounded buffer and can stop admission for recall.
- A FULL delegation permits local acceptance. A pre-existing peer cached handle
  forces WRITETHROUGH. O_SYNC/O_DSYNC and file fsync wait for the accepted file
  cut to become durable.
- Entries progress through accepted, applied, visible, and durable. An Authority
  application ticket is not a durability receipt. The daemon retains entries
  until a contiguous durable prefix covers them.
- Rename, link, and unlink flush every named dirty identity before dispatch.
  Namespace atomicity comes from XFS. Durable application protocols retain
  their ordinary file-and-directory fsync discipline.
- FSKit has no fsync callback. Each successful FSKit mutation reply waits for
  its storage effect to be durable, covering data, attributes, and namespace
  changes. On macOS 26, `write(2)` can return at kernel page-cache acceptance; whether a
  native fsync waits for the resulting write callbacks and reports their
  errors is host behavior that remains unproven pending native qualification.
- Filesystem-wide barriers (FSKit handleless mutations, the Linux root barrier,
  SYNCFS) use syncfs on the cell filesystem. On a shared multi-project cell an
  unrelated project's writeback failure can fail and fence them, and unrelated
  dirty data lengthens them; see
  [COMPATIBILITY.md](../COMPATIBILITY.md#two-limits-that-apply-to-every-deployment).
- A run opens a directory handle on the mount root before its first operation
  and fsyncs that handle at completion. FSYNCDIR takes a mount-wide accepted
  cut and checks loss since OPENDIR. Failure fails the run. Ordinary stock-FUSE
  syncfs does not provide this callback and is not a completion promise.
- RESTORING retains the archive application ordering: verified base bytes and
  their hydration mark precede partial-chunk mutation; whole-chunk replacement
  becomes durable before its mark. A delegated syscall may first return local
  acceptance, so completion still requires the barrier. See
  [restore-mode.md](./tiered-storage/restore-mode.md#hydration-map).

## Names, attributes, and directories

One subscription per mounted Linux participant covers undelegated cached state.
Its Authority horizon is ten seconds with three-second renewal. Reply
publication checks the incarnation, served version, and exact local withdrawal
cut. A cumulative CONTROL acknowledgment means every covered cache-installing
reply has drained and the affected kernel data/attributes and daemon names are
withdrawn. A grant activates only after peer acknowledgment or horizon expiry.

Shared kernel name validity stays zero. Positive and negative bindings,
attributes, and directory pages are cached by the daemon under the subscription.
Directory reads use XFS continuation cookies. Concurrent mutation invalidates
cached pages without abandoning the cursor: unchanged entries appear exactly
once, changed entries may or may not appear, and the walk never returns ESTALE.
A mount of a volume without machine-local routes serves READDIRPLUS: each
Authority page carries entry attributes and capabilities (omitting ones the
session already holds), and the daemon publishes those entries through the same
exact physical-reply transaction as every other cache-installing reply. A mount
of a volume that declares machine-local routes serves plain READDIR only.
Kernel directory-page caching is not used.

Forward pathname resolution and enumeration are covered. Reverse rendering of
retained dentries (`getcwd`, `/proc/*/fd`, and `d_path`) is outside the contract.
Machine-local routes declared by `.portablefs/local-dirs` also have no
cross-mount coherence: their backing belongs to that machine.

## File data and mappings

Cacheable read handles use clean kernel pages under the subscription. New peer
handles on a delegated identity use direct I/O. The holder overlays its buffer
on its own reads and invalidates local cacheable readers on accepted writes.
Shared writable mappings are refused; private/read-only mappings work on
cacheable handles. No contract depends on direct-I/O mmap support.

Stock FUSE does not return the kernel's final page-invalidation result. The
qualified kernel tests cover resident pages and private mappings with kernel
write-back off. A stalled daemon cannot purge resident pages at its horizon;
a process with an existing descriptor or private mapping may read old pages
until the daemon resumes and invalidates. This is the accepted residual, not a
claim that a userspace timeout can erase kernel pages. Failed withdrawal stales
the affected inode and does not earn an acknowledgment.

An attached Mac mount holds writer exclusion, including a Mac mount whose
access is read-only. Linux mutations are refused EBUSY while that exclusion is
live; a second Mac attach is refused. The cacheless files gateway holds no
exclusion and its reads break for read without blocking Linux writers.

On macOS 27, the extension controls retained kernel data through
`FSVolume.DataCacheHandler`, granting only `readCache` with valid
writer/authorization proof and an owned read description. Proof expiry
invalidates and downgrades clean data; terminal ownership or authorization loss
revokes retained items. Calls run without module locks and retain ownership
through completion; a failed withdrawal leaves kernel cache state unchanged
and ends serving. Ordinary open-unlinked files remain accessible. Writes use
durable direct authority callbacks, with no `writeThrough` or `writeBack` grant.

A stopped extension cannot revoke, and cached reads can race wake before the
extension executes. Per-item control does not prove exact negative-name,
inode-attribute or directory-enumeration invalidation. macOS 26 retains the
existing residual: after terminal publication stops new serving, retained
kernel names, attributes and pages can remain observable until unmount. Neither
OS has a qualified guarantee of zero stale access after failover.

## Append

Append is exact, and the authority — not either kernel — places it. A frontend
forwards the intent and the authority assigns the offset at the object's true EOF
inside the same per-inode writer stripe that serializes every other size-changing
operation, then reports that offset back. A kernel `i_size` is advisory
throughout: it is a shadow of what a daemon last published, and a peer may have
moved EOF since.

The intent it forwards is the writing description's `O_APPEND`, which stock FUSE
reports. The two per-call flags it cannot see are disclosed deviations, not
inferences: `RWF_APPEND` on a description without `O_APPEND` arrives as an
ordinary positioned write and is placed at the offset the kernel derived from its
advisory `i_size`, and `RWF_NOAPPEND` on a description with `O_APPEND` is placed
at EOF like any other append. The system never reinterprets an offset it cannot
disambiguate: guessing "this positioned write was really an append" is exactly
what would misplace the ordinary sequential writes that carry the same offset.

## Replay and uncertain outcomes

Replay is session-exact within one authority epoch. Each mutation carries a
client-owned replay slot and sequence; exact replay returns the retained outcome and
does not re-execute. Identity reuse with a different canonical request or a
sequence gap fences the session.

There is no honest atomic transaction spanning an arbitrary XFS syscall and a
separate durable replay database. A mutation whose reply is lost across
authority death is reported `UNCERTAIN`; it is never silently retried in a new
epoch. The application inspects current state and decides. For an `UNCERTAIN`
append that means 0..n bytes may have been placed at an offset the caller was
never told, known only to be at or after the pre-operation EOF; recovering means
reading the object's current state, exactly as for any other uncertain write.

## Locks and open handles

The authority implements independent POSIX record-lock and BSD `flock`
namespaces. Linux forwards both; a kernel or frontend that cannot provide both
is refused. Session expiry, fencing, or epoch end releases its locks. An epoch change
permanently stales every old handle; applications restart affected runs and
open new handles after cold reattachment.

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

Current FSKit cannot invalidate names, attributes, or enumerations, control
per-reply metadata installation, or expose exact append intent or advisory-lock
callbacks. macOS therefore mounts through `FRONTEND_PROFILE_FSKIT_EXCLUSIVE`: a
mounted Mac writes and every other client reads, so the missing invalidation is
never asked to serve a concurrent remote mutation. A second Mac is refused at
activation. Mac mutations publish ordered changes and wait for Linux reader
withdrawal, so Linux readers observe them coherently. Ending or fencing a Mac
session stops PortableFS from serving that Mac. macOS 27 also withdraws retained
item caches within the limits stated above; macOS 26 may continue exposing
retained kernel names, attributes and pages until unmount. Cross-machine `fcntl`/`flock` exclusion and cross-client atomic
append need Linux mounts with no Mac writer attached.

Windows has no admitted transport. A future frontend must prove exact cache
withdrawal, lock forwarding, and cache behavior before it can participate.

## What is not claimed

- Transparent exactly-once mutation across authority death.
- Shared writable file-backed `mmap`.
- Ordinary stock-FUSE `syncfs(2)` as the run-completion barrier.
- Symmetric multi-writer coherence with a macOS mount attached: while a Mac
  is the writer, every Linux peer is a reader whose visible mutations are
  refused `EBUSY`, and a second Mac cannot mount.
- Complete synchronous withdrawal of macOS kernel state on fence or loss,
  including a stopped extension, sleep/wake races and exact namespace state.
- Durability-error or latency isolation between volumes in one XFS cell.
- Multiple POSIX principals inside one volume.
- Writable extended attributes.
- Local-XFS read latency during RESTORING. A cold content read may pay one
  archive-store recall round trip before it returns.
- Content-read availability during `RESTORE_BLOCKED`. Content reads are
  suspended volume-wide; namespace and attribute operations continue.
- Production FSKit or Windows mounts.
- Elimination of the documented stalled-daemon resident-page residual.

SQLite rollback-journal mode is inside the tested Linux compatibility contract.
SQLite WAL is not: its shared-memory protocol requires all participants on one
host. Keep WAL databases local or use a database service.

Failure scope and fencing are specified in
[failure-modes.md](./failure-modes.md).
