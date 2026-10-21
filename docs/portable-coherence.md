# Linux coherence: subscriptions and delegations

The Linux profile (`FRONTEND_PROFILE_LINUX`) uses a volume change subscription
and per-file write delegations on stock Linux FUSE. The Authority owns the
namespace and XFS is the durable truth. An uncontended writer may acknowledge
data into its daemon buffer; completion requires a durability barrier. The
exact wire contract is [wire.md](./coherence-v2/wire.md), with compatibility
surfaces in [COMPATIBILITY.md](../COMPATIBILITY.md).

## Visibility and cache permission

Each Linux mount subscribes with a 10-second Authority horizon, renewed every
three seconds. Subscribe returns an atomic volume-version watermark and the
currently delegated identities. Cache publication checks the subscription
incarnation and served version, so a delayed reply cannot reinstall state older
than a completed withdrawal. Subscription request anchors, receipt and renewal
validation, and every cache or delegation admission use Linux `CLOCK_BOOTTIME`,
which advances across suspend. The authority uses that same local clock domain
for subscription and delegation deadlines and renewable session/lock leases.
Client horizons are anchored before request queueing; pagination retains the
original anchor. Each admission checks the continuous horizon at the moment of
use, even before CONTROL delivery or an active-time timer runs after resume.
An expired horizon closes admission and requires cold cache withdrawal before
resubscription; a late renewal cannot revive it. Timers only wake workers.

Namespace operations execute synchronously at the Authority. Its sequencer
orders conflicting identities and `(parent, name)` bindings; disjoint mutations
can proceed concurrently. Committed peer changes stream over CONTROL in order.
Cumulative acknowledgments certify withdrawal through that position, including
kernel data/attribute invalidation and draining pending cache-installing replies.
`WaitTargeted` captures the affected peer subscription incarnations at commit
and waits for actual withdrawal through cumulative ChangeAck or the existing
cold-reset/horizon proof. DATA reply delivery, a delegation acknowledgment, or
mere session fencing cannot satisfy that obligation. The Authority marks the
application visible only after the wait succeeds, preserving a contiguous
`VisibleSequence` prefix. Filesystem mutation success and activation of a new
delegation wait for the required withdrawal; an authority application receipt
can precede it.
The source updates its own publications through its exact-coordinate gate and
the mutation's returned post-state; it does not acknowledge its own commit as
a peer change.

Object versions are conservative: `0 < v <= s`, strictly increasing on each
logical change, and allowed to advance without one when the authority's bounded
version map compacts. A client orders replies by version and publication cut
but never treats a numerically higher version as a change event; invalidation
comes only from explicit ChangeEntry positions, so version inflation creates no
false withdrawal and never lets an older logical value through a newer
invalidation.

Shared names have zero kernel entry validity. Exact-coordinate daemon cache
withdrawal proves forward lookup without reverse entry notifications that can
deadlock on the initiating VFS lock. Reverse rendering of retained dentries
(`getcwd`, `/proc/*/fd`, and other `d_path` users) remains outside this contract.
Machine-local graft names have their own local-kernel lifetime.

Cache-installing replies and initiating mutations retain a gate keyed by the
same exact identities and names. It drains only overlapping publications, not
unrelated operations on the mount. Stock FUSE kernel write-back stays disabled.
The maintained go-fuse reply lifecycle and inode notifications are part of this
publication proof, not substitutes for a kernel acknowledgment that FUSE does
not expose.

Metadata sampling also retains its ownership interval. If a grant changes or
retires before publication, the client resamples under the original request
deadline; a clean release cannot make an older storage size current again.
Directory replies prepare all rows without physical publication pins, then
validate and pin the deduplicated identities together. No row retains a pin
while another row makes a remote request. Local writes are excluded between
the final sample and publication admission, and all pins remain until the
physical reply settles. Mutation replies preserve the Authority's versioned
post-state when no local ownership overlay is needed.

## Delegated writes and peer reads

CREATE and writable OPEN can return a file delegation with the ordinary reply.
The Authority reserves ownership before publishing a created binding. A full
delegation covers data, size, and file attributes; write handles use direct I/O
so every application write reaches the daemon. The daemon preserves per-file
program order and overlays accepted data for reads on the owning mount.

Application, remote visibility, and durability prove different facts; none
substitutes for another. `AppliedSequence` is the session ticket for applied
storage work, recorded on the pinned delegation through
`DelegationFlush.End(ticket)`. The application ledger maps tickets to volume
versions; the delegation validates its cut using the event floor or a ticket
issued under that exact generation while the cut was pending. Another inode's
session-wide high-water mark cannot satisfy it. Visibility requires actual
targeted withdrawal, while durability requires its separate storage barrier
and prefix; neither visibility nor durability implies the other.

Successful truncating write-intent OPEN and truncating write-intent existing-name
CREATE under the exact delegation pin carry their application ticket, including a
truncate of an already empty existing file. Exact replay retains the original
handle, grant, and ticket without another application. Nontruncating OPEN and
unchanged existing-name CREATE need no new ticket. A new empty-file CREATE
without a preflight file pin may keep a zero ticket because its namespace
result waits synchronously for withdrawal.

The grant paths preserve different reply ordering:

- **Existing public generation.** The synchronous mutation pins the exact
  generation already eligible for a DATA reply. After apply, commit publication,
  release of storage locks, and `End(ticket)`, the Authority returns the
  application receipt before targeted withdrawal. OPEN/CREATE include the real
  handle, retained grant, and operation ticket; the detached authority wait
  retains the visibility obligation. Public does not assert DATA delivery.
- **New private generation.** `RetainDelegation` returns the unoffered generation
  to `DelegationReserved`, opens reserved-reader admission, and clears
  `ephemeral`. The handler releases storage and ends the apply pin, completes
  withdrawal while Reserved, then calls `Grant`. Activation closes reserved
  reader admission and joins existing sample pins before returning the grant.
  No holder CONTROL may issue while Reserved. Newly reserved nontruncating OPEN
  and new-name CREATE retain reservation withdrawal and reader drain where
  applicable; CONTROL may overtake DATA only after activation.

The client installs the returned identity/ref, handle, grant, and ticket in one
admission interval before CONTROL can inspect the generation. A synchronous
operation records its actual application ticket before releasing its operation
lock to CONTROL. A CONTROL handler that overtook DATA waits without holding
locks needed by installation; grant registration wakes it. The client releases
locks needed by CONTROL before waiting for visibility and continues servicing
CONTROL during the wait. FUSE OPEN/CREATE success still waits for visibility
and source publication.

Delegated flushes are ordered: each delegation generation's WRITEs carry dense
ordinals and share a window of four in-flight flushes on a dedicated DATA lane,
which requires `max_in_flight >= 9` on both Linux connections. There is no
serial or capacity-negotiated alternative.

The buffer is bounded at 64 MiB retained write payload and 10,000 entries.
Background flush is event-driven by producer and completion progress. It also
flushes on cap pressure, file fsync, root-directory barrier, recall, unmount,
and before a namespace operation naming the file. Admission blocks at
the cap. Accepted entries remain retained through application and visibility
until the Authority confirms durability with a contiguous session ticket prefix.
`O_SYNC` and `O_DSYNC` wait for that durability before returning.

An Authority read that consumes delegated data, size, or attributes first
breaks the delegation for read to an accepted-entry cut. This includes LOOKUP,
READDIR attributes, GETATTR, READ, FSYNC, and copy-source reads. A peer mutation
recalls ownership before applying. Recall stops admission under the retiring
generation, drains and flushes it, then acknowledges the exact applied cut.
Generation-bound flushes cannot apply under stale ownership.

A delegation acknowledgment proves application and the required local drain;
it certifies neither remote visibility nor durability and need not wait for a
preceding ChangeAck. Peer withdrawal may depend on an in-flight READ that needs
the holder's applied cut. Event delivery, delegation acknowledgments, and
cumulative withdrawal acknowledgments therefore retain independent progress
paths.

A peer cache-capable handle opened before the delegation forces write-through
for as long as it remains open; each commit withdraws the peer's cached state.
New peer handles on a delegated file are direct-I/O and do not force that
downgrade. Concurrent writers to one identity arbitrate through recall; writes
to independent identities retain independent delegation state.

The files gateway is an authenticated `CACHELESS_READER`, with exactly read
access and no subscription or kernel cache. Its reads break for read and see
flushed data. It neither joins Mac writer exclusion nor excludes Linux
writers.

## Namespace, enumeration, and locks

Rename, link, and unlink flush any named delegated identity before the namespace
request. The Authority's exclusive-create ordering and this flush-before-rename
rule make Git's lock-file protocol work across mounts: exactly one
`O_EXCL` creation wins, and a peer reading the renamed file sees its data.

Directory handles continue from opaque XFS `getdents` offsets. A mutation drops
cached pages but preserves the continuation cookie. Every entry unmodified
during a walk is returned exactly once; concurrently added or removed entries
may or may not appear. Concurrent mutation never causes ESTALE or an ordinal
rescan. The directory verifier protects page publication, not permission to
continue an already-started walk.

`flock` and `fcntl` remain Authority-mediated even under a delegation. Writable
shared mappings are unsupported; private/read-only mappings on cacheable
handles use the kernel invalidation path. No contract depends on
`FUSE_DIRECT_IO_ALLOW_MMAP`. Append placement is resolved synchronously at the
Authority's true EOF. Stock FUSE does not expose per-call
`RWF_APPEND`/`RWF_NOAPPEND`; those remain disclosed deviations.

## Durability, losses, and recovery

Open a directory handle on the mount root before a run's first operation. At
completion, `fsync` that same handle. The daemon snapshots an accepted-entry
cut, flushes it, and waits for durability. The handle also observes whether the
mount loss sequence advanced since its open. A failed barrier fails the run.
Later writes cannot let the barrier overtake its cut. File fsync applies the
same ordering to that file. Ordinary stock-FUSE `syncfs` is not this completion
surface: it does not deliver the required daemon callback.

A missed five-second recall budget or rejected stale-generation flush marks
loss and returns EIO on affected handles; it does not disconnect the mount.
A lost subscription withdraws all cache permission and resubscribes cold after
invalidation. During withdrawal, new uncached reads fail rather than return bytes
under an expired permission. An authenticated live session resolves an assigned
DATA mutation's exact replay before current coherence admission, returning its
retained outcome and mutation state without executing again. New operations
still require current permission. Replay does not restore an expired grant,
cache contents, or a discarded volatile tail.

Cold reset cancels old cache and grant work, but preserves session-owned CLOSE,
CLOSE_BATCH, RECLAIM, and Barrier resolution. Each unresolved mutation retains
its exact body, replay slot, and lane permit through bounded transport attempts.
A buffer flush transfers resolution to the session before its assignment callback
publishes an ordinal; stopping its old buffer joins exact resolution before
releasing its immutable bytes. Every allocated descriptor immediately reserves
counted cleanup ownership before grant installation or result validation. A
retained frontend handle takes ownership on success; every other exit, including
temporary write-delegation OPENs, hands the exact descriptor to session cleanup.
File and directory RELEASE use the same counted worker. Rejected item metadata
and failed interning keep their capabilities on the RECLAIM cleanup lane.
Callback completion
finishes grant-history and index bookkeeping before releasing its epoch reader;
only then can reserved producers dispatch. Physical metadata pins remain held
until reply settlement. Interrupted cache preparation retains debt through cold
activation, even before the buffer serial changes; only proven retirement or
terminal session cleanup discharges it.
Old receipts cannot advance the replacement buffer, and recorded loss remains
observable on affected handles and the pre-loss root barrier. Authentication,
session expiry, and unprovable assigned outcomes still fail closed; operator
unmount remains explicit.

An Authority epoch change invalidates every old file and directory handle,
capability, and lock. Shipping `portablefs mount` withdraws the old mount and
retains its exact session identity in durable inventory until cleanup is proven.
Its supervisor must obtain fresh authorization and prove the replacement's
renewal before admitting new work. A Host-managed enrollment never moves to a
different session. This works after the original attach grant expires and still
subjects every replacement to current Host access checks.

The standalone helper and core callers with epoch-aware renewal can instead
reattach using their configured, still-valid attach credential and subscribe
cold. An expired or refused grant leaves that standalone path cold and retrying.
Old handles and their root barrier fail EIO; new handles after recovery can work
and pass a new barrier. There is no open-by-identity recovery or claim that an
interrupted application transaction resumes transparently.
Prior Linux membership is fenced through its old horizon on restart. Persisted
membership still needs an absence proof before route changes or archival;
historical records are not permission to assume an old mount has vanished.

Application-ticket records retire at the durable prefix. Completed control
obligations and replay records retire at the acknowledged completion position.
The session keeps bounded pending obligations, a reusable CONTROL batch, its
exact CONTROL replay, and one delegation-release replay result. Issued-ticket
history does not grow for the lifetime of a healthy session.

## Authority coordinator bounds

The authority's change log is a bounded ring, 65,536 entries by default. Each
subscriber's delivered cursor is its outbox; a poll copies a bounded batch into
a reusable buffer, and delivery, change acknowledgment, and delegation
acknowledgment are separate proofs. A subscriber that falls behind the ring is
fenced on its next request and its renewal is refused; its outstanding
withdrawal obligation remains until its horizon or a cold resubscribe, so
overrun never shortens an issued cache permission. Subscription fencing is
recoverable through a cold Subscribe in a new incarnation, which cannot
acknowledge old obligations. No coordinator mutex covers I/O or a wait, and
delegation turns use their own instance of the mutation sequencer so flushes
and CONTROL acknowledgments never wait behind grant arbitration.

## macOS boundary

A mounted Mac is the volume's only writer (`FRONTEND_PROFILE_FSKIT_EXCLUSIVE`).
Its activation takes profile admission exclusively, recalls Linux delegations
and waits for their exact generations before publishing the writer; while it is
attached, Linux visible mutations and write-intent opens return `EBUSY`. Mac
mutations still publish ordered Linux change entries and wait for reader
withdrawal, so Linux mounts read Mac changes coherently. Current FSKit cannot
invalidate names, attributes, or enumerations or expose append intent or lock
callbacks, so the reverse direction is excluded rather than approximated. See
[fskit-mount.md](./fskit-mount.md).

## Known residuals

The following three residuals are reproduced verbatim from the design:

  - **Stalled daemon, resident pages.** If a reader's daemon stops responding past its horizon, a process on that mount holding an open descriptor or a private mapping can read pages that were resident before the withdrawal, until the daemon resumes and invalidates. Stock FUSE offers no way for userspace to fence this. The current code has the same residual and documents it. The Authority proceeds at the horizon so a healthy writer is not held hostage by a dead reader.

  - **Delayed capacity refusal.** A write accepted into the buffer can fail with `ENOSPC`, `EDQUOT`, or `EFBIG` at flush; the process learns the exact definite pre-apply errno at its next write, close, or fsync on that file, or at the run barrier. This is the NFS contract. A reservation scheme would need quota usage the Authority does not read today.

  - **Contended files run at today's speed.** A file that a peer holds a cached handle on, or writes concurrently, is write-through with invalidation per commit. That is correct and it is what the current system does for every file.

The implementation also has three explicit liveness limits. A local storage
operation already pinned in the filesystem can outlive the five-second recall
budget because cancellation cannot preempt the kernel operation. A synchronous
reverse inode notification blocked in the kernel cannot be interrupted by the
retry context; the context prevents another retry after the call returns. Mac
FSKit activation excludes Linux writer admission while it recalls and activates
the writer; exact-generation recall flushes still drain under it. Waiting to
acquire that exclusion and the recalls issued under it use the activation
authorization deadline, but an already-blocked kernel or local-storage
operation retains the limits above.

## Qualification and remaining work

The privileged suite and the two-mount matrix cover invalidation of resident and
privately mapped pages, delivery of FSYNCDIR, overlapping peer reads and writes,
exact cache publication, stable enumeration under churn, ordered flush, gateway
reads, and loss recovery; the owner-identity-dependent chown case keeps its
declared skip. None of these has passed on the integrated protocol-8 tree yet,
and measurements from earlier protocols are not carried forward
([performance.md](./performance.md)).

These are local Docker/kernel suites, not a production SLO or a broader kernel
certification. Production must pin and qualify its runner kernel and call the
run-start root-handle barrier at completion, sandbox exit, and detach.
Directory delegation, quota reservation, and transparent recovery of old
handles remain outside this design.
