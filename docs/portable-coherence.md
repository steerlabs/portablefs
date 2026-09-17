# PortableFS protocol 7 coherence

Protocol 7 uses a volume change subscription and per-file write delegations on
stock Linux FUSE. The Authority owns the namespace and XFS is the durable truth.
An uncontended writer may acknowledge data into its daemon buffer; completion
requires a durability barrier. This replaces the protocol-6 N/A/E/D lease engine.
There is no mixed-major execution or fallback. The exact wire contract is
[wire.md](./coherence-v2/wire.md), with compatibility surfaces in
[COMPATIBILITY.md](../COMPATIBILITY.md).

## Visibility and cache permission

Each Linux mount subscribes with a 10-second Authority horizon, renewed every
three seconds. Subscribe returns an atomic volume-version watermark and the
currently delegated identities. Cache publication checks the subscription
incarnation and served version, so a delayed reply cannot reinstall state older
than a completed withdrawal.

Namespace operations execute synchronously at the Authority. Its sequencer
orders conflicting identities and `(parent, name)` bindings; disjoint mutations
can proceed concurrently. Committed peer changes stream over CONTROL in order.
Cumulative acknowledgments certify withdrawal through that position, including
kernel data/attribute invalidation and draining pending cache-installing replies.
The Authority waits for the affected peer subscriber's acknowledgment or horizon
before completing a mutation or activating a delegation.
The source repairs its own publications through its exact-coordinate gate and
the mutation's returned post-state; it does not acknowledge its own commit as
a peer change.

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

## Delegated writes and peer reads

CREATE and writable OPEN can return a file delegation with the ordinary reply.
The Authority reserves ownership before publishing a created binding. A full
delegation covers data, size, and file attributes; write handles use direct I/O
so every application write reaches the daemon. The daemon preserves per-file
program order and overlays accepted data for reads on the owning mount.

The buffer is bounded at 64 MiB retained write payload and 10,000 entries. It flushes on its
one-second timer, cap pressure, file fsync, root-directory barrier, recall,
unmount, and before a namespace operation naming the file. Admission blocks at
the cap. Accepted entries remain retained through application and visibility
until the Authority confirms durability with a contiguous session ticket prefix.
`O_SYNC` and `O_DSYNC` wait for that durability before returning.

An Authority read that consumes delegated data, size, or attributes first
breaks the delegation for read to an accepted-entry cut. This includes LOOKUP,
READDIR attributes, GETATTR, READ, FSYNC, and copy-source reads. A peer mutation
recalls ownership before applying. Recall stops admission under the retiring
generation, drains and flushes it, then acknowledges the exact applied cut.
Generation-bound flushes cannot apply under stale ownership.

A peer cache-capable handle opened before the delegation forces write-through
for as long as it remains open; each commit withdraws the peer's cached state.
New peer handles on a delegated file are direct-I/O and do not force that
downgrade. Concurrent writers to one identity arbitrate through recall; writes
to independent identities retain independent delegation state.

The files gateway is an authenticated `CACHELESS_READER`, with exactly read
access and no subscription or kernel cache. Its reads break for read and see
flushed data. It neither acquires Mac compatibility-writer membership nor
excludes Linux writers.

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
under an expired permission. Authentication and exact assigned-mutation outcome
invariants still fail closed; operator unmount remains explicit.

An Authority epoch change permanently stales every old file and directory
handle, capability, and lock. The mount reattaches using its configured attach credential, subscribes cold,
and restarts session-bound reauthorization. Recovery needs that attach grant
to remain valid: there is no replacement-grant installer on this path yet.
An expired or refused grant leaves recovery cold and retrying. Old handles and
their root barrier fail EIO; newly opened
handles can work and pass a new barrier. There is no open-by-identity recovery
or claim that an interrupted application transaction resumes transparently.
Prior Linux membership is fenced through its old horizon on restart. Persisted
membership still needs an absence proof before route changes or archival;
historical records are not permission to assume an old mount has vanished.

Application-ticket records retire at the durable prefix. Completed control
obligations and replay records retire at the acknowledged completion position.
The session keeps bounded pending obligations, a reusable CONTROL batch, its
exact CONTROL replay, and one delegation-release replay result. Issued-ticket
history does not grow for the lifetime of a healthy session.

## macOS boundary

Every attached FSKit mount retains compatibility-writer exclusion, including
read-only mounts. The shipping SDK cannot invalidate names and attributes, and
the SDK 27 adapter covers data only. The existing FSKit synchronous repair,
cache-policy names, and `pfslocal` interface remain; this integration does not
claim Linux-equivalent Mac cache withdrawal, append, or advisory locks. The
Linux mutation path no longer runs through the Mac repair coordinator.

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
FSKit activation globally excludes Linux writer admission while it recalls and
activates the compatibility writer. Waiting to acquire that exclusion and the
recalls issued under it use the activation authorization deadline, but an
already-blocked kernel or local-storage operation retains the limits above.

## Qualification and remaining work

The real-mount inventory includes invalidation of resident and privately mapped
pages, delivery of FSYNCDIR, overlapping peer reads/writes, exact cache
publication, stable enumeration under churn, gateway reads, and loss recovery.
The two-process matrix preserves the original 23 cases and adds six protocol-7
cases; the owner-identity-dependent chown case retains its explicit skip.
Commands and final gate results are recorded in
[integration.md](./coherence-v2/integration.md). Measurements and profiling,
including direct XFS and protocol 6 comparisons, are in
[results.md](./coherence-v2/results.md).

The final G4 baseline records 0.01825 Authority requests per file for warm Git
status (zero LOOKUP/GETATTR and one RECLAIM) and 8.12725 requests per operation
for the two-mount workload (62 RECLAIMs for 229 READDIR pages). The exact
all-case soak passes, including the full 5,000-file/200-commit Git workload and
all fault cases. The additive directory contract lets a client name page-local
stable identities whose capabilities it already retains; the Authority omits a
new Item only for those identities. Residual capabilities are reclaimed in
batches of at most 4,096. Directory page construction owns the store read turn
and never surfaces server-generated `EAGAIN` under peer mutation.

These are local Docker/kernel qualification results, not a production SLO or a
broader kernel certification. Production must pin and qualify its runner kernel
and call the run-start/root-handle barrier at completion, sandbox exit, and
detach. This workstream does not deploy that product integration or qualify a
real macOS mount. Directory delegation, quota reservation, and transparent
recovery of old handles remain outside this foundation.
