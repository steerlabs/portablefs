# Linux workspace admission

The admission substrate is implemented; managed mounts remain unavailable.
`portablefs mount` recognizes the private `--workspace-gate-fd` and
`--workspace-owner-fd` pair and refuses managed launch before credential,
enrollment or mount preparation, without adopting the caller's descriptors. Ordinary mounts have neither
descriptor. Kernel installation, lifecycle suspension/recovery, the guest clock
and the protected-path root driver remain integration dependencies. No readiness
placeholder enables a managed mount.

## Shared word and lifetime

`workspaceadmission.Supervisor` owns one root-owned, mode-0400 memfd, one existing
writable shared mapping and the only lifetime-pipe writer. The immutable header
binds format 8, boot and service identities, mount incarnation and the exact root
PID/start witness. The page is sealed against size changes, future writes and
seal changes, with explicit `MFD_NOEXEC_SEAL` and `F_SEAL_EXEC`. The handoff contains a separate `O_RDONLY` description and the
pipe reader; every parent descriptor starts close-on-exec. Adoption checks the
binding, live supervisor witness, size, owner, mode, seals and descriptor access
modes, then closes the gate descriptor after mapping it read-only.

Close advances the serial and atomically stores `(serial << 1)`. The store is the
admission cut; it performs no I/O or child-dependent wait. Repeated Close in the
same generation still advances it. Exhaustion closes permanently. Open consumes
the current prepared proof and CASes its exact closed word to its open word.
Another Close defeats delayed preparation and Open. Every serving predicate
loads the whole word. A check cannot prevent later child stores: stale
subscription assignments retain their proof and cannot serve. A retained
delegation still owns its accepted dirty overlay and durability cut; permission
to admit new serving work is separate from that ownership.

The independent pipe watcher permanently latches the reader closed on EOF,
unexpected data or read error, before initiating its teardown callback. Socket
loss is distinct from owner death. A descheduled watcher can observe EOF late;
this is not an instantaneous owner-death barrier. Reader retirement closes its
watcher without reporting owner death and retains the read-only mapping for the
process lifetime, so old permits remain safe to check.

## Existing owners and three permits

Serving uses `ServingPermit`. A raw entry reserves an existing reply-arena slot
before its successful word load. A fast cache answer keeps that slot; a slow
callback atomically transfers its reservation to its existing heap publication
owner without registering the FUSE Unique twice. The heap lifetime also covers
contexts retained by descriptor cleanup. Graft syscalls and local answers have
the same entry owner, without adding authority cache coordinates.

Recovery uses a `RecoveryPermit` naming the binding, generation and exact closed
serial. Subscription installation checks it under its installation lock and
retains it for later control and serving decisions. Recovery can establish cold
subscription/control readiness while serving remains closed. A newer Close
invalidates it. Delegation installation checks the callback's serving proof.
Closing admission
still retains the old grant, dirty overlay and accepted cut for admitted READ,
FSYNC and exact cleanup. New WRITE and holder GETATTR must pass entry admission.

A drain permit captures one old buffer, its incarnation and the earlier of the
requested deadline and local cache-withdrawal deadline, preserving its lead
before the authority horizon. It cannot select a successor buffer,
extend the horizon or admit writes. This PR supplies that boundary; the lifecycle
owner and complete cold transition are subsequent work. The lifecycle PR must
also join or fence a renewal admitted before closure: the renew loop checks
permission before dispatch and at acceptance, but drain capture does not join an
RPC already in flight. That RPC can still extend the authority horizon.

Buffer admission checks the captured serving word under the buffer mutex after
every capacity wait for writes, truncation and metadata. The predicate acquires
no frontend lock. Source acquisition checks after waits and before replay
assignment. Scratch-OPEN reacquisition checks before each attempt.

## Physical settlement and cleanup

The pre-close reply cohort is captured once. Canceling its waiter retains its
owners; later refusals and exact cleanup cannot replenish it. Empty admitted
WRITE, barrier and lock results retain their publication until the physical
write and all post-write settlement. Written replies remain discoverable until
lookup rollback, source release and response consumption finish; terminalization
closes the same completion after its settlement. Callback history cleanup still precedes release of the epoch reader;
physical settlement takes no callback fence. Metadata readers are all released
before indexed references, preserving the existing deferred-close ordering.

`PrepareReplyPayload` checks workspace permission before the cache-arena shortcut
and empty candidate handling. Cached-answer refusal rolls back its lookup once.
Accepted mutations retain their exact outcomes and source/response owners. A
SETATTR refusal before buffer acceptance completes as definite no-change, even
if it already acquired or assigned its source lease.
READ includes short and EOF results because the kernel zero-fills folios.
`ReplyWritten` observes delivery: a late successful READ retains its post-write
purge, and delivered metadata retains withdrawal bookkeeping without fresh daemon
cache authority. It cannot reject a write that already reached the kernel.

RELEASE and RELEASEDIR first remove the handle with `takeHandle`; the callback
then owns that handle and its inode pin. Authority handles next enter
`cleanupContext` with the request Unique, and any deferred authority close moves
to counted cleanup before the callback releases its ownership. Local handles
close or release their snapshot directly under callback ownership. The lifecycle
integration must reserve cleanup before handle removal if its drain relies on a
count that spans that handoff; this substrate does not supply that reservation.
FORGET retains its existing counted bookkeeping/RECLAIM ownership. FLUSH preserves
its exact POSIX unlock obligation even when serving or durability fails. Closed, clean
handles return success; dirty or lost work retains its failure. Each description's
accepted prefix names its buffer and epoch. Sequences advance only within that
identity; a successor replaces the old cut only after durability or loss has
disposed of its retained work. Loss reporting keeps its existing handle observer.
INIT and terminal connection notifications bootstrap or retire the connection without a serving
permit. The maintained go-fuse `WaitMountReady` boundary joins the real mount
helper after NewServer completes FUSE INIT, without WaitMount's path probe.
Negotiated kernel validation remains mandatory before Open. The cold proof concerns authority-derived cache authority. Machine-local
backing retains its ordinary local durability and validity semantics; the gate
does not claim to purge every local ext4 kernel cache.

The required privileged root inventory contains a root supervisor/unprivileged
child test of the real sealed page and owner pipe against kernel FUSE and XFS.
It qualifies the admission substrate on the ordinary frontend, not the future
managed launch or protected-path driver. The native workspace inventory is
unchanged. Ordinary mounts reserve no workspace reply owner, take no workspace
registry locks and allocate no gate closures. Unfenced host sleep remains unqualified.

An admitted READ selects its overlay from retained buffer ownership even after
InterruptSubscription clears the incarnation. The callback fence retains that
buffer until the READ returns; FenceSubscription then accounts for its dirty
loss exactly once. Interruption still wakes capacity-blocked writers before
joining callbacks. This ordering also applies to ordinary mounts.
