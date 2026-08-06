# macOS 26 coherence contract

Status: **declared compatibility cache policy — composed and shipping; live-kernel gates open**

This document defines the contract a macOS 26 FSKit mount joins the v3 data
plane under, what the composition actually does today, and what has still not
been proven against a real kernel. It is deliberately separate from the XFS
storage contract: XFS remains the only filesystem truth. The state below is
mount-membership and cache-coordination state, not a second inode tree, a
mutation log, or file history.

The macOS 26 path is a **declared compatibility cache policy**, named
`macos26-synchronous-vfs-repair-v1`. It is selected explicitly by the mount and
validated on both sides; it is never an automatic fallback and never a silent
downgrade from the exact contract. Its owner-accepted fidelity target is
approximately 98 percent: one residual race is known, exactly characterised, and
described in [What the armed truncate coalesces](#what-the-armed-truncate-coalesces)
below. macOS 27's native cache-control API is the primary target and closes that
gap; no implementation of it exists, and selecting the native policy
(`fskit-native-revocation-v1`) fails closed with `ENOTSUP` today.

## Required user-visible boundary

If mutation `M` returns success before operation `R` begins, `R` must not
observe namespace, attributes, size, or data older than `M`, unless a different
operation ordered after `M` changed them again. An operation overlapping `M`
may observe either the before-state or after-state, as it could on one local
machine.

The authority cannot establish that boundary merely by applying `M` to XFS and
then sending an asynchronous notification. macOS 26 may satisfy a lookup,
attribute query, or read from its kernel cache without calling the FSKit
extension. Apple confirms that the current FSKit interface has no general
invalidation mechanism for externally changed items and does not fully support
shared/network filesystems. The June 2026 beta data-cache API is a different,
future platform contract and does not by itself prove negative-name cache
invalidation.

References:

- [Apple DTS: inode invalidation does not currently exist](https://developer.apple.com/forums/thread/821376)
- [FSKit `DataCacheHandler` beta contract](https://developer.apple.com/documentation/fskit/fsvolume/datacachehandler)
- [FSKit cache-coherency actions](https://developer.apple.com/documentation/fskit/fsvolume/kernelcachecoherencyaction)
- [FSKit volume deactivation lifecycle](https://developer.apple.com/documentation/fskit/fsvolume/operations/deactivate%28options%3Areplyhandler%3A%29)

## Participant lifecycle

A mounted macOS 26 volume is a strict coherence participant from before FSKit
activation can publish its root item until the exact kernel mount is proven
absent.

```text
REGISTERING -> ACTIVE -> QUIESCED -> ACTIVE
                    \-> FENCED (session over; membership still recorded)
                    \-> DETACHING -> ABSENT (membership deactivated)
```

The transitions are fail-closed:

- `REGISTERING -> ACTIVE` requires an authenticated mount identity, authority
  epoch, repair channel, and a completed initial cache barrier.
- A broken event socket, daemon crash, missed repair budget, expired session,
  cursor violation, or machine partition moves the participant to `FENCED`.
  Fencing is **participant-scoped**: that mount stops joining new barriers and
  its authority session ends immediately. An obligation already held by the
  current mutation remains for one full additional repair-budget grace, giving
  the mount's watchdog time to revoke its kernel state; it is discharged only
  after that grace (or earlier verified absence). The volume then keeps serving.
- `FENCED` is terminal for that mount incarnation. There is no
  `FENCED -> ACTIVE` edge: a mount whose session ended re-enters only by
  registering as a new incarnation with a fresh initial cache barrier.
- Fencing does **not** remove the participant from durable membership. The
  session is provably over; the kernel mount is not provably gone. Only
  `DETACHING -> ABSENT` deactivates the record.
- `DETACHING -> ABSENT` requires the exact kernel mount to be gone. A clean
  implementation issues unmount outside the long-lived daemon process, then
  reads the mount table without traversing the mounted filesystem and verifies
  that the expected filesystem type, source/attach identity, and mount path are
  absent. Disconnect, an `unmount` callback, or intent to unmount is not proof.
- Participant membership must survive authority-process restart. A fresh
  authority that forgets an old macOS 26 participant and begins accepting
  writes can make that still-mounted kernel serve stale state indefinitely.

The local mechanism is a bounded child process running `/sbin/umount`, followed
by `getfsstat(MNT_NOWAIT)` to verify exact absence without traversing the
filesystem being removed. `portablefsd` owns that transaction — authority sync
barrier, frozen drain, exact kernel unmount, durable attach removal — and the
absence claim it produces is what the authority's configured verification command
corroborates before deactivating a membership record.

### Why an unreachable mount does not block the volume

An earlier revision of this document required the opposite: while any
participant was unreachable, cache-affecting writes stayed blocked until the
mount reconnected or its kernel mount was proven absent. The implemented design
(`vcs/internal/volumeserver/visibility.go`) does not do that, and the reason is
not availability appetite — it is that blocking bought nothing the frontend
budget does not already buy.

The objection to fencing was: server-side credentials can reject future FSKit
callbacks, but they cannot stop the macOS kernel serving a cached read *without*
a callback. That is still true, and it is exactly why a strict mount states a
**repair budget** at attach and is bound by it from its own side. The frontend
must self-revoke when that budget elapses without an authority round trip — on
Linux, `Mount.revoke` withdraws every binding this mount published to the kernel
and then aborts the FUSE connection, after which every request on that mount
fails `ENOTCONN`. So the window in which a lost mount could serve a stale name is
bounded by a number that mount committed to, whether or not the authority is
still talking to it.

The authority therefore fences the lost participant immediately but retains the
current obligation for one full additional repair budget. The frontend's
authority-contact watchdog runs at no more than one third of that budget, so it
must make the old kernel cache unservable before the obligation is discharged.
This bounds one failed phase at two budgets (its phase deadline plus fencing
grace) without converting a broken laptop into an indefinite volume-wide outage.

That paragraph is the required end-state. The Linux half of it is implemented
and tested. The macOS half is implemented in two cooperating layers. The Swift
runner races each delivered phase against the negotiated repair budget,
cancels the repair, reports the cursor blocked, and terminates its pfslocal
client and runner when the timer wins — but macOS 26 FSKit exposes no API that
proves already-cached kernel state became unservable, so the runner alone can
only detect and terminate. The revocation itself lives in the per-mount
supervisor process (`cmd/portablefs/internal/cli/fskit_revocation.go`), which
is daemon-independent by construction: it probes the daemon's attach status at
one third of the repair budget, and when the session is terminal, the daemon
is unreachable, or the daemon no longer owns the attach, it force-unmounts the
exact identity-proven kernel mount. `MNT_FORCE` revokes the covered vnodes at
the VFS layer, which dead-ends every cached page — the one revocation
primitive macOS 26 does provide. The stale window for a cached read on an
already-open descriptor is therefore bounded by probe confirmation plus one
forced unmount, inside the authority's one-budget fencing grace; bytes a
process already copied into its own memory are out of scope on every platform.
Each forced-unmount attempt is itself bounded to a third of the repair budget
— never the operator-scale 30-second platform unmount budget — and retried at
the watchdog interval, so a wedged `/sbin/umount` cannot silently spend twice
the grace inside one attempt. What no client can bound is a kernel that
refuses forced unmount past the grace; that refusal is this contract's
residual, and it is the same shape as a hung kernel on any platform.

The load-bearing kernel claim is live-proven. On a real macOS 26 mount with a
descriptor held open and its bytes cached, portablefsd was killed with
`SIGKILL`: the descriptor answered from the kernel's cache for 8.6 seconds —
the exact exposure the watchdog exists to bound — then the watchdog detected
the death, force-unmounted the identity-proven kernel mount at ~10 seconds,
and from that instant every further `pread` on the held descriptor failed
`EIO`. The supervisor finalized locally with the session ending fenced and no
stale record left behind. Ten seconds is inside the one-budget fencing grace,
so the contract's bound holds end to end.

What is *not* traded away: the fenced mount stays in durable membership, so the
authority-restart gate below still applies to it in full. Availability is
preserved inside an epoch and paid for across one, where an operator is present
to supply the fencing proof.

## Mutation barrier

A post-commit repair acknowledgment is necessary but not sufficient. A
cache-producing callback already in flight can publish an old result after the
repair, and a concurrent stale callback can submit an operation based on the
old binding. The complete barrier for a cache-affecting mutation is:

1. Acquire the volume's cache-mutation ticket.
2. Ask every active macOS 26 participant to close ordinary callback publication
   admission.
3. Wait for every already-admitted cache-producing callback to return its FSKit
   reply and acknowledge that publication boundary.
4. Apply the mutation to XFS.
5. Perform the required, authenticated local cache action on every quiesced
   non-initiating participant and wait for its acknowledgment.
6. Queue `COMPLETE` for the initiating mount and return the mutation result so
   its blocked FSKit callback can publish the ordinary result.
7. The initiating mount publishes that callback, reopens its local admission
   gate, and acknowledges the deferred `COMPLETE` without nested VFS repair.
8. Before admitting the next cache-visible mutation, wait for that deferred
   acknowledgment or exact proof that the source kernel mount is absent.

Operations that finish before step 4 and operations that begin after step 8
are unambiguous. Operations that overlap the interval may legally observe the
before-state, but cannot publish it after the quiesce acknowledgment.

The protocol must handle the initiating mount explicitly. If its own mutation
callback is counted among the callbacks that step 3 waits to finish, it waits
for the authority reply while the authority waits for it: a deadlock. A
mutation ticket therefore identifies exactly one initiating callback, keeps
its reply unpublished, and excludes only that callback from the drain. A
second mutator that has not acquired the ticket is queued outside publication
admission; it is not an active callback the first mutation waits to drain.

The authority must also avoid asking the initiating mount to perform a nested
VFS repair that the kernel serializes behind the initiating callback. The
initiating operation's normal FSKit result must be proven sufficient for its
local cache changes, or the platform test fails. This is a release proof, not
an assumption.

Skipping the initiating mount's `COMPLETE` phase outright is not valid. It
leaves that mount's cursor at `PREPARE(N)`, makes `PREPARE(N+1)` a sequence gap,
and gives the authority no proof that the initiating callback published its
ordinary result and reopened its local gate. The source completion is deferred,
not omitted: the authority may return mutation `N` without waiting for it, to
avoid self-deadlock, but it records a pending `COMPLETE(N)` obligation. The
source acknowledges that obligation only after its FSKit reply has crossed the
framework publication boundary. Mutation `N+1` cannot begin until the deferred
acknowledgment arrives or exact kernel-mount absence satisfies it. A lost reply
replays the same mutation and completion identity; it never creates a second
source exemption.

The v3 Swift coherence model represents PREPARE and COMPLETE as distinct cursor
phases and carries the opaque initiator session/slot/sequence ticket plus the
exact pfslocal callback operation ID for a source event. `portablefsd` has a
lossless one-event bridge whose source COMPLETE waits for the initiating
callback's publication acknowledgement. The production FSKit volume installs
that transport together with its namespace and live-object indexes, the callback
barrier, and the repair backend, and it does so as one composition: if any part
of it fails to build, the volume shuts the core down and fails the mount rather
than serving without it. A resolve is admitted only when it declares
`macos26-synchronous-vfs-repair-v1`; any other policy string, including the
macOS 27 native one, closes the client and returns `ENOTSUP`.

A single volume-wide ticket is the simplest correct starting point. Finer
path/inode tickets are an optimization only after measurements justify their
additional lock ordering, rename, hard-link, and deadlock surface.

## Repair provenance

Every macOS 26 synthetic cache operation must be local-only by construction.
It must be rejected before the authority RPC boundary and must never mutate
XFS.

A reserved filename prefix is not authentication. A repair capability must be
unpredictable and one-shot, and bind at least:

- local mount incarnation;
- authority epoch and barrier sequence;
- repair action;
- target item/parent and name; and
- explicit consumption state.

The list deliberately says consumption state and not expiry. A wall-clock
provenance window has already destroyed user data in this codebase: a repair
that becomes valid for an interval is a repair an ordinary process can walk
into. Authorization here exists between `arm` and `finish`/`cancel` and at no
other time.

### What the code does today

`Sources/PortableFSKit/MacOSV3Coherence.swift` mints the operand:
`PfsMacOS26RepairAuthenticator.makeOperand` builds
`version || kind || sequence || step || nonce` plus a 16-byte HMAC-SHA256 tag
under a 32-byte per-mount key, hex-encoded behind the `.portablefs-v3-r1-`
prefix. The tag covers the epoch, the mount session UUID, the parent and item
stable identities, and a hash of the source name.

`Sources/PortableFSKit/MacOSV3RepairGate.swift` enforces it.
`PfsMacOS26RepairArmRegistry` is one actor implementing both
`PfsMacOS26RepairArmer` and `PfsMacOS26RepairGate`, so "is this callback
authorized?" and "mark it consumed" are a single indivisible actor step:

- `arm` re-validates the operand's HMAC against the plan it arrived with, so a
  forged or step-shifted plan opens no window, and records the ordered list of
  FSKit callbacks that plan declared.
- `consume` admits exactly one callback at a time, in the declared order, and
  only when the rename callbacks name the exact source the HMAC binds.
- `finish` requires every declared callback to have been consumed exactly once.
- A transaction that moved a user's name to the hidden operand and neither
  removed it nor put it back is recorded as torn and permanently seals the
  registry; nothing is armed again.

`Sources/PortableFSKit/OperationsAdapter.swift` is the boundary.
`PortableFSVolume` checks `PfsMacOS26RepairAuthenticator.isReserved` on
`createItem`, `removeItem`, `renameItem` (both names), `createSymbolicLink`,
and `createLink`, before the pfslocal publication boundary. A reserved name is
either the armed transaction's next declared callback — consumed locally, with
no pfslocal request emitted — or refused `EPERM`. Symlink and hard-link
creation are refused unconditionally, because no repair plan contains either.
The scratch item the swallowed create returns is minted from a reserved top
band of the identifier space that `PfsFSKitMapping.itemIdentifier(from:)`
refuses for daemon items, and it rejects `setAttributes`, `read`, and `write`.

Production installs the gate. `PortableFSFileSystem.loadResource` connects
`VolumeCore`, which validates the declared cache policy and records the resolved
strict contract; `PortableFSVolume.make` then composes
`PfsMacOSV3VolumeCoherence` and installs its `repairGate` on the volume. A
composition failure shuts the core down and rethrows, so the mount fails closed
rather than activating without coherence. A volume built without a gate — which
production no longer produces — refuses every reserved name `EPERM`, which is
the same contract's other end: no repair can run, and no user file can occupy a
name the repair machinery would later claim.

`PfsMacOSV3VolumeCoherence` also owns the two client-side indexes and the
callback barrier, and it binds the POSIX actuator's mount root lazily: the root
descriptor is opened on the first served callback, and until it is installed the
actuator fails `ENXIO` rather than acting on an unidentified directory.

`PfsMacOSCoherenceRunner` records the barrier cursor in its completed ledger
before it acknowledges, so a lost, refused, or cancelled acknowledgment costs a
repeated acknowledgment and never a second run of namespace surgery under a
fresh nonce.

`PfsMacOS26POSIXActuator` rolls the isolating rename back if any later step of
the transaction fails, and re-throws either way; a rollback that itself fails
throws an error naming the stranded operand rather than leaving it unreported.
Before it acts, it compares the operand's `st_ino` against the
`expectedVFSFileID` the planner derived locally, so a coordinate that no longer
names the object the plan was built for is an error rather than surgery on the
wrong inode.

### The armed truncate

`.dataInvalidation` is armed in production.
`PfsMacOS26RepairArmRegistry.defaultSupportedKinds` contains `.negativeScratch`,
`.positiveEviction`, and `.dataInvalidation`, and `compose` builds the registry
with that default. This is the one place where the declared policy admits a
callback that carries no operand of its own, so the provenance is stated exactly.

A plain `ftruncate` cannot carry a reserved name: its FSKit callback carries an
item and a requested size and nothing else. An "armed next truncate" table keyed
on nothing but intent would be raceable by any process that reads the hidden name
out of the directory during the transaction, and it could acknowledge a user's
mutation without changing XFS. The registry therefore admits a truncate only
inside a coordinate that an ordinary process cannot address by accident:

- **Arm time.** The plan must carry both a non-nil `expectedVFSFileID` and a
  non-nil `authoritativeSize`, and its operand HMAC must validate over the
  authority epoch, the barrier sequence, the step, the kind, the parent identity,
  the item identity, and the source name, under the per-mount key bound to that
  mount's session UUID. A forged or step-shifted plan opens no window.
- **Consumption time.** The transaction must be a `.dataInvalidation`, its
  isolation window must be open, the callback's item stable identity must equal
  the plan's, and the requested size must equal the plan's exact authoritative
  size. Epoch and sequence are bound transitively: they were verified into the
  operand HMAC at arm time and cannot be re-shaped afterwards.
- **The window is namespace state, never a clock.** It is open exactly between
  the operand rename and the operand removal, and closed by rollback. There is no
  interval an ordinary process can wait for.
- **The adapter narrows it further.** A consumed truncate must set only `size`;
  a callback that also sets mode, uid, gid, or flags is not a repair. Removing the
  operand is refused until the truncate has been consumed, and `finish` requires
  it, so the nameless half of the transaction cannot be skipped.

Forwarding an unauthenticated repair truncate to the authority is not an
alternative. A stale positive vnode may name the replaced, unlinked inode;
changing it would alter the view of a legitimate open-before-replace descriptor
even though the repair was supposed to affect only kernel cache state.

### What the armed truncate coalesces

This is the residual race, stated exactly. It is the reason macOS 26 is a
declared compatibility policy with an approximate fidelity target rather than the
exact contract.

A process that, during the isolation window, addresses the hidden operand and
truncates it to exactly the authoritative post-state size has that metadata-only
effect coalesced with the repair. It observes success for a syscall the authority
never saw. Reaching that state requires reading a per-transaction hidden name out
of the directory inside a window bounded by two authority round trips and issuing
a truncate to one exact byte count, but it is possible, and it is not detected.

A second, narrower coalescing follows from the same key. The armed-truncate check
is keyed on stable identity alone, so while the window is open, any `openItem` or
`closeItem` for that identity — not only the actuator's own — returns locally
without a corresponding daemon open or close. The observable effect is confined
to open bookkeeping for one item during one window, but it is a real deviation
and is recorded here rather than left implicit.

macOS 27's native cache-control API removes the need for the hidden-rename shape
entirely and therefore closes both.

### What is still refused

`.invalidateDataObject` and `.invalidateAttributesObject` — the repairs a native
revoker would use for an open-but-unlinked vnode with no remaining path — are
unrepresentable on macOS 26. The backend refuses to build a plan for them, so
such a barrier fails closed and is never acknowledged.

The hidden-rename actuator also creates a transient local interval in which the
source name is absent: the kernel has completed `source -> authenticated-hidden`
but has not yet removed the hidden name and fetched the authority's current
binding. Draining FSKit callbacks prevents an older callback from publishing
across that interval, but it does not by itself prove that another process
cannot observe the kernel's local rename directly from cache. That proof needs a
live kernel; it is an open gate below.

## Identity, path, and inode number

`VisibilityTarget` carries `scope`, `identity`, `parent_identity`, `name`, and
`size`. It carries no path, and it must not: a path is a per-mount rendering of a
tree that the authority cannot compute for a mount it does not run.

It does carry explicit kernel-cache coordination facts — `kernel_ino`,
`parent_kernel_ino`, and `device` — and the reason is worth stating, because an
earlier revision of this document asserted the opposite and the code was wrong to
match it. The stable identity is an XFS export handle: it encodes type, inode,
and generation, and never a device. A frontend that indexes by item identity
needs nothing else, but a FUSE frontend keys its kernel caches by the inode
number the authority publishes in attributes. When those facts did not travel,
the FUSE frontend parsed them out of an identity whose layout does not contain
them, and the first strict repair against real XFS revoked every mount. The
coordination facts now travel explicitly, as separate fields, so neither frontend
has to infer a projection from an opaque handle.

`Sources/PortableFSKit/MacOSV3Namespace.swift` derives both on the client.
`PfsMacOSNamespaceIndex` maps a stable identity to its parent identity, its
name, and the `st_ino` this mount projects; `path(for:)` walks the parent chain
to the mount root under a bounded depth and refuses a chain that cycles.
`PfsMacOSRepairPlanner` turns targets into `PfsMacOSCacheRepair` values, filling
in `path` and `expectedVFSFileID` from that index. A negative repair retains the
exact target name even though the macOS 26 synthetic actuator cannot address a
negative dentry directly; the future native adapter must prove what its chosen
parent/item action does to that exact child before acknowledging. A separate
`PfsMacOSLiveObjectIndex` maps the same stable identity to every still-live
`PortableFSItem`; unlink retires the alias but not that object. If no path
remains, the planner emits direct object-target data/attribute repairs for a
future native macOS 27+ revoker. The macOS 26 backend rejects those repairs, so
an unpathable open object fails the barrier and is never acknowledged.

A skip is sound only when the identity is absent from both indexes: the kernel
cannot hold a cached binding this extension never returned, and it has no live
object after the last close/reclaim. Upholding that claim requires updating the
namespace index at every published or retired coordinate and the live-object
index at every open, retaining-close, and reclaim boundary. The adapter now does
this. Every callback that publishes a binding records it — `lookupItem` on a hit,
`createItem`, `createSymbolicLink`, `createLink`, both sides of `renameItem`, and
every entry packed by `enumerateDirectory` — `removeItem` retires the binding
while deliberately keeping the live object, `openItem` records the live object on
both its repair-isolated and ordinary branches, and `reclaimItem` retires it.
Callbacks that publish no binding — attribute reads and writes, symlink reads,
data reads and writes, xattr operations — record nothing, which is correct
because they cannot introduce a coordinate the kernel did not already hold.

The namespace index is keyed by `(parentIdentity, name)` with a reverse index
from identity to keys, so every hard-link alias survives independently. Both
indexes are hard-bounded, and the bound is a refusal rather than an eviction
policy: over capacity, the recording callback fails `EIO`. An exact record may be
dropped only after synchronous kernel revocation, never by silent LRU eviction,
so a bound that is too small is a loud mount failure rather than a quiet
coherence hole. An item with no 16-byte stable identity fails its callback for the
same reason.

## Authority restart and host loss

Same-epoch replay slots do not solve cache membership across authority death.
Before a replacement authority accepts a cache-affecting mutation, it must know
the complete set of macOS 26 mount incarnations admitted by the previous epoch
and obtain one of these proofs for each:

1. the same mount reconnected and completed a current-epoch barrier; or
2. the exact kernel mount was removed; or
3. an infrastructure fence guarantees that host incarnation cannot run again
   with the old mount.

That participant list is small coordination metadata and may live in a
strongly consistent control record. It is not filesystem content or operation
history. If PortableFS refuses any durable membership record, the honest
alternative is to keep macOS 26 multi-writer support experimental and not
claim exact behavior across authority restart or a partitioned mount.


## Release gates

This section is the honest ledger. The first list is what the composition
establishes today; the second is what remains open, and every item in it is a
reason the macOS 26 path is a declared compatibility policy rather than the exact
contract.

### Established

- The mount declares `macos26-synchronous-vfs-repair-v1` and the authority
  validates it. `VolumeCore` admits only that policy; an unknown string or the
  macOS 27 native policy closes the client and fails `ENOTSUP`. A second,
  independent check refuses a runner whose backend policy disagrees with the
  resolved contract, so the two cannot drift apart silently.
- `portablefsd` serves a real v3 authority attach: mutual-TLS dial with no mode
  fallback, a real coherence contract on resolve, every operation routed to the
  v3 data plane, and an evidence-bearing detach that either delivers a
  mount-absence proof or ends fenced.
- The FSKit composition is installed as one unit at `loadResource` time, and a
  failure to build it fails the mount closed rather than activating a volume with
  no coherence.
- Both client indexes are populated from every binding-publishing and
  binding-retiring callback, with hard-link aliases preserved separately from
  live objects, and both bound by refusal rather than eviction.
- A real publication barrier closes and reopens callback admission, drains
  already-admitted callbacks to the point where their FSKit reply has crossed the
  framework boundary, and identifies exactly one initiating callback so the
  source cannot deadlock against its own mutation.
- The repair gate is installed, its operands are unforgeable and one-shot, its
  declared callbacks are consumed exactly once in order, and a torn transaction
  permanently seals the registry.
- `.dataInvalidation` is armed under the exact one-shot provenance described
  above, with the residual coalescing stated rather than hidden.
- The authority carries kernel-cache coordination facts explicitly, so a strict
  repair against real XFS addresses the coordinate the frontend actually keys on.
- The revocation watchdog is implemented in the per-mount supervisor and
  live-proven end to end: probes at one third of the repair budget, confirmed
  daemon-death detection, one-probe revocation of a terminal session (the
  daemon reports terminality as a machine-readable field, not prose),
  identity-proven forced unmount, and local finalization when no daemon
  barrier remains to run. In the live kill drill the forced unmount revoked a
  held-open descriptor's cached reads at ~10 seconds after daemon death — the
  8.6-second cached-read window before it is the bounded exposure the
  contract declares, and `EIO` from the revocation instant onward is the
  proof the bound is real.
- Live-kernel evidence now exists for part of the path: a real `pfs` FSKit
  mount against a real XFS authority has served reads, writes, creates,
  renames, symlinks, enumeration, and rename-over-an-open-descriptor with the
  strict barrier completing on those mutations, and the authority-restart
  refusal plus operator fencing assertion drill has been run once end to end.
  What has NOT been shown is a full storm-heavy battery completing green on an
  identity-verified live mount — see the PREPARE-stall item below.
- The offline Swift suite establishes operand unforgeability, one-shot
  consumption under concurrency, callback ordering, reserved-namespace refusal at
  the adapter with a mock daemon witnessing that no request crossed the socket,
  exactly-once barrier accounting across a lost acknowledgment, index population
  and capacity refusal, barrier behaviour, and the dangerous actuator paths
  executed against a real temporary directory with real `renameat`, `unlinkat`,
  `ftruncate`, `mmap`, and `msync` syscalls including their rollback. Those are
  real syscalls on a local filesystem. They say nothing about what the FSKit
  kernel path does with them.

### Open — these require a live kernel

Nothing in the Swift suite mounts a real FSKit volume, and the one live-path test
is opt-in, drives `VolumeCore` over a socket, and does not exercise a kernel
mount. The following are therefore unproven:

- **Mount-root binding.** That the actuator's mount-root locator finds the real
  `pfs` mount through `getfsstat` and that the root inode number matches. Until
  the root is bound the actuator fails `ENXIO`; nobody has watched it succeed on
  a live kernel.
- **Kernel callback shapes for the data path.** That a real macOS 26 kernel
  delivers the truncate, open, and close callbacks in the shape and order the
  armed transaction declares, rather than in a shape the gate refuses.
- **That the synthetic repairs do what they are assumed to do.** That create plus
  unlink actually purges a negative dentry; that rename-to-hidden plus unlink
  actually purges a positive dentry and its cached attributes; that `ftruncate`
  plus `mmap(MAP_SHARED)` plus `msync(MS_INVALIDATE)` actually drops the kernel's
  cached pages and EOF for an FSKit vnode.
- **Hostile races through a real kernel.** Every swallowed local operation, raced
  by an ordinary process against a real VFS rather than against the arm registry
  directly. This includes the specific question of whether the admission gate
  prevents observation of the transient hidden-rename interval.
- **The storm-death investigation, closed.** Under `git init`-class
  workloads live mounts repeatedly missed the repair budget acknowledging a
  PREPARE and were fenced. Instrumenting every teardown choke point exposed
  three stacked defects, each fixed at the root: the daemon's frontend
  reader enforced one global strictly-increasing request-ID watermark across
  a two-lane transport whose control lane legally overtakes the request lane
  (now one watermark per lane); a fast cancellation let an operation's
  acknowledgment overtake its own request on the priority lane (now gated on
  the stamped requests' write receipts); and — the deep one — the PREPARE
  drain waited for admitted callbacks whose requests were still in flight,
  while the authority parks affected-coordinate reads until every strict
  mount acknowledges that very PREPARE: a cross-layer deadlock cycle the
  Linux frontend never had because it drains nothing. The drain now waits
  only for callbacks that are actually installing; a released callback with
  a parked mutation installs normally (its result is ordered after the
  barrier), and one released holding pre-barrier cache-producing replies is
  refused at install with EINTR, the retraction verdict. Live evidence,
  identity-verified on every assertion: fifteen consecutive `git init`s and
  four consecutive full batteries (14/14 each) on one live mount that was
  still serving afterwards. (An earlier revision claimed surviving batteries
  that had in fact run against the bare directory beneath a dead mount; the
  battery now asserts the kernel mount's identity from the mount table
  before every verdict, so that class of false result cannot recur.)
- **Verified deactivation of durable membership.** The restart-refusal half of
  the drill has been run live: an authority restart was refused while old
  strict membership existed, and the operator fencing assertion cleared it
  after the kernel mount was proven absent. The other half — a clean detach
  whose mount-absence claim is corroborated by the configured verification
  command and deactivates membership without any operator assertion — has not
  been observed live.
- **The live cross-platform matrix.** `scripts/coherence-matrix-macos.sh` runs the
  same 23 cases against two already-mounted paths, including a remote Linux peer.
  It has not been run against a live macOS mount, so no macOS-to-Linux result
  exists.
- **Bounded barrier latency under metadata-heavy workloads.**

### macOS 27

macOS 27's native cache control is the primary target, not an eventual
improvement. It removes the hidden-rename actuator entirely, closes the armed
truncate's residual coalescing, and makes the open-but-unlinked object repairs
representable. The surface exists in this tree only as an SDK-symbol-free
protocol with no conformance; nothing implements it, and the policy that would
select it fails closed. Release remains gated on the final SDK plus the same live
matrix — an OS version number is not accepted as proof.

If any of these gates cannot establish its exact boundary, the frontend fails.
It does not silently downgrade to asynchronous "mostly coherent" behaviour, and
it does not quietly widen the declared policy's accepted deviations.
