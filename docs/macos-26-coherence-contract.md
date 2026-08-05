# macOS 26 coherence contract

Status: **failure-model audit and release gate**

This document defines what PortableFS must prove before a macOS 26 FSKit mount
can join the v3 shared-write data plane. It is deliberately separate from the
XFS storage contract: XFS remains the only filesystem truth. The state below is
mount-membership and cache-coordination state, not a second inode tree, a
mutation journal, or file history.

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

The existing v2 macOS teardown code demonstrates the usable local mechanism:
`/sbin/umount` runs in a bounded child process, and `getfsstat(MNT_NOWAIT)`
verifies exact absence afterward. v3 may reuse that mechanism, but not v2's
storage, journal, or history architecture.

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

That paragraph is the required end-state, not a claim about today's macOS
frontend. The Swift foundation now races each delivered phase against the
negotiated repair budget, cancels the repair, reports the cursor blocked, and
terminates its pfslocal client/runner when the timer wins. Those actions stop
the extension from participating in the authority session, but macOS 26 FSKit
exposes no API here that proves already-cached kernel state became unservable.
The watchdog therefore detects and terminates; it does **not** yet self-revoke
or force-unmount the kernel mount. `VolumeCore` continues to reject every v3
resolve with `ENOTSUP` until that withdrawal/absence proof exists.

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
exact pfslocal callback operation ID for a source event. pfslocal minor 8 now
has a dedicated ordered visibility event/ack contract, and `portablefsd` has a
lossless one-event bridge whose source COMPLETE waits for the initiating
callback's `PublicationAck`. The production FSKit volume remains deliberately
gated until it installs that transport together with its namespace index,
callback barrier, and repair backend; a resolve carrying `v3_coherence` closes
and returns `ENOTSUP` today. It never ignores the contract or reinterprets a v2
invalidation as v3 visibility.

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

Production installs no gate: `PortableFSVolume.make` defaults `repairGate` to
`nil`, and with no gate every reserved name is refused `EPERM`. That is the
fail-closed end of the same contract — no repair can run, and no user file can
occupy a name the repair machinery would later claim.

`PfsMacOSCoherenceRunner` records the barrier cursor in its completed ledger
before it acknowledges, so a lost, refused, or cancelled acknowledgment costs a
repeated acknowledgment and never a second run of namespace surgery under a
fresh nonce.

`PfsMacOS26POSIXActuator` rolls the isolating rename back if any later step of
the transaction fails, and re-throws either way; a rollback that itself fails
throws an error naming the stranded operand rather than leaving it unreported.

### What is still refused

`PfsMacOS26RepairArmRegistry.defaultSupportedKinds` contains
`.negativeScratch` and `.positiveEviction` only. `.dataInvalidation` cannot be
armed and therefore cannot be actuated through the gate.

The hidden-rename shape carries provenance in its operand. A plain `ftruncate`
cannot: its FSKit callback carries an item and requested size, but no
unforgeable repair token. An "armed next truncate" table is raceable by an
ordinary process that reads the hidden name out of the directory during the
transaction and issues the same truncate, and it could acknowledge a user
mutation without changing XFS. Until a non-raceable provenance channel or a
native cache-control API is proven, swallowing `ftruncate`/`setattr` as a local
repair is a security and correctness blocker, and the registry refuses to arm
the plan that would need it.

Forwarding an unauthenticated repair truncate is not an answer either. A stale
positive vnode may name the replaced, unlinked inode; changing it would alter
the view of a legitimate open-before-replace descriptor even though the repair
was supposed to affect only kernel cache state.

The hidden-rename actuator also creates a transient local interval in which the
source name is absent: the kernel has completed `source -> authenticated-hidden`
but has not yet removed the hidden name and fetched the authority's current
binding. Draining FSKit callbacks prevents an older callback from publishing
across that interval, but it does not by itself prove that another process
cannot observe the kernel's local rename directly from cache. Production needs
a live test proving the admission gate prevents that observation, or a
different actuator with an atomic replacement boundary. Healthy connected
experiments are encouraging; they are not a proof of ordinary-directory
atomicity.

## Identity, path, and inode number

`VisibilityTarget` carries `scope`, `identity`, `parent_identity`, `name`, and
`size`. It carries no path and no inode number, and it must not: a path is a
per-mount rendering of a tree, and an inode number is a per-mount projection
that the authority cannot compute for a mount it does not run.

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
namespace index at every published/retired coordinate and the live-object index
at every open/retaining-close/reclaim boundary. **The FSKit adapter does not yet
populate either index.** That wiring is part of the live path and is an unmet
release gate, listed below. Production also needs a hard bound for both indexes;
an exact record can be dropped only after synchronous kernel revocation, never
by silent LRU eviction.

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

macOS 26 shared-write support remains blocked. Every item below is unmet
today. Nothing in this section describes existing behavior; it describes what
must be established on the selected production OS build before the live path
may be enabled.

Implemented foundation that is not yet a production mount:

- pfslocal minor 9 carries a validated v3 attach contract, exact two-phase
  visibility events, route-change events, source callback operation IDs, and
  cursor/blocked acknowledgments, plus an on-demand daemon-to-authority
  liveness round trip bound to the resolved epoch and session. The Go bridge is
  lossless, permits one outstanding event, starts an independent repair
  deadline, treats disconnect as terminal, and does not advance source COMPLETE
  before the exact callback publication acknowledgment;
- `PfsLocalMacOSV3CoherenceTransport` consumes that wire shape, validates the
  authority epoch/session/protocol, maps exact coordinates through the local
  namespace and live-object planners, acknowledges through the priority lane,
  and turns route replacement or malformed input into a blocked/terminal
  result. Resolve binds strict participation to one exact UDS connection, which
  cannot reconnect after participant loss. Connect requires the first exact
  authority liveness proof synchronously; an independent priority-lane pulse
  repeats no slower than one third of the repair budget and fails closed on a
  timeout or changed epoch/session. It does not use `SyncVolume` as a liveness
  substitute. The runner also enforces the negotiated local per-phase deadline without waiting for a
  cancellation-ignoring backend, but this is session termination rather than
  kernel-cache withdrawal;
- the planner preserves every hard-link coordinate separately from live FSKit
  objects, including native object-target repair plans for open-but-unlinked
  data and attributes. The macOS 26 backend rejects unpathable object repairs
  rather than acknowledging an empty plan;
- a standalone portablefsd v3 data plane maps the pfslocal operation surface to
  authority RPC, including exact source publication identity, readdir-plus
  items, bounded reads and directory cursors, liveness, stable XFS incarnation
  identity, and `SyncVolume` backed by authority `syncfs(2)`. It remains outside
  the production attach registry until the rest of this list is satisfied; and
- the production `VolumeCore` currently refuses any resolved v3 contract with
  `ENOTSUP`. This guard is intentional: the isolated transport tests cannot be
  mistaken for a live coherent mount.

Gates that still require production integration code:

- production control/registry composition for the standalone v3 data plane.
  The daemon—not Swift—must install the manager-issued mutual-TLS identity and
  access capability, bind the exact authority epoch/session and route revision,
  own the evidence-bearing detach lifecycle, and expose only that independent
  backend to the v3 attach. It must not mix the authority session into the
  legacy `clientcore` attach;
- the FSKit adapter populates `PfsMacOSNamespaceIndex` on every callback that
  publishes or retires every binding, including all hard-link aliases, and
  populates `PfsMacOSLiveObjectIndex` across open, retaining-close, unlink, and
  reclaim. Both are required before an unresolved target is provably uncached
  rather than merely unknown; the two indexes must stay separate so losing the
  last pathname cannot hide an extant vnode from native revocation;
- a `PfsMacOSCallbackPublicationBarrier` implementation that actually closes
  and reopens callback admission, and production installation of the existing
  v3 local transport/runner/backend before FSKit activation;
- a provenance channel for `setattr`/`ftruncate`, without which
  `.dataInvalidation` stays unarmable and the data half of the contract cannot
  be satisfied at all. The public macOS 26.5 FSKit SDK has no vnode/name/data
  cache-revocation API and its only requested mount option is read-only, so
  this is an OS/API blocker rather than missing socket plumbing;
- a watchdog terminal action that makes the exact macOS kernel mount
  unservable (or force-unmounts it and proves exact absence). Closing pfslocal,
  cancelling the runner, and fencing authority credentials do not revoke data
  already resident in the macOS kernel cache;
- a durable participant-membership record, without which the authority-restart
  gate below cannot be met.

Gates that require a live mount to test, and which the doubles in
`Tests/PortableFSKitTests` cannot establish:

- negative lookup, positive lookup, attributes, size, file data, rename-over,
  unlink, and open-before-replace behavior;
- lookups whose replies cross quiesce, repair, and resume boundaries;
- two simultaneous mutators from different mounts without deadlock;
- an initiating mutation plus local repair without nested-VFS deadlock;
- proof that the admission gate prevents an ordinary process from observing the
  transient hidden-rename interval;
- daemon/event-channel freeze, disconnect, reconnect, and exact unmount;
- authority restart with a live old mount;
- hostile races against every swallowed local operation, run through a real
  kernel rather than against the arm registry directly; and
- bounded barrier latency under metadata-heavy workloads.

What the offline suite does establish, without a kernel mount: operand
unforgeability, one-shot consumption under concurrency, callback ordering,
reserved-namespace refusal at the adapter with a mock daemon witnessing that no
request crossed the socket, exactly-once barrier accounting across a lost
acknowledgment, and the two dangerous actuator paths — `.positiveEviction` and
`.dataInvalidation` — executed against a real temporary directory with real
`renameat`/`unlinkat`/`ftruncate`/`mmap`/`msync` syscalls, including their
rollback on failure. Those are real syscalls on a local filesystem; they say
nothing about what the FSKit kernel path does with them.

If any test cannot establish the exact boundary, the frontend fails its
production gate. It does not silently downgrade to asynchronous "mostly
coherent" behavior.
