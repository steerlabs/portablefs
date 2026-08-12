# macOS 26 coherence contract

Status: **shipping compatibility policy; final macOS 26.5/Linux/XFS breadth,
saturation, repair, and daemon-death recovery run live-proven**

PortableFS has one filesystem truth: the authority's mounted XFS tree. A macOS
mount never owns a second inode tree, mutation journal, offline write tail, or
fallback data path. FSKit is a cached projection of that XFS authority.

macOS 26 joins v3 by explicitly selecting
`macos26-synchronous-vfs-repair-v2`. The authority and frontend validate that
name at attach. It is never selected automatically and never falls back to a
weaker consistency model. This is a bounded compatibility contract, not a
numeric success-rate target. The exact deviations and saturation acceptance
criteria are stated below.

`fskit-native-revocation-v1` is the separate macOS 27 policy. It uses the same
authority, sessions, visibility protocol, replay model, and indexes, but replaces
synthetic VFS cache repair with native FSKit cache control. No implementation is
present in the Xcode 26 tree, so selecting it currently fails closed with
`ENOTSUP`.

## User-visible ordering

If mutation `M` returns success before operation `R` starts, `R` must not
observe namespace, attributes, size, or bytes older than `M`, unless another
operation ordered after `M` changed them again. Operations that genuinely
overlap may observe either side of the transition, as on one local machine.

An asynchronous notification cannot establish this boundary. macOS 26 can
answer lookups, attributes, and reads from kernel cache without calling the
extension, and it has no general module-initiated cache-revocation API. The
compatibility policy therefore repairs the kernel cache synchronously inside
the authority's mutation barrier.

Relevant platform contracts:

- [Apple DTS: inode invalidation does not currently exist](https://developer.apple.com/forums/thread/821376)
- [FSKit `DataCacheHandler` beta contract](https://developer.apple.com/documentation/fskit/fsvolume/datacachehandler)
- [FSKit cache-coherency actions](https://developer.apple.com/documentation/fskit/fsvolume/kernelcachecoherencyaction)
- [FSKit volume deactivation lifecycle](https://developer.apple.com/documentation/fskit/fsvolume/operations/deactivate%28options%3Areplyhandler%3A%29)

## One authority scheduling model

Each strict participant declares how its frontend executes visibility repair:

- Linux cached FUSE uses `PARENT_EXCLUSIVE`.
- macOS 26 v1 uses `CALLBACK_SERIALIZED`; current v2 uses
  `CALLBACK_SERIALIZED_PIPELINED`.
- macOS 27 native repair uses `INDEPENDENT`.

These are authority execution contracts, not OS-version guesses.

Frozen policy v1 uses `CALLBACK_SERIALIZED`: the authority will not allow any
mutation from that participant to wait while it owes PREPARE or deferred
COMPLETE. Current policy v2 uses `CALLBACK_SERIALIZED_PIPELINED`, which carries
the frontend's exact pfslocal operation ID and a request-scoped
`source_phase_queueable` proof on every visible authority mutation. A peer phase
may interrupt every kind of ordered mutation from the macOS participant
(definite-preapply); namespace, data, size, attribute, link, and other ordered
families have no exemption. An unknown identity, the same callback as the
pending source phase, or a false proof is interrupted too. A distinct nonzero
callback may queue behind its own source phase only when that exact ordered
request carries `source_phase_queueable=true`. True means the frontend
committed the request while its callback had submitted no ordinary request of
any kind and will
exclude that ordered-only callback from its own-source PREPARE drain. False is
fail-safe: mixed callbacks are interrupted before prepare or XFS apply. Source
repair does not enter FSKit, and deferred source COMPLETE waits only for the
callback that initiated it, so the explicitly proven queue has no reverse
dependency.

Every interruption occurs before prepare, XFS apply, or any repair callback.
The reply is `EINTR`, marked `uncertain=false`, and retained as that replay-slot
outcome; an exact replay returns the same refusal and never executes the
mutation. The frontend operation ID is scheduling metadata rather than
filesystem content. `source_phase_queueable` is scheduling metadata too, not a
capability. Both are excluded from the mutation's canonical content hash; the
replay slot and sequence still retain exactly one outcome.

These two explicit profiles remove the two-writer callback-lane cycle without
turning a normal FSKit writeback burst into application-visible cancellation.
A callback never waits on a repair that must re-enter its own FSKit volume; only
separate callbacks may pipeline behind a source phase that performs no local
actuation. Linux does not inherit this volume-wide rule: its
`PARENT_EXCLUSIVE` profile uses an exact parent gate and interrupts only an
authority request whose held parent overlaps cached-name work in the pending
COMPLETE. macOS 27's `INDEPENDENT` profile inherits neither interruption rule.

## Mutation barrier

A cache-affecting mutation follows one ordered protocol:

1. Acquire the authority's volume mutation order.
2. Deliver PREPARE to every active strict cached participant.
3. Each macOS 26 participant closes admission for overlapping callbacks.
4. Drain or cancel already-admitted overlapping callbacks as described below.
5. Apply the mutation once to XFS.
6. Deliver COMPLETE and synchronously repair every non-initiating cache.
7. Return the initiating mutation so its ordinary FSKit reply can publish.
8. The source acknowledges deferred COMPLETE only after that framework reply
   crosses the publication boundary.
9. Do not admit the next mutation until the deferred obligation clears, the
   participant is fenced, or exact mount absence is proven.

The initiating callback is exempt from its own PREPARE drain by its exact
pfslocal operation ID. Exempting by mount, path, process, or timing would be too
broad. A transparent publication reissue replaces the ticket's operation ID
with the surviving attempt's ID, so deferred COMPLETE cannot acknowledge an
already-retracted attempt.

### macOS callback admission

The Swift adapter declares typed callback selectors: exact namespace
coordinates, parent-directory lanes, stable items, and ordered mutations. It
also records a lock-linearized ingress reservation synchronously before it
spawns the callback `Task`. PREPARE adopts every reservation on its side of that
cut before its first suspension; later reservations still pass through actor
admission after preflight and authenticated repair-exemption checks. A
reservation is accounting only and never grants request permission. The same
ticket remains task-local through operation-ID stamping, and is retired only
after the FSKit reply closure returns.

When PREPARE closes a scope:

- A new overlapping callback fails immediately with `ECANCELED`, before any
  pfslocal request. macOS 26 was live-observed to transparently re-enter
  mutating callbacks after `EINTR`, `EBUSY`, and `EAGAIN`; policy v2 therefore
  uses the non-restartable definite-preapply verdict.
- Under policy v2, an affected callback whose ordinary request was already
  submitted finishes that request naturally, but cannot submit another one.
  PREPARE waits until its reply crosses the FSKit framework boundary before
  starting the VFS actuator. A callback that had not submitted work yet is
  refused immediately. Frozen v1 retains request-local cancellation and drops
  the drained late reply without poisoning the shared connection.
- For a peer PREPARE, every already-submitted ordered macOS mutation remains on
  the definite-preapply interruption path, regardless of operation family or
  callback identity. The authority returns classified Linux `EINTR`;
  portablefsd maps that exact class to Darwin `ECANCELED` before FSKit sees it.
  Source-only pipelining is not permission to wait through a peer repair.
- For a v2 source PREPARE, the exact initiating operation remains exempt. A
  pre-admitted pristine callback parks before dispatch. A distinct callback's
  already-committed ordered request is excluded from the drain only when its
  request-scoped `source_phase_queueable` bit is true, which proves the callback
  had submitted no ordinary request of any kind when that request committed.
  Its later requests park locally through exact COMPLETE ACK while the committed
  request queues at the identity-aware authority. A mixed callback carries
  false: Swift revokes and drains it, and the authority interrupts its ordered
  request definite-preapply instead of queueing it behind PREPARE. The pre-stamp
  transition is a first-class ticket state, so PREPARE cannot mistake a
  committed ordered-only callback for a stale read or wait for the callback it
  just queued. Peer phases, same or zero operation IDs, false proofs, and frozen
  v1 remain on the interruption path.
- Disjoint reads may continue. Namespace mutation selectors remain conservative
  because live testing proved FSKit may serialize distinct children through the
  same parent callback lane.

After local COMPLETE finishes, the repair actuator no longer needs an FSKit
callback lane, but the authority still owns mutation order until it accepts the
exact COMPLETE acknowledgement. Overlapping callbacks therefore park locally
in this ACK-only state. They are admitted only after that exact epoch, sequence,
and phase is acknowledged; a stale or mismatched ACK cannot release them.

Visible mutations use an eligibility-aware cancellable FIFO. If a peer phase
interrupts an authority waiter, the coordinator retains its immutable arrival
ordinal off-list. If PREPARE instead refused the callback wholly inside FSKit,
the frontend coalesces all ordered refusals into one boolean on that exact peer
COMPLETE acknowledgement; a PREPARE-time off-list cut supplies the ordinal that
the late feedback cannot reconstruct. Exact COMPLETE may activate one credit
for at most one second, clamped to the mount's repair budget. A fresh queueable
ordered callback may claim it; the interrupted callback's own operation ID is
excluded. If another peer phase begins before a claim is possible, the same
single credit rolls to that sequence with its earliest ordinal and its claim
window restarts only at the newer exact COMPLETE.

The credit is never a queue node: an absent retry creates no owner, wait, or idle
window. Cancellation consumes a claimed credit, expiry discards it, and detach
or fencing deletes it. Duplicate, stale, PREPARE, source, route-change, frozen
v1, uncached, false, and inapplicable hints cannot mint priority or change ACK
acceptance. This mechanism changes only effective FIFO position; it never
changes eligibility, replay identity, mutation errno, or the definite-preapply
boundary.

Only `ECANCELED` is visible for an active-repair publication refusal under v2.
It means no authority mutation was applied. A distinct-callback source pipeline
with an explicit true proof waits and therefore exposes no refusal. The
authority's internal
`EINTR` remains visible to Linux, where it releases an exact parent lock, but
never crosses the macOS 26 policy-v2 edge. Once a mutation frame has crossed
pfslocal, cancellation drains its exact result; an unrecoverable result loss is
terminal `EIO`, not a retryable errno. Frozen policy v1 retains its original
boundary: authority interruption is `EINTR` and local admission refusal is
`EBUSY`.

## macOS 26 repair actuator

The daemon holds an independently attested descriptor for the exact live mount
root. It issues bounded relative syscalls through that descriptor; the sandboxed
extension authenticates and consumes the resulting callbacks locally. No repair
callback crosses pfslocal or changes XFS.

The four repair shapes are:

1. **Negative name:** create and unlink one authenticated process-local scratch
   child in the cached parent. This purges a negative dentry.
2. **Positive binding:** `unlinkat` the exact cached source coordinate locally.
   The plan authenticates the stable parent, source name, stable item, and item
   kind. Directories use `AT_REMOVEDIR`; files and symlinks do not. XFS retains
   its binding, so the next lookup republishes authority truth.
3. **Attributes:** open the exact file or directory with `O_NOFOLLOW`, attest its
   stable identity and this mount's projected VFS inode, then issue `fchmod` to
   the vnode's existing mode. During that bounded syscall window the gate
   coalesces strictly mode-only `setAttributes` callbacks for the authenticated
   exact item. FSKit exposes no caller or repair token with which to distinguish
   the actuator's existing-mode `fchmod` from a racing user callback. After
   COMPLETE, the adapter reads and returns a full authority attribute snapshot,
   so FSKit replaces its cached attributes. The no-op `fchmod` never becomes an
   authority mutation. Symlinks cannot be opened
   safely for this operation on macOS 26 and therefore fail closed.
4. **Data/size:** open the exact source with `O_NOFOLLOW`, attest its projected
   inode, unlink the local cached binding, then unconditionally `ftruncate` the
   held descriptor to authority size and invalidate bounded shared mappings
   with `MS_INVALIDATE`. The callback returns a fresh full authority attribute
   snapshot, not metadata synthesized from the repair plan.

There is no hidden rename, rollback transaction, reserved-name lookup for a user
file, or torn-namespace registry. Those mechanisms were removed after live
testing showed that direct exact-source removal is simpler and avoids a second
privileged namespace state. Every rename with either side in the reserved
prefix is now unconditionally refused `EPERM`.

### Provenance

`PfsMacOS26RepairAuthenticator` mints a per-mount HMAC operand. Version 2 binds:

- mount incarnation and authority epoch;
- visibility sequence and repair step;
- repair kind;
- stable parent and item identities;
- exact source name;
- authenticated file/directory/symlink kind; and
- a random nonce.

`PfsMacOS26RepairArmRegistry` is one actor implementing both arming and callback
consumption. It revalidates the operand, admits the exact next callback once,
and requires completion before release. Negative scratch create/remove uses the
reserved operand. Positive and data repair consumes an exact
`removeSource(parent,name,item)` callback. Attribute repair consumes one
mode-only `setAttributes` for the authenticated stable item and retains the
expected projected VFS inode for the adapter's full-authority reply check. Any
forged, repeated, wrong-parent, wrong-name, wrong-item, wrong-inode, wrong-kind,
or out-of-order callback fails closed.

The scratch object comes from a process-local identifier band that daemon items
cannot occupy. It refuses read, write, setattr, hard-link, symlink, and other
user mutation surfaces and is deterministically retired at release,
cancellation, reclaim, or shutdown.

## The explicit macOS 26 deviations

The compatibility target is not advertised as bit-for-bit native equivalence.
Four callback-provenance limits remain because FSKit supplies no caller PID,
syscall identity, or repair token on ordinary open, remove, truncate, or
`setAttributes` callbacks:

1. While an exact source-removal plan is armed, a concurrent user unlink of the
   same parent/name/stable object is indistinguishable from the actuator's
   unlink. It can be consumed locally, after which XFS still owns the binding
   and a later lookup republishes it.
2. After a data source has been removed locally and before event release, a
   process that already holds the same vnode and truncates it to the exact
   authority size is indistinguishable from the actuator truncate. That
   metadata-only action can be coalesced; other sizes, items, or attribute sets
   are never swallowed.
3. Before `removeSource` is consumed, an open of the exact armed source vnode is
   indistinguishable from the actuator's source acquisition and is kept local.
   Once removal is consumed, source-open ownership ends: any later open takes
   ordinary publication admission and can receive definite-preapply
   `ECANCELED`. Close, reclaim, and required attribute teardown remain local
   until the syscall lease ends so the actuator cannot deadlock its own tail.
4. While an attribute-refresh plan is armed, any concurrent mode-only setattr
   on the exact same vnode is indistinguishable from the actuator's existing-mode
   `fchmod`. It can be consumed locally and answered with authority attributes
   without applying the user's requested mode to XFS. Other items and other
   user-requested attribute shapes are never swallowed. The gate remains armed
   for the whole syscall so a racing callback cannot strand the actuator.

These windows are event-scoped, HMAC-armed, exact-coordinate checks, never
wall-clock authorizations. They do not create divergent bytes or metadata in
XFS, but an overlapping local process can observe success for an operation the
authority did not execute. This provenance limit is why macOS 26 is a declared
compatibility policy rather than exact native equivalence. No percentage is
assigned: the likelihood is workload-dependent and a success ratio would not
measure the safety of these windows.

The xattr boundary is not a coherence exception. Production resolve advertises
the read/list/remove family while declaring set unsupported. After validating
the exact item and name, FSKit refuses set/create/replace/upsert locally, before
the operation can enter publication ordering. It exposes Darwin `EOPNOTSUPP`
(102), rather than its internal `ENOTSUP` (45), because XNU treats 45 as
permission to create an AppleDouble `._*` sidecar. Returning 102 preserves the
explicit-refusal contract and keeps XFS as the only durable truth. The
process-local repair scratch object remains outside this negotiated surface.

The mount root is pinned in the exact live-object index before visibility event
subscription starts. It has no parent pathname, so root attribute repair uses
the authenticated same-vnode-mode object action directly. `activate` and
`mount` record the same object idempotently as a second guard. A peer root
setattr or xattr removal therefore cannot be acknowledged as an empty plan or
race startup before the root is representable.

A closed vnode with no currently published binding is not automatically
unrepairable. Only data invalidation may move its exact coordinate into a
distinct repair-locator set, because that authority mutation preserves the
name-to-identity binding. Attribute and rapid successor data repair may use the
locator as a path fallback, and every hop still binds the recorded identity.
Positive eviction never retains one: after a namespace-target event the old
coordinate is no longer an attested, reusable authority-stable locator, even if
it happens to exist again. COMPLETE discards any earlier data locator at that
coordinate before planning the event's data or attribute repairs; PREPARE intent
alone does not. The ENOENT-success path for positive eviction also forgets the
coordinate before the publication barrier resumes. Ordinary namespace polarity
always treats a locator as absent. If an object has neither a published
coordinate nor an authenticated data locator, macOS 26 cannot represent its
repair and the mount fails closed rather than leaving attributes stale. A later COMPLETE
namespace target may supply an authority-attested post-binding identity; PREPARE
never does, and that fresh coordinate can be inode-attested and used instead of the discarded old
locator. The macOS 27 SDK's item-scoped data cache API does not replace this
attribute gap; a future native policy still needs a documented kernel operation
for it.

## Saturation contract

Synthetic peer repair competes with macOS 26 callback execution. During that
repair, any ordered macOS mutation may return `ECANCELED` definite-preapply for
that syscall. This is not limited to rename or another namespace family. The
failed syscall did not change XFS, but the verdict does not roll back earlier
syscalls that already returned success.

That distinction is load-bearing for multi-syscall workloads. For example, a
create/write/fsync/close/rename/read sequence may stop at rename. The successful
create and writes remain as a temporary file in XFS while the canceled rename
leaves its destination absent. Cancellation during a later write likewise
preserves the byte prefix acknowledged by earlier writes. Such a result is a
successful syscall prefix followed by one definite-preapply refusal, not an
all-or-nothing failed transaction and not a ghost success.

A macOS 26 saturation run therefore passes only when it proves all of these:

- **Safety:** every tolerated conflict is classified `ECANCELED`; the canceled
  syscall has no XFS effect, and every earlier syscall reported successful has
  exactly its expected XFS effect.
- **Convergence:** after the barriers drain, macOS and Linux converge to the
  authoritative XFS tree, including types, modes, names, link relationships,
  and file bytes, sizes, and hashes. Directory `st_size` is deliberately not a
  cross-platform equality field.
- **Liveness:** both mounts finish the bounded run, remain attached, and serve a
  later create/read/remove probe.
- **No ghost success:** no mutating syscall reported success without the
  corresponding XFS effect, and no canceled mutation appears in XFS as though
  it succeeded.

The macOS completion fraction may be recorded as workload telemetry, but it is
not a pass threshold. Conflict frequency depends on timing, and requiring a
fixed ratio would reject a safe convergent run while rewarding an unsafe run
that happened to report enough successes. Exact simultaneous completion without
application-visible conflict refusal remains the stronger Linux/macOS 27
target; it is not claimed by the macOS 26 compatibility policy.

## Failure, fencing, and revocation

A strict participant moves through:

```text
REGISTERING -> ACTIVE -> QUIESCED -> ACTIVE
                    \-> FENCED
                    \-> DETACHING -> ABSENT
```

A broken event socket, daemon death, missed repair budget, cursor violation,
expired session, or partition fences only that mount. Fencing ends its session
and removes it from later barriers, but durable membership remains until the
official supervisor reports exact kernel mount absence. A new mount is a new
incarnation; a fenced incarnation never becomes active again.

The authority retains the current obligation for one additional repair-budget
grace. The per-mount supervisor probes at no more than one third of that budget.
If nothing can repair the cache, it identity-checks and force-unmounts the exact
FSKit mount. Each force-unmount attempt is bounded to one third of the budget.

This macOS 26 revocation mechanism is live-proven. With a descriptor held open
and bytes already cached, `portablefsd` was killed with SIGKILL. Cached reads
continued for 8.6 seconds; the watchdog force-unmounted at about 10 seconds; from
that instant every `pread` on the held descriptor failed `EIO`. The session was
fenced and local finalization completed. Thus `MNT_FORCE` makes covered FSKit
vnodes unservable inside the fencing grace on the tested kernel.

A kernel that itself refuses forced unmount beyond the grace remains a residual
platform failure, like a hung kernel on any filesystem. Bytes already copied
into a process's own memory are out of scope.

Terminal mounts remain removable even if the daemon cannot attach: forced
unmount resolves the exact mount-table identity, including paths below symlinked
ancestors. A stale Apple `fskitd` record after an abnormally killed development
mount is host state, not an authority fallback; restart `fskitd` or reboot before
creating the next live test incarnation.

## Durable membership and authority restart

Membership is stored on the authoritative XFS control area. Authority restart
never forgets a prior strict cached mount. An ordinary clean detach deactivates
only the exact session whose authenticated `portablefsd` supervisor first
unmounted the exact attach reference and observed it absent in `getfsstat`.
Otherwise startup refuses service until every recorded prior kernel mount is
fenced or absent. `--prior-strict-mounts-fenced` is an explicit fencing
assertion, not a data reset.

Only the supervisor's session-authenticated clean detach after exact
`getfsstat` absence deactivates membership. Disconnect, an unmount callback,
daemon state cleanup, or operator intent is insufficient.

## Verification state

Automated coverage includes:

- full Swift FSKit suite, including callback-lane cancellation, exact
  policy-specific `EBUSY`/`ECANCELED`, post-COMPLETE ACK parking, late replies,
  transparent retry identity, direct file/directory/symlink eviction,
  authenticated same-vnode attribute refresh, data/EOF repair, repair-locator
  fallback, reserved namespace defense, and revocation wiring;
- Go unit and race suites for frozen callback-serialized interruption,
  identity-aware source pipelining, same/zero/peer interruption, replay
  retention, recovery, and unchanged Linux/native profiles;
- cross-OS builds, vet, generated-wire checks, and the repository merge gate;
- true-XFS authority and true-kernel-FUSE Linux integration; and
- live macOS 26 FSKit experiments against that authority.

The decisive live callback experiment showed Apple does dispatch nested volume
callbacks during repair. PortableFS's own scheduling caused the original stall.
Callback-serialized authority ordering plus publication admission then survived
the macOS side of same-parent storms without EIO or mount death. A later,
deeper macOS-rename/Linux-mkdir run exposed the separate Linux `i_rwsem` cycle
now addressed by the exact parent interruption protocol above. Replacing
`EBUSY` with `EINTR` reproduced FSKit transparent retry and ghost-success
semantics; later testing showed `EBUSY` and `EAGAIN` are also restartable, which
is why policy v2 uses `ECANCELED`. Running the new client against the old
authority reproduced the repair-budget fence. Unit, race, and deterministic
1,000-interleaving tests pin the Linux mechanism.

Authenticated attribute refresh is live-proven on a real macOS 26.5 FSKit mount
and Linux FUSE peer backed by the XFS authority. One `0755 -> 0700 -> 0755` mode
cycle converged. A run of 200 recursive `.git` traversals during rapid Linux
`chmod 0700`/`chmod 0755` cycles observed zero mode mismatches and left the mount
healthy; the final packaged strict-mode-shape build passed 50 additional cycles
with zero mismatches. A separate 100-cycle rapid data run observed zero size or
content-hash mismatches.

The final breadth run then passed bidirectional writes and renames, cross-parent
churn, hard links, symlinks, byte-invalid and Unicode names, sparse/large-offset
I/O, the exact xattr policy, Git, SQLite, and recursive macOS = Linux = raw-XFS
manifests with zero retry events. The retry-free 4-by-50-per-side saturation run
classified all 200 macOS conflicts as definite-preapply `ECANCELED`, verified
every successful prefix after bounded dirty-writeback convergence, observed 200
of 200 Linux successes, and passed post-storm cross-mount liveness. The macOS
success count was zero in that maximally conflicting run; as specified above,
that is telemetry rather than a correctness failure.

Finally, killing `portablefsd` caused exact kernel-mount absence in 6.410 seconds
and a held descriptor began returning `EIO`; evidence-bearing cleanup, remount,
bidirectional recovery smoke, and clean detach of both FSKit and FUSE mounts all
succeeded.

The macOS 26 retry-free saturation experiment is not an exact-completion test.
It records the first result of every syscall, admits only classified
`ECANCELED` conflicts on macOS, reconstructs every successful prefix, and
compares the converged macOS and Linux manifests with raw XFS. A high completion
ratio cannot substitute for those checks. Exact simultaneous completion remains
the Linux/macOS 27 target.

Every future release rerun must continue to verify both kernel filesystem types
before trusting a result (`fskit` on macOS and `fuse` on Linux), compare both
mounts with raw XFS truth, classify exact syscall prefixes under saturation, and
repeat bounded daemon-death revocation, recovery, and clean detach. No test may
substitute APFS, overlayfs, or a plain container directory for a mounted peer. A
result without an exact filesystem-type check is invalid.

## macOS 27

macOS 27 is the root target for exact native cache control, not a separate
filesystem architecture. It keeps:

- the one XFS authority;
- v3 sessions and replay;
- durable participant membership;
- PREPARE/COMPLETE and deferred source publication;
- namespace/live-object indexes; and
- fencing and exact absence proof.

It changes the participant execution profile to `INDEPENDENT` and would need to
replace all four macOS 26 VFS actuator shapes with documented native cache
operations. SDK 27 supplies an item-scoped data operation, but no name-entry or
kernel attribute-cache notification. Negative names, positive bindings,
attributes, data/EOF, and open-but-unlinked objects still require live-kernel
proof. Until every shape is representable, the native policy remains declared
but unimplemented and fails closed.
