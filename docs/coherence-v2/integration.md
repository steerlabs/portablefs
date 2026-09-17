# Protocol 7 integration record

Workstream G integrates the handler and Linux client against [wire.md](wire.md).
The starting tree is `aa046b1` on `cv2-integrate`. This record distinguishes
observed results from qualification still outstanding.

Workstream G is implemented and locally qualified. The final full gate and
independent matrix repeat both exit 0 after the SQLite fixture and Swift
contract corrections. Remaining limits and unrun production qualification are
listed explicitly below. The sections below are a chronological
record: early failure and backlog statements are superseded by later run
evidence. [results.md](results.md) contains the final measured build;
[changed-files.txt](changed-files.txt) lists the complete workstream file delta.

## Initial step 1: real mounts

The first real CREATE failed with EIO: the coordinator began at volume version
zero while the storage handler began at one. Version zero is not a valid cache
publication coordinate. The coordinator now begins at one, with a regression
check (`a101aff`). Internal control events also consumed visible change-stream
positions without emitting entries; skipping those events before advancing the
client cursor restores contiguous delivery (`efba03c`).

Further integration decisions and fixes under verification:

- A retained server OPEN handle authorizes buffered metadata flushes. An inode
  item capability may already have been reclaimed before background flush.
  Handle-only chmod, chown and timestamp application preserve that authority.
- Metadata-only SETATTR without an owned delegation stays synchronous. Acquiring
  a writable OPEN merely to restore permissions would incorrectly fail on mode
  zero. Buffered NOW timestamps are still resolved once at admission.
- Ownership checking and local publication admission share an operation turn.
  Reacquisition retries only a rejection before admission; accepted data is never
  replayed by this retry loop. Append and range mutations use the same rule.
- CONTROL may overtake a DATA grant reply. The control worker waits for that
  grant without holding installation locks. A retired-generation floor refuses
  a late reply that would resurrect authority already surrendered.
- Applied receipts belong to a delegation generation. A successor's empty cut
  reports zero, even when the write buffer retains the prior generation's
  historical application high-water mark.
- A holder's synchronous mutation pins its current grant before joining the
  peer arbitration queue. Otherwise a pending peer break can wait for the same
  local operation lock held by the synchronous mutation.

Focused Docker runs have passed real two-mount CRUD/permissions/locking,
concurrent same-file writers, repeated reader opens racing peer writes, stable
paged enumeration, and the delegation unit suite. The latest isolated
`TestTwoKernelMountsShareAuthoritativeXFS` passed in 0.04 s. Focused invocations
exit 70 at the required-inventory check because unrelated tests were not run;
those exits are not full-gate passes. Logs are under `/tmp/cv2-g-*.log`.

Full runs remain failing. The most recent completed full run stopped at the NOW
fixture, which has been updated to install a delegation explicitly. A later non-failfast
run identified additional failures; this is not full-gate qualification. A release racing a peer cut now completes that cut with the exact final ticket
(`827290c`), validated before and after event delivery. Close also retains a
writable capability through buffered application and removes tracked handles
after recall. Concurrent writers and lazy unmount pass with these changes. The blocking-read overlap test retains its
500-read requirement and now paces the writer to collect at least eight reads
per rewrite instead of depending on v6 execution latency.

## Initial step 2: directory decision

Use XFS `getdents` continuation offsets as opaque cookies, preserving each
entry's `d_off` through the store and wire reply. The directory verifier guards
page publication but no longer invalidates a continuation after mutation.
Ordinal rescans cannot preserve exactly-once delivery when earlier entries are
inserted or removed. Tests resume issued cookies beyond a page and alternate
stale and omitted verifiers while another mount mutates transient names;
unchanged anchors must appear exactly once and no ESTALE is allowed.

`TestPagedReaddirContinuesAcrossRemoteMutation` replaces
`TestPagedReaddirRefusesToPageAcrossARemoteMutation` in the required inventory.
The former v6 ESTALE expectation conflicts with design rule F3. No focused
consistency guarantee has been removed.

## Initial qualification backlog

The v7 matrix conversion, v6 engine deletion, the 20,000-file git-add regression,
baseline profiling and measurements, public documentation, and the full local
gate remain outstanding. Gateway admission, bounded ticket/control replay, and
stable-cookie enumeration are implemented; their integration regressions and
remaining qualification are recorded below.
No v7 performance result is claimed yet.

Latest focused evidence: `/tmp/cv2-g-lifetime-24.log` passes concurrent writers,
lazy unmount, NOW, and delegation tests; `/tmp/cv2-g-regression-25.log` passes
writable-capability retention and stock write splitting; `/tmp/cv2-g-cache-26.log`
passes exact release races, cached remote removal, and the metadata workload
(46 requests for warm git status over 200 files, including five LOOKUPs).
`/tmp/cv2-g-saturation-27.log` passes page-cache reuse before and after a peer
write. Cache proofs wait for the asynchronous initial delegation release before
opening a cache-capable reader; immediate post-write freshness is still checked
before waiting for release. Saturated I/O still produces an uncertain assigned
mutation and a disconnected mount. Install/enumeration churn still times out.

The saturation and enumeration timeout root cause was source self-notification.
A kernel EntryNotify for an initiating CREATE/RENAME waited on that mount's VFS
lock, while cumulative peer acknowledgments waited behind the notification.
`OnCommitFrom` filters ordinary committed changes for their source; the source's
existing exact publication gate and post-state perform local repair. Delegation
events remain broadcast. The handler retires internal positions only when all
wire changes have been acknowledged. A 1,024-commit test exceeds the 256-entry
log without fencing the source. `/tmp/cv2-g-source-31.log` passes saturation
(0.11 s), install/enumeration (2.23 s), and enumeration recall (2.76 s). The
remaining metadata-count assertion in that run expected immediate write-through;
its v7 replacement measures application after an explicit durable cut while
retaining the zero-follow-up-GETATTR requirement.

A later full run exposed a private-mapping SIGBUS after reopen: LOOKUP published
storage size zero while the holder had accepted 4 KiB in its buffer. Entry
publication now overlays owned buffered metadata and uses zero attribute cache
lifetime. `TestLookupPublishesHolderBufferedSize` passes; the real two-mount
CRUD/mapping test passed three consecutive runs in `/tmp/cv2-g-overlay-34.log`.
The diagnostic crash connections were aborted by their exact fusectl connection
IDs; unrelated containers were left running.

## Gateway profile

The files gateway now declares the additive `CACHELESS_READER` profile and
`cacheless-peer-reader-v1`. Attach requires exactly read access. The handler
permits only authenticated lifecycle and read operations and rejects write
intent and cache-capable opens. Data and attribute reads use BreakForRead;
activation does not recall Linux writers or join the Mac writer exclusion.
The gateway no longer runs a FSKit repair acknowledgment worker.

The real gateway listing/read and graceful/abrupt-departure tests passed three
consecutive runs in `/tmp/cv2-g-focus-46.log`, with the writer delegation held
across activation and the first listing. The same run passed the exact-access
attach and local cache-admission tests three times. It is not a full-gate pass:
metadata-cache timing and the racing-reader/writer test still failed.

## Grant reply ordering and enumeration regression

Stack capture found a circular wait in truncating OPEN: an activated delegation
was not yet reported to its holder because the handler waited for peer withdrawal.
A peer READ requested a break; its folio blocked kernel invalidation; the holder
could not acknowledge the break until OPEN returned. Successful private mutations
now return to reserved state while withdrawal finishes. A pending private cut
retries reserved-read admission across that transition. Existing visible grants
return their applied receipt before detached withdrawal, as exact-reference
flushes already do. The focused racing-open test passed three consecutive runs
in about 0.2 s each in `/tmp/cv2-g-reserve-52.log`, previously failing at 5 s.
The coordinator regression also covers reads already waiting before promotion.

The F3 replacement now interleaves 600 long immutable names with mutable slots
and runs an independent peer creator/deleter throughout the walk. Every unchanged
name appears exactly once; returned unique transient names cannot duplicate;
ESTALE and nontermination fail. Three runs passed in `/tmp/cv2-g-reserve-50.log`.
The install/enumeration stress no longer tolerates ESTALE.

Cache-reuse fixtures now drain the Authority's exact stream prefix after
asynchronous close before warming caches. A local empty delegation set alone
could precede delivery of a queued grant/release pair. Metadata measurements take
an explicit durable cut so buffered writes are counted; fewer pre-operation
LOOKUPs are accepted, while follow-up GETATTR and operation counts retain their
bounds. The same-name CREATE portion still exposes a ten-second stall and is
under investigation; the full suite is not green yet.

## Namespace withdrawal and rename publication

The same-name CREATE stall was a peer EntryNotify waiting for the parent VFS
lock held by the initiating syscall. Checking whether a source gate already
exists is insufficient: the kernel takes that lock before entering the callback.
All Authority-backed shared names already use zero kernel entry validity.
Namespace withdrawal therefore closes the exact coordinate, revokes or drains
old replies, and purges daemon bindings and stamps before ACK, without EntryNotify.
Forward lookup must re-enter FUSE. Kernel dentry objects used by reverse d_path
remain outside the contract, and machine-local graft names are separate. DATA
and ATTR retain their returned inode-notification proof. The design, wire and
client descriptions now state this boundary explicitly.

The regression holds both positive and negative LOOKUP replies across a peer
change, then proves late physical completion cannot refill withdrawn payloads.
Real cross-mount tests require the first observation of each changed component
to reach the Authority and unchanged negative probes to reuse daemon payloads.

RENAME exposed two extra requests: F4 re-resolved an already known source when
only the destination was unknown, and its authoritative post-bindings were not
published into the daemon cache. Dependency flush now resolves each unknown
coordinate independently. Rename admits fresh coordinate stamps from validated
post-state, owned by its existing reply receipt; it never moves the old name's
stamp. The metadata regression retains its original one-LOOKUP/zero-GETATTR
rename bound. It passed in `/tmp/cv2-g-rename-67.log`; the same-name CREATE took
less than two seconds and retained both subscription incarnations. This focused
run passed all selected tests but exited 70 because the full inventory was not
selected.

## Bounded session retention

Application tickets retain monotonic applied/durable counters and only the
undurable suffix of volume versions. Every volume durability cut retires the
covered prefix for all sessions, including idle writers. Active delegation cuts
validate their exact floor and tickets issued during the cut, independent of
retired application history. The 100,000-ticket regression checks backing capacity,
idle-session retirement, and sequence continuity after complete pruning.

Delivery is not completion: CONTROL polls can overtake flush ACK retries.
The additive `completed_event_through` field explicitly surrenders ACK replay
through a contiguous handler-completion prefix. It does not acknowledge a flush.
The Authority deletes surrendered adapter records; coordinator cuts still expire
on their own deadlines. A failed-handler test verifies that surrender neither
completes the cut nor suppresses the loss increment at its five-second deadline.

Release requests carry contiguous `release_sequence` and
`completed_release_through` coordinates. The client owns the ACK lane across
reconnect and exact retry and validates the result before admitting a successor.
The Authority retains one exact request fingerprint/result, including definite
errors. Malformed or uncertain final responses end the session; invalid local
request shapes consume no sequence. Linux attach requires the additive
`bounded-control-replay-v1` feature. Existing protobuf tags remain unchanged.

The 10,000-cycle grant/break/release test bounds retained grants, obligations and
release replay while retrying exact ACKs after later delivery. These tests and
the failed-handler deadline test pass in `/tmp/cv2-g-retention-65.log`; that run
still failed the newly added nested-name request counter, which counted a parent
attribute miss as a child lookup. The assertion now counts the exact component;
all cross-mount name tests pass in run 67. Native reconnect, malformed-result,
local-validation and golden-wire tests pass in `/tmp/cv2-g-client-64.log`.

The full suite in `/tmp/cv2-g-full-68.log` exposed two further races. Directory
invalidation could clear `pending` after READDIR selected an entry but before
its accepted reply entry advanced the continuation cookie. Consumption now uses
the delivered entry's own cookie even if its buffered page was withdrawn. A
unit regression forces that exact interval. A refetched page also needs its own
RPC-start generation and served version: borrowing the whole callback's oldest
stamp discarded each fresh page repeatedly. Five concurrent churn runs pass in
`/tmp/cv2-g-git-72.log` (1.63–5.62 s), after three correctness passes in run 70
that took 23–40 s before the stamp fix. These are regression timings, not the
requested baseline measurements.

Git intermittently received EIO from a successful read-only OPEN. Diagnostics
in run 72 identified local registration: it observed ownership, waited behind
last-writer release, then treated the absent delegation as an error. Registration
now joins the generation only if it still exists; otherwise the valid Authority
handle remains ordinary and closes through CLOSE. A regression checks both
outcomes. No mount abort or authority error was involved. Full-gate qualification
remains pending.

Run 77 passes every fusev3, xfsstore, Authority RPC, restoremode, archiver and
hydrator test. It reaches the separately gated tiered lifecycle and fails
ServeWhileCold: a buffered writer's stat still reports archived mtime. This is
an unimplemented implicit-attribute overlay, not an allowed v7 test relaxation.
Run 78 passes Git, read-open/release, rename physical-publication (including a
final FORGET), and refetched-page stamp regressions twenty times each. Its exit
70 is only the focused inventory check. Darwin Foundation and static Linux
builds pass; native authorityrpc/volumeserver race suites pass in run 69.

## Buffered attributes and active restore admission

Run 82 passes the complete fusev3/Authority group and the formerly failing
ServeWhileCold lifecycle stage. Buffered write, truncate and size changes now
carry admission-time implicit mtime/ctime in the holder overlay, in program
order with explicit SETATTR values. They add no wire operation. Flush requires
valid post attributes and installs the exact Authority base before consuming a
durability watermark. Base selection and overlay sampling share the delegation
metadata lock, so retirement cannot pair an old base with an empty overlay.

Positioned writes also retain kernel write flags and lock owner. Coalescing
requires identical write options. Privilege clearing is a relative operation
at the write's position: it clears setuid and executable setgid, while a later
chmod still wins. Regressions cover the local mode, metadata ordering, transport
flags, coalescing boundaries, malformed post attributes, and the retired-overlay
handoff. The writeback race suite passes in run 81.

Run 82 then exposes active-restore cache admission: the Linux profile granted
kernel caching to a previously hydrated read handle, bypassing volume-wide
RESTORE_BLOCKED after the hydrator disappeared. Active restore now refuses
cache-capable OPEN/CREATE admission, using the existing reply permission bit.
These handles remain direct I/O through convergence; new handles may cache
once restore is inactive. The existing lifecycle assertion is retained without
relaxation and a handler regression checks the admission rule.

Run 83 and focused run 85 exposed a stale source link count; run 86 happened to
pass it and completed every tiered lifecycle stage. The source's change entries
are intentionally filtered, but its publication gate only drained pending
replies: it did not purge settled daemon attribute payloads. Source completion
now purges its exact ATTR/DATA payloads while leaving kernel-data obligations
registered. Surviving hard links and open unlinked inodes also receive REMOVED
objects' exact post attributes. This is not a change to unlink semantics.

Delegation bases now compare object versions. A delayed LOOKUP cannot replace a
newer applied base, and a newer namespace reply can update link count without
being replaced by older delegation metadata. Peer ATTR/DATA changes establish
an invalidation floor; older replies cannot resurrect the base. Base selection
and overlay sampling remain atomic through metadata/overlay locks.

Run 87 passes all selected frontend, source-cache, base-version and handler
regressions twenty times, including cross-mount link count. The tiered lifecycle
passes 19 of 20 repetitions; one later cold-tree comparison still sees archived
mtime on the truncated file. That failure is under investigation and is not
counted as a passing gate.

The lifecycle now opens a root handle before its mutation stage and requires a
successful directory barrier before deliberately stopping the hydrator. This
replaces the v6 assumption that successful close already completed the preceding
run. Run 88 makes the remaining loss explicit: four barriers fail before the
hydrator is stopped. Investigation identifies writable-handle selection, not
restore timestamp ordering. Buffered size SETATTR selected an arbitrary retained
handle; an overlapping read could make that descriptor read-only, and XFS
correctly refused ftruncate. Size-bearing metadata now selects the retained
writer set, like positioned data writes. The regression exercises both buffered
TRUNCATE and SETATTR-size while many read handles coexist.

Run 88 also found a test-lifetime mistake: its new barrier descriptor remained
open through the later unmount. It now closes immediately after the barrier.
Run 89 passes the full `bash scripts/xfs-fuse-integration.sh` gate, including the
complete tiered lifecycle, required inventory, and root boundary tests. The
subsequent writable-handle selection regression is being repeated separately.

Run 90 passes both writable-handle metadata variants and the complete tiered
lifecycle twenty times each. The lifecycle barrier passes before every injected
hydrator failure, and every cold-tree/unmount/convergence assertion passes.
Its wrapper exits 70 only because the focused command omits other required
inventory. Together with full run 89 (66 privileged tests and one root boundary
test), this closes the current step-1 real-mount qualification. The final full
verification and matrix still remain mandatory after the later deletion and
performance work.

## Step 3: expanded black-box matrix

Run 91 passes the original 23-case matrix under v7: 22 PASS and the existing
single-principal chown SKIP. Concurrent same-file append is enabled and is also
required to fail in the stale-observation negative control. Added cases cover a
retained peer cached handle, Git index.lock exclusion and rename publication,
F4 rename with the writer still open and no prior fsync, authenticated gateway
reads, recall-budget loss with an old-root failed barrier, and Authority epoch
replacement without remounting either kernel filesystem. The destructive
peer-loss case remains last. External gateway and fault-injection cases are
excluded from controls whose intentionally broken actors cannot model them.

Run 92 exposed a fixture validity-window error before mounting: the one-second
NotBefore skew made a nominal one-hour capability exceed a one-hour maximum.
The helper now measures the requested lifetime from NotBefore. Run 93 passes
all original non-destructive cases and the new cached-handle, Git lock, F4, and
recall-budget cases. The latter observes a 5.505-second acquisition, EIO on the
old writer/root barrier, and healthy fresh handles.

Run 93 also exposes two production gaps. The gateway always presented the empty
routing revision and could not read a volume with a local-directory declaration.
It now uses the common, validated one-retry adoption flow, with kernel enforcement
required only for the Linux frontend. Authority restart also caused mounts to
terminate on the first transient reconnect failure before detecting the new
epoch; this remains under repair. Renewal was independently bound to the original
client. The mount now publishes an exact authorization-session snapshot and its
retirement channel; renewal cancels and joins the retired worker, constructs a
fresh file source and renewer, and starts sequence one against the replacement's
deadline. A retired worker never forwards its capability to a new client.
These changes are not yet counted as a passing matrix gate.

Runs 94 and 95 pass the exact-session authorization snapshot regression and all
standalone renewal tests. Run 96 passes the routed gateway case. Its epoch
replacement helper cannot append to a root-owned authority log; the harness
now makes that log writable by the service identity. Transport reconnect now
retries network errors within the caller's deadline while retaining the original
request/replay identity. A new authenticated epoch is never replayed into. A
sent mutation whose reconnect deadline expires retains the uncertain-outcome
verdict. Linux idle CONTROL loss and local keepalive timeout no longer revoke
the mount: its subscription horizon owns cache withdrawal. FSKit's terminal
CONTROL behavior and authenticated session/auth failures remain terminal.

The two terminal EOF publication tests are replaced by
`TestTerminalSessionEndCannotOvertakeBufferedDataResponse` and
`TestTerminalSessionEndCannotOvertakeDeliveredResponseCallback`; they inject an
actual terminal session verdict and preserve the exact publication/drain
assertions. `TestIdleLinuxControlLossResumesWithoutEndingSession` proves the v7
replacement for idle-EOF revocation, including independent DATA preservation.
`TestReconnectSurvivesListenerGapBeforeEpochVerdict` covers both same-epoch
resume and a new epoch across a real unbound-listener interval. The caller
deadline remains bounded. `TestKeepAliveTransportTimeoutDoesNotRevokeMount`
complements the retained authenticated-keepalive-refusal abort test.

Run 97 passes old-handle EIO, fresh reads, new root barriers, and renewal session
replacement, then exposes a fresh-write startup refusal. The single durable
membership set had conflated prior Linux mounts with Mac compatibility caches.
`PFS-VISIBILITY-2` now records `linux-v7`, `compatibility`, or `cacheless` per
session. Every v1 record remains conservatively `compatibility`; migration never
infers Linux. Activation, clean-detach rollback, and the cell-host archive reader
preserve and validate that classification. Operator assertions still audit and
clear the exact recorded IDs. Aggregate prior membership remains unproven for
route changes and archive proof, including old Linux IDs: epoch recovery is not
proof that a kernel mount is absent.

A prior Linux cache set delays mutations and delegation reservation for ten
seconds from the new coordinator's creation, covering the longest old
subscription horizon. This wait holds no identity/storage turn and is
cancelable; cold Subscribe, reads, and barriers remain available. Prior Mac or
untyped records still require the existing external fencing proof. The epoch
matrix now additionally creates and publishes new data to its peer after
recovery, so a passing read-only/barrier path cannot hide mutation refusal.

Run 100 passes all 29 matrix outcomes (28 PASS, the existing chown SKIP), but
its teardown needs intervention: runuser's parent monitor stops itself when the
recall case SIGSTOPs the child and does not resume with the child. The harness
now uses setpriv with the same service UID/GID, supplementary groups, and clean
environment. Run 101 repeats the complete controls and real matrix to qualify
normal process exit. Run 102 passes native race tests for volumeserver and
authorityrpc. Final full verification remains outstanding.

Run 101 exits 0 without intervention: both negative controls behave as declared,
and the real matrix reports 28 PASS, zero failures, and the unchanged chown SKIP.
The authority process and epoch change while kernel mount IDs and serving PIDs
stay fixed. New data is written and read across the recovered mounts before the
final destructive peer-loss case. Run 103 passes Linux standalone renewal,
cell-host membership parsing, exact authorization snapshots, and keepalive
regressions. This closes step 3; the later deletion/performance changes still
require final full qualification.


## Step 4: deleting the retired engine

Deleted `volumeserver/leases.go` and its test file, the client lease grant and
renewal validators and tests, and the unused visibility route coordinator and
tests. Routes now use MountLifecycle's topology writer and clean-absence check
directly, preserving CAS, durable publication, and lock-wait interruption. The
handler and production assembly no longer construct or retain a LeaseCoordinator.
The three frozen cache-lease CLI flags remain accepted and validated with their
old bounds, but are explicitly deprecated and do not configure protocol 7.

Removed executable transport classification for the four old control methods.
The frozen protobuf tags and negative profile/refusal tests remain, together
with one shared rejection check for obsolete response state; they cannot grant,
recall, renew, or discharge anything. Linux request dispatch uses the v7 profile
allowlist. The nested-frame allocation-limit test now uses ChangeBatch entries.
Baseline request classification now counts v7 CONTROL and barrier operations.

No Linux lease ticker or hard-deadline watchdog remains. Subscription horizons,
recall budgets, and epoch transitions invalidate/fail the affected state while
the mount stays up. The remaining `revoke` calls protect malformed protocol
results, impossible callback/publication ownership, or uncertain applied
namespace outcomes; deleting them would weaken the exact-result guarantee.
Mac compatibility exclusion and synchronous repair remain separate and active.

The two previously missing replacement regressions now pass:
`TestCoherenceDelegationChurnRetainsOnlyLiveRecordsAndScalarGeneration` exercises
1,024 identities and reuse without retained per-identity grant history;
`TestCoherenceDataConsumedWakesWhenCanceledRecallRetiresGeneration` proves the
queued reader wakes after exact holder drain without reviving ownership.
Native coordinator/transport tests pass after deletion (runs 104 and 106).
Static Linux product and frontend-test compilation pass. Full real-mount run
107 is in progress.

The following mapping preserves every test from the deleted lease suite:

| # | Retired v6 test | Protocol 7 replacement or disposition |
|---:|---|---|
| 1 | `TestLeaseStartupGraceBlocksMutationsUntilExactPriorTTL` | `TestNewAuthorityRejectsOldEpoch` and `TestEpochRecoveryStalesOldHandlesAndAdmitsNewOpens`. Protocol 7 makes old capabilities permanently stale instead of trusting a grace interval. |
| 2 | `TestLeaseGrantPolicyAndConflicts` | `TestCoherenceDelegationCacheModes` and `TestCoherenceReservedIdentityClosesCachingAndColdSnapshot`. Protocol 7 has one writer delegation; peer cached handles force writethrough or direct I/O. |
| 3 | `TestLeaseHolderCoordinateChurnRetainsOnlyLiveRecordsAndScalarEpoch` | `TestCoherenceDelegationChurnRetainsOnlyLiveRecordsAndScalarGeneration` (added and passing). |
| 4 | `TestLeaseGrantCapacityRefusesCachingWithoutEviction` | `TestSessionResourceAdmissionAndTerminalState`, `TestCapabilityReservationIsPreApplyAndSymmetric`, and `TestCoherenceOpenGrantFailureRetiresTrackedHandle`. Persistent delegations are bounded by admitted open/item resources; refusal precedes publication and does not evict existing state. |
| 5 | `TestLeaseGrantBatchIsAllOrNoneAtCapacity` | `TestCapabilityReservationIsPreApplyAndSymmetric` and `TestCoherenceOpenStorageFailureAbortsUnpublishedReservation`. Protocol 7 has no multi-coordinate grant batch; the stronger filesystem resource reservation is atomic and rolls back before reply publication. |
| 6 | `TestLeaseRecallSelfExemptionAndExactDischarge` | `TestCoherenceCommitNotifiesOnlyPeersOfSource`, `TestWaitWithdrawnExcludesSourceAndHonorsPartitionHorizon`, and `TestCoherencePrivateMutationExcludesSourceUntilPromotion`. The source never owes its own peer withdrawal; promotion and release are explicit. |
| 7 | `TestLeaseRecallFromExternalSourceRecallsPeerWithoutSourceObligation` | `TestCoherenceBreakFlushCutAndRecall`, `TestCoherenceReadWaitsForDelegationBreakBeforeStorage`, and `TestFilesGatewayAttachesToRealXFSWithoutObstructingAMountingPeer`. An authenticated gateway read breaks the holder and never becomes a writer/source participant. |
| 8 | `TestLeaseRecallFromExternalSourceFenceBeforeAndDuringRecall` | `TestCoherencePermanentSessionEndDuringRecall` and `TestFilesGatewayCloseDoesNotStallAMutatingMount`. |
| 9 | `TestLeaseCanceledCompleteCannotReopenAdmission` | `TestCoherenceCanceledReservationAndCutCleanUp`. After a dispatched control cut, cancellation waits for holder drain and cannot revive ownership. |
| 10 | `TestLeaseDischargeRejectsContinuityAndStaleEpoch` | `TestCoherenceDelegationBreakRecallAcksValidateTicketIdentityAndReplay`, `TestCoherenceReleaseBatchIsAtomic`, and `TestCoherenceAckRejectsFutureAppliedCut`. |
| 11 | `TestLeaseRenewalReturnsExactCoordinateWithdrawals` | `TestSubscriptionRenewBoundary` and `TestSubscriptionColdSnapshotIncludesDelegatedSet`. Protocol 7 renews one subscription horizon; exact delegated identities come from the cold snapshot and control stream. |
| 12 | `TestLeaseRepeatedReadGrantKeepsRenewableEpoch` | `TestCoherenceCacheHandlesSurviveColdResubscribe` and `TestCoherenceDelegationCacheModes`. Open-description counts survive renewal/cold subscribe without minting a conflicting generation. |
| 13 | `TestLeaseRenewalLosingToRecallIsNonfatalWithdrawal` | `TestCoherenceRenewAndChangeStreamUseIndependentCursors` and `TestSubscriptionRenewalAndAckProgressWhileControlPollIsParked`. Renewal stays independent and nonterminal while control withdrawal is outstanding. |
| 14 | `TestLeaseRenewalRestampsAdmissionGenerationAfterDisjointRecall` | `TestSubscriptionColdPaginationWatermarkAndStaleReply`. Reply-local incarnation/generation and exact coordinate version reject a stale reply while a fresh disjoint reply remains cacheable. |
| 15 | `TestLeaseDisjointSourceMutationsDischargeOutOfOrder` | `TestCoherenceDisjointRequestBypassesRecall` and `TestDelegationWritebackPipelinesDisjointFiles`. Protocol 7 intentionally has independent identity lanes and no source-discharge token. |
| 16 | `TestLeaseRouteChangeRequiresCleanMountAbsence` | `TestMountLifecyclePriorUnprovenOnlyBlocksRouteChanges` and `TestMountLifecycleActivationRollbackAndExactCleanDetach`. |
| 17 | `TestLeaseRecallExpiryFencesAndImplicitlyDischarges` | `TestCoherenceRecallExpiryAndBudget` and `TestDelegationRecallBudgetMissDropsAndAdvancesLoss`. Protocol 7 retires only the generation, reports loss/EIO, and keeps the mount alive. |
| 18 | `TestLeaseIndependentCoordinatesRecallConcurrently` | `TestCoherenceDisjointRequestBypassesRecall` and `TestDelegationWritebackPipelinesDisjointFiles`. |
| 19 | `TestLeaseSameHolderSerializesAcrossRevokeCompleteGap` | `TestCoherenceBreakRacingRecallIsFIFO` and `TestDelegationControlEventsPreservePerIdentityDeliveryOrder`. The old cross-coordinate holder lane is deliberately gone; protocol 7 serializes the same identity and lets disjoint identities proceed. |
| 20 | `TestLeaseReadAdmissionMakesStaleReplyGrantPartOfRecall` | `TestCoherenceOpenGrantsOnlyAfterHandleReady`, `TestCoherenceCreateKeepsReplyGrantReservedThroughWithdrawal`, and `TestSubscriptionColdPaginationWatermarkAndStaleReply`. |
| 21 | `TestLeaseReadAdmissionCannotGrantAfterRelease` | `TestCoherenceCanceledReservationAndCutCleanUp` and `TestCoherenceOpenStorageFailureAbortsUnpublishedReservation`. |
| 22 | `TestLeasePrepareCancellationCannotSkipDispatchedRevoke` | `TestCoherenceCanceledReservationAndCutCleanUp`; this is its exact protocol 7 assertion. |
| 23 | `TestLeaseNewReadWaitsUntilOldCacheIsDischarged` | `TestCoherenceReadWaitsForDelegationBreakBeforeStorage` and `TestCoherenceBreakFlushCutAndRecall`. Stronger protocol 7 rule: storage read is not entered until the holder flush cut is acknowledged. |
| 24 | `TestLeaseFencePreventsGrantAndRenewal` | `TestCoherencePermanentSessionEndDuringRecall`, `TestSubscriptionOverflowFencesEveryAdmissionPath`, and `TestCoherenceReadPathsRefuseExpiredSubscriptionBeforeStorage`. |
| 25 | `TestLeaseFencedSourceKeepsBarrierUntilOriginalGrantExpiry` | `TestCoherencePermanentSessionEndDuringRecall` and `TestWaitWithdrawnExcludesSourceAndHonorsPartitionHorizon`. Terminal runtime drops write authority but never shortens the old cache horizon. |
| 26 | `TestLeaseNoopPreservesSourceGrantForLaterPeerRecall` | `TestCoherenceSynchronousMutationPinsExistingHolderGrant` and `TestCoherenceConcurrentSynchronousFailureCannotRetireRetainedGrant`. |
| 27 | `TestLeaseEventCursorIsExactTokenNotMonotonicSequence` | `TestCoherenceChangesSkipInternalEventsWithoutCursorHoles`, `TestCoherenceRenewAndChangeStreamUseIndependentCursors`, and `TestDelegationControlEventsPreservePerIdentityDeliveryOrder`. Protocol 7 deliberately replaces opaque/nonmonotonic v6 tokens with a contiguous control sequence and separate change position. |
| 28 | `TestLeaseConstructorRejectsTTLBeyondProtocolHorizon` | `TestCoherenceGrantWaitsOnlyToPartitionHorizon` and `TestSubscriptionRenewBoundary`. Protocol 7 TTL and recall budget are frozen constants, not configuration. |
| 29 | `TestLeaseDataReadWaitsForApplyAndThenMissesUntilDischarge` | `TestCoherenceReadWaitsForDelegationBreakBeforeStorage` and `TestCoherencePromotedPrivateGrantDrainsPendingReaders`. Protocol 7 breaks and flushes before storage instead of serving a post-apply uncacheable v6 reply. |
| 30 | `TestLeaseSourceDataReadWaitsForItsOwnApplyThenSeesAppliedState` | `TestDelegationReadAndAttributeOverlay` and `TestCoherenceSynchronousMutationPinsExistingHolderGrant`. The stronger holder rule makes accepted buffered state visible locally even before apply, while synchronous apply pins ownership. |
| 31 | `TestLeaseDataReadWakesWhenTheRecallAborts` | `TestCoherenceDataConsumedWakesWhenCanceledRecallRetiresGeneration` (added and passing). |
| 32 | `TestLeaseSourcePostStateGrantRejectsAnUnpreparedCoordinate` | `TestCoherenceSynchronousMutationRetainsSuccessfulGrant` and `TestCoherenceCreateReservesBeforeBindingPublication`. Arbitrary successor coordinates are unrepresentable in protocol 7: `RetainDelegation` is bound to the exact mutation-pin identity, while `ReserveNew` is the explicit created-identity path. |

The deleted visibility-route tests have these stronger replacements:

| Retired test | Stronger existing replacement |
|---|---|
| `TestTopologyReadGuardExcludesRouteCASForPausedRequestsAndAttaches` | `TestPausedAttachPinsItsAdmittedTopologyUntilAdmissionFinishes` and `TestPausedFilesystemRequestPinsItsAdmittedTopologyUntilCompletion`; these exercise the real handler admission paths. |
| `TestTopologyExclusiveSerializesConcurrentRouteCompareAndSwap` | `TestRoutesControllerSerializesConcurrentApplyCompareAndSwapOnXFS`; this exercises the same exclusion through the real route controller and XFS persistence. |

Run 107 exposed two stale transport-loss tests that still required automatic
unmount/ENOTCONN. Their protocol 7 replacement keeps both original inventory
names and proves bounded EIO after completed horizon withdrawal, absence of old
bytes in the failed read, live mounts and authenticated sessions, same-runtime
listener recovery, successful reads through the retained handle, and a passing
root barrier on both mounts. Runs 109 and 111 also exposed an invalid test
observation: a zero subscription stamp marks withdrawal admission closing,
not completed inode notification. The test now waits for the post-withdrawal
incarnation fence before trying to refault retained pages.

An uncertain release receipt now fences its subscription incarnation instead
of poisoning the authenticated session. The client refuses release, renewal,
and poll on that incarnation; the subscription worker drains, withdraws caches,
and cold-subscribes before any new release domain can begin. A malformed
response remains terminal. The regression loses every reply in incarnation 1,
proves no completion receipt or successor is issued there, then proves that
incarnation 2 starts at release sequence 1/completion 0. The wire contract
records this decision. Background reclaim and close batches retain their exact
replay identity through a transport gap using the mount lifetime context.

Run 112 captured the remaining read wait in transport reconnect after cold
withdrawal. A kernel refault could enter another bounded network wait instead
of receiving the subscription's scoped failure. Read now refuses locally with
EIO while the subscription stamp is zero, before either buffer overlay or RPC.
This preserves the session and becomes usable after cold Subscribe. The unit
regression checks inactive and elapsed subscriptions without any transport call.
Run 114 passes that test and both real-mount outage/recovery tests (9.04 seconds
each); its wrapper exits 70 only for deliberately unrun inventory. Native race
tests for authorityrpc and volumeserver pass in run 113. Full run 116 is pending.

Deletion validation also passes native `go -C vcs test ./...` (run 115),
`go -C vcs vet ./...` (run 117), Foundation/cgo Darwin build, and static Linux
build. The requested retired-wire identifiers have no remaining references in
`fusev3`, `mountv3`, or the Linux mount command. Frozen schema and explicit
shared-transport refusal tests remain as described above. Full run 116 is not
yet claimed green; its result and the final full gate will qualify subsequent
benchmark changes as well.

Run 116 exits 0: the complete XFS/FUSE suite passes all 66 required privileged
tests and the additional root-boundary test after engine deletion and cold-read
recovery. This closes step 4's real-mount qualification.

A final call-path audit found the F1 `ExecuteFromExternalSource` bridge still
scheduled Linux mutations through an empty Mac repair audience. Removed the
bridge and external-source terminal machinery. Linux now uses only its v7
storage turn, with the same pure preparation/committed-target validators and
runtime terminal check. `strictCache` also restricts old repair read admission
to FSKit. Ordinary Linux mutations still hold profile admission and reject a
live Mac compatibility writer before replay assignment; exact-generation recall
flushes still pass pending Mac activation. Native target validation passes, and
focused Docker run 121 passes the handler/coherence/stock-write suites, including
three new Linux/Mac exclusion and dependency-validation regressions. Run 119
was a compile typo, corrected before 121. The focused wrapper's exit 70 is only
unrun full-suite inventory.

## Step 5: fresh 20,000-file Git regression

The baseline's setup-capacity override is deleted. `git-portablefs` starts a
fresh mount at 65,536 cached names, writes 20,000 files, runs `git add`, checks
that the index contains exactly 20,000 paths, and commits. A root handle opened
before preparation must fsync successfully, and the original mount/session must
still be live before the cold-status remount. The remount uses the same shipping
capacity and retains the v6 cold/warm measurement boundary.

Run 118 uses
`PORTABLEFS_PERFORMANCE_TEST=1 PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$/^git-portablefs$' bash scripts/xfs-fuse-integration.sh`.
It passes in 65.70 seconds, logs `files=20000 cached_name_capacity=65536
committed=true barrier=PASS mount=LIVE`, and passes both status phases. The
wrapper exits 70 for the intentionally omitted inventory. This replaces the v6
ENOTCONN result with a successful fresh shipping-capacity run; no cache-size
workaround remains. The bench package unit suite also passes. The complete
measurement below will repeat this setup after the final bridge deletion.

## Step 6: measurement and profile-driven changes

Run 122 passes the full-size v7 baseline in 118.44 seconds: both install worker
counts, fresh 20,000-file Git setup, cold/warm status, and overlapping peer
write/list/read. The peer path now fails any enumeration error instead of
retrying ESTALE. A root directory handle opened before each measured phase
must pass its completion barrier; barrier and asynchronous CLOSE drain time
are separate from the historical POSIX wall-time column. The complete records
and protocol-6 comparison are in [results.md](results.md).

Optional `PORTABLEFS_PROFILE_DIR` captures CPU, allocation deltas, mutex/block
snapshots, and the exact executable. Authority and frontend are in the same
real-mount test process: inherited CPU labels identify each component; heap
analysis uses stacks. The Docker wrapper copies artifacts from the container's
regular writable layer so remote Docker contexts need not share a host path.
Runs 123–125 exposed profile-export plumbing mistakes (BSD chmod ordering,
unshared host /tmp, then ephemeral tmpfs); run 125's install profiles were
recovered before container teardown, and run 126 repeated Git profiles with
working export. These were not product failures or passing full gates.

The profiles drove four bounded changes:

- Cache immutable canonical field order by schema descriptor; reevaluate field
  presence and reject unknown fields on every message. The wire bytes and
  replay fingerprints are unchanged.
- Reuse one bounded CONTROL event batch only after its queue drains. Responses
  and replay own their data; prefix growth is bounded by the requested batch.
  Tests retain old responses across reuse, replay the current response, and
  force frame splitting before reusing storage.
- Allocate source-publication notification channels only when a waiter exists.
  Predicates, waiter registration, and signaling remain under the same mutex.
  The source gate scans request coordinates, not the global cache.
- Replace one background goroutine per dirty identity with one scheduler
  worker. The Authority already has one reserved delegated-flush execution
  slot. A 32-worker intermediate experiment reduced contention but could fill
  every ordinary client permit in the integration configuration. One worker
  preserves room for explicit close/fsync/recall flushes and avoids a timer
  stampede. Explicit flushes remain independent; queued jobs keep their cut,
  kicks survive an active batch, and cancellation preserves retained entries.

Focused run 129 passes canonical, control/replay, and source-publication tests;
its exit 70 is omitted inventory. Native race run 131 passes authorityrpc,
volumeserver, and writeback. Writeback race run 139 passes bounded dispatch,
explicit bypass, cap rescheduling, and stop cancellation after the final
single-worker change. Run 138 was a test-constant compile typo, corrected before
139. The additional hot-path benchmarks report allocations as well as time.
Final measurement and full-gate evidence follow below.

Run 140 exposed a real backlog failure after the single-worker change: the
8-worker install returned ENFILE at file 6,597. The unbounded background fan-out
had masked per-file durability waits in the close batch. Close cleanup now
applies every retiring file before waiting for each file's durable cut; no
release or server CLOSE precedes durability. A blocked-barrier regression
requires all 16 files to apply while no release can escape (run 142 passes;
141 was a test-helper type mismatch corrected before that run).

New OPEN/CREATE/TMPFILE and directory-handle admissions also wait when 256
asynchronous closes are pending, before taking identity or source gates. The
count includes work already removed from the queue into an active close batch.
Completion and epoch-discard wake admission; cancellation is bounded by the
request/mount context. QueueClose snapshots its epoch without retaining the
epoch lock over a blocking enqueue. This bounds deferred cleanup below the
unchanged 4,096-open integration limit rather than increasing the limit. The
regression blocks real queued cleanup, checks admission cancellation, resumes
cleanup, and requires the pending count to return to zero.

The close producer gate now joins racing QueueClose calls before shutdown's
final drain. A cancellation-ready enqueue can no longer land after the worker
exits. Race run 146 stopped in a test setup deadlock: the fixture added handles
after allowing a blocked close batch to take the same transition lock. It now
registers every handle before enqueueing cleanup. Race run 149 passes the
Linux delegation, pending-close, shutdown-race, publication-channel, control
replay, frame-splitting, and canonical tests. Its exit 70 is solely the focused
inventory omission. The 256-close threshold is backpressure with concurrent
admission headroom, not a negotiated reservation for arbitrary smaller custom
Authority open-table limits.

Final run 150 passes every baseline phase in 112.96 seconds, including the
fresh 20,000-file index/commit at capacity 65,536 and its passing root barrier.
Final unprofiled wall times are 21.029/15.706 seconds for 1/8-worker installs,
1.380/1.196 for cold/warm Git status, and 2.645 for the peer workload. The peer
run verifies all 2,000 files with no ESTALE retry, but only one before the writer
finishes; results.md discloses the changed overlap and mixed before/after v7
wall times. Run 145 supplies final CPU/heap/mutex profiles for both components.
These focused wrappers exit 70 for omitted inventory. Step 6 is measured and
regression-tested; the final full gate remains the step-7 obligation.


## Step 7: final-gate corrections and public contracts

Full run 151 passes Darwin Foundation/cgo and Linux static builds/vet,
govulncheck, native Go and race suites, the go-fuse reply seam, the native
Swift/Xcode inventory (344 enumerated and passed), release policy, and
architecture scans. The real-mount suite then fails the SQLite handoff: the
first mount sees two rows instead of three. This is not a passing full gate.

Focused run 152 reproduces on repetition six. Run 153 captures the previously
ignored holder process output and proves its COMMIT failed with SQLITE_BUSY;
`busy_timeout=0` allowed no wait for the contender's transient SHARED lock.
Closing stdin then rolled the uncommitted holder transaction back. SQLite
[documents this COMMIT result](https://www.sqlite.org/lang_transaction.html).
The fixture now gives the holder the same bounded 60-second busy timeout as the
waiter, checks its exit status, and requires the exact three ordered row values
on both mounts in addition to integrity and count. The contender still uses an
ordinary implicit INSERT transaction, must remain blocked for the full one-second
hold, and both mounts' first final queries must be correct. No filesystem
implementation or coherence guarantee changed. Run 154 passes all 30 repetitions;
the focused wrapper exits 70 only because the other required tests were omitted.

Public contracts replace the v6 description with subscription, delegation,
break-for-read, stable-cookie enumeration, barrier/loss, and cold epoch recovery.
The three design residuals are copied verbatim into portable-coherence.md.
Architecture, consistency, failure, matrix, performance, README, compatibility,
and changelog text now agree with those interfaces. Full-gate qualification
follows below; earlier status sections in this chronological record describe
work outstanding at the time of each run.

Run 155 completes `bash scripts/verify-local.sh --full` with exit 0: all 66
required privileged tests, the root boundary test, and the matrix's 28 PASS /
zero FAIL / unchanged single-principal chown SKIP. Both negative controls have
their declared outcomes. This is the Linux qualification before the following
Mac boundary correction, not the final tree's gate result.

The documentation audit finds Swift's production nested-contract parser still
requires authority major 6, although portablefsd emits ProtocolMajor (7). Its
independently constructed Swift fixtures also used 6, so 344 passing tests had
not covered the pair. The parser and all accepted fixtures now use exact 7;
explicit negative cases refuse 6 and 8. A new shared pfslocal golden compares
an actual Go `newV3CoherenceBridge(...).resolveContract()` Resolve frame against
both language fixture copies, and Swift decodes that frame through its shipping
parser. Local pfslocal remains major 1/minor 15 with unchanged field numbers and
cache-policy names. Go bridge tests pass; run 156's native Xcode gate enumerates
and passes the exact 345-test inventory (59 AppCore, 286 Kit). No real FSKit mount
is claimed by that test. Run 156 repeats the complete full gate after this fix.

## Remaining limits and unrun qualification

- The design's three accepted residuals remain: a stopped daemon cannot fence
  resident kernel pages; quota exhaustion may be learned after buffered
  acceptance; contended files require write-through. The exact design wording
  is reproduced in [portable-coherence.md](../portable-coherence.md).
- Epoch recovery reuses the configured attach grant before restarting exact
  session-bound reauthorization. The matrix proves recovery with a valid grant.
  An expired/refused grant leaves the mount cold and retrying; acquisition and
  installation of a fresh attach grant is not implemented on that path.
- Prior Linux membership waits out its old subscription horizon for serving,
  but remains unproven for route changes and archival until an absence proof.
  Old untyped membership is conservatively treated as Mac compatibility state.
  Inferring absence from an epoch change would be unsafe.
- Reverse `d_path`/`getcwd` rendering of retained dentries is outside the
  forward-lookup contract. Stock FUSE shared writable mmap and per-call
  RWF_APPEND/RWF_NOAPPEND remain unsupported. Mac name/attribute invalidation,
  append, and advisory-lock limitations remain behind Mac writer exclusion.
- `remote_chown_visible` retains its declared SKIP. A single-principal volume
  refuses a change to another owner with EPERM, so the ownership transition
  cannot be demonstrated. The other original 22 and all six additions pass in
  final runs 156 and 157. No passing case became a skip.
- The 256-pending-close budget protects the shipping open-table limit. It is
  not negotiated for arbitrarily smaller custom limits, which may return
  ENFILE. Concurrent handle admissions retain bounded headroom rather than
  reserving individual Authority slots.
- Performance evidence is one shared 4-CPU/8-GiB VM, loopback TLS, and tmpfs-backed
  loop XFS. It does not qualify physical storage, production RTT, or an SLO.
  Final peer overlap is only one of 2,000 files; all are verified, and separate
  concurrent regressions preserve overlap. Final-versus-initial v7 wall times
  are mixed. Defensive asynchronous protobuf/replay/callback ownership still
  allocates; the profiles do not justify unsafe pooling.
- Production runner kernel/image pinning, broader LTS qualification, and
  OpenSteer run-start/root-handle barrier wiring at completion, sandbox exit,
  and detach are deployment obligations outside this local workstream.
  Directory delegation, quota reservation, and transparent recovery of old
  handles are deliberately outside this foundation.
- `scripts/package-manager-matrix.sh` was not run: it is the separate optional
  workload soak, not either required privileged gate. A live
  `scripts/coherence-matrix-macos.sh` was not run: it needs a user-enabled FSKit
  extension and is not established by native Swift tests. No
  `deploy/opensteer/staging-qualification.sh` against a deployed cell was run.
  These omissions are also printed by `verify-local.sh --full`.

## Final verification record

Run 156 executes `bash scripts/verify-local.sh --full` on the final runtime
changes and exits 0. It passes Darwin Foundation/cgo and static Linux builds
and vet, the pinned govulncheck (no vulnerabilities), native Go and race suites,
the maintained go-fuse physical-reply lifecycle tests, exact native Xcode
inventory (345 enumerated = 345 passed), workflow/release-trust policy, and
stale-architecture/active-contract scans. The privileged suite reports all 66
required unprivileged tests and its one root boundary test passed. Its matrix
runs both falsifiability controls and reports 28 PASS, zero unexpected failures,
and only the unchanged `remote_chown_visible` SKIP. The full log is
`/tmp/cv2-g-verify-full-156.log`.

The matrix's disjoint and stale-view controls intentionally print FAIL outcomes
for their declared negative cases; those are required evidence, not hidden
failures. The expected destructive peer-loss case also prints the killed mount
process during cleanup. The gate exits 0 only after those expectations match.
A separate invocation of `bash scripts/coherence-matrix-linux.sh` is run as 157;
its final result is recorded below.


Run 157 independently executes `bash scripts/coherence-matrix-linux.sh` and
exits 0. Both negative controls match; the real matrix again reports 28 PASS,
zero unexpected failures, and the same single-principal chown SKIP. Its log is
`/tmp/cv2-g-matrix-157.log`. This closes the requested final matrix repeat.

Final review confirms every changed Go file is gofmt-clean, relative links in
changed Markdown resolve, the three residual paragraphs match design.md
verbatim, and `git diff --check` passes. No `LEASE_RIGHT_*`, `lease_grants`,
`NextLeaseEvent`, `RenewLeases`, or `SourceLeaseDischarge` reference remains in
fusev3, mountv3, or the Linux mount command. Frozen schema history and refusal
tests remain deliberately. Every workstream commit uses Tim Jang's requested
author identity and DCO sign-off. The full [file list](changed-files.txt) covers
154 added, modified, or deleted paths from the starting tree.

## G2

G2 continues on `cv2-integrate`. The review items below supersede conflicting
G decisions above. Each item records its regression evidence; final full-gate
and performance qualification remain outstanding until explicitly recorded.

### R1: CONTROL-only loss and the cold cache boundary

`TestControlTransportLossWithdrawsEveryCacheAtHorizon` closes only the reader's
CONTROL socket and rejects replacement connections, retaining both processes,
the reader's DATA socket and the peer's transports. It snapshots positive and
negative names and cached inodes, checks every returned reverse notification,
requires empty daemon payload caches and EIO on retained kernel-page reads,
and checks Authority refusal through the still-connected DATA socket. A peer
write completes after the horizon; the reader sees its new bytes only after
cold resubscription. Neither authenticated session nor mount terminates.

The test failed on both missing name notifications. Cold invalidation now
issues EntryNotify, and resolves negative-name parents by Authority inode,
matching their cache keys, rather than by FUSE node id. Cached-data records
remain as invalidation indexes for surviving handles, with their pages withdrawn.
The focused Docker command selecting this test and
`TestColdSubscriptionNeverClearsEpochStaleness` passes (10.02 seconds for the
transport test); the wrapper exits 70 solely for omitted full-suite inventory.
Logs: `/tmp/cv2-g2-r1-before.log`, `/tmp/cv2-g2-r1-after2.log`.

### R2: bounded reconnect without a caller deadline

Reconnect now uses an internal SubscriptionTTL deadline. A shorter caller
cancellation/deadline keeps its original error; exhaustion of the internal
bound returns ErrTransportUncertain without inventing a session verdict.
`TestReconnectUnavailableListenerHonorsCallerDeadline/background` failed after
11 seconds without the change and now returns at ten seconds. The caller
50 ms deadline and listener-gap same/new-epoch tests pass. Exact command:
`go -C vcs test ./internal/authorityrpc -run '^Test(ReconnectUnavailableListenerHonorsCallerDeadline|ReconnectSurvivesListenerGapBeforeEpochVerdict|IdleLinuxControlLossResumesWithoutEndingSession)$' -count=1`.
Logs: `/tmp/cv2-g2-r2-before.log`, `/tmp/cv2-g2-r2-after.log`.

### R3: restored F10; namespace-lock cycle blocks qualification

Restored F10 verbatim from `coherence-v2:docs/coherence-v2/design.md` and
removed the conflicting zero-entry-validity exception from the subscription,
wire and client descriptions. Namespace withdrawal now requires returned
EntryNotify; attribute/data withdrawal retains InodeNotify. The new
`TestNamespaceWithdrawalRequiresReturnedEntryNotify` fails without the change
and passes with it, including a refused notification followed by a successful
retry after the daemon binding has already gone.

`TestKernelEntryInvalidationProof` keeps a positive dentry in use through an
open fd with one-hour entry and attribute validity. Removing the daemon
binding alone leaves stat cached; returned EntryNotify forces exactly one
new LOOKUP and observes ENOENT. The shipping kernel proves that mechanism.
`TestKernelEntryNotifyWaitsForNamespaceCallback` separately holds a CREATE
callback open, then notifies another name in that same parent. The notification
cannot finish until the CREATE callback returns. No PortableFS coordinator,
transport or daemon lock participates in this second proof.

This is a blocking conflict with the existing acknowledgment ordering. A
namespace syscall acquires the kernel parent lock before reaching the daemon.
A peer commit waits for this mount's withdrawal acknowledgment, but EntryNotify
needs that same parent lock. If the held syscall needs the peer's completion,
none can finish until the subscription horizon. Moving a daemon acquire lock
or dispatching the notification on another goroutine cannot release the VFS lock.
Linux 6.8 `fuse_reverse_inval_entry` takes `inode_lock_nested(parent,
I_MUTEX_PARENT)` before looking up or expiring the dentry; FUSE_EXPIRE_ONLY
still takes it. See the [kernel implementation](https://github.com/torvalds/linux/blob/v6.8/fs/fuse/dir.c#L1254).

The unchanged `TestMutationPostStateEliminatesFollowupMetadataRPCs` reproduces
this conflict: same-name CREATE takes 10.005831796 s in the focused run and
10.002519301 s in the full suite, exceeding its two-second bound and expiring
a subscription. The assertion remains unchanged. The full matrix also fails
its stale-view control after transport termination; this is a failed gate,
not an expected negative-control result.

Commands and evidence:

- `PORTABLEFS_GO_TEST_FLAGS='-run ^Test(NamespaceWithdrawalRequiresReturnedEntryNotify|KernelEntryInvalidationProof)$' bash scripts/xfs-fuse-integration.sh`: before restoration, the namespace proof fails; kernel entry proof passes. Log `/tmp/cv2-g2-r3-before.log`.
- `PORTABLEFS_GO_TEST_FLAGS='-run ^Test(NamespaceWithdrawalRequiresReturnedEntryNotify|KernelEntryInvalidationProof|MutationPostStateEliminatesFollowupMetadataRPCs)$' bash scripts/xfs-fuse-integration.sh`: fails the existing CREATE timing assertion. Log `/tmp/cv2-g2-r3-after.log`.
- `PORTABLEFS_GO_TEST_FLAGS='-run ^Test(KernelEntryInvalidationProof|KernelEntryNotifyWaitsForNamespaceCallback|NamespaceWithdrawalRequiresReturnedEntryNotify|Subscription|ColdSubscription)' bash scripts/xfs-fuse-integration.sh`: all selected proofs/subscription tests pass; wrapper exits 70 for unselected required inventory. Log `/tmp/cv2-g2-r3-proofs.log`.
- `bash scripts/xfs-fuse-integration.sh`: exit 1 at the unchanged CREATE timing assertion. Log `/tmp/cv2-g2-xfs-full.log`.
- `bash scripts/coherence-matrix-linux.sh`: exits 71 in its stale-view control, including unexpected cached-handle and peer-loss results after mount transport termination. Log `/tmp/cv2-g2-matrix.log`.

G2 is **incomplete and not merge-ready**. R1 and R2 have passing focused
regressions; R3 restores the requested contract but demonstrates an unresolved
kernel/protocol ordering conflict. R4–R10, the initiator-gate follow-up, C1–C11,
and Part 2 remain unimplemented. No G2 workload measurements or speedup claims
are made, and no existing test has been weakened. The next implementation must
resolve the parent-lock cycle while retaining returned EntryNotify before ACK,
before enabling nonzero kernel lifetimes or claiming full-gate completion.

`bash scripts/verify-local.sh --full` exits 1 on the same unchanged CREATE
regression after 72.889 seconds in fusev3. Before that failure it passes the
Darwin Foundation/cgo and static Linux builds/vet, vulnerability check, native
Go and race suites, physical-reply seam, all 345 enumerated Swift tests,
release-trust policy and architecture/contract scans. Its embedded matrix does
not run because XFS/FUSE failed; the separate matrix result above supplies that
attempt. Full log: `/tmp/cv2-g2-verify-full.log`.

G2 exposes no new wire or cross-workstream interface. Changed paths are
`vcs/internal/authorityrpc/{client_transport.go,client_restart_test.go}`,
`vcs/internal/fusev3/{control_horizon_linux_test.go,integration_support_linux_test.go,subscription_linux.go,subscription_linux_test.go,kernel_invalidation_proof_linux_test.go,kernel_namespace_lock_proof_linux_test.go}`,
and `docs/coherence-v2/{design.md,wire.md,client.md,integration.md}`.

| Measured regression observation | Before | After |
| --- | --- | --- |
| Background reconnect to an unavailable listener | Still waiting at 11 s; regression fails | Returns ErrTransportUncertain at the 10 s internal bound |
| CONTROL-only horizon, positive/negative name notifications | Both missing; regression fails | Every snapshotted name/inode notified; test passes in 10.02 s |
| Namespace withdrawal with failed EntryNotify | Incorrect success | Error; successful notification retry then succeeds |
| Same-name CREATE with restored EntryNotify | G's zero-validity implementation qualified by run 156; no new G2 baseline timing | 10.006 s focused, 10.003 s standalone full suite; unchanged <2 s requirement fails |

These observations measure regressions, not install or Git performance. Part 2
has not begun, so results.md and docs/performance.md retain G's measurements.

### R3 reversal: design owner approved zero kernel validity

The design owner accepted the kernel lock-cycle proof and reversed R3. G's
F10 amendment stands: kernel entry_valid and attr_valid stay zero, daemon
bindings and attributes live under the subscription, and acknowledgment covers
purged bindings plus returned InodeNotify for cached pages. EntryNotify never
participates in the change acknowledgment path. Cold horizon withdrawal retains
R1's notifications and transport-loss proof.

Restored the pre-R3 behavior and its wire/client descriptions. The retained
`TestKernelEntryNotifyUnderHeldParentLockStallsAndMustNotGateAck` names the
parent-lock constraint explicitly; the positive-dentry notification proof also
remains. `TestNamespaceWithdrawalPurgesBindingsWithoutEntryNotify` fails against
R3 when EntryNotify returns EIO, and requires both a removed negative binding
and no notification call. Before log: `/tmp/cv2-g2-r3-reversal-before.log`.

This decision supersedes the preceding R3 requirement and its unresolved
contract statement. Part 2 item 3 now requires allocation-free daemon cache
hits and negative caching, with zero Authority LOOKUPs for a warm stat and a
create whose absent binding is cached. Nonzero kernel cache lifetimes are
excluded by the approved contract.

The standalone matrix exits 0 (28 PASS, the unchanged chown SKIP, both negative
controls matched), log `/tmp/cv2-g2-r3-reversal-matrix.log`. The initial full
XFS/FUSE run stops on a duplicate LOOKUP count after unlink; a focused repetition
also exposes an existing-name CREATE coherence refusal. Neither assertion was
relaxed. Gate repair continues before R4. The no-EntryNotify regression and
renamed kernel parent-lock proof pass in the focused repetition.

### Gate restoration: physical reply cache settlement

Zero kernel validity lets the kernel request a second lookup immediately after
/dev/fuse wakes it, before ReplyWritten settles the preceding daemon cache
candidate. This produced two LOOKUPs after an unlink and follow-up metadata
RPCs after mkdir/SETATTR. Cached LOOKUP and GETATTR now join only finalized,
unrevoked candidates for their exact coordinates, with the registry mutex
released while waiting. They revalidate after waking; callbacks still building
replies, superseded negatives, and revoked candidates never block a cache miss.
No kernel validity changed.

`TestCachedLookupWaitsForFinalizedReplyCacheSettlement` covers negative names,
positive names, attributes, revoked candidates, and superseded negatives. Its
initial negative arm failed before the fix (`negative=false` before settlement,
`/tmp/cv2-g2-negative-settlement-before2.log`). The final table passes in Docker,
`/tmp/cv2-g2-settlement-unit.log`. The real negative-name and mutation post-state
regressions plus the initial settlement test pass 100 repetitions each, log
`/tmp/cv2-g2-cache-settlement-diagnostic2.log`; the focused wrapper exits 70
for intentionally unselected full-suite inventory.

One isolated same-name CREATE returned EIO/COHERENCE during the earlier focused
run. Its concrete server error was not captured and did not recur in those 100
repetitions; this record does not assign it an unproven coordinator cause.

Two test-harness corrections preserve their original contracts. Recovery now
waits for both independent subscriptions before accessing both mounts, within
the existing 20-second bound. The graft filesystem counter excludes protocol-7
poll/ack names instead of their retired protocol-6 spellings; its new unit test
retains counts for every filesystem and unknown request. The zero-filesystem-RPC
assertion remains unchanged. Failing logs are `/tmp/cv2-g2-restored-xfs-3.log`
and `/tmp/cv2-g2-restored-xfs-4.log` respectively.

Both initial gates are green before R4: `bash scripts/xfs-fuse-integration.sh`
exits 0 with all 66 required tests and the root boundary test passing
(`/tmp/cv2-g2-restored-xfs-5.log`). `bash scripts/coherence-matrix-linux.sh`
exits 0 with 28 PASS, the unchanged chown SKIP, and both controls matching
(`/tmp/cv2-g2-restored-matrix-2.log`). The full local gate remains due after the
remaining G2 work.

### R4: SETATTR capability contract

wire.md now states that mode/uid/gid/times and size SETATTR accept a retained
session handle without an item capability, require matching identities when
both are supplied, and refuse neither with EINVAL. The handler already enforces
this refusal; no runtime change was necessary. The new table
`TestCoherenceSetAttrRequiresItemOrHandle` drives the full handler for all eight
field forms and requires EINVAL, no application ticket, and no post-state.

Validation: cross-compiled `./internal/authorityrpc` with
`CGO_ENABLED=0 GOOS=linux go -C vcs test -c`, then executed the test binary in
the pinned Docker image with `-test.run '^TestCoherenceSetAttrRequiresItemOrHandle$'
-test.v`. All eight cases pass; log `/tmp/cv2-g2-r4.log`.

### R5: cookie-only store continuation

Removed the unused input verifier from the store ReadDirOpen API, its handler
interface, adapters, and callers. The returned page verifier still guards
publication revalidation. Stable-cookie seek and concurrent-mutation tests keep
their exact-once unchanged-entry assertions; callers cannot silently supply an
ignored verifier to the store anymore. The frozen wire verifier remains
optional, shape-checked, and independent of continuation authority. A new
handler test refuses malformed lengths before any enumeration call.

`PORTABLEFS_GO_TEST_FLAGS='-run ^Test(ReadDir|CoherenceReadDir|CoherenceLookupAndEmptyReadDir)'
bash scripts/xfs-fuse-integration.sh` passes every selected test with no selected
skip, including deep-cookie seeks and concurrent directory mutation. Exit 70
reports only unselected full-suite inventory. Log: `/tmp/cv2-g2-r5.log`.

### R6: concurrent truncating opens and peer withdrawal

The new real-kernel test
`TestConcurrentTruncatingOpensDoNotBlockReservedGrantWithdrawal` holds a peer's
cached read descriptor, pauses its returned InodeNotify after storage size
reaches zero, and starts two truncating opens on the source mount. While the
withdrawal acknowledgment is withheld, the peer must read EOF promptly and
neither OPEN may complete. Both finish after release, with unchanged subscription
incarnations, no loss advance, and size zero. The notifier's storage-size check
separates pre-apply reservation invalidation from the post-apply interval under
test; the initial test draft incorrectly assumed the first notification implied
storage application.

No production lock change was required. The acquire lock serializes local OPEN
installation; CONTROL does not take it. The unreported grant stays reserved
through withdrawal, allowing the peer read without a break against an OPEN reply
the holder has not received. Ten repetitions pass in the privileged suite with
`PORTABLEFS_GO_TEST_FLAGS='-run ^TestConcurrentTruncatingOpensDoNotBlockReservedGrantWithdrawal$ -count=10'`.
Log `/tmp/cv2-g2-r6-postapply.log`; wrapper exit 70 is unselected inventory.

### R7: release covers a synchronous mutation admitted after recall

`TestCoherenceReleaseCutCoversSynchronousMutationAdmittedAfterRecall` observes a
recall with ticket floor zero, admits a holder synchronous mutation afterward,
ends it with ticket 17, and releases that exact applied cut. It requires both
the completed pending cut and its waiter to report 17. Existing production code
already provides this guarantee. Removing the release-to-pending ticket assignment
through a Go build overlay makes the test fail with `applied 0; want 17`
(`/tmp/cv2-g2-r7-before.log`), without modifying the working runtime source.
The unmodified implementation passes 20 repetitions with
`go -C vcs test ./internal/volumeserver -run '^TestCoherenceReleaseCutCoversSynchronousMutationAdmittedAfterRecall$' -count=20`.

### R8: distinguish retired delegation registration

AddHandle now returns errDelegationRetired for a known identity whose grant
retired before registration. An identity that never had delegation state still
returns nil and remains untracked. The frontend explicitly accepts the retired
sentinel because the Authority OPEN remains valid as an ordinary handle. The
table tests unseen, live, and retired identities and checks the frontend path.
It fails before the change (`retired generation registration = <nil>`) and
passes afterward in the pinned Docker image. Logs:
`/tmp/cv2-g2-r8-before.log`, `/tmp/cv2-g2-r8-after.log`; the binary was built with
`CGO_ENABLED=0 GOOS=linux go -C vcs test -c` and executed with
`-test.run '^TestDelegationReaderOpenRemainsValidWhenLastWriterReleaseWins$' -test.v`.

### R9: auto-ack requires an empty adapter queue

Internal coordinator advances retire only when the wire withdrawal prefix is
complete and the adapter queue is empty. The new test invokes that action
against a real coordinator and checks WaitWithdrawn: a queued change with equal
wire cursors must still block, as must a delivered unacknowledged change; a
drained acknowledged position completes. The queued row fails before the queue
guard and passes after it. Logs `/tmp/cv2-g2-r9-before.log` and
`/tmp/cv2-g2-r9-after.log`, using the cross-compiled authorityrpc test binary in
the pinned Docker image with `-test.run '^TestCoherenceControlAutoAckRequiresDrainedQueue$' -test.v`.

### R10: per-case control exclusions

The matrix script now documents each protocol-7 exclusion at both control
filters. The gateway probe is an external authenticated subprocess that neither
replacement root B nor actor-side stale pathname answers intercept. Recall loss
pauses the real mount-b daemon and tests retained handles/barriers; an unrelated
directory fd is not owned by that daemon, and pathname replay cannot model its
missed CONTROL acknowledgment. Epoch replacement changes the real Authority and
retained server handles; the disjoint directory has no Authority epoch, and the
stale-path actor does not inject old-handle state. These process experiments run
in the real phase, which still requires all three to PASS. No negative-control
coverage is claimed for their process/handle mechanisms.

This is a rationale-only change: selected cases and expectations are identical.
`bash -n scripts/coherence-matrix-linux.sh` passes. The initial complete matrix
runs above exercised these unchanged filters; the final matrix remains required.

### Initiator gate: cover directory enumeration as well as names

The producer inventory test now names all four namespace-operation change kinds:
namespace, directory enumeration, attributes, and data (truncating create).
Source gates omitted the enumeration coordinate. Because the source's own stream
omits those changes, an open directory handle could retain an old page or EOF.
Namespace gates now drain the parent's enumeration coordinate and invalidate its
registered directory cursors before making callback publication ready. Cursor
locks are taken outside the inode-table lock; the source gate stays closed.

The link/truncating-create table verifies all four kinds, source ownership and
exclusion through publication, directory page/EOF retirement, parent and child
attribute retirement (including the stale link-count regression), and retention
of the kernel data obligation. Before the fix both rows report an uncovered
directory coordinate and retained EOF; afterward the source/gate suite and
producer inventory pass in the pinned Docker image. Logs:
`/tmp/cv2-g2-source-before.log`, `/tmp/cv2-g2-source-after.log`, and
`/tmp/cv2-g2-source-producer.log`. Test binaries were cross-compiled with
`CGO_ENABLED=0 GOOS=linux go -C vcs test -c`; selected tests were
`^Test.*(Source|Gate|CreateReply|UnrelatedWrite)` and
`^TestCoherenceChangeCoordinates$`.

### C1: preserve definite capacity errors through delegated writeback

Definite unapplied ENOSPC, EDQUOT, and EFBIG refusals now discard the affected
buffer with its exact errno and retain the delegation. Classification handles
both top-level errno and the stock WRITE negative-error envelope; partial or
applied replies remain uncertain failures. DropReport records errno, and paired
identity loss/errno observations preserve it for each open handle and the root
barrier. The buffer no longer overwrites a flusher's refusal with generic loss
when that callback dropped its records. The retained grant is rebound to the
buffer's successor generation so a later write can succeed.

Synchronous writes release the admission read fence before flushing, while the
per-identity operation lock preserves their cut. This lets a flush failure take
the admission write lock to retire or rebind the generation without self-wait.
The regression matrix covers all three errnos for WRITE, SETATTR-size, and
synchronous WRITE, next-write observation, close FLUSH, FSYNC, root barrier, loss
advance, and a successful successor write. Before the fix ordinary WRITE and
SETATTR rows fail with generic lost-buffer errors. Afterward all delegation
tests pass in the pinned Docker image, and the writeback suite passes with race
detection. Logs: `/tmp/cv2-g2-c1-before.log`,
`/tmp/cv2-g2-c1-delegations.log`, `/tmp/cv2-g2-c1-writeback.log`.
Exact commands: cross-compiled fusev3 binary with `-test.run '^TestDelegation'`,
and `go -C vcs test -race ./internal/writeback`. The separate C8 coherence-rejection
regression follows in its requested order; drop-report delivery is C3.

Review added two boundary checks before this commit: an uncertain ENOSPC reply
must retire the delegation, and a later quota error cannot hide a generic loss
newer than an observer's cut. Per-identity and mount loss records retain the
latest generic-loss ticket as well as the latest errno; generic loss takes
precedence until observed. The mixed-loss test fails with the first implementation
and passes with that correction. Quota rebinding also removes obsolete generation
bindings. The broader unprivileged FUSE run passed after excluding only
`TestKernelFUSEProbeCompletesInit`, whose required fusermount executable is absent
from the base Go image; mounted tests self-skipped there. This is unit evidence,
not a replacement for the unchanged privileged final gate.

### C2: fence admissions parked at the writeback cap

Epoch replacement closes buffer admission and wakes waiters before requesting
the epoch write lock. It does not join the flusher under that read lock. A
pointer-validation retry ensures concurrent replacements also fence a successor
buffer before replacing it. Admission therefore either completes before the cut
and is included in the drop, or wakes with ErrClosed, mapped to EIO. The buffer
exposes its waiting-admission count so the tests prove an actual capacity wait.

The deterministic manager regression fails before the change with a parked write
that survives the fence; it passes 20 repetitions after the change. The mounted
regression fills the real 64 MiB cap, stalls delegated DATA before replay-slot
assignment, then kills the actual CONTROL transport and rejects reconnects. Its
natural horizon wakes the kernel write with EIO, advances loss, and refuses a
cold namespace request with EIO. Healing permits a cold resubscribe; the old root
barrier reports loss and a new root barrier succeeds without revoking the mount.
The pre-assignment DATA fault isolates admission fencing: an earlier draft that
closed an already-assigned DATA socket correctly triggered the separate terminal
uncertainty policy and ENOTCONN, so it could not prove this live-mount boundary.

The mounted test also found that LOOKUP could reach the Authority during the
conservative local horizon and return ENOENT. Shared LOOKUP and source mutations
now refuse locally while the subscription is cold; resource CLOSE remains usable.
A LOOKUP/MKDIR unit table requires EIO and zero Authority mutations. The real
partition test is now required inventory in the privileged script.

Validation: `/tmp/cv2-g2-c2-before.log`, `/tmp/cv2-g2-c2-after.log` (20 manager
repetitions), `go -C vcs test -race ./internal/writeback` passes. The privileged
selection `PORTABLEFS_GO_TEST_FLAGS='-run ^Test(TransportLossInterruptsWritebackCapacityWaitAtHorizon|NamespaceRequestsRefusedWhileSubscriptionCold)$' bash scripts/xfs-fuse-integration.sh`
passes both selected tests, including the mounted horizon at 9.03 s; wrapper
exit 70 names the unselected inventory. Log `/tmp/cv2-g2-c2-mounted-4.log`.

### C3: bound dirty shutdown by the subscription horizon and report loss

Dirty shutdown attempts its barrier even after revocation or a session-end
signal. Its budget is the remaining live Authority horizon, including zero for
an expired horizon; an absent live horizon falls back to SubscriptionTTL. Failed
barriers fence final admission, drop every retained identity, and emit its exact
DropReport through Config.OnWritebackDrop and the standard log. Quota, coherence,
and epoch drops use the same reporting path. Reports include identity, retained
bytes and entries, loss sequence, errno, and cause.

The regression retains an applied-but-not-durable write, makes Barrier unreachable,
and exposes a preexisting terminal session cause. It fails before the change
because shutdown returns nil without a barrier. After the change it waits through
an 80 ms live horizon, returns DeadlineExceeded, reports one eight-byte record,
and leaves no buffered entries. The budget table covers live, expired, inactive,
and absent horizons. DropAll tests accepted, applied, and visible records and
requires that repeating shutdown does not invent another loss.

Validation: `/tmp/cv2-g2-c3-before.log`, `/tmp/cv2-g2-c3-after.log` (shutdown,
clean-close, and delegation suites), `/tmp/cv2-g2-c3-budget.log` (ten repetitions
of shutdown and budget tests), and `/tmp/cv2-g2-c3-writeback.log` from
`go -C vcs test -race ./internal/writeback`. Linux unit binaries ran in the pinned
Docker image. No wire fields or kernel cache policy changed.

Shutdown review added `TestCloseFencesCapacityWaitBeforeBarrier`: a real manager
admission parked at a one-entry cap prevented Barrier from acquiring its frontend
lock. The test fails before moving the admission fence ahead of both the retained
check and Barrier. That order also prevents a clean-buffer check from racing a
new accepted write. The corrected close, clean-close, budget, and delegation
suites pass (`/tmp/cv2-g2-c3-final-unit.log`); the counterexample is recorded in
`/tmp/cv2-g2-c3-cap-before.log`.

### C4: prove break-for-read ordering for every read family

The break test now covers READ, GETATTR, LOOKUP, READDIR, and FSYNC. It observes
the actual StreamBreakForRead before checking storage counters, acknowledges that
exact cut, and verifies the resumed result and call counts. The new READDIR row
fails before the change: its first directory page was read before admission.
READDIR now admits the directory before that page and candidate construction,
then releases its guard before admitting children to avoid nested identity guards.
The final storage turn still revalidates the page.

LOOKUP has an explicit identity-discovery qualification: one binding probe is
needed to discover the child whose delegation must be broken. The test requires
exactly that one probe and zero authoritative attribute samples before the ACK;
it does not claim literally zero Store.Lookup calls. The discarded probe is not
published. READ, GETATTR, READDIR, and FSYNC require zero corresponding value
reads/syncs before ACK. This preserves the actual publication contract rather
than hiding discovery I/O in the counter.

The pre-change READDIR failure is `/tmp/cv2-g2-c4-before.log`. All selected
`^TestCoherence(Read|Lookup)` tests pass in the pinned Docker image after the
change (`/tmp/cv2-g2-c4-after.log`), using the cross-compiled authorityrpc binary.

### C5: recall peer grants before size and range mutations

A full-handler table now holds a peer delegation while issuing SETATTR-size,
FALLOCATE, or COPY_FILE_RANGE. The copy row delegates only the destination, pairing
with the retained source-break test. Each row requires an exact-identity
StreamRecall, zero storage applications before AckDelegation, and one successful
application after that ACK and the subsequent change withdrawals. Production
preflight already implements this ordering; no runtime change was needed.

The table passes in the pinned Docker image (`/tmp/cv2-g2-c5.log`). A Go build
overlay that bypasses BeginSynchronousMutation makes all three rows fail because
no recall is emitted (`/tmp/cv2-g2-c5-fault.log`); the repository runtime was not
modified for that counterexample. Both binaries ran with
`-test.run '^TestCoherenceMutationsRecallPeerDelegationBeforeStorage$' -test.v`.

### C6: holder cache handles do not force writethrough

The cache-mode table now includes one and three holder-owned cache-capable
handles with no peer handles, plus a mixed holder/peer row. Holder-only grants
must remain FULL; peer handles still require WRITETHROUGH and closing the last
peer still upgrades only after the holder acknowledges. Existing runtime logic
is correct. The native table passes 20 repetitions (`/tmp/cv2-g2-c6.log`). A Go
overlay replacing the holder-subtracted count with the total count fails both
holder-only rows and the mixed-row upgrade (`/tmp/cv2-g2-c6-fault.log`). Command:
`go -C vcs test ./internal/volumeserver -run '^TestCoherenceDelegationCacheModes$' -count=20`.

### C7: preserve delegation references on truncate and fallocate

Buffered truncate and size-SETATTR flush assertions now require the grant's exact
ID and generation as well as a writable handle. A raw FALLOCATE test opens a
FULL writer, captures the emitted request, and requires that same exact grant.
Both paths were already correct. The tests pass (`/tmp/cv2-g2-c7.log`); an overlay
removing the two reference fields fails both (`/tmp/cv2-g2-c7-fault.log`). Linux
binaries ran in the pinned Docker image with
`-test.run '^Test(DelegationTruncationAlwaysFlushesThroughWritableHandle|V7FallocateCarriesExactDelegationReference)$'`.

### C8: coherence refusal loses the grant and advances loss

The paired WRITE/SETATTR flush test injects an Authority coherence-class EIO and
requires ErrLost, retired ownership, advanced identity and mount loss, an EIO
handle observation, and an empty overlay. It passes alongside C1's capacity
matrix (`/tmp/cv2-g2-c8.log`). An overlay omitting the permanent-refusal loss
transition makes both rows fail (`/tmp/cv2-g2-c8-fault.log`). Existing production
behavior was correct; this distinguishes coherence refusal from C1's recoverable
capacity refusal. Linux binaries ran in the pinned Docker image.

### C9: namespace dependencies cover unlink, link, and evicted bindings

The F4 regression now covers rename, unlink, hard link, and unlink after eviction
of the daemon name binding. Each requires the buffered WRITE before the namespace
mutation; the evicted row additionally requires the fallback LOOKUP before WRITE.
The existing runtime passes (`/tmp/cv2-g2-c9.log`). An overlay bypassing
flushNamespaceDependencies fails all four rows (`/tmp/cv2-g2-c9-fault.log`). Both
Linux binaries ran in the pinned Docker image with
`-test.run '^TestV7F4RenameFlushesBeforeMutation$'`.

### C10: attach profiles determine compatibility exclusion

The actual Attach/Activate path now has a read-only FSKit row requiring the
compatibility-writer commitment and an EBUSY writer exclusion. A read-only
CACHELESS_READER row requires a false commitment, permits a concurrent read/write
Linux Attach/Activate, and leaves its writer admission open. Existing production
behavior passes (`/tmp/cv2-g2-c10.log`). An overlay removing the FSKit commitment
fails the positive row (`/tmp/cv2-g2-c10-fault.log`). Linux binaries ran in the
pinned Docker image with
`-test.run '^TestReadOnlyAttachCompatibilityWriterExclusion$'`.

### C11: remove retired lease residue and share renewal timing

Commit 81b011c already removed authorityrpc's lease client and the old
volumeserver lease coordinator, including ActivateHolder; those deletions are
not repeated. The unused delegatedIdentity helper and the duplicate three-second
renewal constant are now removed. renewLoop uses the coordinator constant and a
manual-clock test requires a renewal of the exact incarnation when it fires.
Changing only the coordinator interval to four seconds through a Go overlay
fails the old client and passes the new one (`/tmp/cv2-g2-c11-before.log`,
`/tmp/cv2-g2-c11-shared.log`).

The repair-budget sentinel was still used by two live withdrawal timeout paths.
Those paths retain their timeout, diagnostic, and fail-closed behavior; only the
obsolete special revocation classification is removed. They now report the
ordinary coherence-violation reason. Existing report-once and withdrawal-verdict
assertions remain. The CLI still reads the historical persisted reason token.
client.md now names G's successful integrated gates instead of its superseded
lease-activation failure. Focused subscription, revocation, and withdrawal tests
pass in the pinned Docker image (`/tmp/cv2-g2-c11.log`). These are targeted checks;
the final full gate remains required after the performance changes.

### C2 follow-up: unit fixtures cross the real cold-subscribe boundary

The broader Linux suite exposed four fixtures which bypassed production's
initial or replacement cold subscription and therefore correctly received EIO
from C2's new namespace fence. The graft fixture now subscribes after creating
its raw frontend. The direct epoch-recovery test performs the subscription
runner's replacement subscribe explicitly. Old-handle rejection and routing
assertions are unchanged. The unprivileged Docker fusev3 suite passes after
these corrections, excluding only the FUSE-device probe; mounted tests retain
their existing environment skips (`/tmp/cv2-g2-cache-suite2.log`).

### Part 2 amended 3/8: allocation-free subscribed metadata replies

Authority-backed entry_valid and attr_valid are now both zero on every ordinary
metadata output path, including anonymous creation. Shared cached positive and
negative LOOKUP and GETATTR bypass mutationContext and protobuf cloning. Cached
attributes retain a prefilled fuse.Attr. A bounded 256-slot reply arena preserves
physical reply ownership; exhausted slots fall back to the ordinary tracked
path. Hit registration and cache/source checks share raw.mu, while delegation
ownership is checked outside it. Subscription-only validation avoids acquiring
a delegation epoch reader beneath raw.mu. Delegation incarnation is atomic.

The lean reply is conservatively finalized at registration. Peer withdrawal,
cold invalidation, source gates, and terminalization all join its physical write.
Waiters allocate completion channels only when they attach. It neither
re-admits nor clones cached facts. Unit tests prove zero Authority calls and
zero allocations through PrepareReplyPayload/ReplyWritten: positive LOOKUP
22 -> 0, negative LOOKUP 9 -> 0, GETATTR 18 -> 0. Withdrawal and shutdown tests
pin the lazy receipt and source-gate drain. Before/after logs are
`/tmp/cv2-g2-cache-before.log`, `/tmp/cv2-g2-cache-proof2.log`, and the final
unprivileged Docker suite `/tmp/cv2-g2-cache-final-unit.log` (FUSE probe excluded;
real-mount tests keep their environment skips).

Zero attribute validity exposed a pre-existing TMPFILE cache hole: a versionless
anonymous-entry candidate hid the exact post-state candidate. Anonymous mutation
replies now defer attribute admission to versioned post-state. The retained
real-mount post-state request-count table passes (`/tmp/cv2-g2-cache-mounted3.log`).

New required mounted tests prove warm stat has zero LOOKUP/GETATTR RPCs and
CREATE with a subscribed negative has zero LOOKUP RPCs. The negative must be
known; arbitrary unseen names still need an Authority fact. The combined
CREATE-plus-stat test still permits one LOOKUP while its FULL delegation is
held; optimizing that holder path is separate from shared-cache reuse.
Mounted timing and its boundaries are in results.md. LOOKUP daemon read-to-reply
is 4.417 us median, while the enclosing syscall with two permission GETATTRs is
70.125 us; the full below-20-us round-trip target is not established. The focused
wrapper exits 70 for omitted inventory, not a test failure
(`/tmp/cv2-g2-cache-mounted7.log`). Final full qualification remains pending.

### Part 2 item 0: one workload profile capture path

Removed M's duplicate CPU/allocation capture implementation and optional
TestCoherenceProfiles entry point. The baseline meter is now the sole capture
path, including completion barrier and deferred CLOSE drain. It retains both
PORTABLEFS_PROFILE_DIR and PORTABLEFS_PROFILE_RUN; the wrapper forwards the
previously dropped run prefix. Each run exports its exact executable and all
profile types. Allocation snapshots retain the two-GC accounting boundary.
Historical profile artifacts remain readable by the analysis script.

The artifact test fails against the former baseline capture because the run
prefix is missing (`/tmp/cv2-g2-profile-before.log`) and passes with the unified
path (`/tmp/cv2-g2-profile.log`). The wrapper passes bash syntax validation and
the profile analysis script compiles. profiles.md distinguishes the historical
measurement from the replacement command.

### Part 2 item 0a: amortize fallback durability barriers

WRITE and FSYNC reply prefixes still retire retained entries immediately. The
fallback pump now caps Barrier attempts at one per second and defers them for a
second after observing reply-carried prefix progress. A first stalled cut may
advance immediately; application kicks thereafter cannot trigger per-file
syncfs. Epoch buffer replacement resets the fallback observation. The pump's
short timer only checks this constant-time policy; it does not scan retained
entries or issue a Barrier on every tick.

The deterministic policy test covers clean buffers, a thousand application
kicks, stalled retry, reply progress, and complete durability. The real flush
burst passes; an overlay restoring unconditional per-kick Barrier dispatch
fails with six Barriers inside the one-second limit
(`/tmp/cv2-g2-durable-fault.log`). All delegation tests pass with their existing
liveness deadlines (`/tmp/cv2-g2-durable.log`). The required mounted 1,000-file
install also passes its at-most-eight-Barrier assertion
(`/tmp/cv2-g2-durable-mounted.log`); the focused wrapper exits 70 only for omitted
inventory. Explicit completion barriers remain independent of this fallback cap.

The first mounted counter sample was invalid: the integration classifier folded
Barrier into `other`. The classifier now names Barrier, and the test also
requires at least the explicit completion Barrier so a missing counter cannot
pass. The corrected run observes seven Barriers for 1,000 files in 5.36 seconds
(`/tmp/cv2-g2-durable-mounted2.log`).

### Part 2 item 0b: implicit source progress

The CONTROL coordinator now consumes source-only changes inside the outstanding
long poll, advancing its delivered/acknowledged position without emitting a wire
event. A peer change still requires its withdrawal receipt; a trailing internal
advance retires immediately when that receipt arrives. The handler retains the
advanced cursor even when a poll is cancelled. Public coordinator Poll semantics
remain unchanged.

Grant/release events carry an internal exact-token owner. The current owner
installs and retires its grant through DATA/release replies and the local grant
registry, so it needs no duplicate subscription event. A cold incarnation still
receives an old pinned delegation's eventual release, including an ephemeral
one; SessionID equality cannot hide that cleanup. No wire fields changed.

Coordinator proofs pass ten repetitions, including peer obligations and cold
incarnations (`/tmp/cv2-g2-own-coordinator.log`). All authorityrpc coherence tests
pass in Docker (`/tmp/cv2-g2-own-authority.log`); replay tests now use genuine
broadcast changes where they previously used holder-local bookkeeping. Their
replay, sequence, and cut assertions remain intact. The frontend test proves
local ownership closes and reopens cache admission without subscription events.
The implicit-progress proof fails when PollControl uses the former behavior
(`/tmp/cv2-g2-poll-fault.log`).

The mounted 1,000-file install passes in 5.37 seconds with seven Barriers, zero
ChangeAck requests, and zero additional NextControlEvent requests (the initial
long poll remains outstanding), `/tmp/cv2-g2-own-mounted.log`. The focused wrapper
exits 70 for the intentionally omitted full inventory; this is targeted evidence,
not the final full gate.

### Part 2 item 1: local FULL-delegation FLUSH

An unlocked FULL holder now handles FLUSH locally after the existing stale/loss
checks. WRITETHROUGH and nondelegated handles retain the RPC. POSIX record-lock
owners retain synchronous Authority FLUSH even under FULL: tracking is per
stable identity and kernel owner, shared across handles, and begins before an
acquisition RPC. A successful FLUSH removes only its observed generation. A
mount-wide monotonic generation prevents both concurrent acquisition loss and
ABA after a key was removed. Flock remains a RELEASE/CLOSE obligation.

The table covers unlocked FULL, locked FULL, and WRITETHROUGH; generation tests
cover concurrency and reacquisition. Existing lock-owner forwarding and capacity
loss tests pass (`/tmp/cv2-g2-flush.log`). Disabling the fast path makes the new
FULL rows fail (`/tmp/cv2-g2-flush-before.log`). The mounted two-peer POSIX test
passes without retrying lock acquisition after close, and the 1,000-file install
passes in 5.26 seconds with zero FLUSH, zero ChangeAck, zero additional control
polls, and seven Barriers (`/tmp/cv2-g2-flush-mounted.log`). The focused wrapper
omits the other required tests; the full gate remains pending.

### Part 2 item 2: transactional READDIRPLUS

Pure Authority mounts now negotiate stock READDIRPLUS and use the existing
physical-reply transaction for lookup references, path bindings, and the directory
cursor. Mixed local-route mounts remain on READDIR. A fitting entry transfers
its capability from the buffered page under the directory lock before interning;
concurrent invalidation cannot reclaim it. Buffer-full leaves ownership and the
cursor unchanged. Dot/opaque records carry no inode lookup, and abandoned
capabilities have one reclaim edge. Physical reply failure rolls back the
provisional cursor and references.

Page admission now supplies daemon name stamps and full attribute payloads and
versions, while both kernel lifetimes stay zero. Every reservation is acquired
before charging capacity; expiry cannot leave a partial page or dereference a
failed reservation. Tests cover four pages for 1,000 entries, cached LOOKUP and
GETATTR reuse, buffer-full and invalidation ownership, physical failure, expiry,
and mount negotiation. The new page-count test fails with the former ENOSYS
handler (`/tmp/cv2-g2-plus-before.log`). All unprivileged fusev3 tests pass in
Docker, excluding the device-only probe; mounted tests self-skip in that run
(`/tmp/cv2-g2-plus-suite.log`).

The required mounted cold `ls -ln` lists 1,000 files with exactly four READDIR
RPCs and zero LOOKUP RPCs (`/tmp/cv2-g2-plus-mounted.log`). The selected wrapper
exits 70 for omitted inventory. The 1,000-entry callback proof and additional
expiry proof pass (`/tmp/cv2-g2-plus-final.log`).

### Intermediate baseline and discovered PLUS churn failure

The requested baseline after items 1–3 (amended 3/8 first) ran on `68fd4cf`.
Both 40,000-file install cases and cold/warm Git completed; results.md records
all measured values and the one-worker opcode table. Install regressed to
277/274 seconds because close still waits for the now-amortized durability pump.
The fresh 20,000-file git-add conformance case passes. The peer workload fails
with READDIRPLUS EIO, so the overall run is not green
(`/tmp/cv2-g2-baseline-1-3.log`). Close batching is being prepared separately;
the PLUS churn failure is addressed first in this worktree.

The failure combined entries from two Authority pages in one physical PLUS
reply when withdrawal replaced the page between entries. Each reply now retains
its first page generation and stamp, stops before fetching a replacement, and
observes exhaustion atomically with capability transfer. Expiry advances the
page generation too. The regression covers withdrawal and expiry, successful
physical commit of the partial reply, and the next callback's continuation.
Both rows fail with the boundary predicate disabled
(`/tmp/cv2-g2-plus-fault.log`); all PLUS unit tests pass
(`/tmp/cv2-g2-plus-fix.log`). The focused peer baseline passes three initial
repetitions and two after the final pre-fetch check
(`/tmp/cv2-g2-plus-peer3.log`, `/tmp/cv2-g2-plus-peer-final.log`). These filtered
wrappers exit 70 for omitted required inventory; full gates remain pending.

### Part 2 item 4: applied release and batched descriptor cleanup

Final-handle cleanup now closes per-identity admission, captures the accepted
cuts, and performs application, release, and descriptor-close RPCs without the
states' acquire, transition, or operation locks. A shared release flight orders
new same-identity operations; unrelated identities keep progressing. The epoch
reader still pins the old transport and capabilities. Release waits for
application only. Applied records detach from the read/attribute overlay but
remain charged until durability or loss, including across a fresh grant;
retirement of an older truncate cannot damage a successor's overlay.

`CloseBatch` is additive (request 74, response 68), Linux DATA-only, and requires
`batched-close-v1` at Activate. One replay slot retains up to 128 ordered outcomes.
The ingress grammar and handler bound both lists. Each result states whether its
handle was retired even if descriptor cleanup reported an error. A validated
handle is closed and untracked even when explicit flock cleanup fails; exact
replay never closes twice. Unknown/malformed cleanup outcomes revoke the mount
so terminal session cleanup retains ownership of unresolved descriptors.

Definite release refusal preserves the grant and reopens its unchanged
admission generation. Uncertain release closes delegation admission, detaches
the applied overlay, and retains durability obligations. A coherence rejection
records loss. A valid atomic release finalizes every local grant even if one
local detach invariant fails. Flights wake only after these decisions. Cancel
cannot reopen a detached generation.

The unit proof closes 128 dirty handles in one release and one close RPC while
Barrier is blocked and verifies all 128 records remain retained. Tests also
cover free per-state locks during RPC, same-identity join ordering, unrelated
progress, definite/uncertain/malformed release outcomes, multi-grant detach
failure, consumed-close errors, unlock failure, replay mismatch, malformed
result semantics, canonical tags, and maximum frame sizes. Validation and
mounted measurement results follow after the running checks.

All unprivileged fusev3 and authorityrpc tests pass in Docker
(`/tmp/cv2-g2-close-fuse-suite.log`, `/tmp/cv2-g2-close-authority-suite.log`);
the frontend device probe is excluded and mounted tests self-skip in that unit
run. The final outcome table and Authority close tests pass in
`/tmp/cv2-g2-close-outcomes6.log` and `/tmp/cv2-g2-close-authority3.log`.
Writeback passes with the race detector
(`/tmp/cv2-g2-release-writeback-final.log`). Reintroducing the pre-release Fsync
makes the blocked-durability test fail with its deadline
(`/tmp/cv2-g2-close-durability-fault.log`).

A 10-millisecond collection window completed the mounted 1,000-file test in
1.08 seconds but produced 69 batches, exceeding its new amortization target.
The final bounded 25-millisecond window passes twice: 0.69/0.64 seconds,
19/16 CloseBatch calls, two Barriers, and zero serial CLOSE, FLUSH, ChangeAck,
or additional control polls. Concurrent truncating opens and the cold
1,000-entry PLUS listing also pass twice
(`/tmp/cv2-g2-close-mounted2.log`). That selected wrapper exits 70 because the
other required tests were omitted. No full-gate claim is made here.

### Part 2 item 0c: new-name absence from complete directories

A successful MKDIR can establish an empty-directory proof at its physical reply.
The daemon preserves that proof across its own CREATE/MKDIR only when the exact
new positive binding also settles. Every extant member must remain in
`cachedNames`; losing a member or discovering an untracked member invalidates
completeness. Other local namespace mutations conservatively invalidate the
proof through their source enumeration gate. Peer namespace/enumeration changes,
cold subscription, teardown, and directory collection remove it as well.

The proof consumes one name-capacity unit. Enumeration reservations make both
new-child and preserved-parent candidates revocable before physical settlement.
The existing source gate prevents serving an intermediate parent state. A new
name absent from a complete directory returns a zero-validity negative reply
locally, with both name and enumeration coordinates retained until physical
write. The hit allocates nothing and issues no Authority RPC.

Tests cover physical success/failure, zero allocations/RPCs, withdrawal waiting
for an inferred absence reply, CREATE preservation, revoked candidates, peer
and cold withdrawal, generic source mutation, capacity refusal, and member
loss. All unprivileged fusev3 tests pass in Docker, with the device-only probe
excluded and mounted tests self-skipping (`/tmp/cv2-g2-complete-suite.log`).
Disabling completeness publication makes the physical-settlement regression
fail (`/tmp/cv2-g2-complete-fault.log`). The required mounted new-directory test
creates 1,000 names with zero LOOKUP RPCs in two runs. The existing root-directory
amortization test also passes twice (`/tmp/cv2-g2-complete-mounted.log`); its
filtered wrapper exits 70 for omitted inventory. Directory completeness learned
from arbitrary READDIR snapshots is not implemented; preexisting unknown
directories retain the ordinary lookup path.

Independent read-only review found no false-absence or unbounded-bookkeeping
path. The new-child regression also finalizes the MKDIR reply and proves its
enumeration withdrawal waits for the physical write before refusing the proof
(`/tmp/cv2-g2-complete-final.log`).

#### G2 intermediate baseline after items 0–4

All baseline workloads at `7ca2d25` pass (182.20 seconds); focused wrapper
exit 70 reflects omitted full-gate tests. The 40,000-file install measures
34.665 seconds / 2.001024 requests per operation with one worker, and
15.409 seconds / 1.975619 with eight. One worker has zero LOOKUP, FLUSH,
change ACK and additional control poll RPCs. Full opcode tables, direct-XFS
controls, Git results, peer results and the preceding direct-XFS ENOSPC
attempt are recorded in results.md. No full-gate claim is made.

#### G2 Part 2 item 5: reader-aware own-write invalidation

Buffered WRITE now uses its pinned raw inode directly, eliminating the global
inode lookup, hook mutex and cloned identity from every accepted write. An inode
that has never published KEEP_CACHE takes an atomic check and issues no notify;
the new 100-write test proves zero notifications and zero invalidation-path
allocations. The buffer still owns a copy of accepted user data.

Live cached descriptions are counted through their last in-flight READ. With a
live reader, WRITE drains its range before returning: deferring this to a timer
would permit a later kernel-only read to serve an old folio. Closed descriptions
can leave resident pages, so the inode retains a merged dirty interval. A
background identity flush cycle drains that interval once, and every future
cached OPEN drains before registering its physical publication. The latter is
the correctness boundary across implicit local delegation release; the flush
observer is amortization only because admission may race ahead of raw WRITE's
range registration. Same-inode source publication serializes live-reader writes,
so they cannot safely coalesce across successful syscall replies without a
separate protocol change. Unpublished-handle drain failures discharge handles,
pins and CREATE/TMPFILE lookups before revoking the mount.

Validation: focused unit tests cover no-reader skips, merged ranges, concurrent
notify/writer ordering, in-flight-close counts and OPEN failure cleanup. Restoring
the old unconditional invalidation fails the 100-write regression
(`/tmp/cv2-g2-own-cache-fault.log`). The full unprivileged FUSE suite passes, as
does `go -C vcs test -race ./internal/writeback`. The new required mounted
`TestSameMountWritesInvalidateLiveAndReopenedCachedReaders` passes three times
(0.12/0.13/0.12 seconds), including retained live reads and close/write/local
release/reopen. Focused wrapper exit 70 is expected for omitted gate inventory.
Logs: `/tmp/cv2-g2-own-cache-suite.log`, `own-cache-final.log`,
`own-cache-writeback.log`, `own-cache-mounted.log` (same `/tmp/cv2-g2-` prefix).

#### G2 Part 2 item 6: target namespace waits by admitted cache facts

The coordinator records separate directory, attribute and data footprints per
exact subscription token. Reads register under their final storage dependency
turn; mutation source gates and authoritative post-state register atomically
with commit publication, including unchanged existing-name CREATE and MKDIR's
new empty-directory proof. Plain READDIR also admits its attribute-bearing
entries. A commit snapshots only subscribers that could hold affected facts;
broadcast delivery remains unchanged. The wait checks exact tokens through ACK,
proven cold replacement or horizon, never treating a merely fenced session as
withdrawn. Delegation grant/recall retains its existing global withdrawal proof.

Footprints are conservative sets since the cold watermark, bounded at 65,536
identities per scope. Overflow targets all coordinates in that scope until cold
reset; no LRU eviction and no unsafe inference from current open-handle counts.
Cached handles carry their refill obligation through cold Subscribe, while
server-owned close accounting now follows the session across that race. Root
Activate attributes are not a subscription cache fact: raw starts with empty
attribute caches and the first GETATTR samples the Authority. CACHELESS_READER
records no footprint.

Review found a cold mutation race: an old request can apply storage after its
last token check but lose to Subscribe before commit publication. Source ownership
now uses the exact token; that old response is a coherence-class uncertain
refusal with no cache-bearing body, never a false definite-no-change result.
Exact replay preserves it without applying storage twice. A cold boundary after
commit is covered by the existing physical publication stamp/reservation fence.

Validation: coordinator race suite passes; full Authority unit suite passes;
handler admission tests cover negative/positive LOOKUP, READ, GETATTR, plain/PLUS
READDIR, cacheless reads, unchanged CREATE, MKDIR completeness and cold read/
mutation races. Frontend tests prove the first root GETATTR fetches fresh data.
Forcing all subscribers into the target set fails the unrelated-cache regression
(`/tmp/cv2-g2-footprint-fault.log`). The required mounted partition test passes:
unrelated subscriber CONTROL loss permits MKDIR in 416.794 us; cached-parent and
new-directory-completeness arms remain blocked until the peer heals. Total test
0.26 seconds; focused wrapper exit 70 names omitted full-gate inventory. Logs:
`/tmp/cv2-g2-footprint-mounted.log`, `footprint-rpc-final.log`,
`footprint-admissions3.log`, `footprint-fuse.log`, `footprint-race3.log`
(the latter names use the same `/tmp/cv2-g2-` prefix).

#### G2 gate follow-up: epoch fixture handle registration

The first full XFS gate after item 6 stopped in the epoch-recovery unit fixture:
it inserted a buffered handle directly into `raw.handles`, bypassing item 5's
reader/pin accounting. The fixture now uses `addHandle` for its file and root
directory descriptions. The production underflow invariant stays intact and all
epoch/loss/stale-handle assertions remain. The full unprivileged FUSE suite
passes (`/tmp/cv2-g2-epoch-registration.log`); the original gate failure is
retained in `/tmp/cv2-g2-after-item6-xfs.log`. The full gate is being rerun.

#### G2 gate follow-up: application-only handoff

The full XFS gate reached the repeated-open/peer-write regression and failed
its unchanged 20-second limit: 96 rounds took 99.89 seconds. The one-second
fallback durability cadence exposed two older visibility paths that waited on
`Buffer.Fsync`: recall and synchronous range/truncating-open dispatch. Recall
now flushes to application, detaches the old overlay and acknowledges that
applied ticket. Synchronous dispatch uses the same detach, then installs the
successor buffer-generation binding and resumes admission under its operation
lock. Applied records remain charged until their durable prefix arrives.
`client.md` now matches the wire contract: recall ACK does not assert durability.

A blocked-durability regression fails the former recall path after 100 ms with
no ACK and a false loss (`/tmp/cv2-g2-recall-fault.log`). Tests now prove both
handoffs complete while durability is blocked, retain bytes and loss accounting,
read the Authority after detach, and flush a successor through the preserved
grant. CREATE-truncate still checks write-before-create ordering, authoritative
post-size and no stale overlay; its obsolete requirement for an intervening
Barrier is replaced by an explicit retained-obligation assertion. Release
outcome fixtures withhold the background durability prefix so their retained
record assertions cannot race legitimate retirement.

The recall-only intermediate still took 100.49 seconds, identifying synchronous
dispatch as the mounted regression's remaining cause. With both paths fixed,
the exact mounted test passes twice in 0.33 and 0.35 seconds
(`/tmp/cv2-g2-recall-mounted2.log`). The focused wrapper exits 70 for omitted
inventory; this is not a full gate result.

Final validation for this follow-up: the full unprivileged FUSE suite passes
(`/tmp/cv2-g2-recall-fullunit3.log`) and the writeback race suite passes
(`/tmp/cv2-g2-recall-writeback.log`). Privileged-only tests are left to the full
Docker gate.

#### G2 Part 2 item 7a: bound all-identity flush fan-out

`FlushAll` now uses at most 16 workers by default, configurable through the
internal `MaxFlushIdentities` option. Each worker retains the existing per-file
serialization and visits the remaining cut even after another identity fails.
Explicit identity flushes used by recall and fsync remain independently
admissible. A 100-identity test checks exact peak concurrency at limits 1, 2 and
4, all-target completion after a refusal, and explicit flush progress while
all workers are parked. Restoring the former one-goroutine-per-identity loop
fails that test (`/tmp/cv2-g2-flush-pool-fault.log`); the writeback race suite
passes (`/tmp/cv2-g2-flush-pool-root.log`). Four-chunk per-file dispatch and
retained-record scatter transmission are the remaining portions of item 7.
