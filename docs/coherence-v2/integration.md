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
