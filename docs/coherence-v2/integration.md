# Protocol 7 integration record

Workstream G integrates the handler and Linux client against [wire.md](wire.md).
The starting tree is `aa046b1` on `cv2-integrate`. This record distinguishes
observed results from qualification still outstanding.

## Step 1: real mounts (in progress)

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

## Step 2: directory decision (implemented, not fully qualified)

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

## Outstanding qualification

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
