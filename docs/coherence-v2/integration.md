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
