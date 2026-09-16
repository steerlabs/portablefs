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

Gateway reader admission, ticket/replay retention, the v7 matrix conversion,
v6 engine deletion, the 20,000-file git-add regression, baseline profiling and
measurements, public documentation, and the full local gate remain outstanding.
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
