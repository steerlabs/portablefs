# Linux workspace local control

This exact paired format 8 is unreleased. It changes with its root supervisor
and child daemon together; authority protocol 8 and host/guest protobuf control
remain unchanged. The real root driver supplies the sealed gate, protected kernel
bootstrap and shared clock owners to its UID/GID 1000 child.

## Requests and correlation

One write-half-closed abstract Unix socket carries one strict JSON request and
one response. The existing ordinary renewal/loss grammar remains separate.
Workspace input and output each fit 64 KiB. Reject unknown or duplicate keys,
null values, noncanonical decimals, unequal versions and trailing JSON.

Each request binds `mountInstanceId` and `workspace` fields `version=8`,
`requestId`, `operationId`, `bootId`, `hostServiceId`, `guestServiceId`,
`generation`, `gateSerial` and `budgetNanos`. IDs and durations use canonical
uint64 decimal strings; request/operation IDs are positive and never wrap.
`budgetNanos` is positive and at most 45000000000. The root serializes starts
and chooses strictly increasing operation IDs, with `operationId=requestId`.
Other request IDs only correlate socket attempts.

| Operation | Additional exact body | Acknowledgment |
| --- | --- | --- |
| `workspace-prepare` | None | `accepted` |
| `workspace-recover` | `hostRequestId`, canonical unpadded base64url ResumeToken in `transaction` | `accepted` |
| `workspace-suspend` | `hostRequestId`, canonical unpadded base64url Suspension in `transaction`, positive decimal `drainBudgetNanos` at most 15000000000 | `accepted` |
| `workspace-cleanup` | `phase` with voluntary/terminal mode and exact witness | `accepted` |
| `workspace-install-kernel` | Exact offered `phase`, including options, action ID and witness; two ordered rights | `accepted` |
| `workspace-unmount-complete` | Exact removal `phase` plus `removal.kernelAbsent=true`; terminal also requires `abortCompleted=true` | `unmount-recorded` |
| `workspace-observe` | None | Current snapshot |

A current legal Suspend invalidates admission and cancels its predecessor
before checking the receipt-relative drain deadline. A spent drain therefore
refuses the start after cancellation, possibly leaving that predecessor failed.
The root escalates to Cleanup; refusal does not prove completed withdrawal.

Transactions retain the paired canonical protobuf scanner and full fixed
roster. Their boot/services/generation must equal the local binding. Only
Suspend carries the drain allowance; that allowance and the socket budget sit
outside immutable start identity. Compact response bindings omit transaction,
host request, phase and drain allowance.

## Acceptance and finite ownership

The current job retains one immutable semantic start until a legal next job
replaces it. Equal operation ID and content acknowledge the same acceptance;
changed content refuses and closes admission. Older operations refuse retired.
A larger number alone grants no transition. Prepare is single-use, including
failure or cancellation. Recover requires cold state, a current permit and an
unconsumed exact Resume authorization with advancing generation. Before
consuming the token, its complete canonical Suspension, including nonce and
fixed roster, must equal the Suspension retained by the exact cold job.

Under the owner lock, acceptance reserves a job or consumes an offered action.
Only then does the owner dispatch work on its lifecycle context. No handler,
network operation, INIT, join, descriptor close or response write holds that
lock. Install follows offered to running to complete/failed. Failure retains
resources and partial witness for cleanup; it cannot offer the action again.

The Mount driver's `Run` returns an explicit `LifecycleResult`: Completed
requires successful publication and no error; Failed includes every independent
failure, including one joined with cancellation. Overtaken asserts that this
job ended only because its generation lost admission, with no independent
failure during work or teardown. Its error is diagnostic and may omit the
cancellation chain. The owner exempts Overtaken from the incarnation terminal
latch only when it recorded cancelling that exact job, through a legal Close,
owner shutdown or rejected prepared publication. A context error alone grants
no exemption. Missing/unknown dispositions fail closed. The owner cancels the
context when prepared publication loses its permit, so the driver can join;
it must return Overtaken only after establishing no independent failure.

A failed Prepare/Recover ends serving preparation for this incarnation, even
if a concurrent Close also cancels it. Later Suspend preserves the terminal
fact and exact Cleanup remains available. A new serving start then refuses
`incarnation-terminal`; malformed input still refuses `invalid`.

The mount has one install slot and one removal lifecycle, represented by fixed
voluntary and terminal slots. Each mode has at most one action identity, so an
incarnation has at most three identities. Terminal escalation waits for the
old worker/root action to join and retires its voluntary offer. Successful
removal is irreversible. Suspend/Cleanup invalidate admission and cancel old
work before waiting; occupied means the caller must retry that same start
after the old owner joins. Socket disappearance never replaces a worker. An
ended Prepare changes its unaccepted install offer to failed/stopped; it
retains that action as evidence and cannot invite another handoff. Publish and
Offer require a running job.

`AdmitFrame` invalidates daemon admission exactly once for every fully framed,
authenticated Suspend/Cleanup, including an equal retry, retired operation or
foreign binding, before lane, hangup or budget exits. This is a local safety
action; it never accepts, cancels, replaces or erases a job by itself and
writes no supervisor memfd. A valid Close may additionally cancel the current
worker only as a legal successor: matching mount, boot and both service
identities; strictly higher operation ID; generation and gate serial no older
than the current job; current closed permit; and a legal lifecycle transition.
Suspend cannot succeed Cleanup. Voluntary Cleanup cannot interrupt terminal
Cleanup; terminal escalation may interrupt voluntary Cleanup.
Retired/foreign/changed same-ID frames never cancel accepted work. The old
worker remains owned until it joins; the new start then revalidates
acceptance.

Malformed authenticated write-half-closed input invalidates admission as well.
Receive-level body bounds, excess rights and ancillary truncation are proven
grammar failures and invalidate even if the peer subsequently disconnects.
Incomplete full socket loss, reset and timeout alone prove no frame and do not
invalidate. Every Receive error disposes of all received rights; the kernel
closes rights truncated from the ancillary buffer. Configuration, including
callbacks, precedes listener publication.

## Observation

Commands acknowledge acceptance only. A snapshot uses one of `preparing`,
`kernel-required`, `pending-recovery`, `pending-suspend`, `prepared`,
`recovery-required`, `cold`,
`unmount-required`, `cleanup-finalized` or `failed`. Only prepared carries the
exact validated session, subscription and renewal readiness proof.

Every snapshot contains `phases.install`, `phases.voluntaryRemoval` and
`phases.terminalRemoval`. Each has `progress`: absent, offered, running,
complete or failed. Absent has no action. Other states retain a compact action
with `actionId` and its mode/options/reason/removal evidence. All slots bind to
the snapshot's single mount `witness`; its already-bound fields cannot change.
This avoids repeating long witnesses alongside a full loss ledger. Failed
slots carry one finite `failure`: handler-failed, stopped or deadline. Reason
and option limits remain 256 bytes; a witness totals at most 512 bytes. The
maximum fixed-slot/loss fixture fits the existing frame bound.

Snapshots retain cumulative Loss, immutable acquired witness and cleanup debt
through job changes. Durability/observation/release describe the current
serving interval. Successful prepared publication starts a new
unresolved/unobserved interval while preserving Loss and debt; failed or
overtaken preparation does not claim a new interval. Valid cumulative Loss
merges independently of any conflicting disposition or other invalid
publication field. Install complete does not imply prepared; removal complete
does not imply cleanup-finalized. A late exact removal result updates its slot
even after the job fails, preserving the failed state and reason. It advances
progress only for a live worker waiting in unmount-required. A failed job with
successful removal may accept a legal Cleanup successor for remaining
session/connection cleanup; no successor can repeat successful removal. An
observation beyond the current operation refuses not-accepted, and one before
it refuses retired. Those facts apply at the snapshot instant. Repeated IDs
may return newer snapshots. The owner retains no observations and accepts no
snapshot as an action permit.

After a lost start response, observe before resending the same semantic start.
After lost phase delivery on a live job, offered permits another copy of the
same action; running/complete/failed never permits re-execution. A failed job
retains an unaccepted install action as failed/stopped evidence. The root
preserves monotone ownership facts and rechecks the current permit before
Open, including after a delayed kernel-required observation.

All refusals have `ok=false`, state refused, compact correlation and one code:
unavailable, occupied, retired, invalid, handler-failed, deadline, stopped,
peer-refused, action-consumed, not-accepted or incarnation-terminal. They carry
unresolved/unobserved outcome and no readiness, phase facts or unbounded diagnostic. A refusal never
erases an earlier accepted job.

## Time, rights and death

Socket expiry bounds admission/delivery only. Accepted Prepare/Recover have
bounded network attempts without an outer socket-derived recovery timeout.
Suspend captures the root's shrinking drain remainder from original attempt
receipt, charging framing and admission delay. An already-spent drain deadline
refuses before acceptance and consumes no operation ID. Retries cannot extend
that captured deadline; later observations use independent socket budgets.
Host cold acknowledgment/pause, authorization, renewal and withdrawal
deadlines keep their existing meanings.

Only install receives rights, in FUSE/abort order. Account for all ancillary
input and set close-on-exec at recvmsg. Before acceptance the real driver
validates roles, bootstrap and exact action/options/source/target. Acceptance
atomically moves rights into the job. Every later install refuses
`action-consumed`, closing all new rights, including duplicates and fresh opens
of the same inode. There is no descriptor comparison or retained replay copy.

The root records bootstrap in progress before its single mount syscall and
retains original descriptions and partial effects. Begin owns an outstanding
attempt until Finish settles, including cancellation before the syscall.
BeginRemoval and Finalize refuse occupied while it remains outstanding. The
caller must reobserve absence after it settles; observations from the refused
finalization cannot establish later absence. Finish retains every
nonconflicting acquired witness field before testing handoff completeness,
even on partial descriptor acquisition or owner loss. No effect may appear
behind completed finalization. Unknown delivery permits copies of those
originals, never a second mount. Observed child ownership ends the redundant
root FUSE copy while retaining the original abort description. An install
observation cannot transfer child ownership until the root confirms that its
original rights exist. Failed/stopped denotes an unaccepted offer: it ends
retransmission while the root retains both original descriptions. Exact
finalization requires independent process exit and kernel/source/alias absence. Voluntary EBUSY remains a real error owned by
root removal.

Full socket loss discards an unaccepted request or accepted response waiter.
Actual supervisor death/owner-pipe EOF permanently closes the child and takes
terminal cleanup. Child death leaves root-owned abort and witness evidence.
Neither a new supervisor nor a replacement child resumes vanished in-memory
work; ambiguous inventory blocks replacement until exact cleanup or confirmed
VM termination. Boundary tests cover these transitions with owned descriptions;
the protected-path driver adds actual device/bootstrap tests. Host sleep remains
unqualified.
