# Linux workspace local control

This exact paired format 8 is unreleased. It changes with its root supervisor
and child daemon together; authority protocol 8 and host/guest protobuf control
remain unchanged. Real managed handlers remain unavailable until the gate,
protected-path kernel driver and clock owners exist.

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
unconsumed exact Resume authorization with advancing generation.

Under the owner lock, acceptance reserves a job or consumes an offered action.
Only then does the owner dispatch work on its lifecycle context. No handler,
network operation, INIT, join, descriptor close or response write holds that
lock. Install follows offered to running to complete/failed. Failure retains
resources and partial witness for cleanup; it cannot offer the action again.

The mount has one install slot and one removal lifecycle, represented by fixed
voluntary and terminal slots. Each mode has at most one action identity, so an
incarnation has at most three identities. Terminal escalation waits for the old
worker/root action to join and retires its voluntary offer. Successful removal
is irreversible. Suspend/Cleanup invalidate admission and cancel old work
before waiting; occupied means the caller must retry that same start after the
old owner joins. Socket disappearance never replaces a worker.

`AdmitFrame` invalidates admission once for a fully framed authenticated Close,
before lane, hangup or budget exits. It performs no supervisor memfd write.
Malformed half-closed input also invalidates admission; truncated full loss
creates no request. Configuration, including callbacks, precedes listener
publication.

## Observation

Commands acknowledge acceptance only. A snapshot uses one of `preparing`,
`kernel-required`, `pending-recovery`, `pending-suspend`, `prepared`, `cold`,
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

Snapshots retain cumulative Loss, durability, observed disposition and cleanup
debt through job changes. Install complete does not imply prepared; removal
complete does not imply cleanup-finalized. An observation beyond the current
operation refuses not-accepted, and one before it refuses retired. Those facts
apply at the snapshot instant. Repeated IDs may return newer snapshots. The
owner retains no observations and accepts no snapshot as an action permit.

After a lost start response, observe before resending the same semantic start.
After lost phase delivery on a live job, offered permits another copy of the
same action; running/complete/failed never permits re-execution. A failed job
can retain an unaccepted offer as evidence, but cannot accept that handoff. The root preserves monotone
ownership facts and rechecks the current permit before Open, including after a
delayed kernel-required observation.

All refusals have `ok=false`, state refused, compact correlation and one code:
unavailable, occupied, retired, invalid, handler-failed, deadline, stopped,
peer-refused, action-consumed or not-accepted. They carry unresolved/unobserved
outcome and no readiness, phase facts or unbounded diagnostic. A refusal never
erases an earlier accepted job.

## Time, rights and death

Socket expiry bounds admission/delivery only. Accepted Prepare/Recover have
bounded network attempts without an outer socket-derived recovery timeout.
Suspend captures the root's shrinking drain remainder from original attempt
receipt, charging framing and admission delay. Retries cannot extend that
captured deadline; later observations use independent socket budgets. Host
cold acknowledgment/pause, authorization, renewal and withdrawal deadlines keep
their existing meanings.

Only install receives rights, in FUSE/abort order. Account for all ancillary
input and set close-on-exec at recvmsg. Before acceptance the real driver
validates roles, bootstrap and exact action/options/source/target. Acceptance
atomically moves rights into the job. Every later install refuses
`action-consumed`, closing all new rights, including duplicates and fresh opens
of the same inode. There is no descriptor comparison or retained replay copy.

The root records bootstrap in progress before its single mount syscall and
retains original descriptions and partial effects. Unknown delivery permits
copies of those originals, never a second mount. Observed child ownership ends
the redundant root FUSE copy while retaining the original abort description.
Exact finalization requires independent process exit and kernel/source/alias
absence. Voluntary EBUSY remains a real error owned by root removal.

Full socket loss discards an unaccepted request or accepted response waiter.
Actual supervisor death/owner-pipe EOF permanently closes the child and takes
terminal cleanup. Child death leaves root-owned abort and witness evidence.
Neither a new supervisor nor a replacement child resumes vanished in-memory
work; ambiguous inventory blocks replacement until exact cleanup or confirmed
VM termination. Boundary tests cover these transitions with owned descriptions;
this PR does not implement real managed mounts or qualify host sleep.
