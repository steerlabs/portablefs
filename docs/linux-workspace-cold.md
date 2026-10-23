# Linux workspace cold lifecycle

The protected-path driver runs the stock Linux frontend under UID/GID 1000.
It supplies the shared TLS clock reader, exact serving/recovery permit, session
dispatch fence and outcome persistence owner. Authority protocol 8 and ordinary
mount dispatch remain unchanged. Supported release remains unqualified.

## Suspension ownership

Close precedes the lifecycle call. The transition takes ownership of the
subscription runner before deactivation, joins initial/cold Subscribe and
subscription renewal, and parks the same enrollment renewer and KeepAlive
attempt. The ownership handoff captures the old buffer, incarnation and the
earlier of the supplied continuous-clock deadline and cacheUntil before any
blocking join. It freezes renewal installation at that boundary. Closing serving
keeps the old CONTROL capability until this fixed deadline; it cannot renew that
capability. No shutdown budget extends the cut. KeepAlive retains its park
cancellation disposition through result classification and terminal policy.

FenceAdmissions wakes capacity waiters. The callback fence joins their history
cleanup, then releases before the fixed physical-reply cohort joins. Raw cache
withdrawal retains its notification inventory through failure. A blocked
notification retains its join after the waiter times out; it cannot certify
coldness. SuspendCut drains the captured accepted cut and releases the captured
grants under the original horizon. An elapsed or incomplete drain never gains a
new deadline: withdrawal and epoch fencing account for its unprovable tail,
then permit a cold acknowledgment. Recover can finish that retained cut before
using its fresh token to subscribe. The old CONTROL runner can still process
recalls and changes and acknowledge them; stopping its poller captures a finite
sequence, which must finish before its remaining workers stop.

The dispatch fence refuses cold proof until applying mutation owners settle.
Transport cancellation does not discharge a session-owned submitted write.
Parked non-applying requests retain their exact body, replay slot and sequence;
response readers may observe a result while dispatch and reconnect are parked.
Parking does not cancel the CLOSE_BATCH or visibility owner or take its
unknown-close failure path. Logical owners retain their exact requests through
transient reconnect failures; parked waiting consumes no network-attempt budget.
A readiness refusal blocks before request submission and cannot break a healthy
transport. Managed callbacks, nested operations and deferred cleanup retain
cancelable logical contexts; their network budgets begin at dispatch admission.
Initial bootstrap also waits on the startup fence before its network budget
starts. Callback settlement never acquires the lifecycle lane.

| Owner | Cold disposition |
| --- | --- |
| Admitted callbacks and physical replies | Settled, including consumption and purge |
| Subscription supervisor, initial/cold Subscribe | Parked; attempts and installation joined |
| CONTROL poll/change/recall/ack | Settled through the captured sequence |
| Subscription renewal and horizon | Parked; late renewal cannot install |
| KeepAlive and enrollment | Parked; retain the same renewal object and pending grant |
| Writeback scheduler/pool and explicit flush waves | Settled; an unresolved application refuses cold |
| Empty successor scheduler | Parked until fresh preparation |
| Background durability and visibility | Parked with the old buffer/request binding, or already settled |
| Deferred CLOSE producers, consumer and retries | Parked with counted descriptor ownership and exact assigned requests |
| RECLAIM producers/lanes and local collector | Parked authority dispatch; local collection may finish bookkeeping |
| Assigned foreground mutations/replay | Settled; never relabeled cleanup |
| DATA/CONTROL readers and terminal receipts | Passive observation or exact teardown only |
| Reconnect/replay dispatch | Parked; attempts already dispatching must join |
| FUSE/session/epoch/owner/control watchers | Refusal, observation or exact teardown only |
| Spawned terminal withdrawal/close work | No healthy cold proof after terminalization |

Partial barrier/release outcomes remain observed even when a later phase fails.
Unknown release authority is abandoned, never reported as released. Accounted
abandonment belongs to the current interval and appears in its outcome; it does
not by itself refuse coldness. A new cold Subscribe starts a fresh interval.
Independent failures remain unresolved. A bounded waiter never substitutes for
a worker's completion; retained notification and callback joins use their own
mount context. Kernel machine-local caches keep their ordinary local
semantics; this proof withdraws authority-derived cache authority.

## Preparation and recovery

Both operations keep one logical owner through classified transport/DNS failures,
with bounded network attempts and capped backoff. Publication belongs to that
same job: a proof aged during persistence withdraws and subscribes again, while
clock unreadiness waits for correction. The job persists the defeated
candidate's refusal before retrying. There is no outer 45-second
recovery deadline. The local control job owns acceptance, observation and token
consumption. A socket attempt cannot repeat Attach or logical Recover.
Initial attachment retains its connection-set/Attach identity and explicit
ownership disposition across retry. Recovery validates the existing session and
authorization through real traffic, then installs a fresh cold subscription with
fresh anchors. An expired/reset subscription attempt withdraws again and retries
from an empty cursor inside the same pending job. This includes an aged first
page, pagination horizon, or withdrawal lead. Structural refusal remains a
failure. Epoch change, authenticated refusal, protocol defects and independent
local failure end recovery. Protocol 8 already defines errno and session_terminal;
Resume uses the same existing refusal for foreign/unbound credentials and
unknown or ended sessions, without querying the unowned target's state. A
bound Resume authenticates its credential before the runtime chooses a state
or renews a lease. Real lease expiry therefore ends recovery with
ErrSessionEnded, including on ordinary mounts. The refusal does not fence a
foreign target. The wire and schema remain unchanged.

Cold state lasts until Prepared actually publishes. An interrupted Prepare or
Recover re-parks every owner it resumed. A later Suspend re-acknowledges the
retained cut when no callback has served since that cut, without draining again
or consulting the old horizon. Entry admission and this decision share the raw
registry lock. Each park deactivates the subscription, stops writeback and
captures current cleanup debt and exact retained requests; recovery retains the
prior inventory until final publication. A persistence failure also retains the physical
cut for a later acknowledgment. Cold POSIX FLUSH returns EAGAIN promptly while
keeping the tracked unlock obligation for session-owned RELEASE cleanup; a
closed serving gate whose dispatch still runs keeps its existing cleanup path.
Known loss still wins the FLUSH result.

A serving managed driver must close admission and Park the renewer before its
safe cutoff. Resume is not a way to clear a latched terminal cutoff. Park joins
installation and its policy disposition; an unknown installer result keeps the
same sequence and exact grant for reconciliation. The driver must provide
current clock/permit checks to dispatch and the installer itself. The supervisor
remains outside renewal ownership.

## Retained evidence

Every transition completion returns cumulative loss and outcome evidence, even
when it fails or loses its generation. Prepare and Recover return an explicit
Completed, Overtaken or Failed result for the local owner. Cancellation-only
completion may be Overtaken. The local owner records overtaking separately
from the diagnostic, so an obsolete permit cannot turn a known newer Close into
a failed incarnation. Any independent cause, including a cause joined
with transport loss or cancellation, remains Failed and sets the owner's
incarnation terminal latch. Drop tickets identify accepted entries
and bytes; a repeated reset cannot create another loss for the same discarded
records. Recording the in-memory fact performs no inventory fsync or RPC under
buffer/index/state locks. Persistence precedes cold acknowledgment and the
publication of a new prepared serving interval. The bounded final loss aggregate
is valid evidence; a codec refusal remains an error and cannot erase the ledger.
Cleanup debt counts deferred descriptions and outstanding reclaim tokens once,
including tokens already dequeued by a lane. Request dispositions enumerate
retained exact owners; passive services retain session ownership behind the
joined dispatch fence. The empty successor is checked for retained entries.
Publication checks run before persistence and again after it. If persistence
outlives a proof, the owner persists the refusal before returning it.

A new interval persists unresolved/unobserved while retaining earlier known
loss. The workspace outcome inventory uses a synced temporary file, atomic
rename and directory sync. Persistence failure refuses acknowledgment. A crash
cannot reconstruct volatile accepted-byte counts: its retained run stays
unresolved/unobserved through replacement. No second write journal exists.
Affected file descriptions and old root barriers retain their errors across
same-session recovery. Resolved retired epochs release their arenas and the
accepted-cut references held by descriptions.

The required privileged inventory includes a frontend pause falsification on
real kernel FUSE and XFS: a held frontend clock/CONTROL stream allows stale
successful metadata after a causally completed peer write in the unfenced
negative control; cold withdrawal plus closed-until-fresh-recovery prevents it.
This controlled frontend schedule does not qualify VZ resume ordering or real
host sleep. The native workspace inventory requires real managed Mount/Umount outcomes,
peer coherence and exact replacement. Its unprovisioned-job case retains the
actual handler failure.

## One drain deadline

The paired dispatcher closes admission and cancels desired jobs before starting
independent fixed-roster drains in parallel. The first guest frame byte anchors
one deadline from the host's remaining allowance. Framing and dispatcher waits,
old-job joins, mount lanes and local Suspend all consume it. The supervisor
preserves the deadline in the context passed to Mount.Suspend. The root adapter
forwards only its remainder at the local send boundary, then observes the local
job through actual settlement even if the caller deadline expires. There
is no new outer deadline for Prepare or Recover.

Failed or elapsed drains cancel sibling waiters, retain physical owners and
discard the suspension. A cancellation request cannot certify a notification
join. Cold acknowledgement requires every desired job to join and the entire
registered roster to prove withdrawal, in canonical order. The host separately
checks its original continuous deadline, an idle control FIFO and successful
pause completion; late callbacks cannot recreate eligibility.

The guest TLS clock owner invalidates its shared result at suspension and starts
a new correction after accepted Resume. Each mount binds that generation to its
exact close serial, including at low-level authority and Manager TLS dispatch.
A delayed or failed measurement denies freshness synchronously; correction does
not restore latched serving permission. The root driver observes WorkspaceRecoveryRequired with its exact generation
and close serial; a delayed old observation cannot close a new serving interval. RTC is not an admission clock, and its source UTC allocation
remains conditional on exact-image qualification.
