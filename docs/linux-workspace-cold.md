# Linux workspace cold lifecycle

Managed launch remains unavailable. The private lifecycle engine requires a real
clock owner, an exact serving/recovery permit, the session's dispatch fence and
an outcome persistence owner. Provisioning, protected-path bootstrap and the
root driver are separate dependencies; no ready implementation substitutes for
them. Authority protocol 8 and ordinary mount dispatch remain unchanged.

## Suspension ownership

Close precedes the lifecycle call. The transition takes ownership of the
subscription runner before deactivation, joins initial/cold Subscribe and
subscription renewal, and parks the same enrollment renewer and KeepAlive
attempt. It captures the old buffer, incarnation and the earlier of the supplied
continuous-clock deadline and cacheUntil. No shutdown budget extends that cut.

FenceAdmissions wakes capacity waiters. The callback fence joins their history
cleanup, then releases before the fixed physical-reply cohort joins. Raw cache
withdrawal retains its notification inventory through failure. A blocked
notification retains its join after the waiter times out; it cannot certify
coldness. SuspendCut drains the captured accepted cut and releases the captured
grants under the original horizon. The old CONTROL runner can still process
recalls and changes and acknowledge them; stopping its poller captures a finite
sequence, which must finish before its remaining workers stop.

The dispatch fence refuses cold proof until applying mutation owners settle.
Transport cancellation does not discharge a session-owned submitted write.
Parked non-applying requests retain their exact body, replay slot and sequence;
response readers may observe a result while dispatch and reconnect are parked.
Parking does not cancel the CLOSE_BATCH owner or take its unknown-close failure
path. Callback settlement never acquires the lifecycle lane.

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
Unknown release authority is abandoned, never reported as released; it refuses a
healthy cold proof. A failed condition remains unresolved. A bounded waiter never substitutes for a
worker's completion. Kernel machine-local caches keep their ordinary local
semantics; this proof withdraws authority-derived cache authority.

## Preparation and recovery

Both operations keep one logical owner through classified transport/DNS failures,
with bounded network attempts and capped backoff. There is no outer 45-second
recovery deadline. The local control job owns acceptance, observation and token
consumption. A socket attempt cannot repeat Attach or logical Recover.
Initial attachment retains its connection-set/Attach identity and explicit
ownership disposition across retry. Recovery validates the existing session and
authorization through real traffic, then installs a fresh cold subscription with
fresh anchors. Epoch change, authenticated refusal, protocol defects and genuine
local failure end recovery. Offline time alone proves none of those outcomes.

A serving managed driver must close admission and Park the renewer before its
safe cutoff. Resume is not a way to clear a latched terminal cutoff. Park joins
installation and its policy disposition; an unknown installer result keeps the
same sequence and exact grant for reconciliation. The driver must provide
current clock/permit checks to dispatch and the installer itself. The supervisor
remains outside renewal ownership.

## Retained evidence

Every transition completion returns cumulative loss and outcome evidence, even
when it fails or loses its generation. Drop tickets identify accepted entries
and bytes; a repeated reset cannot create another loss for the same discarded
records. Recording the in-memory fact performs no inventory fsync or RPC under
buffer/index/state locks. Persistence precedes cold acknowledgment and the
publication of a new prepared serving interval.

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
host sleep. The native workspace inventory remains unchanged.
