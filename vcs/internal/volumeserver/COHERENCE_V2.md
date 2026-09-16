# Authority coordinator integration

Workstream C implements the protocol-7 coordinator as a pure-Go component. It
adds no protocol selection, wire conversion, storage I/O, or background goroutine.
Construct one coordinator per volume and authority epoch. The integration stream
must select this component on the v7 path and remove the old lease path there.

## Decisions and invariants

- The volume log is a bounded ring, defaulting to 65,536 entries. Each subscriber's
  delivered cursor is its outbox. A poll copies a batch into a reusable caller
  buffer. Holder events occupy the same positions as changes; other sessions see
  `StreamAdvance` at those positions. An ack cannot exceed delivered position.
- Cumulative withdrawal and holder-cut acknowledgments are separate proofs. A
  holder can receive and acknowledge a recall behind an unacknowledged change.
  Poll advances independently of cumulative ack and can replay unacknowledged
  batches. Clients must service holder events even while a prior withdrawal waits
  for pending replies. Replay the exact applied-cut ack through the runtime's
  existing mutation replay slots; a completed recall removes its live record.
- Indexed heaps maintain minimum acknowledged position and horizon. Append is
  O(1); ack is O(log subscribers), plus amortized log reclamation. Lookup is O(1).
  Expiring a session necessarily visits that session's delegations. Cold subscribe
  necessarily copies the current delegated identity set. There is no per-entry
  allocation in append/deliver/ack with a reused delivery buffer.
- Ring overrun fences a lagging subscriber on its next request and refuses renewal.
  Its old withdrawal obligation remains until its horizon or a cold resubscribe.
  Overrun never shortens cache permission. Fenced session tombstones retain the
  incarnation and loss state until the runtime calls `ForgetSession`.
- TTL is 10 seconds, renew interval 3 seconds, recall/break budget 5 seconds.
  All deadlines use `CoherenceClock`. The clock is injectable; tests advance time
  explicitly. The runtime should call `Sweep` for idle cleanup. Every ordinary
  admission also processes expired horizons.
- Subscription fencing is recoverable. Do not use the historical permanent
  `Authority.FenceSession` for a subscription horizon. `Subscribe` requires the
  authenticated client to have invalidated all caches and abandoned its old
  delegated buffer. Its new incarnation cannot acknowledge old obligations.
- Cache-capable open descriptions survive page invalidation. Their counts remain
  across subscription expiry and cold resubscription, conservatively keeping
  peer delegations in writethrough mode. Close them through the new incarnation.
  Permanent runtime termination may clear the counts because its handles cannot
  be used again. `ForgetSession` also requires permanent handle retirement.
- A reservation closes new cache-capable opens immediately. An open while a
  reservation, active delegation, or pinned retired record exists is direct-IO,
  including a new handle on the holder. Existing holder handles do not force
  writethrough; existing peer handles do. Closing the last peer handle upgrades
  an active delegation through the holder's outbox. A recalling generation never
  receives an upgrade event.
- A volume-global id/generation counter increases on every grant reservation.
  No counter is retained for a deleted identity. Releases validate their entire
  batch before changing state. Failed generations and missed cuts advance the
  holder's loss counter and enqueue a loss event. Cold snapshots retain that loss.
- Delegation request turns use a separate instance of the existing mutation
  sequencer, with its exact identity keys and FIFO conflict ordering. Flushes and
  CONTROL acks never acquire these turns. Once a cut is dispatched, cancellation
  waits for its ack or budget instead of dropping a healthy holder's buffer.
  No coordinator mutex covers I/O or a wait. Do not nest independently acquired data guards for multiple identities.
- A read admitted during reservation uses a reader pin instead of waiting behind
  the grant. This breaks the cycle in which a client withdrawal needs a pending
  read reply to drain. After withdrawal, the grant closes new reader admission
  and drains existing pins. Observing the reservation and enqueueing a read are
  atomic with respect to each other.
- A flush pin binds storage application to the exact id/generation. Timeout can
  revoke subsequent flushes immediately, but reassignment and the release entry
  wait for admitted storage application to finish. A stuck local storage syscall
  can therefore outlast the peer recall budget; the coordinator does not pretend
  it can interrupt storage safely. Break acknowledgments name an applied cut between the event's applied floor
  and the applied high-water recorded by `DelegationFlush.End`. Later flushes
  may still be applying. Recall additionally requires all active pins drained.

## Handler and sequencer hooks

`coherence_hooks.go` defines `CoherenceCommitHooks`, `CoherenceDurabilityHooks`,
and `CoherenceSessionHooks`; the coordinator implements all three.

1. Authenticate with the runtime, then call `CheckSession` on every subscribed
   request. Map CONTROL to `Poll`, `Ack`, `AckDelegation`, and `Renew`. Keep CONTROL
   and flush-application capacity available while ordinary RPCs are waiting.
2. For existing-file OPEN/CREATE with write intent, or first data mutation, call
   `Reserve` outside storage and commit locks, then `Grant`. `DataMutated` combines
   those two calls. Always finish a returned reservation with `Grant` or `Abort`.
3. New CREATE needs a binding-publication exclusion from the handler/sequencer.
   After storage assigns the new stable identity, call nonblocking `ReserveNew`
   before allowing any peer to resolve or cache the binding. `Store.Create` alone
   already links the inode and is not this exclusion. Publish namespace,
   directory, and attribute changes, release all storage locks, then call `Grant`.
   No existing store or sequencer source is changed in this workstream.
4. `OpenCacheCapable` makes the atomic open-mode decision. A false result requires
   direct-IO. Remember successful accounting on each server handle; undo on open
   failure and call `CloseCacheCapable` once on close. Runtime replay must prevent
   duplicate open/close accounting.
5. Before READ, GETATTR, attribute-bearing LOOKUP/READDIR, FSYNC, or a copy source,
   call `DataConsumed` and release its guard after sampling storage and its
   version. The holder's backing reads bypass self-break because flushing may
   need them. `BreakForRead` is the authenticated non-subscriber/gateway preflight
   form without a retained guard. Multiple-identity operations must preflight
   cuts without nesting guards, then use the handler's atomic complete
   `MutationDependencies` footprint and revalidate resolved bindings. Do not
   request another delegation while retaining an independently acquired guard.
6. For a flush, call `BeginFlush` before entering storage ordering. Inside the
   storage dependency turn: apply, assign the volume version in commit-publication
   order, and call `OnCommit`. Release the storage locks and dependency turn;
   call `DelegationFlush.End(appliedSequence)` (zero on definite no-apply).
7. Publish a separate **applied** receipt to a flushing holder before waiting for
   visibility. The holder's cut ack waits for application, never for visibility.
   Otherwise cross-recalls can wait for one another's withdrawal acknowledgments.
   After any committed mutation, wait on `WaitWithdrawn(position, sourceSession)`
   before acknowledging visibility. Use `context.WithoutCancel(requestContext)`
   after apply so request cancellation cannot discharge a committed obligation.
   Read replies carry the sampled storage version; client publication still
   rejects stale replies and drains exact identities before cumulative ack.
8. The fsync group calls `DurableSequence` only with a contiguous, proven durable
   **volume** cut. Existing per-inode `appliedGeneration` is insufficient. Track
   completed inode generations or establish a volume barrier before publication.
   Include `LatestDurable` in the replies. This component does not implement the
   storage durability proof or the client's directory-handle barrier.
9. Wire `Authority.OnSessionEnd` to `ExpireSession`; retain the old cache horizon.
   Call `ForgetSession` once permanent runtime handle cleanup and that horizon
   have completed. Preserve the macOS compatibility-writer exclusion in the
   handler's cross-profile admission layer.

## Exported API

The existing `SessionID` and `MutationDependencies` types are reused. Every new
exported declaration is listed below; struct fields are the wire adapter's input.

```go
const SubscriptionTTL = 10 * time.Second
const SubscriptionRenewInterval = 3 * time.Second
const DelegationRecallBudget = 5 * time.Second

var ErrSubscription, ErrSubscriptionPosition, ErrCoherenceIdentity error
var ErrDelegationStale, ErrDelegationBusy, ErrDelegationAck error
// Existing ErrSessionFenced and ErrSessionActive are also returned.

type CoherenceClock interface {
    Now() time.Time
    NewTimer(time.Duration) CoherenceTimer
}
type CoherenceTimer interface { C() <-chan time.Time; Stop() bool }
type CoherenceConfig struct { Clock CoherenceClock; MaxLogEntries int }

type ChangeKind uint8
const (NamespaceChanged ChangeKind = iota + 1; AttributesChanged; DataChanged;
       DelegationGranted; DelegationReleased; DirectoryChanged)
type ChangeEntry struct {
    Position, VolumeVersion uint64
    Kind ChangeKind
    Identity, ParentIdentity [16]byte
    Name string
    HasRange bool
    Offset, Length uint64
}
type StreamEventKind uint8
const (StreamChange StreamEventKind = iota + 1; StreamRecall; StreamBreakForRead;
       StreamDelegationMode; StreamLoss; StreamAdvance)
type StreamEvent struct {
    Position uint64
    Kind StreamEventKind
    Target SessionID
    Change ChangeEntry
    Delegation Delegation
    Request, AppliedSequence, LossSequence uint64
    Deadline time.Time
}
type SubscriptionToken struct { Session SessionID; Incarnation uint64 }
type SubscriptionSnapshot struct {
    Token SubscriptionToken
    Position, Watermark, LossSequence uint64
    Horizon time.Time
    Delegated [][16]byte
}
type DelegationMode uint8
const (DelegationFull DelegationMode = iota + 1; DelegationWritethrough)
type DelegationState uint8
const (DelegationReserved DelegationState = iota + 1; DelegationActive; DelegationRecalling)
type Delegation struct {
    ID uint64
    Identity [16]byte
    Holder SessionID
    Generation uint64
    Mode DelegationMode
    State DelegationState
}

type CoherenceCoordinator struct { /* private state */ }
func NewCoherenceCoordinator(CoherenceConfig) *CoherenceCoordinator
func (*CoherenceCoordinator) Subscribe(SessionID) (SubscriptionSnapshot, error)
func (*CoherenceCoordinator) CheckSession(SubscriptionToken) error
func (*CoherenceCoordinator) Renew(SubscriptionToken) (time.Time, error)
func (*CoherenceCoordinator) Poll(context.Context, SubscriptionToken, uint64, []StreamEvent, int) ([]StreamEvent, error)
func (*CoherenceCoordinator) Ack(SubscriptionToken, uint64) error
func (*CoherenceCoordinator) OnCommit([]ChangeEntry) uint64
func (*CoherenceCoordinator) WaitWithdrawn(context.Context, uint64, SessionID) error
func (*CoherenceCoordinator) ExpireSession(SessionID)
func (*CoherenceCoordinator) Sweep()
func (*CoherenceCoordinator) ForgetSession(SessionID) error
func (*CoherenceCoordinator) LossSequence(SessionID) uint64
func (*CoherenceCoordinator) DurableSequence(uint64)
func (*CoherenceCoordinator) LatestDurable() uint64
func (*CoherenceCoordinator) OpenCacheCapable(SubscriptionToken, [16]byte) (bool, error)
func (*CoherenceCoordinator) CloseCacheCapable(SubscriptionToken, [16]byte) error
func (*CoherenceCoordinator) ReserveNew(SubscriptionToken, [16]byte) (*DelegationReservation, error)
func (*CoherenceCoordinator) Reserve(context.Context, SubscriptionToken, [16]byte) (*DelegationReservation, error)
func (*CoherenceCoordinator) DataMutated(context.Context, SubscriptionToken, [16]byte) (Delegation, error)
func (*CoherenceCoordinator) DataConsumed(context.Context, SubscriptionToken, [16]byte) (*DataGuard, error)
func (*CoherenceCoordinator) BreakForRead(context.Context, [16]byte) error
func (*CoherenceCoordinator) Recall(context.Context, [16]byte) error
func (*CoherenceCoordinator) AckDelegation(SubscriptionToken, [16]byte, uint64, uint64, uint64, uint64) error
func (*CoherenceCoordinator) BeginFlush(SubscriptionToken, [16]byte, uint64, uint64) (*DelegationFlush, error)
func (*CoherenceCoordinator) ReleaseBatch(SubscriptionToken, []Delegation) (uint64, error)
func (*CoherenceCoordinator) LookupDelegation([16]byte) (Delegation, bool)

type DelegationReservation struct { /* private state */ }
func (*DelegationReservation) Grant(context.Context) (Delegation, error)
func (*DelegationReservation) Abort()
type DataGuard struct { AppliedSequence uint64 /* plus private state */ }
func (*DataGuard) Release()
type DelegationFlush struct { /* private state */ }
func (*DelegationFlush) End(uint64)

type CoherenceCommitHooks interface {
    OnCommit([]ChangeEntry) uint64
    WaitWithdrawn(context.Context, uint64, SessionID) error
}
type CoherenceDurabilityHooks interface {
    DurableSequence(uint64)
    LatestDurable() uint64
}
type CoherenceSessionHooks interface {
    CheckSession(SubscriptionToken) error
    ExpireSession(SessionID)
}
```

## Verification scope

The new tests use fake clocks for horizons and budgets; real-time deadlines only
fail a stuck test or synchronize goroutine scheduling. They cover every change
kind, cumulative acks, replay, cold incarnations, truncation/overrun, handle modes,
reserved reads, cross-session recalls, recall during pending withdrawal, expiry,
break/recall FIFO, disjoint progress, cancellation, batch atomicity, stale cuts,
flush pinning, and durable-sequence publication.

The full local gate exercises the existing authority and frontend paths. Because
this workstream deliberately adds only coordinator files, its privileged mounts
are regression evidence, not a claim that the v7 handler/client integration has
shipped. Workstream F must wire these hooks and run the v7 mount proofs.

## Benchmark result

On 2026-09-16, Darwin/arm64, Apple M5 Max, while the repository gate was running:

| Benchmark | Result | Allocation |
|---|---:|---:|
| Append + deliver + ack, batch 1 | 10.74 million entries/s | 0 B, 0 allocs/op |
| Append + deliver + ack, batch 64 | 26.04 million entries/s | 0 B, 0 allocs/op |
| Append + deliver + ack, batch 1,024 | 21.32 million entries/s | 0 B, 0 allocs/op |
| Lookup with 100,000 active delegations | 59.30 ns/lookup | 0 B, 0 allocs/op |

The benchmark prints the 100,000 entries/s budget alongside observed throughput.
These are in-memory coordinator measurements, excluding transport and storage;
there is no timing assertion sensitive to host load. Subscriber scaling covers
1, 64, and 1,024 subscribers with allocation-free delivery and acknowledgment.

## Test commands and results

Executed on 2026-09-16:

| Command | Result |
|---|---|
| `CGO_ENABLED=1 GOOS=darwin go -C vcs build ./...` | PASS |
| `CGO_ENABLED=0 GOOS=linux go -C vcs build ./...` | PASS |
| `go -C vcs vet ./...` | PASS |
| `go -C vcs test ./...` | PASS, also run by both local gate modes |
| `go -C vcs test -race ./internal/volumeserver/...` | PASS, including unchanged existing tests |
| `go -C vcs test -bench . -benchmem ./internal/volumeserver/ -run XXX` | PASS; measurements above |
| `go -C vcs test -race ./internal/volumeserver -run 'Test(Coherence\|Subscription\|WaitWithdrawn\|DurableSequence)' -count=25 -timeout 60s` | PASS |
| `bash scripts/verify-local.sh` | PASS |
| `bash scripts/verify-local.sh --full` | PASS; `verify-local: ok (full)`, 64 required privileged tests plus one root-boundary test; matrix 22 pass, one declared skip, zero unexpected |

The full gate also runs the native whole-repository race suite, Foundation/cgo
and static Linux vet/build, vulnerability checks, the go-fuse reply seam,
344 enumerated native Swift tests, release policy, and architecture checks.

Two verification attempts encountered the unchanged protocol-6
`TestMutationPostStateEliminatesFollowupMetadataRPCs`: one observed an extra
LOOKUP after SETATTR; an isolated run with
`PORTABLEFS_GO_TEST_FLAGS='-run ^TestMutationPostStateEliminatesFollowupMetadataRPCs$ -count=5' bash scripts/xfs-fuse-integration.sh`
stopped at its first failure after observing four GETATTRs in the concurrent
existing-CREATE window, against a bound of three. The same test passed in the
successful full privileged runs. No existing test or frontend file was changed;
this component is not called by that v6 path. This intermittent regression is
retained as a qualification limit rather than hidden by changing its assertion.

The full mode does not run the package-manager soak, live macOS FSKit mount
matrix, or live-cell staging qualification. These remain integration/release
qualification work, alongside wiring the new coordinator into protocol 7.
