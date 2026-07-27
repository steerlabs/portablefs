// Package lifecycle implements the managed authority's production lifecycle
// primitives: fenced, idempotent admin operations and the graceful eviction
// drain a journal child executes on every ordinary stop.
//
// One explicit state machine owns the transitions:
//
//	serving ──evict (SIGTERM/manager evict)──▶ evicting ──drained + journal suspended──▶ evicted   (process exits)
//	                                              │
//	                                              └─drain or suspension failed─▶ evict-failed ──retry evict──▶ evicting
//
// EVICT is the ordinary graceful stop (SIGTERM, manager evict). Every
// acknowledged write is already durable before it was made visible (the
// remote journal's synchronous append happens inside each mutation's own
// acknowledgement boundary), so eviction only closes admission, drains the
// already-admitted operations through that existing boundary, proves the
// applied-and-durable live revision, executes the exact receipted journal
// suspension, and closes the data plane. It runs NO checkpoint, claims no
// committed head, touches no object storage, and claims no lease release —
// the next incarnation cold-replays from the journal.
//
// Checkpoint, quiesce, and terminal lease release are NOT in-process
// operations on a managed authority: snapshots, publishing, and terminal
// history materialization belong to the EXTERNAL HistoryCut service, so the
// corresponding admin endpoints answer the explicit typed refusal
// (VCS_HISTORY_CUT_UNAVAILABLE) instead of pretending a durability domain
// this process does not own. The development file-WAL mode keeps its own
// periodic checkpoint loop outside this package.
//
// Sealing is one-way: once write admission closes it never reopens in this
// process. An evicted authority keeps its process alive (admin endpoints keep
// answering idempotent retries) until the manager terminates it.
//
// Admission is serialized, not just execution: every operation is admitted
// under one controller lock that checks the durable receipt store, coalesces
// concurrent identical operation ids onto a single execution, rejects an id
// reused with a different canonical request (fingerprint of kind + volume +
// branch + authority instance + normalized request), and re-checks lifecycle
// state under the execution lock.
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/opstate"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// State is the controller's lifecycle state.
type State string

const (
	// StateServing is normal writable operation.
	StateServing State = "serving"
	// StateEvicting means a graceful eviction is in flight: write admission is
	// closed and already-admitted operations are draining through their own
	// acknowledgement (durable journal append) boundaries.
	StateEvicting State = "evicting"
	// StateEvictFailed means the eviction drain or the exact journal suspension
	// did not complete within its bound: admission stays sealed (fail closed)
	// and a retried eviction may complete it. Acknowledged writes were durable
	// before this state was ever entered; only never-acknowledged in-flight
	// operations are stuck.
	StateEvictFailed State = "evict-failed"
	// StateEvicted means this process gracefully stopped serving: admission is
	// sealed, every acknowledged mutation drained through its durability
	// boundary, the journal generation is exactly suspended, and the data
	// plane is closed. Nothing was checkpointed and no marker was persisted —
	// acknowledged history lives in the remote journal for the successor.
	StateEvicted State = "evicted"
	// StateQuiescing/StateQuiesceFailed/StateQuiesced belong to the terminal
	// retirement protocol, which is the external HistoryCut service's job for
	// a managed authority. The states remain part of the receipt vocabulary
	// (a receipt naming them is legible), but this process never enters them.
	StateQuiescing     State = "quiescing"
	StateQuiesceFailed State = "quiesce-failed"
	StateQuiesced      State = "quiesced"
)

// Machine-readable error codes returned by the admin API.
const (
	CodeOperationIDRequired = "VCS_OPERATION_ID_REQUIRED"
	CodeFenceMismatch       = "VCS_FENCE_MISMATCH"
	CodeOperationConflict   = "VCS_OPERATION_CONFLICT"
	CodeOperationExpired    = "VCS_OPERATION_EXPIRED"
	CodeQuiesced            = "VCS_QUIESCED"
	CodeNotQuiesced         = "VCS_NOT_QUIESCED"
	CodeCheckpointFailed    = "VCS_CHECKPOINT_FAILED"
	CodeDrainFailed         = "VCS_DRAIN_FAILED"
	CodeSuspendFailed       = "VCS_SUSPEND_FAILED"
	CodeLeaseReleaseFailed  = "VCS_LEASE_RELEASE_FAILED"
	CodeLifecycleInFlight   = "VCS_LIFECYCLE_IN_FLIGHT"
	CodeNotWritable         = "VCS_NOT_WRITABLE"
	CodeMethodNotAllowed    = "VCS_METHOD_NOT_ALLOWED"
	CodeInvalidRequest      = "VCS_INVALID_REQUEST"
	CodeUnauthorized        = "VCS_UNAUTHORIZED"
	CodeInternal            = "VCS_INTERNAL"
	// CodeHistoryCutUnavailable names the managed-authority answer for
	// checkpoint/quiesce: snapshots, publishing, and terminal history
	// materialization are the EXTERNAL HistoryCut service's job, not ordinary
	// durability, and no managed child ever runs them in-process.
	CodeHistoryCutUnavailable = "VCS_HISTORY_CUT_UNAVAILABLE"
)

// sealDrainTimeout bounds how long an eviction waits for already admitted
// mutations to drain through their acknowledgement boundary. Admitted work
// completes in milliseconds under healthy I/O; minutes here means a wedged
// durability path, and the operation fails (sealed, retryable) instead of
// wedging the controller forever. Tests shorten it.
var sealDrainTimeout = 60 * time.Second

// defaultSuspendDeadline bounds the exact journal suspension inside one
// eviction attempt when Deps.SuspendDeadline is zero.
const defaultSuspendDeadline = 30 * time.Second

// Eviction observability: how many graceful evictions completed, how many
// drains timed out (retryable, sealed), and how long the seal+drain took.
var (
	evictions             = metrics.Default.Counter("vcs_lifecycle_evictions")
	evictionDrainFailures = metrics.Default.Counter("vcs_lifecycle_eviction_drain_failures")
	evictionDrainDuration = metrics.Default.Histogram("vcs_lifecycle_eviction_drain_duration")
)

// OpError is a machine-readable operation failure.
type OpError struct {
	Code    string
	Message string
	Status  int // suggested HTTP status
}

func (e *OpError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func opErrorf(code string, status int, format string, args ...any) *OpError {
	return &OpError{Code: code, Message: fmt.Sprintf(format, args...), Status: status}
}

// Identity fences this authority process: requests must name the exact volume,
// branch, and (when the process was launched with one) authority instance id.
type Identity struct {
	VolumeID   string
	Branch     string
	InstanceID string
}

// OpRequest is a fenced, idempotent operation request.
type OpRequest struct {
	OperationID         string
	VolumeID            string
	Branch              string
	AuthorityInstanceID string
}

// fingerprint is the canonical fingerprint of a lifecycle request: operation
// kind, volume, branch, authority instance, and the normalized request body.
// Two requests with the same operation id must carry the same fingerprint or
// the reuse is a conflict — in the durable store AND while one is in flight.
func fingerprint(kind string, req OpRequest) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf(
		"portablefs-lifecycle\x00%s\x00%s\x00%s\x00%s", kind, req.VolumeID, req.Branch, req.AuthorityInstanceID,
	)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// LeaseReleaser is the held write lease an evicted authority may release with
// durable proof (authority.Authority implements it).
type LeaseReleaser interface {
	LeaseID() string
	Release(ctx context.Context) error
}

// JournalSuspendProof is the exact receipted result of the managed journal's
// terminal step-down (pfj.journal_suspend_exact): the database's own durable
// head at suspension. After it commits, no append can land at or after
// NextSeq under this generation until a fresh claim rebinds it.
type JournalSuspendProof struct {
	NextSeq   uint64
	TipDigest string
	Replayed  bool
}

// JournalStepDown is the narrow managed-journal seam ordinary eviction calls
// AFTER the local drain: observe the exact durable head, then execute (or
// replay) the receipted exact suspension. Implemented by the cmd/vcs adapter
// over remotejournal.Log; nil in local/self-host file-WAL mode.
type JournalStepDown interface {
	StepDown(ctx context.Context) (JournalSuspendProof, error)
}

// Deps wires the controller to the serving process.
type Deps struct {
	FS *workfs.FS
	// StopDataPlane closes the mount data plane (fsproto listeners and
	// connections) WITHOUT tearing down lease renewal, metrics, or the admin
	// endpoints. Must be idempotent.
	StopDataPlane func()
	Store         opstate.OperationStore
	Identity      Identity
	// Lease releases this authority's exact write lease (nil in unit tests that
	// never exercise release).
	Lease LeaseReleaser
	// Journal is the managed remote journal's terminal step-down (nil for the
	// local file WAL). When set, a successful eviction drain is followed by the
	// exact receipted suspension and the proof is part of the evict receipt.
	Journal JournalStepDown
	// SuspendDeadline bounds the exact journal suspension inside one eviction
	// attempt (on top of the caller's own context). Zero means the 30s
	// default. An unresolved suspension at the bound fails the eviction
	// CLOSED (unknown outcome, admission sealed, same-identity retry).
	SuspendDeadline time.Duration
	// Now is the clock (defaults to time.Now).
	Now func() time.Time
}

// inflightOp coalesces concurrent requests for one operation id onto a single
// execution: the first request executes; identical duplicates wait on done and
// observe the same outcome; a different fingerprint under the same id conflicts.
type inflightOp struct {
	fingerprint string
	kind        string
	done        chan struct{}
	op          opstate.Operation
	oerr        *OpError
}

// Controller is the lifecycle state machine. One per writable serving process.
type Controller struct {
	deps Deps

	// mu guards admission: state reads, the in-flight table, and receipt checks
	// happen under it, so two requests can never both admit for the same id.
	mu       sync.Mutex
	state    State
	inflight map[string]*inflightOp

	// execMu serializes operation EXECUTION and the state re-check immediately
	// before it.
	execMu sync.Mutex
	// evictMu coalesces ordinary eviction callers without putting eviction
	// behind execMu. Eviction must close filesystem admission immediately even
	// when an unrelated admin operation is blocked; waiting for that work
	// would incorrectly make its availability part of ordinary filesystem
	// shutdown durability.
	evictMu sync.Mutex
	// evicted holds the completed eviction result once StateEvicted is reached
	// (guarded by execMu), so repeated Evict calls are idempotent: they return
	// the identical proof without re-draining or re-closing anything.
	evicted *EvictResult
	// evictFlight is non-nil from the atomic StateEvicting transition through
	// publication of the drain result. Guarded by mu; closed while holding mu
	// before being cleared.
	evictFlight chan struct{}
	// evictionReleaseStarted closes the final race between a completed ordinary
	// eviction and main's best-effort early writer-claim release. It is set under
	// the same mu used by quiesce admission; whichever wins that lock excludes
	// the other. Once a release attempt starts it never reopens terminal
	// admission because a lost release response is itself ambiguous.
	evictionReleaseStarted bool
}

// NewController builds a Controller in StateServing.
func NewController(deps Deps) *Controller {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Controller{deps: deps, state: StateServing, inflight: map[string]*inflightOp{}}
}

// State reports the current lifecycle state.
func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Controller) hasInflightKindLocked(kind string) bool {
	for _, operation := range c.inflight {
		if operation.kind == kind {
			return true
		}
	}
	return false
}

func (c *Controller) finishEvictFlightLocked() {
	if c.evictFlight != nil {
		close(c.evictFlight)
		c.evictFlight = nil
	}
}

func (c *Controller) validate(req OpRequest) *OpError {
	if req.OperationID == "" || len(req.OperationID) > 256 {
		return opErrorf(CodeOperationIDRequired, 400, "operationId is required (non-empty, at most 256 bytes)")
	}
	if req.VolumeID == "" || len(req.VolumeID) > 256 || req.Branch == "" || len(req.Branch) > 128 || len(req.AuthorityInstanceID) > 256 {
		return opErrorf(CodeInvalidRequest, 400, "volumeId/branch/authorityInstanceId are required within protocol bounds")
	}
	id := c.deps.Identity
	if req.VolumeID != id.VolumeID || req.Branch != id.Branch {
		return opErrorf(CodeFenceMismatch, 409,
			"request is fenced to %s@%s but this authority serves %s@%s",
			req.VolumeID, req.Branch, id.VolumeID, id.Branch)
	}
	if id.InstanceID != "" {
		if req.AuthorityInstanceID != id.InstanceID {
			return opErrorf(CodeFenceMismatch, 409,
				"request is fenced to authority instance %q but this authority is %q",
				req.AuthorityInstanceID, id.InstanceID)
		}
	} else if req.AuthorityInstanceID != "" {
		return opErrorf(CodeFenceMismatch, 409,
			"request is fenced to authority instance %q but this authority has no instance identity",
			req.AuthorityInstanceID)
	}
	if c.deps.Store == nil {
		return opErrorf(CodeInternal, 500, "lifecycle operation store is not configured")
	}
	if err := c.deps.Store.Healthy(); err != nil {
		return opErrorf(CodeInternal, 503, "lifecycle operation store is unavailable; refusing admission: %v", err)
	}
	return nil
}

// recordedLocked returns the durably stored result for req when one exists,
// enforcing the fingerprint (a reused id with a different canonical request is
// a conflict) and answering expired receipts explicitly. Caller holds c.mu.
func (c *Controller) recordedLocked(req OpRequest, fp string) (opstate.Operation, *OpError, bool) {
	if ts, ok := c.deps.Store.Tombstone(req.OperationID); ok {
		if ts.Fingerprint != fp {
			return opstate.Operation{}, opErrorf(CodeOperationConflict, 409,
				"operationId %q was already used for a different %s operation", req.OperationID, ts.Kind), true
		}
		return opstate.Operation{}, opErrorf(CodeOperationExpired, 410,
			"operationId %q completed long ago and its receipt expired at %d; use a fresh operation id", req.OperationID, ts.ExpiredAtMs), true
	}
	op, ok := c.deps.Store.Operation(req.OperationID)
	if !ok {
		expired, err := c.deps.Store.UnknownExpired(req.VolumeID, req.Branch, req.AuthorityInstanceID)
		if err != nil {
			return opstate.Operation{}, opErrorf(CodeInternal, 503,
				"lifecycle operation store became unavailable while checking %q: %v", req.OperationID, err), true
		}
		if expired {
			return opstate.Operation{}, opErrorf(CodeOperationExpired, 410,
				"operationId %q is unknown inside a closed receipt-retention generation; rotate to a fresh authority instance and use a fresh operation id", req.OperationID), true
		}
		return opstate.Operation{}, nil, false
	}
	if op.Fingerprint != fp {
		return opstate.Operation{}, opErrorf(CodeOperationConflict, 409,
			"operationId %q was already used for a different %s operation", req.OperationID, op.Kind), true
	}
	return op, nil, true
}

// admit is the serialized admission step shared by every lifecycle operation:
// under ONE c.mu hold it (a) returns the durable receipt for an already
// completed identical request, (b) conflicts an id reused with a different
// fingerprint (recorded OR in flight), (c) joins an in-flight identical
// request, or (d) registers this request as the executor. Exactly one of the
// returns is meaningful: a recorded/inherited result, a wait channel, or an
// executor registration.
func (c *Controller) admit(kind string, req OpRequest, fp string) (op opstate.Operation, oerr *OpError, waitOn *inflightOp, exec *inflightOp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rop, roerr, ok := c.recordedLocked(req, fp); ok {
		return rop, roerr, nil, nil
	}
	if kind == opstate.KindQuiesce && c.evictionReleaseStarted {
		return opstate.Operation{}, opErrorf(CodeNotWritable, 409,
			"ordinary eviction has started releasing this authority's writer claim; terminal quiesce must run on the replacement generation"), nil, nil
	}
	if cur, ok := c.inflight[req.OperationID]; ok {
		if cur.fingerprint != fp {
			return opstate.Operation{}, opErrorf(CodeOperationConflict, 409,
				"operationId %q is currently executing a different %s operation", req.OperationID, cur.kind), nil, nil
		}
		return opstate.Operation{}, nil, cur, nil
	}
	entry := &inflightOp{fingerprint: fp, kind: kind, done: make(chan struct{})}
	c.inflight[req.OperationID] = entry
	return opstate.Operation{}, nil, nil, entry
}

// finish publishes the executor's outcome to coalesced waiters and clears the
// in-flight registration.
func (c *Controller) finish(operationID string, entry *inflightOp, op opstate.Operation, oerr *OpError) {
	c.mu.Lock()
	entry.op, entry.oerr = op, oerr
	delete(c.inflight, operationID)
	c.mu.Unlock()
	close(entry.done)
}

// runOperation drives one admitted lifecycle operation end to end: admission
// (receipts, coalescing, conflicts), then serialized execution via execute
// (called with execMu held), then result publication.
func (c *Controller) runOperation(
	ctx context.Context,
	kind string,
	req OpRequest,
	execute func(ctx context.Context, fp string) (opstate.Operation, *OpError),
) (opstate.Operation, *OpError) {
	if err := c.validate(req); err != nil {
		return opstate.Operation{}, err
	}
	fp := fingerprint(kind, req)
	op, oerr, waitOn, exec := c.admit(kind, req, fp)
	if waitOn != nil {
		select {
		case <-waitOn.done:
			return waitOn.op, waitOn.oerr
		case <-ctx.Done():
			return opstate.Operation{}, opErrorf(CodeInternal, 500, "wait for concurrent identical operation canceled: %v", ctx.Err())
		}
	}
	if exec == nil {
		return op, oerr
	}
	// Once execution starts it runs to completion and persists its result even
	// if the initiating request is abandoned — a lost-response retry depends on
	// that record. Every backend call inside carries its own bounded timeout.
	execCtx := context.WithoutCancel(ctx)
	c.execMu.Lock()
	op, oerr = execute(execCtx, fp)
	c.execMu.Unlock()
	c.finish(req.OperationID, exec, op, oerr)
	return op, oerr
}

// Checkpoint answers the fenced admin checkpoint request. A managed authority
// never materializes history in-process, so the answer is the explicit typed
// refusal — never a nil-pointer crash, never a silent no-op.
func (c *Controller) Checkpoint(ctx context.Context, req OpRequest) (opstate.Operation, *OpError) {
	return c.runOperation(ctx, opstate.KindCheckpoint, req, func(context.Context, string) (opstate.Operation, *OpError) {
		return opstate.Operation{}, c.historyCutUnavailable("checkpoint")
	})
}

// Quiesce answers the terminal retirement request. Terminal history
// materialization belongs to the external HistoryCut service; a managed
// authority refuses it explicitly (ordinary teardown is Evict).
func (c *Controller) Quiesce(ctx context.Context, req OpRequest) (opstate.Operation, *OpError) {
	return c.runOperation(ctx, opstate.KindQuiesce, req, func(context.Context, string) (opstate.Operation, *OpError) {
		return opstate.Operation{}, c.historyCutUnavailable("quiesce")
	})
}

// ReleaseLease answers the terminal durable lease-release request, which is
// only legal after a quiesce — an operation this process never runs.
func (c *Controller) ReleaseLease(ctx context.Context, req OpRequest) (opstate.Operation, *OpError) {
	return c.runOperation(ctx, opstate.KindReleaseLease, req, func(context.Context, string) (opstate.Operation, *OpError) {
		return opstate.Operation{}, c.historyCutUnavailable("release-lease")
	})
}

// EvictResult is the graceful-eviction proof: which terminal state was reached
// and the exact live revision every acknowledged mutation is durable through.
// It deliberately carries no head commit id, no tree hash, and no lease fact —
// eviction materializes no history and releases nothing.
type EvictResult struct {
	// State is the terminal state the eviction observed: StateEvicted for the
	// ordinary drain, or StateQuiesced when an explicit quiesce already sealed,
	// materialized, and persisted everything (eviction is then a no-op).
	State State
	// Revision is the applied-and-durable live revision at the drain point:
	// every acknowledged mutation's record has Seq < Revision.AppliedLSN inside
	// Revision.WALEpoch and passed its durable acknowledgement boundary —
	// restart or failover recovers it from base + journal without any
	// checkpoint.
	Revision workfs.LiveRevision
	// WALPoisoned reports that the durability path had already failed (the node
	// was fencing before the eviction). Acknowledged writes are still durable
	// — durability always precedes acknowledgement — but this process's live
	// log must not be trusted past the revision.
	WALPoisoned bool
	// Journal is the exact receipted remote-journal suspension (managed mode
	// only; nil for the local file WAL). Present exactly when the eviction
	// completed the terminal step-down.
	Journal *JournalSuspendProof
}

// Evict is the ordinary graceful stop (SIGTERM, manager evict): close write
// admission, drain every already-admitted operation through its existing
// acknowledgement boundary, prove the applied-and-durable live revision,
// execute the exact receipted journal suspension (managed mode), and close
// the data plane. A write racing the stop either completes its full
// durability boundary and is acknowledged, or fails with ErrSealed and never
// acknowledges.
//
// Evict runs NO checkpoint and needs NO object-store access: an acknowledged
// write was durable before it became visible, so it survives in the journal
// for the successor's cold replay. Nothing is persisted about the eviction
// itself beyond the process-local receipt.
//
// It is idempotent (repeat calls return the identical result) and bounded
// (the drain fails after sealDrainTimeout with a *OpError of code
// VCS_DRAIN_FAILED; admission stays sealed — never reopened — and a retry may
// complete the drain).
func (c *Controller) Evict(ctx context.Context) (EvictResult, error) {
	// Do not acquire execMu here. An admin operation can be waiting on an
	// unavailable dependency under that lock. Ordinary eviction's first
	// correctness obligation is to close live write admission now, then drain
	// only already-admitted mutations through their existing durability
	// boundary. evictMu provides single-flight/idempotence among eviction
	// callers without coupling that path to anything else.
	c.evictMu.Lock()
	defer c.evictMu.Unlock()
	c.mu.Lock()
	if c.state == StateQuiesced {
		c.mu.Unlock()
		return EvictResult{State: StateQuiesced, Revision: c.deps.FS.LiveRevision()}, nil
	}
	if c.evicted != nil && !c.hasInflightKindLocked(opstate.KindQuiesce) {
		result := *c.evicted
		c.mu.Unlock()
		return result, nil
	}
	// A Quiesce admitted first owns the stronger terminal transition. Eviction
	// still seals/drains immediately below, but must not overwrite or certify an
	// ordinary release-safe StateEvicted result.
	terminalInFlight := c.hasInflightKindLocked(opstate.KindQuiesce) || c.state == StateQuiescing
	ownsFlight := !terminalInFlight
	if ownsFlight {
		c.state = StateEvicting
		c.evictFlight = make(chan struct{})
	}
	c.mu.Unlock()
	start := time.Now()
	// A lost admin connection or canceled shutdown parent must not reopen or
	// abandon an already-started drain. Strip cancellation, then apply the
	// controller's own hard bound.
	sealCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sealDrainTimeout)
	err := c.deps.FS.Seal(sealCtx)
	cancel()
	if err != nil {
		c.mu.Lock()
		if ownsFlight {
			c.state = StateEvictFailed
			c.finishEvictFlightLocked()
		}
		c.mu.Unlock()
		evictionDrainFailures.Inc()
		return EvictResult{State: StateEvictFailed, Revision: c.deps.FS.LiveRevision(), WALPoisoned: c.walPoisoned()},
			opErrorf(CodeDrainFailed, 503,
				"eviction drain did not complete (admission stays sealed; acknowledged writes are already journal-durable; retry evict): %v", err)
	}
	evictionDrainDuration.Time(start)
	// A terminal quiesce that was already in flight may have completed while
	// eviction drained. Preserve its stronger terminal state/result.
	c.mu.Lock()
	if c.state == StateQuiesced {
		if ownsFlight {
			c.finishEvictFlightLocked()
		}
		c.mu.Unlock()
		return EvictResult{State: StateQuiesced, Revision: c.deps.FS.LiveRevision(), WALPoisoned: c.walPoisoned()}, nil
	}
	terminalInFlight = terminalInFlight || c.hasInflightKindLocked(opstate.KindQuiesce) || c.state == StateQuiescing
	if terminalInFlight {
		// The journal-only drain succeeded, but a terminal intent was admitted
		// before we could certify ordinary release safety. Publish the drained
		// intermediate state only; do not cache a successful Evict receipt and
		// do not permit main to release.
		if ownsFlight {
			c.state = StateEvicted
			c.finishEvictFlightLocked()
		}
		c.mu.Unlock()
		if c.deps.StopDataPlane != nil {
			c.deps.StopDataPlane()
		}
		result := EvictResult{State: StateEvicted, Revision: c.deps.FS.LiveRevision(), WALPoisoned: c.walPoisoned()}
		return result, opErrorf(CodeLifecycleInFlight, 503,
			"eviction drained live writes but a terminal quiesce is in flight; refusing to certify ordinary lease release")
	}
	// MANAGED journal step-down: after the drain proved every admitted mutation
	// durable, execute (or replay) the exact receipted pfj suspension. This is
	// lifecycle fencing, not persistence — nothing is checkpointed, published,
	// or materialized. A failed/ambiguous suspension fails the eviction closed:
	// admission stays sealed, nothing is cached, and the exact retry replays
	// the receipt. The lock is not held across the SQL call; managed mode has
	// no in-process quiesce (VCS_HISTORY_CUT_UNAVAILABLE), so no terminal
	// transition can interleave through the gap.
	var journal *JournalSuspendProof
	if c.deps.Journal != nil {
		c.mu.Unlock()
		// The suspension honors the CALLER'S bounded context, capped by the
		// controller's own suspend deadline: a caller that stops waiting
		// stops the WAIT — it never invents a failure, never retries under a
		// new identity (the adapter's operation id is immutable), and the
		// receipt reconciles on the next attempt or after a restart.
		stepCtx, stepCancel := context.WithTimeout(ctx, c.suspendDeadline())
		proof, stepErr := c.deps.Journal.StepDown(stepCtx)
		stepCancel()
		c.mu.Lock()
		if stepErr != nil {
			if ownsFlight {
				c.state = StateEvictFailed
				c.finishEvictFlightLocked()
			}
			c.mu.Unlock()
			evictionDrainFailures.Inc()
			return EvictResult{State: StateEvictFailed, Revision: c.deps.FS.LiveRevision(), WALPoisoned: c.walPoisoned()},
				opErrorf(CodeSuspendFailed, 503,
					"eviction drained but the exact journal suspension did not complete (admission stays sealed; retry evict with the same operationId): %v", stepErr)
		}
		journal = &proof
	}
	// The drain IS the durability proof: every admitted mutation exits the
	// admission gate only after its durable acknowledgement boundary, so the
	// applied watermark below is by construction the durable one.
	res := EvictResult{State: StateEvicted, Revision: c.deps.FS.LiveRevision(), WALPoisoned: c.walPoisoned(), Journal: journal}
	c.state = StateEvicted
	c.evicted = &res
	if ownsFlight {
		c.finishEvictFlightLocked()
	}
	c.mu.Unlock()
	if c.deps.StopDataPlane != nil {
		c.deps.StopDataPlane()
	}
	evictions.Inc()
	return res, nil
}

// EvictOperation is the fenced, exact admin form of Evict. It deliberately
// bypasses execMu so a blocked admin operation cannot delay write sealing.
// Successful receipts persist the exact live journal revision before the HTTP
// response; a lost response retries from that receipt without another
// teardown. Failures are not recorded and remain safely retryable.
func (c *Controller) EvictOperation(ctx context.Context, req OpRequest) (opstate.Operation, *OpError) {
	if oerr := c.validate(req); oerr != nil {
		return opstate.Operation{}, oerr
	}
	fp := fingerprint(opstate.KindEvict, req)
	op, oerr, waitOn, exec := c.admit(opstate.KindEvict, req, fp)
	if waitOn != nil {
		select {
		case <-waitOn.done:
			return waitOn.op, waitOn.oerr
		case <-ctx.Done():
			return opstate.Operation{}, opErrorf(CodeInternal, 500,
				"wait for concurrent identical eviction canceled: %v", ctx.Err())
		}
	}
	if exec == nil {
		return op, oerr
	}

	result, err := c.Evict(ctx)
	if err != nil {
		var typed *OpError
		if errors.As(err, &typed) {
			oerr = typed
		} else {
			oerr = opErrorf(CodeDrainFailed, 503, "eviction failed: %v", err)
		}
		c.finish(req.OperationID, exec, opstate.Operation{}, oerr)
		return opstate.Operation{}, oerr
	}
	op = opstate.Operation{
		ID:                  req.OperationID,
		Kind:                opstate.KindEvict,
		Fingerprint:         fp,
		VolumeID:            req.VolumeID,
		Branch:              req.Branch,
		AuthorityInstanceID: req.AuthorityInstanceID,
		CompletedAtMs:       c.deps.Now().UnixMilli(),
		State:               string(result.State),
		WALEpoch:            result.Revision.WALEpoch,
		AppliedLSN:          result.Revision.AppliedLSN,
		CoherenceGeneration: result.Revision.CoherenceGeneration,
		WALPoisoned:         result.WALPoisoned,
	}
	if result.Journal != nil {
		op.JournalSuspended = true
		op.JournalNextSeq = result.Journal.NextSeq
		op.JournalTipDigest = result.Journal.TipDigest
	}
	if err := c.deps.Store.RecordOperation(op); err != nil {
		oerr = opErrorf(CodeInternal, 500,
			"eviction drained through WAL epoch %s LSN %s coherence generation %s but persisting its exact receipt failed: %v",
			strconv.FormatUint(result.Revision.WALEpoch, 10), strconv.FormatUint(result.Revision.AppliedLSN, 10),
			strconv.FormatUint(result.Revision.CoherenceGeneration, 10), err)
		c.finish(req.OperationID, exec, opstate.Operation{}, oerr)
		return opstate.Operation{}, oerr
	}
	c.finish(req.OperationID, exec, op, nil)
	return op, nil
}

// ReleaseAfterEvict performs the ordinary shutdown's best-effort early writer
// claim release with an atomic admission handshake. It is deliberately
// separate from terminal ReleaseLease (which requires Quiesce and persists an
// exact final-head receipt). A terminal Quiesce admitted first makes this call
// fail; if this call wins, subsequent Quiesce is refused because the claim may
// already have been released even when its response is lost.
func (c *Controller) ReleaseAfterEvict(ctx context.Context) error {
	c.mu.Lock()
	if c.state != StateEvicted || c.evicted == nil {
		state := c.state
		c.mu.Unlock()
		return opErrorf(CodeLifecycleInFlight, 409,
			"ordinary writer-claim release requires one completed release-safe eviction (state %s)", state)
	}
	if c.hasInflightKindLocked(opstate.KindQuiesce) {
		c.mu.Unlock()
		return opErrorf(CodeLifecycleInFlight, 409,
			"terminal quiesce was admitted before ordinary writer-claim release")
	}
	if c.evictionReleaseStarted {
		c.mu.Unlock()
		return opErrorf(CodeLifecycleInFlight, 409,
			"ordinary writer-claim release was already attempted; its outcome must be reconciled")
	}
	if c.deps.Lease == nil {
		c.mu.Unlock()
		return opErrorf(CodeInternal, 500, "this process holds no releasable writer claim")
	}
	c.evictionReleaseStarted = true
	c.mu.Unlock()
	return c.deps.Lease.Release(ctx)
}

// historyCutUnavailable is the managed authority's honest answer for every
// history-materialization request: snapshots/checkpoints/quiesce/terminal
// retirement are the external HistoryCut service's job (manager-side), never
// an in-process concern, and ordinary journal durability is unaffected.
func (c *Controller) historyCutUnavailable(kind string) *OpError {
	return opErrorf(CodeHistoryCutUnavailable, 501,
		"managed authorities do not run in-process %s operations: history materialization belongs to the external HistoryCut service (not yet available). Ordinary write durability is the fenced remote journal and is unaffected; ordinary teardown is evict.", kind)
}

func (c *Controller) suspendDeadline() time.Duration {
	if c.deps.SuspendDeadline > 0 {
		return c.deps.SuspendDeadline
	}
	return defaultSuspendDeadline
}

// walPoisoned reports whether the durable log has signalled an unrecoverable
// durability failure (the node fences on that signal).
func (c *Controller) walPoisoned() bool {
	select {
	case <-c.deps.FS.PoisonedCh():
		return true
	default:
		return false
	}
}
