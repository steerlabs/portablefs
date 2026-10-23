//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"encoding/base64"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"google.golang.org/protobuf/proto"
)

// A clock must both await correction and synchronously reject stale evidence at
// dispatch. Neither a missing owner nor a goroutine start constitutes readiness.
type workspaceClock interface {
	Wait(context.Context, mountenrollment.Permit) error
	// Check also runs under buffer admission: no I/O, joins or owner mutex.
	Check(mountenrollment.Permit) error
}
type workspaceDispatch interface {
	ParkDispatch(context.Context) error
	ResumeDispatch(func() error) error
	DrainDispatch(func() error) error
	DispatchSnapshot() authorityrpc.DispatchSnapshot
	AuthorizationDeadline() time.Time
}
type workspaceWorker struct{ Name, Disposition string }
type WorkspaceState uint8

const (
	WorkspaceIdle WorkspaceState = iota
	WorkspacePrepared
	WorkspaceRecoveryRequired
	WorkspaceCold
	WorkspaceTerminal
)

type WorkspaceObservation struct {
	State WorkspaceState
	// Result is authoritative; the separately returned error is diagnostic only.
	Result                                          authorityrpc.LifecycleResult
	Generation, GateSerial, SubscriptionIncarnation uint64
	Prepared, ColdComplete                          bool
	Loss                                            []*pb.Loss
	Outcome                                         *pb.MountOutcome
	Workers                                         []workspaceWorker
	ParkedRequests                                  []authorityrpc.DispatchOwner
}
type workspaceEvidence struct {
	loss      []*pb.Loss
	failure   error
	abandoned bool
}
type workspaceLifecycle struct {
	initialPermit       mountenrollment.Permit
	beforeRecoveryProof func()
	afterFlushLoss      func(*fileHandle) // deterministic reset boundary; nil in production
	observation         atomic.Pointer[WorkspaceObservation]
	lane                chan struct{}
	clock               workspaceClock
	renewer             *mountenrollment.Renewer
	standalone          bool
	persist             func(WorkspaceObservation) error
	evidence            atomic.Pointer[workspaceEvidence]
	// Lane-owned facts. Joins survive cancellation of their waiter.
	preparedOnce    bool
	cold            bool
	withdrawal      *workspaceJoin
	callbacks       *workspaceJoin
	outcome         *pb.MountOutcome
	workers         []workspaceWorker
	parkedRequests  []authorityrpc.DispatchOwner
	keepalive       workspaceAttempt
	servedSinceCold atomic.Bool
	kernelColdReady atomic.Bool
	coldOutcome     *pb.MountOutcome
	closeCleanupErr error // protected by Mount.mu; terminal/barrier verdicts stay separate
}

// FinalizeWorkspace preserves the run's terminal/loss evidence independently
// of whether exact connection/session cleanup completed. Ordinary Close keeps
// returning its combined terminal, barrier and cleanup diagnostic.
func (m *Mount) FinalizeWorkspace() (WorkspaceObservation, error) {
	w := m.workspaceLifecycle
	if w == nil || w.persist == nil {
		return WorkspaceObservation{}, errors.New("fusev3: managed finalization has no outcome owner")
	}
	m.mu.Lock()
	_ = m.closeLocked()
	cleanupErr := w.closeCleanupErr
	m.mu.Unlock()
	o := m.WorkspaceObservation()
	return o, errors.Join(cleanupErr, w.persist(o))
}

var workspaceWorkerGroups = [][]string{
	{"subscription supervisor", "initial/cold Subscribe"},
	{"subscription renewal", "subscription horizon", "session KeepAlive", "hosted enrollment"},
	{"admitted callbacks", "physical reply settlement"},
	{"cache withdrawal notifications"},
	{"writeback scheduler and pool", "explicit flush waves and metadata", "assigned foreground mutations"},
	{"old CONTROL poll", "change handlers and acknowledgments", "spawned recall handlers"},
	{"background durability and visibility", "deferred CLOSE producers and consumer", "CLOSE_BATCH retries", "RECLAIM producers and lanes", "local state collector", "DATA/CONTROL passive readers", "authority reconnect/replay", "FUSE and session/epoch/owner/control watchers"},
	{"empty successor scheduler"},
	{"spawned terminal withdrawal/close workers"},
}

func (w *workspaceLifecycle) workerDisposition(group int, disposition string) {
	for _, name := range workspaceWorkerGroups[group] {
		found := false
		for i := range w.workers {
			if w.workers[i].Name == name {
				w.workers[i].Disposition = disposition
				found = true
				break
			}
		}
		if !found {
			w.workers = append(w.workers, workspaceWorker{name, disposition})
		}
	}
}

type workspaceJoin struct {
	done chan struct{}
	err  error
}

func startWorkspaceJoin(run func() error) *workspaceJoin {
	j := &workspaceJoin{done: make(chan struct{})}
	go func() { j.err = run(); close(j.done) }()
	return j
}
func (j *workspaceJoin) wait(ctx context.Context) error {
	if err := joinWorkspaceOwner(ctx, j.done); err != nil {
		return err
	}
	return j.err
}

// Cancellation parks an attempt; its actual completion owns the join. This
// does not cancel session-owned mutation or cleanup contexts.
type workspaceAttempt struct {
	mu                sync.Mutex
	parked            bool
	cancel            context.CancelFunc
	done              chan struct{}
	beforeDisposition func() // deterministic completion-boundary test seam
}

func (a *workspaceAttempt) start(ctx context.Context) (context.Context, func(func(bool)), bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.parked {
		return ctx, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	a.cancel, a.done = cancel, done
	return ctx, func(settle func(bool)) {
		cancel()
		if a.beforeDisposition != nil {
			a.beforeDisposition()
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		settle(a.parked)
		a.cancel, a.done = nil, nil
		close(done)
	}, true
}
func (a *workspaceAttempt) park(ctx context.Context) error {
	a.mu.Lock()
	a.parked = true
	if a.cancel != nil {
		a.cancel()
	}
	done := a.done
	a.mu.Unlock()
	return joinWorkspaceOwner(ctx, done)
}
func (a *workspaceAttempt) resume() { a.mu.Lock(); a.parked = false; a.mu.Unlock() }

func (w *workspaceLifecycle) recordDrop(r writeback.DropReport) {
	for {
		old := w.evidence.Load()
		next := &workspaceEvidence{}
		if old != nil {
			next.loss = append(next.loss, old.loss...)
			next.failure = old.failure
			next.abandoned = old.abandoned
		}
		for _, l := range next.loss {
			if l.Sequence == r.LossSequence || l.Aggregated && r.LossSequence <= l.Sequence {
				return
			}
		}
		next.loss = append(next.loss, &pb.Loss{Sequence: r.LossSequence, AcceptedEntries: uint64(r.Entries), AcceptedBytes: uint64(r.Bytes), Reason: control.BoundedReason(r.Reason)})
		// Buffer observers arrive in ticket order; direct duplicate reports keep
		// their original sequence and cannot contribute twice.
		for i := len(next.loss) - 1; i > 0 && next.loss[i].Sequence < next.loss[i-1].Sequence; i-- {
			next.loss[i], next.loss[i-1] = next.loss[i-1], next.loss[i]
		}
		if len(next.loss) > 1 && next.loss[len(next.loss)-2].GetAggregated() {
			a, b := next.loss[len(next.loss)-2], next.loss[len(next.loss)-1]
			next.loss[len(next.loss)-2] = &pb.Loss{Sequence: max(a.Sequence, b.Sequence), AcceptedEntries: saturatingLossAdd(a.AcceptedEntries, b.AcceptedEntries), AcceptedBytes: saturatingLossAdd(a.AcceptedBytes, b.AcceptedBytes), Reason: control.AggregateReason, Aggregated: true}
			next.loss = next.loss[:len(next.loss)-1]
		} else {
			bounded, _, boundErr := control.BoundLoss(next.loss)
			if boundErr != nil {
				next.failure = errors.Join(next.failure, boundErr)
			} else {
				next.loss = bounded
			}
		}
		if w.evidence.CompareAndSwap(old, next) {
			return
		}
	}
}
func saturatingLossAdd(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

func (w *workspaceLifecycle) newInterval() {
	for {
		old := w.evidence.Load()
		if old == nil || !old.abandoned {
			return
		}
		next := &workspaceEvidence{loss: old.loss, failure: old.failure}
		if w.evidence.CompareAndSwap(old, next) {
			return
		}
	}
}

func (w *workspaceLifecycle) abandonGrant() {
	for {
		old := w.evidence.Load()
		if old != nil && old.abandoned {
			return
		}
		next := &workspaceEvidence{abandoned: true}
		if old != nil {
			next.loss, next.failure = old.loss, old.failure
		}
		if w.evidence.CompareAndSwap(old, next) {
			return
		}
	}
}

func (m *Mount) workspaceObservation(g, serial uint64) WorkspaceObservation {
	w := m.workspaceLifecycle
	o := WorkspaceObservation{Generation: g, GateSerial: serial, Outcome: control.UnknownOutcome()}
	if w == nil {
		return o
	}
	if prior := w.observation.Load(); prior != nil {
		o.Result = prior.Result
		o.Outcome = proto.Clone(prior.Outcome).(*pb.MountOutcome)
		o.Workers = append(o.Workers, prior.Workers...)
		for _, request := range prior.ParkedRequests {
			request.Body = append([]byte(nil), request.Body...)
			o.ParkedRequests = append(o.ParkedRequests, request)
		}
	}
	if e := w.evidence.Load(); e != nil {
		for _, l := range e.loss {
			o.Loss = append(o.Loss, proto.Clone(l).(*pb.Loss))
		}
		if e.abandoned && o.Outcome.Release == "unresolved" {
			o.Outcome.Observation = "observed"
			o.Outcome.Release = "abandoned"
		}
	}

	m.subscription.mu.RLock()
	o.SubscriptionIncarnation = m.subscription.incarnation
	m.subscription.mu.RUnlock()
	return o
}
func (m *Mount) WorkspaceObservation() WorkspaceObservation {
	if m.workspaceLifecycle == nil {
		return WorkspaceObservation{Outcome: control.UnknownOutcome()}
	}
	prior := m.workspaceLifecycle.observation.Load()
	var g, serial uint64
	if prior != nil {
		g, serial = prior.Generation, prior.GateSerial
	}
	o := m.workspaceObservation(g, serial)
	terminal := m.isRevoked() || m.ctx.Err() != nil || m.rpc.SessionEndCause() != nil
	if m.workspace != nil {
		select {
		case <-m.workspace.Done():
			terminal = true
		default:
		}
	}
	if terminal {
		o.Prepared, o.ColdComplete = false, false
		o.State = WorkspaceTerminal
		cause := m.fatalError()
		if cause == nil {
			cause = m.rpc.SessionEndCause()
		}
		if cause == nil {
			cause = m.ctx.Err()
		}
		if cause == nil {
			cause = errors.New("workspace owner ended")
		}
		o.Result = authorityrpc.LifecycleResult{Disposition: authorityrpc.LifecycleFailed, Err: cause}
		return o
	}
	if prior != nil {
		o.Prepared, o.ColdComplete = prior.Prepared, prior.ColdComplete
	}
	o.State = WorkspaceIdle
	if o.ColdComplete {
		o.State = WorkspaceCold
	}
	if o.Prepared {
		o.State = WorkspacePrepared
	}
	if o.Prepared {
		proof, err := m.workspace.Recovery(o.Generation, o.GateSerial)
		permit := mountenrollment.Permit{Generation: o.Generation, GateSerial: o.GateSerial}
		_, _, _, live := m.subscription.currentIncarnation()
		if err != nil && !m.workspace.Installed(proof) || !live || m.workspaceLifecycle.clock.Check(permit) != nil {
			o.Prepared = false
			o.State = WorkspaceRecoveryRequired
		}
	}
	return o
}

// A retained terminal renewal verdict is independent of the lifecycle waiter,
// even when its diagnostic wraps cancellation or an attempt deadline.
func (w *workspaceLifecycle) renewalFailure() error {
	if w.renewer != nil {
		if err := w.renewer.Failure(); err != nil {
			return &authorityrpc.LifecycleIndependentFailure{Err: err}
		}
	}
	return nil
}

func (m *Mount) workspaceDependencies() (*workspaceLifecycle, workspaceDispatch, error) {
	w := m.workspaceLifecycle
	if m.workspace == nil || w == nil || w.clock == nil || w.persist == nil || w.standalone == (w.renewer != nil) {
		return nil, nil, errors.New("fusev3: real workspace lifecycle dependencies are unavailable")
	}
	e, ok := m.rpc.(*epochRPC)
	if !ok {
		return nil, nil, errors.New("fusev3: workspace requires session-owned transport")
	}
	d, ok := e.current().(workspaceDispatch)
	if !ok {
		return nil, nil, errors.New("fusev3: transport has no lifecycle dispatch fence")
	}
	return w, d, nil
}
func (w *workspaceLifecycle) enter(ctx context.Context) error {
	if w.lane == nil {
		return errors.New("fusev3: workspace lifecycle lane is unavailable")
	}
	select {
	case w.lane <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Every completion, including an overtaken/failed one, snapshots cumulative
// evidence. Persistence happens on the lifecycle lane, outside data-plane locks.
// publication keeps readiness/reset dispositions separate from failures. An
// owner's overtaking bit applies only to permit loss, never independent facts.
func (m *Mount) workspacePublication(ctx context.Context, g, serial uint64, prepared bool) authorityrpc.LifecycleAttempt {
	failed := func(err error) authorityrpc.LifecycleAttempt {
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: &authorityrpc.LifecycleIndependentFailure{Err: err}}
	}
	if m.isRevoked() || m.ctx.Err() != nil {
		return failed(errors.New("fusev3: terminal mount before lifecycle publication"))
	}
	if cause := m.rpc.SessionEndCause(); cause != nil {
		return failed(cause)
	}
	w := m.workspaceLifecycle
	if e := w.evidence.Load(); e != nil && e.failure != nil {
		return failed(e.failure)
	}
	if err := w.renewalFailure(); err != nil {
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: err}
	}
	proof, err := m.workspace.Recovery(g, serial)
	if err != nil {
		if authorityrpc.LifecycleOwnerOvertaken(ctx) {
			return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptOvertaken, Err: err}
		}
		return authorityrpc.ClassifyLifecycleAttempt(err)
	}
	if ctx.Err() != nil {
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptOvertaken, Err: ctx.Err()}
	}
	if !prepared {
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete}
	}
	p := mountenrollment.Permit{Generation: g, GateSerial: serial}
	if err := w.clock.Check(p); err != nil {
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptPending, Err: err}
	}
	_, d, err := m.workspaceDependencies()
	if err != nil {
		return failed(err)
	}
	deadline := d.AuthorizationDeadline()
	if !deadline.After(time.Now()) {
		return failed(mountenrollment.ErrDefinitiveDenial)
	}
	if w.renewer != nil && !w.renewer.Readiness().Ready(false, p, base64.RawURLEncoding.EncodeToString(m.rpc.SessionID()), deadline) {
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptPending}
	}
	m.subscription.mu.Lock()
	live := m.subscription.controlLiveLocked()
	same := m.subscription.workspaceProof != nil && m.subscription.workspaceProof.Serial() == proof.Serial()
	m.subscription.mu.Unlock()
	if !live || !same {
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptColdReset, Err: errSubscriptionExpired}
	}
	return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete}
}

func workspaceResult(ctx context.Context, phase authorityrpc.LifecycleAttempt) authorityrpc.LifecycleResult {
	if phase.Disposition == authorityrpc.AttemptOvertaken {
		result := authorityrpc.LifecycleCompletion(ctx, phase.Err)
		result.Disposition = authorityrpc.LifecycleOvertaken
		return result
	}
	return authorityrpc.LifecycleCompletion(ctx, phase.Err)
}

// A defeated persisted candidate is followed by a persisted refusal before the
// same logical job waits/retries. Storage errors remain independent failures.
func (m *Mount) publishWorkspace(ctx context.Context, g, serial uint64, ready, cold bool, phase authorityrpc.LifecycleAttempt) (WorkspaceObservation, authorityrpc.LifecycleAttempt) {
	w := m.workspaceLifecycle
	o := m.workspaceObservation(g, serial)
	if e := w.evidence.Load(); e != nil && e.failure != nil {
		phase = authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: errors.Join(phase.Err, e.failure)}
	}
	if phase.Disposition == authorityrpc.AttemptComplete {
		phase = m.workspacePublication(ctx, g, serial, ready)
	}
	o.Prepared, o.ColdComplete = ready && phase.Disposition == authorityrpc.AttemptComplete, cold && phase.Disposition == authorityrpc.AttemptComplete
	if w.outcome != nil {
		o.Outcome = proto.Clone(w.outcome).(*pb.MountOutcome)
	}
	if e := w.evidence.Load(); e != nil && e.abandoned {
		o.Outcome.Release = "abandoned"
		o.Outcome.Observation = "observed"
	}
	o.Workers = append([]workspaceWorker(nil), w.workers...)
	o.ParkedRequests = nil
	for _, request := range w.parkedRequests {
		request.Body = append([]byte(nil), request.Body...)
		o.ParkedRequests = append(o.ParkedRequests, request)
	}
	o.State = WorkspaceIdle
	if o.Prepared {
		o.State = WorkspacePrepared
	}
	if o.ColdComplete {
		o.State = WorkspaceCold
	}
	o.Result = workspaceResult(ctx, phase)
	persist := func() bool {
		if err := w.persist(o); err != nil {
			phase = authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: errors.Join(phase.Err, &authorityrpc.LifecycleIndependentFailure{Err: fmt.Errorf("persist workspace outcome: %w", err)})}
			o.Prepared, o.ColdComplete = false, false
			o.State = WorkspaceIdle
			o.Result = workspaceResult(ctx, phase)
			return false
		}
		return true
	}
	if persist() && (o.Prepared || o.ColdComplete) {
		phase = m.workspacePublication(ctx, g, serial, o.Prepared)
		o.Result = workspaceResult(ctx, phase)
		if phase.Disposition != authorityrpc.AttemptComplete {
			o.Prepared, o.ColdComplete = false, false
			o.State = WorkspaceIdle
			persist()
		}
	}
	w.observation.Store(&o)
	return o, phase
}

func (m *Mount) PrepareWorkspace(ctx context.Context, g, serial uint64) (o WorkspaceObservation, err error) {
	return m.prepareWorkspace(ctx, g, serial, false)
}
func (m *Mount) RecoverWorkspace(ctx context.Context, g, serial uint64) (o WorkspaceObservation, err error) {
	return m.prepareWorkspace(ctx, g, serial, true)
}
func (m *Mount) prepareWorkspace(ctx context.Context, g, serial uint64, recover bool) (o WorkspaceObservation, err error) {
	w, d, err := m.workspaceDependencies()
	if err != nil {
		o = m.workspaceObservation(g, serial)
		o.Result = authorityrpc.LifecycleCompletion(ctx, err)
		return o, err
	}
	if err = w.enter(ctx); err != nil {
		o = m.workspaceObservation(g, serial)
		o.Result = authorityrpc.LifecycleCompletion(ctx, err)
		return o, err
	}
	defer func() { <-w.lane }()
	phase := authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete}
	published := false
	defer func() {
		if published {
			return
		}
		parkErr := m.parkWorkspace(m.ctx, w, d)
		if parkErr != nil {
			phase = authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: errors.Join(phase.Err, parkErr)}
		}
		if phase.Disposition == authorityrpc.AttemptComplete {
			phase = authorityrpc.ClassifyLifecycleAttempt(err)
		}
		o, _ = m.publishWorkspace(ctx, g, serial, false, false, phase)
		err = o.Result.Err
	}()
	fail := func(cause error) error {
		phase = authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: cause}
		return cause
	}
	if !recover && w.preparedOnce {
		return o, fail(errors.New("fusev3: Prepare is consumed"))
	}
	w.preparedOnce = true
	// Recover also finishes a retained incomplete cut. It never extends that
	// cut's old drain capability; an expired tail is fenced and accounted below.
	if !w.cold {
		_, phase = m.suspendWorkspace(ctx, w, d, g, serial, m.subscription.config.clock.Now().Add(m.requestTimeout))
		if phase.Disposition != authorityrpc.AttemptComplete {
			return o, phase.Err
		}
	}
	phase = m.workspacePublication(ctx, g, serial, false)
	if phase.Disposition != authorityrpc.AttemptComplete {
		return o, phase.Err
	}
	if w.beforeRecoveryProof != nil {
		w.beforeRecoveryProof()
	}
	proof, err := m.workspace.Recovery(g, serial)
	if err != nil {
		phase = authorityrpc.ClassifyLifecycleAttempt(err)
		return o, err
	}
	if err = m.subscription.takeWorkspaceOwnership(ctx); err != nil {
		return o, fail(err)
	}
	p := mountenrollment.Permit{Generation: g, GateSerial: serial}
	check := func() authorityrpc.LifecycleAttempt {
		result := m.workspacePublication(ctx, g, serial, false)
		if result.Disposition != authorityrpc.AttemptComplete {
			return result
		}
		if err := w.clock.Check(p); err != nil {
			return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptPending, Err: err}
		}
		if !m.workspace.Installed(proof) {
			if err := m.workspace.Recover(proof); err != nil {
				result = m.workspacePublication(ctx, g, serial, false)
				if result.Disposition != authorityrpc.AttemptComplete {
					return result
				}
				return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: err}
			}
		}
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete}
	}
	waitReady := func() authorityrpc.LifecycleResult {
		return authorityrpc.RetryLifecycleAttempts(ctx, m.requestTimeout, func(attempt context.Context) authorityrpc.LifecycleAttempt {
			result := check()
			if result.Disposition == authorityrpc.AttemptPending || result.Disposition == authorityrpc.AttemptComplete {
				// Wait is only a readiness owner. Its diagnostic cannot terminalize a
				// healthy session, even if correction raced its initial return.
				if err := w.clock.Wait(attempt, p); err != nil {
					return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptPending, Err: err}
				}
				result = check()
			}
			if result.Disposition != authorityrpc.AttemptComplete {
				return result
			}
			if err := d.ResumeDispatch(func() error { return w.clock.Check(p) }); err != nil {
				return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptPending, Err: err}
			}
			return result
		})
	}
	setResult := func(result authorityrpc.LifecycleResult) {
		disposition := authorityrpc.AttemptFailed
		if result.Disposition == authorityrpc.LifecycleOvertaken {
			disposition = authorityrpc.AttemptOvertaken
		}
		phase = authorityrpc.LifecycleAttempt{Disposition: disposition, Err: result.Err}
	}
	if result := waitReady(); result.Disposition != authorityrpc.LifecycleCompleted {
		setResult(result)
		return o, result.Err
	}
	validation := authorityrpc.RetryLifecycleAttempts(ctx, m.requestTimeout, func(attempt context.Context) authorityrpc.LifecycleAttempt {
		if result := check(); result.Disposition != authorityrpc.AttemptComplete {
			return result
		}
		r, callErr := m.rpc.CallRead(attempt, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
		if callErr != nil {
			return authorityrpc.ClassifyLifecycleAttempt(callErr)
		}
		if r != nil && r.GetSessionTerminal() {
			return authorityrpc.ClassifyLifecycleAttempt(authorityrpc.ErrSessionEnded)
		}
		if r == nil || r.GetUncertain() {
			return authorityrpc.ClassifyLifecycleAttempt(authorityrpc.ErrTransportUncertain)
		}
		if r.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
			return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete}
		}
		if r.GetFailure() != 0 || r.GetErrno() != 0 {
			return authorityrpc.ClassifyLifecycleAttempt(authorityrpc.ErrSessionEnded)
		}
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete}
	})
	if validation.Disposition != authorityrpc.LifecycleCompleted {
		setResult(validation)
		return o, validation.Err
	}
	if !d.AuthorizationDeadline().After(time.Now()) {
		return o, fail(mountenrollment.ErrDefinitiveDenial)
	}
	recoveryCtx := context.WithValue(ctx, workspaceRecoveryKey{}, proof)
	if w.renewer != nil {
		if err = w.renewer.Resume(p); err != nil {
			if failure := w.renewalFailure(); failure != nil {
				return o, fail(failure)
			}
			if errors.Is(err, mountenrollment.ErrPermitObsolete) {
				if _, lost := m.workspace.Recovery(g, serial); lost != nil {
					phase = authorityrpc.ClassifyLifecycleAttempt(lost)
					return o, lost
				}
			}
			return o, fail(err)
		}
		w.renewer.RefreshNow()
	}
	for {
		if result := waitReady(); result.Disposition != authorityrpc.LifecycleCompleted {
			setResult(result)
			return o, result.Err
		}
		result := m.retryWorkspaceSubscribe(recoveryCtx)
		if result.Disposition != authorityrpc.LifecycleCompleted {
			setResult(result)
			return o, result.Err
		}
		if w.renewer != nil {
			result = authorityrpc.RetryLifecycleAttempts(recoveryCtx, m.requestTimeout, func(attempt context.Context) authorityrpc.LifecycleAttempt {
				if result := check(); result.Disposition != authorityrpc.AttemptComplete {
					return result
				}
				if err := w.renewalFailure(); err != nil {
					return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: err}
				}
				_, _, _, live := m.subscription.currentIncarnation()
				if !live {
					return workspaceSubscribeAttempt(m.subscription.subscribe(attempt))
				}
				if w.renewer.Readiness().Ready(false, p, base64.RawURLEncoding.EncodeToString(m.rpc.SessionID()), d.AuthorizationDeadline()) {
					return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete}
				}
				return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptPending}
			})
			if result.Disposition != authorityrpc.LifecycleCompleted {
				setResult(result)
				return o, result.Err
			}
		}
		// Persist unresolved/unobserved before any usable prepared publication.
		// Retained worker/request inventory lives until publication succeeds.
		w.outcome = control.UnknownOutcome()
		w.newInterval()
		o, phase = m.publishWorkspace(ctx, g, serial, true, false, authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete})
		switch phase.Disposition {
		case authorityrpc.AttemptPending, authorityrpc.AttemptColdReset:
			continue
		case authorityrpc.AttemptComplete:
			w.cold = false
			w.coldOutcome = &pb.MountOutcome{Durability: "durable", Observation: "observed", Release: "released"}
			w.workers, w.parkedRequests = nil, nil
			m.delegations.StartWriteback()
			m.subscription.releaseWorkspaceOwnership()
			w.keepalive.resume()
			published = true
			return o, nil
		default:
			return o, phase.Err
		}
	}
}

func (m *Mount) SuspendWorkspace(ctx context.Context, g, serial uint64, deadline time.Time) (o WorkspaceObservation, err error) {
	w, d, err := m.workspaceDependencies()
	if err != nil {
		o = m.workspaceObservation(g, serial)
		o.Result = authorityrpc.LifecycleCompletion(ctx, err)
		return o, err
	}
	if err = w.enter(ctx); err != nil {
		o = m.workspaceObservation(g, serial)
		o.Result = authorityrpc.LifecycleCompletion(ctx, err)
		return o, err
	}
	defer func() { <-w.lane }()
	cold, phase := m.suspendWorkspace(ctx, w, d, g, serial, deadline)
	o, _ = m.publishWorkspace(ctx, g, serial, false, cold, phase)
	return o, o.Result.Err
}

func (m *Mount) suspendWorkspace(ctx context.Context, w *workspaceLifecycle, d workspaceDispatch, g, serial uint64, deadline time.Time) (bool, authorityrpc.LifecycleAttempt) {
	phase := m.workspacePublication(ctx, g, serial, false)
	if phase.Disposition != authorityrpc.AttemptComplete {
		return false, phase
	}
	cold, err := m.cutWorkspace(ctx, w, d, deadline)
	if err != nil {
		phase = authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptFailed, Err: err}
	}
	return cold, phase
}

func (m *Mount) cutWorkspace(ctx context.Context, w *workspaceLifecycle, d workspaceDispatch, deadline time.Time) (cold bool, err error) {
	// Entry admission and the served decision share raw.mu. Fence the buffer
	// before releasing it, so a concurrent first entry cannot escape re-park.
	m.raw.mu.Lock()
	unserved := !w.servedSinceCold.Load()
	repark := w.cold || w.coldOutcome != nil && unserved
	var p workspaceDrainPermit
	if !repark {
		p = m.workspaceFS().captureWorkspaceDrain(deadline)
	}
	m.delegations.epoch.RLock()
	m.delegations.buf.FenceAdmissions()
	m.delegations.epoch.RUnlock()
	m.raw.mu.Unlock()
	if repark {
		if err = m.parkWorkspace(ctx, w, d); err != nil {
			return false, err
		}
		if err = m.workspaceFS().captureWorkspaceReplies().wait(ctx); err != nil {
			return false, err
		}
		if w.coldOutcome != nil {
			w.outcome = proto.Clone(w.coldOutcome).(*pb.MountOutcome)
		}
		return m.finishWorkspaceCold(w, d)
	}
	w.outcome = control.UnknownOutcome()
	if err = m.drainWorkspaceDispatch(d, p); err != nil {
		return false, err
	}
	w.workers = nil
	for group := 0; group < 6; group++ {
		w.workerDisposition(group, "unresolved")
	}
	if err = m.subscription.takeWorkspaceOwnership(ctx); err != nil {
		return false, err
	}
	w.workerDisposition(0, "parked")
	if w.renewer != nil {
		if err = errors.Join(w.renewer.Park(ctx), w.renewalFailure()); err != nil {
			return false, err
		}
	}
	if err = w.keepalive.park(ctx); err != nil {
		return false, err
	}
	w.workerDisposition(1, "parked")
	p.buffer.FenceAdmissions()
	cohort := m.workspaceFS().captureWorkspaceReplies()
	if w.callbacks == nil {
		w.callbacks = startWorkspaceJoin(func() error { m.epochMu.Lock(); m.epochMu.Unlock(); return nil })
	}
	if err = w.callbacks.wait(ctx); err != nil {
		return false, err
	}
	if err = cohort.wait(ctx); err != nil {
		return false, err
	}
	w.workerDisposition(2, "settled")
	if w.withdrawal == nil {
		w.withdrawal = startWorkspaceJoin(func() error { return m.raw.invalidateAllCaches(m.ctx) })
	}
	if err = w.withdrawal.wait(ctx); err != nil {
		return false, err
	}
	w.workerDisposition(3, "settled")
	cut, cutErr := m.delegations.SuspendCut(ctx, p)
	w.outcome = &pb.MountOutcome{Durability: cut.durability, Observation: "observed", Release: cut.release}
	if cutErr != nil {
		if ctx.Err() != nil {
			return false, cutErr
		}
		if !errors.Is(cutErr, errSubscriptionExpired) && !errors.Is(cutErr, context.DeadlineExceeded) {
			return false, cutErr
		}
		// No elapsed drain is renewed. Withdrawal has completed; reset below
		// accounts for any unprovable accepted tail and abandons the old grant.
		w.abandonGrant()
	}
	w.workerDisposition(4, "settled")
	if err = m.subscription.parkWorkspaceControl(ctx); err != nil {
		return false, err
	}
	w.workerDisposition(5, "settled")
	if err = d.ParkDispatch(ctx); err != nil {
		return false, err
	}

	if cause := m.rpc.SessionEndCause(); cause != nil {
		return false, cause
	}
	if m.isRevoked() || m.ctx.Err() != nil {
		return false, errors.New("fusev3: terminal worker prevents healthy cold proof")
	}
	return m.finishWorkspaceCold(w, d)
}

func (m *Mount) drainWorkspaceDispatch(d workspaceDispatch, p workspaceDrainPermit) error {
	return d.DrainDispatch(func() error {
		if err := m.ctx.Err(); err != nil {
			return err
		}
		if !p.allows(p.buffer, p.incarnation, m.subscription.config.clock.Now()) {
			return errors.Join(authorityrpc.ErrDispatchExpired, errSubscriptionExpired)
		}
		return nil
	})
}

func (m *Mount) prepareWorkspaceClose() error {
	if m.workspaceLifecycle == nil || !m.delegations.hasRetainedEntries() || m.rpc.SessionEndCause() != nil {
		return nil
	}
	_, d, err := m.workspaceDependencies()
	if err != nil {
		return err
	}
	// Exact kernel removal has closed frontend admission. Its accepted tail
	// remains owned by the old grant, not the now-defeated serving predicate.
	// Capture never refreshes the subscription's original conservative horizon.
	p := m.workspaceFS().captureWorkspaceDrain(m.subscription.config.clock.Now().Add(m.subscription.shutdownBudget()))
	return m.drainWorkspaceDispatch(d, p)
}

// Both a full cut and a re-acknowledgment retire cache ownership, then capture
// current cleanup and exact-request evidence. The physical cut is not repeated.
func (m *Mount) finishWorkspaceCold(w *workspaceLifecycle, d workspaceDispatch) (bool, error) {
	m.delegations.epoch.Lock()
	m.delegations.writebackStarted = false
	m.delegations.epoch.Unlock()
	m.delegations.FenceSubscription("workspace cold suspension")
	m.subscription.mu.Lock()
	m.subscription.active = false
	m.subscription.workspaceProof = nil
	failure := m.subscription.workspaceFailure
	m.subscription.mu.Unlock()
	if failure != nil {
		return false, failure
	}
	if w.outcome == nil {
		w.outcome = control.UnknownOutcome()
	}
	w.outcome.Observation = "observed"
	if w.outcome.Durability == "unresolved" {
		w.outcome.Durability = "durable"
	}
	if w.outcome.Release == "unresolved" {
		w.outcome.Release = "abandoned"
	}
	if e := w.evidence.Load(); e != nil {
		if len(e.loss) > 0 {
			w.outcome.Durability = "lost"
		}
		if e.abandoned {
			w.outcome.Release = "abandoned"
		}
	}
	w.workers = nil
	for group := 0; group < 6; group++ {
		w.workerDisposition(group, "joined; cache ownership withdrawn")
	}

	w.parkedRequests = d.DispatchSnapshot().Owners
	m.delegations.closeMu.Lock()
	w.outcome.CleanupDebt = uint64(m.delegations.closePending)
	m.delegations.closeMu.Unlock()
	if m.reclaim != nil {
		w.outcome.CleanupDebt += uint64(m.reclaim.debt())
	}
	for i, owner := range w.parkedRequests {
		if owner.Applying {
			return false, errors.New("fusev3: unresolved applying owner at cold boundary")
		}
		var request authoritypb.Request
		if proto.Unmarshal(owner.Body, &request) != nil {
			return false, errors.New("fusev3: invalid parked owner evidence")
		}
		operation := request.ProtoReflect().WhichOneof(request.ProtoReflect().Descriptor().Oneofs().ByName("body"))
		if operation == nil {
			return false, errors.New("fusev3: parked owner has no operation")
		}
		w.workers = append(w.workers, workspaceWorker{fmt.Sprintf("%s owner %d (%d/%d)", operation.Name(), i, owner.Identity.Slot, owner.Identity.Sequence), "retained exact request behind dispatch fence"})
	}
	// These services are retained, not joined or claimed individually parked.
	// Their only outward effects require the session dispatch fence just joined.
	for _, name := range workspaceWorkerGroups[6] {
		w.workers = append(w.workers, workspaceWorker{name, "retained; outward dispatch fenced"})
	}
	if stats := m.delegations.buf.Stats(); stats.Entries != 0 {
		return false, errors.New("fusev3: successor buffer is not empty")
	}
	w.workers = append(w.workers, workspaceWorker{"empty successor scheduler", "empty; writeback not started"})
	w.workers = append(w.workers, workspaceWorker{"terminal withdrawal/close", "not requested; live mount and session checked"})
	w.cold = true
	w.coldOutcome = proto.Clone(w.outcome).(*pb.MountOutcome)
	w.servedSinceCold.Store(false)
	w.kernelColdReady.Store(true)
	w.callbacks, w.withdrawal = nil, nil
	return true, nil
}

// Re-parking is owned by the mount, not by the waiter that lost its generation.
func (m *Mount) parkWorkspace(ctx context.Context, w *workspaceLifecycle, d workspaceDispatch) error {
	var err error
	err = errors.Join(err, m.subscription.takeWorkspaceOwnership(ctx))
	if w.renewer != nil {
		err = errors.Join(err, w.renewer.Park(ctx), w.renewalFailure())
	}
	err = errors.Join(err, w.keepalive.park(ctx), m.subscription.parkWorkspaceControl(ctx), d.ParkDispatch(ctx))
	if cause := m.rpc.SessionEndCause(); cause != nil {
		err = errors.Join(err, cause)
	}
	return err
}

func (m *Mount) retryWorkspaceSubscribe(ctx context.Context) authorityrpc.LifecycleResult {
	return authorityrpc.RetryLifecycleAttempts(ctx, m.requestTimeout, func(attempt context.Context) authorityrpc.LifecycleAttempt {
		// subscribe withdraws/reset before each new empty-cursor request.
		return workspaceSubscribeAttempt(m.subscription.subscribe(attempt))
	})
}
func workspaceSubscribeAttempt(err error) authorityrpc.LifecycleAttempt {
	result := authorityrpc.ClassifyLifecycleAttempt(err)
	if result.Disposition == authorityrpc.AttemptFailed && subscriptionResetAttempt(err) {
		return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptColdReset, Err: err}
	}
	return result
}

// Every cause must describe an unusable cache attempt. A reset joined with an
// independent local/authorization/protocol failure is still a failed job.
func subscriptionResetAttempt(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !subscriptionResetAttempt(cause) {
				return false
			}
		}
		return true
	}
	if err == authorityrpc.ErrSubscriptionReset || err == errSubscriptionExpired || authorityrpc.TransientTransport(err) {
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return subscriptionResetAttempt(wrapped.Unwrap())
	}
	return false
}

// A closed serving serial still admits the fixed old cleanup cut. Only an
// acknowledged transport park makes a synchronous cold FLUSH impossible.
func (m *Mount) workspaceDispatchParked() bool {
	if m.workspace == nil {
		return false
	}
	e, ok := m.rpc.(*epochRPC)
	if !ok {
		return false
	}
	d, ok := e.current().(interface {
		DispatchSnapshot() authorityrpc.DispatchSnapshot
	})
	return ok && d.DispatchSnapshot().Parked
}
