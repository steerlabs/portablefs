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

// The real clock/protected-path driver is intentionally not wired by this PR.
// A clock must both await correction and synchronously reject stale evidence at
// dispatch. Neither a missing owner nor a goroutine start constitutes readiness.
type workspaceClock interface {
	Wait(context.Context, mountenrollment.Permit) error
	Check(mountenrollment.Permit) error
}
type workspaceDispatch interface {
	ParkDispatch(context.Context) error
	ResumeDispatch(func() error) error
	DispatchSnapshot() authorityrpc.DispatchSnapshot
	AuthorizationDeadline() time.Time
}
type workspaceWorker struct{ Name, Disposition string }
type WorkspaceObservation struct {
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
	observation atomic.Pointer[WorkspaceObservation]
	lane        chan struct{}
	clock       workspaceClock
	renewer     *mountenrollment.Renewer
	standalone  bool
	persist     func(WorkspaceObservation) error
	evidence    atomic.Pointer[workspaceEvidence]
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
	coldOutcome     *pb.MountOutcome
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
	if r.Entries == 0 {
		return
	}
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
	if prior == nil {
		return m.workspaceObservation(0, 0)
	}
	o := m.workspaceObservation(prior.Generation, prior.GateSerial)
	o.Prepared, o.ColdComplete = prior.Prepared, prior.ColdComplete
	if o.Prepared {
		proof, err := m.workspace.Recovery(o.Generation, o.GateSerial)
		permit := mountenrollment.Permit{Generation: o.Generation, GateSerial: o.GateSerial}
		_, _, _, live := m.subscription.currentIncarnation()
		if err != nil && !m.workspace.Installed(proof) || !live || m.workspaceLifecycle.clock.Check(permit) != nil || m.isRevoked() {
			o.Prepared = false
		}
	}
	return o
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
func (m *Mount) completeWorkspace(ctx context.Context, g, serial uint64, ready, cold bool, err error) (WorkspaceObservation, error) {
	o := m.workspaceObservation(g, serial)
	w := m.workspaceLifecycle
	if w == nil {
		return o, err
	}
	if e := w.evidence.Load(); e != nil {
		err = errors.Join(err, e.failure)
	}
	o.Prepared, o.ColdComplete = ready && err == nil, cold && err == nil
	if w.outcome != nil {
		o.Outcome = proto.Clone(w.outcome).(*pb.MountOutcome)
	}
	if evidence := w.evidence.Load(); evidence != nil && evidence.abandoned {
		o.Outcome.Release = "abandoned"
		o.Outcome.Observation = "observed"
	}
	o.Workers = append([]workspaceWorker(nil), w.workers...)
	o.ParkedRequests = nil
	for _, request := range w.parkedRequests {
		request.Body = append([]byte(nil), request.Body...)
		o.ParkedRequests = append(o.ParkedRequests, request)
	}
	err = errors.Join(err, m.validateWorkspacePublication(g, serial, o.Prepared || o.ColdComplete, o.Prepared))
	o.Result = authorityrpc.LifecycleCompletion(ctx, err)
	err = o.Result.Err
	if o.Result.Disposition != authorityrpc.LifecycleCompleted {
		o.Prepared, o.ColdComplete = false, false
	}
	persistedPrepared, persistedCold := o.Prepared, o.ColdComplete
	if persistErr := w.persist(o); persistErr != nil {
		o.Prepared, o.ColdComplete = false, false
		err = errors.Join(err, fmt.Errorf("persist workspace outcome: %w", persistErr))
	} else {
		// Persistence is I/O. Recheck the exact proof and persist a refusal if
		// any independent owner changed it while the record was being written.
		err = errors.Join(err, m.validateWorkspacePublication(g, serial, o.Prepared || o.ColdComplete, o.Prepared))
		o.Result = authorityrpc.LifecycleCompletion(ctx, err)
		err = o.Result.Err
		if o.Result.Disposition != authorityrpc.LifecycleCompleted {
			o.Prepared, o.ColdComplete = false, false
		}
		if persistedPrepared != o.Prepared || persistedCold != o.ColdComplete {
			if persistErr := w.persist(o); persistErr != nil {
				err = errors.Join(err, fmt.Errorf("persist workspace refusal: %w", persistErr))
			}
		}
	}
	o.Result = authorityrpc.LifecycleCompletion(ctx, err)
	w.observation.Store(&o)
	return o, err
}

func (m *Mount) validateWorkspacePublication(g, serial uint64, publish, prepared bool) error {
	if !publish {
		return nil
	}
	proof, err := m.workspace.Recovery(g, serial)
	if err != nil {
		return err
	}
	if m.isRevoked() || m.ctx.Err() != nil {
		return errors.New("fusev3: terminal mount before lifecycle publication")
	}
	if cause := m.rpc.SessionEndCause(); cause != nil {
		return cause
	}
	if !prepared {
		return nil
	} // A completed cold cut has no live-cache horizon.
	w := m.workspaceLifecycle
	p := mountenrollment.Permit{Generation: g, GateSerial: serial}
	if err := w.clock.Check(p); err != nil {
		return err
	}
	_, d, err := m.workspaceDependencies()
	if err != nil {
		return err
	}
	deadline := d.AuthorizationDeadline()
	if !deadline.After(time.Now()) {
		return mountenrollment.ErrDefinitiveDenial
	}
	if w.renewer != nil && !w.renewer.Readiness().Ready(false, p, base64.RawURLEncoding.EncodeToString(m.rpc.SessionID()), deadline) {
		return errors.Join(errors.New("fusev3: enrollment readiness changed before publication"), w.renewer.Failure())
	}
	// Expiry advances the subscription generation; this is a writer check.
	m.subscription.mu.Lock()
	live := m.subscription.controlLiveLocked()
	same := m.subscription.workspaceProof != nil && m.subscription.workspaceProof.Serial() == proof.Serial()
	m.subscription.mu.Unlock()
	if !live || !same {
		return errSubscriptionExpired
	}
	return nil
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
	ready := false
	defer func() {
		if !ready {
			err = errors.Join(err, m.parkWorkspace(m.ctx, w, d))
		}
		o, err = m.completeWorkspace(ctx, g, serial, ready, false, err)
		if o.Prepared {
			w.cold = false
			w.coldOutcome = &pb.MountOutcome{Durability: "durable", Observation: "observed", Release: "released"}
			m.delegations.StartWriteback()
			m.subscription.releaseWorkspaceOwnership()
			w.keepalive.resume()
		} else {
			parkErr := m.parkWorkspace(m.ctx, w, d)
			if parkErr != nil {
				o, err = m.completeWorkspace(ctx, g, serial, false, false, errors.Join(err, parkErr))
			}
		}
	}()
	if recover {
		if !w.cold {
			return o, errors.New("fusev3: recovery requires a completed cold cut")
		}
		w.preparedOnce = true
	} else {
		if w.preparedOnce {
			return o, errors.New("fusev3: Prepare is consumed")
		}
		w.preparedOnce = true
		// Initial preparation also owns an interruptible, retained cold cut.
		if _, err = m.suspendWorkspace(ctx, w, d, g, serial, m.subscription.config.clock.Now().Add(m.requestTimeout)); err != nil {
			return o, err
		}
	}
	proof, err := m.workspace.Recovery(g, serial)
	if err != nil {
		return o, err
	}
	if err = m.subscription.takeWorkspaceOwnership(ctx); err != nil {
		return o, err
	}
	p := mountenrollment.Permit{Generation: g, GateSerial: serial}
	if err = w.clock.Wait(ctx, p); err != nil {
		return o, err
	}
	check := func() error {
		if err := w.clock.Check(p); err != nil {
			return err
		}
		if m.workspace.Installed(proof) {
			return nil
		}
		return m.workspace.Recover(proof)
	}
	// Entry/installer admission owns the exact serial. The transport's
	// check must also admit settlement of already-assigned old operations
	// after Close; applying that serving serial to replay would erase them.
	if err = check(); err != nil {
		return o, err
	}
	if err = d.ResumeDispatch(func() error { return w.clock.Check(p) }); err != nil {
		return o, err
	}
	// KeepAlive is real same-session authorization validation; never recoverEpoch
	// or Attach. A bounded attempt timeout cannot become a terminal verdict.
	retry := authorityrpc.RetryLifecycle(ctx, m.requestTimeout, func(attempt context.Context) error {
		if err := check(); err != nil {
			return err
		}
		if cause := m.rpc.SessionEndCause(); cause != nil {
			return cause
		}
		r, err := m.rpc.CallRead(attempt, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
		if err != nil {
			return err
		}
		if r != nil && r.GetSessionTerminal() {
			return authorityrpc.ErrSessionEnded
		}
		if r == nil || r.GetUncertain() {
			return authorityrpc.ErrTransportUncertain
		}
		// Runtime credential/authorization validation precedes the Linux
		// coherence check. Its nonterminal coherence refusal validates this
		// session, while requiring the fresh cold Subscribe below.
		if r.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE && !r.GetSessionTerminal() {
			return nil
		}
		if r.GetFailure() != 0 || r.GetErrno() != 0 {
			return fmt.Errorf("fusev3: workspace session validation refused: %w", authorityrpc.ErrSessionEnded)
		}
		return nil
	})
	err = retry.Err
	if err != nil {
		return o, err
	}
	if !d.AuthorizationDeadline().After(time.Now()) {
		return o, mountenrollment.ErrDefinitiveDenial
	}
	recoveryCtx := context.WithValue(ctx, workspaceRecoveryKey{}, proof)
	if retry = m.retryWorkspaceSubscribe(recoveryCtx); retry.Err != nil {
		err = retry.Err
		return o, err
	}
	if w.renewer != nil {
		if err = w.renewer.Resume(p); err != nil {
			return o, err
		}
		w.renewer.RefreshNow()
		retry = authorityrpc.RetryLifecycleAttempts(recoveryCtx, m.requestTimeout, func(attempt context.Context) authorityrpc.LifecycleAttempt {
			if err := check(); err != nil {
				return authorityrpc.ClassifyLifecycleAttempt(err)
			}
			_, _, _, live := m.subscription.currentIncarnation()
			if !live {
				result := workspaceSubscribeAttempt(m.subscription.subscribe(attempt))
				if result.Disposition != authorityrpc.AttemptComplete {
					return result
				}
			}
			if err := w.renewer.Failure(); err != nil {
				return authorityrpc.ClassifyLifecycleAttempt(err)
			}
			if w.renewer.Readiness().Ready(false, p, base64.RawURLEncoding.EncodeToString(m.rpc.SessionID()), d.AuthorizationDeadline()) {
				return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptComplete}
			}
			return authorityrpc.LifecycleAttempt{Disposition: authorityrpc.AttemptPending}
		})
		err = retry.Err
		if err != nil {
			return o, err
		}
	}

	// Persist the new interval as unobserved BEFORE its proof can be opened.
	w.outcome = control.UnknownOutcome()
	w.newInterval()
	m.subscription.mu.Lock()
	m.subscription.workspaceFailure = nil
	m.subscription.mu.Unlock()
	if err = check(); err != nil {
		return o, err
	}
	w.workers = nil
	w.parkedRequests = nil
	ready = true
	return o, nil
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
	cold, runErr := m.suspendWorkspace(ctx, w, d, g, serial, deadline)
	o, err = m.completeWorkspace(ctx, g, serial, false, cold, runErr)
	return o, err
}

func (m *Mount) suspendWorkspace(ctx context.Context, w *workspaceLifecycle, d workspaceDispatch, g, serial uint64, deadline time.Time) (cold bool, err error) {
	if _, err = m.workspace.Recovery(g, serial); err != nil {
		return false, err
	}
	// A completed cut remains valid until a new Prepared interval publishes.
	// A repeated Suspend only has to re-park work that recovery resumed.
	if w.cold || w.coldOutcome != nil && !w.servedSinceCold.Load() {
		if err = m.parkWorkspace(ctx, w, d); err != nil {
			return false, err
		}
		w.cold = true
		if w.coldOutcome != nil {
			w.outcome = proto.Clone(w.coldOutcome).(*pb.MountOutcome)
		}
		return true, nil
	}
	w.outcome = control.UnknownOutcome()
	w.workers = nil
	for group := 0; group < 6; group++ {
		w.workerDisposition(group, "unresolved")
	}
	p := m.workspaceFS().captureWorkspaceDrain(deadline)
	if err = m.subscription.takeWorkspaceOwnership(ctx); err != nil {
		return false, err
	}
	w.workerDisposition(0, "parked")
	if w.renewer != nil {
		if err = w.renewer.Park(ctx); err != nil {
			return false, err
		}
		if err = w.renewer.Failure(); err != nil {
			return false, err
		}
	}
	if err = w.keepalive.park(ctx); err != nil {
		return false, err
	}
	w.workerDisposition(1, "parked")
	if !p.allows(p.buffer, p.incarnation, m.subscription.config.clock.Now()) {
		return false, errSubscriptionExpired
	}
	ctx, cancel := context.WithTimeout(ctx, p.deadline.Sub(m.subscription.config.clock.Now()))
	defer cancel()
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
		return false, cutErr
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
	if !m.subscription.config.clock.Now().Before(p.deadline) {
		return false, errSubscriptionExpired
	}
	// No applying owner or callback remains. Retire under the existing reset and
	// settlement order; the successor must not dispatch a background flush.
	m.delegations.epoch.Lock()
	m.delegations.writebackStarted = false
	m.delegations.epoch.Unlock()
	m.delegations.FenceSubscription("workspace cold suspension")
	m.subscription.mu.Lock()
	m.subscription.active = false
	m.subscription.workspaceProof = nil
	m.subscription.mu.Unlock()
	w.outcome = &pb.MountOutcome{Durability: "durable", Observation: "observed", Release: "released"}
	if e := w.evidence.Load(); e != nil && len(e.loss) > 0 {
		w.outcome.Durability = "lost"
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
	w.callbacks, w.withdrawal = nil, nil
	return true, nil
}

// Re-parking is owned by the mount, not by the waiter that lost its generation.
func (m *Mount) parkWorkspace(ctx context.Context, w *workspaceLifecycle, d workspaceDispatch) error {
	var err error
	err = errors.Join(err, m.subscription.takeWorkspaceOwnership(ctx))
	if w.renewer != nil {
		err = errors.Join(err, w.renewer.Park(ctx), w.renewer.Failure())
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
