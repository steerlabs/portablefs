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
	Generation, GateSerial, SubscriptionIncarnation uint64
	Prepared, ColdComplete                          bool
	Loss                                            []*pb.Loss
	Outcome                                         *pb.MountOutcome
	Workers                                         []workspaceWorker
	ParkedRequests                                  []authorityrpc.DispatchOwner
}
type workspaceEvidence struct {
	loss      []*pb.Loss
	overflow  bool
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
	preparedOnce   bool
	cold           bool
	withdrawal     *workspaceJoin
	callbacks      *workspaceJoin
	outcome        *pb.MountOutcome
	workers        []workspaceWorker
	parkedRequests []authorityrpc.DispatchOwner
	keepalive      workspaceAttempt
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
	mu     sync.Mutex
	parked bool
	cancel context.CancelFunc
	done   chan struct{}
}

func (a *workspaceAttempt) start(ctx context.Context) (context.Context, func(), bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.parked {
		return ctx, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	a.cancel, a.done = cancel, done
	return ctx, func() { cancel(); a.mu.Lock(); a.cancel, a.done = nil, nil; close(done); a.mu.Unlock() }, true
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
			next.overflow = old.overflow
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
		var overflow bool
		if len(next.loss) > 1 && next.loss[len(next.loss)-2].GetAggregated() {
			a, b := next.loss[len(next.loss)-2], next.loss[len(next.loss)-1]
			next.loss[len(next.loss)-2] = &pb.Loss{Sequence: max(a.Sequence, b.Sequence), AcceptedEntries: a.AcceptedEntries + b.AcceptedEntries, AcceptedBytes: a.AcceptedBytes + b.AcceptedBytes, Reason: control.AggregateReason, Aggregated: true}
			next.loss = next.loss[:len(next.loss)-1]
			overflow = true
		} else {
			next.loss, overflow, _ = control.BoundLoss(next.loss)
		}
		next.overflow = next.overflow || overflow
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
			next.loss, next.overflow = old.loss, old.overflow
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
func (m *Mount) completeWorkspace(g, serial uint64, ready, cold bool, err error) (WorkspaceObservation, error) {
	o := m.workspaceObservation(g, serial)
	w := m.workspaceLifecycle
	if w == nil {
		return o, err
	}
	if e := w.evidence.Load(); e != nil && e.overflow {
		err = errors.Join(err, errors.New("fusev3: workspace loss ledger exhausted"))
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
	if persistErr := w.persist(o); persistErr != nil {
		o.Prepared, o.ColdComplete = false, false
		err = errors.Join(err, fmt.Errorf("persist workspace outcome: %w", persistErr))
	}
	if o.Prepared || o.ColdComplete {
		proof, proofErr := m.workspace.Recovery(g, serial)
		if proofErr != nil || m.isRevoked() || m.ctx.Err() != nil || m.rpc.SessionEndCause() != nil {
			o.Prepared, o.ColdComplete = false, false
			err = errors.Join(err, errors.New("fusev3: lifecycle proof overtaken before publication"))
		}

		if o.Prepared {
			permit := mountenrollment.Permit{Generation: g, GateSerial: serial}
			_, dispatch, dependencyErr := m.workspaceDependencies()
			readinessErr := w.clock.Check(permit)
			if dependencyErr != nil {
				readinessErr = errors.Join(readinessErr, dependencyErr)
			} else {
				deadline := dispatch.AuthorizationDeadline()
				if !deadline.After(time.Now()) {
					readinessErr = errors.Join(readinessErr, mountenrollment.ErrDefinitiveDenial)
				}
				if w.renewer != nil && !w.renewer.Readiness().Ready(false, permit, base64.RawURLEncoding.EncodeToString(m.rpc.SessionID()), deadline) {
					readinessErr = errors.Join(readinessErr, errors.New("fusev3: renewal readiness changed during outcome persistence"), w.renewer.Failure())
				}
			}
			if readinessErr != nil {
				o.Prepared = false
				err = errors.Join(err, readinessErr)
			}
		}
		m.subscription.mu.Lock()
		if o.Prepared {
			live := m.subscription.controlLiveLocked()
			same := m.subscription.workspaceProof != nil && m.subscription.workspaceProof.Serial() == proof.Serial()
			if !live || !same {
				o.Prepared = false
				err = errors.Join(err, errors.New("fusev3: prepared subscription expired before publication"))
			}
		}
		if o.ColdComplete && (m.subscription.workspaceDrain == nil || !m.subscription.config.clock.Now().Before(m.subscription.workspaceDrain.deadline)) {
			o.ColdComplete = false
			err = errors.Join(err, errSubscriptionExpired)
		}
		m.subscription.mu.Unlock()
	}
	if cold {
		w.cold = o.ColdComplete
	}
	w.observation.Store(&o)
	return o, err
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
		return m.workspaceObservation(g, serial), err
	}
	if err = w.enter(ctx); err != nil {
		return m.workspaceObservation(g, serial), err
	}
	defer func() { <-w.lane }()
	ready := false
	defer func() { o, err = m.completeWorkspace(g, serial, ready, false, err) }()
	if recover {
		if !w.cold {
			return o, errors.New("fusev3: recovery requires a completed cold cut")
		}
		w.cold = false
		w.preparedOnce = true
	} else {
		if w.preparedOnce {
			return o, errors.New("fusev3: Prepare is consumed")
		}
		w.preparedOnce = true
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
	err = authorityrpc.RetryLifecycle(ctx, m.requestTimeout, func(attempt context.Context) error {
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
	if err != nil {
		return o, err
	}
	if !d.AuthorizationDeadline().After(time.Now()) {
		return o, mountenrollment.ErrDefinitiveDenial
	}
	recoveryCtx := context.WithValue(ctx, workspaceRecoveryKey{}, proof)
	if err = authorityrpc.RetryLifecycle(recoveryCtx, m.requestTimeout, m.subscription.subscribe); err != nil {
		return o, err
	}
	if w.renewer != nil {
		if err = w.renewer.Resume(p); err != nil {
			return o, err
		}
		w.renewer.RefreshNow()
		err = authorityrpc.RetryLifecycle(recoveryCtx, m.requestTimeout, func(attempt context.Context) error {
			if err := check(); err != nil {
				return err
			}
			_, _, _, live := m.subscription.currentIncarnation()
			if !live {
				if err := m.subscription.subscribe(attempt); err != nil {
					return err
				}
			}
			if err := w.renewer.Failure(); err != nil {
				return err
			}
			r := w.renewer.Readiness()
			if r.Ready(false, p, base64.RawURLEncoding.EncodeToString(m.rpc.SessionID()), d.AuthorizationDeadline()) {
				return nil
			}
			return authorityrpc.ErrTransportUncertain
		})
		if err != nil {
			return o, err
		}
	}

	// Persist the new interval as unobserved BEFORE its proof can be opened.
	w.outcome = control.UnknownOutcome()
	w.cold = false
	m.subscription.mu.Lock()
	m.subscription.workspaceFailure = nil
	m.subscription.mu.Unlock()
	if err = check(); err != nil {
		return o, err
	}
	m.delegations.StartWriteback()
	m.subscription.releaseWorkspaceOwnership()
	w.keepalive.resume()
	w.workers = nil
	w.parkedRequests = nil
	ready = true
	return o, nil
}

func (m *Mount) SuspendWorkspace(ctx context.Context, g, serial uint64, deadline time.Time) (o WorkspaceObservation, err error) {
	w, d, err := m.workspaceDependencies()
	if err != nil {
		return m.workspaceObservation(g, serial), err
	}
	if err = w.enter(ctx); err != nil {
		return m.workspaceObservation(g, serial), err
	}
	defer func() { <-w.lane }()
	cold := false
	defer func() { o, err = m.completeWorkspace(g, serial, false, cold, err) }()
	if _, err = m.workspace.Recovery(g, serial); err != nil {
		return o, err
	}
	w.cold = false
	w.outcome = control.UnknownOutcome()
	w.workers = nil
	for group := range workspaceWorkerGroups {
		w.workerDisposition(group, "unresolved")
	}
	if err = m.subscription.takeWorkspaceOwnership(ctx); err != nil {
		return o, err
	}
	w.workerDisposition(0, "parked")
	if w.renewer != nil {
		if err = w.renewer.Park(ctx); err != nil {
			return o, err
		}
		if err = w.renewer.Failure(); err != nil {
			return o, err
		}
	}
	if err = w.keepalive.park(ctx); err != nil {
		return o, err
	}
	w.workerDisposition(1, "parked")
	p := m.workspaceFS().captureWorkspaceDrain(deadline)
	if !p.allows(p.buffer, p.incarnation, m.subscription.config.clock.Now()) {
		return o, errSubscriptionExpired
	}
	ctx, cancel := context.WithTimeout(ctx, p.deadline.Sub(m.subscription.config.clock.Now()))
	defer cancel()
	p.buffer.FenceAdmissions()
	cohort := m.workspaceFS().captureWorkspaceReplies()
	if w.callbacks == nil {
		w.callbacks = startWorkspaceJoin(func() error { m.epochMu.Lock(); m.epochMu.Unlock(); return nil })
	}
	if err = w.callbacks.wait(ctx); err != nil {
		return o, err
	}
	if err = cohort.wait(ctx); err != nil {
		return o, err
	}
	w.workerDisposition(2, "settled")
	if w.withdrawal == nil {
		w.withdrawal = startWorkspaceJoin(func() error { return m.raw.invalidateAllCaches(ctx) })
	}
	if err = w.withdrawal.wait(ctx); err != nil {
		return o, err
	}
	w.workerDisposition(3, "settled")
	cut, cutErr := m.delegations.SuspendCut(ctx, p)
	w.outcome = &pb.MountOutcome{Durability: cut.durability, Observation: "observed", Release: cut.release}
	if cutErr != nil {
		return o, cutErr
	}
	w.workerDisposition(4, "settled")
	if err = m.subscription.parkWorkspaceControl(ctx); err != nil {
		return o, err
	}
	w.workerDisposition(5, "settled")
	if evidence := w.evidence.Load(); evidence != nil && evidence.abandoned {
		return o, errors.New("fusev3: abandoned grant outcome prevents healthy cold proof")
	}
	if err = d.ParkDispatch(ctx); err != nil {
		return o, err
	}
	w.workerDisposition(6, "parked")
	if cause := m.rpc.SessionEndCause(); cause != nil {
		return o, cause
	}
	if m.isRevoked() || m.ctx.Err() != nil {
		return o, errors.New("fusev3: terminal worker prevents healthy cold proof")
	}
	if !m.subscription.config.clock.Now().Before(p.deadline) {
		return o, errSubscriptionExpired
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
	w.workerDisposition(7, "parked")
	w.workerDisposition(8, "settled")
	w.parkedRequests = d.DispatchSnapshot().Owners
	m.delegations.closeMu.Lock()
	w.outcome.CleanupDebt = uint64(m.delegations.closePending)
	m.delegations.closeMu.Unlock()
	for _, owner := range w.parkedRequests {
		if owner.Applying {
			return o, errors.New("fusev3: unresolved applying owner at cold boundary")
		}
		w.outcome.CleanupDebt++
	}
	w.cold = true
	w.callbacks, w.withdrawal = nil, nil
	cold = true
	return o, nil
}
