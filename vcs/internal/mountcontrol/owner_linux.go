//go:build linux

package mountcontrol

import (
	"context"
	"crypto/sha256"
	"reflect"
	"sync"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

// Driver runs lifecycle work, never socket requests. ValidateInstall verifies
// first-delivery roles/bootstrap without taking ownership. All three callbacks
// and CheckPermit must exist before this boundary can accept a real job.
type Driver struct {
	Run             func(context.Context, *Job) error
	ValidateInstall func(*Rights, Phase) error
	Install         func(context.Context, *Job, *Rights) (Witness, error)
}

type Facts struct {
	Witness                        Witness
	AuthorizationDeadlineUnixNanos string
	Outcome                        Outcome
	Loss                           []Loss
	Readiness                      *Prepared
}

type actionSlot struct {
	status ActionStatus
	phase  *Phase
	rights *Rights
	done   chan struct{}
}

// Owner is the lifecycle state itself. Its short lock never crosses driver
// work, descriptor disposal, joins or socket I/O. Configuration is immutable
// after publication to the listener.
type Owner struct {
	Driver Driver
	// CheckPermit reads the exact closed permit without blocking or I/O.
	CheckPermit    func(Workspace) bool
	CloseAdmission func()
	Now            func() time.Time

	mu                           sync.Mutex
	job                          *Job
	prepareUsed, closed          bool
	recoveredGeneration          uint64
	lastResume                   [32]byte
	install, voluntary, terminal actionSlot
	facts                        Facts
}

// Job retains the immutable start and its worker until it joins. Kernel slots
// and cumulative evidence belong to the mount, across successive jobs.
type Job struct {
	owner             *Owner
	start             Request
	ctx               context.Context
	cancel            context.CancelFunc
	done              chan struct{}
	running, stopping bool
	state, reason     string
	drainDeadline     time.Time
}

func unknownOutcome() Outcome { return Outcome{"unresolved", "unobserved", "unresolved", "0"} }
func (o *Owner) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}
func semanticStart(q Request) Request {
	w := *q.Workspace
	w.BudgetNanos, w.DrainBudgetNanos = "", ""
	q.Workspace = &w
	return q
}
func clonePhase(p *Phase) *Phase {
	if p == nil {
		return nil
	}
	c := *p
	c.Options = append([]string(nil), p.Options...)
	if p.Removal != nil {
		x := *p.Removal
		c.Removal = &x
	}
	return &c
}
func cloneRequest(q Request) Request {
	w := *q.Workspace
	w.Phase = clonePhase(w.Phase)
	q.Workspace = &w
	return q
}
func (j *Job) Request() Request         { return cloneRequest(j.start) }
func (j *Job) DrainDeadline() time.Time { return j.drainDeadline }

func (o *Owner) cancelJob(q Request) {
	o.mu.Lock()
	var cancel context.CancelFunc
	if o.job != nil && !reflect.DeepEqual(semanticStart(q), semanticStart(o.job.start)) {
		o.job.stopping = true
		cancel = o.job.cancel
	}
	o.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// AdmitFrame is the only framed Close hook. It runs before socket hangup,
// lanes or budgets are inspected, and never writes the supervisor-only memfd.
func (o *Owner) AdmitFrame(q Request, rights *Rights) error {
	err := q.ValidateWorkspace()
	if err == nil {
		err = rights.Validate(q.Operation)
	}
	closeFrame := q.Operation == "workspace-suspend" || q.Operation == "workspace-cleanup"
	if err != nil || closeFrame {
		if o.CloseAdmission != nil {
			o.CloseAdmission()
		}
	}
	if err == nil && closeFrame {
		o.cancelJob(q)
	}
	return err
}
func (o *Owner) Do(ctx context.Context, q Request, rights *Rights) (Response, error) {
	receivedAt := o.now()
	if err := o.AdmitFrame(q, rights); err != nil {
		rights.Close()
		return Response{}, err
	}
	return o.DoAdmitted(ctx, q, rights, receivedAt)
}

// DoAdmitted owns no response history. Acknowledgment follows the synchronized
// transition; completion remains observable even if delivery expires.
func (o *Owner) DoAdmitted(ctx context.Context, q Request, rights *Rights, receivedAt time.Time) (Response, error) {
	defer rights.Close()
	budget, _ := decimal(q.Workspace.BudgetNanos, true)
	deadline := receivedAt.Add(time.Duration(budget))
	o.mu.Lock()
	if err := ctx.Err(); err != nil {
		o.mu.Unlock()
		return Response{}, err
	}
	if !o.now().Before(deadline) {
		o.mu.Unlock()
		return Response{}, context.DeadlineExceeded
	}
	if o.closed {
		o.mu.Unlock()
		return Response{}, context.Canceled
	}
	if q.Operation == "workspace-observe" {
		out, err := o.observeLocked(q)
		o.mu.Unlock()
		return out, err
	}
	if q.Workspace.RequestID == q.Workspace.OperationID {
		out, job, err := o.startLocked(q, receivedAt)
		o.mu.Unlock()
		if err == ErrGrammar && q.Operation != "workspace-suspend" && q.Operation != "workspace-cleanup" && o.CloseAdmission != nil {
			o.CloseAdmission()
		}
		if job != nil {
			go o.run(job)
		}
		return out, err
	}
	if err := o.currentLocked(q); err != nil {
		o.mu.Unlock()
		return Response{}, err
	}
	if q.Operation == "workspace-install-kernel" {
		if err := o.actionLocked(q, &o.install); err != nil {
			o.mu.Unlock()
			return Response{}, err
		}
		if !o.job.running || o.job.state != "kernel-required" || o.job.stopping {
			o.mu.Unlock()
			return Response{}, ErrActionConsumed
		}
		if o.Driver.ValidateInstall == nil || o.Driver.Install == nil {
			o.mu.Unlock()
			return Response{}, ErrUnavailable
		}
		o.mu.Unlock()
		// Validation may inspect descriptors. Revalidate state and permit afterward;
		// no I/O or arbitrary callback runs under the state lock.
		if err := o.Driver.ValidateInstall(rights, *q.Workspace.Phase); err != nil {
			return Response{}, ErrGrammar
		}
		o.mu.Lock()
		if err := ctx.Err(); err != nil {
			o.mu.Unlock()
			return Response{}, err
		}
		if !o.now().Before(deadline) {
			o.mu.Unlock()
			return Response{}, context.DeadlineExceeded
		}
		if err := o.currentLocked(q); err != nil {
			o.mu.Unlock()
			return Response{}, err
		}
		if err := o.actionLocked(q, &o.install); err != nil {
			o.mu.Unlock()
			return Response{}, err
		}
		if !o.job.running || o.job.state != "kernel-required" || o.job.stopping {
			o.mu.Unlock()
			return Response{}, ErrActionConsumed
		}
		if o.closed || o.job.stopping || !o.permitted(q) {
			o.mu.Unlock()
			return Response{}, ErrGrammar
		}
		slot, job := &o.install, o.job
		slot.status.Progress = "running"
		slot.rights = &Rights{FDs: rights.FDs}
		rights.FDs = nil // The acceptance transition moves, rather than duplicates.
		job.state = "preparing"
		owned := slot.rights
		o.mu.Unlock()
		go o.installKernel(job, owned)
		return acknowledgment(q, "accepted"), nil
	}
	slot := &o.voluntary
	if q.Workspace.Phase.Mode == "terminal" {
		slot = &o.terminal
	}
	if err := o.actionLocked(q, slot); err != nil {
		o.mu.Unlock()
		return Response{}, err
	}
	proof := *q.Workspace.Phase.Removal
	if q.Workspace.Phase.Mode == "terminal" && !proof.AbortCompleted {
		o.mu.Unlock()
		return Response{}, ErrGrammar
	}
	slot.status.Progress = "running"
	slot.status.Action.Removal = &proof
	slot.status.Progress = "complete"
	o.job.state = "preparing"
	close(slot.done)
	o.mu.Unlock()
	out := acknowledgment(q, "unmount-recorded")
	out.Workspace.Witness = q.Workspace.Phase.Witness
	return out, nil
}
func acknowledgment(q Request, state string) Response {
	return Response{OK: true, MountInstanceID: q.MountInstanceID, Workspace: &WorkspaceResponse{Binding: q.Workspace.ResponseBinding(), State: state, AuthorizationDeadlineUnixNanos: "0", Outcome: unknownOutcome()}}
}
func (o *Owner) permitted(q Request) bool { return o.CheckPermit != nil && o.CheckPermit(*q.Workspace) }
func (o *Owner) startLocked(q Request, receivedAt time.Time) (Response, *Job, error) {
	id, _ := decimal(q.Workspace.OperationID, true)
	if o.job != nil {
		old, _ := decimal(o.job.start.Workspace.OperationID, true)
		if id < old {
			return Response{}, nil, ErrRetired
		}
		if id == old {
			if !reflect.DeepEqual(semanticStart(q), semanticStart(o.job.start)) {
				return Response{}, nil, ErrGrammar
			}
			return acknowledgment(q, "accepted"), nil, nil
		}
		a, b := q.Workspace, o.job.start.Workspace
		generation, _ := decimal(a.Generation, false)
		oldGeneration, _ := decimal(b.Generation, false)
		serial, _ := decimal(a.GateSerial, false)
		oldSerial, _ := decimal(b.GateSerial, false)
		if q.MountInstanceID != o.job.start.MountInstanceID || a.BootID != b.BootID || a.HostServiceID != b.HostServiceID || a.GuestServiceID != b.GuestServiceID || generation < oldGeneration || serial < oldSerial {
			return Response{}, nil, ErrGrammar
		}
		if o.job.running || o.install.status.Progress == "running" {
			return Response{}, nil, ErrOccupied
		}
	}
	if o.Driver.Run == nil || o.CheckPermit == nil {
		return Response{}, nil, ErrUnavailable
	}
	if !o.permitted(q) {
		return Response{}, nil, ErrGrammar
	}
	if o.terminal.status.Progress == "complete" || o.voluntary.status.Progress == "complete" {
		return Response{}, nil, ErrGrammar
	}
	switch q.Operation {
	case "workspace-prepare":
		if o.prepareUsed || o.job != nil {
			return Response{}, nil, ErrGrammar
		}
	case "workspace-recover":
		generation, _ := decimal(q.Workspace.Generation, false)
		if o.job == nil || o.job.state != "cold" || generation <= o.recoveredGeneration || o.lastResume == sha256.Sum256([]byte(q.Workspace.Transaction)) {
			return Response{}, nil, ErrGrammar
		}
	case "workspace-suspend":
		if o.job != nil && o.job.start.Operation == "workspace-cleanup" {
			return Response{}, nil, ErrGrammar
		}
	case "workspace-cleanup":
		if o.job != nil && o.job.start.Operation == "workspace-cleanup" && (o.job.start.Workspace.Phase.Mode == "terminal" || q.Workspace.Phase.Mode != "terminal") {
			return Response{}, nil, ErrGrammar
		}
	}
	if q.Operation == "workspace-cleanup" {
		if err := o.mergeFactsLocked(Facts{Witness: q.Workspace.Phase.Witness}); err != nil {
			return Response{}, nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &Job{owner: o, start: cloneRequest(q), ctx: ctx, cancel: cancel, done: make(chan struct{}), running: true, state: "preparing"}
	if q.Operation == "workspace-recover" {
		j.state = "pending-recovery"
	}
	if q.Operation == "workspace-suspend" {
		drain, _ := decimal(q.Workspace.DrainBudgetNanos, true)
		j.drainDeadline = receivedAt.Add(time.Duration(drain))
		cancel()
		j.ctx, j.cancel = context.WithDeadline(context.Background(), j.drainDeadline)
		j.state = "pending-suspend"
	}
	if o.facts.Outcome == (Outcome{}) {
		o.facts.Outcome = unknownOutcome()
		o.facts.AuthorizationDeadlineUnixNanos = "0"
	}
	o.facts.Readiness = nil
	if q.Operation == "workspace-cleanup" && q.Workspace.Phase.Mode == "terminal" && o.voluntary.status.Progress == "offered" {
		o.voluntary.status.Progress = "failed"
		o.voluntary.status.Failure = "stopped"
		close(o.voluntary.done)
	}
	o.job = j
	if q.Operation == "workspace-prepare" {
		o.prepareUsed = true
	}
	if q.Operation == "workspace-recover" {
		o.recoveredGeneration, _ = decimal(q.Workspace.Generation, false)
		o.lastResume = sha256.Sum256([]byte(q.Workspace.Transaction))
	}
	return acknowledgment(q, "accepted"), j, nil
}
func (o *Owner) currentLocked(q Request) error {
	id, _ := decimal(q.Workspace.OperationID, true)
	if o.job == nil {
		return ErrNotAccepted
	}
	old, _ := decimal(o.job.start.Workspace.OperationID, true)
	if id > old {
		return ErrNotAccepted
	}
	if id < old {
		return ErrRetired
	}
	if q.MountInstanceID != o.job.start.MountInstanceID || !sameBinding(*q.Workspace, *o.job.start.Workspace) {
		return ErrGrammar
	}
	return nil
}
func (o *Owner) actionLocked(q Request, s *actionSlot) error {
	if s.status.Progress != "" && s.status.Progress != "offered" {
		return ErrActionConsumed
	}
	p := clonePhase(q.Workspace.Phase)
	p.Removal = nil
	if s.status.Action == nil || !reflect.DeepEqual(p, s.phase) {
		return ErrGrammar
	}
	return nil
}
func (o *Owner) run(j *Job) {
	err := o.Driver.Run(j.ctx, j)
	o.mu.Lock()
	if err != nil || j.state != "prepared" && j.state != "cold" && j.state != "cleanup-finalized" && j.state != "failed" {
		j.state, j.reason = "failed", "lifecycle work failed"
		o.facts.Readiness = nil
	}
	j.running = false
	close(j.done)
	o.mu.Unlock()
	j.cancel()
}
func (o *Owner) installKernel(j *Job, rights *Rights) {
	w, err := o.Driver.Install(j.ctx, j, rights)
	o.mu.Lock()
	slot := &o.install
	mergeErr := o.mergeFactsLocked(Facts{Witness: w})
	if err == nil {
		err = mergeErr
	}
	if err == nil {
		if err == nil && (!boundWitness(o.facts.Witness) || o.facts.Witness.Kernel == "") {
			err = ErrGrammar
		}
	}
	if err != nil {
		slot.status.Progress = "failed"
		slot.status.Failure = "handler-failed"
	} else {
		slot.status.Progress = "complete"
	}
	close(slot.done)
	o.mu.Unlock()
}
func status(s actionSlot) ActionStatus {
	if s.status.Progress == "" {
		return ActionStatus{Progress: "absent"}
	}
	a := s.status
	if a.Action != nil {
		a.Action = kernelAction(*a.Action.WithWitness(Witness{}))
	}
	return a
}
func (o *Owner) observeLocked(q Request) (Response, error) {
	if err := o.currentLocked(q); err != nil {
		return Response{}, err
	}
	j := o.job
	out := acknowledgment(q, j.state)
	w := out.Workspace
	w.Witness = o.facts.Witness
	w.AuthorizationDeadlineUnixNanos = o.facts.AuthorizationDeadlineUnixNanos
	w.Outcome = o.facts.Outcome
	w.Loss = append([]Loss(nil), o.facts.Loss...)
	w.Phases = &PhaseFacts{status(o.install), status(o.voluntary), status(o.terminal)}
	w.Reason = j.reason
	w.ColdComplete = j.state == "cold"
	if j.state == "prepared" && o.facts.Readiness != nil {
		p := *o.facts.Readiness
		w.Readiness = &p
	}
	return out, nil
}

// Publish records lifecycle facts, never a response. Evidence is cumulative;
// obsolete readiness cannot overwrite facts needed by a later cleanup.
func (j *Job) Publish(state string, f Facts) error {
	o := j.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.job != j {
		return ErrRetired
	}
	if err := o.mergeFactsLocked(f); err != nil {
		return err
	}
	if j.state == "failed" || j.state == "cleanup-finalized" {
		return ErrGrammar
	}
	switch state {
	case "prepared":
		if j.stopping || j.ctx.Err() != nil || !o.permitted(j.start) || o.install.status.Progress != "complete" {
			return ErrGrammar
		}
	case "cold":
		if j.start.Operation != "workspace-suspend" || j.ctx.Err() != nil {
			return ErrGrammar
		}
	case "cleanup-finalized":
		if j.start.Operation != "workspace-cleanup" || o.voluntary.status.Progress != "complete" && o.terminal.status.Progress != "complete" {
			return ErrGrammar
		}
	case "preparing", "pending-recovery", "pending-suspend":
	default:
		return ErrGrammar
	}
	out, _ := o.observeLocked(j.start)
	out.Workspace.State = state
	out.Workspace.ColdComplete = state == "cold"
	out.Workspace.Readiness = f.Readiness
	if state != "prepared" {
		out.Workspace.Readiness = nil
	}
	if out.ValidateWorkspace() != nil {
		return ErrGrammar
	}
	j.state = state
	o.facts.Readiness = nil
	if out.Workspace.Readiness != nil {
		p := *out.Workspace.Readiness
		o.facts.Readiness = &p
	}
	return nil
}
func (j *Job) OfferInstall(p Phase) error {
	o := j.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.job != j || j.stopping || o.closed || j.start.Operation != "workspace-prepare" || !o.permitted(j.start) || o.install.status.Progress != "" {
		return ErrGrammar
	}
	facts := &PhaseFacts{Install: ActionStatus{Progress: "offered", Action: kernelAction(p)}, VoluntaryRemoval: status(o.voluntary), TerminalRemoval: status(o.terminal)}
	if !validPhases(facts, p.Witness) {
		return ErrGrammar
	}
	if err := o.mergeFactsLocked(Facts{Witness: p.Witness}); err != nil {
		return err
	}
	o.install = actionSlot{status: facts.Install, phase: clonePhase(&p), done: make(chan struct{})}
	j.state = "kernel-required"
	return nil
}
func (j *Job) OfferRemoval(p Phase) error {
	o := j.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.job != j || j.start.Operation != "workspace-cleanup" || o.install.status.Progress == "running" || o.voluntary.status.Progress == "complete" || o.terminal.status.Progress == "complete" {
		return ErrGrammar
	}
	s := &o.voluntary
	if p.Mode == "terminal" {
		s = &o.terminal
	}
	if s.status.Progress != "" {
		return ErrActionConsumed
	}
	if p.Mode != j.start.Workspace.Phase.Mode || p.Witness != o.facts.Witness {
		return ErrGrammar
	}
	f := &PhaseFacts{status(o.install), status(o.voluntary), status(o.terminal)}
	a := ActionStatus{Progress: "offered", Action: kernelAction(p)}
	if p.Mode == "terminal" {
		f.TerminalRemoval = a
	} else {
		f.VoluntaryRemoval = a
	}
	if !validPhases(f, p.Witness) {
		return ErrGrammar
	}
	*s = actionSlot{status: a, phase: clonePhase(&p), done: make(chan struct{})}
	j.state = "unmount-required"
	return nil
}
func (j *Job) WaitInstall(ctx context.Context) error              { return j.waitAction(ctx, "install") }
func (j *Job) WaitRemoval(ctx context.Context, mode string) error { return j.waitAction(ctx, mode) }
func (j *Job) waitAction(ctx context.Context, kind string) error {
	o := j.owner
	o.mu.Lock()
	s := &o.install
	if kind == "voluntary" {
		s = &o.voluntary
	}
	if kind == "terminal" {
		s = &o.terminal
	}
	done := s.done
	o.mu.Unlock()
	if done == nil {
		return ErrGrammar
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if s.status.Progress != "complete" {
		return ErrGrammar
	}
	return nil
}

// CloseKernel disposes the real child owner; no receipt retains extra copies.
func (j *Job) CloseKernel() {
	o := j.owner
	o.mu.Lock()
	var done chan struct{}
	if o.install.status.Progress == "running" {
		done = o.install.done
	}
	o.mu.Unlock()
	if done != nil {
		<-done
	}
	o.mu.Lock()
	r := o.install.rights
	o.install.rights = nil
	o.mu.Unlock()
	if r != nil {
		r.Close()
	}
}
func (o *Owner) Close() {
	if o.CloseAdmission != nil {
		o.CloseAdmission()
	}
	o.mu.Lock()
	o.closed = true
	j := o.job
	var installDone chan struct{}
	if o.install.status.Progress == "running" {
		installDone = o.install.done
	}
	if j != nil {
		j.stopping = true
	}
	o.mu.Unlock()
	if j != nil {
		j.cancel()
		<-j.done
	}
	if installDone != nil {
		<-installDone
	}
	o.mu.Lock()
	r := o.install.rights
	o.install.rights = nil
	o.mu.Unlock()
	if r != nil {
		r.Close()
	}
}

// mergeWitness never publishes a partial conflicting binding.
func mergeWitness(old, next Witness) (Witness, error) {
	a, b := reflect.ValueOf(&old).Elem(), reflect.ValueOf(next)
	for i := 0; i < a.NumField(); i++ {
		if b.Field(i).String() == "" {
			continue
		}
		if a.Field(i).String() != "" && a.Field(i).String() != b.Field(i).String() {
			return Witness{}, ErrGrammar
		}
		a.Field(i).SetString(b.Field(i).String())
	}
	if !boundedWitness(old) {
		return Witness{}, ErrGrammar
	}
	return old, nil
}
func (o *Owner) mergeFactsLocked(f Facts) error {
	merged := o.facts
	var err error
	merged.Witness, err = mergeWitness(merged.Witness, f.Witness)
	if err != nil {
		return err
	}
	if merged.Outcome == (Outcome{}) {
		merged.Outcome = unknownOutcome()
	}
	if merged.AuthorizationDeadlineUnixNanos == "" {
		merged.AuthorizationDeadlineUnixNanos = "0"
	}
	if f.AuthorizationDeadlineUnixNanos != "" {
		merged.AuthorizationDeadlineUnixNanos = f.AuthorizationDeadlineUnixNanos
	}
	if f.Outcome != (Outcome{}) {
		debt, err := decimal(f.Outcome.CleanupDebt, false)
		if err != nil || control.Outcome(&pb.MountOutcome{Durability: f.Outcome.Durability, Observation: f.Outcome.Observation, Release: f.Outcome.Release, CleanupDebt: debt}) != nil {
			return ErrGrammar
		}
		n, _ := decimal(merged.Outcome.CleanupDebt, false)
		if debt > n {
			merged.Outcome.CleanupDebt = f.Outcome.CleanupDebt
		}
		for _, pair := range [][2]*string{{&merged.Outcome.Durability, &f.Outcome.Durability}, {&merged.Outcome.Release, &f.Outcome.Release}} {
			if *pair[0] != "unresolved" && *pair[1] != "unresolved" && *pair[0] != *pair[1] {
				o.facts.Outcome.CleanupDebt = merged.Outcome.CleanupDebt
				return ErrGrammar
			}
			if *pair[1] != "unresolved" {
				*pair[0] = *pair[1]
			}
		}
		if f.Outcome.Observation == "observed" {
			merged.Outcome.Observation = "observed"
		}
	}
	// Validate canonical loss and bounds before converting it for the shared
	// cumulative-ledger comparison. Invalid evidence never poisons observation.
	if len(f.Loss) > 0 {
		if validLoss(f.Loss) != nil {
			return ErrGrammar
		}
		toPB := func(loss []Loss) []*pb.Loss {
			out := make([]*pb.Loss, len(loss))
			for i, l := range loss {
				seq, _ := decimal(l.Sequence, true)
				entries, _ := decimal(l.AcceptedEntries, false)
				size, _ := decimal(l.AcceptedBytes, false)
				out[i] = &pb.Loss{Sequence: seq, AcceptedEntries: entries, AcceptedBytes: size, Reason: l.Reason, Aggregated: l.Aggregated}
			}
			return out
		}
		if control.RetainsLoss(toPB(f.Loss), toPB(o.facts.Loss)) {
			merged.Loss = append([]Loss(nil), f.Loss...)
		} else if !control.RetainsLoss(toPB(o.facts.Loss), toPB(f.Loss)) {
			return ErrGrammar
		}
	}
	if _, err := decimal(merged.AuthorizationDeadlineUnixNanos, false); err != nil {
		return err
	}
	o.facts = merged
	return nil
}
