//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func awaitResult[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("owner did not progress")
		var zero T
		return zero
	}
}
func absentPhases() *PhaseFacts {
	return &PhaseFacts{Install: ActionStatus{Progress: "absent"}, VoluntaryRemoval: ActionStatus{Progress: "absent"}, TerminalRemoval: ActionStatus{Progress: "absent"}}
}

// Legacy fixtures report ordinary errors as independent failures. Cancellation
// fixtures use testOwnerResult and state their lifecycle disposition explicitly.
func lifecycleResult(err error) LifecycleResult {
	if err != nil {
		return LifecycleResult{Disposition: LifecycleFailed, Err: err}
	}
	return LifecycleResult{Disposition: LifecycleCompleted}
}
func lifecycleDriver(run func(context.Context, *Job) error) func(context.Context, *Job) LifecycleResult {
	return func(ctx context.Context, j *Job) LifecycleResult { return lifecycleResult(run(ctx, j)) }
}
func testOwnerResult(t *testing.T, run func(context.Context, *Job) LifecycleResult) *Owner {
	t.Helper()
	o := testOwner(t, nil)
	o.Driver.Run = run
	return o
}
func testOwner(t *testing.T, run func(context.Context, *Job) error) *Owner {
	t.Helper()
	o := &Owner{Driver: Driver{Run: lifecycleDriver(run), ValidateInstall: func(*Rights, Phase) error { return nil }, Install: func(context.Context, *Job, *Rights) (Witness, error) { return witness(), nil }}, CheckPermit: func(Workspace) bool { return true }}
	t.Cleanup(o.Close)
	return o
}
func do(t *testing.T, o *Owner, q Request, d *Rights) Response {
	t.Helper()
	out, err := o.Do(context.Background(), q, d)
	if err != nil {
		t.Fatal(q.Operation, err)
	}
	raw, err := EncodeResponse(out)
	if err != nil {
		t.Fatal(out, err)
	}
	out, err = DecodeResponse(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func observe(t *testing.T, o *Owner, n, id uint64) Response {
	t.Helper()
	return do(t, o, request("workspace-observe", n, id), &Rights{})
}
func start(t *testing.T, o *Owner, q Request) *Job {
	t.Helper()
	do(t, o, q, &Rights{})
	o.mu.Lock()
	j := o.job
	o.mu.Unlock()
	return j
}
func installRequest(n, id uint64) Request {
	q := request("workspace-install-kernel", n, id)
	q.Workspace.Phase = phase()
	return q
}
func cleanupRequest(n uint64, mode string) Request {
	q := request("workspace-cleanup", n, n)
	q.Workspace.Phase = &Phase{Mode: mode, Witness: witness()}
	return q
}
func readyFacts() Facts {
	w := witness()
	w.Session = "session"
	return Facts{Witness: w, AuthorizationDeadlineUnixNanos: "2000000000000000000", Readiness: &Prepared{SessionValidated: true, AuthorizationValidated: true, Renewal: Renewal{"installed", "1"}, SubscriptionIncarnation: "1"}}
}

// Replaces receipt-deadline and lost-waiter expectations: the linearization
// point is the job reservation, before any driver work or response delivery.
func TestJobAcceptanceSurvivesSocketLossAndExpiry(t *testing.T) {
	for _, loss := range []string{"before-acceptance", "after-acceptance", "after-expiry"} {
		t.Run(loss, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			o := testOwner(t, func(ctx context.Context, j *Job) error {
				calls.Add(1)
				close(entered)
				<-release
				if ctx.Err() != nil {
					t.Error("socket canceled lifecycle", ctx.Err())
				}
				return j.OfferInstall(*phase())
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			q := request("workspace-prepare", 1, 1)
			if loss == "before-acceptance" {
				cancel()
				if _, err := o.Do(ctx, q, &Rights{}); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if _, err := o.Do(context.Background(), request("workspace-observe", 2, 1), &Rights{}); !errors.Is(err, ErrNotAccepted) {
					t.Fatal(err)
				}
				ctx = context.Background()
			}
			var elapsed atomic.Int64
			base := time.Now().Add(time.Hour)
			o.Now = func() time.Time { return base.Add(time.Duration(elapsed.Load())) }
			j := start(t, o, q)
			awaitResult(t, entered)
			cancel()
			if loss == "after-expiry" {
				elapsed.Store(int64(time.Minute))
			}
			out := do(t, o, q, &Rights{})
			if out.Workspace.State != "accepted" {
				t.Fatal(out)
			}
			close(release)
			awaitResult(t, j.done)
			// This fixture deliberately returns without completing readiness. The job
			// fails, but its acquired install slot and one-shot Prepare survive.
			snap := observe(t, o, 2, 1)
			if snap.Workspace.State != "failed" || snap.Workspace.Phases.Install.Progress != "failed" || snap.Workspace.Phases.Install.Failure != "stopped" || calls.Load() != 1 {
				t.Fatal(snap, calls.Load())
			}
			if _, err := o.Do(context.Background(), request("workspace-prepare", 3, 3), &Rights{}); !errors.Is(err, ErrIncarnationTerminal) {
				t.Fatal("Prepare rearmed", err)
			}
		})
	}
}

func TestObservationsAreSnapshotsWithoutRetainedGrowth(t *testing.T) {
	offered, release := make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		close(offered)
		<-release
		return nil
	})
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	old := observe(t, o, 5000, 1)
	o.mu.Lock()
	before := o.job
	body := cloneRequest(o.job.start)
	slots := [3]ActionStatus{status(o.install), status(o.voluntary), status(o.terminal)}
	o.mu.Unlock()
	for i := 0; i < 4096; i++ {
		out := observe(t, o, 2, 1)
		if out.Workspace.Phases.Install.Progress != "offered" {
			t.Fatal(out)
		}
	}
	o.mu.Lock()
	unchanged := before == o.job && reflect.DeepEqual(body, o.job.start) && reflect.DeepEqual(slots, [3]ActionStatus{status(o.install), status(o.voluntary), status(o.terminal)})
	o.mu.Unlock()
	if !unchanged {
		t.Fatal("observations mutated retained ownership")
	}
	d, _ := descriptors(t)
	do(t, o, installRequest(3, 1), d)
	o.mu.Lock()
	done := o.install.done
	o.mu.Unlock()
	awaitResult(t, done)
	newer := observe(t, o, 5000, 1)
	if newer.Workspace.Phases.Install.Progress != "complete" || reflect.DeepEqual(old, newer) {
		t.Fatal("request ID froze observation")
	}
	close(release)
	awaitResult(t, j.done)
}

func TestStaleActionsRetiredStartsAndChangedBodiesRefuse(t *testing.T) {
	var closes atomic.Int32
	entered := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-prepare" {
			j.OfferInstall(*phase())
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}
		return errors.New("cleanup failed")
	})
	o.CloseAdmission = func() { closes.Add(1) }
	q := request("workspace-prepare", 1, 1)
	j := start(t, o, q)
	awaitResult(t, entered)
	changed := cloneRequest(q)
	changed.Workspace.GateSerial = "1"
	if _, err := o.Do(context.Background(), changed, &Rights{}); !errors.Is(err, ErrGrammar) || closes.Load() != 1 {
		t.Fatal(err, closes.Load())
	}
	// An unknown snapshot and an obsolete binding have no lifecycle effect.
	if _, err := o.Do(context.Background(), request("workspace-observe", 3, 4), &Rights{}); !errors.Is(err, ErrNotAccepted) {
		t.Fatal(err)
	}
	bad := installRequest(4, 1)
	bad.Workspace.Phase.ActionID = "2"
	d, fd := descriptors(t)
	if _, err := o.Do(context.Background(), bad, d); !errors.Is(err, ErrGrammar) {
		t.Fatal(err)
	}
	assertClosed(t, fd)
	closeQ := cleanupRequest(5, "voluntary")
	o.AdmitFrame(closeQ, &Rights{})
	awaitResult(t, j.done)
	next := start(t, o, closeQ)
	awaitResult(t, next.done)
	if _, err := o.Do(context.Background(), q, &Rights{}); !errors.Is(err, ErrRetired) {
		t.Fatal(err)
	}
	d, fd = descriptors(t)
	if _, err := o.Do(context.Background(), installRequest(6, 1), d); !errors.Is(err, ErrRetired) {
		t.Fatal(err)
	}
	assertClosed(t, fd)
	if _, err := o.Do(context.Background(), request("workspace-observe", 7, 1), &Rights{}); !errors.Is(err, ErrRetired) {
		t.Fatal(err)
	}
}

func TestSuspendClosesCancelsAndRetainsOccupiedWorker(t *testing.T) {
	entered, canceled, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}, 4)
	o := testOwnerResult(t, func(ctx context.Context, j *Job) LifecycleResult {
		if j.start.Operation == "workspace-prepare" {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			return LifecycleResult{Disposition: LifecycleOvertaken, Err: ctx.Err()}
		}
		return lifecycleResult(j.Publish("cold", Facts{}))
	})
	o.CloseAdmission = func() { closed <- struct{}{} }
	old := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, entered)
	q := request("workspace-suspend", 3, 3)
	transaction(t, &q)
	if _, err := o.Do(context.Background(), q, &Rights{}); !errors.Is(err, ErrOccupied) {
		t.Fatal(err)
	}
	awaitResult(t, closed)
	awaitResult(t, canceled)
	if snap := observe(t, o, 4, 1); snap.Workspace.State != "preparing" {
		t.Fatal(snap)
	}
	close(release)
	awaitResult(t, old.done)
	next := start(t, o, q)
	awaitResult(t, next.done)
	if snap := observe(t, o, 5, 3); snap.Workspace.State != "cold" {
		t.Fatal(snap)
	}
}

func TestFixedDrainDeadlineChargesAdmissionAndAllowsLaterObservation(t *testing.T) {
	base := time.Now().Add(time.Hour)
	var elapsed atomic.Int64
	entered, release := make(chan time.Time, 1), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		d, _ := ctx.Deadline()
		entered <- d
		<-release
		return errors.New("drain failed")
	})
	o.Now = func() time.Time { return base.Add(time.Duration(elapsed.Load())) }
	q := request("workspace-suspend", 1, 1)
	transaction(t, &q)
	q.Workspace.DrainBudgetNanos = "10000000000"
	// Framing and lock delay are charged to the original receipt, never to
	// acceptance. The allowance is outside immutable transaction identity.
	o.AdmitFrame(q, &Rights{})
	elapsed.Store(int64(3 * time.Second))
	if _, err := o.DoAdmitted(context.Background(), q, &Rights{}, base); err != nil {
		t.Fatal(err)
	}
	deadline := awaitResult(t, entered)
	if !deadline.Equal(base.Add(10 * time.Second)) {
		t.Fatal(deadline)
	}
	elapsed.Store(int64(20 * time.Second))
	q.Workspace.DrainBudgetNanos = "15000000000"
	do(t, o, q, &Rights{})
	o.mu.Lock()
	j := o.job
	if !j.drainDeadline.Equal(deadline) {
		t.Error("retry extended drain")
	}
	o.mu.Unlock()
	snap := observe(t, o, 2, 1)
	if snap.Workspace.State != "pending-suspend" {
		t.Fatal(snap)
	}
	close(release)
	awaitResult(t, j.done)
	if observe(t, o, 2, 1).Workspace.State != "failed" {
		t.Fatal("snapshot did not advance")
	}
}

func TestWorkspaceResponseMaximumIsBoundedBeforeDispatch(t *testing.T) {
	q := request("workspace-recover", 1, 1)
	transaction(t, &q)
	q.Workspace.Transaction = strings.Repeat("x", MaxWorkspaceRequest-1024)
	out := response(q, "failed")
	out.Workspace.Phases = absentPhases()
	out.Workspace.Reason = strings.Repeat("\x00", 256)
	out.Workspace.Witness = Witness{Process: "p", Source: "s", Target: "/" + strings.Repeat("\x00", 509)}
	for i := 1; i <= 32; i++ {
		out.Workspace.Loss = append(out.Workspace.Loss, Loss{Sequence: strconv.Itoa(i), AcceptedEntries: "18446744073709551615", AcceptedBytes: "18446744073709551615", Reason: strings.Repeat("\x00", 256)})
	}
	f := out.Workspace.Phases
	for i, s := range []*ActionStatus{&f.Install, &f.VoluntaryRemoval, &f.TerminalRemoval} {
		p := &Phase{ActionID: strconv.Itoa(i + 1), Witness: Witness{Process: "p", Source: "s", Target: "/" + strings.Repeat("\x00", 509)}}
		s.Progress = "failed"
		s.Failure = "handler-failed"
		if i == 0 {
			p.Options = []string{strings.Repeat("\x00", 256)}
		} else {
			p.Mode = "voluntary"
			if i == 2 {
				p.Mode = "terminal"
			}
			p.Reason = strings.Repeat("\x00", 256)
		}
		s.Action = kernelAction(*p)
	}
	raw, err := EncodeResponse(out)
	if err != nil || len(raw) > MaxWorkspaceResponse {
		t.Fatal(len(raw), err)
	}
	if strings.Contains(string(raw), strings.Repeat("x", 100)) {
		t.Fatal("transaction echoed")
	}
	out.Workspace.Witness.Target += "x"
	if _, err := EncodeResponse(out); err == nil {
		t.Fatal("unbounded witness")
	}
}

func TestOperationIDExhaustionNeverWraps(t *testing.T) {
	o := testOwner(t, func(context.Context, *Job) error { return errors.New("finished") })
	q := request("workspace-prepare", ^uint64(0), ^uint64(0))
	j := start(t, o, q)
	awaitResult(t, j.done)
	do(t, o, q, &Rights{})
	if _, err := o.Do(context.Background(), request("workspace-prepare", 1, 1), &Rights{}); !errors.Is(err, ErrRetired) {
		t.Fatal("operation ID wrapped", err)
	}
	overflow := cloneRequest(q)
	overflow.Workspace.RequestID = "18446744073709551616"
	overflow.Workspace.OperationID = overflow.Workspace.RequestID
	if _, err := o.Do(context.Background(), overflow, &Rights{}); !errors.Is(err, ErrGrammar) {
		t.Fatal("overflow accepted", err)
	}
	if observe(t, o, 1, ^uint64(0)).Workspace.State != "failed" {
		t.Fatal("retired/overflow changed job")
	}
}
