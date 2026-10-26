//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
)

// Replaces immutable overlapping receipts. Each observation reads the real
// slot, and even a retained offered snapshot cannot authorize re-execution.
func TestObservationOverlapsSuccessfulInstallAndRemoval(t *testing.T) {
	for _, op := range []string{"install", "removal"} {
		t.Run(op, func(t *testing.T) {
			offered, phaseEntered, releasePhase, releaseJob := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			o := testOwner(t, func(ctx context.Context, j *Job) error {
				if op == "install" {
					if err := j.OfferInstall(*phase()); err != nil {
						return err
					}
				} else {
					if err := j.Publish("preparing", Facts{Witness: witness()}); err != nil {
						return err
					}
					p := Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup", Witness: witness()}
					if err := j.OfferRemoval(p); err != nil {
						return err
					}
				}
				close(offered)
				<-releaseJob
				return nil
			})
			o.Driver.Install = func(context.Context, *Job, *Rights) (Witness, error) {
				calls.Add(1)
				close(phaseEntered)
				<-releasePhase
				return witness(), nil
			}
			q := request("workspace-prepare", 1, 1)
			if op == "removal" {
				q = cleanupRequest(1, "voluntary")
			}
			j := start(t, o, q)
			awaitResult(t, offered)
			stale := observe(t, o, 2, 1)
			delayed := &heldResponse{entered: make(chan struct{}), release: make(chan struct{})}
			delivered := make(chan error, 1)
			go func() { delivered <- WriteResponse(delayed, stale) }()
			awaitResult(t, delayed.entered)
			var action Request
			var d *Rights
			if op == "install" {
				action = installRequest(3, 1)
				d, _ = descriptors(t)
			} else {
				action = request("workspace-unmount-complete", 3, 1)
				action.Workspace.Phase = stale.Workspace.Phases.VoluntaryRemoval.Action.WithWitness(stale.Workspace.Witness)
				action.Workspace.Phase.Removal = &Removal{KernelAbsent: true}
				d = &Rights{}
			}
			ack := do(t, o, action, d)
			if op == "install" {
				if ack.Workspace.State != "accepted" {
					t.Fatal(ack)
				}
				awaitResult(t, phaseEntered)
				if snap := observe(t, o, 2, 1); snap.Workspace.Phases.Install.Progress != "running" || snap.Workspace.Readiness != nil {
					t.Fatal(snap)
				}
				close(releasePhase)
				o.mu.Lock()
				done := o.install.done
				o.mu.Unlock()
				awaitResult(t, done)
			} else {
				if ack.Workspace.State != "unmount-recorded" {
					t.Fatal(ack)
				}
			}
			snap := observe(t, o, 2, 1)
			slot := snap.Workspace.Phases.Install
			if op == "removal" {
				slot = snap.Workspace.Phases.VoluntaryRemoval
			}
			if slot.Progress != "complete" || snap.Workspace.State == "prepared" || snap.Workspace.State == "cleanup-finalized" {
				t.Fatal(snap)
			}
			close(delayed.release)
			if err := awaitResult(t, delivered); err != nil {
				t.Fatal(err)
			}
			old, err := DecodeResponse(delayed.body, true)
			if err != nil {
				t.Fatal(err)
			}
			oldSlot := old.Workspace.Phases.Install
			if op == "removal" {
				oldSlot = old.Workspace.Phases.VoluntaryRemoval
			}
			if oldSlot.Progress != "offered" {
				t.Fatal("delayed observation mutated")
			}
			d = &Rights{}
			if op == "install" {
				d, _ = descriptors(t)
			}
			if _, err := o.Do(context.Background(), action, d); !errors.Is(err, ErrActionConsumed) {
				t.Fatal("stale action rearmed", err)
			}
			if op == "install" && calls.Load() != 1 {
				t.Fatal(calls.Load())
			}
			close(releaseJob)
			awaitResult(t, j.done)
		})
	}
}

func TestAcceptedInstallCompletesAfterSocketExpiryAndClose(t *testing.T) {
	offered, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		close(offered)
		<-ctx.Done()
		return ctx.Err()
	})
	o.Driver.Install = func(context.Context, *Job, *Rights) (Witness, error) {
		close(entered)
		<-release
		return witness(), nil
	}
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	q := installRequest(3, 1)
	d, _ := descriptors(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ack, err := o.Do(ctx, q, d)
	if err != nil || ack.Workspace.State != "accepted" {
		t.Fatal(ack, err)
	}
	awaitResult(t, entered)
	<-ctx.Done()
	closeQ := cleanupRequest(4, "terminal")
	if _, err := o.Do(context.Background(), closeQ, &Rights{}); !errors.Is(err, ErrOccupied) {
		t.Fatal(err)
	}
	awaitResult(t, j.done)
	close(release)
	o.mu.Lock()
	done := o.install.done
	o.mu.Unlock()
	awaitResult(t, done)
	snap := observe(t, o, 5, 1)
	if snap.Workspace.State != "failed" || snap.Workspace.Phases.Install.Progress != "complete" || snap.Workspace.Readiness != nil {
		t.Fatal(snap)
	}
}

func TestConsumedInstallRefusesEveryDescriptorAndRealOwnerHangup(t *testing.T) {
	offered, release := make(chan struct{}), make(chan struct{})
	var installs atomic.Int32
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		j.OfferInstall(*phase())
		close(offered)
		<-release
		return nil
	})
	o.Driver.Install = func(context.Context, *Job, *Rights) (Witness, error) { installs.Add(1); return witness(), nil }
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[0])
	abort, err := os.CreateTemp(t.TempDir(), "abort")
	if err != nil {
		t.Fatal(err)
	}
	defer abort.Close()
	fd, err := unix.Dup(int(abort.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	original := &Rights{FDs: []int{pipe[1], fd}}
	duplicates := &Rights{}
	for _, fd := range original.FDs {
		x, err := unix.Dup(fd)
		if err != nil {
			t.Fatal(err)
		}
		duplicates.FDs = append(duplicates.FDs, x)
	}
	q := installRequest(3, 1)
	do(t, o, q, original)
	o.mu.Lock()
	done := o.install.done
	o.mu.Unlock()
	awaitResult(t, done)
	fresh := &Rights{}
	for _, path := range []string{"/dev/null", abort.Name()} {
		x, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		fresh.FDs = append(fresh.FDs, x)
	}
	for _, d := range []*Rights{duplicates, fresh} {
		fds := append([]int(nil), d.FDs...)
		if _, err := o.Do(context.Background(), q, d); !errors.Is(err, ErrActionConsumed) {
			t.Fatal(err)
		}
		assertClosed(t, fds)
	}
	// No receipt owns a redundant FUSE reference. Closing the actual job owner
	// produces kernel hangup, before or after further snapshots.
	poll := []unix.PollFd{{Fd: int32(pipe[0]), Events: unix.POLLIN}}
	unix.Poll(poll, 0)
	if poll[0].Revents&unix.POLLHUP != 0 {
		t.Fatal("premature owner loss")
	}
	j.CloseKernel()
	unix.Poll(poll, 0)
	if poll[0].Revents&unix.POLLHUP == 0 {
		t.Fatal("hidden descriptor owner")
	}
	if observe(t, o, 4, 1).Workspace.Phases.Install.Progress != "complete" || installs.Load() != 1 {
		t.Fatal("ownership facts erased")
	}
	close(release)
	awaitResult(t, j.done)
}

func TestFixedActionSlotsNeverRearmAcrossJobs(t *testing.T) {
	offered, failVoluntary := make(chan struct{}, 3), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-prepare" {
			if err := j.OfferInstall(*phase()); err != nil {
				return err
			}
			offered <- struct{}{}
			if err := j.WaitInstall(ctx); err != nil {
				return err
			}
			return j.Publish("prepared", readyFacts())
		}
		mode := j.start.Workspace.Phase.Mode
		p := Phase{ActionID: "2", Mode: mode, Reason: "cleanup", Witness: readyFacts().Witness}
		if mode == "terminal" {
			p.ActionID = "3"
		}
		if err := j.OfferRemoval(p); err != nil {
			return err
		}
		offered <- struct{}{}
		if mode == "voluntary" {
			<-failVoluntary
			return errors.New("EBUSY retained by root removal owner")
		}
		if err := j.WaitRemoval(ctx, mode); err != nil {
			return err
		}
		return j.Publish("cleanup-finalized", Facts{})
	})
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	d, _ := descriptors(t)
	do(t, o, installRequest(2, 1), d)
	awaitResult(t, j.done)
	if observe(t, o, 3, 1).Workspace.State != "prepared" {
		t.Fatal("not prepared")
	}
	c := cleanupRequest(4, "voluntary")
	c.Workspace.Phase.Witness = readyFacts().Witness
	v := start(t, o, c)
	awaitResult(t, offered)
	close(failVoluntary)
	awaitResult(t, v.done)
	c = cleanupRequest(5, "terminal")
	c.Workspace.Phase.Witness = readyFacts().Witness
	terminal := start(t, o, c)
	awaitResult(t, offered)
	snap := observe(t, o, 6, 5)
	if snap.Workspace.Phases.Install.Progress != "complete" || snap.Workspace.Phases.VoluntaryRemoval.Action.ActionID != "2" || snap.Workspace.Phases.TerminalRemoval.Action.ActionID != "3" {
		t.Fatal(snap)
	}
	// A thousand invented actions cannot grow the three slots or replace them.
	for i := 0; i < 1024; i++ {
		p := *phase()
		p.ActionID = "999"
		if err := terminal.OfferInstall(p); err == nil {
			t.Fatal("rearmed install")
		}
		p.Mode = "terminal"
		p.Options = nil
		p.Reason = "again"
		if err := terminal.OfferRemoval(p); !errors.Is(err, ErrActionConsumed) {
			t.Fatal(err)
		}
	}
	q := request("workspace-unmount-complete", 7, 5)
	q.Workspace.Phase = snap.Workspace.Phases.TerminalRemoval.Action.WithWitness(snap.Workspace.Witness)
	q.Workspace.Phase.Removal = &Removal{KernelAbsent: true, AbortCompleted: true}
	do(t, o, q, &Rights{})
	awaitResult(t, terminal.done)
	if observe(t, o, 8, 5).Workspace.State != "cleanup-finalized" {
		t.Fatal("cleanup not finalized")
	}
	if _, err := o.Do(context.Background(), cleanupRequest(9, "terminal"), &Rights{}); !errors.Is(err, ErrGrammar) {
		t.Fatal("successful removal reversed", err)
	}
}

func TestRecoverConsumesExactAuthorizationAndPreservesKernelSlot(t *testing.T) {
	// Cold and recovery use one owner; failed Prepare never makes bootstrap legal.
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-suspend" {
			return j.Publish("cold", Facts{})
		}
		return errors.New("transient fixture stopped")
	})
	q := request("workspace-suspend", 1, 1)
	transaction(t, &q)
	j := start(t, o, q)
	awaitResult(t, j.done)
	recover := request("workspace-recover", 2, 2)
	transaction(t, &recover)
	j = start(t, o, recover)
	awaitResult(t, j.done)
	recover.Workspace.RequestID = "3"
	recover.Workspace.OperationID = "3"
	if _, err := o.Do(context.Background(), recover, &Rights{}); !errors.Is(err, ErrIncarnationTerminal) {
		t.Fatal("token reused", err)
	}
	if _, err := o.Do(context.Background(), request("workspace-prepare", 4, 4), &Rights{}); !errors.Is(err, ErrIncarnationTerminal) {
		t.Fatal("bootstrap resurrected", err)
	}
}

func TestObservationRefusalsAndExpiredAcceptanceHaveNoLifecycleEffect(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error { close(entered); <-release; return nil })
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	q := request("workspace-prepare", 1, 1)
	if _, err := o.Do(ctx, q, &Rights{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if o.job != nil || o.prepareUsed {
		t.Fatal("expired attempt consumed start")
	}
	j := start(t, o, q)
	awaitResult(t, entered)
	if _, err := o.Do(ctx, request("workspace-observe", 2, 1), &Rights{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if observe(t, o, 2, 1).Workspace.State != "preparing" {
		t.Fatal("observation refusal ended job")
	}
	close(release)
	awaitResult(t, j.done)
	do(t, o, q, &Rights{})
	if observe(t, o, 2, 1).Workspace.State != "failed" {
		t.Fatal("failed accepted job disappeared")
	}
}

func TestObservationAfterDrainExpiry(t *testing.T) {
	// Admission must precede expiry even when race instrumentation or host
	// scheduling takes longer than this pure fixture's ten-millisecond budget.
	synctest.Test(t, func(t *testing.T) {
		expired, release := make(chan struct{}), make(chan struct{})
		o := testOwner(t, func(ctx context.Context, j *Job) error {
			<-ctx.Done()
			close(expired)
			<-release
			if err := j.Publish("cold", Facts{}); err == nil {
				t.Error("expired drain certified cold")
			}
			return ctx.Err()
		})
		q := request("workspace-suspend", 1, 1)
		transaction(t, &q)
		q.Workspace.DrainBudgetNanos = "10000000"
		j := start(t, o, q)
		awaitResult(t, expired)
		if snap := observe(t, o, 2, 1); snap.Workspace.State != "pending-suspend" {
			t.Fatal(snap)
		}
		do(t, o, q, &Rights{}) // A live waiter neither extends nor cancels the fixed job.
		close(release)
		awaitResult(t, j.done)
		if snap := observe(t, o, 2, 1); snap.Workspace.State != "failed" {
			t.Fatal(snap)
		}
	})
}

func TestFirstDeliveryValidationNeverOwnsRejectedRights(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		j.OfferInstall(*phase())
		close(entered)
		<-release
		return nil
	})
	var installs atomic.Int32
	o.Driver.ValidateInstall = func(*Rights, Phase) error { return errors.New("wrong bootstrap role") }
	o.Driver.Install = func(context.Context, *Job, *Rights) (Witness, error) { installs.Add(1); return witness(), nil }
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, entered)
	d, fds := descriptors(t)
	if _, err := o.Do(context.Background(), installRequest(3, 1), d); !errors.Is(err, ErrGrammar) {
		t.Fatal(err)
	}
	assertClosed(t, fds)
	if snap := observe(t, o, 4, 1); snap.Workspace.Phases.Install.Progress != "offered" || installs.Load() != 0 {
		t.Fatal(snap)
	}
	close(release)
	awaitResult(t, j.done)
}

func TestPartialFailureAndCumulativeOutcomeSurviveCleanup(t *testing.T) {
	offered, release := make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-prepare" {
			j.OfferInstall(*phase())
			close(offered)
			<-release
			return errors.New("startup failed")
		}
		return errors.New("cleanup unresolved")
	})
	o.Driver.Install = func(context.Context, *Job, *Rights) (Witness, error) {
		w := witness()
		w.Session = "partial-session"
		return w, errors.New("INIT failed after acquisition")
	}
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	d, fds := descriptors(t)
	do(t, o, installRequest(3, 1), d)
	o.mu.Lock()
	done := o.install.done
	o.mu.Unlock()
	awaitResult(t, done)
	facts := Facts{Outcome: Outcome{"lost", "observed", "abandoned", "2"}, Loss: []Loss{{Sequence: "1", AcceptedEntries: "1", AcceptedBytes: "4", Reason: "lost dirty cut"}}}
	if err := j.Publish("preparing", facts); err != nil {
		t.Fatal(err)
	}
	if err := j.Publish("preparing", Facts{Outcome: Outcome{"durable", "observed", "released", "3"}}); !errors.Is(err, ErrGrammar) {
		t.Fatal("contradiction accepted", err)
	}
	close(release)
	awaitResult(t, j.done)
	q := cleanupRequest(4, "terminal")
	q.Workspace.Phase.Witness = witness()
	q.Workspace.Phase.Witness.Session = "partial-session"
	cleanup := start(t, o, q)
	awaitResult(t, cleanup.done)
	snap := observe(t, o, 5, 4)
	if snap.Workspace.Phases.Install.Progress != "failed" || snap.Workspace.Witness.Session != "partial-session" || snap.Workspace.Outcome != (Outcome{"lost", "observed", "abandoned", "3"}) || len(snap.Workspace.Loss) != 1 {
		t.Fatal(snap)
	}
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Fatal("failed acceptance released resources", err)
		}
	}
	cleanup.CloseKernel()
	assertClosed(t, fds)
}

func TestInstallRechecksPermitAfterFirstDeliveryValidation(t *testing.T) {
	offered, validating, release, stop := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var permit atomic.Bool
	permit.Store(true)
	o := testOwner(t, func(ctx context.Context, j *Job) error { j.OfferInstall(*phase()); close(offered); <-stop; return nil })
	o.CheckPermit = func(Workspace) bool { return permit.Load() }
	o.Driver.ValidateInstall = func(*Rights, Phase) error { close(validating); <-release; return nil }
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	d, fds := descriptors(t)
	done := make(chan error, 1)
	go func() { _, err := o.Do(context.Background(), installRequest(3, 1), d); done <- err }()
	awaitResult(t, validating)
	if snap := observe(t, o, 4, 1); snap.Workspace.Phases.Install.Progress != "offered" {
		t.Fatal(snap)
	}
	permit.Store(false)
	close(release)
	if err := awaitResult(t, done); !errors.Is(err, ErrGrammar) {
		t.Fatal("obsolete permit accepted", err)
	}
	assertClosed(t, fds)
	close(stop)
	awaitResult(t, j.done)
}

// A response waiter can remain blocked after its state snapshot. Acceptance
// and completion on the other lane must proceed independently of this write.
type heldResponse struct {
	entered, release chan struct{}
	body             []byte
}

func (w *heldResponse) Write(raw []byte) (int, error) {
	close(w.entered)
	<-w.release
	w.body = append([]byte(nil), raw...)
	return len(raw), nil
}

func TestCloseInvalidatesAdmissionButRequiresCurrentPermitToStart(t *testing.T) {
	var current atomic.Bool
	current.Store(true)
	var closed atomic.Int32
	o := testOwner(t, func(context.Context, *Job) error { return errors.New("old worker joined") })
	o.CheckPermit = func(Workspace) bool { return current.Load() }
	o.CloseAdmission = func() { closed.Add(1) }
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, j.done)
	current.Store(false)
	if _, err := o.Do(context.Background(), cleanupRequest(2, "terminal"), &Rights{}); !errors.Is(err, ErrGrammar) {
		t.Fatal("stale Close accepted a job", err)
	}
	if closed.Load() != 1 || o.job != j {
		t.Fatal("Close skipped invalidation or replaced ownership")
	}
}

// A failed start retains its stopped install action as evidence. That evidence
// cannot authorize new effects after the worker has ended.
func TestFailedJobCannotAcceptItsUnacceptedInstallOffer(t *testing.T) {
	offered, release := make(chan struct{}), make(chan struct{})
	var installs atomic.Int32
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		close(offered)
		<-release
		return errors.New("preparation failed before handoff")
	})
	o.Driver.Install = func(context.Context, *Job, *Rights) (Witness, error) { installs.Add(1); return witness(), nil }
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	old := observe(t, o, 2, 1)
	close(release)
	awaitResult(t, j.done)
	q := installRequest(3, 1)
	q.Workspace.Phase = old.Workspace.Phases.Install.Action.WithWitness(old.Workspace.Witness)
	d, fds := descriptors(t)
	if _, err := o.Do(context.Background(), q, d); !errors.Is(err, ErrActionConsumed) {
		t.Fatal("failed job executed stale offer", err)
	}
	assertClosed(t, fds)
	snap := observe(t, o, 2, 1)
	if snap.Workspace.State != "failed" || snap.Workspace.Phases.Install.Progress != "failed" || snap.Workspace.Phases.Install.Failure != "stopped" || installs.Load() != 0 {
		t.Fatal("unaccepted evidence misreported as accepted", snap, installs.Load())
	}
}
