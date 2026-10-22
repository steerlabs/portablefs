//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func r4FDCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

func r4Pipe() *Rights {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		panic(err)
	}
	return &Rights{FDs: []int{p[0], p[1]}}
}

func r4Observe(o *Owner, n, id uint64) (Response, error) {
	out, err := o.Do(context.Background(), request("workspace-observe", n, id), &Rights{})
	if err != nil {
		return out, err
	}
	if verr := out.ValidateWorkspace(); verr != nil {
		return out, fmt.Errorf("snapshot violates response grammar: %w", verr)
	}
	if _, eerr := EncodeResponse(out); eerr != nil {
		return out, fmt.Errorf("snapshot not encodable: %w", eerr)
	}
	return out, nil
}

func r4Unmount(n, id uint64, s ActionStatus, w Witness, terminal bool) Request {
	q := request("workspace-unmount-complete", n, id)
	q.Workspace.Phase = s.Action.WithWitness(w)
	q.Workspace.Phase.Removal = &Removal{KernelAbsent: true, AbortCompleted: terminal}
	return q
}

// R4-1: an accepted unmount-complete on a job that already failed overwrites
// the job's terminal "failed" state with "preparing" while keeping its reason.
func TestR4UnmountCompleteRewritesFailedJobState(t *testing.T) {
	offered, fail := make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		p := Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup", Witness: witness()}
		if err := j.OfferRemoval(p); err != nil {
			return err
		}
		close(offered)
		<-fail
		return errors.New("cleanup driver failed after offering removal")
	})
	j := start(t, o, cleanupRequest(1, "voluntary"))
	awaitResult(t, offered)
	close(fail)
	awaitResult(t, j.done)
	snap, err := r4Observe(o, 2, 1)
	if err != nil || snap.Workspace.State != "failed" {
		t.Fatal(snap, err)
	}
	q := r4Unmount(3, 1, snap.Workspace.Phases.VoluntaryRemoval, snap.Workspace.Witness, false)
	ack, err := o.Do(context.Background(), q, &Rights{})
	t.Logf("R4-1 unmount-complete on failed job: state=%v err=%v", ack.Workspace, err)
	after, err := r4Observe(o, 4, 1)
	o.mu.Lock()
	state, reason, running := o.job.state, o.job.reason, o.job.running
	o.mu.Unlock()
	t.Logf("R4-1 job after: state=%q reason=%q running=%v observeErr=%v", state, reason, running, err)
	if err != nil || (after.Workspace != nil && after.Workspace.State != "failed") {
		t.Errorf("REPRO R4-1: failed job resurrected or snapshot invalid: state=%q err=%v", state, err)
	}
	if _, err := o.Do(context.Background(), cleanupRequest(5, "terminal"), &Rights{}); err != nil {
		t.Fatalf("remaining cleanup refused after successful removal: %v", err)
	}
}

// R4-2: AdmitFrame cancels the current job for any valid Suspend/Cleanup
// frame whose semantic start differs, even when the frame is retired (an older
// operation) or belongs to another binding. A terminal cleanup cannot restart.
func TestR4RetiredCloseFrameCancelsCurrentJob(t *testing.T) {
	cases := []string{"retired-voluntary-cleanup-vs-terminal", "retired-suspend-vs-recovered-serving", "foreign-mount-suspend-vs-terminal"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			var closes atomic.Int32
			offered := make(chan string, 8)
			o := testOwner(t, func(ctx context.Context, j *Job) error {
				switch j.start.Operation {
				case "workspace-prepare":
					return j.Publish("preparing", Facts{})
				case "workspace-suspend":
					return j.Publish("cold", Facts{})
				case "workspace-recover":
					// Serving recovery: stays running until canceled.
					offered <- "recover"
					<-ctx.Done()
					return ctx.Err()
				}
				mode := j.start.Workspace.Phase.Mode
				p := Phase{ActionID: "2", Mode: mode, Reason: "cleanup", Witness: witness()}
				if mode == "terminal" {
					p.ActionID = "3"
				}
				if err := j.OfferRemoval(p); err != nil {
					return err
				}
				offered <- mode
				if err := j.WaitRemoval(ctx, mode); err != nil {
					return err
				}
				return j.Publish("cleanup-finalized", Facts{})
			})
			o.CloseAdmission = func() { closes.Add(1) }
			var current *Job
			var stale Request
			var currentID uint64
			switch name {
			case "retired-voluntary-cleanup-vs-terminal", "foreign-mount-suspend-vs-terminal":
				v := cleanupRequest(4, "voluntary")
				vj := start(t, o, v)
				awaitResult(t, offered)
				term := cleanupRequest(5, "terminal")
				for {
					_, err := o.Do(context.Background(), term, &Rights{})
					if err == nil {
						break
					}
					if !errors.Is(err, ErrOccupied) {
						t.Fatal(err)
					}
					time.Sleep(time.Millisecond)
				}
				awaitResult(t, vj.done)
				if m := awaitResult(t, offered); m != "terminal" {
					t.Fatal(m)
				}
				o.mu.Lock()
				current = o.job
				o.mu.Unlock()
				currentID = 5
				stale = v
				if name == "foreign-mount-suspend-vs-terminal" {
					stale = request("workspace-suspend", 9, 9)
					transaction(t, &stale)
					stale.MountInstanceID = "mnt_0000000000000000000002"
				}
			case "retired-suspend-vs-recovered-serving":
				pj := start(t, o, request("workspace-prepare", 1, 1))
				awaitResult(t, pj.done)
				s := request("workspace-suspend", 2, 2)
				transaction(t, &s)
				sj := start(t, o, s)
				awaitResult(t, sj.done)
				r := request("workspace-recover", 3, 3)
				transaction(t, &r)
				r.Workspace.Generation = "1"
				current = start(t, o, r)
				if m := awaitResult(t, offered); m != "recover" {
					t.Fatal(m)
				}
				currentID = 3
				stale = s // delayed retransmission of the already-completed Suspend
			}
			before := closes.Load()
			_, err := o.Do(context.Background(), stale, &Rights{})
			t.Logf("R4-2 %s: stale frame result: %v; admission closes +%d", name, err, closes.Load()-before)
			select {
			case <-current.done:
				snap, _ := r4Observe(o, 20, currentID)
				t.Errorf("REPRO R4-2 %s: stale frame canceled current job; state=%v", name, snap.Workspace)
				if name != "retired-suspend-vs-recovered-serving" {
					_, err := o.Do(context.Background(), cleanupRequest(6, "terminal"), &Rights{})
					t.Logf("R4-2 %s: restart terminal cleanup after cancellation: %v", name, err)
				}
			case <-time.After(300 * time.Millisecond):
				t.Logf("R4-2 %s: current job survived", name)
			}
		})
	}
}

// R4-3: Finalize before Finish (mount syscall still in flight) succeeds, and a
// later Finish moves rights into a finalized Bootstrap that never closes them.
func TestR4BootstrapFinalizeBeforeFinishLeaksRights(t *testing.T) {
	var b Bootstrap
	p := *phase()
	p.Witness.Kernel = ""
	if err := b.Begin(p); err != nil {
		t.Fatal(err)
	}
	ferr := b.Finalize(Absence{true, true, true, true})
	d, fds := descriptors(t)
	err := b.Finish(d, witness())
	t.Logf("R4-3 Finalize-before-Finish=%v Finish-after-Finalize=%v", ferr, err)
	open := 0
	for _, fd := range fds {
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e == nil {
			open++
		}
	}
	if ferr == nil && open > 0 {
		t.Errorf("REPRO R4-3: finalized bootstrap retained %d descriptors with no owner", open)
	}
	if !errors.Is(ferr, ErrOccupied) || err != nil {
		t.Fatalf("outstanding owner not joined: finalize=%v finish=%v", ferr, err)
	}
	if err := b.Finalize(Absence{true, true, true, true}); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, fds)
}

// R4-3b: removal can be reserved while the root's single mount attempt has
// begun but not finished.
func TestR4BootstrapRemovalBeforeFinish(t *testing.T) {
	var b Bootstrap
	p := *phase()
	if err := b.Begin(p); err != nil {
		t.Fatal(err)
	}
	s := ActionStatus{Progress: "offered", Action: kernelAction(Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup"})}
	err := b.BeginRemoval(s, p.Witness)
	t.Logf("R4-3b BeginRemoval before Finish: %v", err)
	if !errors.Is(err, ErrOccupied) {
		t.Fatalf("removal overtook mount owner: %v", err)
	}
	if err := b.Finish(&Rights{}, Witness{}); !errors.Is(err, ErrGrammar) {
		t.Fatal(err)
	}
	if err := b.Finalize(Absence{true, true, true, true}); err != nil {
		t.Fatal(err)
	}
}

// R4-3c: a "running" observation before Finish latches childOwns although no
// rights exist, permanently blocking Handoff.
func TestR4BootstrapObserveBeforeFinishLatchesChildOwns(t *testing.T) {
	var b Bootstrap
	p := *phase()
	p.Witness.Kernel = ""
	if err := b.Begin(p); err != nil {
		t.Fatal(err)
	}
	err := b.ObserveInstall(ActionStatus{Progress: "running", Action: kernelAction(p)}, p.Witness)
	d, fds := descriptors(t)
	if ferr := b.Finish(d, witness()); ferr != nil {
		t.Fatal(ferr)
	}
	copy, herr := b.Handoff()
	t.Logf("R4-3c ObserveInstall-before-Finish=%v Handoff=%v", err, herr)
	if copy != nil {
		copy.Close()
	}
	if err == nil || herr != nil {
		t.Fatalf("early observation=%v subsequent handoff=%v", err, herr)
	}
	b.Finalize(Absence{true, true, true, true})
	assertClosed(t, fds)
}

// R4-4: job replacement while the install worker is still running.
func TestR4ReplacementWaitsForRunningInstall(t *testing.T) {
	installEntered, releaseInstall := make(chan struct{}), make(chan struct{})
	var installCtxErr atomic.Value
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-suspend" {
			return j.Publish("cold", Facts{})
		}
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		return j.WaitInstall(ctx) // canceled by Suspend while install runs
	})
	o.Driver.Install = func(ctx context.Context, j *Job, r *Rights) (Witness, error) {
		close(installEntered)
		<-releaseInstall
		installCtxErr.Store(fmt.Sprint(ctx.Err()))
		return witness(), nil
	}
	base := r4FDCount(t)
	pj := start(t, o, request("workspace-prepare", 1, 1))
	for {
		o.mu.Lock()
		ok := o.install.status.Progress == "offered"
		o.mu.Unlock()
		if ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	d, fds := descriptors(t)
	if ack := do(t, o, installRequest(2, 1), d); ack.Workspace.State != "accepted" {
		t.Fatal(ack)
	}
	awaitResult(t, installEntered)
	s := request("workspace-suspend", 3, 3)
	transaction(t, &s)
	_, err := o.Do(context.Background(), s, &Rights{})
	awaitResult(t, pj.done)
	_, err2 := o.Do(context.Background(), s, &Rights{})
	t.Logf("R4-4 suspend while install running: first=%v after prepare worker exit=%v", err, err2)
	if !errors.Is(err2, ErrOccupied) {
		t.Errorf("job replaced while install worker still running: %v", err2)
	}
	close(releaseInstall)
	o.mu.Lock()
	done := o.install.done
	o.mu.Unlock()
	awaitResult(t, done)
	sj := start(t, o, s)
	awaitResult(t, sj.done)
	snap, err := r4Observe(o, 4, 3)
	t.Logf("R4-4 final: state=%s install=%+v installCtx=%v err=%v", snap.Workspace.State, snap.Workspace.Phases.Install.Progress, installCtxErr.Load(), err)
	// Rights stay in the slot until Close/CloseKernel.
	open := 0
	for _, fd := range fds {
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e == nil {
			open++
		}
	}
	if open != 2 {
		t.Errorf("accepted install rights not retained: %d open", open)
	}
	o.Close()
	assertClosed(t, fds)
	if n := r4FDCount(t); n != base {
		t.Errorf("fd count %d != base %d", n, base)
	}
}

// R4-5: drain deadline captured once on acceptance; equal retries cannot
// extend it; a drain that is already spent at acceptance still accepts.
func TestR4DrainDeadlineCaptureAndRetry(t *testing.T) {
	var ctxDeadline atomic.Value
	release := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-prepare" {
			return j.Publish("preparing", Facts{})
		}
		d, _ := ctx.Deadline()
		ctxDeadline.Store(d)
		<-release
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return j.Publish("cold", Facts{})
	})
	pj := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, pj.done)
	s := request("workspace-suspend", 2, 2)
	transaction(t, &s)
	s.Workspace.DrainBudgetNanos = "1000000000"
	received := time.Now()
	if _, err := o.DoAdmitted(context.Background(), s, &Rights{}, received); err != nil {
		t.Fatal(err)
	}
	o.mu.Lock()
	j := o.job
	first := j.drainDeadline
	o.mu.Unlock()
	retry := s
	w := *s.Workspace
	w.DrainBudgetNanos = "15000000000"
	retry.Workspace = &w
	if out, err := o.DoAdmitted(context.Background(), retry, &Rights{}, time.Now()); err != nil || out.Workspace.State != "accepted" {
		t.Fatal(out, err)
	}
	if j.drainDeadline != first || o.job != j {
		t.Errorf("retry extended or replaced drain deadline")
	}
	close(release)
	awaitResult(t, j.done)
	snap, _ := r4Observe(o, 3, 2)
	t.Logf("R4-5 captured=%v ctx=%v final=%s", first.Sub(received), ctxDeadline.Load().(time.Time).Sub(received), snap.Workspace.State)

	// Already-spent drain allowance at acceptance (framing took longer than drain).
	release2 := make(chan struct{})
	close(release2)
	o2 := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-prepare" {
			return j.Publish("preparing", Facts{})
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return j.Publish("cold", Facts{})
	})
	pj2 := start(t, o2, request("workspace-prepare", 1, 1))
	awaitResult(t, pj2.done)
	s2 := request("workspace-suspend", 2, 2)
	transaction(t, &s2)
	s2.Workspace.DrainBudgetNanos = "1000000"
	_, err := o2.DoAdmitted(context.Background(), s2, &Rights{}, time.Now().Add(-time.Second))
	if !errors.Is(err, context.DeadlineExceeded) || o2.job != pj2 {
		t.Fatalf("spent drain accepted or consumed identity: %v", err)
	}

}

// R4-6: stale action IDs and modes are refused without consuming the slot.
func TestR4StaleActionIDsDoNotConsume(t *testing.T) {
	offered := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		close(offered)
		if err := j.WaitInstall(ctx); err != nil {
			return err
		}
		return j.Publish("prepared", readyFacts())
	})
	var closes atomic.Int32
	o.CloseAdmission = func() { closes.Add(1) }
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	bad := []func(*Request){
		func(q *Request) { q.Workspace.Phase.ActionID = "9" },
		func(q *Request) { q.Workspace.Phase.Options = []string{"nodev"} },
		func(q *Request) { q.Workspace.Phase.Witness.Target = "/other" },
		func(q *Request) { q.Workspace.OperationID = "2"; q.Workspace.RequestID = "3" },
	}
	for i, mutate := range bad {
		q := installRequest(uint64(10+i), 1)
		mutate(&q)
		d, fds := descriptors(t)
		_, err := o.Do(context.Background(), q, d)
		assertClosed(t, fds)
		t.Logf("R4-6 stale install %d: %v", i, err)
		if err == nil {
			t.Fatal("stale action accepted")
		}
	}
	// unmount-complete for the install action is refused.
	u := request("workspace-unmount-complete", 20, 1)
	u.Workspace.Phase = &Phase{ActionID: "1", Mode: "voluntary", Reason: "x", Witness: witness(), Removal: &Removal{KernelAbsent: true}}
	_, err := o.Do(context.Background(), u, &Rights{})
	t.Logf("R4-6 unmount against install slot: %v", err)
	snap, _ := r4Observe(o, 21, 1)
	if snap.Workspace.Phases.Install.Progress != "offered" {
		t.Fatal("stale action consumed slot", snap.Workspace.Phases)
	}
	d, _ := descriptors(t)
	if ack := do(t, o, installRequest(22, 1), d); ack.Workspace.State != "accepted" {
		t.Fatal(ack)
	}
	awaitResult(t, j.done)
	snap, _ = r4Observe(o, 23, 1)
	t.Logf("R4-6 final state=%s admissionCloses=%d", snap.Workspace.State, closes.Load())
}

// R4-7: Publish from a stray goroutine after Run returned mutates a finished job.
func TestR4PublishAfterRunReturned(t *testing.T) {
	var held *Job
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		held = j
		return j.Publish("cold", Facts{})
	})
	pj := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, pj.done)
	_ = held
	s := request("workspace-suspend", 2, 2)
	transaction(t, &s)
	sj := start(t, o, s)
	awaitResult(t, sj.done)
	err := sj.Publish("pending-suspend", Facts{})
	snap, _ := r4Observe(o, 3, 2)
	if !errors.Is(err, ErrRetired) || snap.Workspace.State != "cold" || sj.running {
		t.Fatalf("finished job mutated: %v %+v", err, snap.Workspace)
	}
	if err := sj.OfferInstall(*phase()); err == nil {
		t.Fatal("ended job offered install")
	}
	if err := sj.OfferRemoval(Phase{}); err == nil {
		t.Fatal("ended job offered removal")
	}
}

// R4-8: concurrent starts, phases, observations, AdmitFrame and Close. Race
// detector + invariant checks + /proc/self/fd leak accounting.
func TestR4ConcurrentOwnerStress(t *testing.T) {
	invalidIters := 0
	defer func() { t.Logf("R4-8 iterations with invalid snapshots: %d/40", invalidIters) }()
	for iter := 0; iter < 40; iter++ {
		base := r4FDCount(t)
		var runs, installs, prepares atomic.Int32
		o := &Owner{CheckPermit: func(Workspace) bool { return true }}
		o.Driver = Driver{
			ValidateInstall: func(*Rights, Phase) error { runtime.Gosched(); return nil },
			Install: func(ctx context.Context, j *Job, r *Rights) (Witness, error) {
				installs.Add(1)
				time.Sleep(time.Duration(rand.Intn(200)) * time.Microsecond)
				return witness(), nil
			},
			Run: func(ctx context.Context, j *Job) error {
				runs.Add(1)
				switch j.start.Operation {
				case "workspace-prepare":
					prepares.Add(1)
					if err := j.OfferInstall(*phase()); err != nil {
						return err
					}
					if err := j.WaitInstall(ctx); err != nil {
						return err
					}
					if err := j.Publish("prepared", readyFacts()); err != nil {
						return err
					}
					<-ctx.Done()
					return nil
				case "workspace-suspend":
					j.CloseKernel()
					return j.Publish("cold", Facts{})
				}
				p := Phase{ActionID: "2", Mode: j.start.Workspace.Phase.Mode, Reason: "cleanup", Witness: readyFacts().Witness}
				if p.Mode == "terminal" {
					p.ActionID = "3"
				}
				if err := j.OfferRemoval(p); err != nil {
					return err
				}
				if err := j.WaitRemoval(ctx, p.Mode); err != nil {
					return err
				}
				return j.Publish("cleanup-finalized", Facts{})
			},
		}
		var admits atomic.Int32
		o.CloseAdmission = func() { admits.Add(1) }
		var wg sync.WaitGroup
		stop := make(chan struct{})
		var invalid atomic.Value
		worker := func(f func(i int)) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					f(i)
				}
			}()
		}
		ctx := context.Background()
		worker(func(i int) { o.Do(ctx, request("workspace-prepare", 1, 1), &Rights{}) })
		worker(func(i int) {
			for _, id := range []uint64{1, 2, 3, 4} {
				out, err := o.Do(ctx, request("workspace-observe", uint64(100+i%50), id), &Rights{})
				if err == nil {
					if verr := out.ValidateWorkspace(); verr != nil {
						invalid.Store(fmt.Sprintf("op %d: %v state=%q reason=%q", id, verr, out.Workspace.State, out.Workspace.Reason))
					}
				}
			}
		})
		worker(func(i int) {
			o.Do(ctx, installRequest(uint64(200+i%50), 1), r4Pipe())
		})
		worker(func(i int) {
			time.Sleep(time.Duration(rand.Intn(300)) * time.Microsecond)
			c := cleanupRequest(3, "voluntary")
			c.Workspace.Phase.Witness = readyFacts().Witness
			o.Do(ctx, c, &Rights{})
			c = cleanupRequest(4, "terminal")
			c.Workspace.Phase.Witness = readyFacts().Witness
			o.Do(ctx, c, &Rights{})
		})
		worker(func(i int) {
			s := request("workspace-suspend", 2, 2)
			transaction(t, &s)
			o.Do(ctx, s, &Rights{})
		})
		worker(func(i int) {
			c := cleanupRequest(3, "voluntary")
			c.Workspace.Phase.Witness = readyFacts().Witness
			o.AdmitFrame(c, &Rights{})
			time.Sleep(50 * time.Microsecond)
		})
		worker(func(i int) {
			o.mu.Lock()
			v, term, w := status(o.voluntary), status(o.terminal), o.facts.Witness
			o.mu.Unlock()
			if v.Progress == "offered" {
				o.Do(ctx, r4Unmount(uint64(300+i%50), 3, v, w, false), &Rights{})
			}
			if term.Progress == "offered" {
				o.Do(ctx, r4Unmount(uint64(300+i%50), 4, term, w, true), &Rights{})
			}
			runtime.Gosched()
		})
		time.Sleep(time.Duration(5+rand.Intn(20)) * time.Millisecond)
		closed := make(chan struct{})
		go func() { o.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("Close deadlocked\n%s", buf[:n])
		}
		close(stop)
		wg.Wait()
		o.Close()
		if v := invalid.Load(); v != nil {
			invalidIters++
			if invalidIters == 1 {
				t.Errorf("iteration %d invalid snapshot: %v", iter, v)
			}
		}
		if installs.Load() > 1 || prepares.Load() > 1 {
			t.Errorf("iteration %d: at-most-once violated installs=%d prepares=%d", iter, installs.Load(), prepares.Load())
		}
		if n := r4FDCount(t); n != base {
			t.Errorf("iteration %d: fd count %d != base %d", iter, n, base)
		}
	}
}

// R4-9: Close during first-delivery validation and after acceptance races.
func TestR4CloseDuringValidationDisposesRights(t *testing.T) {
	for i := 0; i < 200; i++ {
		base := r4FDCount(t)
		offered := make(chan struct{})
		o := &Owner{CheckPermit: func(Workspace) bool { return true }}
		o.Driver = Driver{
			Run: func(ctx context.Context, j *Job) error {
				if err := j.OfferInstall(*phase()); err != nil {
					return err
				}
				close(offered)
				return j.WaitInstall(ctx)
			},
			ValidateInstall: func(*Rights, Phase) error { runtime.Gosched(); return nil },
			Install:         func(context.Context, *Job, *Rights) (Witness, error) { return witness(), nil },
		}
		if _, err := o.Do(context.Background(), request("workspace-prepare", 1, 1), &Rights{}); err != nil {
			t.Fatal(err)
		}
		awaitResult(t, offered)
		d, _ := descriptors(t)
		done := make(chan struct{})
		go func() { o.Do(context.Background(), installRequest(2, 1), d); close(done) }()
		if i%2 == 0 {
			runtime.Gosched()
		}
		o.Close()
		<-done
		o.Close()
		if n := r4FDCount(t); n != base {
			t.Fatalf("iteration %d: fd count %d != base %d", i, n, base)
		}
	}
}

// R4-10: failed install handler retains rights for cleanup; CloseKernel disposes.
func TestR4FailedInstallRetainsRightsUntilCloseKernel(t *testing.T) {
	offered, waited := make(chan struct{}), make(chan error, 1)
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.start.Operation == "workspace-cleanup" {
			j.CloseKernel()
			return nil
		}
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		close(offered)
		err := j.WaitInstall(ctx)
		waited <- err
		return err
	})
	o.Driver.Install = func(context.Context, *Job, *Rights) (Witness, error) {
		w := witness()
		w.Session = "partial"
		return w, errors.New("INIT failed")
	}
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	d, fds := descriptors(t)
	do(t, o, installRequest(2, 1), d)
	t.Logf("R4-10 WaitInstall after failed handler: %v", awaitResult(t, waited))
	awaitResult(t, j.done)
	snap, err := r4Observe(o, 3, 1)
	t.Logf("R4-10 snapshot state=%s install=%+v witness=%+v err=%v", snap.Workspace.State, snap.Workspace.Phases.Install, snap.Workspace.Witness, err)
	for _, fd := range fds {
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e != nil {
			t.Fatal("failed install did not retain rights")
		}
	}
	c := cleanupRequest(4, "voluntary")
	c.Workspace.Phase.Witness.Session = "partial"
	cj := start(t, o, c)
	awaitResult(t, cj.done)
	assertClosed(t, fds)
}

// R4-11: many observations and loss publications retain bounded state.
func TestR4ObservationAndLossGrowthBounded(t *testing.T) {
	release := make(chan struct{})
	var pub *Job
	ready := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		pub = j
		close(ready)
		<-release
		return nil
	})
	start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, ready)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	before := ms.HeapAlloc
	for i := 0; i < 20000; i++ {
		if _, err := o.Do(context.Background(), request("workspace-observe", uint64(i%7+2), 1), &Rights{}); err != nil {
			t.Fatal(err)
		}
		if i%100 == 0 {
			loss := []Loss{{Sequence: "1", AcceptedEntries: "1", AcceptedBytes: "1", Reason: "r"}}
			if err := pub.Publish("preparing", Facts{Loss: loss}); err != nil {
				t.Fatal(err)
			}
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&ms)
	o.mu.Lock()
	n := len(o.facts.Loss)
	o.mu.Unlock()
	t.Logf("R4-11 heap delta after 20000 observations: %d bytes; retained losses=%d", int64(ms.HeapAlloc)-int64(before), n)
	if n != 1 {
		t.Errorf("loss ledger grew: %d", n)
	}
}

// R4-12: socket-level cancel after acceptance (ctx cancel between first and
// second lock in install) disposes rights and leaves slot offered.
func TestR4InstallCancelBetweenLocksLeavesOffer(t *testing.T) {
	offered := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		close(offered)
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	o.Driver.ValidateInstall = func(*Rights, Phase) error { cancel(); return nil }
	start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	d, fds := descriptors(t)
	_, err := o.Do(ctx, installRequest(2, 1), d)
	assertClosed(t, fds)
	snap, _ := r4Observe(o, 3, 1)
	t.Logf("R4-12 canceled after validation: err=%v install=%s", err, snap.Workspace.Phases.Install.Progress)
	if snap.Workspace.Phases.Install.Progress != "offered" {
		t.Error("unaccepted install consumed slot")
	}
}
