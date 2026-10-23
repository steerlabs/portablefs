//go:build linux

package mountcontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
)

// ---------- helpers ----------

func o5Req(t *testing.T, op string, id, gen uint64, mode string) Request {
	t.Helper()
	q := request(op, id, id)
	q.Workspace.Generation = strconv.FormatUint(gen, 10)
	q.Workspace.GateSerial = "2"
	switch op {
	case "workspace-suspend", "workspace-recover":
		q.Workspace.HostRequestID = "7"
		s := suspension(t)
		s.Generation = gen
		var err error
		if op == "workspace-suspend" {
			q.Workspace.DrainBudgetNanos = "15000000000"
			q.Workspace.Transaction, err = EncodeTransaction(s)
		} else {
			q.Workspace.Transaction, err = EncodeTransaction(&pb.ResumeToken{Suspension: s, WakeNonce: bytes.Repeat([]byte{7}, 16)})
		}
		if err != nil {
			t.Fatal(err)
		}
	case "workspace-cleanup":
		q.Workspace.Phase = &Phase{Mode: mode, Witness: witness()}
	}
	if err := q.ValidateWorkspace(); err != nil {
		t.Fatalf("fixture %s/%d invalid: %v", op, id, err)
	}
	return q
}

func o5Encodable(out Response) error {
	if err := out.ValidateWorkspace(); err != nil {
		return err
	}
	_, err := EncodeResponse(out)
	return err
}

func o5Open(fds []int) int {
	n := 0
	for _, fd := range fds {
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e == nil {
			n++
		}
	}
	return n
}

// a proof observed before the late mount existed still finalizes afterwards.
func TestO5IntervalResetKeepsCumulativeEvidence(t *testing.T) {
	loss1 := []Loss{{Sequence: "1", AcceptedEntries: "1", AcceptedBytes: "4", Reason: "first interval"}}
	loss2 := append(append([]Loss(nil), loss1...), Loss{Sequence: "2", AcceptedEntries: "2", AcceptedBytes: "8", Reason: "second interval"})
	var recoverFails atomic.Bool
	offered := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		q := j.Request()
		switch q.Operation {
		case "workspace-prepare":
			if err := j.OfferInstall(*phase()); err != nil {
				return err
			}
			close(offered)
			if err := j.WaitInstall(ctx); err != nil {
				return err
			}
			return j.Publish("prepared", readyFacts())
		case "workspace-recover":
			if recoverFails.Load() {
				if err := j.Publish("pending-recovery", Facts{}); err != nil {
					return err
				}
				return errors.New("recovery failed before serving")
			}
			f := readyFacts()
			f.Loss = loss1
			return j.Publish("prepared", f)
		case "workspace-suspend":
			if q.Workspace.Generation == "1" {
				return j.Publish("cold", Facts{Outcome: Outcome{"lost", "observed", "abandoned", "2"}, Loss: loss1})
			}
			if q.Workspace.Generation == "2" {
				return j.Publish("cold", Facts{Outcome: Outcome{"durable", "observed", "released", "0"}, Loss: loss1})
			}
			return j.Publish("cold", Facts{Outcome: Outcome{"lost", "observed", "abandoned", "1"}, Loss: loss2})
		}
		return errors.New("unexpected")
	})
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	d, _ := descriptors(t)
	do(t, o, installRequest(2, 1), d)
	awaitResult(t, j.done)
	snap := observe(t, o, 3, 1)
	t.Logf("interval0 prepared: %+v loss=%d", snap.Workspace.Outcome, len(snap.Workspace.Loss))

	s := request("workspace-suspend", 4, 4)
	transaction(t, &s)
	j = start(t, o, s)
	awaitResult(t, j.done)
	snap = observe(t, o, 5, 4)
	t.Logf("cut1 (lost): state=%s %+v loss=%d", snap.Workspace.State, snap.Workspace.Outcome, len(snap.Workspace.Loss))

	r := request("workspace-recover", 6, 6)
	transaction(t, &r)
	j = start(t, o, r)
	awaitResult(t, j.done)
	snap = observe(t, o, 7, 6)
	t.Logf("interval2 prepared: state=%s %+v loss=%d", snap.Workspace.State, snap.Workspace.Outcome, len(snap.Workspace.Loss))
	if snap.Workspace.Outcome.Durability != "unresolved" || snap.Workspace.Outcome.Observation != "unobserved" || snap.Workspace.Outcome.CleanupDebt != "2" || len(snap.Workspace.Loss) != 1 {
		t.Errorf("new interval did not reset disposition while keeping cumulative debt/loss: %+v loss=%v", snap.Workspace.Outcome, snap.Workspace.Loss)
	}
	s2 := o5Req(t, "workspace-suspend", 8, 2, "")
	s2.Workspace.GateSerial = "0"
	j = start(t, o, s2)
	awaitResult(t, j.done)
	q := request("workspace-observe", 9, 8)
	q.Workspace.Generation = "2"
	snap = do(t, o, q, &Rights{})
	t.Logf("cut2 (durable): state=%s %+v loss=%d", snap.Workspace.State, snap.Workspace.Outcome, len(snap.Workspace.Loss))
	if snap.Workspace.State != "cold" || snap.Workspace.Outcome.Durability != "durable" || snap.Workspace.Outcome.CleanupDebt != "2" {
		t.Errorf("second interval cut wrong: %+v", snap.Workspace)
	}

	// A failed recovery claims no new interval: the durable cut remains.
	recoverFails.Store(true)
	r2 := o5Req(t, "workspace-recover", 10, 2, "")
	r2.Workspace.GateSerial = "0"
	j = start(t, o, r2)
	awaitResult(t, j.done)
	q = request("workspace-observe", 11, 10)
	q.Workspace.Generation = "2"
	snap = do(t, o, q, &Rights{})
	t.Logf("failed recovery: state=%s %+v", snap.Workspace.State, snap.Workspace.Outcome)
	if snap.Workspace.State != "failed" || snap.Workspace.Outcome.Durability != "durable" {
		t.Errorf("failed recovery changed the interval: %+v", snap.Workspace)
	}
	if err := o5Encodable(snap); err != nil {
		t.Error(err)
	}
}

// A prepared publication that also carries a conflicting cut is refused; its
// Loss still merges; no interval starts.
func TestO5PreparedWithConflictingCutStillMergesLoss(t *testing.T) {
	entered := make(chan *Job, 1)
	offered := make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		switch j.Request().Operation {
		case "workspace-prepare":
			if err := j.OfferInstall(*phase()); err != nil {
				return err
			}
			close(offered)
			if err := j.WaitInstall(ctx); err != nil {
				return err
			}
			return j.Publish("prepared", readyFacts())
		case "workspace-suspend":
			return j.Publish("cold", Facts{Outcome: Outcome{"durable", "observed", "released", "0"}})
		case "workspace-recover":
			entered <- j
			<-ctx.Done()
			return ctx.Err()
		}
		return errors.New("unexpected")
	})
	j := start(t, o, request("workspace-prepare", 1, 1))
	awaitResult(t, offered)
	d, _ := descriptors(t)
	do(t, o, installRequest(2, 1), d)
	awaitResult(t, j.done)
	s := request("workspace-suspend", 3, 3)
	transaction(t, &s)
	j = start(t, o, s)
	awaitResult(t, j.done)
	r := request("workspace-recover", 4, 4)
	transaction(t, &r)
	start(t, o, r)
	rj := awaitResult(t, entered)
	f := readyFacts()
	f.Outcome = Outcome{"lost", "observed", "abandoned", "3"}
	f.Loss = []Loss{{Sequence: "1", AcceptedEntries: "1", AcceptedBytes: "1", Reason: "x"}}
	err := rj.Publish("prepared", f)
	snap := observe(t, o, 5, 4)
	t.Logf("prepared+conflicting cut: publish=%v state=%s %+v loss=%d", err, snap.Workspace.State, snap.Workspace.Outcome, len(snap.Workspace.Loss))
	if err == nil || snap.Workspace.State == "prepared" || len(snap.Workspace.Loss) != 1 || snap.Workspace.Outcome.CleanupDebt != "3" {
		t.Errorf("unexpected merge result")
	}
}

// ---------- 3. legal successor rules and AdmitFrame/start races ----------

type o5Scenario struct {
	name    string
	setup   func(t *testing.T, o *Owner) *Job
	illegal map[string]Request
	legal   map[string]Request
}

func TestO5IllegalCloseFramesNeverCancelLiveJob(t *testing.T) {
	run := func(ctx context.Context, j *Job) error {
		q := j.Request()
		switch q.Operation {
		case "workspace-suspend":
			if q.Workspace.OperationID == "4" {
				return j.Publish("cold", Facts{})
			}
		case "workspace-cleanup":
			p := Phase{ActionID: "2", Mode: q.Workspace.Phase.Mode, Reason: "cleanup", Witness: witness()}
			if p.Mode == "terminal" {
				p.ActionID = "3"
			}
			if err := j.OfferRemoval(p); err != nil {
				return err
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}
	conflicting := func(r Request) Request {
		r = cloneRequest(r)
		r.Workspace.Phase.Witness.Kernel = "other-kernel"
		return r
	}
	foreign := func(r Request, f func(*Request)) Request { r = cloneRequest(r); f(&r); return r }
	scenarios := []func(t *testing.T) o5Scenario{
		func(t *testing.T) o5Scenario {
			return o5Scenario{name: "suspend-running",
				setup: func(t *testing.T, o *Owner) *Job { return start(t, o, o5Req(t, "workspace-suspend", 5, 2, "")) },
				illegal: map[string]Request{
					"retired-suspend":       o5Req(t, "workspace-suspend", 4, 2, ""),
					"retired-cleanup":       o5Req(t, "workspace-cleanup", 3, 2, "terminal"),
					"equal-changed":         foreign(o5Req(t, "workspace-suspend", 5, 2, ""), func(r *Request) { r.Workspace.HostRequestID = "9" }),
					"foreign-mount":         foreign(o5Req(t, "workspace-suspend", 6, 2, ""), func(r *Request) { r.MountInstanceID = "mnt_0000000000000000000002" }),
					"foreign-boot":          foreign(o5Req(t, "workspace-cleanup", 6, 2, "terminal"), func(r *Request) { r.Workspace.BootID = "04040404040404040404040404040404" }),
					"foreign-guest-service": foreign(o5Req(t, "workspace-cleanup", 6, 2, "terminal"), func(r *Request) { r.Workspace.GuestServiceID = "04040404040404040404040404040404" }),
					"older-generation":      o5Req(t, "workspace-cleanup", 6, 1, "terminal"),
					"older-serial":          foreign(o5Req(t, "workspace-cleanup", 6, 2, "terminal"), func(r *Request) { r.Workspace.GateSerial = "1" }),
				},
				legal: map[string]Request{"terminal-cleanup": o5Req(t, "workspace-cleanup", 6, 2, "terminal")},
			}
		},
		func(t *testing.T) o5Scenario {
			return o5Scenario{name: "voluntary-cleanup-running",
				setup: func(t *testing.T, o *Owner) *Job {
					return start(t, o, o5Req(t, "workspace-cleanup", 5, 2, "voluntary"))
				},
				illegal: map[string]Request{
					"voluntary-after-voluntary": o5Req(t, "workspace-cleanup", 6, 2, "voluntary"),
					"suspend-after-cleanup":     o5Req(t, "workspace-suspend", 6, 2, ""),
					"terminal-conflicting":      conflicting(o5Req(t, "workspace-cleanup", 6, 2, "terminal")),
					"equal-retry":               o5Req(t, "workspace-cleanup", 5, 2, "voluntary"),
				},
				legal: map[string]Request{"terminal-escalation": o5Req(t, "workspace-cleanup", 6, 2, "terminal")},
			}
		},
		func(t *testing.T) o5Scenario {
			return o5Scenario{name: "terminal-cleanup-running",
				setup: func(t *testing.T, o *Owner) *Job { return start(t, o, o5Req(t, "workspace-cleanup", 5, 2, "terminal")) },
				illegal: map[string]Request{
					"voluntary-after-terminal": o5Req(t, "workspace-cleanup", 6, 2, "voluntary"),
					"terminal-after-terminal":  o5Req(t, "workspace-cleanup", 6, 2, "terminal"),
					"suspend-after-terminal":   o5Req(t, "workspace-suspend", 6, 2, ""),
				},
			}
		},
		func(t *testing.T) o5Scenario {
			return o5Scenario{name: "recover-serving",
				setup: func(t *testing.T, o *Owner) *Job {
					j := start(t, o, o5Req(t, "workspace-suspend", 4, 2, ""))
					awaitResult(t, j.done)
					return start(t, o, o5Req(t, "workspace-recover", 5, 2, ""))
				},
				illegal: map[string]Request{
					"retired-suspend":  o5Req(t, "workspace-suspend", 4, 2, ""),
					"foreign-mount":    foreign(o5Req(t, "workspace-suspend", 6, 2, ""), func(r *Request) { r.MountInstanceID = "mnt_0000000000000000000002" }),
					"older-generation": foreign(o5Req(t, "workspace-suspend", 6, 1, ""), func(r *Request) {}),
				},
				legal: map[string]Request{"suspend": o5Req(t, "workspace-suspend", 6, 2, ""), "cleanup": o5Req(t, "workspace-cleanup", 6, 2, "voluntary")},
			}
		},
	}
	for _, mkScenario := range scenarios {
		sc := mkScenario(t)
		t.Run(sc.name, func(t *testing.T) {
			var closes atomic.Int32
			o := testOwner(t, run)
			o.CloseAdmission = func() { closes.Add(1) }
			j := sc.setup(t, o)
			baseCloses := closes.Load()
			var wg sync.WaitGroup
			for name, frame := range sc.illegal {
				for g := 0; g < 4; g++ {
					wg.Add(1)
					go func(name string, frame Request) {
						defer wg.Done()
						for k := 0; k < 50; k++ {
							if k%2 == 0 {
								o.AdmitFrame(frame, &Rights{})
							} else {
								o.Do(context.Background(), frame, &Rights{})
							}
						}
					}(name, frame)
				}
			}
			wg.Wait()
			o.mu.Lock()
			current := o.job
			o.mu.Unlock()
			if j.ctx.Err() != nil || current != j {
				t.Errorf("%s: illegal close frame canceled or replaced the live job (ctx=%v replaced=%v)", sc.name, j.ctx.Err(), current != j)
			}
			want := int32(0)
			for range sc.illegal {
				want += 4 * 50
			}
			t.Logf("%s: illegal frames=%d admission closes=%d live job intact=%v", sc.name, want, closes.Load(), j.ctx.Err() == nil)
			if closes.Load()-baseCloses != want {
				t.Errorf("admission invalidation count %d != frames %d", closes.Load(), want)
			}
			for name, frame := range sc.legal {
				if err := o.AdmitFrame(frame, &Rights{}); err != nil {
					t.Fatal(name, err)
				}
				if j.ctx.Err() == nil {
					t.Errorf("%s: legal successor %s did not cancel", sc.name, name)
				}
				break
			}
		})
	}
}

// AdmitFrame races the start it would have to cancel: a terminal Cleanup frame
// whose AdmitFrame runs before an earlier legal Recover is accepted cannot
// cancel it; the root's retry of the same start must still converge.
func TestO5AdmitFrameVersusStartRace(t *testing.T) {
	var stuck, converged, recoverWon, recoverCanceled int
	for i := 0; i < 300; i++ {
		o := testOwner(t, func(ctx context.Context, j *Job) error {
			switch j.Request().Operation {
			case "workspace-suspend":
				return j.Publish("cold", Facts{})
			case "workspace-recover":
				<-ctx.Done()
				return ctx.Err()
			}
			<-ctx.Done()
			return ctx.Err()
		})
		sj := start(t, o, o5Req(t, "workspace-suspend", 1, 2, ""))
		awaitResult(t, sj.done)
		rec := o5Req(t, "workspace-recover", 2, 2, "")
		cleanup := o5Req(t, "workspace-cleanup", 3, 2, "terminal")
		var wg sync.WaitGroup
		var recErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, recErr = o.Do(context.Background(), rec, &Rights{}) }()
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				time.Sleep(time.Duration(rand.Intn(100)) * time.Microsecond)
			}
			o.Do(context.Background(), cleanup, &Rights{})
		}()
		wg.Wait()
		var rj *Job
		if i < 3 {
			t.Logf("race iteration %d: recover result %v", i, recErr)
		}
		if recErr == nil {
			recoverWon++
			o.mu.Lock()
			for _, cand := range []*Job{o.job} {
				if cand != nil && cand.start.Operation == "workspace-recover" {
					rj = cand
				}
			}
			o.mu.Unlock()
		}
		deadline := time.Now().Add(2 * time.Second)
		var err error
		for time.Now().Before(deadline) {
			_, err = o.Do(context.Background(), cleanup, &Rights{})
			if err == nil || !errors.Is(err, ErrOccupied) {
				break
			}
			time.Sleep(200 * time.Microsecond)
		}
		if rj != nil && rj.ctx.Err() != nil {
			recoverCanceled++
		}
		if err != nil {
			stuck++
			if stuck == 1 {
				t.Errorf("iteration %d: terminal cleanup never accepted: %v", i, err)
			}
		} else {
			converged++
		}
		o.Close()
	}
	t.Logf("AdmitFrame/start race: converged=%d stuck=%d recoverAcceptedFirst=%d (all later canceled by retry: %d)", converged, stuck, recoverWon, recoverCanceled)
}

// A legal-looking Close with a stale permit is not allowed to cancel, but the
// start path reports occupied before it checks the permit.
func TestO5StalePermitCloseRefusesInvalid(t *testing.T) {
	var serial atomic.Uint64
	serial.Store(2)
	o := testOwner(t, func(ctx context.Context, j *Job) error { <-ctx.Done(); return ctx.Err() })
	o.CheckPermit = func(w Workspace) bool { return w.GateSerial == strconv.FormatUint(serial.Load(), 10) }
	j := start(t, o, o5Req(t, "workspace-suspend", 5, 2, ""))
	serial.Store(3)
	stale := o5Req(t, "workspace-cleanup", 6, 2, "terminal") // serial 2: not current
	var errs []string
	for k := 0; k < 3; k++ {
		_, err := o.Do(context.Background(), stale, &Rights{})
		errs = append(errs, fmt.Sprint(err))
		if !errors.Is(err, ErrGrammar) {
			t.Fatalf("stale permit must refuse invalid, got %v", err)
		}
	}
	if j.ctx.Err() != nil {
		t.Fatal("stale permit canceled current job")
	}
	t.Logf("stale-permit terminal Cleanup: results=%v liveJobCanceled=%v", errs, j.ctx.Err() != nil)
}

// A spent-drain Suspend is refused, but its AdmitFrame already canceled the
// running job as a "legal successor".
func TestO5SpentDrainSuspendCancelsBeforeRefusal(t *testing.T) {
	o := testOwner(t, func(ctx context.Context, j *Job) error { <-ctx.Done(); return ctx.Err() })
	j := start(t, o, request("workspace-prepare", 1, 1))
	s := request("workspace-suspend", 2, 2)
	transaction(t, &s)
	s.Workspace.DrainBudgetNanos = "1"
	receivedAt := o.now().Add(-time.Second)
	if err := o.AdmitFrame(s, &Rights{}); err != nil {
		t.Fatal(err)
	}
	awaitResult(t, j.done)
	_, err := o.DoAdmitted(context.Background(), s, &Rights{}, receivedAt)
	snap := observe(t, o, 3, 1)
	if !errors.Is(err, context.DeadlineExceeded) || j.ctx.Err() == nil || snap.Workspace.State != "failed" {
		t.Fatalf("spent drain disposition: %v %+v", err, snap.Workspace)
	}
	t.Logf("spent-drain Suspend: refusal=%v; prepare canceled=%v state=%s", err, j.ctx.Err() != nil, snap.Workspace.State)
}

// ---------- 4. broad concurrent stress ----------

func TestO5OwnerLifecycleStress(t *testing.T) {
	var invalidTotal, regressions int
	for iter := 0; iter < 60; iter++ {
		base := r4FDCount(t)
		var installs, prepares atomic.Int32
		var heldJobs sync.Map
		o := &Owner{CheckPermit: func(Workspace) bool { return true }}
		o.Driver = Driver{
			ValidateInstall: func(*Rights, Phase) error { runtime.Gosched(); return nil },
			Install: func(ctx context.Context, j *Job, r *Rights) (Witness, error) {
				installs.Add(1)
				time.Sleep(time.Duration(rand.Intn(100)) * time.Microsecond)
				if rand.Intn(5) == 0 {
					w := witness()
					w.Session = "partial"
					return w, errors.New("INIT failed")
				}
				return witness(), nil
			},
			Run: lifecycleDriver(func(ctx context.Context, j *Job) error {
				heldJobs.Store(j, true)
				q := j.Request()
				switch q.Operation {
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
				case "workspace-recover":
					f := readyFacts()
					f.Loss = []Loss{{Sequence: "1", AcceptedEntries: "1", AcceptedBytes: "1", Reason: "r"}}
					if err := j.Publish("prepared", f); err != nil {
						return err
					}
					<-ctx.Done()
					return nil
				case "workspace-suspend":
					if rand.Intn(3) == 0 {
						return errors.New("drain failed")
					}
					return j.Publish("cold", Facts{Outcome: Outcome{"durable", "observed", "released", "1"}})
				}
				mode := q.Workspace.Phase.Mode
				p := Phase{ActionID: "2", Mode: mode, Reason: "cleanup", Witness: o5WitnessOf(j)}
				if mode == "terminal" {
					p.ActionID = "3"
				}
				if err := j.OfferRemoval(p); err != nil {
					if errors.Is(err, ErrGrammar) {
						// removal already complete: finish remaining cleanup only
						j.CloseKernel()
						return j.Publish("cleanup-finalized", Facts{})
					}
					return err
				}
				if rand.Intn(4) == 0 {
					return errors.New("cleanup worker failed after offering")
				}
				if err := j.WaitRemoval(ctx, mode); err != nil {
					return err
				}
				j.CloseKernel()
				return j.Publish("cleanup-finalized", Facts{})
			}),
		}
		var admits atomic.Int32
		o.CloseAdmission = func() { admits.Add(1) }
		var wg sync.WaitGroup
		stop := make(chan struct{})
		var invalid atomic.Value
		var strays atomic.Int32
		defer func() {
			if strays.Load() > 0 {
				t.Errorf("ended job mutated owner %d times", strays.Load())
			}
		}()
		var mu sync.Mutex
		finalStates := map[string]string{}
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
		suspend2 := request("workspace-suspend", 2, 2)
		transaction(t, &suspend2)
		recover3 := request("workspace-recover", 3, 3)
		transaction(t, &recover3)
		cleanupV := cleanupRequest(4, "voluntary")
		cleanupT := cleanupRequest(5, "terminal")
		cleanupT2 := cleanupRequest(6, "terminal")
		foreignS := request("workspace-suspend", 7, 7)
		transaction(t, &foreignS)
		foreignS.MountInstanceID = "mnt_0000000000000000000002"
		worker(func(i int) { o.Do(ctx, request("workspace-prepare", 1, 1), &Rights{}) })
		worker(func(i int) { o.Do(ctx, suspend2, &Rights{}) })
		worker(func(i int) { o.Do(ctx, recover3, &Rights{}) })
		worker(func(i int) {
			time.Sleep(time.Duration(rand.Intn(400)) * time.Microsecond)
			o.Do(ctx, cleanupV, &Rights{})
			o.Do(ctx, cleanupT, &Rights{})
			o.Do(ctx, cleanupT2, &Rights{})
		})
		worker(func(i int) { // retired / foreign close frames
			o.AdmitFrame(suspend2, &Rights{})
			o.AdmitFrame(foreignS, &Rights{})
			o.Do(ctx, cleanupV, &Rights{})
			time.Sleep(20 * time.Microsecond)
		})
		worker(func(i int) { o.Do(ctx, installRequest(uint64(200+i%50), 1), r4Pipe()) })
		worker(func(i int) {
			o.mu.Lock()
			v, term, w := status(o.voluntary), status(o.terminal), o.facts.Witness
			var id uint64
			if o.job != nil {
				id, _ = decimal(o.job.start.Workspace.OperationID, true)
			}
			o.mu.Unlock()
			if v.Progress == "offered" {
				o.Do(ctx, r4Unmount(uint64(300+i%50), id, v, w, false), &Rights{})
			}
			if term.Progress == "offered" {
				o.Do(ctx, r4Unmount(uint64(300+i%50), id, term, w, true), &Rights{})
			}
			runtime.Gosched()
		})
		worker(func(i int) { // stray publishes from ended jobs
			heldJobs.Range(func(k, _ any) bool {
				j := k.(*Job)
				o.mu.Lock()
				ended := o.job != j || !j.running
				o.mu.Unlock()
				if ended {
					if j.Publish("pending-suspend", Facts{}) == nil || j.OfferInstall(*phase()) == nil {
						strays.Add(1)
					}
				}
				return true
			})
			time.Sleep(50 * time.Microsecond)
		})
		worker(func(i int) {
			for id := uint64(1); id <= 7; id++ {
				out, err := o.Do(ctx, request("workspace-observe", uint64(100+i%50), id), &Rights{})
				if err != nil {
					continue
				}
				if verr := o5Encodable(out); verr != nil {
					invalid.Store(fmt.Sprintf("op %d: %v state=%q reason=%q", id, verr, out.Workspace.State, out.Workspace.Reason))
				}
				key := strconv.FormatUint(id, 10)
				mu.Lock()
				prev := finalStates[key]
				if (prev == "failed" || prev == "cleanup-finalized") && out.Workspace.State != prev {
					regressions++
					if regressions == 1 {
						t.Errorf("op %d regressed from %s to %s", id, prev, out.Workspace.State)
					}
				}
				finalStates[key] = out.Workspace.State
				mu.Unlock()
			}
		})
		time.Sleep(time.Duration(5+rand.Intn(25)) * time.Millisecond)
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
			invalidTotal++
			if invalidTotal == 1 {
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
	t.Logf("lifecycle stress: invalid-snapshot iterations=%d terminal-state regressions=%d", invalidTotal, regressions)
}

func o5WitnessOf(j *Job) Witness {
	o := j.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.facts.Witness
}
