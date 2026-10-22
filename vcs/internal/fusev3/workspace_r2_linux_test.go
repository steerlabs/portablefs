//go:build linux

package fusev3

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"golang.org/x/sys/unix"
)

func TestWorkspaceOwnerCloseDuringPublication(t *testing.T) {
	for _, independent := range []bool{false, true} {
		t.Run(strconv.FormatBool(independent), func(t *testing.T) {
			f, gate, _ := coldFixture(t)
			serial := gate.Close(1)
			var hold atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
				if o.Prepared && hold.CompareAndSwap(true, false) {
					close(entered)
					<-release
					if independent {
						return syscall.ENOSPC
					}
				}
				return nil
			}
			results := make(chan WorkspaceObservation, 8)
			witness := mountcontrol.Witness{Process: "process", Source: "source", Target: "/mount", Kernel: "kernel", Session: "session"}
			owner := &mountcontrol.Owner{CheckPermit: func(w mountcontrol.Workspace) bool {
				g, _ := strconv.ParseUint(w.Generation, 10, 64)
				s, _ := strconv.ParseUint(w.GateSerial, 10, 64)
				_, err := f.mount.workspace.Recovery(g, s)
				return err == nil
			}}
			owner.Driver.ValidateInstall = func(*mountcontrol.Rights, mountcontrol.Phase) error { return nil }
			owner.Driver.Install = func(context.Context, *mountcontrol.Job, *mountcontrol.Rights) (mountcontrol.Witness, error) {
				return witness, nil
			}
			owner.Driver.Run = func(ctx context.Context, j *mountcontrol.Job) mountcontrol.LifecycleResult {
				q := j.Request()
				generation, _ := strconv.ParseUint(q.Workspace.Generation, 10, 64)
				s, _ := strconv.ParseUint(q.Workspace.GateSerial, 10, 64)
				var o WorkspaceObservation
				switch q.Operation {
				case "workspace-prepare":
					if err := j.OfferInstall(mountcontrol.Phase{ActionID: "1", Options: []string{"rw"}, Witness: witness}); err != nil {
						return authorityrpc.LifecycleCompletion(ctx, err)
					}
					if err := j.WaitInstall(ctx); err != nil {
						return authorityrpc.LifecycleCompletion(ctx, err)
					}
					o, _ = f.mount.PrepareWorkspace(ctx, generation, s)
				case "workspace-recover":
					o, _ = f.mount.RecoverWorkspace(ctx, generation, s)
				case "workspace-suspend":
					o, _ = f.mount.SuspendWorkspace(ctx, generation, s, continuous.Time().Add(5*time.Second))
				}
				if o.Result.Disposition == authorityrpc.LifecycleCompleted {
					facts := mountcontrol.Facts{Witness: witness, Outcome: mountcontrol.Outcome{Durability: o.Outcome.Durability, Observation: o.Outcome.Observation, Release: o.Outcome.Release, CleanupDebt: strconv.FormatUint(o.Outcome.CleanupDebt, 10)}}
					state := "cold"
					if o.Prepared {
						state = "prepared"
						facts.AuthorizationDeadlineUnixNanos = "2000000000000000000"
						facts.Readiness = &mountcontrol.Prepared{SessionValidated: true, AuthorizationValidated: true, Standalone: true, Renewal: mountcontrol.Renewal{State: "not-required", InstalledSequence: "0"}, SubscriptionIncarnation: strconv.FormatUint(o.SubscriptionIncarnation, 10)}
					}
					if err := j.Publish(state, facts); err != nil {
						o.Result = authorityrpc.LifecycleCompletion(ctx, err)
					}
				}
				t.Logf("driver %s generation %d result=%v err=%v cold=%v ready=%v", q.Operation, generation, o.Result.Disposition, o.Result.Err, o.ColdComplete, o.Prepared)
				results <- o
				return o.Result
			}
			defer owner.Close()
			var requestID uint64
			req := func(op string, id, g, s uint64, transaction string) mountcontrol.Request {
				requestID++
				w := &mountcontrol.Workspace{Version: 8, RequestID: strconv.FormatUint(requestID, 10), OperationID: strconv.FormatUint(id, 10), BootID: strings.Repeat("01", 16), HostServiceID: strings.Repeat("02", 16), GuestServiceID: strings.Repeat("03", 16), Generation: strconv.FormatUint(g, 10), GateSerial: strconv.FormatUint(s, 10), BudgetNanos: "45000000000", Transaction: transaction}
				if op == "workspace-suspend" || op == "workspace-recover" {
					w.HostRequestID = "1"
				}
				if op == "workspace-suspend" {
					w.DrainBudgetNanos = "5000000000"
				}
				return mountcontrol.Request{Operation: op, MountInstanceID: "mnt_0000000000000000000001", Workspace: w}
			}
			do := func(q mountcontrol.Request, rights *mountcontrol.Rights) {
				t.Helper()
				if len(rights.FDs) != 0 {
					if _, err := owner.Do(t.Context(), q, rights); err != nil {
						t.Fatal(q.Operation, err)
					}
					return
				}
				// Publish precedes the driver's final return and owner join. Retry
				// the same framed start until that finite lane owner settles.
				waitUntil(t, time.Second, "owner accepts "+q.Operation, func() bool {
					_, err := owner.Do(t.Context(), q, &mountcontrol.Rights{})
					if err != nil && !errors.Is(err, mountcontrol.ErrOccupied) {
						t.Fatal(q.Operation, err)
					}
					return err == nil
				})
			}
			await := func() WorkspaceObservation {
				t.Helper()
				select {
				case o := <-results:
					return o
				case <-time.After(5 * time.Second):
					t.Fatal("owner did not complete")
					return WorkspaceObservation{}
				}
			}
			observe := func(q mountcontrol.Request, want string) {
				t.Helper()
				waitUntil(t, time.Second, "owner "+want, func() bool {
					q.Operation = "workspace-observe"
					requestID++
					binding := q.Workspace.ResponseBinding()
					q.Workspace = &binding
					q.Workspace.RequestID = strconv.FormatUint(requestID, 10)
					out, err := owner.Do(t.Context(), q, &mountcontrol.Rights{})
					if err != nil {
						t.Logf("observe err %v", err)
					} else if out.Workspace.State == "failed" {
						t.Logf("observe failed %s", out.Workspace.Reason)
					}
					return err == nil && out.Workspace.State == want
				})
			}
			q := req("workspace-prepare", 1, 1, serial, "")
			do(q, &mountcontrol.Rights{})
			waitUntil(t, time.Second, "kernel offer", func() bool {
				obs := q
				obs.Operation = "workspace-observe"
				requestID++
				binding := q.Workspace.ResponseBinding()
				obs.Workspace = &binding
				obs.Workspace.RequestID = strconv.FormatUint(requestID, 10)
				r, err := owner.Do(t.Context(), obs, &mountcontrol.Rights{})
				return err == nil && r.Workspace.State == "kernel-required"
			})
			install := req("workspace-install-kernel", 1, 1, serial, "")
			install.Workspace.Phase = &mountcontrol.Phase{ActionID: "1", Options: []string{"rw"}, Witness: witness}
			fds := make([]int, 2)
			if err := unix.Pipe(fds); err != nil {
				t.Fatal(err)
			}
			do(install, &mountcontrol.Rights{FDs: fds})
			if o := await(); !o.Prepared {
				t.Fatal(o)
			}
			observe(q, "prepared")
			suspension := func(g uint64) *pb.Suspension {
				boot, _ := hex.DecodeString(strings.Repeat("01", 16))
				host, _ := hex.DecodeString(strings.Repeat("02", 16))
				guest, _ := hex.DecodeString(strings.Repeat("03", 16))
				return &pb.Suspension{BootId: boot, HostServiceId: host, GuestServiceId: guest, Generation: g, Nonce: []byte(strings.Repeat("n", 16))}
			}
			transaction := func(g uint64, resume bool) string {
				t.Helper()
				s := suspension(g)
				var tx string
				var err error
				if resume {
					tx, err = mountcontrol.EncodeTransaction(&pb.ResumeToken{Suspension: s, WakeNonce: []byte(strings.Repeat("w", 16))})
				} else {
					tx, err = mountcontrol.EncodeTransaction(s)
				}
				if err != nil {
					t.Fatal(err)
				}
				return tx
			}
			serial = gate.Close(2)
			q = req("workspace-suspend", requestID+1, 2, serial, transaction(2, false))
			do(q, &mountcontrol.Rights{})
			if o := await(); !o.ColdComplete {
				t.Fatal(o)
			}
			observe(q, "cold")
			hold.Store(true)
			q = req("workspace-recover", requestID+1, 2, serial, transaction(2, true))
			do(q, &mountcontrol.Rights{})
			<-entered
			newerSerial := gate.Close(3)
			newer := req("workspace-suspend", requestID+1, 3, newerSerial, transaction(3, false))
			if err := owner.AdmitFrame(newer, &mountcontrol.Rights{}); err != nil {
				t.Fatal(err)
			}
			close(release)
			o := await()
			observe(q, "failed")
			want := authorityrpc.LifecycleOvertaken
			if independent {
				want = authorityrpc.LifecycleFailed
			}
			if o.Result.Disposition != want || o.Prepared {
				t.Fatal("owner Close changed disposition", o.Result)
			}
			// Do starts the exact previously framed successor once the old job joins.
			do(newer, &mountcontrol.Rights{})
			o = await()
			if independent {
				observe(newer, "failed")
				recover := req("workspace-recover", requestID+1, 3, newerSerial, transaction(3, true))
				waitUntil(t, time.Second, "terminal result after owner join", func() bool {
					_, err := owner.Do(t.Context(), recover, &mountcontrol.Rights{})
					if errors.Is(err, mountcontrol.ErrOccupied) {
						return false
					}
					if !errors.Is(err, mountcontrol.ErrIncarnationTerminal) {
						t.Fatal("independent failure did not latch terminal", err)
					}
					return true
				})
			} else {
				if !o.ColdComplete {
					t.Fatal(o)
				}
				observe(newer, "cold")
				recover := req("workspace-recover", requestID+1, 3, newerSerial, transaction(3, true))
				do(recover, &mountcontrol.Rights{})
				o = await()
				if !o.Prepared {
					t.Fatal("overtaking stranded owner", o.Result)
				}
				observe(recover, "prepared")
			}
		})
	}
}

func TestWorkspaceOvertakenBeforeInitialCut(t *testing.T) {
	f, gate, _ := coldFixture(t)
	serial := gate.Close(1)
	ctx, owner := authorityrpc.WithLifecycleOwner(t.Context())
	gate.Close(2)
	// The owner records overtaking before cancellation delivery reaches the
	// running call. Permit loss already has an explicit disposition.
	owner.Overtake()
	o, err := f.mount.PrepareWorkspace(ctx, 1, serial)
	if o.Result.Disposition != authorityrpc.LifecycleOvertaken || err == nil || o.Prepared {
		t.Fatal("initial cut reclassified known overtaking", o.Result, err)
	}
}

type r2RetirementContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *r2RetirementContext) Err() error {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Err()
}

func TestWorkspaceRetirementFenceIsUnsubmitted(t *testing.T) {
	for _, drain := range []bool{false, true} {
		t.Run(strconv.FormatBool(drain), func(t *testing.T) {
			f, gate, _ := coldFixture(t)
			m := f.mount.delegations
			state := m.retainState(writeback.Identity{1}, true)
			defer m.releaseState(state)
			prior, err := m.buf.BeginRetire(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer prior.Cancel()
			ctx := &r2RetirementContext{Context: t.Context(), entered: make(chan struct{})}
			done := make(chan error, 1)
			go func() { _, err := m.beginRetireBuffer(ctx, m.buf, state); done <- err }()
			<-ctx.entered // The capability sample preceded BeginRetire's wait.
			if drain {
				gate.Close(1)
				f.mount.workspaceFS().captureWorkspaceDrain(m.subscription.config.clock.Now().Add(time.Second))
			}
			m.buf.FenceAdmissions()
			select {
			case err := <-done:
				if drain {
					var classified cleanupClassified
					if !errors.As(err, &classified) || classified.cleanupFailureClass() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || !errors.Is(err, authorityrpc.ErrSubscriptionReset) {
						t.Fatal("local drain refusal became unknown CLOSE", err)
					}
				} else if !errors.Is(err, writeback.ErrClosed) {
					t.Fatal("unexpected closure lost its independent error", err)
				}
			case <-time.After(time.Second):
				t.Fatal("retirement did not observe admission fencing")
			}
		})
	}
}

// A held post-validation poll result models the scheduling edge before the
// CONTROL owner records completion. Cancellation is causally observed first.
type r2HeldPoll struct {
	poll func(context.Context, uint64, uint64, uint64) (*authoritypb.ControlEvent, error)
	*subscriptionTestRPC
	cause                      error
	entered, canceled, release chan struct{}
	once                       sync.Once
}

func (r *r2HeldPoll) NextControlEvent(ctx context.Context, inc, after, completed uint64) (*authoritypb.ControlEvent, error) {
	if r.poll != nil {
		_, r.cause = r.poll(ctx, inc, after, completed)
	}
	r.once.Do(func() { close(r.entered) })
	<-ctx.Done()
	close(r.canceled)
	<-r.release
	if r.cause != nil {
		return nil, r.cause
	}
	return nil, ctx.Err()
}
func TestWorkspacePollFailureSurvivesPark(t *testing.T) {
	for _, cause := range []error{nil, errors.New("authorityrpc: control poll returned a non-successor event"), errors.Join(context.Canceled, errors.New("independent local change failure")), authorityrpc.ErrSessionEnded} {
		name := "cancellation"
		if cause != nil {
			name = cause.Error()
		}
		t.Run(name, func(t *testing.T) {
			f, g, _ := coldFixture(t)
			s := f.mount.subscription
			r := &r2HeldPoll{subscriptionTestRPC: &subscriptionTestRPC{}, cause: cause, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
			s.rpc = r
			serving := make(chan error, 1)
			go func() { serving <- s.serveIncarnation(t.Context()) }()
			<-r.entered
			serial := g.Close(1)
			done := make(chan WorkspaceObservation, 1)
			go func() {
				o, _ := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
				done <- o
			}()
			<-r.canceled
			select {
			case o := <-done:
				t.Fatal("cold preceded poll disposition", o)
			default:
			}
			close(r.release)
			o := <-done
			<-serving
			s.mu.RLock()
			failure := s.workspaceFailure
			s.mu.RUnlock()
			if cause == nil {
				if !o.ColdComplete || failure != nil {
					t.Fatal(o, failure)
				}
			} else if o.ColdComplete || !errors.Is(failure, cause) || o.Result.Disposition != authorityrpc.LifecycleFailed {
				t.Fatal("poll failure erased", o.Result, failure)
			}
		})
	}
}

func TestWorkspacePublicationRenewsAgedProofInOriginalJob(t *testing.T) {
	for _, recover := range []bool{false, true} {
		t.Run(strconv.FormatBool(recover), func(t *testing.T) {
			f, g, rpc := coldFixture(t)
			serial := g.Close(1)
			if recover {
				if o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second)); err != nil || !o.ColdComplete {
					t.Fatal(o, err)
				}
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once atomic.Bool
			var records []WorkspaceObservation
			f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
				records = append(records, o)
				if o.Prepared && once.CompareAndSwap(false, true) {
					close(entered)
					<-release
				}
				return nil
			}
			done := make(chan WorkspaceObservation, 1)
			go func() {
				var o WorkspaceObservation
				if recover {
					o, _ = f.mount.RecoverWorkspace(t.Context(), 1, serial)
				} else {
					o, _ = f.mount.PrepareWorkspace(t.Context(), 1, serial)
				}
				done <- o
			}()
			<-entered
			f.mount.subscription.mu.Lock()
			f.mount.subscription.cacheUntil = continuous.Time().Add(-time.Second)
			f.mount.subscription.mu.Unlock()
			close(release)
			o := <-done
			if !o.Prepared || o.Result.Disposition != authorityrpc.LifecycleCompleted || rpc.subscriptions.Load() != 2 || rpc.validations.Load() != 1 {
				t.Fatal("publication ended original job", o.Result, rpc.subscriptions.Load())
			}
			if len(records) < 3 || !records[0].Prepared || records[1].Prepared || records[1].Outcome.Observation != "unobserved" || records[1].Outcome.Durability != "unresolved" {
				t.Fatal("unusable publication interval missing", records)
			}
			if f.mount.workspaceServing() {
				t.Fatal("job opened supervisor admission")
			}
		})
	}
}

type r2MalformedPollHandler struct{ authorityrpc.Handler }

func (h *r2MalformedPollHandler) Handle(ctx context.Context, q *authoritypb.Request) *authoritypb.Response {
	if poll := q.GetNextControlEvent(); poll != nil {
		return &authoritypb.Response{RequestId: q.GetRequestId(), Epoch: h.Epoch(), Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{Incarnation: poll.Incarnation, Sequence: poll.AfterSequence + 2, Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{Incarnation: poll.Incarnation, Entries: []*authoritypb.ChangeEntry{{Position: 1, VolumeVersion: 1, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: []byte(strings.Repeat("i", 16))}}}}}}}
	}
	return h.Handler.Handle(ctx, q)
}
func TestWorkspaceRealSemanticPollFailureSurvivesPark(t *testing.T) {
	real := newIntegrationFixture(t, integrationConfig{skipMounts: true, beforeServe: func(f *integrationFixture) { f.server.Handler = &r2MalformedPollHandler{f.server.Handler} }})
	client, _ := real.dialClient()
	defer client.Close()
	f, g, _ := coldFixture(t)
	s := f.mount.subscription
	r := &r2HeldPoll{poll: client.NextControlEvent, subscriptionTestRPC: &subscriptionTestRPC{}, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	s.rpc = r
	serving := make(chan error, 1)
	go func() { serving <- s.serveIncarnation(t.Context()) }()
	<-r.entered
	if r.cause == nil || !strings.Contains(r.cause.Error(), "non-successor") || client.SessionEndCause() != nil {
		t.Fatal("expected independent semantic validation failure", r.cause, client.SessionEndCause())
	}
	serial := g.Close(1)
	done := make(chan WorkspaceObservation, 1)
	go func() {
		o, _ := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
		done <- o
	}()
	<-r.canceled
	close(r.release)
	o := <-done
	<-serving
	s.mu.RLock()
	failure := s.workspaceFailure
	s.mu.RUnlock()
	if o.ColdComplete || o.Result.Disposition != authorityrpc.LifecycleFailed || !errors.Is(failure, r.cause) {
		t.Fatal("real semantic poll failure erased", o.Result, failure)
	}
}
