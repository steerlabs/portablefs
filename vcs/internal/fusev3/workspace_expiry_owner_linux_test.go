//go:build linux

package fusev3

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"golang.org/x/sys/unix"
)

func TestOpusR3GateCloseBeforeFrameDuringPublication(t *testing.T) {
	testWorkspacePermitClose(t, "publication")
}
func TestWorkspaceOwnerCloseAtPermitBoundaries(t *testing.T) {
	for _, boundary := range []string{"proof", "subscribe-entry", "subscribe-install"} {
		t.Run(boundary, func(t *testing.T) { testWorkspacePermitClose(t, boundary) })
	}
}

func TestWorkspaceOwnerRenewalCutoffSurvivesClose(t *testing.T) {
	testWorkspacePermitClose(t, "renewal-cutoff")
}

func testWorkspacePermitClose(t *testing.T, boundary string) {
	for _, independent := range []bool{false, true} {
		t.Run(strconv.FormatBool(independent), func(t *testing.T) {
			f, gate, rpc := coldFixture(t)
			serial := gate.Close(1)
			var hold atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			resume := func() { releaseOnce.Do(func() { close(release) }) }
			pause := func() {
				if hold.CompareAndSwap(true, false) {
					close(entered)
					<-release
				}
			}
			if boundary == "proof" {
				f.mount.workspaceLifecycle.beforeRecoveryProof = pause
			}
			f.mount.subscription.config.beforeRecoveryProof = func(install bool) {
				if boundary == "subscribe-entry" && !install || (boundary == "subscribe-install" || boundary == "renewal-cutoff") && install {
					pause()
				}
			}
			f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
				if boundary == "publication" && o.Prepared && hold.CompareAndSwap(true, false) {
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
						if renewer := f.mount.workspaceLifecycle.renewer; renewer != nil {
							r := renewer.Readiness()
							facts.Readiness.Standalone = false
							facts.Readiness.Renewal = mountcontrol.Renewal{State: r.State, InstalledSequence: strconv.FormatUint(r.InstalledSequence, 10)}
							facts.AuthorizationDeadlineUnixNanos = strconv.FormatInt(r.AuthorizationDeadline.UnixNano(), 10)
						}
					}
					if err := j.Publish(state, facts); err != nil {
						o.Result = authorityrpc.LifecycleCompletion(ctx, err)
					}
				}
				t.Logf("driver %s generation %d result=%v err=%v cold=%v ready=%v", q.Operation, generation, o.Result.Disposition, o.Result.Err, o.ColdComplete, o.Prepared)
				results <- o
				return o.Result
			}
			defer func() { resume(); owner.Close() }()
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
			var renewalBoundary func()
			if boundary == "renewal-cutoff" {
				renewalBoundary = startWorkspaceCutoffRenewer(t, f.mount, rpc, independent)
			}
			hold.Store(true)
			q = req("workspace-recover", requestID+1, 2, serial, transaction(2, true))
			do(q, &mountcontrol.Rights{})
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("recovery boundary not reached")
			}
			if renewalBoundary != nil {
				// Subscribe owns its response but has not performed the final
				// permit validation. Renewal reaches its own disposition first.
				renewalBoundary()
			}
			// Production order: the supervisor closes the gate, then frames the
			// newer Suspend. The running job may observe the closed gate first.
			newerSerial := gate.Close(3)
			if independent && boundary != "publication" && boundary != "renewal-cutoff" {
				f.mount.workspaceLifecycle.evidence.Store(&workspaceEvidence{failure: syscall.ENOSPC})
			}
			resume()
			o := await()
			t.Logf("job observed gate Close before the frame: result=%v err=%v", o.Result.Disposition, o.Result.Err)
			newer := req("workspace-suspend", requestID+1, 3, newerSerial, transaction(3, false))
			if err := owner.AdmitFrame(newer, &mountcontrol.Rights{}); err != nil {
				t.Fatal(err)
			}
			observe(q, "failed")
			want := authorityrpc.LifecycleOvertaken
			if independent {
				want = authorityrpc.LifecycleFailed
			}
			if o.Result.Disposition != want || o.Prepared {
				t.Error("a pure newer Close observed through the gate became", o.Result)
			}
			if !independent && (o.Result.PermitLoss == nil || *o.Result.PermitLoss != (authorityrpc.LifecyclePermitLoss{Generation: 2, Serial: serial, Successor: newerSerial})) {
				t.Error("pure Close lost the exact job attribution", o.Result)
			}
			if boundary == "renewal-cutoff" && independent && !errors.Is(o.Result.Err, context.DeadlineExceeded) {
				t.Error("completion lost the terminal renewal cutoff", o.Result)
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
				t.Logf("newer Suspend frontend result: cold=%v result=%v", o.ColdComplete, o.Result.Disposition)
				recover := req("workspace-recover", requestID+1, 3, newerSerial, transaction(3, true))
				var rerr error
				waitUntil(t, time.Second, "recover start", func() bool {
					_, rerr = owner.Do(t.Context(), recover, &mountcontrol.Rights{})
					return !errors.Is(rerr, mountcontrol.ErrOccupied)
				})
				if rerr != nil {
					t.Fatal("Recover after a pure Close refused:", rerr)
				}
				o = await()
				if !o.Prepared {
					t.Fatal("overtaking stranded owner", o.Result)
				}
				observe(recover, "prepared")
			}
		})
	}
}

type workspaceRenewalSourceFunc func(context.Context, string, uint64) (controlplane.MountAuthorization, error)

func (f workspaceRenewalSourceFunc) Refresh(ctx context.Context, session string, sequence uint64) (controlplane.MountAuthorization, error) {
	return f(ctx, session, sequence)
}

// The real renewal owner installs a grant, then fails a Manager refresh just
// before its serving cutoff. Only the renewal clock advances; the lifecycle
// job and its permit remain live until the test explicitly closes the gate.
func startWorkspaceCutoffRenewer(t *testing.T, m *Mount, rpc *coldTestRPC, cutoff bool) func() {
	t.Helper()
	start := time.Now().Truncate(time.Second)
	rpc.deadline = start.Add(2 * time.Minute)
	var now atomic.Int64
	now.Store(start.UnixNano())
	installed, refreshing, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var runErr error
	renewer := &mountenrollment.Renewer{
		Managed: true,
		Now:     func() time.Time { return time.Unix(0, now.Load()) },
		CheckPermit: func(p mountenrollment.Permit) bool {
			_, err := m.workspace.Recovery(p.Generation, p.GateSerial)
			return err == nil
		},
		Observe: func(e mountenrollment.RenewalEvent) {
			if e.Kind == mountenrollment.RenewalSucceeded && e.Status.Sequence == 1 {
				close(installed)
			}
		},
	}
	refreshes := 0
	renewer.Source = workspaceRenewalSourceFunc(func(ctx context.Context, session string, sequence uint64) (controlplane.MountAuthorization, error) {
		if sequence == 2 {
			refreshes++
			if refreshes == 1 {
				close(refreshing)
				if cutoff {
					return controlplane.MountAuthorization{}, context.DeadlineExceeded
				}
				<-ctx.Done()
				return controlplane.MountAuthorization{}, ctx.Err()
			}
		}
		return controlplane.MountAuthorization{SessionID: session, Sequence: sequence, Capability: "grant", ExpiresUnix: rpc.deadline.Unix()}, nil
	})
	if err := renewer.Park(t.Context()); err != nil {
		t.Fatal(err)
	}
	m.workspaceLifecycle.standalone, m.workspaceLifecycle.renewer = false, renewer
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		defer close(done)
		runErr = renewer.Run(ctx, base64.RawURLEncoding.EncodeToString(m.rpc.SessionID()), rpc.deadline, func(context.Context, string, uint64, []byte) (time.Time, error) {
			return rpc.deadline, nil
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("renewal owner did not stop")
		}
	})
	return func() {
		t.Helper()
		select {
		case <-installed:
		case <-time.After(5 * time.Second):
			t.Fatal("renewal did not install the serving grant")
		}
		// A two-minute window has a twelve-second safety margin. A failed
		// refresh's 500 ms retry is outside that cutoff and becomes terminal.
		now.Store(rpc.deadline.Add(-12*time.Second - 250*time.Millisecond).UnixNano())
		renewer.RefreshNow()
		select {
		case <-refreshing:
		case <-time.After(5 * time.Second):
			t.Fatal("renewal did not reach the Manager refresh")
		}
		if cutoff {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("renewal did not latch its independent cutoff")
			}
			if ctx.Err() != nil || !errors.Is(runErr, context.DeadlineExceeded) || renewer.Failure() == nil {
				t.Fatal("renewal cutoff was not independent", runErr, renewer.Failure(), ctx.Err())
			}
		}
	}
}

func TestWorkspaceManagedResumePermitLoss(t *testing.T) {
	f, gate, _ := coldFixture(t)
	serial := gate.Close(1)
	if o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second)); err != nil || !o.ColdComplete {
		t.Fatal(o, err)
	}
	w := f.mount.workspaceLifecycle
	w.standalone = false
	w.renewer = &mountenrollment.Renewer{Managed: true, CheckPermit: func(mountenrollment.Permit) bool { gate.Close(2); return false }}
	o, err := f.mount.RecoverWorkspace(t.Context(), 1, serial)
	if err == nil || o.Prepared || o.Result.Disposition != authorityrpc.LifecycleOvertaken || o.Result.PermitLoss == nil || o.Result.PermitLoss.Serial != serial {
		t.Fatal("managed Resume permit loss became a failure", o.Result, err)
	}
}

func TestWorkspacePersistenceFailureSurvivesPermitLoss(t *testing.T) {
	for _, diagnostic := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(diagnostic.Error(), func(t *testing.T) {
			f, gate, _ := coldFixture(t)
			serial := gate.Close(1)
			closed := false
			f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
				if o.Prepared && !closed {
					closed = true
					gate.Close(2)
					return nil
				}
				if closed {
					return diagnostic
				}
				return nil
			}
			o, err := f.mount.PrepareWorkspace(t.Context(), 1, serial)
			if !closed || o.Prepared || o.Result.Disposition != authorityrpc.LifecycleFailed || !errors.Is(err, diagnostic) {
				t.Fatal("persistence diagnostic erased an independent failure", o.Result, err)
			}
		})
	}
}

func TestWorkspaceZeroEntryLossTicketRecorded(t *testing.T) {
	f, gate, _ := coldFixture(t)
	manager := f.mount.delegations
	report := manager.buf.Drop(writeback.Identity{99}, "uncertain clean grant")
	evidence := f.mount.workspaceLifecycle.evidence.Load()
	if report.LossSequence != 1 || report.Entries != 0 || report.Bytes != 0 || evidence == nil || len(evidence.loss) != 1 || evidence.loss[0].Sequence != report.LossSequence {
		t.Fatal("buffer advanced a zero-entry ticket without its authoritative record", report, evidence)
	}
	// Buffer ownership records the ticket before the outside-lock diagnostic;
	// repeated delivery must retain one cumulative record through publication.
	f.mount.workspaceLifecycle.recordDrop(report)
	serial := gate.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
	check := func(o WorkspaceObservation, err error) {
		t.Helper()
		if err != nil || len(o.Loss) != 1 || o.Loss[0].Sequence != report.LossSequence || o.Loss[0].AcceptedEntries != 0 || o.Loss[0].AcceptedBytes != 0 || o.Loss[0].Reason != report.Reason {
			t.Fatal("publication lost or invented zero-entry ticket evidence", o, err)
		}
	}
	check(o, err)
	if !o.ColdComplete {
		t.Fatal("zero-entry loss prevented a complete cold cut", o)
	}
	o, err = f.mount.RecoverWorkspace(t.Context(), 1, serial)
	check(o, err)
	if !o.Prepared {
		t.Fatal("accounted zero-entry loss prevented authorized recovery", o)
	}
}
