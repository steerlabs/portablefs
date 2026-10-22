//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
)

func TestBootstrapSettlesCanceledAndPartialAcquisitions(t *testing.T) {
	for _, mode := range []string{"canceled-before-syscall", "partial-conflicting-witness"} {
		t.Run(mode, func(t *testing.T) {
			var b Bootstrap
			p := *phase()
			p.Witness.Kernel = ""
			if err := b.Begin(p); err != nil {
				t.Fatal(err)
			}
			b.OwnerLost()
			if err := b.Finalize(absentBootstrap(&b)); !errors.Is(err, ErrOccupied) {
				t.Fatal(err)
			}
			r := &Rights{}
			w := Witness{}
			var fds []int
			if mode == "partial-conflicting-witness" {
				r, fds = descriptors(t)
				unix.Close(r.FDs[1])
				r.FDs = r.FDs[:1]
				w = witness()
				w.Source = "foreign"
				w.Session = "new-session"
			}
			if err := b.Finish(r, w); !errors.Is(err, ErrGrammar) {
				t.Fatal(err)
			}
			if mode == "partial-conflicting-witness" && (b.action.Witness.Kernel != w.Kernel || b.action.Witness.Session != w.Session || b.action.Witness.Source != p.Witness.Source) {
				t.Fatal("partial acquisition erased", b.action.Witness)
			}
			if err := b.Finalize(Absence{ProcessExited: true}); !errors.Is(err, ErrGrammar) {
				t.Fatal("stale absence replaced observation", err)
			}
			if err := b.Finalize(absentBootstrap(&b)); err != nil {
				t.Fatal(err)
			}
			if len(fds) > 0 {
				assertClosed(t, fds[:1])
			}
		})
	}
}

func TestLossMergesIndependentlyOfConflictingPublication(t *testing.T) {
	for _, invalid := range []string{"disposition", "witness", "deadline", "outcome"} {
		t.Run(invalid, func(t *testing.T) {
			entered, release := make(chan *Job, 1), make(chan struct{})
			o := testOwner(t, func(ctx context.Context, j *Job) error {
				entered <- j
				defer close(release)
				<-ctx.Done()
				return ctx.Err()
			})
			j := start(t, o, request("workspace-prepare", 1, 1))
			<-entered
			if err := j.Publish("preparing", Facts{Witness: witness(), Outcome: Outcome{"durable", "observed", "released", "1"}}); err != nil {
				t.Fatal(err)
			}
			f := Facts{Loss: []Loss{{Sequence: "1", AcceptedEntries: "1", AcceptedBytes: "4", Reason: "new cumulative loss"}}, Outcome: Outcome{"unresolved", "unobserved", "unresolved", "2"}}
			switch invalid {
			case "disposition":
				f.Outcome = Outcome{"lost", "observed", "abandoned", "2"}
			case "witness":
				f.Witness.Source = "foreign"
				f.Witness.Session = "acquired"
			case "deadline":
				f.AuthorizationDeadlineUnixNanos = "bad"
			case "outcome":
				f.Outcome.Release = "bad"
			}
			if err := j.Publish("preparing", f); !errors.Is(err, ErrGrammar) {
				t.Fatal(err)
			}
			snap := observe(t, o, 2, 1)
			if len(snap.Workspace.Loss) != 1 || snap.Workspace.Outcome.Durability != "durable" {
				t.Fatal("publication lost cumulative evidence", snap)
			}
			if invalid == "witness" && snap.Workspace.Witness.Session != "acquired" {
				t.Fatal("nonconflicting witness lost", snap)
			}
			if invalid != "outcome" && snap.Workspace.Outcome.CleanupDebt != "2" {
				t.Fatal("debt lost", snap)
			}
			o.Close()
			<-release
		})
	}
}

func TestRemainingCleanupAfterLateSuccessfulRemoval(t *testing.T) {
	offered, fail := make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.Request().Workspace.OperationID == "1" {
			if err := j.OfferRemoval(Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup", Witness: witness()}); err != nil {
				return err
			}
			close(offered)
			<-fail
			return errors.New("session cleanup failed")
		}
		// The irreversible root action already succeeded. Only final cleanup remains.
		if err := j.WaitRemoval(ctx, "voluntary"); err != nil {
			return err
		}
		j.CloseKernel()
		return j.Publish("cleanup-finalized", Facts{})
	})
	j := start(t, o, cleanupRequest(1, "voluntary"))
	<-offered
	action := observe(t, o, 2, 1).Workspace.Phases.VoluntaryRemoval
	close(fail)
	<-j.done
	q := r4Unmount(3, 1, action, witness(), false)
	do(t, o, q, &Rights{})
	before := observe(t, o, 4, 1)
	if before.Workspace.State != "failed" || before.Workspace.Phases.VoluntaryRemoval.Progress != "complete" {
		t.Fatal(before)
	}
	j = start(t, o, cleanupRequest(5, "terminal"))
	<-j.done
	after := observe(t, o, 6, 5)
	if after.Workspace.State != "cleanup-finalized" || after.Workspace.Phases.VoluntaryRemoval.Progress != "complete" || after.Workspace.Phases.TerminalRemoval.Progress != "absent" {
		t.Fatal(after)
	}
	q.Workspace.OperationID = "5"
	if _, err := o.Do(context.Background(), q, &Rights{}); !errors.Is(err, ErrActionConsumed) {
		t.Fatal("removal executed twice", err)
	}
}

func TestRecoverExactSuspensionRefusalDoesNotConsumeToken(t *testing.T) {
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if j.Request().Operation == "workspace-suspend" {
			return j.Publish("cold", Facts{})
		}
		return errors.New("recovery ends this fixture")
	})
	s := request("workspace-suspend", 1, 1)
	transaction(t, &s)
	j := start(t, o, s)
	<-j.done
	for _, field := range []string{"nonce", "roster"} {
		r := request("workspace-recover", 2, 2)
		transaction(t, &r)
		cold := suspension(t)
		if field == "nonce" {
			cold.Nonce[0] ^= 0xff
		} else {
			cold.Roster[0].Incarnation[0] ^= 0xff
		}
		// The token remains canonical while naming a different cold transaction.
		token := &pb.ResumeToken{Suspension: cold, WakeNonce: make([]byte, 16)}
		token.WakeNonce[0] = 1
		var err error
		r.Workspace.Transaction, err = EncodeTransaction(token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = o.Do(context.Background(), r, &Rights{}); !errors.Is(err, ErrGrammar) {
			t.Fatal("foreign token accepted", err)
		}
		if o.job != j || o.recoveredGeneration != 0 {
			t.Fatal("refusal consumed authorization")
		}
	}
	r := request("workspace-recover", 2, 2)
	transaction(t, &r)
	j = start(t, o, r)
	<-j.done
	if o.recoveredGeneration != 1 {
		t.Fatal("exact token did not consume generation")
	}
}

func TestCloseCancellationRequiresLegalSuccessor(t *testing.T) {
	for _, field := range []string{"retired", "equal-changed", "mount", "boot", "host-service", "guest-service", "generation", "serial", "suspend", "voluntary", "legal"} {
		t.Run(field, func(t *testing.T) {
			entered := make(chan struct{})
			o := testOwner(t, func(ctx context.Context, j *Job) error { close(entered); <-ctx.Done(); return ctx.Err() })
			q := cleanupRequest(5, "terminal")
			q.Workspace.Generation = "2"
			q.Workspace.GateSerial = "2"
			if field == "legal" {
				q.Workspace.Phase.Mode = "voluntary"
			}
			j := start(t, o, q)
			<-entered
			next := cloneRequest(q)
			next.Workspace.RequestID = "6"
			next.Workspace.OperationID = "6"
			switch field {
			case "retired":
				next.Workspace.RequestID = "4"
				next.Workspace.OperationID = "4"
			case "equal-changed":
				next.Workspace.RequestID = "5"
				next.Workspace.OperationID = "5"
				next.Workspace.Phase.Reason = "changed"
			case "mount":
				next.MountInstanceID = "mnt_0000000000000000000002"
			case "boot":
				next.Workspace.BootID = "04040404040404040404040404040404"
			case "host-service":
				next.Workspace.HostServiceID = "04040404040404040404040404040404"
			case "guest-service":
				next.Workspace.GuestServiceID = "04040404040404040404040404040404"
			case "generation":
				next.Workspace.Generation = "1"
			case "serial":
				next.Workspace.GateSerial = "1"
			case "suspend":
				next = request("workspace-suspend", 6, 6)
				transaction(t, &next)
			case "voluntary":
				next.Workspace.Phase.Mode = "voluntary"
			case "legal":
				next.Workspace.Phase.Mode = "terminal"
			}
			if err := o.AdmitFrame(next, &Rights{}); err != nil {
				t.Fatal(err)
			}
			if (j.ctx.Err() != nil) != (field == "legal") {
				t.Fatalf("illegal cancellation for %s: %v", field, j.ctx.Err())
			}
			if o.job != j {
				t.Fatal("admission erased current job")
			}
		})
	}
}

func TestStoppedInstallOfferRetainsRootOwnershipAndEndsHandoff(t *testing.T) {
	var b Bootstrap
	if err := b.Begin(*phase()); err != nil {
		t.Fatal(err)
	}
	rights, fds := descriptors(t)
	if err := b.Finish(rights, witness()); err != nil {
		t.Fatal(err)
	}
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferInstall(*phase()); err != nil {
			return err
		}
		return errors.New("prepare ended before handoff")
	})
	j := start(t, o, request("workspace-prepare", 1, 1))
	<-j.done
	snap := observe(t, o, 2, 1)
	slot := snap.Workspace.Phases.Install
	if slot.Progress != "failed" || slot.Failure != "stopped" {
		t.Fatal(slot)
	}
	if err := b.ObserveInstall(slot, snap.Workspace.Witness); err != nil {
		t.Fatal(err)
	}
	if b.childOwns {
		t.Fatal("unaccepted offer transferred ownership")
	}
	if _, err := b.Handoff(); !errors.Is(err, ErrRetired) {
		t.Fatal("stopped offer invited retransmission", err)
	}
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Fatal("stopped offer dropped original root owner", err)
		}
	}
	if err := b.Finalize(absentBootstrap(&b)); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, fds)
}

func TestRemovalDuringWorkerCancellationKeepsSnapshotEncodable(t *testing.T) {
	offered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	o := testOwner(t, func(ctx context.Context, j *Job) error {
		if err := j.OfferRemoval(Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup", Witness: witness()}); err != nil {
			return err
		}
		close(offered)
		<-ctx.Done()
		close(canceled)
		<-release
		return ctx.Err()
	})
	j := start(t, o, cleanupRequest(1, "voluntary"))
	<-offered
	action := observe(t, o, 2, 1).Workspace.Phases.VoluntaryRemoval
	if _, err := o.Do(context.Background(), cleanupRequest(3, "terminal"), &Rights{}); !errors.Is(err, ErrOccupied) {
		t.Fatal(err)
	}
	<-canceled
	do(t, o, r4Unmount(4, 1, action, witness(), false), &Rights{})
	snap := observe(t, o, 5, 1)
	if snap.Workspace.State != "preparing" || snap.Workspace.Phases.VoluntaryRemoval.Progress != "complete" {
		t.Fatal(snap)
	}
	close(release)
	<-j.done
	if snap := observe(t, o, 6, 1); snap.Workspace.State != "failed" {
		t.Fatal(snap)
	}
}

func TestEndedOfferingWorkerCannotCreateAnAction(t *testing.T) {
	for _, op := range []string{"workspace-prepare", "workspace-cleanup"} {
		t.Run(op, func(t *testing.T) {
			o := testOwner(t, func(context.Context, *Job) error { return errors.New("worker ended without offering") })
			q := request(op, 1, 1)
			if op == "workspace-cleanup" {
				q = cleanupRequest(1, "voluntary")
			}
			j := start(t, o, q)
			<-j.done
			before := observe(t, o, 2, 1)
			var err error
			if op == "workspace-prepare" {
				err = j.OfferInstall(*phase())
			} else {
				err = j.OfferRemoval(Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup", Witness: witness()})
			}
			if err == nil {
				t.Fatal("ended worker offered an action")
			}
			after := observe(t, o, 3, 1)
			if after.Workspace.State != before.Workspace.State || after.Workspace.Phases.Install.Progress != "absent" || after.Workspace.Phases.VoluntaryRemoval.Progress != "absent" {
				t.Fatal("ended worker mutated action ownership", after)
			}
		})
	}
}
