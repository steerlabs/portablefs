package workspaceguest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

func writtenStatus(t *testing.T, s *Supervisor, snapshot *pb.StatusReply) {
	t.Helper()
	if err := s.writeReply(io.Discard, &pb.Envelope{Version: 8, RequestId: 100, Body: &pb.Envelope_StatusReply{StatusReply: snapshot}}); err != nil {
		t.Fatal(err)
	}
}

func TestObservationPreservesDistinctSameCategoryFailures(t *testing.T) {
	s, _, mid := fixture(t)
	s.jobDriver = jobDriverFunc(func(_ context.Context, j *pb.MountJob, _ *pb.Provision) error {
		return fmt.Errorf("diagnostic-%d", j.RequestId)
	})
	for rid := uint64(2); rid < 102; rid++ {
		if err := s.AcceptJob(jobRequest(rid, mid, "mount")); err != nil {
			t.Fatal(err)
		}
		waitDesiredJobsJoined(t, s)
		snapshot := s.Status()
		exact := snapshot.Jobs[0]
		if exact.RequestId != rid || exact.Reason != fmt.Sprintf("diagnostic-%d", rid) || exact.Failure != "handler-failed" {
			t.Fatal(exact)
		}
		if err := s.AcceptJob(jobRequest(rid+1, mid, "umount")); !errors.Is(err, ErrPredecessorUnobserved) {
			t.Fatalf("retry erased result: %v", err)
		}
		if !proto.Equal(s.Status().Jobs[0], exact) {
			t.Fatal("refusal changed slot")
		}
		writtenStatus(t, s, snapshot)
		if !proto.Equal(s.Status().Jobs[0], exact) {
			t.Fatal("observation erased result")
		}
	}
}

type failingStatusWriter struct{ wrote bool }

func (w *failingStatusWriter) Write(p []byte) (int, error) {
	w.wrote = true
	return len(p) / 2, io.ErrClosedPipe
}

func TestObservationPublicationBoundaries(t *testing.T) {
	for _, mode := range []string{"internal", "failed-write", "running-snapshot", "different-result", "successful-write"} {
		t.Run(mode, func(t *testing.T) {
			s, _, mid := fixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			s.jobDriver = jobDriverFunc(func(_ context.Context, j *pb.MountJob, _ *pb.Provision) error {
				if j.RequestId == 2 {
					close(entered)
					<-release
				}
				return errors.New("EPERM")
			})
			if err := s.AcceptJob(jobRequest(2, mid, "mount")); err != nil {
				t.Fatal(err)
			}
			await(t, entered)
			running := s.Status()
			close(release)
			waitDesiredJobsJoined(t, s)
			terminal := s.Status()
			switch mode {
			case "internal":
				for range 10 {
					_ = s.Status()
				}
			case "failed-write":
				writer := &failingStatusWriter{}
				err := s.writeReply(writer, &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_StatusReply{StatusReply: terminal}})
				if !writer.wrote || !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
			case "running-snapshot":
				writtenStatus(t, s, running)
			case "different-result":
				changed := clone(terminal)
				changed.Jobs[0].Reason = "ENOSPC"
				writtenStatus(t, s, changed)
			case "successful-write":
				writtenStatus(t, s, terminal)
			}
			err := s.AcceptJob(jobRequest(4, mid, "mount"))
			if mode == "successful-write" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrPredecessorUnobserved) {
				t.Fatal(err)
			}
			if mode != "successful-write" && !proto.Equal(s.Status().Jobs[0], terminal.Jobs[0]) {
				t.Fatal("result changed")
			}
			// A late publication of the predecessor snapshot cannot observe its successor.
			if mode == "successful-write" {
				waitDesiredJobsJoined(t, s)
				writtenStatus(t, s, terminal)
				if err := s.AcceptJob(jobRequest(5, mid, "umount")); !errors.Is(err, ErrPredecessorUnobserved) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestObservationTransportTypedRefusalAndLostAcceptance(t *testing.T) {
	c, s, done := transportRig(t)
	pairTransport(t, c)
	mid := mountID(4)
	if err := s.Register(context.Background(), mid, Witness{}, &fakeMount{}); err != nil {
		t.Fatal(err)
	}
	accepted := exchange(t, c, jobRequest(2, mid, "mount"))
	if accepted.GetResult().Code != "accepted" {
		t.Fatal(accepted)
	}
	// Treat the acceptance as lost to the caller: a second attempt cannot erase it.
	waitDesiredJobsJoined(t, s)
	refused := exchange(t, c, jobRequest(3, mid, "umount"))
	if refused.GetResult().Code != "predecessor-unobserved" || refused.GetResult().Reason != ErrPredecessorUnobserved.Error() {
		t.Fatal(refused)
	}
	snapshot := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 4, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}).GetStatusReply()
	if snapshot.Jobs[0].RequestId != 2 || snapshot.Jobs[0].Failure != "unavailable" {
		t.Fatal(snapshot)
	}
	if exchange(t, c, jobRequest(5, mid, "umount")).GetResult().Code != "accepted" {
		t.Fatal("observed successor refused")
	}
	// Losing the next Status reply destroys the boot, with its exact result intact.
	waitDesiredJobsJoined(t, s)
	if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 6, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if await(t, done) == nil {
		t.Fatal("lost channel survived")
	}
	if s.Status().State != "discard-only" || s.AcceptJob(jobRequest(7, mid, "mount")) == nil {
		t.Fatal("lost channel readmitted work")
	}
}

func TestObservationRetirementAndSuspendDoNotWait(t *testing.T) {
	s, _, mid := fixture(t)
	if err := s.AcceptJob(jobRequest(2, mid, "mount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	exact := s.Status().Jobs[0]
	ack, err := s.Suspend(context.Background(), suspension(s), time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resumeAndWait(t, s, context.Background(), token(ack.Suspension)); err != nil {
		t.Fatal(err)
	}
	e := s.mounts[control.MountKey(mid)]
	if err := acquire(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	release(e)
	if err := s.Terminal(mid, "removed", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(mid, CleanupProof{Witness: s.mounts[control.MountKey(mid)].witness, ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(context.Background(), mid, mountID(5), Witness{}, &fakeMount{}); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(s.Retired()[0].Job, exact) {
		t.Fatal("retirement dropped unobserved result")
	}
	var frame bytes.Buffer
	if err := s.writeReply(&frame, &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_StatusReply{StatusReply: s.Status()}}); err != nil {
		t.Fatal(err)
	}
	if err := acknowledgeExposedRetired(s, 1); err != nil {
		t.Fatal(err)
	}
}

func TestObservationChannelRejectsReplayAfterRetireAck(t *testing.T) {
	c, s, done := transportRig(t)
	pairTransport(t, c)
	mid := mountID(4)
	if exchange(t, c, jobRequest(2, mid, "mount")).GetResult().Code != "accepted" {
		t.Fatal("not accepted")
	}
	waitDesiredJobsJoined(t, s)
	snapshot := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}).GetStatusReply()
	if len(snapshot.Retired) != 1 {
		t.Fatal(snapshot)
	}
	ack := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 4, Body: &pb.Envelope_RetireAck{RetireAck: &pb.RetireAck{ThroughSequence: 1}}})
	if ack.GetResult().Code != "accepted" {
		t.Fatal(ack)
	}
	_ = control.Write(c, jobRequest(2, mid, "mount"))
	if err := await(t, done); err == nil {
		t.Fatal("replayed request admitted")
	}
	if len(s.Status().Jobs) != 0 || len(s.Retired()) != 0 || s.Status().State != "discard-only" {
		t.Fatal("replay dispatched work")
	}
}

// The review's retry storm now observes every exact attempt instead of counting
// categories. Repeated handler failures must preserve each distinct diagnostic.
func TestObservationRetryStormRetainsEveryExactResult(t *testing.T) {
	s, _, mid := fixture(t)
	s.jobDriver = jobDriverFunc(func(_ context.Context, j *pb.MountJob, _ *pb.Provision) error {
		switch j.RequestId % 7 {
		case 0:
			return nil
		case 1:
			return ErrUnavailable
		case 2:
			return ErrState
		case 3:
			return context.DeadlineExceeded
		case 4:
			return context.Canceled
		default:
			return fmt.Errorf("handler failure %d", j.RequestId)
		}
	})
	distinct := map[string]bool{}
	for rid := uint64(2); rid < 3002; rid++ {
		if err := s.AcceptJob(jobRequest(rid, mid, []string{"provision", "mount", "umount"}[rid%3])); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		j := s.jobs[control.MountKey(mid)]
		s.mu.Unlock()
		await(t, j.done)
		terminal := s.Status()
		exact := terminal.Jobs[0]
		if exact.RequestId != rid || (exact.Phase != "complete" && exact.Phase != "failed") {
			t.Fatal(exact)
		}
		if err := s.AcceptJob(jobRequest(rid+1, mid, "mount")); !errors.Is(err, ErrPredecessorUnobserved) {
			t.Fatal(err)
		}
		if !proto.Equal(exact, s.Status().Jobs[0]) {
			t.Fatal("retry erased exact result")
		}
		writtenStatus(t, s, terminal)
		distinct[exact.Reason] = true
	}
	if len(distinct) < 800 || len(s.Retired()) != 0 {
		t.Fatal("distinct diagnostics collapsed or retry allocated retirement")
	}
}

type blockedStatusWriter struct{ entered, release chan struct{} }

func (w blockedStatusWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}

func TestObservationTerminalPublicationDuringStatusWrite(t *testing.T) {
	s, _, mid := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	s.jobDriver = jobDriverFunc(func(_ context.Context, j *pb.MountJob, _ *pb.Provision) error {
		if j.RequestId == 2 {
			close(entered)
			<-release
		}
		return errors.New("late EPERM")
	})
	if err := s.AcceptJob(jobRequest(2, mid, "mount")); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	running := s.Status()
	writer := blockedStatusWriter{make(chan struct{}), make(chan struct{})}
	written := make(chan error, 1)
	go func() {
		written <- s.writeReply(writer, &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_StatusReply{StatusReply: running}})
	}()
	await(t, writer.entered)
	close(release)
	waitDesiredJobsJoined(t, s)
	// Joining while the writer is blocked also proves no state lock spans I/O.
	close(writer.release)
	if err := await(t, written); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptJob(jobRequest(4, mid, "umount")); !errors.Is(err, ErrPredecessorUnobserved) {
		t.Fatal(err)
	}
	if s.Status().Jobs[0].Reason != "late EPERM" {
		t.Fatal("late publication erased")
	}
	writtenStatus(t, s, s.Status())
	if err := s.AcceptJob(jobRequest(5, mid, "umount")); err != nil {
		t.Fatal(err)
	}
}
