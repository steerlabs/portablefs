package workspaceguest

import (
	"context"
	"errors"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func TestAwakeRecoveryAcknowledgesBeforeColdWorkAndRetainsLoss(t *testing.T) {
	s, m, _ := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	defer s.cancel()
	m.suspend = func(ctx context.Context, x *pb.Suspension) (ColdResult, error) {
		if !x.AwakeRecovery {
			t.Error("awake cut lost its identity")
		}
		if _, ok := ctx.Deadline(); ok {
			t.Error("awake work inherited a power deadline")
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ColdResult{}, ctx.Err()
		}
		return ColdResult{ColdComplete: true, Loss: []*pb.Loss{{Sequence: 1, AcceptedEntries: 1, AcceptedBytes: 17, Reason: "accepted tail unprovable"}}}, nil
	}
	x := suspension(s)
	x.AwakeRecovery = true
	ctx, cancel := context.WithCancel(context.Background())
	a, err := s.RecoverAwake(ctx, token(x))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if !control.MatchesSuspension(a.Token.Suspension, x) || len(a.Token.Suspension.Roster) != 1 || a.Mounts[0].State != "recovering" || m.isOpen() {
		t.Fatal("admission did not bind the closed fixed cohort", a)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("cold worker not owned")
	}
	if s.Status().State != "running" {
		t.Fatal("awake cut blocks Status")
	}
	close(release)
	ms := waitRecovered(t, s)
	if ms[0].State != "ready" || len(ms[0].Loss) != 1 || !m.isOpen() {
		t.Fatal(ms)
	}
	if _, err := s.RecoverAwake(context.Background(), token(x)); err == nil {
		t.Fatal("awake token replay accepted")
	}
}

func TestPowerSuspendOvertakesAwakeColdWorkerAndJoinsIt(t *testing.T) {
	s, m, mid := fixture(t)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer s.cancel()
	m.suspend = func(ctx context.Context, x *pb.Suspension) (ColdResult, error) {
		if !x.AwakeRecovery {
			return ColdResult{ColdComplete: true}, nil
		}
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return ColdResult{Loss: []*pb.Loss{{Sequence: 1, AcceptedBytes: 19, Reason: "late accepted tail"}}}, ctx.Err()
	}
	x := suspension(s)
	x.AwakeRecovery = true
	if _, err := s.RecoverAwake(context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	<-entered
	power := begin(t, s, suspension(s))
	<-cancelled
	done := make(chan error, 1)
	go func() { done <- s.Drain(context.Background(), power, mid) }()
	select {
	case err := <-done:
		t.Fatalf("unjoined worker escaped cold cut: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	a, err := s.SuspendAck(power)
	if err != nil || a.Suspension.AwakeRecovery || len(a.Mounts[0].Loss) != 1 || m.isOpen() {
		t.Fatalf("power cut: %v, %v", a, err)
	}
}

func TestAwakeColdFailureEndsIncarnationWithActualCause(t *testing.T) {
	s, m, _ := fixture(t)
	defer s.cancel()
	m.suspend = func(context.Context, *pb.Suspension) (ColdResult, error) {
		return ColdResult{}, errors.New("original worker failed")
	}
	x := suspension(s)
	x.AwakeRecovery = true
	if _, err := s.RecoverAwake(context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	ms := waitRecovered(t, s)
	if ms[0].State != "terminal" || ms[0].Reason != "original worker failed" || m.isOpen() {
		t.Fatal(ms)
	}
}
