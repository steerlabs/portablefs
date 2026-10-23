package workspaceguest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

type rrRecordingMount struct {
	fakeMount
	mu2              sync.Mutex
	subscriptionLive bool
	recoverEntered   chan struct{}
	recoverRelease   chan struct{}
}

func (m *rrRecordingMount) Suspend(ctx context.Context, s *pb.Suspension) (ColdResult, error) {
	m.mu2.Lock()
	m.subscriptionLive = false
	m.mu2.Unlock()
	return ColdResult{Generation: s.Generation, ColdComplete: true}, nil
}
func (m *rrRecordingMount) Recover(ctx context.Context, t *pb.ResumeToken) (Recovery, error) {
	close(m.recoverEntered)
	<-m.recoverRelease // ignores ctx entirely
	m.mu2.Lock()
	m.subscriptionLive = true
	m.mu2.Unlock()
	r := ready()
	r.Generation = t.Suspension.Generation
	m.bindProof(&r)
	return r, nil
}

// Original reviewer schedule (finding 1), adapted to the corrected API.
func TestRROriginalOvertakenRecoverSchedule(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := &rrRecordingMount{recoverEntered: make(chan struct{}), recoverRelease: make(chan struct{})}
	mid := mountID(4)
	if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(context.Background(), mid, 0); err != nil {
		t.Fatal(err)
	}
	x1 := cold(t, s, mid)
	if _, err := s.Resume(context.Background(), token(x1)); err != nil {
		t.Fatal(err)
	}
	<-m.recoverEntered
	x2 := begin(t, s, suspension(s))
	drained := make(chan error, 1)
	go func() { drained <- s.Drain(context.Background(), x2, mid) }()
	select {
	case err := <-drained:
		t.Fatalf("drain completed while overtaken Recover still running: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(m.recoverRelease)
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
	ack, err := s.SuspendAck(x2)
	m.mu2.Lock()
	live := m.subscriptionLive
	m.mu2.Unlock()
	if err == nil && live {
		t.Fatalf("SUSPENDED-COLD acknowledged while overtaken Recover reinstalled a live subscription: %v", ack)
	}
	if err != nil {
		t.Fatal(err)
	}
	if m.isOpen() {
		t.Fatal("open")
	}
}

// Drain parent context expires while waiting for an overtaken call: drain
// cannot be retried in that generation (draining marker stays set).
func TestRRDrainWaitTimeoutBlocksRetry(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := &rrRecordingMount{recoverEntered: make(chan struct{}), recoverRelease: make(chan struct{})}
	mid := mountID(4)
	_ = s.Register(context.Background(), mid, Witness{}, m)
	_ = s.Activate(context.Background(), mid, 0)
	x1 := cold(t, s, mid)
	_, _ = s.Resume(context.Background(), token(x1))
	<-m.recoverEntered
	x2 := begin(t, s, suspension(s))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = s.Drain(ctx, x2, mid)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("drain wait did not expire: %v", err)
	}
	close(m.recoverRelease)
	if err := s.Drain(context.Background(), x2, mid); !errors.Is(err, ErrState) {
		t.Fatalf("incomplete drain retried in same generation: %v", err)
	}
	if _, err := s.SuspendAck(x2); err == nil {
		t.Fatal("incomplete drain earned cold proof")
	}
}
