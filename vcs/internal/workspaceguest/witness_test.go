package workspaceguest

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func partialWitnessFixture(t *testing.T) (*Supervisor, *fakeMount, *pb.MountID) {
	t.Helper()
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, mid := new(fakeMount), mountID(4)
	if err = s.Register(context.Background(), mid, Witness{Process: "pid/start"}, m); err != nil {
		t.Fatal(err)
	}
	return s, m, mid
}

func TestRecoveryRequiredClosesOnlyItsExactServingInterval(t *testing.T) {
	s, m, mid := partialWitnessFixture(t)
	for interval := 0; interval < 3; interval++ {
		if err := s.Activate(context.Background(), mid, 0); err != nil {
			t.Fatal(err)
		}
		m.mu.Lock()
		serial := m.gateSerial
		m.mu.Unlock()
		for _, obsolete := range [][2]uint64{{1, serial}, {0, serial - 1}} {
			if err := s.RecoveryRequired(mid, obsolete[0], obsolete[1], "delayed old observation"); err == nil {
				t.Fatal("obsolete observation closed a new interval")
			}
		}
		m.mu.Lock()
		open := m.open && m.gateSerial == serial
		m.mu.Unlock()
		if !open {
			t.Fatal("stale observation changed serving admission")
		}
		if err := s.RecoveryRequired(mid, 0, serial, "clock proof unavailable"); err != nil {
			t.Fatal(err)
		}
		if err := s.RecoveryRequired(mid, 0, serial, "duplicate observation"); err == nil {
			t.Fatal("old observation advanced the close serial again")
		}
		m.mu.Lock()
		closed := !m.open && m.gateSerial == serial+1
		m.mu.Unlock()
		if !closed || s.Status().Mounts[0].State != "closed" {
			t.Fatal("unavailable proof retained serving admission")
		}
	}
}

func TestWitnessPartialConflictRetainsNewAcquisitions(t *testing.T) {
	s, _, mid := partialWitnessFixture(t)
	if _, err := s.BindWitness(mid, Witness{Session: "first"}); err != nil {
		t.Fatal(err)
	}
	w, err := s.BindWitness(mid, Witness{Session: "other", Kernel: "kernel", Enrollment: "enrollment"})
	if err == nil || w.Session != "first" || w.Kernel != "kernel" || w.Enrollment != "enrollment" {
		t.Fatal(w, err)
	}
	if err = s.Cleanup(mid, CleanupProof{Witness: Witness{}, ProcessExited: true, KernelAbsent: true}); err == nil {
		t.Fatal("stale registration certified cleanup")
	}
	if err = s.Cleanup(mid, CleanupProof{Witness: w, ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
}
func TestWitnessCommitCloseCannotBlockOrOpen(t *testing.T) {
	s, m, mid := partialWitnessFixture(t)
	entered, finish := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	s.ConfigureWitnessPersistence(func(_ *pb.MountID, w Witness) error { writes.Add(1); close(entered); <-finish; return nil })
	done := make(chan error, 1)
	go func() { _, err := s.BindWitness(mid, Witness{Session: "session", Kernel: "kernel"}); done <- err }()
	<-entered
	if _, err := s.BeginSuspend(suspension(s)); err != nil {
		t.Fatal(err)
	}
	close(finish)
	if err := <-done; err == nil {
		t.Fatal("commit ignored newer Close")
	}
	w, err := s.BoundWitness(mid)
	if err != nil || w.Kernel != "kernel" || writes.Load() != 1 {
		t.Fatal(w, err, writes.Load())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.open || m.opens != 0 {
		t.Fatal("overtaken witness opened admission")
	}
}
func TestWitnessPersistenceFailureRetainsOwnerAndRefusesReady(t *testing.T) {
	s, _, mid := partialWitnessFixture(t)
	s.ConfigureWitnessPersistence(func(*pb.MountID, Witness) error { return errors.New("fsync failed") })
	w, err := s.BindWitness(mid, Witness{Session: "session", Kernel: "kernel"})
	if err == nil || w.Kernel != "kernel" {
		t.Fatal(w, err)
	}
	if err = s.Activate(context.Background(), mid, 0); err == nil {
		t.Fatal("persistence failure admitted mount")
	}
	if got := s.Status().Mounts[0]; got.State != "terminal" || got.Cleanup != "retained" {
		t.Fatal(got)
	}
}
func TestWitnessStablePathRejectsAnotherAuthority(t *testing.T) {
	s, _, mid := partialWitnessFixture(t)
	if _, err := s.BindWitness(mid, Witness{Target: "/workspaces/shared"}); err != nil {
		t.Fatal(err)
	}
	other := mountID(12)
	other.AuthorityId[0]++
	m := new(fakeMount)
	if err := s.Register(context.Background(), other, Witness{Target: "/workspaces/shared"}, m); err == nil {
		t.Fatal("stacked same target for another authority")
	}
	if !m.cleaned || len(s.Status().Mounts) != 1 {
		t.Fatal("refused child ownership escaped")
	}
}
