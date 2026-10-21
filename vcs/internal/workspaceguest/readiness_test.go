package workspaceguest

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"testing"
	"time"
)

func registeredForReadiness(t *testing.T) (*Supervisor, *fakeMount, *pb.MountID) {
	t.Helper()
	s, err := New(id(1), id(2), id(3), true)
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready()}
	mid := mountID(4)
	if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	return s, m, mid
}
func TestRecoveryTypedReadinessBindsSerialAndStandalone(t *testing.T) {
	for _, tc := range []struct {
		name, state      string
		seq              uint64
		standalone, want bool
	}{
		{"pending", "pending", 0, false, false}, {"zero", "installed", 0, false, false}, {"installed", "installed", 1, false, true}, {"standalone", "not-required", 0, true, true}, {"hosted", "not-required", 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ready()
			r.Generation = 4
			r.GateSerial = 7
			r.Standalone = tc.standalone
			r.Renewal.State = tc.state
			r.Renewal.InstalledSequence = tc.seq
			r.Renewal.Permit = mountenrollment.Permit{Generation: 4, GateSerial: 7}
			if r.ready(4, 7) != tc.want {
				t.Fatal(r)
			}
			if r.ready(4, 8) {
				t.Fatal("stale prepared serial")
			}
			r.AuthorizationDeadline = r.AuthorizationDeadline.Add(time.Nanosecond)
			if !tc.standalone && r.ready(4, 7) {
				t.Fatal("unequal deadline")
			}
		})
	}
}
func TestGuestRepeatedSameGenerationCloseDefeatsDelayedPreparedProof(t *testing.T) {
	s, m, mid := registeredForReadiness(t)
	// Capture a proof for the already bound serial, then close again without
	// advancing generation. Open's exact comparison must reject the old proof.
	m.mu.Lock()
	serial := m.gateSerial
	m.mu.Unlock()
	r := ready()
	r.Generation = 0
	r.GateSerial = serial
	r.Renewal.Permit = mountenrollment.Permit{GateSerial: serial}
	m.prepareResult = &r
	if next := m.CloseAdmission(0); next <= serial {
		t.Fatal("Close did not advance serial")
	}
	if err := s.Activate(context.Background(), mid, 0); err == nil || m.isOpen() {
		t.Fatal("delayed Open crossed repeated Close")
	}
	if s.Status().Mounts[0].State != "terminal" {
		t.Fatal("failed Prepare reactivatable")
	}
}
func TestGuestOvertakenPrepareRetainsLossAndUnobservedOutcome(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true)
	if err != nil {
		t.Fatal(err)
	}
	m := &invariantMount{entered: make(chan struct{}), proceed: make(chan struct{}), result: ready(), failure: errors.New("failed prepare")}
	m.result.Loss = []*pb.Loss{{Sequence: 1, AcceptedBytes: 4096, Reason: "known tail"}}
	m.result.Outcome = control.UnknownOutcome()
	m.result.Outcome.CleanupDebt = 3
	mid := mountID(4)
	if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Activate(context.Background(), mid, 0) }()
	<-m.entered
	begin(t, s, suspension(s))
	close(m.proceed)
	if err := <-done; err == nil {
		t.Fatal("overtaken prepare succeeded")
	}
	status := s.Status().Mounts[0]
	if len(status.Loss) != 1 || status.Outcome.CleanupDebt != 3 || status.Outcome.Observation != "unobserved" {
		t.Fatal("failed prepare evidence lost", status)
	}
}
func TestGuestPreparationOutlivesObservationContext(t *testing.T) {
	s, _, mid := registeredForReadiness(t)
	m := &invariantMount{entered: make(chan struct{}), proceed: make(chan struct{}), result: ready()}
	m.CloseAdmission(0)
	s.mounts[control.MountKey(mid)].driver = m
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Activate(ctx, mid, 0) }()
	<-m.entered
	if _, ok := m.context.Deadline(); ok {
		t.Fatal("Prepare inherited a waiter deadline")
	}
	cancel()
	close(m.proceed)
	if err := <-done; err != nil || s.Status().Mounts[0].State != "ready" {
		t.Fatal("observer canceled generation-owned Prepare", err)
	}
}

func TestGuestOutcomeEvidenceAndDebtAreMonotonic(t *testing.T) {
	s, _, mid := registeredForReadiness(t)
	e := s.mounts[control.MountKey(mid)]
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range []*pb.MountOutcome{
		{Durability: "durable", Observation: "observed", Release: "released", CleanupDebt: 5},
		{Durability: "unresolved", Observation: "unobserved", Release: "unresolved", CleanupDebt: 1},
		{Durability: "unresolved", Observation: "observed", Release: "unresolved", CleanupDebt: 2},
	} {
		if err := s.mergeEvidenceLocked(e, nil, o); err != nil {
			t.Fatal(err)
		}
	}
	got := e.status.Outcome
	if got.Durability != "durable" || got.Observation != "observed" || got.Release != "released" || got.CleanupDebt != 5 {
		t.Fatal("evidence regressed", got)
	}
	if err := s.mergeEvidenceLocked(e, nil, &pb.MountOutcome{Durability: "lost", Observation: "observed", Release: "abandoned", CleanupDebt: 7}); err == nil {
		t.Fatal("contradictory outcome accepted")
	}
	if got := e.status.Outcome; got.Durability != "durable" || got.Release != "released" || got.CleanupDebt != 7 {
		t.Fatal("contradiction discarded prior evidence or debt", got)
	}
}
func TestGuestFailedOpenPreservesOutcomeEvidence(t *testing.T) {
	s, _, mid := registeredForReadiness(t)
	m := &invariantMount{openFailure: true}
	m.CloseAdmission(0)
	e := s.mounts[control.MountKey(mid)]
	e.driver = m
	e.status.Outcome = &pb.MountOutcome{Durability: "durable", Observation: "observed", Release: "released", CleanupDebt: 4}
	r := ready()
	m.bindProof(&r)
	s.mu.Lock()
	err := s.publishRecoveryLocked(context.Background(), e, 0, r, nil)
	s.mu.Unlock()
	if err == nil {
		t.Fatal("failed Open published")
	}
	got := s.Status().Mounts[0].Outcome
	if got.Durability != "durable" || got.Observation != "observed" || got.Release != "released" || got.CleanupDebt != 4 {
		t.Fatal("failed Open reset outcome", got)
	}
}
