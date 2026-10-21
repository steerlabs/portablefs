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
func TestGuestPrepareAndRecoverOwnLogicalTransientOutageBeyond45Seconds(t *testing.T) {
	for _, initial := range []bool{true, false} {
		t.Run(map[bool]string{true: "prepare", false: "recover"}[initial], func(t *testing.T) {
			s, m, mid := registeredForReadiness(t)
			start := time.Unix(100, 0)
			now := start
			attempts := 0
			retry := func(ctx context.Context, g uint64) (Recovery, error) {
				// Bounded network attempts advance injected elapsed time. The same valid
				// session, generation and renewal object remain owned throughout the job.
				for attempts < 6 {
					if ctx.Err() != nil {
						return Recovery{}, ctx.Err()
					}
					now = now.Add(10 * time.Second)
					attempts++
				}
				r := ready()
				r.Generation = g
				m.bindProof(&r)
				return r, nil
			}
			if initial {
				im := &transientPrepareMount{prepare: retry}
				im.CloseAdmission(0)
				// Rebind to the actual embedded owner; the fixture has never activated.
				retryOwner := func(ctx context.Context, g uint64) (Recovery, error) {
					r, err := retry(ctx, g)
					im.bindProof(&r)
					return r, err
				}
				im.prepare = retryOwner
				s.mounts[control.MountKey(mid)].driver = im
				if err := s.Activate(context.Background(), mid, 0); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := s.Activate(context.Background(), mid, 0); err != nil {
					t.Fatal(err)
				}
				x := cold(t, s, mid)
				m.recover = func(ctx context.Context, tok *pb.ResumeToken) (Recovery, error) {
					return retry(ctx, tok.Suspension.Generation)
				}
				if _, err := resumeAndWait(t, s, context.Background(), token(x)); err != nil {
					t.Fatal(err)
				}
			}
			if now.Sub(start) <= 45*time.Second || attempts != 6 || s.Status().Mounts[0].State != "ready" {
				t.Fatal("logical recovery timed out")
			}
		})
	}
}

type transientPrepareMount struct {
	fakeMount
	prepare func(context.Context, uint64) (Recovery, error)
}

func (m *transientPrepareMount) Prepare(c context.Context, g uint64) (Recovery, error) {
	return m.prepare(c, g)
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
	cancel()
	close(m.proceed)
	if err := <-done; err != nil || s.Status().Mounts[0].State != "ready" {
		t.Fatal("observer canceled generation-owned Prepare", err)
	}
}
