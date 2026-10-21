package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func encodable(t *testing.T, body any) {
	t.Helper()
	e := &pb.Envelope{Version: 8, RequestId: 1}
	switch v := body.(type) {
	case *pb.StatusReply:
		e.Body = &pb.Envelope_StatusReply{StatusReply: v}
	case *pb.SuspendAck:
		e.Body = &pb.Envelope_SuspendAck{SuspendAck: v}
	case *pb.ResumeAck:
		e.Body = &pb.Envelope_ResumeAck{ResumeAck: v}
	default:
		t.Fatalf("unknown reply %T", body)
	}
	raw, err := control.Encode(e)
	if err != nil {
		t.Fatalf("unencodable %T: %v: %v", body, err, body)
	}
	if _, err := control.Decode(raw); err != nil {
		t.Fatal(err)
	}
}

type invariantMount struct {
	fakeMount
	entered, proceed chan struct{}
	result           Recovery
	failure          error
	openFailure      bool
}

func (m *invariantMount) proof(g uint64) (Recovery, error) {
	close(m.entered)
	<-m.proceed
	r := m.result
	if r.Generation != math.MaxUint64 {
		r.Generation = g
	}
	return r, m.failure
}
func (m *invariantMount) Prepare(_ context.Context, g uint64) (Recovery, error) { return m.proof(g) }
func (m *invariantMount) Recover(_ context.Context, tok *pb.ResumeToken) (Recovery, error) {
	return m.proof(tok.Suspension.Generation)
}
func (m *invariantMount) OpenAdmission(g uint64) error {
	if m.openFailure {
		return errors.New("admission publication refused")
	}
	return m.fakeMount.OpenAdmission(g)
}

// Exercise every recovery outcome and every public transition, checking the
// actual guest-built replies at each boundary, including in-flight recovery.
func TestGuestEveryTransitionReplyEncodes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*invariantMount)
	}{
		{"ready", func(m *invariantMount) {}},
		{"error", func(m *invariantMount) { m.failure = errors.New("authority unavailable") }},
		{"stale-generation", func(m *invariantMount) { m.result.Generation = math.MaxUint64 }},
		{"session", func(m *invariantMount) { m.result.SessionValidated = false }},
		{"authorization", func(m *invariantMount) { m.result.AuthorizationValidated = false }},
		{"renewal", func(m *invariantMount) { m.result.InitialRenewalInstalled = false }},
		{"subscription", func(m *invariantMount) { m.result.ColdSubscriptionInstalled = false }},
		{"terminal", func(m *invariantMount) { m.result.State = "terminal" }},
		{"authorization-required", func(m *invariantMount) { m.result.State = "authorization-required" }},
		{"closed", func(m *invariantMount) { m.result.State = "closed" }},
		{"admission-refused", func(m *invariantMount) { m.openFailure = true }},
		{"invalid-loss", func(m *invariantMount) { m.result.Loss = []*pb.Loss{{Sequence: 0}} }},
		{"loss-overflow", func(m *invariantMount) {
			for i := 1; i <= 129; i++ {
				m.result.Loss = append(m.result.Loss, &pb.Loss{Sequence: uint64(i), Reason: "lost"})
			}
		}},
	}
	for _, initial := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("initial=%t/%s", initial, tc.name), func(t *testing.T) {
				s, err := New(id(1), id(2), id(3), true)
				if err != nil {
					t.Fatal(err)
				}
				encodable(t, s.Status())
				m := &invariantMount{entered: make(chan struct{}), proceed: make(chan struct{}), result: ready()}
				m.cold.ColdComplete = true
				mid := mountID(4)
				if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
					t.Fatal(err)
				}
				encodable(t, s.Status())
				if initial {
					tc.mutate(m)
					done := make(chan error, 1)
					go func() { done <- s.Activate(context.Background(), mid, 0) }()
					<-m.entered
					encodable(t, s.Status())
					close(m.proceed)
					<-done
				} else {
					close(m.proceed)
					if err := s.Activate(context.Background(), mid, 0); err != nil {
						t.Fatal(err)
					}
					m.entered = make(chan struct{})
					m.proceed = make(chan struct{})
					tc.mutate(m)
					encodable(t, s.Status())
					x := begin(t, s, suspension(s))
					encodable(t, s.Status())
					if err := s.Drain(context.Background(), x, mid); err != nil {
						t.Fatal(err)
					}
					encodable(t, s.Status())
					ack, err := s.SuspendAck(x)
					if err != nil {
						t.Fatal(err)
					}
					encodable(t, ack)
					encodable(t, s.Status())
					resume, err := s.Resume(context.Background(), token(x))
					if err != nil {
						t.Fatal(err)
					}
					encodable(t, resume)
					<-m.entered
					encodable(t, s.Status())
					close(m.proceed)
					waitRecovered(t, s)
				}
				encodable(t, s.Status())
				// A second sleep/wake must remain encodable even after failed proof.
				x := begin(t, s, suspension(s))
				encodable(t, s.Status())
				if err := s.Drain(context.Background(), x, mid); err != nil {
					t.Fatal(err)
				}
				encodable(t, s.Status())
				ack, err := s.SuspendAck(x)
				if err != nil {
					t.Fatal(err)
				}
				encodable(t, ack)
				encodable(t, s.Status())
				// Keep successful mounts from starting a second proof on closed channels.
				m.entered = make(chan struct{})
				m.proceed = make(chan struct{})
				close(m.proceed)
				resume, err := s.Resume(context.Background(), token(x))
				if err != nil {
					t.Fatal(err)
				}
				encodable(t, resume)
				waitRecovered(t, s)
				encodable(t, s.Status())
				if err := s.Terminal(mid, "explicit terminal outcome", nil); err != nil {
					t.Fatal(err)
				}
				encodable(t, s.Status())
				for _, p := range []CleanupProof{{ProcessExited: true}, {KernelAbsent: true}, {ProcessExited: true, KernelAbsent: true}} {
					_ = s.Cleanup(mid, p)
					encodable(t, s.Status())
				}
				next := mountID(5)
				if err := s.Replace(context.Background(), mid, next, Witness{}, &fakeMount{}); err != nil {
					t.Fatal(err)
				}
				encodable(t, s.Status())
				if err := s.AcknowledgeRetired(s.Retired()[0].RetirementSequence); err != nil {
					t.Fatal(err)
				}
				encodable(t, s.Status())
				bad := suspension(s)
				bad.Generation += 1
				if _, err := s.BeginSuspend(bad); err == nil {
					t.Fatal("invalid generation accepted")
				}
				encodable(t, s.Status())
			})
		}
	}
}
func TestGuestRetirementAcknowledgementIsMonotonicAndIdempotent(t *testing.T) {
	s, _, mid := fixture(t)
	for i := 0; i < 3; i++ {
		if err := s.Terminal(mid, "ended", nil); err != nil {
			t.Fatal(err)
		}
		e := s.mounts[control.MountKey(mid)]
		if err := s.Cleanup(mid, CleanupProof{Witness: e.witness, ProcessExited: true, KernelAbsent: true}); err != nil {
			t.Fatal(err)
		}
		next := mountID(byte(10 + i))
		if err := s.Replace(context.Background(), mid, next, Witness{}, &fakeMount{}); err != nil {
			t.Fatal(err)
		}
		mid = next
	}
	for _, n := range []uint64{1, 1, 2, 1, 3, 3} {
		if err := s.AcknowledgeRetired(n); err != nil {
			t.Fatal(err)
		}
		encodable(t, s.Status())
	}
	if len(s.Retired()) != 0 {
		t.Fatal("acknowledged outcomes retained")
	}
	if err := s.AcknowledgeRetired(4); err == nil {
		t.Fatal("future ack accepted")
	}
	if s.acknowledgedSequence != 3 {
		t.Fatal("refusal changed acknowledgement")
	}
}
func TestGuestRefusesRetainedIncarnationReuse(t *testing.T) {
	s, _, old := fixture(t)
	_ = s.Terminal(old, "ended", nil)
	_ = s.Cleanup(old, CleanupProof{Witness: s.mounts[control.MountKey(old)].witness, ProcessExited: true, KernelAbsent: true})
	next := mountID(5)
	if err := s.Replace(context.Background(), old, next, Witness{}, &fakeMount{}); err != nil {
		t.Fatal(err)
	}
	_ = s.Terminal(next, "ended again", nil)
	_ = s.Cleanup(next, CleanupProof{ProcessExited: true, KernelAbsent: true})
	for _, replace := range []bool{false, true} {
		m := &fakeMount{}
		var err error
		if replace {
			err = s.Replace(context.Background(), next, old, Witness{}, m)
		} else {
			err = s.Register(context.Background(), old, Witness{}, m)
		}
		if err == nil || !m.cleaned {
			t.Fatal("retired incarnation reused or refused daemon not cleaned")
		}
		encodable(t, s.Status())
	}
}
