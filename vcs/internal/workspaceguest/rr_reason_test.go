package workspaceguest

import (
	"context"
	"errors"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

// Failed recovery retains a terminal reason across the next encodable sleep/wake.
func TestGuestFailedRecoveryRetainsEncodableTerminalReason(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	m.recover = func(context.Context, *pb.ResumeToken) (Recovery, error) {
		return Recovery{}, errors.New("authority unreachable after wake")
	}
	if _, err := resumeAndWait(t, s, context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	t.Logf("after failed recovery: state=%q reason=%q", st.Mounts[0].State, st.Mounts[0].Reason)
	if _, err := control.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_StatusReply{StatusReply: st}}); err != nil {
		t.Fatalf("status unencodable already: %v", err)
	}
	// Second sleep/wake.
	m.recover = nil
	y := cold(t, s, mid)
	a, err := s.Resume(context.Background(), token(y))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("resume ack mount: state=%q reason=%q", a.Mounts[0].State, a.Mounts[0].Reason)
	if _, err := control.Encode(&pb.Envelope{Version: 8, RequestId: 2, Body: &pb.Envelope_ResumeAck{ResumeAck: a}}); err != nil {
		t.Fatalf("guest-built ResumeAck cannot be encoded -> Serve returns, channel lost, VM discarded: %v", err)
	}
}

// Same for a failed initial Prepare.
func TestGuestFailedPrepareRetainsEncodableTerminalReason(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := &Recovery{State: "closed"}
	m := &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready(), prepareResult: bad}
	mid := mountID(4)
	if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(context.Background(), mid, 0); err == nil {
		t.Fatal("expected prepare failure")
	}
	y := cold(t, s, mid)
	a, err := s.Resume(context.Background(), token(y))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.Encode(&pb.Envelope{Version: 8, RequestId: 2, Body: &pb.Envelope_ResumeAck{ResumeAck: a}}); err != nil {
		t.Fatalf("ResumeAck unencodable: %v (state=%q reason=%q)", err, a.Mounts[0].State, a.Mounts[0].Reason)
	}
}
