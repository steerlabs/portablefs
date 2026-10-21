package workspaceguest

import (
	"context"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func TestTransportFailedPrepareRetainsTerminalOutcomeOnResume(t *testing.T) {
	c, s, done := transportRig(t)
	m := &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready(), prepareResult: &Recovery{State: "closed"}}
	mid := mountID(4)
	if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	_ = s.Activate(context.Background(), mid, 0) // invalid closed proof terminalizes this incarnation
	pairTransport(t, c)
	x := suspension(s)
	r := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 2, Body: &pb.Envelope_Suspend{Suspend: x}})
	ack := r.GetSuspendAck()
	if ack == nil {
		t.Fatalf("no ack: %v", r)
	}
	if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_Resume{Resume: &pb.ResumeToken{Suspension: ack.Suspension, WakeNonce: id(9)}}}); err != nil {
		t.Fatal(err)
	}
	if reply, err := control.Read(c); err == nil {
		if reply.GetResumeAck() == nil || reply.GetResumeAck().Mounts[0].State != "terminal" {
			t.Fatalf("failed Prepare lost terminal outcome: %v", reply)
		}
		return
	} else {
		t.Logf("host read error: %v", err)
	}
	err := <-done
	t.Fatalf("guest Serve ended after valid Resume: %v; phase=%s", err, s.Status().State)
}
