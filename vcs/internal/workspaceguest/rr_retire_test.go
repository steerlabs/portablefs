package workspaceguest

import (
	"context"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

// Repeated retirement acknowledgements and future-sequence refusals keep the
// paired stream available for subsequent status observations.
func TestTransportDuplicateRetirementAcknowledgementKeepsChannel(t *testing.T) {
	c, s, done := transportRig(t)
	pairTransport(t, c)
	ctx := context.Background()
	old := mountID(4)
	replacement := proto.Clone(old).(*pb.MountID)
	replacement.Incarnation = id(5)
	if err := s.Register(ctx, old, Witness{}, &fakeMount{}); err != nil {
		t.Fatal(err)
	}
	_ = s.Terminal(old, "test terminal outcome", nil)
	_ = s.Cleanup(old, CleanupProof{ProcessExited: true, KernelAbsent: true})
	if err := s.Replace(ctx, old, replacement, Witness{}, &fakeMount{}); err != nil {
		t.Fatal(err)
	}
	status := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 2, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}).GetStatusReply()
	ack := &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_RetireAck{RetireAck: &pb.RetireAck{ThroughSequence: status.Retired[len(status.Retired)-1].RetirementSequence}}}
	if r := exchange(t, c, ack); r.GetResult().GetCode() != "accepted" {
		t.Fatal("first ack refused")
	}
	dup := proto.Clone(ack).(*pb.Envelope)
	dup.RequestId = 4
	if err := control.Write(c, dup); err != nil {
		t.Fatal(err)
	}
	if r, err := control.Read(c); err == nil {
		if r.GetResult().GetCode() != "accepted" {
			t.Fatalf("duplicate refused: %v", r)
		}
		// A future sequence is an operation refusal, not a channel failure.
		future := clone(dup)
		future.RequestId = 5
		future.GetRetireAck().ThroughSequence++
		if reply := exchange(t, c, future); reply.GetResult().GetCode() != "refused" {
			t.Fatal("future ack accepted")
		}
		status := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 6, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}).GetStatusReply()
		if status == nil || status.State != "running" {
			t.Fatal("refusal ended paired stream")
		}
		return
	}
	t.Fatalf("duplicate RetireAck ended the paired channel (VM discard): %v phase=%s", <-done, s.Status().State)
}
