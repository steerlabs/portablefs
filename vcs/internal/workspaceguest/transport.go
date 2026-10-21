package workspaceguest

import (
	"context"
	"fmt"
	"io"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

// Serve pairs one ordered stream. Disconnect permanently discards this model;
// there is no reconnect that could restore resume eligibility. expected is
// provisioned over a separate VM-bound console, not learned from the peer.
func Serve(ctx context.Context, stream io.ReadWriter, expected *pb.Hello, supervisor *Supervisor, paired func()) error {
	defer supervisor.Discard()
	request, err := control.Read(stream)
	if err != nil {
		return err
	}
	host := request.GetHello()
	if host == nil || !proto.Equal(host.Release, expected.Release) || string(host.BootId) != string(expected.BootId) || string(host.HostServiceId) != string(expected.HostServiceId) {
		return fmt.Errorf("workspace pairing refused")
	}
	if err := control.Pair(host, expected); err != nil {
		return err
	}
	if paired != nil {
		paired()
	}
	if err := control.Write(stream, &pb.Envelope{Version: 8, RequestId: request.RequestId, Body: &pb.Envelope_HelloAck{HelloAck: expected}}); err != nil {
		return err
	}
	prior := request.RequestId
	for {
		request, err = control.Read(stream)
		if err != nil {
			return err
		}
		if request.RequestId <= prior {
			return fmt.Errorf("workspace request ID did not increase")
		}
		prior = request.RequestId
		reply := &pb.Envelope{Version: 8, RequestId: prior}
		switch body := request.Body.(type) {
		case *pb.Envelope_Status:
			reply.Body = &pb.Envelope_StatusReply{StatusReply: supervisor.Status()}
		case *pb.Envelope_Suspend:
			if err := supervisor.BeginSuspend(body.Suspend); err != nil {
				return err
			}
			for _, id := range body.Suspend.Roster {
				if err := supervisor.Drain(ctx, body.Suspend, id); err != nil {
					return err
				}
			}
			ack, err := supervisor.SuspendAck(body.Suspend)
			if err != nil {
				return err
			}
			reply.Body = &pb.Envelope_SuspendAck{SuspendAck: ack}
		case *pb.Envelope_Resume:
			ack, err := supervisor.Resume(ctx, body.Resume)
			if err != nil {
				return err
			}
			reply.Body = &pb.Envelope_ResumeAck{ResumeAck: ack}
		case *pb.Envelope_Provision, *pb.Envelope_Mount, *pb.Envelope_Umount:
			reply.Body = &pb.Envelope_Result{Result: &pb.Result{Code: "unavailable", Reason: "real mount integration pending"}}
		default:
			return fmt.Errorf("workspace request body refused")
		}
		if err := control.Write(stream, reply); err != nil {
			return err
		}
	}
}
