package workspaceguest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

// Serve pairs one ordered stream. Disconnect permanently discards this model;
// there is no reconnect that could restore resume eligibility. expected is
// provisioned over a separate VM-bound console, not learned from the peer.
// PairingProof authenticates the seeded guest before the host discloses identity.
// Fresh boot nonces make this proof unusable on any later boot.
func PairingProof(expected *pb.Hello) []byte {
	h := hmac.New(sha256.New, expected.BootId)
	h.Write([]byte("portablefs-workspace-control-8"))
	h.Write(expected.HostServiceId)
	return h.Sum(nil)
}

func Serve(ctx context.Context, stream io.ReadWriter, expected *pb.Hello, supervisor *Supervisor, paired func()) error {
	defer supervisor.ChannelLost()
	if _, err := stream.Write(PairingProof(expected)); err != nil {
		return fmt.Errorf("write guest pairing proof: %w", err)
	}
	request, err := control.Read(stream)
	if err != nil {
		return fmt.Errorf("workspace control stream: %w", err)
	}
	host := request.GetHello()
	if host == nil || !proto.Equal(host.Release, expected.Release) || string(host.BootId) != string(expected.BootId) || string(host.HostServiceId) != string(expected.HostServiceId) {
		return fmt.Errorf("workspace pairing refused")
	}
	if err := control.Pair(host, expected); err != nil {
		return fmt.Errorf("workspace control stream: %w", err)
	}
	if paired != nil {
		paired()
	}
	if err := control.Write(stream, &pb.Envelope{Version: 8, RequestId: request.RequestId, Body: &pb.Envelope_HelloAck{HelloAck: expected}}); err != nil {
		return fmt.Errorf("workspace control stream: %w", err)
	}
	prior := request.RequestId
	for {
		request, err = control.Read(stream)
		if err != nil {
			return fmt.Errorf("workspace control stream: %w", err)
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
			transaction, err := supervisor.BeginSuspend(body.Suspend)
			if err != nil {
				return fmt.Errorf("workspace control stream: %w", err)
			}
			for _, id := range transaction.Roster {
				if err := supervisor.Drain(ctx, transaction, id); err != nil {
					return fmt.Errorf("workspace control stream: %w", err)
				}
			}
			ack, err := supervisor.SuspendAck(transaction)
			if err != nil {
				return fmt.Errorf("workspace control stream: %w", err)
			}
			reply.Body = &pb.Envelope_SuspendAck{SuspendAck: ack}
		case *pb.Envelope_Resume:
			ack, err := supervisor.Resume(ctx, body.Resume)
			if err != nil {
				refusal := &pb.Envelope{Version: 8, RequestId: prior, Body: &pb.Envelope_Result{Result: &pb.Result{Code: "refused", Reason: err.Error()}}}
				if writeErr := control.Write(stream, refusal); writeErr != nil {
					return fmt.Errorf("write resume refusal: %w (resume: %v)", writeErr, err)
				}
				return fmt.Errorf("workspace resume refused: %w", err)
			}
			reply.Body = &pb.Envelope_ResumeAck{ResumeAck: ack}
		case *pb.Envelope_RetireAck:
			if err := supervisor.AcknowledgeRetired(body.RetireAck.Outcomes); err != nil {
				return fmt.Errorf("acknowledge retired outcomes: %w", err)
			}
			reply.Body = &pb.Envelope_Result{Result: &pb.Result{Code: "accepted"}}
		case *pb.Envelope_Provision, *pb.Envelope_Mount, *pb.Envelope_Umount:
			reply.Body = &pb.Envelope_Result{Result: &pb.Result{Code: "unavailable", Reason: "real mount integration pending"}}
		default:
			return fmt.Errorf("workspace request body refused")
		}
		if err := control.Write(stream, reply); err != nil {
			return fmt.Errorf("workspace control stream: %w", err)
		}
	}
}
