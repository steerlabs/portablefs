package workspaceguest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

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

func Serve(ctx context.Context, stream io.ReadWriteCloser, expected *pb.Hello, supervisor *Supervisor, paired func()) (serveErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer stream.Close()
	defer func() {
		if serveErr != nil && supervisor.channelFailure != nil {
			supervisor.channelFailure(serveErr)
		}
	}()
	defer supervisor.ChannelLost()
	stop := context.AfterFunc(ctx, func() { supervisor.ChannelLost(); _ = stream.Close() })
	defer stop()
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
	// One reader can observe EOF while the ordered dispatcher waits on a drain
	// or response write. Bounded read-ahead is not concurrent RPC dispatch.
	type frame struct {
		request    *pb.Envelope
		receivedAt time.Time
	}
	frames := make(chan frame, 1)
	readDone := make(chan error, 1)
	// The reader publishes its cause before cancellation closes a blocked
	// response write. Preserve that cause at every dispatcher return boundary.
	defer func() {
		select {
		case err := <-readDone:
			serveErr = fmt.Errorf("workspace control stream: %w", err)
		default:
		}
	}()
	go func(prior uint64) {
		for {
			request, receivedAt, err := control.ReadReceived(stream)
			if err == nil && request.RequestId <= prior {
				err = fmt.Errorf("workspace request ID did not increase")
			}
			if err != nil {
				supervisor.ChannelLost()
				readDone <- err
				cancel()
				return
			}
			prior = request.RequestId
			select {
			case frames <- frame{request, receivedAt}:
			case <-ctx.Done():
				return
			default:
				// Never stop reading behind dispatch: this paired peer has one
				// ordered exchange, not an arbitrary pipelined RPC window.
				supervisor.ChannelLost()
				readDone <- fmt.Errorf("workspace request read-ahead exceeded")
				cancel()
				return
			}
		}
	}(request.RequestId)
	for {
		var incoming frame
		select {
		case incoming = <-frames:
		case <-ctx.Done():
			select {
			case err := <-readDone:
				return fmt.Errorf("workspace control stream: %w", err)
			default:
				return fmt.Errorf("workspace control stream: %w", ctx.Err())
			}
		}
		request = incoming.request
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("workspace control stream: %w", err)
		}
		prior := request.RequestId
		reply := &pb.Envelope{Version: 8, RequestId: prior}
		switch body := request.Body.(type) {
		case *pb.Envelope_IdentityRequest:
			identity, err := supervisor.Identity(body.IdentityRequest)
			if err != nil {
				reply.Body = &pb.Envelope_Result{Result: &pb.Result{Code: "refused", Reason: control.BoundedReason(err.Error())}}
			} else {
				reply.Body = &pb.Envelope_IdentityReply{IdentityReply: identity}
			}
		case *pb.Envelope_Status:
			reply.Body = &pb.Envelope_StatusReply{StatusReply: supervisor.Status()}
		case *pb.Envelope_Suspend:
			ack, err := supervisor.Suspend(ctx, body.Suspend, incoming.receivedAt.Add(time.Duration(request.DrainBudgetNanos)))
			if err != nil {
				return fmt.Errorf("workspace control stream: %w", err)
			}
			reply.Body = &pb.Envelope_SuspendAck{SuspendAck: ack}
		case *pb.Envelope_Resume:
			ack, err := supervisor.Resume(ctx, body.Resume)
			if err != nil {
				refusal := &pb.Envelope{Version: 8, RequestId: prior, Body: &pb.Envelope_Result{Result: &pb.Result{Code: "refused", Reason: control.BoundedReason(err.Error())}}}
				if writeErr := control.Write(stream, refusal); writeErr != nil {
					return fmt.Errorf("write resume refusal: %w (resume: %v)", writeErr, err)
				}
				return fmt.Errorf("workspace resume refused: %w", err)
			}
			reply.Body = &pb.Envelope_ResumeAck{ResumeAck: ack}
		case *pb.Envelope_RetireAck:
			result := &pb.Result{Code: "accepted"}
			if err := supervisor.AcknowledgeRetired(body.RetireAck.ThroughSequence); err != nil {
				result.Code = "refused"
				result.Reason = control.BoundedReason(err.Error())
			}
			reply.Body = &pb.Envelope_Result{Result: result}
		case *pb.Envelope_Provision, *pb.Envelope_Mount, *pb.Envelope_Umount:
			result := &pb.Result{Code: "accepted"}
			if err := supervisor.AcceptJob(request); err != nil {
				result.Code = "refused"
				if errors.Is(err, ErrPredecessorUnobserved) {
					result.Code = "predecessor-unobserved"
				}
				result.Reason = control.BoundedReason(err.Error())
			}
			reply.Body = &pb.Envelope_Result{Result: result}
		default:
			return fmt.Errorf("workspace request body refused")
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("workspace control stream: %w", err)
		}
		if err := supervisor.writeReply(stream, reply); err != nil {
			return fmt.Errorf("workspace control stream: %w", err)
		}
	}
}

// ConfigureChannelFailure is installed before pairing. Observation runs after
// admission closure and before the owned stream closes; host discard may stop
// the VM immediately at EOF, before main could report a returned error.
func (s *Supervisor) ConfigureChannelFailure(observe func(error)) { s.channelFailure = observe }

// No supervisor lock spans I/O. Only the paired dispatcher commits observation,
// after the complete frame has been written successfully.
func (s *Supervisor) writeReply(w io.Writer, reply *pb.Envelope) error {
	if err := control.Write(w, reply); err != nil {
		return err
	}
	if status := reply.GetStatusReply(); status != nil {
		s.observeWrittenStatus(status)
	}
	return nil
}
