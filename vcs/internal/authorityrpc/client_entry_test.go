package authorityrpc

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestR3ReviewServingEntryGuards(t *testing.T) {
	read := func() *authoritypb.Request {
		return &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
	}
	force := func(error) {}
	entries := []struct {
		name string
		call func(context.Context, *Client) error
	}{
		{"one-shot", func(ctx context.Context, c *Client) error { _, err := c.Call(ctx, read()); return err }},
		{"reconnect", func(ctx context.Context, c *Client) error { return c.Reconnect(ctx) }},
		{"reauthorize", func(ctx context.Context, c *Client) error {
			_, err := c.Reauthorize(ctx, []byte("renewal"), 1)
			return err
		}},
		{"reauthorize-certificate", func(ctx context.Context, c *Client) error {
			_, err := c.ReauthorizeWithCertificate(ctx, []byte("renewal"), 1, nil, time.Now())
			return err
		}},
		{"read", func(ctx context.Context, c *Client) error { _, err := c.CallRead(ctx, read()); return err }},
		{"read-retained", func(ctx context.Context, c *Client) error {
			_, receipt, err := c.CallReadRetained(ctx, read(), force)
			if receipt != nil {
				receipt.Consume()
				t.Error("terminal call returned receipt")
			}
			return err
		}},
		{"idempotent", func(ctx context.Context, c *Client) error { _, err := c.CallIdempotent(ctx, read()); return err }},
		{"idempotent-retained", func(ctx context.Context, c *Client) error {
			_, receipt, err := c.CallIdempotentRetained(ctx, read(), force)
			if receipt != nil {
				receipt.Consume()
				t.Error("terminal call returned receipt")
			}
			return err
		}},
		{"mutation", func(ctx context.Context, c *Client) error {
			_, err := c.CallMutation(ctx, settlementTestMkdir())
			return err
		}},
		{"mutation-identity", func(ctx context.Context, c *Client) error {
			_, err := c.CallMutationWithIdentity(ctx, settlementTestMkdir(), func(MutationIdentity) error { t.Error("assigned after terminal"); return nil })
			return err
		}},
		{"mutation-retained", func(ctx context.Context, c *Client) error {
			_, receipt, err := c.CallMutationWithIdentityRetained(ctx, settlementTestMkdir(), nil, force)
			if receipt != nil {
				receipt.Consume()
				t.Error("terminal call returned receipt")
			}
			return err
		}},
		{"mutation-segments", func(ctx context.Context, c *Client) error {
			req := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: make([]byte, 16), Size: 1}}}
			_, err := c.CallMutationSegments(ctx, req, [][]byte{[]byte("x")}, nil)
			return err
		}},
		{"keepalive", func(ctx context.Context, c *Client) error { _, err := c.KeepAlive(ctx); return err }},
		{"local-publication", func(_ context.Context, c *Client) error {
			receipt, err := c.BeginLocalPublication(force)
			if receipt != nil {
				receipt.Consume()
				t.Error("terminal publication returned receipt")
			}
			return err
		}},
		{"reconnect-data", func(ctx context.Context, c *Client) error {
			return c.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
		}},
		{"reconnect-control", func(ctx context.Context, c *Client) error {
			return c.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
		}},
	}
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		for _, canceled := range []bool{false, true} {
			for _, entry := range entries {
				t.Run(fmt.Sprintf("%s/canceled=%t/%s", profile, canceled, entry.name), func(t *testing.T) {
					c := newTerminalDrainTestClient(nil, nil, time.Second)
					c.cfg.FrontendProfile = profile
					c.cfg.RequireLocalSessionEnforcement = true
					defer c.Close()
					cause := fmt.Errorf("%w: review cause identity", ErrTransportBinding)
					c.signalSessionEnd(cause)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					if canceled {
						cancel()
					}
					if err := entry.call(ctx, c); err != cause {
						t.Fatalf("got %v, want exact recorded cause %v", err, cause)
					}
					if c.SessionError() != nil || c.LocalAdmissionOpen() {
						t.Fatal("entry call changed enforcement/admission")
					}
					if c.data.nextID.Load() != 0 || c.control.nextID.Load() != 0 || c.ordinary.nextSlot.Load() != 0 {
						t.Fatal("entry call assigned an envelope/slot")
					}
				})
			}
		}
	}
}

func TestR3ReviewOneShotCallReportsTerminalCause(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		t.Run(profile.String(), func(t *testing.T) {
			c := newTerminalDrainTestClient(nil, nil, time.Second)
			c.cfg.FrontendProfile = profile
			defer c.Close()
			c.signalSessionEnd(ErrAuthorityChanged)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, err := c.Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}})
			if err != ErrAuthorityChanged {
				t.Fatalf("one-shot Call = %v, recorded cause = %v", err, c.SessionEndCause())
			}
		})
	}
}

func TestR3ReviewOneShotCallDoesNotDispatchAfterTerminal(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		t.Run(profile.String(), func(t *testing.T) {
			var calls atomic.Int32
			var c *Client
			var err error
			if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX {
				c, err = dialLinuxKeepAliveTestClient(t, func(*authoritypb.Response) { calls.Add(1) })
			} else {
				h := newFskitProofTestHandler()
				h.set(uint64(time.Second), func(*authoritypb.Response) { calls.Add(1) }, 0)
				c, err = dialFskitProofTestClient(t, h, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			id := c.control.nextID.Load()
			c.signalSessionEnd(ErrAuthorityChanged)
			request := &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}
			response, err := c.Call(t.Context(), request)
			if response != nil || err != ErrAuthorityChanged || calls.Load() != 0 {
				t.Fatalf("post-terminal one-shot Call = (%v, %v), handler_calls=%d, admission=%t, cause=%v", response, err, calls.Load(), c.LocalAdmissionOpen(), c.SessionEndCause())
			}
			if request.GetRequestId() != 0 || c.control.nextID.Load() != id {
				t.Fatal("ended call assigned an envelope")
			}
		})
	}
}

func TestAssignedMutationReportsTerminalBeforeCancellation(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		t.Run(profile.String(), func(t *testing.T) {
			c := newTerminalDrainTestClient(nil, nil, time.Second)
			c.cfg.FrontendProfile = profile
			defer c.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request := settlementTestMkdir()
			response, err := c.CallMutationWithIdentity(ctx, request, func(MutationIdentity) error {
				c.signalSessionEnd(ErrAuthorityChanged)
				cancel()
				return nil
			})
			if response != nil || err != ErrAuthorityChanged || request.GetRequestId() != 0 || c.ordinary.slots[0].sequence != 0 {
				t.Fatalf("terminal during assignment = (%v, %v), request=%v", response, err, request)
			}
		})
	}
}

func TestTerminalDetachPreservesExactAbsenceDelivery(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		t.Run(profile.String(), func(t *testing.T) {
			control, peer := net.Pipe()
			defer peer.Close()
			c := newTerminalDrainTestClient(nil, control, time.Second)
			c.cfg.FrontendProfile = profile
			defer c.Close()
			go c.readLoop(c.control, control)
			c.signalSessionEnd(ErrAuthorityChanged)
			proof := &authoritypb.MountAbsenceProof{Observation: []byte("exact-mount-attempt"), Component: "test-observer", ObservedUnixNanos: time.Now().UnixNano()}
			// Raw Call cannot use cleanup bodies as an admission escape.
			if _, err := c.Call(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{MountAbsence: proof}}}); err != ErrAuthorityChanged {
				t.Fatalf("raw terminal Detach = %v", err)
			}
			if err := c.DetachAfterUnmount(t.Context(), nil); err != ErrAuthorityChanged {
				t.Fatalf("evidence-free terminal Detach = %v", err)
			}
			done := make(chan error, 1)
			go func() { done <- c.DetachAfterUnmount(t.Context(), proof) }()
			if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			request := new(authoritypb.Request)
			if err := readFrame(peer, testMaxFrame, nil, 0, request); err != nil {
				t.Fatal(err)
			}
			sent := request.GetDetach().GetMountAbsence()
			if sent.GetComponent() != proof.GetComponent() || string(sent.GetObservation()) != string(proof.GetObservation()) || sent.GetObservedUnixNanos() != proof.GetObservedUnixNanos() {
				t.Fatalf("terminal Detach carried %v, want %v", sent, proof)
			}
			if err := writeFrame(peer, testMaxFrame, &authoritypb.Response{RequestId: request.GetRequestId(), Epoch: c.Epoch()}); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("exact terminal Detach = %v", err)
			}
			if c.LocalAdmissionOpen() || c.SessionEndCause() != ErrAuthorityChanged {
				t.Fatal("cleanup changed the terminal verdict")
			}
		})
	}
}
