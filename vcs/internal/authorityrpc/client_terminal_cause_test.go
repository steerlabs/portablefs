package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestReconnectEndedSessionPrecedesCallerCancellation(t *testing.T) {
	for _, role := range []authoritypb.TransportRole{
		authoritypb.TransportRole_TRANSPORT_ROLE_DATA,
		authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL,
	} {
		for _, closed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/closed=%t", role, closed), func(t *testing.T) {
				client := newTerminalDrainTestClient(nil, nil, time.Second)
				defer client.Close()
				cause := ErrAuthorityChanged
				if closed {
					client.Close()
					cause = net.ErrClosed
				} else {
					client.signalSessionEnd(cause)
				}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if err := client.reconnectTransport(ctx, role); !errors.Is(err, cause) {
					t.Fatalf("ended session reconnect = %v, want %v", err, cause)
				}
			})
		}
	}
}

func TestInterruptedIdempotentReportsSessionEndCause(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{
		authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX,
		authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE,
		authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER,
	} {
		for _, role := range []authoritypb.TransportRole{
			authoritypb.TransportRole_TRANSPORT_ROLE_DATA,
			authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL,
		} {
			t.Run(fmt.Sprintf("%s/%s", profile, role), func(t *testing.T) {
				local, peer := net.Pipe()
				defer peer.Close()
				client := newTerminalDrainTestClient(nil, nil, time.Second)
				client.cfg.FrontendProfile = profile
				defer client.Close()
				transport := client.transportForRole(role)
				transport.conn = local
				request := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}}}
				if role == authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL {
					request.Body = &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}
				}
				done := make(chan error, 1)
				go func() {
					_, err := client.CallRead(t.Context(), request)
					done <- err
				}()
				if err := readFrame(peer, testMaxFrame, nil, 0, new(authoritypb.Request)); err != nil {
					t.Fatal(err)
				}
				client.signalSessionEnd(ErrAuthorityChanged)
				client.failConnection(transport, local, ErrTransportUncertain)
				if err := <-done; !errors.Is(err, ErrAuthorityChanged) {
					t.Fatalf("interrupted read = %v, want the recorded authority change", err)
				}
			})
		}
	}
}

func TestLinuxCanceledMutationReportsSessionEndCause(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	client := newTerminalDrainTestClient(local, nil, 10*time.Millisecond)
	client.cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{
			Parent: make([]byte, 16), Name: []byte("x"), Mode: 0o755,
		}}})
		done <- err
	}()
	if err := readFrame(peer, testMaxFrame, nil, 0, new(authoritypb.Request)); err != nil {
		t.Fatal(err)
	}
	client.signalSessionEnd(ErrAuthorityChanged)
	cancel()
	cancelRequest := new(authoritypb.Request)
	if err := readFrame(peer, testMaxFrame, nil, 0, cancelRequest); err != nil || cancelRequest.GetCancel() == nil {
		t.Fatalf("cancellation frame = (%v, %v)", cancelRequest, err)
	}
	// No reply settles the mutation. Once its cancel-drain expires, the
	// recorded epoch change must classify it just like an uncanceled sibling.
	if err := <-done; !errors.Is(err, ErrAuthorityChanged) {
		t.Fatalf("canceled mutation = %v, want the recorded authority change", err)
	}
	if client.LocalAdmissionOpen() || !errors.Is(client.SessionEndCause(), ErrAuthorityChanged) {
		t.Fatalf("canceled mutation changed terminal state: admission=%t cause=%v", client.LocalAdmissionOpen(), client.SessionEndCause())
	}
}
