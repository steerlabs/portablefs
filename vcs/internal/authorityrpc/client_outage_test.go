package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestOrdinaryAssignedMutationHasFiniteOutage(t *testing.T) {
	for _, retained := range []bool{false, true} {
		name := "background"
		if retained {
			name = "retained-write-deadline"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, tlsConfig := testTLSConfigs(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			_ = listener.Close()
			data, peer := net.Pipe()
			defer peer.Close()
			client := newTerminalDrainTestClient(data, nil, 10*time.Millisecond)
			client.cfg.Address, client.cfg.TLS, client.cfg.DialTimeout = address, tlsConfig, time.Second
			client.cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX
			defer client.Close()
			go client.readLoop(client.data, data)
			ctx := t.Context()
			bound := volumeserver.SubscriptionTTL + time.Second
			if retained {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
				ctx = RetainMutationForSession(ctx, t.Context())
				bound = time.Second
			}
			done := make(chan error, 1)
			go func() {
				_, err := client.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{bytes.Repeat([]byte{1}, 16)}}}})
				done <- err
			}()
			// Consume the submitted frame, then lose the socket without an
			// outcome. Reconnect has a genuinely unbound listener throughout.
			if err := readFrame(peer, testMaxFrame, nil, 0, &authoritypb.Request{}); err != nil {
				t.Fatal(err)
			}
			_ = peer.Close()
			select {
			case err := <-done:
				if !errors.Is(err, ErrTransportUncertain) || !errors.Is(client.SessionEndCause(), ErrTransportUncertain) {
					t.Fatalf("unsettled submitted mutation: result=%v session=%v", err, client.SessionEndCause())
				}
				if !errors.Is(err, ErrSessionEnded) || !errors.Is(client.SessionEndCause(), ErrSessionEnded) || client.LocalAdmissionOpen() {
					t.Fatalf("abandoned replay kept a usable session: result=%v session=%v", err, client.SessionEndCause())
				}
				canceled, cancel := context.WithCancel(t.Context())
				cancel()
				if _, nextErr := client.CallMutation(canceled, settlementTestMkdir()); nextErr != err {
					t.Fatalf("subsequent call = %v, want first terminal cause %v", nextErr, err)
				}
				if len(client.ordinary.permits) != 0 {
					t.Fatal("ended replay retained its lane permit")
				}
			case <-time.After(bound):
				t.Fatal("ordinary mutation retried past its outage bound")
			}
		})
	}
}
