package authorityrpc

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type separateAckHandler struct {
	coherenceV2ClientHandler
	change           bool
	started, proceed chan struct{}
}

func (h *separateAckHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	if h.change && r.GetChangeAck() != nil || !h.change && r.GetDelegationBreakAck() != nil {
		close(h.started)
		select {
		case <-h.proceed:
		case <-ctx.Done():
		}
	}
	return h.coherenceV2ClientHandler.Handle(ctx, r)
}
func TestChangeAndDelegationAcknowledgmentsHaveIndependentPermits(t *testing.T) {
	for _, change := range []bool{false, true} {
		name := "delegation-blocked"
		if change {
			name = "change-blocked"
		}
		t.Run(name, func(t *testing.T) {
			h := &separateAckHandler{coherenceV2ClientHandler: coherenceV2ClientHandler{clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{1}, 16), maxInFlight: 6}}, change: change, started: make(chan struct{}), proceed: make(chan struct{})}
			address, tlsConfig, stop := startTestServer(t, h, 6, time.Minute)
			defer stop()
			client, err := DialClient(t.Context(), coherentTestClientConfig(address, tlsConfig, "volume", 6, 6))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			defer close(h.proceed)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			call := func(ctx context.Context, isChange bool) error {
				if isChange {
					return client.AcknowledgeChanges(ctx, 7, 1)
				}
				return client.AcknowledgeDelegationBreak(ctx, 7, 1, &authoritypb.DelegationRef{Id: bytes.Repeat([]byte{2}, 16), Generation: 1}, 0)
			}
			done := make(chan error, 1)
			go func() { done <- call(ctx, change) }()
			select {
			case <-h.started:
			case err := <-done:
				t.Fatalf("ack never parked: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			independent, budget := context.WithTimeout(ctx, 200*time.Millisecond)
			defer budget()
			if err := call(independent, !change); err != nil {
				t.Fatalf("independent acknowledgment blocked: %v", err)
			}
		})
	}
}
