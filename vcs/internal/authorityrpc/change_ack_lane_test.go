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
			h := &separateAckHandler{coherenceV2ClientHandler: coherenceV2ClientHandler{clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{1}, 16), maxInFlight: 9}}, change: change, started: make(chan struct{}), proceed: make(chan struct{})}
			address, tlsConfig, stop := startTestServer(t, h, 9, time.Minute)
			defer stop()
			client, err := DialClient(t.Context(), coherentTestClientConfig(address, tlsConfig, "volume", 9, 9))
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

type minimumControlCapacityHandler struct {
	coherenceV2ClientHandler
	entered chan struct{}
	release chan struct{}
}

func (h *minimumControlCapacityHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	if request.GetChangeAck() != nil || request.GetDelegationBreakAck() != nil {
		h.entered <- struct{}{}
		select {
		case <-h.release:
		case <-ctx.Done():
		}
	}
	return h.coherenceV2ClientHandler.Handle(ctx, request)
}

func TestMinimumLinuxCapacityKeepsControlLivenessIndependentOfBothAcknowledgments(t *testing.T) {
	handler := &minimumControlCapacityHandler{
		coherenceV2ClientHandler: coherenceV2ClientHandler{clientTestHandler: clientTestHandler{epoch: bytes.Repeat([]byte{1}, 16), maxInFlight: 9}},
		entered:                  make(chan struct{}, 2), release: make(chan struct{}),
	}
	address, tlsConfig, stop := startTestServer(t, handler, 9, time.Minute)
	defer stop()
	client, err := DialClient(t.Context(), coherentTestClientConfig(address, tlsConfig, "volume", 9, 9))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- client.AcknowledgeChanges(ctx, 7, 1) }()
	go func() {
		done <- client.AcknowledgeDelegationBreak(ctx, 7, 1, &authoritypb.DelegationRef{Id: bytes.Repeat([]byte{2}, 16), Generation: 1}, 0)
	}()
	defer func() {
		close(handler.release)
		for range 2 {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}()
	for range 2 {
		select {
		case <-handler.entered:
		case <-ctx.Done():
			t.Fatal("CONTROL could not admit both acknowledgment classes")
		}
	}
	if _, err := client.KeepAlive(ctx); err != nil {
		t.Fatalf("KeepAlive blocked behind acknowledgments: %v", err)
	}
	if _, err := client.RenewSubscription(ctx, 7); err != nil {
		t.Fatalf("subscription renewal blocked behind acknowledgments: %v", err)
	}
}
