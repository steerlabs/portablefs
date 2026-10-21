package authorityrpc

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"io"
	"net"
	"testing"
	"time"
)

type cancelAttachHandler struct {
	clientTestHandler
	stage   string
	entered chan struct{}
	release chan struct{}
}

func (h *cancelAttachHandler) Handle(ctx context.Context, q *authoritypb.Request) *authoritypb.Response {
	if h.stage == "hello" && q.GetHello() != nil || h.stage == "attach" && q.GetAttach() != nil || h.stage == "activate" && q.GetActivate() != nil {
		close(h.entered)
		<-h.release
	}
	return h.clientTestHandler.Handle(ctx, q)
}
func TestAttachCancellationInterruptsNegotiationReads(t *testing.T) {
	for _, stage := range []string{"hello", "attach", "activate"} {
		t.Run(stage, func(t *testing.T) {
			h := &cancelAttachHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, stage: stage, entered: make(chan struct{}), release: make(chan struct{})}
			addr, tls, stop := startTestServer(t, h, 9, time.Minute)
			defer stop()
			defer close(h.release)
			cfg := coherentTestClientConfig(addr, tls, "volume", 9, 9)
			cfg.DialTimeout = 30 * time.Second
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				client, err := DialClient(ctx, cfg)
				if client != nil {
					client.Close()
				}
				done <- err
			}()
			select {
			case <-h.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("negotiation did not enter", stage)
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled attach succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("canceled negotiation waited for deadline", stage)
			}
		})
	}
}
func TestAttachContextCancellationAfterPublicationPreservesTransport(t *testing.T) {
	addr, tls, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, 9, time.Minute)
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := DialClient(ctx, coherentTestClientConfig(addr, tls, "volume", 9, 9))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cancel()
	if out, err := client.Call(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}); err != nil || out.GetErrno() != 0 {
		t.Fatal("attach context retained serving ownership", out, err)
	}
}

func TestCanceledNegotiationPublicationClosesUnpublishedTransport(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	role := authoritypb.TransportRole_TRANSPORT_ROLE_DATA
	opened := &transportNegotiation{conn: local, role: role, stopCancellation: func() error { return context.Canceled }}
	client := &Client{}
	if err := client.publishTransport(newClientTransport(role), opened, 1, 2); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("canceled publication leaked transport", err)
	}
}
func TestCanceledInitialPublicationJoinsBothNegotiations(t *testing.T) {
	data, dataPeer := net.Pipe()
	defer data.Close()
	defer dataPeer.Close()
	control, controlPeer := net.Pipe()
	defer control.Close()
	defer controlPeer.Close()
	stopped := 0
	a := &transportNegotiation{conn: data, role: authoritypb.TransportRole_TRANSPORT_ROLE_DATA, stopCancellation: func() error { stopped++; return context.Canceled }}
	b := &transportNegotiation{conn: control, role: authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, stopCancellation: func() error { stopped++; return context.Canceled }}
	client := &Client{}
	if err := client.publishInitialPair(a, b, 1, 1); !errors.Is(err, context.Canceled) || stopped != 2 {
		t.Fatal("committed cleanup could race a negotiation cancellation", err, stopped)
	}
}
