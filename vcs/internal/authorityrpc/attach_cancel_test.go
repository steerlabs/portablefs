package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type cancelAttachHandler struct {
	clientTestHandler
	once        sync.Once
	stage       string
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func (h *cancelAttachHandler) Handle(ctx context.Context, q *authoritypb.Request) *authoritypb.Response {
	if h.stage == "activate" && q.GetHello() != nil {
		select {
		case <-h.entered:
			h.releaseOnce.Do(func() { close(h.release) })
		default:
		}
	}
	if h.stage == "hello" && q.GetHello() != nil || h.stage == "attach" && q.GetAttach() != nil || h.stage == "activate" && q.GetActivate() != nil {
		first := false
		h.once.Do(func() { first = true; close(h.entered) })
		if first {
			<-h.release
		}
	}
	return h.clientTestHandler.Handle(ctx, q)
}
func TestAttachCancellationInterruptsNegotiationReads(t *testing.T) {
	for _, stage := range []string{"hello", "attach", "activate"} {
		t.Run(stage, func(t *testing.T) {
			h := &cancelAttachHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, stage: stage, entered: make(chan struct{}), release: make(chan struct{})}
			addr, tls, stop := startTestServer(t, h, 9, time.Minute)
			defer stop()
			defer h.releaseOnce.Do(func() { close(h.release) })
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

// Cancellation is deliberately fired after Detach installs its independent
// deadline. Only joining both startup writers at the common ACTIVE boundary
// can prevent their overwrite on the local-validation failure path.
type cleanupDeadlineConn struct {
	net.Conn
	cancel    context.CancelFunc
	settled   <-chan struct{}
	joined    *atomic.Int32
	installed chan struct{}
}

func (c *cleanupDeadlineConn) SetDeadline(deadline time.Time) error {
	err := c.Conn.SetDeadline(deadline)
	if !deadline.IsZero() && deadline.After(time.Now()) {
		c.cancel()
		<-c.settled
		close(c.installed)
	}
	return err
}
func TestInvalidActiveCleanupJoinsStartupCancellation(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settled := make(chan struct{})
	var joined atomic.Int32
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { local.SetDeadline(time.Now()); close(interrupted); close(settled) })
	stopCancellation := func() error {
		if stop() {
			joined.Add(1)
			close(interrupted)
			close(settled)
		}
		<-interrupted
		return ctx.Err()
	}
	conn := &cleanupDeadlineConn{Conn: local, cancel: cancel, settled: settled, joined: &joined, installed: make(chan struct{})}
	epoch := bytes.Repeat([]byte{0x76}, 16)
	proof := &authoritypb.SessionProof{Id: bytes.Repeat([]byte{0x77}, 16), Generation: 4, ResumeSecret: bytes.Repeat([]byte{0x78}, 32)}
	client := &Client{cfg: ClientConfig{CancelDrainTimeout: time.Second, ObservePreKernelMountAbsence: testPreKernelMountAbsence}, epoch: epoch, proof: proof}
	var dataJoined atomic.Bool
	data := &transportNegotiation{stopCancellation: func() error { dataJoined.Store(true); return nil }}
	control := &transportNegotiation{conn: conn, maxFrame: testMaxFrame, stopCancellation: stopCancellation}
	result := make(chan error, 1)
	go func() {
		<-conn.installed
		q := new(authoritypb.Request)
		if err := readFrame(peer, testMaxFrame, nil, 0, q); err != nil {
			result <- err
			return
		}
		if q.GetDetach() == nil || q.GetDetach().GetMountAbsence() == nil {
			result <- errors.New("missing exact Detach")
			return
		}
		result <- writeFrame(peer, testMaxFrame, &authoritypb.Response{RequestId: q.RequestId, Epoch: epoch})
	}()
	err := client.publishCommittedActivation(context.Background(), &authoritypb.ActivateReply{State: authoritypb.SessionState_SESSION_STATE_PROVISIONAL}, data, control, 1, 1, 19)
	if err == nil || strings.Contains(err.Error(), "release ACTIVE session") {
		t.Fatal("independent cleanup failed", err)
	}
	if joined.Load() != 1 || !dataJoined.Load() {
		t.Fatal("committed cleanup preceded cancellation join")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
