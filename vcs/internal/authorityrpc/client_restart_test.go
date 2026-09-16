package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// Keep the port genuinely unbound between listeners: an immediate replacement
// misses the ECONNREFUSED window that used to end a healthy mount permanently.
func TestReconnectSurvivesListenerGapBeforeEpochVerdict(t *testing.T) {
	for _, change := range []bool{false, true} {
		name := "same_epoch"
		if change {
			name = "new_epoch"
		}
		t.Run(name, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			epoch := bytes.Repeat([]byte{1}, 16)
			var server *Server
			serve := func(listener net.Listener, epoch []byte) func() {
				ctx, cancel := context.WithCancel(context.Background())
				if server == nil || change {
					server = &Server{Handler: clientTestHandler{epoch: epoch, maxInFlight: 5}, MaxFrame: testMaxFrame, MaxInFlight: 5, MaxConnections: 8, MaxFrameBytesInFlight: 8 << 20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
				}
				done := make(chan error, 1)
				go func() { done <- server.Serve(ctx, listener, serverTLS) }()
				return func() {
					cancel()
					if err := <-done; err != nil {
						t.Errorf("serve: %v", err)
					}
				}
			}
			stop := serve(listener, epoch)
			client, err := DialClient(context.Background(), coherentTestClientConfig(address, clientTLS, "volume", 5, 5))
			if err != nil {
				stop()
				t.Fatal(err)
			}
			defer client.Close()
			// Force the DATA edge explicitly; CONTROL remains unused by this client.
			client.data.pendingMu.Lock()
			conn := client.data.conn
			client.data.pendingMu.Unlock()
			client.failConnection(client.data, conn, ErrTransportUncertain)
			stop()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- client.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_DATA) }()
			select {
			case err := <-result:
				t.Fatalf("reconnect ended during listener gap: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			if change {
				epoch = bytes.Repeat([]byte{2}, 16)
			}
			listener, err = net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			stop = serve(listener, epoch)
			defer stop()
			err = <-result
			if change {
				if !errors.Is(err, ErrAuthorityChanged) || !errors.Is(client.SessionEndCause(), ErrAuthorityChanged) {
					t.Fatalf("epoch verdict: call=%v cause=%v", err, client.SessionEndCause())
				}
			} else if err != nil || client.SessionEndCause() != nil {
				t.Fatalf("same epoch: call=%v cause=%v", err, client.SessionEndCause())
			}
		})
	}
}

func TestReconnectUnavailableListenerHonorsCallerDeadline(t *testing.T) {
	address, tls, stop := startTestServer(t, clientTestHandler{epoch: make([]byte, 16), maxInFlight: 5}, 5, time.Minute)
	client, err := DialClient(context.Background(), coherentTestClientConfig(address, tls, "volume", 5, 5))
	if err != nil {
		stop()
		t.Fatal(err)
	}
	defer client.Close()
	client.data.pendingMu.Lock()
	conn := client.data.conn
	client.data.pendingMu.Unlock()
	client.failConnection(client.data, conn, ErrTransportUncertain)
	stop()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := client.reconnectTransport(ctx, authoritypb.TransportRole_TRANSPORT_ROLE_DATA); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
}
