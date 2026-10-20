package authorityrpc

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// readBoundaryConn puts shutdown on either side of the first session read
// deadline, after the complete Hello response has been consumed.
type readBoundaryConn struct {
	net.Conn
	beforeDeadline bool
	atBoundary     func() error
	deadlineCalls  int
}

func (c *readBoundaryConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineCalls++
	if c.deadlineCalls == 2 && c.beforeDeadline {
		if err := c.atBoundary(); err != nil {
			return err
		}
	}
	err := c.Conn.SetReadDeadline(deadline)
	if c.deadlineCalls == 2 && !c.beforeDeadline {
		if err := c.atBoundary(); err != nil {
			return err
		}
	}
	return err
}

func TestServerSessionReadShutdown(t *testing.T) {
	for _, test := range []struct {
		name           string
		beforeDeadline bool
		closePeer      bool
		wantErr        error
	}{
		{name: "peer before deadline", beforeDeadline: true, closePeer: true},
		{name: "peer before frame", closePeer: true},
		{name: "local before deadline", beforeDeadline: true},
		{name: "local before frame"},
		{name: "deadline timeout", beforeDeadline: true, wantErr: os.ErrDeadlineExceeded},
		{name: "deadline failure", beforeDeadline: true, wantErr: errors.New("read deadline failure")},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &Server{
				Handler: echoHandler{epoch: []byte("epoch")}, MaxFrame: 4096, MaxInFlight: 9, MaxConnections: 4,
				MaxFrameBytesInFlight: controlFrameReserve() + 1<<20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second,
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			conn := &readBoundaryConn{Conn: server, beforeDeadline: test.beforeDeadline, atBoundary: func() error {
				if test.wantErr != nil {
					return test.wantErr
				}
				if test.closePeer {
					return client.Close()
				}
				return server.Close()
			}}
			done := testServeSession(t, s, conn)
			if err := writeFrame(client, 4096, &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{
				ProtocolMajor: ProtocolMajor, Role: authoritypb.TransportRole_TRANSPORT_ROLE_DATA, ConnectionSetId: bytes.Repeat([]byte{7}, 32),
			}}}); err != nil {
				t.Fatal(err)
			}
			var response authoritypb.Response
			if err := readFrame(client, 4096, nil, 0, &response); err != nil {
				t.Fatal(err)
			}
			if response.GetHello() == nil {
				t.Fatalf("Hello response = %v", &response)
			}
			if err := <-done; !errors.Is(err, test.wantErr) {
				t.Fatalf("session shutdown = %v, want %v", err, test.wantErr)
			}
		})
	}
}
