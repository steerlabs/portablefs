package authorityrpc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestTLSClockBlocksInitialAndCleanupDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	unavailable := errors.New("clock unavailable")
	c := &Client{cfg: ClientConfig{Address: listener.Addr().String(), DialTimeout: time.Second, AwaitTLS: func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return unavailable
	}}}
	for _, ctx := range []context.Context{t.Context(), context.WithoutCancel(t.Context())} {
		if _, err = c.dialTLS(ctx); !errors.Is(err, unavailable) {
			t.Fatal(err)
		}
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("TLS prerequisite was bypassed by dial")
	}
}
