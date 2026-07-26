package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
)

func TestServeShutsDownOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, memfs.New()) }()

	time.Sleep(50 * time.Millisecond) // let it start accepting
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil on clean shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not shut down within 2s of context cancel")
	}
}
