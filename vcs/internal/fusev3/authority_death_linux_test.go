//go:build linux

package fusev3

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// Stop the authority after application and before delivery of one delegated
// WRITE. A timed kill alone does not reliably land in this replay interval.
type authorityDeathWriteHandler struct {
	authorityrpc.Handler
	entered chan struct{}
	once    sync.Once
}

func (h *authorityDeathWriteHandler) Handle(ctx context.Context, q *authoritypb.Request) *authoritypb.Response {
	r := h.Handler.Handle(ctx, q)
	if q.GetWrite() != nil {
		h.once.Do(func() { close(h.entered); <-ctx.Done() })
	}
	return r
}

func TestKernelAuthorityDeathSettlesAssignedWrite(t *testing.T) {
	const budget = time.Second
	var h *authorityDeathWriteHandler
	var listener *replayCutListener
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1, RequestTimeout: budget, SessionLease: 3 * time.Second, wrapListener: func(l net.Listener) net.Listener {
		listener = &replayCutListener{Listener: l}
		return listener
	}, beforeServe: func(f *integrationFixture) {
		h = &authorityDeathWriteHandler{Handler: f.counter.inner, entered: make(chan struct{})}
		f.counter.inner = h
	}})
	// Failure must also release the deliberately unresolved replay during cleanup.
	file := mustOpenFile(t, f.join(0, "assigned-write"), os.O_CREATE|os.O_RDWR, 0o600)
	defer func() { _ = f.clients[0].Close(); _ = file.Close() }()
	if _, err := file.WriteAt([]byte("accepted before authority death"), 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- file.Sync() }()
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("delegated WRITE never applied")
	}
	// Refuse reconnect before destroying DATA, so the held result cannot race
	// a successful exact replay on a replacement socket.
	listener.mu.Lock()
	data := listener.connections[0]
	listener.mu.Unlock()
	f.stopped = true
	_ = listener.Close()
	// Serve may already have closed DATA after observing the listener close.
	_ = data.Close()
	f.stopServe()
	if err := <-f.served; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fsync certified an undelivered WRITE after authority death")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary fsync retained its assigned WRITE beyond its request budget and session lease")
	}
}
