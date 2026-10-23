package authorityrpc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type opusReconnectFailHandler struct {
	clientTestHandler
	failResumeUntil atomic.Int64
	resumes         atomic.Int32
}

func (h *opusReconnectFailHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	if r.GetResume() != nil && time.Now().UnixNano() < h.failResumeUntil.Load() {
		h.resumes.Add(1)
		entry, _ := transportConnectionFromContext(ctx)
		_ = entry.close()
	}
	return h.clientTestHandler.Handle(ctx, r)
}

// How long can a session-owned request that is re-establishing a broken DATA
// connection (every Resume attempt failing, as during a network loss at lid
// close) delay a lifecycle Park?
func TestOpusParkLatencyDuringFailingReconnect(t *testing.T) {
	h := &opusReconnectFailHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}}
	address, tls, stop := startTestServer(t, h, testMaxInFlight, time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, tls, "volume", 9, 9)
	cfg.DispatchFence = NewDispatchFence()
	if err := cfg.DispatchFence.Resume(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	c, err := DialClient(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h.failResumeUntil.Store(time.Now().Add(time.Minute).UnixNano())
	c.data.pendingMu.Lock()
	conn := c.data.conn
	c.data.pendingMu.Unlock()
	c.failConnection(c.data, conn, ErrTransportUncertain)
	callCtx, cancelCall := context.WithCancel(t.Context())
	defer cancelCall()
	done := make(chan error, 1)
	go func() {
		_, err := c.CallIdempotent(callCtx, &authoritypb.Request{Body: &authoritypb.Request_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityRequest{CutSequence: 1}}})
		done <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for h.resumes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.resumes.Load() < 2 {
		t.Fatal("reconnect did not retry failed Resume")
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	err = c.ParkDispatch(ctx)
	elapsed := time.Since(start)
	t.Logf("ParkDispatch returned after %v err=%v (failed Resume attempts so far %d, DialTimeout %v)", elapsed.Round(10*time.Millisecond), err, h.resumes.Load(), cfg.DialTimeout)
	if elapsed > 250*time.Millisecond {
		t.Errorf("one failing reconnect held Park for %v", elapsed.Round(10*time.Millisecond))
	}
	cancelCall()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Error("reconnecting call did not observe cancellation")
	}
}
