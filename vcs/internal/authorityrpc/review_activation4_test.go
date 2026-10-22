package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// The authority commits ACTIVE (strict membership) and its response is delayed.
type commitThenStallHandler struct {
	clientTestHandler
	committed        atomic.Bool
	detaches, aborts atomic.Int32
	resumes          atomic.Int32
	entered          chan struct{}
	release          chan struct{}
	mu               sync.Mutex
	attempt          []byte
	session          []byte
	absence          bool
	holdAll          bool
	releaseOnce      sync.Once
	recoveryHellos   atomic.Int32
}

func (h *commitThenStallHandler) Handle(ctx context.Context, q *authoritypb.Request) *authoritypb.Response {
	switch {
	case q.GetHello() != nil && h.committed.Load():
		h.recoveryHellos.Add(1)
		if !h.holdAll {
			h.releaseOnce.Do(func() { close(h.release) })
		}
	case q.GetActivate() != nil:
		out := h.clientTestHandler.Handle(ctx, q)
		first := !h.committed.Swap(true)
		h.mu.Lock()
		if first {
			h.attempt = append([]byte(nil), q.GetActivate().GetAttachAttemptId()...)
			h.session = append([]byte(nil), q.GetSession().GetId()...)
		} else if !bytes.Equal(h.attempt, q.GetActivate().GetAttachAttemptId()) || !bytes.Equal(h.session, q.GetSession().GetId()) {
			panic("activation recovery changed its owner")
		}
		h.mu.Unlock()
		if first {
			close(h.entered)
		}
		if first || h.holdAll {
			<-h.release
		}
		return out
	case q.GetDetach() != nil:
		h.mu.Lock()
		h.absence = completeMountAbsenceProof(q.GetDetach().GetMountAbsence()) && bytes.Equal(h.session, q.GetSession().GetId())
		h.mu.Unlock()
		h.detaches.Add(1)
		return &authoritypb.Response{RequestId: q.GetRequestId(), Epoch: h.Epoch()}
	case q.GetAbortAttach() != nil:
		h.aborts.Add(1)
	case q.GetResume() != nil:
		h.resumes.Add(1)
	}
	return h.clientTestHandler.Handle(ctx, q)
}

func TestR3CancelAfterActivateCommitAbandonsSession(t *testing.T) {
	for _, mode := range []string{"signal-cancel", "dial-timeout", "unreconciled"} {
		t.Run(mode, func(t *testing.T) {
			h := &commitThenStallHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, entered: make(chan struct{}), release: make(chan struct{})}
			addr, tls, stop := startTestServer(t, h, 9, time.Minute)
			defer stop()
			defer h.releaseOnce.Do(func() { close(h.release) })
			cfg := coherentTestClientConfig(addr, tls, "volume", 9, 9)
			h.holdAll = mode == "unreconciled"
			cfg.DialTimeout = 30 * time.Second
			cfg.CancelDrainTimeout = 500 * time.Millisecond
			if mode == "dial-timeout" {
				cfg.DialTimeout = 400 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			started := time.Now()
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
				t.Fatal("activate not reached")
			}
			if mode != "dial-timeout" {
				cancel()
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("dial did not return")
			}
			if err == nil || h.aborts.Load() != 0 || h.recoveryHellos.Load() == 0 {
				t.Fatalf("activation owner lost: %v resumes=%d aborts=%d", err, h.resumes.Load(), h.aborts.Load())
			}
			if mode == "unreconciled" {
				if !errors.Is(err, ErrTransportUncertain) || h.detaches.Load() != 0 {
					t.Fatalf("missing explicit uncertainty: %v detaches=%d", err, h.detaches.Load())
				}
			} else {
				h.mu.Lock()
				exact := h.absence
				h.mu.Unlock()
				if h.detaches.Load() != 1 || h.resumes.Load() != 2 || !exact {
					t.Fatalf("committed activation not released exactly: detaches=%d exact=%v err=%v", h.detaches.Load(), exact, err)
				}
			}
			t.Logf("REPRO %s: DialClient err=%v after %v; authority committed=%v; activation-recovery resumes=%d detaches=%d aborts=%d",
				mode, err, time.Since(started).Round(time.Millisecond), h.committed.Load(), h.resumes.Load(), h.detaches.Load(), h.aborts.Load())
		})
	}
}
