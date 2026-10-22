package authorityrpc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestLifecycleRetryOutlivesSocketBudget(t *testing.T) {
	for _, phase := range []string{"Prepare", "Recover"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				sessionUntil := start.Add(2 * time.Minute)
				calls := 0
				err := RetryLifecycle(context.Background(), 2*time.Second, func(ctx context.Context) error {
					calls++
					if deadline, _ := ctx.Deadline(); deadline.After(time.Now().Add(2 * time.Second)) {
						t.Fatal("unbounded attempt")
					}
					if time.Since(start) < 46*time.Second {
						return &net.DNSError{Err: "temporary transport outage", IsTemporary: true}
					}
					if !time.Now().Before(sessionUntil) {
						t.Fatal("session expired")
					}
					return nil
				})
				if err != nil || time.Since(start) < 46*time.Second || calls < 2 {
					t.Fatal("logical recovery ended at socket deadline", err, calls, time.Since(start))
				}
			})
		})
	}
}
func TestLifecycleRetryClassifiesEvidence(t *testing.T) {
	for _, tc := range []struct {
		err   error
		retry bool
	}{{ErrSessionEnded, false}, {ErrAuthorityChanged, false}, {ErrTransportBinding, false}, {ErrReplayDesynchronized, false}, {ErrFrameEncoding, false}, {io.EOF, true}, {context.DeadlineExceeded, true}, {&net.DNSError{Err: "DNS unavailable"}, true}, {errors.New("local persistence failure"), false}} {
		if got := TransientTransport(tc.err); got != tc.retry {
			t.Errorf("%v retry=%t", tc.err, got)
		}
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		err := RetryLifecycle(ctx, time.Second, func(context.Context) error {
			calls++
			if calls == 60 {
				cancel()
			}
			return io.EOF
		})
		if !errors.Is(err, context.Canceled) || calls != 60 {
			t.Fatal(err, calls)
		}
	})
}
func TestDispatchFenceRetainsAssignedOwners(t *testing.T) {
	for _, kind := range []string{"write", "close", "barrier", "reclaim"} {
		t.Run(kind, func(t *testing.T) {
			f := NewDispatchFence()
			if err := f.Resume(func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			r := &authoritypb.Request{Mutation: &authoritypb.Mutation{Slot: 3, Sequence: 8}}
			switch kind {
			case "write":
				r.Body = &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Data: []byte("accepted")}}
			case "close":
				r.Body = &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{}}
			case "barrier":
				r.Body = &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{CutSequence: 17}}
			case "reclaim":
				r.Body = &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{[]byte("capability")}}}
			}
			release, err := f.own(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			before := f.Snapshot().Owners[0]
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err = f.Park(ctx)
			if kind == "write" {
				if !errors.Is(err, context.Canceled) || f.Snapshot().Parked {
					t.Fatal("applying write hidden as cleanup", err)
				}
				if err = f.Resume(func() error { return nil }); err == nil {
					t.Fatal("Resume bypassed unresolved Park")
				}
				release()
				if err = f.Park(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else {
				if err != nil || !f.Snapshot().Parked {
					t.Fatal(err)
				}
				after := f.Snapshot().Owners[0]
				if string(before.Body) != string(after.Body) || before.Identity != after.Identity {
					t.Fatal("park replaced exact request")
				}
				release()
			}
			if len(f.Snapshot().Owners) != 0 {
				t.Fatal("resolved owner leaked")
			}
		})
	}
}
func TestDispatchFenceJoinsIOAndRejectsStaleClock(t *testing.T) {
	f := NewDispatchFence()
	var allowed atomic.Bool
	allowed.Store(true)
	check := func() error {
		if !allowed.Load() {
			return ErrSessionEnded
		}
		return nil
	}
	if err := f.Resume(check); err != nil {
		t.Fatal(err)
	}
	release, err := f.begin(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = f.Park(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("unjoined wire owner acknowledged", err)
	}
	if f.Snapshot().InFlightIO != 1 {
		t.Fatal("cancelled waiter erased wire owner")
	}
	release()
	if err = f.Park(context.Background()); err != nil {
		t.Fatal(err)
	}
	allowed.Store(false)
	if err = f.Resume(check); err == nil {
		t.Fatal("stale clock released dispatch")
	}
}

// Real TLS, runtime replay and an assigned non-applying request cross Park.
// Losing its response cannot turn the parked owner into terminal cancellation.
func TestLifecycleParkedCleanupReplaysSameIdentityAtWake(t *testing.T) {
	for _, kind := range []string{"close", "reclaim", "barrier"} {
		t.Run(kind, func(t *testing.T) {
			runtime, err := volumeserver.New("workspace-replay", volumeserver.Config{ContinuousNow: func() (time.Duration, error) { return 0, nil }, SessionLease: 2 * time.Minute, MaxReplaySlots: 9, MaxSessions: 4, MaxLockRecords: 16})
			if err != nil {
				t.Fatal(err)
			}
			handler := &replayHandler{runtime: runtime, access: volumeserver.AccessRead | volumeserver.AccessWrite, afterExecution: make(chan struct{}), releaseFirst: make(chan struct{})}
			address, tls, stop := startTestServer(t, handler, testMaxInFlight, time.Minute)
			defer stop()
			cfg := coherentTestClientConfig(address, tls, "workspace-replay", 9, 9)
			cfg.DispatchFence = NewDispatchFence()
			if err = cfg.DispatchFence.Resume(func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			client, err := DialClient(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			request := &authoritypb.Request{}
			switch kind {
			case "close":
				request.Body = &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{Closes: []*authoritypb.CloseRequest{{Handle: make([]byte, 16)}}}}
			case "reclaim":
				request.Body = &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{make([]byte, 16)}}}
			case "barrier":
				request.Body = &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{CutSequence: 7}}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := client.CallMutation(ctx, request); done <- err }()
			select {
			case <-handler.afterExecution:
			case <-time.After(2 * time.Second):
				t.Fatal("cleanup never assigned/applied")
			}
			if err = client.ParkDispatch(t.Context()); err != nil {
				t.Fatal(err)
			}
			before := client.DispatchSnapshot()
			if len(before.Owners) != 1 || before.Owners[0].Applying {
				t.Fatal("lost cleanup ownership", before)
			}
			client.data.pendingMu.Lock()
			conn := client.data.conn
			client.data.pendingMu.Unlock()
			client.failConnection(client.data, conn, ErrTransportUncertain)
			// The logical owner is still present after wire loss and has no terminal
			// verdict. Resume releases the same replay, never a new mutation call.
			if client.SessionEndCause() != nil {
				t.Fatal(client.SessionEndCause())
			}
			close(handler.releaseFirst)
			after := client.DispatchSnapshot()
			if len(after.Owners) != 1 || string(before.Owners[0].Body) != string(after.Owners[0].Body) || before.Owners[0].Identity != after.Owners[0].Identity {
				t.Fatal("park changed body or replay identity", before, after)
			}
			if err = client.ResumeDispatch(func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("wake stranded replay")
			}
			if handler.applyCalls.Load() != 1 || handler.mutationCalls.Load() != 2 || len(client.DispatchSnapshot().Owners) != 0 {
				t.Fatal("wake duplicated application or leaked owner", handler.applyCalls.Load(), handler.mutationCalls.Load())
			}
		})
	}
}

type lifecycleVisibilityHandler struct {
	clientTestHandler
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	ready   sync.Once
}

func (h *lifecycleVisibilityHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	if wait := r.GetWaitVisibility(); wait != nil {
		h.calls.Add(1)
		h.ready.Do(func() { close(h.started) })
		select {
		case <-h.release:
		case <-ctx.Done():
		}
		cut := wait.GetCutSequence()
		return &authoritypb.Response{RequestId: r.GetRequestId(), Epoch: h.Epoch(), VisibleSequence: cut, Body: &authoritypb.Response_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityReply{AppliedSequence: cut, VisibleSequence: cut}}}
	}
	return h.clientTestHandler.Handle(ctx, r)
}
func TestLifecycleParkedVisibilityRetainsImmutableCut(t *testing.T) {
	h := &lifecycleVisibilityHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, started: make(chan struct{}), release: make(chan struct{})}
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
	result := make(chan error, 1)
	go func() {
		r, err := c.CallIdempotent(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityRequest{CutSequence: 23}}})
		if err == nil && r.GetWaitVisibility().GetVisibleSequence() != 23 {
			err = errors.New("visibility cut changed")
		}
		result <- err
	}()
	select {
	case <-h.started:
	case <-time.After(time.Second):
		t.Fatal("visibility owner never dispatched")
	}
	if err = c.ParkDispatch(t.Context()); err != nil {
		t.Fatal(err)
	}
	old := c.DispatchSnapshot()
	if len(old.Owners) != 1 || old.Owners[0].Applying {
		t.Fatal("visibility owner not retained", old)
	}
	c.data.pendingMu.Lock()
	conn := c.data.conn
	c.data.pendingMu.Unlock()
	c.failConnection(c.data, conn, ErrTransportUncertain)
	now := c.DispatchSnapshot()
	if len(now.Owners) != 1 || string(now.Owners[0].Body) != string(old.Owners[0].Body) {
		t.Fatal("park lost immutable visibility request")
	}
	close(h.release)
	if err = c.ResumeDispatch(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("visibility did not retry at wake")
	}
	if h.calls.Load() != 2 || c.SessionEndCause() != nil || len(c.DispatchSnapshot().Owners) != 0 {
		t.Fatal("visibility retry changed session or leaked owner", h.calls.Load(), c.SessionEndCause())
	}
}

type lifecycleActivationOutageHandler struct {
	attachActivationRecoveryHandler
	until atomic.Int64
}

func (h *lifecycleActivationOutageHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	if r.GetResume() != nil && time.Now().UnixNano() < h.until.Load() {
		entry, _ := transportConnectionFromContext(ctx)
		_ = entry.close()
		return h.clientTestHandler.Handle(ctx, r)
	}
	if r.GetActivate() != nil {
		h.until.CompareAndSwap(0, time.Now().Add(46*time.Second).UnixNano())
		response := h.attachActivationRecoveryHandler.Handle(ctx, r)
		if response.GetActivate() != nil {
			response.GetActivate().SessionLeaseMilliseconds = 120_000
		}
		return response
	}
	return h.attachActivationRecoveryHandler.Handle(ctx, r)
}
func TestLifecycleInitialActivationOutageRetainsAttachOwner(t *testing.T) {
	h := &lifecycleActivationOutageHandler{attachActivationRecoveryHandler: attachActivationRecoveryHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, closeFirstActivate: true}}
	address, tls, stop := startTestServer(t, h, 9, 2*time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, tls, "volume", 9, 9)
	cfg.DialTimeout = 2 * time.Second
	cfg.LifecycleRetry = true
	cfg.DispatchFence = NewDispatchFence()
	if err := cfg.DispatchFence.Resume(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	start := time.Now()
	c, err := DialClient(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h.mu.Lock()
	attaches, activations, aborts := len(h.attachAttempts), h.activations, h.aborts
	h.mu.Unlock()
	if time.Since(start) < 46*time.Second || attaches != 1 || activations != 2 || aborts != 0 || c.attachDisposition != AttachCleanupRequired {
		t.Fatal("outage replaced or abandoned the original possible commitment", time.Since(start), attaches, activations, aborts, c.attachDisposition)
	}
}
