package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func cv2Coordinator(t *testing.T) (*CoherenceCoordinator, *cv2Clock) {
	t.Helper()
	clock := newCV2Clock()
	return NewCoherenceCoordinator(CoherenceConfig{Clock: clock, MaxLogEntries: 256}), clock
}
func cv2Subscribe(t *testing.T, c *CoherenceCoordinator, id byte) SubscriptionToken {
	t.Helper()
	s, err := c.Subscribe(SessionID{id})
	if err != nil {
		t.Fatal(err)
	}
	return s.Token
}
func cv2AckAll(t *testing.T, c *CoherenceCoordinator, token SubscriptionToken) []StreamEvent {
	t.Helper()
	c.mu.Lock()
	s := c.subscribers[token.Session]
	after := s.acked
	position := c.position
	c.mu.Unlock()
	if after == position {
		return nil
	}
	events, err := c.Poll(t.Context(), token, after, nil, 10000)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ack(token, events[len(events)-1].Position); err != nil {
		t.Fatal(err)
	}
	return events
}
func cv2Grant(t *testing.T, c *CoherenceCoordinator, token SubscriptionToken, identity [16]byte, peers ...SubscriptionToken) Delegation {
	t.Helper()
	r, err := c.Reserve(t.Context(), token, identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		cv2AckAll(t, c, p)
	}
	g, err := r.Grant(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func cv2Result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("coordinator did not progress")
		return nil
	}
}
func cv2Event(t *testing.T, c *CoherenceCoordinator, token SubscriptionToken, kind StreamEventKind) StreamEvent {
	t.Helper()
	c.mu.Lock()
	after := c.subscribers[token.Session].acked
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		events, err := c.Poll(ctx, token, after, nil, 128)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Kind == kind {
				return e
			}
			after = e.Position
		}
	}
}
func cv2CutAck(t *testing.T, c *CoherenceCoordinator, token SubscriptionToken, e StreamEvent, seq uint64) {
	t.Helper()
	g := e.Delegation
	if err := c.AckDelegation(token, g.Identity, g.ID, g.Generation, e.Request, seq); err != nil {
		t.Fatal(err)
	}
}

func TestCoherenceDelegationCacheModes(t *testing.T) {
	for _, peerHandles := range []int{0, 1, 3} {
		t.Run(string(rune('0'+peerHandles)), func(t *testing.T) {
			c, _ := cv2Coordinator(t)
			a := cv2Subscribe(t, c, 1)
			b := cv2Subscribe(t, c, 2)
			f := [16]byte{9}
			for range peerHandles {
				if ok, err := c.OpenCacheCapable(b, f); !ok || err != nil {
					t.Fatalf("open = %v %v", ok, err)
				}
			}
			g := cv2Grant(t, c, a, f, b)
			want := DelegationFull
			if peerHandles > 0 {
				want = DelegationWritethrough
			}
			if g.Mode != want {
				t.Fatalf("mode=%v", g.Mode)
			}
			for _, token := range []SubscriptionToken{a, b} {
				if ok, err := c.OpenCacheCapable(token, f); ok || err != nil {
					t.Fatalf("delegated open=%v %v", ok, err)
				}
			}
			for i := 0; i < peerHandles; i++ {
				if err := c.CloseCacheCapable(b, f); err != nil {
					t.Fatal(err)
				}
				got, _ := c.LookupDelegation(f)
				if i+1 == peerHandles && got.Mode != DelegationFull {
					t.Fatal("last close did not upgrade")
				}
			}
			if peerHandles > 0 {
				e := cv2Event(t, c, a, StreamDelegationMode)
				if e.Delegation.Mode != DelegationFull {
					t.Fatal(e)
				}
			}
			if _, err := c.ReleaseBatch(a, []Delegation{g}); err != nil {
				t.Fatal(err)
			}
			if _, ok := c.LookupDelegation(f); ok {
				t.Fatal("released grant retained")
			}
			if ok, err := c.OpenCacheCapable(b, f); !ok || err != nil {
				t.Fatalf("released open=%v %v", ok, err)
			}
		})
	}
}
func TestCoherenceReservedIdentityClosesCachingAndColdSnapshot(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	f := [16]byte{8}
	r, err := c.ReserveNew(a, f)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := c.Subscribe(SessionID{2})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Delegated) != 1 || snapshot.Delegated[0] != f {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if ok, err := c.OpenCacheCapable(snapshot.Token, f); ok || err != nil {
		t.Fatalf("open=%v %v", ok, err)
	}
	if _, err := r.Grant(t.Context()); err != nil {
		t.Fatal(err)
	}
}
func TestCoherenceBreakFlushCutAndRecall(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	f := [16]byte{1}
	g := cv2Grant(t, c, a, f)
	initial, err := c.BeginFlush(a, f, g.ID, g.Generation)
	if err != nil {
		t.Fatal(err)
	}
	initial.End(4)
	done := make(chan error, 1)
	go func() { done <- c.BreakForRead(t.Context(), f) }()
	event := cv2Event(t, c, a, StreamBreakForRead)
	pin, err := c.BeginFlush(a, f, g.ID, g.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AckDelegation(a, f, g.ID, g.Generation, event.Request, 8); !errors.Is(err, ErrDelegationAck) {
		t.Fatalf("unapplied ack=%v", err)
	}
	if err := c.AckDelegation(a, f, g.ID, g.Generation, event.Request, 3); !errors.Is(err, ErrDelegationAck) {
		t.Fatalf("short cut=%v", err)
	}
	// A later write can still be applying when the holder acknowledges the
	// already-applied cut. Breaking a reader must not require an idle writer.
	cv2CutAck(t, c, a, event, 4)
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
	c.OnCommit([]ChangeEntry{{Kind: DataChanged, Identity: f, VolumeVersion: 8}})
	pin.End(8)
	if got, ok := c.LookupDelegation(f); !ok || got.Generation != g.Generation {
		t.Fatal("break removed grant")
	}
	go func() { done <- c.Recall(t.Context(), f) }()
	event = cv2Event(t, c, a, StreamRecall)
	pin, err = c.BeginFlush(a, f, g.ID, g.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AckDelegation(a, f, g.ID, g.Generation, event.Request, 8); !errors.Is(err, ErrDelegationBusy) {
		t.Fatalf("active recall ack=%v", err)
	}
	pin.End(9)
	cv2CutAck(t, c, a, event, 9)
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.LookupDelegation(f); ok {
		t.Fatal("recall retained grant")
	}
	if c.LossSequence(a.Session) != 0 {
		t.Fatal("clean recall recorded loss")
	}
}
func TestCoherenceRecallPassesPendingWithdrawalToSameSession(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	f := [16]byte{1}
	cv2Grant(t, c, a, f)
	cv2AckAll(t, c, a)
	position := c.OnCommit([]ChangeEntry{{Kind: AttributesChanged, Identity: [16]byte{2}, VolumeVersion: 1}})
	withdrawn := make(chan error, 1)
	go func() { withdrawn <- c.WaitWithdrawn(t.Context(), position, SessionID{2}) }()
	recalled := make(chan error, 1)
	go func() { recalled <- c.Recall(t.Context(), f) }()
	event := cv2Event(t, c, a, StreamRecall)
	cv2CutAck(t, c, a, event, 0)
	if err := cv2Result(t, recalled); err != nil {
		t.Fatal(err)
	}
	select {
	case <-withdrawn:
		t.Fatal("recall ack discharged cumulative withdrawal")
	default:
	}
	cv2AckAll(t, c, a)
	if err := cv2Result(t, withdrawn); err != nil {
		t.Fatal(err)
	}
}
func TestCoherenceCrossSessionRequestsDoNotDeadlock(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	x, y := [16]byte{1}, [16]byte{2}
	gx := cv2Grant(t, c, a, x)
	b := cv2Subscribe(t, c, 2)
	gy := cv2Grant(t, c, b, y, a)
	cv2AckAll(t, c, b)
	type result struct {
		g   Delegation
		err error
	}
	done := make(chan result, 2)
	go func() { g, err := c.DataMutated(t.Context(), a, y); done <- result{g, err} }()
	go func() { g, err := c.DataMutated(t.Context(), b, x); done <- result{g, err} }()
	ea := cv2Event(t, c, a, StreamRecall)
	eb := cv2Event(t, c, b, StreamRecall)
	cv2CutAck(t, c, a, ea, 0)
	cv2CutAck(t, c, b, eb, 0)
	// Wait for both replacement reservations before the cumulative ack. Both
	// holder acks were serviceable despite each mount's outstanding request.
	cv2Wait(t, c, func() bool {
		rx, ry := c.delegations[x], c.delegations[y]
		return rx != nil && ry != nil && rx.grant.Holder == b.Session && ry.grant.Holder == a.Session
	})
	cv2AckAll(t, c, a)
	cv2AckAll(t, c, b)
	for range 2 {
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatal(r.err)
			}
			if r.g.Generation <= min(gx.Generation, gy.Generation) {
				t.Fatal("generation reused")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cross recall stalled")
		}
	}
}
func cv2Wait(t *testing.T, c *CoherenceCoordinator, condition func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		c.mu.Lock()
		if condition() {
			c.mu.Unlock()
			return
		}
		changed := c.notificationLocked()
		c.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("state transition stalled")
		}
	}
}
func TestCoherenceGrantWaitsOnlyToPartitionHorizon(t *testing.T) {
	c, clock := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	b := cv2Subscribe(t, c, 2)
	f := [16]byte{3}
	clock.Advance(3 * time.Second)
	if _, err := c.Renew(a); err != nil {
		t.Fatal(err)
	}
	r, err := c.Reserve(t.Context(), a, f)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := r.Grant(t.Context()); done <- err }()
	clock.Advance(7 * time.Second)
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckSession(b); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("partition=%v", err)
	}
}
func TestCoherenceRecallExpiryAndBudget(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "budget", true: "holder expiry"}[expiry], func(t *testing.T) {
			c, clock := cv2Coordinator(t)
			a := cv2Subscribe(t, c, 1)
			f := [16]byte{5}
			g := cv2Grant(t, c, a, f)
			if expiry {
				clock.Advance(8 * time.Second)
			}
			done := make(chan error, 1)
			go func() { done <- c.Recall(t.Context(), f) }()
			cv2Event(t, c, a, StreamRecall)
			if expiry {
				clock.Advance(2 * time.Second)
			} else {
				clock.Advance(DelegationRecallBudget)
			}
			if err := cv2Result(t, done); err != nil {
				t.Fatal(err)
			}
			if _, ok := c.LookupDelegation(f); ok {
				t.Fatal("expired holder retained")
			}
			if c.LossSequence(a.Session) != 1 {
				t.Fatal("missing exact loss")
			}
			if !expiry {
				if _, err := c.BeginFlush(a, f, g.ID, g.Generation); !errors.Is(err, ErrDelegationStale) {
					t.Fatal(err)
				}
				if c.LossSequence(a.Session) != 2 {
					t.Fatal("stale flush did not record loss")
				}
			}
		})
	}
}
func TestCoherenceBreakRacingRecallIsFIFO(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	f := [16]byte{1}
	cv2Grant(t, c, a, f)
	broken, recalled := make(chan error, 1), make(chan error, 1)
	go func() { broken <- c.BreakForRead(t.Context(), f) }()
	e := cv2Event(t, c, a, StreamBreakForRead)
	go func() { recalled <- c.Recall(t.Context(), f) }()
	cv2CutAck(t, c, a, e, 0)
	if err := cv2Result(t, broken); err != nil {
		t.Fatal(err)
	}
	e = cv2Event(t, c, a, StreamRecall)
	cv2CutAck(t, c, a, e, 0)
	if err := cv2Result(t, recalled); err != nil {
		t.Fatal(err)
	}
}
func TestCoherenceDisjointRequestBypassesRecall(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	x, y := [16]byte{1}, [16]byte{2}
	cv2Grant(t, c, a, x)
	done := make(chan error, 1)
	go func() { done <- c.Recall(t.Context(), x) }()
	e := cv2Event(t, c, a, StreamRecall)
	g := cv2Grant(t, c, a, y)
	if g.Identity != y {
		t.Fatal(g)
	}
	cv2CutAck(t, c, a, e, 0)
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
}
func TestCoherenceExpiryCannotReassignAnApplyingFlush(t *testing.T) {
	c, clock := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	f := [16]byte{7}
	g := cv2Grant(t, c, a, f)
	pin, err := c.BeginFlush(a, f, g.ID, g.Generation)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Recall(t.Context(), f) }()
	cv2Event(t, c, a, StreamRecall)
	clock.Advance(DelegationRecallBudget)
	cv2Wait(t, c, func() bool { return c.delegations[f].retired })
	select {
	case <-done:
		t.Fatal("recall passed applying flush")
	default:
	}
	pin.End(17)
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
	g2 := cv2Grant(t, c, a, f)
	if g2.Generation <= g.Generation {
		t.Fatal("reused generation")
	}
}
func TestCoherenceReleaseBatchIsAtomic(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	x, y := [16]byte{1}, [16]byte{2}
	gx := cv2Grant(t, c, a, x)
	gy := cv2Grant(t, c, a, y)
	bad := gy
	bad.Generation++
	for _, batch := range [][]Delegation{{gx, bad}, {gx, gx}} {
		if _, err := c.ReleaseBatch(a, batch); !errors.Is(err, ErrDelegationStale) {
			t.Fatal(err)
		}
		if _, ok := c.LookupDelegation(x); !ok {
			t.Fatal("partial release")
		}
	}
	pin, err := c.BeginFlush(a, y, gy.ID, gy.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReleaseBatch(a, []Delegation{gx, gy}); !errors.Is(err, ErrDelegationBusy) {
		t.Fatal(err)
	}
	pin.End(0)
	if _, err := c.ReleaseBatch(a, []Delegation{gx, gy}); err != nil {
		t.Fatal(err)
	}
}
func TestCoherenceCanceledReservationAndCutCleanUp(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	b := cv2Subscribe(t, c, 2)
	f := [16]byte{1}
	r, err := c.Reserve(t.Context(), a, f)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.Grant(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, ok := c.LookupDelegation(f); ok {
		t.Fatal("canceled reservation retained")
	}
	cv2Grant(t, c, a, f, b)
	ctx, cancel = context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Recall(ctx, f) }()
	cv2Event(t, c, a, StreamRecall)
	cancel()
	if err := cv2Result(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, ok := c.LookupDelegation(f); ok {
		t.Fatal("canceled recall revived delegation")
	}
}

func TestCoherenceCacheHandlesSurviveColdResubscribe(t *testing.T) {
	c, clock := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	b := cv2Subscribe(t, c, 2)
	f := [16]byte{1}
	if ok, err := c.OpenCacheCapable(b, f); !ok || err != nil {
		t.Fatalf("open=%v %v", ok, err)
	}
	g := cv2Grant(t, c, a, f, b)
	if g.Mode != DelegationWritethrough {
		t.Fatal(g)
	}
	clock.Advance(3 * time.Second)
	if _, err := c.Renew(a); err != nil {
		t.Fatal(err)
	}
	clock.Advance(7 * time.Second)
	c.Sweep()
	g, _ = c.LookupDelegation(f)
	if g.Mode != DelegationWritethrough {
		t.Fatal("expiry forgot cache-capable open description")
	}
	snapshot, err := c.Subscribe(b.Session)
	if err != nil {
		t.Fatal(err)
	}
	g, _ = c.LookupDelegation(f)
	if g.Mode != DelegationWritethrough {
		t.Fatal("cold reset forgot cache-capable open description")
	}
	if err := c.CloseCacheCapable(snapshot.Token, f); err != nil {
		t.Fatal(err)
	}
	g, _ = c.LookupDelegation(f)
	if g.Mode != DelegationFull {
		t.Fatal("close did not upgrade")
	}
}

func TestCoherenceAckRejectsFutureAppliedCut(t *testing.T) {
	c, _ := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	f := [16]byte{1}
	g := cv2Grant(t, c, a, f)
	done := make(chan error, 1)
	go func() { done <- c.BreakForRead(t.Context(), f) }()
	e := cv2Event(t, c, a, StreamBreakForRead)
	if err := c.AckDelegation(a, f, g.ID, g.Generation, e.Request, 99); !errors.Is(err, ErrDelegationAck) {
		t.Fatalf("future cut=%v", err)
	}
	cv2CutAck(t, c, a, e, 0)
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
}
