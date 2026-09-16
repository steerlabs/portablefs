package volumeserver

import (
	"context"
	"errors"
	"fmt"
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
				if i+1 == peerHandles && got.Mode != DelegationWritethrough {
					t.Fatal("mode changed before holder acknowledgment")
				}
			}
			if peerHandles > 0 {
				e := cv2Event(t, c, a, StreamDelegationMode)
				if e.Delegation.Mode != DelegationFull {
					t.Fatal(e)
				}
				cv2CutAck(t, c, a, e, 0)
				got, _ := c.LookupDelegation(f)
				if got.Mode != DelegationFull {
					t.Fatal("last close did not upgrade after holder acknowledgment")
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

func TestCoherenceDelegationModeTimeoutRetiresGeneration(t *testing.T) {
	c, clock := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	identity := [16]byte{0x19}
	if ok, err := c.OpenCacheCapable(peer, identity); !ok || err != nil {
		t.Fatalf("peer cache handle = %v, %v", ok, err)
	}
	grant := cv2Grant(t, c, holder, identity, peer)
	if grant.Mode != DelegationWritethrough {
		t.Fatalf("grant mode = %v", grant.Mode)
	}
	if err := c.CloseCacheCapable(peer, identity); err != nil {
		t.Fatal(err)
	}
	event := cv2Event(t, c, holder, StreamDelegationMode)
	if event.Request == 0 || event.Deadline.IsZero() {
		t.Fatalf("mode event has no acknowledged obligation: %+v", event)
	}
	clock.Advance(DelegationRecallBudget)
	c.Sweep()
	if _, ok := c.LookupDelegation(identity); ok {
		t.Fatal("timed-out mode transition retained generation")
	}
	if c.LossSequence(holder.Session) != 1 {
		t.Fatalf("loss sequence = %d, want 1", c.LossSequence(holder.Session))
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

func TestCoherenceSynchronousMutationIsPinnedAndNeverRecalled(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	identity := [16]byte{0x51}

	type result struct {
		flush *DelegationFlush
		err   error
	}
	granted := make(chan result, 1)
	go func() {
		flush, err := c.BeginSynchronousMutation(t.Context(), holder, identity)
		granted <- result{flush: flush, err: err}
	}()

	// The private reservation is published before it can become active.
	reserved := cv2Event(t, c, peer, StreamChange)
	if reserved.Change.Kind != DelegationGranted || reserved.Change.Identity != identity {
		t.Fatalf("reservation change = %+v", reserved)
	}
	if err := c.Ack(peer, reserved.Position); err != nil {
		t.Fatal(err)
	}
	var flush *DelegationFlush
	select {
	case got := <-granted:
		if got.err != nil {
			t.Fatal(got.err)
		}
		flush = got.flush
	case <-time.After(5 * time.Second):
		t.Fatal("synchronous mutation did not acquire")
	}
	if flush == nil {
		t.Fatal("synchronous mutation returned no storage pin")
	}

	consumed := make(chan error, 1)
	go func() {
		guard, err := c.DataConsumed(t.Context(), peer, identity)
		if guard != nil {
			guard.Release()
		}
		consumed <- err
	}()
	select {
	case err := <-consumed:
		t.Fatalf("peer passed active synchronous mutation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	// No recall or break is addressed to the holder for the private generation.
	c.mu.Lock()
	for position := c.subscribers[holder.Session].acked + 1; position <= c.position; position++ {
		event := c.log[(position-1)%uint64(len(c.log))]
		if event.Target == holder.Session && (event.Kind == StreamRecall || event.Kind == StreamBreakForRead) {
			c.mu.Unlock()
			t.Fatalf("private generation emitted holder obligation: %+v", event)
		}
	}
	c.mu.Unlock()

	flush.End(17)
	if err := cv2Result(t, consumed); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.LookupDelegation(identity); ok {
		t.Fatal("private generation survived synchronous mutation")
	}
	changes := cv2AckAll(t, c, peer)
	foundRelease := false
	for _, event := range changes {
		foundRelease = foundRelease || event.Kind == StreamChange && event.Change.Kind == DelegationReleased && event.Change.Identity == identity
	}
	if !foundRelease {
		t.Fatalf("release changes = %+v", changes)
	}
}

func TestCoherenceSynchronousMutationPinsExistingHolderGrant(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	identity := [16]byte{0x52}
	grant := cv2Grant(t, c, holder, identity)

	flush, err := c.BeginSynchronousMutation(t.Context(), holder, identity)
	if err != nil {
		t.Fatal(err)
	}
	flush.End(23)
	got, ok := c.LookupDelegation(identity)
	if !ok || got.ID != grant.ID || got.Generation != grant.Generation {
		t.Fatalf("existing grant after synchronous mutation = %+v, %v", got, ok)
	}
}

func TestCoherenceHolderSynchronousMutationPassesPendingPeerCut(t *testing.T) {
	for _, recall := range []bool{false, true} {
		c, _ := cv2Coordinator(t)
		holder := cv2Subscribe(t, c, 1)
		identity := [16]byte{0x53}
		grant := cv2Grant(t, c, holder, identity)
		done := make(chan error, 1)
		kind := StreamBreakForRead
		if recall {
			kind = StreamRecall
		}
		go func() {
			if recall {
				done <- c.Recall(t.Context(), identity)
			} else {
				done <- c.BreakForRead(t.Context(), identity)
			}
		}()
		event := cv2Event(t, c, holder, kind)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		flush, err := c.BeginSynchronousMutation(ctx, holder, identity)
		cancel()
		if err != nil {
			t.Fatalf("holder apply behind pending %v: %v", kind, err)
		}
		flush.End(23)
		if err := c.AckDelegation(holder, identity, grant.ID, grant.Generation, event.Request, 23); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoherenceSynchronousMutationRetainsSuccessfulGrant(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	identity := [16]byte{0x53}
	if ok, err := c.OpenCacheCapable(peer, identity); !ok || err != nil {
		t.Fatalf("peer cache handle = %v, %v", ok, err)
	}
	type result struct {
		flush *DelegationFlush
		err   error
	}
	acquired := make(chan result, 1)
	go func() {
		flush, err := c.BeginSynchronousMutation(t.Context(), holder, identity)
		acquired <- result{flush, err}
	}()
	event := cv2Event(t, c, peer, StreamChange)
	if err := c.Ack(peer, event.Position); err != nil {
		t.Fatal(err)
	}
	got := <-acquired
	if got.err != nil {
		t.Fatal(got.err)
	}
	if err := c.CloseCacheCapable(peer, identity); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	for position := c.first; position <= c.position; position++ {
		if event := c.log[(position-1)%uint64(len(c.log))]; event.Kind == StreamDelegationMode && event.Target == holder.Session {
			c.mu.Unlock()
			t.Fatalf("private generation emitted mode event: %+v", event)
		}
	}
	c.mu.Unlock()
	reservation, _, err := got.flush.RetainDelegation()
	if err != nil {
		t.Fatal(err)
	}
	got.flush.End(31)
	grant, err := reservation.Grant(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if live, ok := c.LookupDelegation(identity); !ok || live.ID != grant.ID || live.Generation != grant.Generation {
		t.Fatalf("retained grant = %+v, %v", live, ok)
	}
	if grant.Mode != DelegationFull {
		t.Fatalf("retained mode = %v, want current full mode", grant.Mode)
	}
	if _, _, err := got.flush.RetainDelegation(); !errors.Is(err, ErrDelegationStale) {
		t.Fatalf("retain after End = %v", err)
	}
}

func TestCoherenceConcurrentSynchronousFailureCannotRetireRetainedGrant(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	identity := [16]byte{0x54}
	first, err := c.BeginSynchronousMutation(t.Context(), holder, identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.BeginSynchronousMutation(t.Context(), holder, identity)
	if err != nil {
		t.Fatal(err)
	}
	first.End(0)
	if _, ok := c.LookupDelegation(identity); !ok {
		t.Fatal("failed operation retired a generation still pinned by its peer")
	}
	reservation, _, err := second.RetainDelegation()
	if err != nil {
		t.Fatal(err)
	}
	second.End(32)
	grant, err := reservation.Grant(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if live, ok := c.LookupDelegation(identity); !ok || live.ID != grant.ID {
		t.Fatalf("concurrently retained grant = %+v, %v", live, ok)
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
	applied, err := c.BeginFlush(a, x, gx.ID, gx.Generation)
	if err != nil {
		t.Fatal(err)
	}
	applied.End(7)
	if _, err := c.ReleaseAppliedBatch(a, []Delegation{gx, gy}, []uint64{0, 0}); !errors.Is(err, ErrDelegationAck) {
		t.Fatalf("stale applied cut = %v", err)
	}
	if _, ok := c.LookupDelegation(y); !ok {
		t.Fatal("stale applied cut partially released batch")
	}
	pin, err := c.BeginFlush(a, y, gy.ID, gy.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReleaseBatch(a, []Delegation{gx, gy}); !errors.Is(err, ErrDelegationBusy) {
		t.Fatal(err)
	}
	pin.End(0)
	if _, err := c.ReleaseAppliedBatch(a, []Delegation{gx, gy}, []uint64{7, 0}); err != nil {
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
	event := cv2Event(t, c, a, StreamRecall)
	cancel()
	select {
	case <-done:
		t.Fatal("cancellation skipped holder drain")
	default:
	}
	cv2CutAck(t, c, a, event, 0)
	if err := cv2Result(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, ok := c.LookupDelegation(f); ok {
		t.Fatal("canceled recall revived delegation")
	}
	if c.LossSequence(a.Session) != 0 {
		t.Fatal("caller cancellation discarded holder data")
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
	event := cv2Event(t, c, a, StreamDelegationMode)
	cv2CutAck(t, c, a, event, 0)
	g, _ = c.LookupDelegation(f)
	if g.Mode != DelegationFull {
		t.Fatal("close acknowledgment did not upgrade")
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

func TestCoherencePermanentSessionEndDuringRecall(t *testing.T) {
	c, clock := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	f, other := [16]byte{1}, [16]byte{2}
	if ok, err := c.OpenCacheCapable(holder, other); !ok || err != nil {
		t.Fatalf("open=%v %v", ok, err)
	}
	cv2Grant(t, c, holder, f, peer)
	cv2AckAll(t, c, holder)
	recalled := make(chan error, 1)
	go func() { recalled <- c.Recall(t.Context(), f) }()
	cv2Event(t, c, holder, StreamRecall)
	// Backing reads needed by a flushing holder must not queue behind recall.
	guard, err := c.DataConsumed(t.Context(), holder, f)
	if err != nil {
		t.Fatal(err)
	}
	guard.Release()
	position := c.OnCommit([]ChangeEntry{{Kind: AttributesChanged, Identity: other, VolumeVersion: 1}})
	withdrawn := make(chan error, 1)
	go func() { withdrawn <- c.WaitWithdrawn(t.Context(), position, peer.Session) }()
	c.ExpireSession(holder.Session)
	if err := cv2Result(t, recalled); err != nil {
		t.Fatal(err)
	}
	if c.LossSequence(holder.Session) != 1 {
		t.Fatal("terminal holder did not record loss")
	}
	if err := c.CheckSession(holder); !errors.Is(err, ErrSessionFenced) {
		t.Fatal(err)
	}
	if err := c.ForgetSession(holder.Session); !errors.Is(err, ErrSessionActive) {
		t.Fatalf("forgot old cache horizon: %v", err)
	}
	c.mu.Lock()
	handlesRemain := c.cacheHandles[other] != nil
	c.mu.Unlock()
	if handlesRemain {
		t.Fatal("terminal handles retained")
	}
	select {
	case <-withdrawn:
		t.Fatal("terminal runtime shortened cache horizon")
	default:
	}
	clock.Advance(SubscriptionTTL)
	if err := cv2Result(t, withdrawn); err != nil {
		t.Fatal(err)
	}
	if err := c.ForgetSession(holder.Session); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckSession(holder); !errors.Is(err, ErrSubscription) {
		t.Fatal(err)
	}
	fresh, err := c.Subscribe(holder.Session)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Token.Incarnation <= holder.Incarnation {
		t.Fatal("forgotten incarnation was reused")
	}
}

func TestCoherenceReleaseCompletesPendingPeerCut(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind StreamEventKind
	}{
		{"break", StreamBreakForRead},
		{"recall", StreamRecall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := cv2Coordinator(t)
			holder := cv2Subscribe(t, c, 1)
			identity := [16]byte{91}
			grant := cv2Grant(t, c, holder, identity)
			done := make(chan error, 1)
			go func() {
				if tc.kind == StreamRecall {
					done <- c.Recall(t.Context(), identity)
				} else {
					done <- c.BreakForRead(t.Context(), identity)
				}
			}()
			cv2Event(t, c, holder, tc.kind)
			pin, err := c.BeginFlush(holder, identity, grant.ID, grant.Generation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.ReleaseAppliedBatch(holder, []Delegation{grant}, []uint64{0}); !errors.Is(err, ErrDelegationBusy) {
				t.Fatalf("active release = %v", err)
			}
			pin.End(13)
			for _, ticket := range []uint64{0, 12, 14} {
				if _, err := c.ReleaseAppliedBatch(holder, []Delegation{grant}, []uint64{ticket}); !errors.Is(err, ErrDelegationAck) {
					t.Fatalf("inexact release %d = %v", ticket, err)
				}
			}
			if _, err := c.ReleaseAppliedBatch(holder, []Delegation{grant}, []uint64{13}); err != nil {
				t.Fatal(err)
			}
			if err := cv2Result(t, done); err != nil {
				t.Fatal(err)
			}
			if _, exists := c.LookupDelegation(identity); exists {
				t.Fatal("released grant remains live")
			}
			for _, event := range cv2AckAll(t, c, holder) {
				if event.Kind == StreamLoss {
					t.Fatal("release reported loss")
				}
			}
		})
	}
}

func TestCoherencePrivateMutationExcludesSourceUntilPromotion(t *testing.T) {
	for _, promote := range []bool{false, true} {
		c, _ := cv2Coordinator(t)
		source, peer := cv2Subscribe(t, c, 1), cv2Subscribe(t, c, 2)
		identity := [16]byte{94}
		type result struct {
			pin *DelegationFlush
			err error
		}
		done := make(chan result, 1)
		go func() {
			pin, err := c.BeginSynchronousMutation(t.Context(), source, identity)
			done <- result{pin, err}
		}()
		cv2Event(t, c, peer, StreamChange)
		cv2AckAll(t, c, peer)
		var pin *DelegationFlush
		select {
		case outcome := <-done:
			if outcome.err != nil {
				t.Fatal(outcome.err)
			}
			pin = outcome.pin
		case <-time.After(time.Second):
			t.Fatal("private mutation did not acquire")
		}
		var reservation *DelegationReservation
		if promote {
			var err error
			reservation, _, err = pin.RetainDelegation()
			if err != nil {
				t.Fatal(err)
			}
		}
		pin.End(7)
		if promote {
			grant, err := reservation.Grant(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.ReleaseAppliedBatch(source, []Delegation{grant}, []uint64{7}); err != nil {
				t.Fatal(err)
			}
		}
		events, err := c.Poll(t.Context(), source, 0, nil, 8)
		if err != nil || len(events) != 2 {
			t.Fatalf("source events=%v err=%v", events, err)
		}
		if events[0].Kind != StreamAdvance {
			t.Fatal("private grant notified its source")
		}
		want := StreamAdvance
		if promote {
			want = StreamChange
		}
		if events[1].Kind != want {
			t.Fatalf("promote=%v release kind=%v", promote, events[1].Kind)
		}
		peerEvents := cv2AckAll(t, c, peer)
		if len(peerEvents) != 1 || peerEvents[0].Change.Kind != DelegationReleased {
			t.Fatalf("peer release=%v", peerEvents)
		}
	}
}

func TestCoherencePromotedPrivateGrantDrainsPendingReaders(t *testing.T) {
	for _, beforePromotion := range []bool{false, true} {
		t.Run(fmt.Sprint(beforePromotion), func(t *testing.T) {
			c, clock := cv2Coordinator(t)
			holder := cv2Subscribe(t, c, 1)
			identity := [16]byte{0x61}
			pin, err := c.BeginSynchronousMutation(t.Context(), holder, identity)
			if err != nil {
				t.Fatal(err)
			}
			peer := cv2Subscribe(t, c, 2)
			type result struct {
				guard *DataGuard
				err   error
			}
			read := make(chan result, 1)
			startRead := func() {
				go func() { guard, err := c.DataConsumed(t.Context(), peer, identity); read <- result{guard, err} }()
			}
			if beforePromotion {
				startRead()
				clock.waitForTimers(t, 1)
			}
			reservation, existing, err := pin.RetainDelegation()
			if err != nil || reservation == nil || existing.ID != 0 {
				t.Fatalf("retain=%v %v %v", reservation, existing, err)
			}
			pin.End(17)
			if !beforePromotion {
				startRead()
			}
			var guard *DataGuard
			select {
			case got := <-read:
				if got.err != nil || got.guard.record == nil {
					t.Fatalf("read admission=%+v", got)
				}
				guard = got.guard
			case <-time.After(time.Second):
				t.Fatal("reader waited for an unreported delegation break")
			}
			defer guard.Release()
			granted := make(chan error, 1)
			go func() { _, err := reservation.Grant(t.Context()); granted <- err }()
			clock.waitForTimers(t, 1)
			select {
			case err := <-granted:
				t.Fatalf("grant passed pinned reader: %v", err)
			default:
			}
			guard.Release()
			if err := cv2Result(t, granted); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCoherenceCutValidatesExactTicketsWithoutHistoricalLedger(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	identity, other := [16]byte{71}, [16]byte{72}
	grant := cv2Grant(t, c, holder, identity)
	otherGrant := cv2Grant(t, c, holder, other)
	apply := func(g Delegation, ticket uint64) {
		pin, err := c.BeginFlush(holder, g.Identity, g.ID, g.Generation)
		if err != nil {
			t.Fatal(err)
		}
		pin.End(ticket)
	}
	apply(grant, 1)
	cv2AckAll(t, c, holder)
	done := make(chan error, 1)
	go func() { done <- c.BreakForRead(t.Context(), identity) }()
	event := cv2Event(t, c, holder, StreamBreakForRead)
	apply(grant, 3)
	apply(otherGrant, 4)
	apply(grant, 5)
	if err := c.AckDelegation(holder, identity, grant.ID, grant.Generation, event.Request, 4); !errors.Is(err, ErrDelegationAck) {
		t.Fatalf("foreign identity ticket=%v", err)
	}
	// A later same-file application does not invalidate the reader's earlier cut.
	cv2CutAck(t, c, holder, event, 3)
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
	cv2AckAll(t, c, holder)
	go func() { done <- c.Recall(t.Context(), identity) }()
	event = cv2Event(t, c, holder, StreamRecall)
	apply(grant, 7)
	if err := c.AckDelegation(holder, identity, grant.ID, grant.Generation, event.Request, 5); !errors.Is(err, ErrDelegationAck) {
		t.Fatalf("recall did not cover final application: %v", err)
	}
	cv2CutAck(t, c, holder, event, 7)
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
}
