package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDataConsumedSetUsesOneTurnAndRetainsEveryIdentity(t *testing.T) {
	c, _ := cv2Coordinator(t)
	token := cv2Subscribe(t, c, 1)
	ids := [][16]byte{{1}, {2}, {3}, {2}}
	before := c.requests.nextOrdinal
	guard, err := c.DataConsumedSet(t.Context(), token, ids)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.requests.nextOrdinal - before; got != 1 {
		t.Fatalf("page request turns=%d, want one", got)
	}
	var waiters []*mutationSequencerWaiter
	for _, id := range ids[:3] {
		w := c.requests.enqueue(delegationDependencies(id))
		waiters = append(waiters, w)
		select {
		case <-w.ready:
			t.Fatal("page failed to retain identity")
		default:
		}
	}
	guard.Release()
	guard.Release()
	for _, w := range waiters {
		select {
		case <-w.ready:
			w.release()
		case <-time.After(time.Second):
			t.Fatal("page leaked identity")
		}
	}
}

func TestDataConsumedSetPinsReservedReadersIncludingLateReservations(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "existing"
		if late {
			name = "late"
		}
		t.Run(name, func(t *testing.T) {
			c, _ := cv2Coordinator(t)
			holder := cv2Subscribe(t, c, 1)
			reader := cv2Subscribe(t, c, 2)
			id := [16]byte{1}
			var reservation *DelegationReservation
			var ahead *mutationSequencerWaiter
			var err error
			if late {
				ahead, err = c.requests.acquire(t.Context(), delegationDependencies(id))
			} else {
				reservation, err = c.Reserve(t.Context(), holder, id)
			}
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				guard *DataGuard
				err   error
			}
			done := make(chan result, 1)
			go func() { g, e := c.DataConsumedSet(t.Context(), reader, [][16]byte{id, {2}, id}); done <- result{g, e} }()
			if late {
				deadline := time.Now().Add(time.Second)
				for c.requests.queued() == 0 {
					if time.Now().After(deadline) {
						t.Fatal("read did not queue")
					}
					time.Sleep(time.Millisecond)
				}
				c.mu.Lock()
				subscriber, checkErr := c.subscriberLocked(holder)
				if checkErr != nil {
					c.mu.Unlock()
					t.Fatal(checkErr)
				}
				reservation, err = c.reserveLocked(subscriber, id, ahead, false)
				c.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			var got result
			select {
			case got = <-done:
			case <-time.After(time.Second):
				t.Fatal("reader waited behind reservation it must pin")
			}
			if got.err != nil {
				t.Fatal(got.err)
			}
			if len(got.guard.records) != 1 {
				t.Fatalf("reserved reader pins=%d", len(got.guard.records))
			}
			cv2AckAll(t, c, reader)
			granted := make(chan error, 1)
			go func() { _, e := reservation.Grant(t.Context()); granted <- e }()
			select {
			case e := <-granted:
				t.Fatalf("grant passed pinned storage sample: %v", e)
			case <-time.After(10 * time.Millisecond):
			}
			got.guard.Release()
			if err := cv2Result(t, granted); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDataConsumedSetCancellationReleasesPinsAndQueuedTurn(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	reader := cv2Subscribe(t, c, 2)
	reservation, err := c.Reserve(t.Context(), holder, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Abort()
	held, err := c.requests.acquire(t.Context(), delegationDependencies([16]byte{2}))
	if err != nil {
		t.Fatal(err)
	}
	defer held.release()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := c.DataConsumedSet(ctx, reader, [][16]byte{{1}, {2}}); done <- err }()
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		pinned := reservation.record.readers == 1
		c.mu.Unlock()
		if pinned {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing reader pin")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := cv2Result(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	c.mu.Lock()
	readers := reservation.record.readers
	c.mu.Unlock()
	if readers != 0 || c.requests.queued() != 0 {
		t.Fatalf("cancel retained readers=%d waiters=%d", readers, c.requests.queued())
	}
}

func TestDataConsumedSetWaitsForEveryForeignBreak(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	reader := cv2Subscribe(t, c, 2)
	for _, id := range [][16]byte{{1}, {2}} {
		cv2Grant(t, c, holder, id, reader)
	}
	done := make(chan *DataGuard, 1)
	failed := make(chan error, 1)
	go func() {
		g, e := c.DataConsumedSet(t.Context(), reader, [][16]byte{{2}, {1}, {2}})
		if e != nil {
			failed <- e
		} else {
			done <- g
		}
	}()
	after := uint64(0)
	for _, id := range [][16]byte{{1}, {2}} {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		var event StreamEvent
		for event.Kind != StreamBreakForRead {
			events, err := c.Poll(ctx, holder, after, nil, 128)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			for _, candidate := range events {
				after = candidate.Position
				if candidate.Kind == StreamBreakForRead {
					event = candidate
					break
				}
			}
		}
		cancel()
		if event.Delegation.Identity != id {
			t.Fatalf("break identity=%x, want canonical %x", event.Delegation.Identity, id)
		}
		select {
		case g := <-done:
			g.Release()
			t.Fatal("page passed incomplete break")
		case err := <-failed:
			t.Fatal(err)
		default:
		}
		cv2CutAck(t, c, holder, event, 0)
	}
	select {
	case g := <-done:
		g.Release()
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("page did not finish both breaks")
	}
}

func TestDataConsumedSetOppositeOrderPagesDoNotNestGuards(t *testing.T) {
	c, _ := cv2Coordinator(t)
	reader := cv2Subscribe(t, c, 1)
	first, err := c.DataConsumedSet(t.Context(), reader, [][16]byte{{1}, {2}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		g, e := c.DataConsumedSet(t.Context(), reader, [][16]byte{{2}, {1}})
		if g != nil {
			g.Release()
		}
		done <- e
	}()
	deadline := time.Now().Add(time.Second)
	for c.requests.queued() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("opposite page did not queue as one set")
		}
		time.Sleep(time.Millisecond)
	}
	first.Release()
	if err := cv2Result(t, done); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkReadPageAdmission256(b *testing.B) {
	ids := make([][16]byte, 256)
	for i := range ids {
		ids[i] = [16]byte{byte(i), 1}
	}
	for _, batch := range []bool{false, true} {
		name := "per-entry"
		if batch {
			name = "batch"
		}
		b.Run(name, func(b *testing.B) {
			c := NewCoherenceCoordinator(CoherenceConfig{})
			snapshot, err := c.Subscribe(SessionID{1})
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if batch {
					g, e := c.DataConsumedSet(b.Context(), snapshot.Token, ids)
					if e != nil {
						b.Fatal(e)
					}
					g.Release()
				} else {
					for _, id := range ids {
						g, e := c.DataConsumed(b.Context(), snapshot.Token, id)
						if e != nil {
							b.Fatal(e)
						}
						g.Release()
					}
				}
			}
		})
	}
}

func TestDataConsumedSetPinsOwnGenerationWhileWaitingForAnotherIdentity(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	id := [16]byte{1}
	cv2Grant(t, c, holder, id, peer)
	held, err := c.requests.acquire(t.Context(), delegationDependencies([16]byte{2}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *DataGuard, 1)
	failed := make(chan error, 1)
	go func() {
		g, e := c.DataConsumedSet(t.Context(), holder, [][16]byte{id, {2}})
		if e != nil {
			failed <- e
		} else {
			done <- g
		}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		pinned := c.delegations[id].readers == 1
		c.mu.Unlock()
		if pinned {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("own generation not pinned")
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	c.dropDelegationLocked(c.delegations[id], true)
	c.mu.Unlock()
	replaced := make(chan *DelegationReservation, 1)
	go func() {
		r, e := c.Reserve(t.Context(), peer, id)
		if e != nil {
			failed <- e
		} else {
			replaced <- r
		}
	}()
	held.release()
	var guard *DataGuard
	select {
	case guard = <-done:
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("batch failed to acquire remaining identity")
	}
	select {
	case r := <-replaced:
		r.Abort()
		t.Fatal("own generation replaced before storage sample completed")
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(10 * time.Millisecond):
	}
	guard.Release()
	select {
	case r := <-replaced:
		r.Abort()
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("old generation pin leaked")
	}
}
