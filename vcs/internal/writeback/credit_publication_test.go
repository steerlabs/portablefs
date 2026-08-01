package writeback

import (
	"sync"
	"testing"
)

// TestFastPathCannotCommitAgainstAPrePublicationObservation is the fairness
// property at the ONE point the retry loop cannot reach: the window between the
// fast path's last observation of an empty queue and the CAS that commits its
// admission.
//
// Re-reading the queue inside the loop is not enough on its own. It only makes
// a RETRY re-examine occupancy, and a retry only happens when the commit fails.
// If occupancy and debt live in two independent words, a caller that observes
// an empty queue and then has a waiter published underneath it still commits:
// its CAS compares debt, the publication moved a different word, and the CAS
// succeeds. Every individual step is correct and the waiter has still been
// barged past — exactly once, which is enough to break the FIFO.
//
// The seam lands B's COMPLETE publication (append plus occupancy store, under
// c.mu, the way wait() does it) in that window, and B never touches debt. The
// only thing that can refuse A here is publishing occupancy and debt as one
// state: A's CAS must fail because the state it observed no longer holds.
func TestFastPathCannotCommitAgainstAPrePublicationObservation(t *testing.T) {
	c := newTestCredits(t, 512<<20)

	seamCalls := 0
	creditFastPathCAS = func() {
		seamCalls++
		if seamCalls > 1 {
			return
		}
		// B publishes itself as a waiter exactly as wait() does — and, unlike
		// wait(), that is ALL it does. No debt movement, so nothing here can
		// make A's CAS fail except the publication itself.
		c.mu.Lock()
		c.queue = append(c.queue, &creditWaiter{want: 1 << 20, ready: make(chan struct{}, 1)})
		c.waiting.Store(int64(len(c.queue)))
		c.mu.Unlock()
	}
	t.Cleanup(func() { creditFastPathCAS = nil })

	if c.tryFast(1 << 20) {
		t.Fatal("the fast path committed an admission decided against a queue snapshot " +
			"taken before the waiter published itself; the waiter was barged past")
	}
	if seamCalls != 1 {
		t.Fatalf("the CAS seam ran %d times, want exactly 1; the test proved nothing", seamCalls)
	}
	if got := c.debt.Load(); got != 0 {
		t.Fatalf("debt %d after a refused fast-path admission, want 0: nothing may be charged", got)
	}
	if got := c.waiting.Load(); got != 1 {
		t.Fatalf("waiting %d after the publication, want 1", got)
	}
}

// TestOccupancyAndDebtArePublishedAsOneState is the same property stated as an
// invariant rather than a single interleaving, and is the one that must hold
// under -race: while the queue is non-empty NO fast-path admission may complete,
// no matter how the publication interleaves with the admission attempts.
func TestOccupancyAndDebtArePublishedAsOneState(t *testing.T) {
	c := newTestCredits(t, 512<<20)

	const admitters = 8
	const rounds = 2000

	var admit, publish sync.WaitGroup
	stop := make(chan struct{})

	// The publisher flips occupancy on and off under c.mu, the way wait() and
	// dequeue() do.
	publish.Add(1)
	go func() {
		defer publish.Done()
		w := &creditWaiter{want: 1 << 20, ready: make(chan struct{}, 1)}
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.mu.Lock()
			c.queue = append(c.queue, w)
			c.waiting.Store(int64(len(c.queue)))
			c.mu.Unlock()

			c.mu.Lock()
			c.queue = c.queue[:0]
			c.waiting.Store(0)
			c.mu.Unlock()
		}
	}()

	for i := 0; i < admitters; i++ {
		admit.Add(1)
		go func() {
			defer admit.Done()
			for r := 0; r < rounds; r++ {
				if c.tryFast(4 << 10) {
					// A completed admission must have been decided against an
					// empty queue AND must never push the ledger past the
					// setpoint.
					if d, s := c.debt.Load(), c.setpoint.Load(); d > s {
						t.Errorf("debt %d passed the setpoint %d", d, s)
					}
					c.release(4 << 10)
				}
			}
		}()
	}
	admit.Wait()
	close(stop)
	publish.Wait()

	c.mu.Lock()
	c.queue = nil
	c.waiting.Store(0)
	c.mu.Unlock()

	if got := c.debt.Load(); got != 0 {
		t.Fatalf("%d bytes survived every admission being released", got)
	}
}
