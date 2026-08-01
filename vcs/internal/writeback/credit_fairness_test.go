package writeback

import (
	"testing"
)

// TestFastPathCannotBargePastAWaiterItRacedWith is the fairness property at its
// weakest point: the CONTENDED fast path.
//
// The uncontended case is obvious — one look at a non-empty queue and the fast
// path steps aside. The case that matters is the one where the fast path loses
// its CAS and retries. If the queue were consulted only once, before the loop,
// that retry would commit an admission decided against a queue snapshot taken
// before a waiter arrived: a flood of small arrivals could each observe an empty
// queue, race, and keep committing while the waiter they raced with is still in
// line. That is exactly the starvation the FIFO exists to prevent, and it is
// invisible to a test that only exercises the uncontended path.
//
// The seam lands a waiter in the one window where it can be missed: after the
// debt snapshot, before the CAS. The CAS then fails (the seam also moves debt),
// so the caller must re-examine the queue before committing anything.
func TestFastPathCannotBargePastAWaiterItRacedWith(t *testing.T) {
	c := newTestCredits(t, 512<<20)

	calls := 0
	creditFastPathCAS = func() {
		calls++
		if calls > 1 {
			return
		}
		// A waiter joins the queue, and an unrelated admission moves debt so
		// this caller's snapshot is stale and its CAS fails.
		c.mu.Lock()
		c.queue = append(c.queue, &creditWaiter{want: 1 << 20, ready: make(chan struct{}, 1)})
		c.waiting.Store(int64(len(c.queue)))
		c.mu.Unlock()
		c.debt.Add(1)
	}
	t.Cleanup(func() { creditFastPathCAS = nil })

	if c.tryFast(1 << 20) {
		t.Fatalf("the fast path barged past a waiter that queued while it was retrying its CAS")
	}
	if calls < 1 {
		t.Fatalf("the CAS seam never ran (%d calls); the test proved nothing", calls)
	}
	// Only the seam's own byte is charged: the barging admission never happened.
	if got := c.debt.Load(); got != 1 {
		t.Fatalf("debt %d after a refused fast-path admission, want 1 (the seam's own byte)", got)
	}
}
