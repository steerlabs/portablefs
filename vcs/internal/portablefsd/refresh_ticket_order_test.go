package portablefsd

// ── FINDING 1 (ROUND 14): FAIRNESS THAT ONLY RUNS ONE WAY IS NOT FAIRNESS ───
//
// The refresh intent gave the refresh a claim it never had, and it gave it
// ONLY to the refresh. A size mutation that finds an intent installed waits on
// a channel; nothing anywhere records that it is waiting, and nothing obliges
// the item to be handed to it when the intent is released.
//
// So the mutation can be barged indefinitely, and not by a race that needs bad
// luck — by the ordinary shape of a refresh stream:
//
//	R1 holds the intent on the item;
//	W waits on intent.done, holding no lock at all;
//	R2 is parked on the per-stripe kernel-refresh gate, waiting to start;
//	R1 releases: it deletes its intent, closes done — W is now runnable — and
//	  then releases the gate, which wakes R2 directly;
//	R2 reaches a.mu and installs the next intent before W's woken goroutine
//	  reaches a.mu at all. W queues again.
//
// Repeat for W's whole operation deadline and W returns EINTR having attempted
// nothing. Under sustained peer invalidations — which is exactly when refresh
// passes stream — that is livelock by priority.
//
// ── WHY THESE TESTS DRIVE THE INTERLEAVING INSTEAD OF RACING FOR IT ─────────
//
// Left to the scheduler, W usually wins: R2 and W are both woken by a channel,
// W was queued on it first, and close(2) makes its waiters runnable in the order
// they blocked. That accidental ordering is the whole problem — it is a property
// of the runtime, not of the protocol, and it disappears the moment R2 is
// waiting somewhere else (the kernel-refresh gate, which is exactly where the
// next pass in a stream waits).
//
// So the arrival of the next refresh is placed EXPLICITLY between W's queueing
// and W's retry, which is what a real gate hand-off does and what no amount of
// re-running proves on its own. The fix is one explicit FIFO ticket queue per
// item covering BOTH refresh intents and mutation reservations
// (itemturnstile.go): arrival order is recorded under a.mu when the ticket is
// taken, and the item is handed to the head of that queue inside the SAME a.mu
// hold that gives it up.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// refreshStream stands in for the queue of refresh passes waiting on the
// per-stripe kernel-refresh gate: each pass takes the item, HOLDS it, and gives
// it up only when the next pass is asked for.
type refreshStream struct {
	a       *attach
	itemID  uint64
	ask     chan struct{}
	landed  chan struct{}
	release chan struct{}
	stop    chan struct{}
	wg      sync.WaitGroup
	passes  atomic.Int64
	failed  atomic.Int64
}

func newRefreshStream(t *testing.T, a *attach, itemID uint64) *refreshStream {
	t.Helper()
	s := &refreshStream{
		a:       a,
		itemID:  itemID,
		ask:     make(chan struct{}),
		landed:  make(chan struct{}),
		release: make(chan struct{}),
		stop:    make(chan struct{}),
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.stop:
				return
			case <-s.ask:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			done, err := s.a.acquireRefreshIntent(ctx, s.itemID)
			cancel()
			if err != nil {
				s.failed.Add(1)
				continue
			}
			s.passes.Add(1)
			select {
			case s.landed <- struct{}{}:
			case <-s.stop:
				done()
				return
			}
			select {
			case <-s.release:
			case <-s.stop:
			}
			done()
		}
	}()
	t.Cleanup(func() {
		close(s.stop)
		s.wg.Wait()
	})
	return s
}

// next gives up the pass that currently holds the item and lets the following
// one take it, waiting — BOUNDED — for it to land.
//
// The bound is what makes the same call meaningful on both sides of the fix.
// Before it, the next pass lands every single time, because nothing records
// that a mutation is already waiting. After it, a pass that asks for the item
// after a mutation has queued cannot be ahead of it, and the wait simply
// expires.
func (s *refreshStream) next(holding func(), within time.Duration) bool {
	if !s.giveUp(holding, within) {
		return false
	}
	select {
	case s.ask <- struct{}{}:
	case <-time.After(within):
		return false
	}
	select {
	case <-s.landed:
		return true
	case <-time.After(within):
		return false
	}
}

// giveUp releases whatever holds the item now — the caller's own intent, or the
// stream's current pass — and asks for nothing further.
func (s *refreshStream) giveUp(holding func(), within time.Duration) bool {
	if holding != nil {
		holding()
		return true
	}
	select {
	case s.release <- struct{}{}:
		return true
	case <-time.After(within):
		return false
	}
}

func (a *attach) reservationsForTest(itemID uint64) int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sizeMutationReservations[itemID]
}

// TestRefreshBargeCannotStarveAQueuedSizeMutation is the finding's interleaving,
// sustained: every time the queued mutation is woken, the next refresh pass in
// the stream takes the item before the mutation can retry for it.
//
// Nothing here is pathological — it is one gate hand-off per wake-up, which is
// what a stream of peer invalidations produces on its own. The mutation must
// still get its turn; without a queue it spends its entire operation deadline
// and returns EINTR having attempted nothing.
func TestRefreshBargeCannotStarveAQueuedSizeMutation(t *testing.T) {
	a := &attach{}
	const item = uint64(0x7C11)

	first, err := a.acquireRefreshIntent(context.Background(), item)
	if err != nil {
		t.Fatalf("the first refresh could not take an idle item: %v", err)
	}
	stream := newRefreshStream(t, a, item)

	var holding func() = first
	var wakes atomic.Int64
	a.testSizeMutationQueued = func(uint64) {
		wakes.Add(1)
		stream.next(holding, 2*time.Second)
		holding = nil
	}

	// A real frontend deadline. Its expiry is the failure the finding describes:
	// EINTR for a request that was never given the chance to attempt anything.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	release, eno := a.reserveSizeMutation(ctx, item)
	if eno != 0 {
		t.Fatalf("a size mutation queued for the item and was woken %d times "+
			"without ever being given it; %d later refresh passes took it instead, "+
			"and the mutation failed with errno=%d after its whole operation "+
			"deadline\n"+
			"queued refreshes barge past queued mutations, so sustained peer "+
			"invalidations livelock every writer on the item by priority",
			wakes.Load(), stream.passes.Load(), eno)
	}
	release()
}

// TestItemTicketsAreServedInArrivalOrder is the ticket order itself, at its
// smallest: refresh, mutation, refresh — arriving in that order.
//
// The third arrival is placed after the mutation has queued and before the
// mutation is woken, which is precisely where the next pass off the
// kernel-refresh gate lands. The proof is taken at the instant that third
// arrival takes the item: the mutation that queued BEFORE it must already hold
// its reservation.
func TestItemTicketsAreServedInArrivalOrder(t *testing.T) {
	a := &attach{}
	const item = uint64(0x7C12)

	first, err := a.acquireRefreshIntent(context.Background(), item)
	if err != nil {
		t.Fatalf("the first refresh could not take an idle item: %v", err)
	}
	stream := newRefreshStream(t, a, item)

	var (
		once      sync.Once
		landed    atomic.Bool
		reserved  atomic.Int64
		queuedFor atomic.Int64
	)
	a.testSizeMutationQueued = func(uint64) {
		queuedFor.Add(1)
		once.Do(func() {
			// EXACTLY ONE later arrival, placed where the next pass off the
			// kernel-refresh gate lands: after the mutation has queued and
			// before it can retry. Whether it manages to take the item is the
			// question; either way the protocol has already decided the order by
			// the time this returns, so read the DECISION rather than racing the
			// mutation's own goroutine for it.
			landed.Store(stream.next(first, 300*time.Millisecond))
			reserved.Store(int64(a.reservationsForTest(item)))
			// And let the item go, so a violated order is reported as the order
			// it is rather than as the mutation's deadline expiring.
			go func() {
				time.Sleep(50 * time.Millisecond)
				stream.giveUp(nil, 2*time.Second)
			}()
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, eno := a.reserveSizeMutation(ctx, item)
	if eno != 0 {
		t.Fatalf("the size mutation was refused with errno=%d after queueing %d "+
			"time(s)", eno, queuedFor.Load())
	}
	release()

	if reserved.Load() == 0 {
		t.Fatalf("a refresh that arrived AFTER a size mutation had already queued "+
			"for the item was given it first (took the item: %v; the mutation "+
			"queued %d time(s))\n"+
			"service order is not arrival order, so a stream of refresh passes "+
			"keeps a writer waiting for its whole deadline",
			landed.Load(), queuedFor.Load())
	}
}

// TestSustainedRefreshStreamStillYieldsTheItemToAQueuedMutation is the
// production shape: real exact-refresh passes, through the per-stripe kernel
// refresh gate, one after another for as long as peer invalidations keep
// arriving. A writer that arrives in the middle of that stream must get its
// turn, and must get it after a BOUNDED number of passes rather than eventually.
func TestSustainedRefreshStreamStillYieldsTheItemToAQueuedMutation(t *testing.T) {
	a, _, itemID, _ := newMutationSeqAttach(t)
	a.mountPath = "/unused-test-mount"
	// A refresh's ftruncate(2) is fast, not instantaneous, and the pin it
	// brackets is held for the whole of it — which is what makes a stream of
	// passes something a writer actually has to queue behind.
	a.testRefreshKernelFile = func(
		_ string, _ string, _ uint64, _ int64, arm func() (func(), error),
	) (kernelRefreshOutcome, error) {
		disarm, err := arm()
		if err != nil {
			return kernelRefreshRetry, err
		}
		time.Sleep(200 * time.Microsecond)
		disarm()
		return kernelRefreshApplied, nil
	}

	const streams = 4
	stop := make(chan struct{})
	var passes atomic.Int64
	var stream sync.WaitGroup
	for i := 0; i < streams; i++ {
		stream.Add(1)
		go func() {
			defer stream.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := a.exactKernelRefreshMode(ctx, itemID, true); err == nil {
					passes.Add(1)
				}
				cancel()
			}
		}()
	}
	t.Cleanup(func() {
		close(stop)
		stream.Wait()
	})

	// Let the stream reach steady state so the mutation really does arrive into
	// a busy item rather than an idle one.
	time.Sleep(100 * time.Millisecond)

	var atQueue atomic.Int64
	a.testSizeMutationQueued = func(uint64) {
		atQueue.CompareAndSwap(-1, passes.Load())
	}

	// Several writers, one after another. A mutation that finds the item free is
	// served on the spot and proves nothing; the bound below is asserted for
	// every one that actually had to queue.
	waiters := 0
	for i := 0; i < 20; i++ {
		atQueue.Store(-1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		release, eno := a.reserveSizeMutation(ctx, itemID)
		waited := time.Since(start)
		cancel()
		if eno != 0 {
			t.Fatalf("a size mutation arriving into a sustained refresh stream was "+
				"refused with errno=%d after %s: the stream never yielded the item",
				eno, waited)
		}
		queuedAt := atQueue.Load()
		served := passes.Load() - queuedAt
		release()
		if queuedAt < 0 {
			continue
		}
		waiters++
		// Every pass that had already taken its ticket when this mutation
		// arrived is entitled to run first, and one more may already be holding
		// the item. Any more than that is a pass that arrived LATER and was
		// served EARLIER.
		if max := int64(streams + 1); served > max {
			t.Fatalf("%d refresh passes completed after the size mutation queued "+
				"(at most %d could have been ahead of it): later arrivals were "+
				"served before an earlier one, which is starvation with extra steps",
				served, max)
		}
	}
	if waiters == 0 {
		t.Skip("no size mutation ever had to queue: the stream was not busy enough " +
			"for this test to say anything")
	}
}

// TestAbandonedTicketDoesNotWedgeTheItemQueue is the cancellation half. A
// waiter whose context dies leaves the queue; it must not leave the item's turn
// with it.
func TestAbandonedTicketDoesNotWedgeTheItemQueue(t *testing.T) {
	a := &attach{}
	const item = uint64(0x7C13)

	held, err := a.acquireRefreshIntent(context.Background(), item)
	if err != nil {
		t.Fatalf("the first refresh could not take an idle item: %v", err)
	}

	// A mutation that queues and then dies on its own deadline.
	dying, cancelDying := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelDying()
	abandoned := make(chan int32, 1)
	queued := make(chan struct{})
	var once sync.Once
	a.testSizeMutationQueued = func(uint64) { once.Do(func() { close(queued) }) }
	go func() {
		release, eno := a.reserveSizeMutation(dying, item)
		if release != nil {
			release()
		}
		abandoned <- eno
	}()
	<-queued

	// A second mutation queues behind it and must be served once the item is
	// free, even though the ticket ahead of it never will be.
	survivor := make(chan int32, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		release, eno := a.reserveSizeMutation(ctx, item)
		if release != nil {
			release()
		}
		survivor <- eno
	}()

	select {
	case eno := <-abandoned:
		if eno == 0 {
			t.Fatal("a size mutation whose context died was still granted the item")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a size mutation whose context died never returned")
	}

	held()
	select {
	case eno := <-survivor:
		if eno != 0 {
			t.Fatalf("the mutation queued behind an abandoned ticket failed with "+
				"errno=%d: a cancelled waiter wedged the item's queue", eno)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the mutation queued behind an abandoned ticket was never served: " +
			"a cancelled waiter wedged the item's queue")
	}

	a.mu.Lock()
	stuck := len(a.refreshIntents) + len(a.sizeMutationReservations)
	a.mu.Unlock()
	if stuck != 0 {
		t.Fatalf("the item was left carrying %d claim(s) after every waiter "+
			"finished", stuck)
	}
	if queued := a.itemTicketsQueued(item); queued != 0 {
		t.Fatalf("the item's queue still holds %d ticket(s) after every waiter "+
			"finished", queued)
	}
}
