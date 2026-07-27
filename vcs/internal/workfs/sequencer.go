package workfs

import (
	"fmt"
	"sync"
)

// ErrDurabilityUnknown is declared in control.go (shared by both stores).

// mutationSequencer enforces durable-before-visible with strict LSN-order
// application:
//
//  1. a writer RESERVES a contiguous WAL range (buffered append under fs.mu);
//  2. it waits for the range's durability barrier (group-commit fsync +
//     synchronous replication) with no lock held;
//  3. it waits for its TURN (all lower LSNs applied), applies the range to the
//     visible tree under fs.mu, publishes the invalidation batch, and only then
//     replies.
//
// A registered range is never abandoned: the reserving goroutine proceeds
// unconditionally through apply (there is no cancellation point between
// reservation and application), so the turn chain always advances. A
// durability failure poisons the sequencer instead — nothing above the applied
// cursor is ever applied on this authority again, and every waiter is released
// with ErrDurabilityUnknown so the node can fence and fail over.
type mutationSequencer struct {
	mu      sync.Mutex
	cond    *sync.Cond
	applied uint64 // next LSN to apply == exclusive upper bound of applied LSNs
	poison  error  // non-nil once the durability invariant broke
}

func (s *mutationSequencer) init(applied uint64) {
	s.cond = sync.NewCond(&s.mu)
	s.applied = applied
}

// appliedWatermark is the exclusive upper bound of applied LSNs. Every applied
// record is durable (apply happens only after the durability barrier), so this
// is also the exact LiveRevision cursor.
func (s *mutationSequencer) appliedWatermark() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied
}

// waitTurn blocks until every LSN below firstSeq has been applied (or the
// sequencer is poisoned).
func (s *mutationSequencer) waitTurn(firstSeq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.poison == nil && s.applied < firstSeq {
		s.cond.Wait()
	}
	if s.poison != nil {
		return s.poison
	}
	if s.applied != firstSeq {
		// A lower LSN was skipped or applied twice — an invariant violation that
		// must never be papered over. Poison while holding the condition lock so
		// every current/future waiter observes one fenced UNKNOWN outcome.
		cause := fmt.Errorf("vcs: sequencer turn corrupted: applied=%d want=%d", s.applied, firstSeq)
		s.poison = fmt.Errorf("%w: %v", ErrDurabilityUnknown, cause)
		s.cond.Broadcast()
		return s.poison
	}
	return nil
}

// advance marks the range ending at endSeq (exclusive) applied and wakes the
// next writer in LSN order.
func (s *mutationSequencer) advance(endSeq uint64) {
	s.mu.Lock()
	if endSeq > s.applied {
		s.applied = endSeq
	}
	s.mu.Unlock()
	s.cond.Broadcast()
}

// poisonWith marks the sequencer unusable (durability broke) and releases every
// waiter with ErrDurabilityUnknown.
func (s *mutationSequencer) poisonWith(cause error) {
	s.mu.Lock()
	if s.poison == nil {
		s.poison = fmt.Errorf("%w: %v", ErrDurabilityUnknown, cause)
	}
	s.mu.Unlock()
	s.cond.Broadcast()
}
