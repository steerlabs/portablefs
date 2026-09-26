package volumeserver

import (
	"context"
	"errors"
	"testing"
)

func TestOrderedFlushWaitsForAcceptedSequenceDespiteArrivalOrder(t *testing.T) {
	c, clock := cv2Coordinator(t)
	token := cv2Subscribe(t, c, 1)
	grant := cv2Grant(t, c, token, [16]byte{9})
	second, err := c.BeginOrderedFlush(token, grant.ID, grant.Generation, 2, MutationID{Slot: 1, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Abort()
	ready := make(chan error, 1)
	go func() { ready <- second.Wait(t.Context()) }()
	clock.waitForTimers(t, 1)
	select {
	case err := <-ready:
		t.Fatalf("successor overtook absent predecessor: %v", err)
	default:
	}
	first, err := c.BeginOrderedFlush(token, grant.ID, grant.Generation, 1, MutationID{Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Abort()
	if err := first.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ready:
		t.Fatalf("successor overtook applying predecessor: %v", err)
	default:
	}
	first.Complete()
	if err := cv2Result(t, ready); err != nil {
		t.Fatal(err)
	}
	second.Complete()
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.delegationsByID[grant.ID]
	if r.flushSequence != 2 || r.active != 0 || len(r.ordered) != 0 || r.applied != 0 {
		t.Fatalf("definite no-apply sequence accounting: %+v", r)
	}
}

func TestOrderedFlushUnrecordedRefusalRetiresGrantAndWakesSuccessors(t *testing.T) {
	c, clock := cv2Coordinator(t)
	token := cv2Subscribe(t, c, 1)
	grant := cv2Grant(t, c, token, [16]byte{9})
	first, err := c.BeginOrderedFlush(token, grant.ID, grant.Generation, 1, MutationID{Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.BeginOrderedFlush(token, grant.ID, grant.Generation, 2, MutationID{Slot: 1, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- second.Wait(t.Context()) }()
	clock.waitForTimers(t, 1)
	first.Abort()
	if err := cv2Result(t, done); !errors.Is(err, ErrDelegationStale) {
		t.Fatalf("gap did not fail closed: %v", err)
	}
	second.Abort()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.delegationsByID[grant.ID] != nil || c.delegations[grant.Identity] != nil || c.subscribers[token.Session].loss != 1 {
		t.Fatal("aborted wave stranded authority or double-counted loss")
	}
}

func TestOrderedFlushWindowAndRetirement(t *testing.T) {
	for _, edge := range []string{"cold", "horizon", "recall-deadline"} {
		t.Run(edge, func(t *testing.T) {
			c, clock := cv2Coordinator(t)
			token := cv2Subscribe(t, c, 1)
			grant := cv2Grant(t, c, token, [16]byte{9})
			if _, err := c.BeginOrderedFlush(token, grant.ID, grant.Generation, OrderedFlushWindow+1, MutationID{Sequence: 1}); !errors.Is(err, ErrDelegationAck) {
				t.Fatal("unbounded pending order admitted", err)
			}
			second, err := c.BeginOrderedFlush(token, grant.ID, grant.Generation, 2, MutationID{Sequence: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer second.Abort()
			done := make(chan error, 1)
			go func() { done <- second.Wait(t.Context()) }()
			clock.waitForTimers(t, 1)
			var recall chan error
			switch edge {
			case "cold":
				if _, err := c.Subscribe(token.Session); err != nil {
					t.Fatal(err)
				}
			case "horizon":
				clock.Advance(SubscriptionTTL)
			case "recall-deadline":
				recall = make(chan error, 1)
				go func() { recall <- c.Recall(context.Background(), grant.Identity) }()
				cv2Event(t, c, token, StreamRecall)
				clock.Advance(DelegationRecallBudget)
			}
			if err := cv2Result(t, done); !errors.Is(err, ErrDelegationStale) {
				t.Fatalf("retired sequence waiter=%v", err)
			}
			second.Abort()
			if recall != nil {
				if err := cv2Result(t, recall); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
