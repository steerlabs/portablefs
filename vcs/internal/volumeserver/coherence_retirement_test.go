package volumeserver

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestCoherenceDelegationChurnRetainsOnlyLiveRecordsAndScalarGeneration(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	var first Delegation
	for i := uint64(1); i <= 1024; i++ {
		var identity [16]byte
		binary.LittleEndian.PutUint64(identity[:], i)
		grant := cv2Grant(t, c, holder, identity)
		if i == 1 {
			first = grant
		}
		if _, err := c.ReleaseBatch(holder, []Delegation{grant}); err != nil {
			t.Fatal(err)
		}
		cv2AckAll(t, c, holder)
	}
	c.mu.Lock()
	subscriber := c.subscribers[holder.Session]
	empty := len(c.delegations) == 0 && len(subscriber.held) == 0 && len(c.cacheHandles) == 0 && len(subscriber.handles) == 0
	generation := c.nextDelegation
	c.mu.Unlock()
	if !empty || generation != 1024 {
		t.Fatalf("retention empty=%v generation=%d", empty, generation)
	}
	next := cv2Grant(t, c, holder, first.Identity)
	if next.ID <= first.ID || next.Generation <= first.Generation {
		t.Fatal("retired identity revived its old grant")
	}
}

func TestCoherenceDataConsumedWakesWhenCanceledRecallRetiresGeneration(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	reader := cv2Subscribe(t, c, 2)
	identity := [16]byte{1}
	cv2Grant(t, c, holder, identity, reader)
	ctx, cancel := context.WithCancel(t.Context())
	recall := make(chan error, 1)
	go func() { recall <- c.Recall(ctx, identity) }()
	event := cv2Event(t, c, holder, StreamRecall)
	guards := make(chan *DataGuard, 1)
	reads := make(chan error, 1)
	go func() { guard, err := c.DataConsumed(t.Context(), reader, identity); guards <- guard; reads <- err }()
	select {
	case <-guards:
		t.Fatal("reader passed active recall")
	case <-time.After(10 * time.Millisecond):
	}
	cancel()
	cv2CutAck(t, c, holder, event, 0)
	if err := cv2Result(t, recall); !errors.Is(err, context.Canceled) {
		t.Fatalf("recall=%v", err)
	}
	select {
	case guard := <-guards:
		if err := <-reads; err != nil {
			t.Fatal(err)
		}
		guard.Release()
	case <-time.After(time.Second):
		t.Fatal("reader stranded behind canceled recall")
	}
	if _, ok := c.LookupDelegation(identity); ok {
		t.Fatal("canceled recall revived ownership")
	}
}
