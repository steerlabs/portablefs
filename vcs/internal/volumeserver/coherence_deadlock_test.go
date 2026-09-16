package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

type cv2ReservationResult struct {
	reservation *DelegationReservation
	err         error
}

type cv2GuardResult struct {
	guard *DataGuard
	err   error
}

func cv2WaitForRequestQueue(t *testing.T, c *CoherenceCoordinator, want int) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if got := c.requests.queued(); got == want {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("delegation request queue = %d, want %d", c.requests.queued(), want)
		}
	}
}

func cv2ReceiveReservation(t *testing.T, result <-chan cv2ReservationResult) *DelegationReservation {
	t.Helper()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.reservation
	case <-time.After(5 * time.Second):
		t.Fatal("delegation reservation did not progress")
		return nil
	}
}

func cv2ReceiveGuard(t *testing.T, result <-chan cv2GuardResult) *DataGuard {
	t.Helper()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.guard
	case <-time.After(5 * time.Second):
		t.Fatal("data guard did not progress")
		return nil
	}
}

func cv2ChangePositionSince(c *CoherenceCoordinator, after uint64, kind ChangeKind, identity [16]byte) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	start := after + 1
	if start < c.first {
		start = c.first
	}
	for position := start; position <= c.position; position++ {
		event := c.log[(position-1)%uint64(len(c.log))]
		if event.Kind == StreamChange && event.Change.Kind == kind && event.Change.Identity == identity {
			return position
		}
	}
	return 0
}

func TestCoherenceReservedReadDrainsBeforeGrant(t *testing.T) {
	t.Run("ReserveNew", func(t *testing.T) {
		c, _ := cv2Coordinator(t)
		holder := cv2Subscribe(t, c, 1)
		reader := cv2Subscribe(t, c, 2)
		identity := [16]byte{0x31}

		reservation, err := c.ReserveNew(holder, identity)
		if err != nil {
			t.Fatal(err)
		}
		guard, err := c.DataConsumed(t.Context(), reader, identity)
		if err != nil {
			t.Fatal(err)
		}
		cv2Wait(t, c, func() bool { return reservation.record.readers == 1 })

		granted := make(chan error, 1)
		go func() { _, err := reservation.Grant(t.Context()); granted <- err }()
		cv2AckAll(t, c, reader)
		cv2Wait(t, c, func() bool { return reservation.record.closingReaders })
		select {
		case err := <-granted:
			t.Fatalf("grant passed a pinned reserved read: %v", err)
		default:
		}

		guard.Release()
		if err := cv2Result(t, granted); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("queued read observes Reserve", func(t *testing.T) {
		c, _ := cv2Coordinator(t)
		holder := cv2Subscribe(t, c, 1)
		reader := cv2Subscribe(t, c, 2)
		identity := [16]byte{0x32}

		// Hold the identity turn, then place Reserve ahead of a read. When the
		// turn opens, Reserve installs its record while the read is still queued.
		// The read must observe that transition and use a reader pin instead of
		// waiting behind the reservation whose withdrawal needs it to finish.
		blocker, err := c.DataConsumed(t.Context(), reader, identity)
		if err != nil {
			t.Fatal(err)
		}
		reserved := make(chan cv2ReservationResult, 1)
		go func() {
			reservation, err := c.Reserve(t.Context(), holder, identity)
			reserved <- cv2ReservationResult{reservation: reservation, err: err}
		}()
		cv2WaitForRequestQueue(t, c, 1)
		read := make(chan cv2GuardResult, 1)
		go func() {
			guard, err := c.DataConsumed(t.Context(), reader, identity)
			read <- cv2GuardResult{guard: guard, err: err}
		}()
		cv2WaitForRequestQueue(t, c, 2)

		blocker.Release()
		reservation := cv2ReceiveReservation(t, reserved)
		guard := cv2ReceiveGuard(t, read)
		cv2Wait(t, c, func() bool { return reservation.record.readers == 1 })

		granted := make(chan error, 1)
		go func() { _, err := reservation.Grant(t.Context()); granted <- err }()
		cv2AckAll(t, c, reader)
		cv2Wait(t, c, func() bool { return reservation.record.closingReaders })
		select {
		case err := <-granted:
			t.Fatalf("grant passed the queued read pin: %v", err)
		default:
		}

		guard.Release()
		if err := cv2Result(t, granted); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCoherenceRecallSuppressesCacheModeUpgrade(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	identity := [16]byte{0x41}
	if cacheable, err := c.OpenCacheCapable(peer, identity); !cacheable || err != nil {
		t.Fatalf("OpenCacheCapable = %t, %v", cacheable, err)
	}
	grant := cv2Grant(t, c, holder, identity, peer)
	if grant.Mode != DelegationWritethrough {
		t.Fatalf("grant mode = %v, want writethrough", grant.Mode)
	}
	cv2AckAll(t, c, holder)
	cv2AckAll(t, c, peer)

	recalled := make(chan error, 1)
	go func() { recalled <- c.Recall(t.Context(), identity) }()
	event := cv2Event(t, c, holder, StreamRecall)
	c.mu.Lock()
	beforeClose := c.position
	c.mu.Unlock()
	if err := c.CloseCacheCapable(peer, identity); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	afterClose := c.position
	mode := c.delegations[identity].grant.Mode
	c.mu.Unlock()
	if mode != DelegationFull {
		t.Fatalf("internal recalling mode = %v, want full", mode)
	}
	if afterClose != beforeClose {
		t.Fatalf("peer close published event at %d during recall; position was %d", afterClose, beforeClose)
	}

	cv2CutAck(t, c, holder, event, 0)
	if err := cv2Result(t, recalled); err != nil {
		t.Fatal(err)
	}
}

func TestCoherenceRecallTimeoutPublishesReleaseAfterFlushEnd(t *testing.T) {
	c, clock := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	identity := [16]byte{0x51}
	grant := cv2Grant(t, c, holder, identity)
	cv2AckAll(t, c, holder)
	pin, err := c.BeginFlush(holder, identity, grant.ID, grant.Generation)
	if err != nil {
		t.Fatal(err)
	}

	recalled := make(chan error, 1)
	go func() { recalled <- c.Recall(t.Context(), identity) }()
	recall := cv2Event(t, c, holder, StreamRecall)
	clock.waitForTimers(t, 1)
	clock.Advance(DelegationRecallBudget)
	cv2Wait(t, c, func() bool {
		record := c.delegations[identity]
		return record != nil && record.retired && record.active == 1
	})
	if position := cv2ChangePositionSince(c, recall.Position, DelegationReleased, identity); position != 0 {
		t.Fatalf("release published at %d while flush remained pinned", position)
	}
	select {
	case err := <-recalled:
		t.Fatalf("recall returned before the pinned flush ended: %v", err)
	default:
	}

	dataPosition := c.OnCommit([]ChangeEntry{{Kind: DataChanged, Identity: identity, VolumeVersion: 9}})
	if position := cv2ChangePositionSince(c, recall.Position, DelegationReleased, identity); position != 0 {
		t.Fatalf("release published at %d before flush End", position)
	}
	pin.End(9)
	if err := cv2Result(t, recalled); err != nil {
		t.Fatal(err)
	}
	releasePosition := cv2ChangePositionSince(c, recall.Position, DelegationReleased, identity)
	if releasePosition <= dataPosition {
		t.Fatalf("release position = %d, want after data position %d", releasePosition, dataPosition)
	}
}

func TestCoherenceConflictingRequestCancellationPreservesFIFOAndDisjointProgress(t *testing.T) {
	c, _ := cv2Coordinator(t)
	holder := cv2Subscribe(t, c, 1)
	x, y := [16]byte{0x61}, [16]byte{0x62}
	cv2Grant(t, c, holder, x)
	cv2AckAll(t, c, holder)

	broken := make(chan error, 1)
	go func() { broken <- c.BreakForRead(t.Context(), x) }()
	breakEvent := cv2Event(t, c, holder, StreamBreakForRead)

	cancelContext, cancel := context.WithCancel(t.Context())
	canceled := make(chan error, 1)
	go func() { canceled <- c.Recall(cancelContext, x) }()
	cv2WaitForRequestQueue(t, c, 1)
	recalled := make(chan error, 1)
	go func() { recalled <- c.Recall(t.Context(), x) }()
	cv2WaitForRequestQueue(t, c, 2)

	// A blocked and a canceled request for x must not occupy y's lane.
	if err := c.BreakForRead(t.Context(), y); err != nil {
		t.Fatalf("disjoint request: %v", err)
	}
	c.mu.Lock()
	positionBeforeBreakAck := c.position
	c.mu.Unlock()
	if positionBeforeBreakAck != breakEvent.Position {
		t.Fatalf("conflicting recall overtook break: position = %d, break = %d", positionBeforeBreakAck, breakEvent.Position)
	}

	cancel()
	if err := cv2Result(t, canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation = %v, want context.Canceled", err)
	}
	cv2WaitForRequestQueue(t, c, 1)
	cv2CutAck(t, c, holder, breakEvent, 0)
	if err := cv2Result(t, broken); err != nil {
		t.Fatal(err)
	}

	recallEvent := cv2Event(t, c, holder, StreamRecall)
	if recallEvent.Position <= breakEvent.Position {
		t.Fatalf("recall position = %d, want after break %d", recallEvent.Position, breakEvent.Position)
	}
	cv2CutAck(t, c, holder, recallEvent, 0)
	if err := cv2Result(t, recalled); err != nil {
		t.Fatal(err)
	}
}
