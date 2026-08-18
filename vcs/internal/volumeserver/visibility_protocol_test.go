package volumeserver

import (
	"context"
	"testing"
	"time"
)

func TestVisibilityAckRetryAfterNextPhaseIsPending(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	participant := SessionID{1}
	h.register(t, participant, testRepairBudget)
	h.resolve(t, participant, "retry")
	done := make(chan error, 1)
	go func() {
		done <- h.coordinator.Execute(context.Background(), SessionID{2}, MutationID{Slot: 3, Sequence: 4}, testMutationDependencies("retry"), testVisibilityPrepare("retry"), func() ([]VisibilityTarget, bool) {
			return testVisibilityTargets("retry"), true
		})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, participant)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.coordinator.Next(ctx, participant, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	// The PREPARE Ack response may have been lost even though COMPLETE is now
	// pending. Replaying that exact Ack must not fence the participant.
	if err := h.coordinator.Ack(participant, prepare.Cursor); err != nil {
		t.Fatalf("replayed PREPARE Ack: %v", err)
	}
	if err := h.coordinator.Ack(participant, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestVisibilityLateRegistrationStartsAtCurrentCompleteCursor(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	first := SessionID{1}
	h.register(t, first, testRepairBudget)
	h.resolve(t, first, "first", "second")
	done := make(chan error, 1)
	go func() {
		done <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1}, testMutationDependencies("first"), testVisibilityPrepare("first"), func() ([]VisibilityTarget, bool) {
			return testVisibilityTargets("first"), true
		})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	complete := runBarrier(t, h.coordinator, first, initialVisibilityCursor(t, h.coordinator, first))
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	late := SessionID{2}
	h.register(t, late, testRepairBudget)
	h.resolve(t, late, "second")
	initial, err := h.coordinator.InitialCursor(late)
	if err != nil {
		t.Fatal(err)
	}
	if initial != complete {
		t.Fatalf("late cursor = %+v, want %+v", initial, complete)
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 2}, testMutationDependencies("second"), testVisibilityPrepare("second"), func() ([]VisibilityTarget, bool) {
			return testVisibilityTargets("second"), true
		})
	}()
	next, err := h.coordinator.Next(ctx, late, initial)
	if err != nil {
		t.Fatal(err)
	}
	if next.Cursor != (VisibilityCursor{Sequence: initial.Sequence + 1, Phase: VisibilityPrepare}) {
		t.Fatalf("late participant first event = %+v", next.Cursor)
	}
	// A proven detach is enough to release this test participant; the first
	// participant completes the ordinary two-phase barrier.
	if err := h.coordinator.CleanDetach(late, testMountAbsence(time.Now())); err != nil {
		t.Fatal(err)
	}
	runBarrier(t, h.coordinator, first, complete)
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}
