package writeback

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestLaneChangedUnwindIsCounted pins the door the brief called "the big one".
//
// It is counted at the point the ENGINE produces it, which is the only place it
// is a fact rather than an inference: the frontend sees an errno and a retry,
// and cannot tell an unwind driven by saturation from one driven by a genuine
// recall. Counting it here is also what makes a NON-terminating unwind visible
// — DoorLaneChanged and DoorForced should advance together, and a run where the
// first outpaces the second is a frontend that unwound and never came back.
func TestLaneChangedUnwindIsCounted(t *testing.T) {
	pinCreditTimings(t, 100*time.Millisecond, 25*time.Second, 30*time.Second)
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("the fixture took no delegation over d/f")
	}
	exhaustCreditLedger(t, f.e)

	before := f.e.LaneRouting()
	// A RESOLVED delegated write against an exhausted gate is the exact input
	// that produces the unwind (engine.go, admitDataBytes).
	opCtx := WithResolvedLane(ctx, LaneDelegated)
	_, _, err := f.e.WriteAt(opCtx, "d/f", 0, make([]byte, 256<<10))
	if !errors.Is(err, ErrLaneChanged) {
		t.Fatalf("a resolved delegated write against an exhausted gate returned %v, want ErrLaneChanged", err)
	}
	after := f.e.LaneRouting()
	if after.Ops[DoorLaneChanged] != before.Ops[DoorLaneChanged]+1 {
		t.Fatalf("the unwind was not counted: %d -> %d",
			before.Ops[DoorLaneChanged], after.Ops[DoorLaneChanged])
	}
	if after.Bytes[DoorLaneChanged] <= before.Bytes[DoorLaneChanged] {
		t.Fatal("the unwind counted no bytes; a door with an op count and no byte count " +
			"cannot say how much of a flood went through it")
	}
}

// TestRoutingTallyDoesNotDoubleCountTheUnwind guards the one arithmetic trap in
// the report. DoorLaneChanged and DoorForced are the SAME bytes seen at both
// ends of one unwind, so a total that sums every door overstates the authority
// lane by exactly the unwound traffic — which is how a routing report talks
// itself into believing the unwind dominates.
func TestRoutingTallyDoesNotDoubleCountTheUnwind(t *testing.T) {
	var c laneCounters
	c.note(DoorLaneChanged, 1000)
	c.note(DoorForced, 1000)
	c.note(DoorUncovered, 500)
	c.noteDelegated(2500)
	r := c.snapshot()
	if got := r.AuthorityBytes(); got != 1500 {
		t.Fatalf("AuthorityBytes = %d; one 1000-byte unwind plus a 500-byte uncovered write "+
			"is 1500 authority bytes, not %d — the unwind's two halves are being summed", got, got)
	}
	if got := r.EscapedBytes(); got != 1000 {
		t.Fatalf("EscapedBytes = %d, want 1000 (the forced pass only; an uncovered write is "+
			"structural and did not escape anything)", got)
	}
	if got := r.AuthorityShare(); got < 0.37 || got > 0.38 {
		t.Fatalf("AuthorityShare = %.4f, want 1500/(1500+2500) = 0.375", got)
	}
}
