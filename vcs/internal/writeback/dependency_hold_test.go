package writeback

// A DEPENDENCY HOLD IS NOT A STALL.
//
// The data lane may not offer a batch ahead of the namespace state its records
// were admitted behind (pendingRec.nsRequired, set from the namespace lane's
// appended tail at append time). While that dependency is unmet the data worker
// never dispatches, so it never reaches advance(), so laneQueue.lastProgress —
// which only ever moved on an authority watermark advance in the SAME lane —
// froze at the moment the first record was admitted.
//
// Everything downstream then read that frozen clock as evidence about the far
// end, and it is evidence about nothing of the sort:
//
//   - the watchdog latched f.degraded, which is STREAM-WIDE, so a lane-local
//     wait converted the healthy namespace lane's verdict too;
//   - laneStallVerdictLocked independently declared the data lane stalled from
//     the same frozen clock;
//   - StallVerdict is the engine's one stall answer, and clientcore's data gate
//     turns Stalled into ErrUplinkStalled, which creditErrno maps to EIO.
//
// So a mount whose uplink was demonstrably alive — the namespace lane applying
// batch after batch, on time — returned EIO on writes, because a lane that was
// correctly waiting its turn looked, from the outside, exactly like a lane
// nothing was ever going to apply again.
//
// The honest statement about a blocked lane is not "no progress"; it is "the
// lane it is waiting on is making progress". These tests pin both halves of
// that: the inheritance, and the fact that it is inheritance rather than an
// exemption.

import (
	"context"
	"testing"
	"time"
)

// pinNamespaceBatchBytes shrinks the namespace lane's request bound so that ONE
// namespace record is ONE flush.
//
// That is what makes these tests deterministic instead of timing races. The
// dependency has to stay unmet across more than a whole no-progress window
// while the namespace lane keeps advancing inside it, and the only way to hold
// a watermark N records short for a controlled span is to make the authority
// spend N releases getting there. Left at its production 1 MiB, a single
// namespace batch would apply every pending record at once and the hold would
// end before the window ever opened.
func pinNamespaceBatchBytes(t *testing.T, n int64) {
	t.Helper()
	old := nsFlushMaxBytes
	nsFlushMaxBytes = n
	t.Cleanup(func() { nsFlushMaxBytes = old })
}

// admitHeldDataBatch builds the shape both tests need: nsRecords namespace-lane
// records with NONE of them applied, followed by one data-lane record whose
// nsRequired is therefore the whole namespace backlog. The data lane cannot
// dispatch until the namespace watermark has walked all the way up.
//
// The order matters twice over. The namespace records come first so the data
// record's nsRequired names them; and the data record comes last so that no
// later namespace record is routed into the data lane by the scope-has-
// unapplied-data rule, which would put the thing we are watching in the lane we
// are watching it against.
func admitHeldDataBatch(t *testing.T, f *stallFixture, nsRecords int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < nsRecords-1; i++ {
		if _, _, err := f.e.Mkdir(ctx, "d/ns"+itoa(i), 0o755); err != nil {
			t.Fatalf("mkdir d/ns%d: %v", i, err)
		}
	}
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create d/f: handled=%v err=%v", handled, err)
	}
	if _, _, err := f.e.WriteAppend(ctx, "d/f", make([]byte, 4<<10)); err != nil {
		t.Fatalf("write d/f: %v", err)
	}

	nsPending, nsApplied := f.e.fl.laneStateForTest(StreamLaneNamespace)
	dataPending, _ := f.e.fl.laneStateForTest(StreamLaneData)
	if nsPending != nsRecords || nsApplied != 0 {
		t.Fatalf("namespace lane holds %d records at watermark %d, want %d unapplied: "+
			"the fixture's uplink is not shut", nsPending, nsApplied, nsRecords)
	}
	if dataPending != 1 {
		t.Fatalf("data lane holds %d records, want exactly the one bulk write", dataPending)
	}
	blocked, needed := f.e.fl.laneDependencyBlockedForTest(StreamLaneData)
	if !blocked {
		t.Fatalf("the data batch is not dependency-blocked (declares namespace watermark "+
			"%d): this fixture does not exercise the hold at all", needed)
	}
	if needed != uint64(nsRecords) {
		t.Fatalf("the data batch declares namespace watermark %d, want %d (the whole "+
			"unapplied namespace backlog)", needed, nsRecords)
	}
}

// TestDependencyBlockedDataLaneIsNotStalledWhileTheNamespaceLaneAdvances is the
// finding, at engine scope.
//
// The namespace lane is slow but unambiguously alive: one record applied per
// release, comfortably inside every no-progress window. The data batch sits
// behind it for more than two whole windows. Nothing about that is a stall —
// not on the data lane, whose turn has simply not come; not on the namespace
// lane, which is applying; and not stream-wide, where f.degraded would take the
// whole mount to EIO over one lane's queue discipline.
func TestDependencyBlockedDataLaneIsNotStalledWhileTheNamespaceLaneAdvances(t *testing.T) {
	const window = time.Second
	pinCreditTimings(t, creditWaitCap, creditDrainTarget, window)
	pinNamespaceBatchBytes(t, 1)
	f := newStallFixture(t, 1<<30)

	// Deep enough that the release cadence below cannot drain it: the hold must
	// outlast the assertion loop, or the loop stops proving anything.
	const nsRecords = 24
	admitHeldDataBatch(t, f, nsRecords)

	// Walk the namespace watermark up, one applied record per release, for well
	// over two windows. Each release is a real authority advance in the lane the
	// data batch names.
	start := time.Now()
	deadline := start.Add(5 * window / 2)
	releases := 0
	for time.Now().Before(deadline) {
		f.releaseOneFlush()
		releases++
		time.Sleep(window / 3)

		if v := f.e.fl.laneStallVerdict(StreamLaneData); v.Stalled {
			t.Fatalf("the data lane was declared STALLED after %s of a dependency hold, "+
				"with the namespace lane it is waiting on applying a record every %s "+
				"(%d released, watermark %d): a lane waiting its turn is not a lane "+
				"nothing will ever apply for",
				time.Since(start).Round(time.Millisecond),
				(window / 3).Round(time.Millisecond), releases, nsAppliedOf(f))
		}
		if v := f.e.fl.laneStallVerdict(StreamLaneNamespace); v.Stalled {
			t.Fatalf("the NAMESPACE lane was declared stalled while it was applying a "+
				"record every %s (%d released, watermark %d); the only way it can be is "+
				"through the stream-wide sticky flag, which the blocked data lane must "+
				"not latch", (window / 3).Round(time.Millisecond), releases, nsAppliedOf(f))
		}
		if f.e.fl.degradedForTest() {
			t.Fatalf("a lane-local dependency hold latched the STREAM-WIDE degraded flag "+
				"after %d namespace advances; every frontend on this mount now reports a "+
				"dead uplink", releases)
		}
		if v := f.e.StallVerdict(); v.Stalled {
			t.Fatalf("the engine's stream-wide verdict = %+v during a dependency hold; "+
				"this is the value clientcore's data gate turns into ErrUplinkStalled "+
				"and creditErrno turns into EIO", v)
		}
	}

	// The hold must still be the reason nothing shipped — otherwise the loop
	// above measured a drained stream rather than a held one.
	if blocked, needed := f.e.fl.laneDependencyBlockedForTest(StreamLaneData); !blocked {
		t.Fatalf("the dependency (namespace watermark %d) was met after %d releases; "+
			"the assertion loop stopped covering the hold before it finished", needed, releases)
	}
	f.auth.mu.Lock()
	held := f.auth.heldDataBatches
	f.auth.mu.Unlock()
	if held != 0 {
		t.Fatalf("the client offered %d data batches the authority had to hold with "+
			"EAGAIN; the whole point of the client-side predicate is that a held batch "+
			"never costs a round trip", held)
	}

	// And the hold is a hold, not a wedge: opening the uplink drains it.
	f.openUplink()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := f.e.DrainAll(ctx); err != nil {
		t.Fatalf("draining a stream that was only ever dependency-blocked: %v", err)
	}
}

// TestDependencyBlockedDataLaneStillStallsWhenTheNamespaceLaneStops is the
// anti-hole, and it is the reason the fix is INHERITANCE rather than an
// exemption.
//
// "A blocked lane is never stalled" would pass the test above and would be a
// hole big enough to drive the original wedge through: with the uplink dead the
// namespace lane stops applying, its watermark never reaches the data batch's
// nsRequired, and the data lane is blocked FOREVER. If blocked meant exempt,
// drainThrough on the data lane would wait forever with no verdict and no exit —
// exactly the permanently-draining scope shape that made a mount unusable for
// thirteen minutes. A blocked lane inherits the clock of the lane it waits on;
// when that clock stops, so does the inheritance.
func TestDependencyBlockedDataLaneStillStallsWhenTheNamespaceLaneStops(t *testing.T) {
	t.Run("uplink shut", func(t *testing.T) {
		const window = 300 * time.Millisecond
		pinCreditTimings(t, creditWaitCap, creditDrainTarget, window)
		pinNamespaceBatchBytes(t, 1)
		f := newStallFixture(t, 1<<30)

		// Same shape as the test above, with the one difference that decides
		// everything: no release is ever granted, so the lane the data batch
		// waits on makes no progress either.
		admitHeldDataBatch(t, f, 8)

		// Waited on the DATA lane's own verdict, not the stream's. The two lanes
		// arm their progress clocks when they each first hold something, and the
		// data record is admitted after the namespace backlog, so the stream-wide
		// verdict — which is the worst of the lanes — turns Stalled on the
		// namespace lane's older clock while the data lane still has some window
		// left. Asserting at that instant would be asserting about the wrong
		// lane's clock.
		waitForLaneStallVerdict(t, f.e.fl, StreamLaneData, true)
		if blocked, _ := f.e.fl.laneDependencyBlockedForTest(StreamLaneData); !blocked {
			t.Fatal("the data lane stopped being dependency-blocked; this subtest no " +
				"longer distinguishes inheritance from an exemption")
		}
	})

	t.Run("no sticky verdict to lean on", func(t *testing.T) {
		// The subtest above can be satisfied by the STREAM-WIDE degraded flag,
		// which the namespace lane latches on its own account — so it cannot
		// tell an exemption placed after that flag from a correct one. This
		// states the property directly against flusher state, with nothing
		// sticky latched and nothing terminal: a data lane blocked on a
		// namespace lane whose own clock has run out is stalled, full stop.
		old := noProgressWindow
		noProgressWindow = time.Second
		t.Cleanup(func() { noProgressWindow = old })

		f := &flusher{}
		for lane := range f.lanes {
			f.lanes[lane].lane = StreamLane(lane)
		}
		stale := time.Now().Add(-2 * noProgressWindow)
		f.lanes[StreamLaneNamespace].pending = []pendingRec{{seq: 1, laneSeq: 1, length: 8}}
		f.lanes[StreamLaneNamespace].lastProgress = stale
		f.lanes[StreamLaneData].pending = []pendingRec{{seq: 2, laneSeq: 1, length: 8, nsRequired: 1}}
		f.lanes[StreamLaneData].lastProgress = stale

		if blocked, needed := f.laneDependencyBlockedLocked(StreamLaneData); !blocked {
			t.Fatalf("the data lane is not blocked (needs %d, namespace applied %d); the "+
				"case under test is not set up", needed, f.lanes[StreamLaneNamespace].applied)
		}
		now := time.Now()
		if v := f.laneStallVerdictLocked(StreamLaneData, now); !v.Stalled {
			t.Fatalf("data-lane verdict = %+v with the namespace lane's own clock a full "+
				"window stale and no sticky flag set; inherited progress must be real "+
				"inheritance, not a blanket exemption for blocked lanes", v)
		}
		if v := f.laneStallVerdictLocked(StreamLaneNamespace, now); !v.Stalled {
			t.Fatalf("namespace-lane verdict = %+v; this fixture's premise (a namespace "+
				"lane that has itself stopped) does not hold", v)
		}
	})

	t.Run("a resend that moves no watermark is not progress to inherit", func(t *testing.T) {
		// The narrowest way to reopen the hole: keep the round trips flowing but
		// stop making anything durable. A namespace lane resending a batch the
		// authority has already applied replies success every time and moves no
		// watermark, so it is not progress — advance() does not restart the
		// namespace lane's own clock for it, and it must not restart a blocked
		// data lane's either. Inheriting a live-but-fruitless retry loop would
		// hide precisely the far end this verdict exists to name.
		old := noProgressWindow
		noProgressWindow = time.Second
		t.Cleanup(func() { noProgressWindow = old })

		e := &Engine{cfg: Config{BudgetBytes: 1 << 20}}
		e.fl = newFlusher(e)
		e.credits = newCreditController(e)
		f := e.fl

		stale := time.Now().Add(-2 * noProgressWindow)
		ns := &f.lanes[StreamLaneNamespace]
		ns.applied = 5
		ns.pending = []pendingRec{{seq: 6, scope: "d", laneSeq: 6, length: 8}}
		ns.lastProgress = stale
		data := &f.lanes[StreamLaneData]
		data.pending = []pendingRec{{seq: 7, scope: "d", laneSeq: 1, length: 8, nsRequired: 9}}
		data.lastProgress = stale
		f.perScope["d"] = 2
		f.perScopeData["d"] = 1
		f.admitted = 7

		f.advance(StreamLaneNamespace, 5) // a resend landing on durable state
		if !data.lastProgress.Equal(stale) {
			t.Fatal("the blocked data lane inherited a namespace reply that advanced no " +
				"watermark; a retry loop against a far end that applies nothing would " +
				"hold the window open forever")
		}
		if v := f.laneStallVerdictLocked(StreamLaneData, time.Now()); !v.Stalled {
			t.Fatalf("data-lane verdict = %+v after a window in which nothing was made "+
				"durable in either lane", v)
		}

		// The positive control, so this cannot pass by inheritance being broken
		// outright: a watermark that genuinely moves IS the blocked lane's
		// progress, and it is the SAME call that delivers both answers.
		f.advance(StreamLaneNamespace, 6)
		if data.lastProgress.Equal(stale) {
			t.Fatal("the blocked data lane did not inherit a real namespace advance")
		}
		if v := f.laneStallVerdictLocked(StreamLaneData, time.Now()); v.Stalled {
			t.Fatalf("data-lane verdict = %+v immediately after the namespace lane it "+
				"waits on applied a record", v)
		}
	})
}

// waitForLaneStallVerdict is waitForStallVerdict for ONE lane. A test about a
// lane-local condition has to wait on that lane's own verdict: the stream-wide
// form is the worst of the lanes, so it can be satisfied by a lane the test is
// not talking about.
func waitForLaneStallVerdict(t *testing.T, f *flusher, lane StreamLane, want bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if v := f.laneStallVerdict(lane); v.Stalled == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the %s lane's verdict never reached Stalled=%v (now %+v)",
				lane, want, f.laneStallVerdict(lane))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func nsAppliedOf(f *stallFixture) uint64 {
	_, applied := f.e.fl.laneStateForTest(StreamLaneNamespace)
	return applied
}
