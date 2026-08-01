package writeback

// The stall verdict is the engine's ONE answer to "is the far end dead?", and
// these tests exist because two admission gates used to answer it for
// themselves, from a constant.
//
// Both justified a fixed budget with
//
//	noProgressWindow (30s) + creditWaitCap (5s) = 35s  <  budget (40s)
//
// and concluded that a genuinely stalled uplink must already have been DECLARED
// stalled by the time the budget expired — so expiry could only mean "healthy
// but slow". The arithmetic is right; the conclusion does not follow, because
// the watchdog's window is measured from the last WATERMARK ADVANCE and
// flusher.advance resets that clock on every advance. The first test below is
// the direct refutation: after a late advance the verdict is not merely absent,
// it is a FULL window away, whatever the caller has already waited.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// stallFixture is one engine whose uplink is released ONE FLUSH AT A TIME, so a
// test can land an authority advance at an exact moment. The saturation fixture
// models a blackholed uplink (nothing ever applies); this one models the shape
// the false proof got wrong — a stream that is making progress, just late.
type stallFixture struct {
	e    *Engine
	auth *fakeAuthority
}

func newStallFixture(t *testing.T, budget int64) *stallFixture {
	t.Helper()
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushGate = make(chan struct{})
	auth.flushEntered = make(chan struct{}, 1)
	auth.mu.Unlock()

	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: budget,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	f := &stallFixture{e: e, auth: auth}
	t.Cleanup(func() {
		f.openUplink()
		_, _ = e.ForceClose("test teardown")
	})
	return f
}

// openUplink removes the gate entirely: every flush from now on applies.
func (f *stallFixture) openUplink() {
	f.auth.mu.Lock()
	gate := f.auth.flushGate
	f.auth.flushGate = nil
	f.auth.mu.Unlock()
	if gate != nil {
		close(gate)
	}
}

// releaseOneFlush lets exactly one flush attempt through and re-arms the gate
// behind it. The flusher ships from a single goroutine, so "one attempt" is
// exact: whatever is parked at the gate completes, and the next attempt blocks
// on the fresh gate.
func (f *stallFixture) releaseOneFlush() {
	f.auth.mu.Lock()
	gate := f.auth.flushGate
	f.auth.flushGate = make(chan struct{})
	f.auth.mu.Unlock()
	if gate != nil {
		close(gate)
	}
}

// pinMetadataAdmissionBudget compresses the namespace lane's pre-lock budget so
// its EXPIRY — the arm under test — is reachable inside a unit test's patience.
// It is deliberately left far under creditWaitCap so the budget, not the
// acquisition cap, is what ends the wait: the cap already consults the watchdog,
// and the whole point is what the BUDGET does when it expires on its own.
func pinMetadataAdmissionBudget(t *testing.T, d time.Duration) {
	t.Helper()
	old := metadataAdmissionBudget
	metadataAdmissionBudget = d
	t.Cleanup(func() { metadataAdmissionBudget = old })
}

// TestStallVerdictMatchesWatchdogAfterLateProgress is the finding itself,
// reproduced against the real advance path.
//
// A backlog is admitted at t0 and nothing applies. Three quarters of the way
// through the watchdog's window the authority applies ONE batch — the t39
// advance — and the rest of the backlog stays pending. The old proof says the
// verdict is in hand by t0+window. It is not: advance() reset the clock, so the
// watchdog cannot declare for another FULL window, and a budget expiring at
// t0+window would be classifying a far end nobody has any information about.
func TestStallVerdictMatchesWatchdogAfterLateProgress(t *testing.T) {
	const window = 3 * time.Second
	pinCreditTimings(t, creditWaitCap, creditDrainTarget, window)
	f := newStallFixture(t, 16<<20)
	ctx := context.Background()

	// More than one batch's worth, so the single advance below cannot drain the
	// stream: there must still be pending work for a verdict to be about.
	t0 := time.Now()
	for i := 0; i < 3*flushMaxRecords; i++ {
		if _, _, err := f.e.Mkdir(ctx, "d/late"+itoa(i), 0o755); err != nil {
			t.Fatalf("mkdir %d: %v", i, err)
		}
	}
	before, _ := f.e.Pending()
	if v := f.e.StallVerdict(); !v.Pending || v.Stalled {
		t.Fatalf("verdict right after admission = %+v, want pending work and no stall", v)
	}

	// Wait as a parked operation does, without any progress at all.
	if until := time.Until(t0.Add(window * 3 / 4)); until > 0 {
		time.Sleep(until)
	}
	if v := f.e.StallVerdict(); v.Stalled {
		t.Fatalf("the watchdog declared a stall %s into a %s window; this fixture is "+
			"too slow to model late progress", time.Since(t0), window)
	}

	// The LATE advance. From here the watchdog's clock starts over.
	f.releaseOneFlush()
	deadline := time.Now().Add(window / 2)
	var v StallVerdict
	for {
		if after, _ := f.e.Pending(); after < before {
			v = f.e.StallVerdict()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no authority advance landed after releasing one flush "+
				"(pending still %d of %d)", pendingOf(f.e), before)
		}
		time.Sleep(2 * time.Millisecond)
	}

	if !v.Pending {
		t.Fatalf("verdict after a partial advance = %+v; the backlog was fully "+
			"drained, so this run proves nothing about a watched stream", v)
	}
	if v.Stalled {
		t.Fatalf("verdict after a fresh authority advance = %+v, want no stall", v)
	}
	// The refutation, stated as the inequality the old comment relied on: the
	// EARLIEST the watchdog could declare is now+Remaining, and that is strictly
	// after t0+window — the instant the arithmetic claimed the verdict was
	// already in hand. Everything from t0+window to now+Remaining is time in
	// which a budget can expire while the verdict is unavailable.
	elapsed := time.Since(t0)
	if declareAt := time.Now().Add(v.Remaining); !declareAt.After(t0.Add(window)) {
		t.Fatalf("after a late advance %s into the run the watchdog could declare "+
			"at %s, at or before t0+window; the verdict would then be available at "+
			"budget expiry after all", elapsed, declareAt.Sub(t0))
	}
	if v.Remaining <= window/2 {
		t.Fatalf("Remaining = %s after a fresh advance, want ~the full window (%s): "+
			"the advance must restart the watchdog's clock, which is exactly why "+
			"elapsed time cannot stand in for the verdict", v.Remaining, window)
	}
}

func pendingOf(e *Engine) int {
	recs, _ := e.Pending()
	return recs
}

// TestMetadataAdmissionExpiryClassifiesFromLiveVerdict pins what the namespace
// gate DOES at expiry. The budget bounds the wait; the verdict classifies the
// outcome. Before this, the arm could only ever produce a deadline — a stalled
// uplink was answered "interrupted operation", and the EIO-class truth was
// unreachable from here.
func TestMetadataAdmissionExpiryClassifiesFromLiveVerdict(t *testing.T) {
	t.Run("stalled uplink is the watchdog's EIO-class answer", func(t *testing.T) {
		// A window far under the budget, so the watchdog genuinely holds the
		// verdict by the time the budget expires...
		pinCreditTimings(t, creditWaitCap, creditDrainTarget, 50*time.Millisecond)
		// ...and a budget far under creditWaitCap, so it is the BUDGET that ends
		// the wait rather than the acquisition cap (which already consults the
		// watchdog and would prove nothing about this arm).
		pinMetadataAdmissionBudget(t, 150*time.Millisecond)
		f := newSaturationFixture(t, 4<<20)
		if err := fillMetadataLane(t, f); err == nil {
			t.Fatal("the metadata lane never refused an append")
		}
		if !f.e.MetadataLaneFull() {
			t.Fatal("the lane refused an append but does not report itself full")
		}
		waitForStallVerdict(t, f.e, true)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := f.e.AdmitMetadataMutation(ctx)
		if !errors.Is(err, ErrUplinkStalled) {
			t.Fatalf("metadata admission expiring against a STALLED watchdog = %v, "+
				"want ErrUplinkStalled: the budget's expiry proves nothing, and the "+
				"live verdict says the far end is dead", err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a stalled uplink was reported as a deadline (%v); an "+
				"application cannot tell a dead far end from an interrupted call", err)
		}
	})

	t.Run("live uplink keeps the definite deadline", func(t *testing.T) {
		// A window far over the budget: the backlog is real, nothing is applying
		// yet, and the watchdog is nowhere near able to declare — the exact
		// state the t39 advance leaves behind.
		pinCreditTimings(t, creditWaitCap, creditDrainTarget, 60*time.Second)
		pinMetadataAdmissionBudget(t, 150*time.Millisecond)
		f := newSaturationFixture(t, 4<<20)
		if err := fillMetadataLane(t, f); err == nil {
			t.Fatal("the metadata lane never refused an append")
		}
		if v := f.e.StallVerdict(); v.Stalled || !v.Pending {
			t.Fatalf("verdict before admission = %+v, want a watched stream with no "+
				"verdict yet", v)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := f.e.AdmitMetadataMutation(ctx)
		if errors.Is(err, ErrUplinkStalled) {
			t.Fatalf("metadata admission expiring against a LIVE watchdog = %v; the "+
				"gate reported a dead far end the engine never declared", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("metadata admission expiry with a live uplink = %v, want the "+
				"definite deadline the caller's own bound promises", err)
		}
	})
}

func waitForStallVerdict(t *testing.T, e *Engine, want bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if v := e.StallVerdict(); v.Stalled == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the watchdog verdict never reached Stalled=%v (now %+v)",
				want, e.StallVerdict())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestUplinkStalledAndStallVerdictAgree proves there is ONE verdict, not two.
// uplinkStalled is now literally the Stalled field of the snapshot, and this
// table is what stops that from quietly becoming two computations again.
func TestUplinkStalledAndStallVerdictAgree(t *testing.T) {
	old := noProgressWindow
	noProgressWindow = time.Second
	t.Cleanup(func() { noProgressWindow = old })

	now := time.Now()
	one := []pendingRec{{seq: 1}}
	cases := []struct {
		name          string
		terminal      error
		pending       []pendingRec
		degraded      bool
		lastProgress  time.Time
		wantStalled   bool
		wantPending   bool
		wantRemaining time.Duration
	}{{
		name: "idle stream", wantStalled: false, wantPending: false,
	}, {
		name: "parked stream with no pending work", terminal: errors.New("parked"),
		wantStalled: true,
	}, {
		name: "parked stream with pending work", terminal: errors.New("parked"),
		pending: one, lastProgress: now, wantStalled: true,
	}, {
		// The sticky verdict the sweep latched.
		name: "sticky degraded", pending: one, degraded: true,
		lastProgress: now, wantStalled: true, wantPending: true,
	}, {
		// Degraded is meaningless without pending work: advance() clears it the
		// moment the backlog empties.
		name: "degraded with an empty backlog", degraded: true, lastProgress: now,
	}, {
		name: "fresh progress", pending: one, lastProgress: now.Add(-250 * time.Millisecond),
		wantPending: true, wantRemaining: 750 * time.Millisecond,
	}, {
		name: "the window exactly closed", pending: one, lastProgress: now.Add(-time.Second),
		wantStalled: true, wantPending: true,
	}, {
		name: "the window long closed", pending: one, lastProgress: now.Add(-time.Hour),
		wantStalled: true, wantPending: true,
	}, {
		// Pending work whose progress clock never started: nothing has been
		// observed to stall, and a whole window would have to elapse first.
		name: "no progress clock yet", pending: one,
		wantPending: true, wantRemaining: time.Second,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The verdict is per LANE now; the table's cases are all
			// statements about one lane's backlog, so they are driven
			// through the namespace lane and read back through both the
			// lane form and the stream-wide worst-of form (which must
			// agree when only one lane holds anything).
			f := &flusher{terminal: tc.terminal, degraded: tc.degraded}
			for lane := range f.lanes {
				f.lanes[lane].lane = StreamLane(lane)
			}
			f.lanes[StreamLaneNamespace].pending = tc.pending
			f.lanes[StreamLaneNamespace].lastProgress = tc.lastProgress
			v := f.laneStallVerdictLocked(StreamLaneNamespace, now)
			if v.Stalled != tc.wantStalled {
				t.Fatalf("verdict %+v, want Stalled=%v", v, tc.wantStalled)
			}
			if v.Pending != tc.wantPending {
				t.Fatalf("verdict %+v, want Pending=%v", v, tc.wantPending)
			}
			if v.Remaining != tc.wantRemaining {
				t.Fatalf("verdict %+v, want Remaining=%v", v, tc.wantRemaining)
			}
			if v.Stalled && v.Remaining != 0 {
				t.Fatalf("verdict %+v carries a countdown to a verdict it already "+
					"holds", v)
			}
			if !v.Pending && v.Remaining != 0 {
				t.Fatalf("verdict %+v counts down to a stall about nothing", v)
			}
			// The agreement itself: the gate's boolean and the snapshot cannot
			// disagree, because they are the same read.
			if got := f.uplinkStalled(); got != v.Stalled {
				t.Fatalf("uplinkStalled() = %v but StallVerdict().Stalled = %v; the "+
					"engine holds two verdicts again", got, v.Stalled)
			}
		})
	}
}

// TestMetadataAdmissionBudgetBoundsTheWaitNotTheVerdict replaces the arithmetic
// the old comment called a proof. The budget must still land inside the bounds
// it composes with — that part was always true — but nothing about it decides
// whether the uplink is stalled, and this is where that split is stated.
func TestMetadataAdmissionBudgetBoundsTheWaitNotTheVerdict(t *testing.T) {
	if MetadataAdmissionBudget() <= 0 {
		t.Fatalf("metadataAdmissionBudget = %s", MetadataAdmissionBudget())
	}
	// A backlog admitted right now is watched, unstalled, and a FULL window away
	// from any verdict — however large the budget is.
	pinCreditTimings(t, creditWaitCap, creditDrainTarget, NoProgressWindow())
	f := newStallFixture(t, 8<<20)
	if _, _, err := f.e.Mkdir(context.Background(), "d/one", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	v := f.e.StallVerdict()
	if v.Stalled || !v.Pending {
		t.Fatalf("verdict for a fresh backlog = %+v", v)
	}
	if v.Remaining <= 0 {
		t.Fatalf("verdict %+v reports no time to a declaration it has not made", v)
	}
}
