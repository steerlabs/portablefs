package writeback

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

// saturationFixture is one engine whose uplink is gated shut, so nothing the
// data plane admits can ever drain. Every bounded write-back resource
// (stream WAL budget, per-file overlay extent set) therefore reaches its
// bound and stays there until the test opens the gate.
type saturationFixture struct {
	e    *Engine
	auth *fakeAuthority
	gate chan struct{}
	once sync.Once
}

func (f *saturationFixture) openUplink() {
	f.once.Do(func() { close(f.gate) })
}

func newSaturationFixture(t *testing.T, budget int64) *saturationFixture {
	t.Helper()
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.dirs["meta"] = true
	auth.files["meta/probe"] = []byte("probe")
	auth.modes["meta/probe"] = 0o644
	auth.flushGate = make(chan struct{})
	auth.flushEntered = make(chan struct{}, 1)
	gate := auth.flushGate
	auth.mu.Unlock()

	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: budget,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	f := &saturationFixture{e: e, auth: auth, gate: gate}
	t.Cleanup(func() {
		f.openUplink()
		_, _ = e.ForceClose("test teardown")
	})
	return f
}

// promptly runs fn on its own goroutine and fails the test if it has not
// returned within limit. It never leaks the assertion into later subtests: a
// timeout is fatal for the whole test.
func promptly(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not complete within %s: it is waiting on the stalled uplink", what, limit)
	}
}

// TestBlockedRemotePacesThenReportsUplinkStalled is the WAL-budget saturation
// contract AFTER the credit gate replaced the instant-ENOSPC cliff.
//
// The uplink is gated shut, so the measured applied rate is zero and nothing
// can ever drain. Writers are admitted up to the operating setpoint and then
// PACE: they wait, bounded, holding nothing. When the flusher's no-progress
// watchdog declares the uplink stalled, the wait resolves into a typed
// ErrUplinkStalled — an EIO-class outcome for a far end that stopped
// answering, deliberately distinct from the ENOSPC that means a local store is
// full. As before, the refusal stays in the delegated lane, releases no
// delegation, and does not poison the engine.
func TestBlockedRemotePacesThenReportsUplinkStalled(t *testing.T) {
	pinCreditTimings(t, 150*time.Millisecond, 25*time.Second, 200*time.Millisecond)
	f := newSaturationFixture(t, 1<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	chunk := make([]byte, 64<<10)
	_, _, releasesBefore := f.auth.calls()

	var refused error
	for i := 0; i < 256 && refused == nil; i++ {
		wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, handled, err := f.e.WriteAppend(wctx, "d/f", chunk)
		cancel()
		switch {
		case err != nil && !handled:
			t.Fatalf("append %d changed lanes on an error: %v", i, err)
		case err != nil:
			refused = err
		case !handled:
			t.Fatalf("append %d left the delegated lane while the budget was the binding constraint", i)
		}
	}
	if !errors.Is(refused, ErrUplinkStalled) {
		t.Fatalf("a blocked uplink surfaced %v, want %v", refused, ErrUplinkStalled)
	}
	if errors.Is(refused, ErrNoSpace) {
		t.Fatal("a stalled uplink must not be reported as a full local store")
	}
	if err := f.e.MutationError(); err != nil {
		t.Fatalf("the stalled-uplink refusal poisoned the engine: %v", err)
	}
	if _, _, releasesAfter := f.auth.calls(); releasesAfter != releasesBefore {
		t.Fatalf("saturation released %d delegations; a paced refusal must not hand off",
			releasesAfter-releasesBefore)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("saturation dropped the covering delegation")
	}
	if used := walBytes(t, f.e); used > 1<<20 {
		t.Fatalf("stream WAL reached %d bytes, past its %d hard cap", used, 1<<20)
	}
}

// TestMetadataStaysInstantWhileTheDataLaneIsSaturated is the metadata reserve
// under test. One segment of the hard cap is carved out for records that carry
// no bulk bytes, and metadata is never credit-charged — so while a data flood
// is paced against a dead uplink, create/mkdir/rename/unlink/setattr keep
// answering IMMEDIATELY. Before the split, appendRecordsLocked answered every
// caller at hard-full with ENOSPC, which is how a saturated data plane took the
// namespace down with it.
func TestMetadataStaysInstantWhileTheDataLaneIsSaturated(t *testing.T) {
	pinCreditTimings(t, 150*time.Millisecond, 25*time.Second, 200*time.Millisecond)
	f := newSaturationFixture(t, 4<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	// Drive the data lane to its bound.
	chunk := make([]byte, 256<<10)
	var stalled error
	for i := 0; i < 64 && stalled == nil; i++ {
		wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, _, err := f.e.WriteAppend(wctx, "d/f", chunk)
		cancel()
		stalled = err
	}
	if !errors.Is(stalled, ErrUplinkStalled) {
		t.Fatalf("data lane surfaced %v, want %v", stalled, ErrUplinkStalled)
	}

	// Every metadata surface, timed. None may block and none may ENOSPC.
	promptly(t, 3*time.Second, "metadata mutations during data saturation", func() {
		for i := 0; i < 32; i++ {
			name := "d/meta" + strconv.Itoa(i)
			if _, handled, err := f.e.Create(ctx, name, 0o644, false, false); err != nil || !handled {
				t.Errorf("create %s under data saturation: handled=%v err=%v", name, handled, err)
				return
			}
			if _, handled, err := f.e.Setattr(ctx, name, SetattrRequest{SetMode: true, Mode: 0o600}); err != nil || !handled {
				t.Errorf("setattr %s under data saturation: handled=%v err=%v", name, handled, err)
				return
			}
			if _, handled, err := f.e.Rename(ctx, name, name+"r", nil); err != nil || !handled {
				t.Errorf("rename %s under data saturation: handled=%v err=%v", name, handled, err)
				return
			}
			if _, handled, err := f.e.Remove(ctx, name+"r"); err != nil || !handled {
				t.Errorf("remove %s under data saturation: handled=%v err=%v", name, handled, err)
				return
			}
		}
	})
	if used := walBytes(t, f.e); used > 4<<20 {
		t.Fatalf("stream WAL reached %d bytes, past its %d hard cap: the reserve is inside the cap, not on top of it", used, 4<<20)
	}
}

// TestPacedWritersHoldNothingWhileQueued is the property that makes the whole
// gate safe to sit in front of the data plane: a writer parked waiting for
// credit holds NO engine lock, no delegation and no handle. It is checked the
// only way that proves it — by taking the engine mutex, the read-admission
// path and a delegated metadata mutation while writers are demonstrably queued.
// If a waiter held e.mu (or its grant) across the wait, a recall, a barrier and
// every metadata operation would queue behind a stalled uplink, which is the
// original production failure this design exists to prevent.
func TestPacedWritersHoldNothingWhileQueued(t *testing.T) {
	pinCreditTimings(t, 5*time.Second, 25*time.Second, 30*time.Second)
	f := newSaturationFixture(t, 4<<20) // uplink gated shut: writers park
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}

	stop := make(chan struct{})
	var writers sync.WaitGroup
	chunk := make([]byte, 512<<10)
	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				_, _, _ = f.e.WriteAppend(wctx, "d/f", chunk)
				cancel()
			}
		}()
	}
	defer func() {
		close(stop)
		writers.Wait()
	}()

	// Wait until writers are actually parked in the credit queue (or against
	// hard-cap headroom), not merely running.
	deadline := time.Now().Add(10 * time.Second)
	for f.e.Status().CreditDebt == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	promptly(t, 5*time.Second, "engine mutex while writers are paced", func() {
		for i := 0; i < 50; i++ {
			f.e.mu.Lock()
			f.e.mu.Unlock() //nolint:staticcheck // the point IS that it is grantable
			time.Sleep(time.Millisecond)
		}
	})
	promptly(t, 5*time.Second, "read admission while writers are paced", func() {
		for i := 0; i < 20; i++ {
			rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			permit, err := f.e.BeginRead(rctx, "d/f")
			cancel()
			if err != nil {
				t.Errorf("read admission with writers paced: %v", err)
				return
			}
			permit.Lookup("d/f")
			permit.Close()
		}
	})
	promptly(t, 5*time.Second, "delegated metadata while writers are paced", func() {
		for i := 0; i < 20; i++ {
			name := "d/held" + strconv.Itoa(i)
			if _, handled, err := f.e.Create(ctx, name, 0o644, false, false); err != nil || !handled {
				t.Errorf("create %s with writers paced: handled=%v err=%v", name, handled, err)
				return
			}
			if _, handled, err := f.e.Remove(ctx, name); err != nil || !handled {
				t.Errorf("remove %s with writers paced: handled=%v err=%v", name, handled, err)
				return
			}
		}
	})
}

// TestMetadataReserveHoldsWhenFramingOverrunsTheCreditLedger pins the RESERVE
// at the layer that actually guarantees it. The credit ledger counts payload
// bytes; the WAL counts framed bytes. For small writes the framing overhead is
// most of the record, so a data flood governed only by credit would still walk
// the stream's real footprint into the last segment and start answering
// metadata with ENOSPC — the pre-split behaviour, where a bulk-data flood took
// the namespace down with it. The lane budget is what makes it impossible: data
// reserves against budget-minus-reserve, so the reserve is untouchable no
// matter what shape the data takes.
func TestMetadataReserveHoldsWhenFramingOverrunsTheCreditLedger(t *testing.T) {
	pinCreditTimings(t, 100*time.Millisecond, 25*time.Second, 150*time.Millisecond)
	// Lift the overlay extent bound out of the way: this test is about the WAL
	// lane split, and with tiny writes the extent bound would bind first.
	oldExtents := maxFileExtents
	maxFileExtents = 1 << 20
	t.Cleanup(func() { maxFileExtents = oldExtents })

	const budget = 4 << 20
	f := newSaturationFixture(t, budget) // uplink gated shut
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}

	// 128-byte writes: the frame header, PFR1 header and path dominate, so the
	// stream's framed footprint grows far faster than the credit ledger's
	// payload-byte view of it.
	chunk := make([]byte, 128)
	var refused error
	for i := 0; i < 1<<20 && refused == nil; i++ {
		wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, handled, err := f.e.WriteAppend(wctx, "d/f", chunk)
		cancel()
		if err != nil && !handled {
			t.Fatalf("append %d changed lanes: %v", i, err)
		}
		refused = err
	}
	if !errors.Is(refused, ErrUplinkStalled) && !errors.Is(refused, ErrNoSpace) {
		t.Fatalf("the data lane surfaced %v", refused)
	}
	dataCap := f.e.dataBudgetBytes()
	if used := walBytes(t, f.e); used > dataCap {
		t.Fatalf("bulk data drove the stream to %d bytes, past the data lane's %d cap "+
			"(hard cap %d): the metadata reserve was consumed by data", used, dataCap, budget)
	}

	// The reserve is intact, so every metadata surface is still instant.
	promptly(t, 3*time.Second, "metadata mutations with the data lane at its cap", func() {
		for i := 0; i < 64; i++ {
			name := "d/m" + strconv.Itoa(i)
			if _, handled, err := f.e.Create(ctx, name, 0o644, false, false); err != nil || !handled {
				t.Errorf("create %s with the data lane full: handled=%v err=%v", name, handled, err)
				return
			}
		}
	})
	if used := walBytes(t, f.e); used > budget {
		t.Fatalf("the reserve pushed the stream to %d bytes, past its %d hard cap", used, budget)
	}
}

// TestPacedWritesCompleteAgainstASlowButDrainingRemote is the outcome the whole
// controller exists for. The remote applies at a finite rate rather than not at
// all, so the measured rate is non-zero, the setpoint is non-zero, and every
// write COMPLETES — paced to the uplink — instead of either failing at a cliff
// or blocking unboundedly. The data lands byte-exact on the authority.
func TestPacedWritesCompleteAgainstASlowButDrainingRemote(t *testing.T) {
	// A compressed drain horizon puts the setpoint (rate x T_drain) well below
	// the hard cap, so the CREDIT gate — not the cap — is what paces the writer.
	pinCreditTimings(t, 2*time.Second, 250*time.Millisecond, 30*time.Second)
	// Small segments so whole-segment reclamation actually returns applied
	// bytes to the cap while the writer is still going.
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 1 << 20
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushRateBps = 8 << 20 // 8 MiB/s uplink
	auth.mu.Unlock()
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 16 << 20,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _, _ = e.ForceClose("test teardown") }()

	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	chunk := bytes.Repeat([]byte("p"), 256<<10)
	const writes = 64 // far more than the cap can hold at once: pacing is forced
	want := make([]byte, 0, writes*len(chunk))
	start := time.Now()
	for i := 0; i < writes; i++ {
		wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		res, handled, err := e.WriteAppend(wctx, "d/f", chunk)
		cancel()
		if err != nil || !handled {
			t.Fatalf("paced append %d: handled=%v err=%v", i, handled, err)
		}
		if res.Count != len(chunk) {
			t.Fatalf("paced append %d wrote %d of %d bytes", i, res.Count, len(chunk))
		}
		want = append(want, chunk...)
	}
	elapsed := time.Since(start)

	// The setpoint must have engaged: a measured 8 MiB/s link over a 250ms
	// horizon is ~2 MiB of resident debt, far below the 24 MiB data cap.
	st := e.Status()
	if st.CreditSetpoint >= st.CreditCeiling {
		t.Fatalf("setpoint %d never fell below the %d data cap against an 8 MiB/s link; "+
			"the measured-rate loop did not engage", st.CreditSetpoint, st.CreditCeiling)
	}
	if st.AppliedRateBps <= 0 {
		t.Fatalf("no applied rate was measured (%v) after %d paced writes", st.AppliedRateBps, writes)
	}
	// Pacing means the writers actually waited on the uplink rather than
	// absorbing everything into the cap: 6 MiB at 8 MiB/s cannot finish
	// instantly.
	if floor := time.Duration(float64(len(want)) / float64(8<<20) * float64(time.Second)); elapsed < floor/2 {
		t.Fatalf("wrote %d bytes in %s against an 8 MiB/s uplink: nothing was paced", len(want), elapsed)
	}

	dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := e.DrainAll(dctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if err := auth.equalFile("d/f", want); err != nil {
		t.Fatalf("paced writes did not land byte-exact: %v", err)
	}
	if used := walBytes(t, e); used > 16<<20 {
		t.Fatalf("stream WAL reached %d bytes, past its %d hard cap", used, 16<<20)
	}
}

// TestLargeAndSmallPacedWritersBothProgress is the fairness argument at the
// engine surface: while a multi-megabyte writer is paced against a slow uplink,
// a small writer on another file is not starved behind it. Credit is handed out
// a chunk at a time in arrival order, so the small writer's completions
// interleave with the large one's.
func TestLargeAndSmallPacedWritersBothProgress(t *testing.T) {
	pinCreditTimings(t, 2*time.Second, 200*time.Millisecond, 30*time.Second)
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 1 << 20
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushRateBps = 8 << 20
	auth.mu.Unlock()
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 16 << 20,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _, _ = e.ForceClose("test teardown") }()

	ctx := context.Background()
	for _, name := range []string{"d/big", "d/small"} {
		if _, handled, err := e.Create(ctx, name, 0o644, false, false); err != nil || !handled {
			t.Fatalf("create %s: handled=%v err=%v", name, handled, err)
		}
	}

	stop := make(chan struct{})
	bigDone := make(chan error, 1)
	go func() {
		big := bytes.Repeat([]byte("B"), 2<<20)
		for i := 0; i < 8; i++ {
			wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			_, handled, err := e.WriteAppend(wctx, "d/big", big)
			cancel()
			if err != nil || !handled {
				bigDone <- err
				return
			}
		}
		bigDone <- nil
	}()

	// The small writer must keep completing while the large one is in flight.
	small := bytes.Repeat([]byte("s"), 4<<10)
	completed := 0
	deadline := time.Now().Add(30 * time.Second)
	for completed < 40 && time.Now().Before(deadline) {
		select {
		case err := <-bigDone:
			if err != nil {
				t.Fatalf("large writer: %v", err)
			}
			bigDone = nil
			close(stop)
		default:
		}
		wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		startOne := time.Now()
		_, handled, err := e.WriteAppend(wctx, "d/small", small)
		cancel()
		if err != nil || !handled {
			t.Fatalf("small write %d starved behind the large writer: handled=%v err=%v", completed, handled, err)
		}
		if waited := time.Since(startOne); waited > 15*time.Second {
			t.Fatalf("small write %d waited %s behind the large writer", completed, waited)
		}
		completed++
		if bigDone == nil {
			break // the large writer finished; fairness held for its whole run
		}
	}
	if completed == 0 {
		t.Fatal("the small writer never completed a single write")
	}
	select {
	case <-stop:
	default:
	}
	if bigDone != nil {
		select {
		case err := <-bigDone:
			if err != nil {
				t.Fatalf("large writer: %v", err)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("the large writer never finished")
		}
	}
}

// TestBoundedOverlayExhaustionIsDefiniteENOSPC is the exact defect reproduced
// in production: a file's overlay extent set reaches its hard bound while the
// uplink cannot drain. The engine used to escape that bound by releasing the
// delegation and running write-through, and the release drains through the
// stalled uplink — so the write blocked until the frontend's operation
// deadline expired and surfaced ETIMEDOUT. Bounded local write-back resources
// are a definite condition: relieve once, then refuse with ENOSPC.
func TestBoundedOverlayExhaustionIsDefiniteENOSPC(t *testing.T) {
	oldExtents := maxFileExtents
	maxFileExtents = 8
	t.Cleanup(func() { maxFileExtents = oldExtents })

	f := newSaturationFixture(t, 1<<30) // budget is NOT the binding constraint
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	_, _, releasesBefore := f.auth.calls()

	var refused error
	for i := 0; i < 4*maxFileExtents && refused == nil; i++ {
		// Disjoint one-byte writes with gaps: every write is its own extent.
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		_, handled, err := f.e.WriteAt(wctx, "d/f", int64(i*3), []byte("x"))
		elapsed := time.Since(start)
		cancel()
		if elapsed > 2*time.Second {
			t.Fatalf("write %d blocked for %s: the overlay bound escaped through a drain", i, elapsed)
		}
		switch {
		case err != nil && !handled:
			t.Fatalf("write %d changed lanes on an error: %v", i, err)
		case err != nil:
			refused = err
		case !handled:
			t.Fatalf("write %d fell through to write-through; the fall-through drain is exactly the "+
				"unbounded wait that turned a full store into ETIMEDOUT", i)
		}
	}
	if !errors.Is(refused, ErrNoSpace) {
		t.Fatalf("overlay bound surfaced %v, want %v", refused, ErrNoSpace)
	}
	f.e.mu.RLock()
	extents := len(f.e.files["d/f"].extents)
	f.e.mu.RUnlock()
	if extents > maxFileExtents {
		t.Fatalf("overlay grew to %d extents past the %d bound", extents, maxFileExtents)
	}
	if _, _, releasesAfter := f.auth.calls(); releasesAfter != releasesBefore {
		t.Fatalf("overlay exhaustion released %d delegations; a definite ENOSPC must not hand off",
			releasesAfter-releasesBefore)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("overlay exhaustion dropped the covering delegation")
	}
}

// TestTruncateUnderExhaustionIsDefiniteENOSPC covers the third data-plane
// entry point: an extending truncate needs one more extent and must reach the
// same definite verdict as a write.
func TestTruncateUnderExhaustionIsDefiniteENOSPC(t *testing.T) {
	oldExtents := maxFileExtents
	maxFileExtents = 4
	t.Cleanup(func() { maxFileExtents = oldExtents })

	f := newSaturationFixture(t, 1<<30)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	// Contiguous one-byte writes: each is its own extent, and none extends
	// past EOF, so no hole extents are inserted.
	for i := 0; i < maxFileExtents-1; i++ {
		if _, handled, err := f.e.WriteAt(ctx, "d/f", int64(i), []byte("x")); err != nil || !handled {
			t.Fatalf("seed write %d: handled=%v err=%v", i, handled, err)
		}
	}
	type outcome struct {
		handled bool
		err     error
	}
	var last outcome
	promptly(t, 3*time.Second, "truncate under overlay exhaustion", func() {
		for i := 0; i < 8; i++ {
			tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, handled, err := f.e.Truncate(tctx, "d/f", int64(1<<20+i))
			cancel()
			last = outcome{handled: handled, err: err}
			if err != nil || !handled {
				return
			}
		}
	})
	if !last.handled {
		t.Fatalf("truncate fell through to a draining write-through under exhaustion (err=%v)", last.err)
	}
	if !errors.Is(last.err, ErrNoSpace) {
		t.Fatalf("truncate under exhaustion surfaced %v, want %v", last.err, ErrNoSpace)
	}
}

// TestExhaustedDataPlaneDoesNotStallReadsOrMetadata is symptom (b)/(c) of the
// production defect. While the data plane is saturated, every read and
// metadata surface must stay live. Before the fix the refused write drained
// and released its delegation, which closes read admission on that scope:
// concurrent readers then blocked on the same stalled uplink, the frontend's
// operation deadlines expired, and the kernel marked the whole volume dead
// while the daemon was healthy.
func TestExhaustedDataPlaneDoesNotStallReadsOrMetadata(t *testing.T) {
	oldExtents := maxFileExtents
	maxFileExtents = 8
	t.Cleanup(func() { maxFileExtents = oldExtents })

	f := newSaturationFixture(t, 1<<30)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	// Seed a second, unrelated delegated scope so the assertion covers both
	// "same scope as the saturated writer" and "unrelated directory".
	if _, handled, err := f.e.Create(ctx, "meta/other", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create meta/other: handled=%v err=%v", handled, err)
	}

	stop := make(chan struct{})
	var writers sync.WaitGroup
	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_, _, _ = f.e.WriteAt(wctx, "d/f", int64(w*1_000_000+i*3), []byte("x"))
				cancel()
			}
		}(w)
	}
	defer func() {
		close(stop)
		writers.Wait()
	}()

	// Give the writers time to drive the file past its bound.
	time.Sleep(100 * time.Millisecond)

	var readErr error
	undecided := false
	promptly(t, 5*time.Second, "read and metadata surfaces during data saturation", func() {
		for i := 0; i < 200 && readErr == nil && !undecided; i++ {
			rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			permit, err := f.e.BeginRead(rctx, "d/f")
			cancel()
			if err != nil {
				readErr = err
				return
			}
			permit.Lookup("d/f")
			permit.Readdir("d")
			permit.Close()

			rctx, cancel = context.WithTimeout(ctx, 2*time.Second)
			other, err := f.e.BeginRead(rctx, "meta/other")
			cancel()
			if err != nil {
				readErr = err
				return
			}
			other.Lookup("meta/other")
			other.MergeReaddir("meta", []Entry{{Name: "probe", Kind: "file"}})
			other.Close()

			if _, res := f.e.Lookup("d/f"); res == LookupUndecided {
				undecided = true
			}
		}
	})
	if readErr != nil {
		t.Fatalf("read admission failed while the data plane was saturated: %v", readErr)
	}
	if undecided {
		t.Fatal("the saturated scope stopped serving its acknowledged overlay: " +
			"data backpressure handed the delegation off and pushed reads onto the stalled uplink")
	}
}

// TestExhaustionRecoversWhenTheUplinkDrains proves bounded-resource semantics
// rather than self-healing: the refusal lasts exactly as long as the bound
// binds. Once the uplink accepts the backlog, folding relieves the overlay and
// the very next write is admitted locally again.
func TestExhaustionRecoversWhenTheUplinkDrains(t *testing.T) {
	oldExtents := maxFileExtents
	maxFileExtents = 8
	t.Cleanup(func() { maxFileExtents = oldExtents })

	f := newSaturationFixture(t, 1<<30)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	var refused error
	for i := 0; i < 4*maxFileExtents && refused == nil; i++ {
		_, handled, err := f.e.WriteAt(ctx, "d/f", int64(i*3), []byte("x"))
		if err != nil && handled {
			refused = err
		} else if err != nil || !handled {
			t.Fatalf("write %d: handled=%v err=%v", i, handled, err)
		}
	}
	if !errors.Is(refused, ErrNoSpace) {
		t.Fatalf("saturation surfaced %v, want %v", refused, ErrNoSpace)
	}

	// fsync of already-admitted data must still drain, never ENOSPC: it is the
	// barrier the application uses to relieve the very bound it just hit.
	f.openUplink()
	fsyncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := f.e.Fsync(fsyncCtx, "d/f"); err != nil {
		t.Fatalf("fsync of admitted data during exhaustion: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		_, handled, err := f.e.WriteAt(ctx, "d/f", 1<<20, []byte("y"))
		if err == nil && handled {
			break
		}
		if !errors.Is(err, ErrNoSpace) {
			t.Fatalf("post-drain write: handled=%v err=%v", handled, err)
		}
		if time.Now().After(deadline) {
			t.Fatal("writes never resumed after the uplink drained the backlog")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if records, _ := f.e.Pending(); records < 0 {
		t.Fatalf("impossible pending count %d", records)
	}
}
