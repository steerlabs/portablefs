package writeback

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestLargeWriteIsRefusedInsteadOfOvershootingTheBudget pins the reservation
// contract. Observing that CURRENT usage is still under the budget says nothing
// about the append that is about to happen: a single large write admitted one
// byte under the limit appends megabytes past it. The budget then stops being a
// bound at all, and the store the operator sized to it answers the NEXT append
// with a PHYSICAL ENOSPC — which lands in failLocalWAL and terminally poisons
// the mount, the exact opposite of the promised definite pre-mutation refusal.
// Admission must reserve the append's real on-disk cost, so an accepted append
// can never push the stream past the budget.
func TestLargeWriteIsRefusedInsteadOfOvershootingTheBudget(t *testing.T) {
	const budget = 4 << 20
	f := newSaturationFixture(t, budget) // uplink gated shut: nothing can drain
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}

	// One write, far larger than the budget, issued while usage is still a few
	// kilobytes. Nothing about the CURRENT usage forbids it; its own cost does.
	big := bytes.Repeat([]byte("x"), 8<<20)
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, handled, err := f.e.WriteAt(wctx, "d/f", 0, big)
	cancel()
	if err != nil {
		if !handled {
			t.Fatalf("the refusal changed lanes: handled=%v err=%v", handled, err)
		}
		if !errors.Is(err, ErrNoSpace) {
			t.Fatalf("oversized write surfaced %v, want %v", err, ErrNoSpace)
		}
	}
	if used := walBytes(t, f.e); used > budget {
		t.Fatalf("stream WAL grew to %d bytes, past its %d budget: admission observed usage "+
			"instead of reserving the append's cost, so the budget is a high-water mark, not a bound",
			used, budget)
	}

	// A pre-mutation refusal is definite, not terminal: nothing was written, so
	// the engine keeps its delegation and keeps admitting what does fit.
	if err := f.e.MutationError(); err != nil {
		t.Fatalf("the ENOSPC refusal poisoned the engine: %v", err)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("the ENOSPC refusal dropped the covering delegation")
	}
	if _, handled, err := f.e.WriteAt(ctx, "d/f", 0, []byte("fits")); err != nil || !handled {
		t.Fatalf("write that fits after a refusal: handled=%v err=%v", handled, err)
	}
}

// TestConcurrentAdmissionsNeverExceedTheBudget proves the budget is an
// invariant rather than an observation: however admissions interleave, the
// stream's on-disk footprint is never above the configured budget. Run under
// -race, it also covers the reservation counter itself.
func TestConcurrentAdmissionsNeverExceedTheBudget(t *testing.T) {
	const budget = 4 << 20
	f := newSaturationFixture(t, budget)
	ctx := context.Background()
	const writers = 4
	for w := 0; w < writers; w++ {
		if _, handled, err := f.e.Create(ctx, fileName(w), 0o644, false, false); err != nil || !handled {
			t.Fatalf("create %s: handled=%v err=%v", fileName(w), handled, err)
		}
	}

	chunk := bytes.Repeat([]byte("y"), 1<<20)
	var wg sync.WaitGroup
	over := make(chan int64, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 16; i++ {
				wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				_, handled, err := f.e.WriteAt(wctx, fileName(w), int64(i)*int64(len(chunk)), chunk)
				cancel()
				if err != nil && (!handled || !errors.Is(err, ErrNoSpace)) {
					t.Errorf("writer %d append %d: handled=%v err=%v", w, i, handled, err)
					return
				}
				if used := walBytes(t, f.e); used > budget {
					select {
					case over <- used:
					default:
					}
					return
				}
			}
		}(w)
	}
	wg.Wait()
	select {
	case used := <-over:
		t.Fatalf("stream WAL reached %d bytes under concurrent admission, past its %d budget", used, budget)
	default:
	}
	if err := f.e.MutationError(); err != nil {
		t.Fatalf("budget refusals poisoned the engine: %v", err)
	}
}

// TestBudgetRelievedByTheUplinkReadmitsALargeWrite keeps the refusal honest as
// bounded-resource semantics: the reservation refuses exactly as long as the
// bound binds, and the write is admitted again once the authority applies the
// backlog and the reclaimed segments free the reserved bytes.
func TestBudgetRelievedByTheUplinkReadmitsALargeWrite(t *testing.T) {
	const budget = 8 << 20
	// Small segments so the budget is reachable across several of them: whole
	// applied segments are what reclamation frees, and the rollovers also put
	// the reservation's segment-rollover cost (header + re-emitted live
	// delegations) under test.
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 1 << 20
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	f := newSaturationFixture(t, budget)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	chunk := bytes.Repeat([]byte("z"), 512<<10)
	var refused error
	off := int64(0)
	for i := 0; i < 64 && refused == nil; i++ {
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, handled, err := f.e.WriteAt(wctx, "d/f", off, chunk)
		cancel()
		switch {
		case err != nil && !handled:
			t.Fatalf("append %d changed lanes: %v", i, err)
		case err != nil:
			refused = err
		default:
			off += int64(len(chunk))
		}
	}
	if !errors.Is(refused, ErrNoSpace) {
		t.Fatalf("budget exhaustion surfaced %v, want %v", refused, ErrNoSpace)
	}
	if used := walBytes(t, f.e); used > budget {
		t.Fatalf("stream WAL reached %d bytes, past its %d budget", used, budget)
	}

	f.openUplink()
	fsyncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := f.e.Fsync(fsyncCtx, "d/f"); err != nil {
		t.Fatalf("fsync of admitted data during exhaustion: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, handled, err := f.e.WriteAt(ctx, "d/f", off, chunk)
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
}

// TestWALReservationIsExactAndSettles pins the reservation at the layer that
// owns it. The projected cost must equal the bytes the append actually adds —
// an underestimate lets the log grow past the budget, an overestimate is a
// false ENOSPC — including across segment rollovers, which charge a header and
// the re-emitted live-delegation set. A refusal must leave the log byte-for-byte
// unchanged and must not strand its reservation, and the headroom the budget
// still has must remain usable.
func TestWALReservationIsExactAndSettles(t *testing.T) {
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 16 << 10 // several rollovers inside the budget
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	w, err := createStreamWAL(t.TempDir(), [16]byte{1}, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create stream: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if err := w.appendControl(frameDelegation, delegationFrame{Scope: "d", Epoch: "e1"}); err != nil {
		t.Fatalf("install delegation: %v", err)
	}

	const budget = 128 << 10
	payload := make([]byte, 4<<10)
	var admitted int
	for i := 0; i < 1024; i++ {
		w.mu.Lock()
		before := w.diskBytesLocked()
		cost, err := w.appendCostLocked([][]byte{payload})
		w.mu.Unlock()
		if err != nil {
			t.Fatalf("project cost: %v", err)
		}
		_, err = w.appendMutationsWithin([][]byte{payload}, budget)
		if errors.Is(err, ErrNoSpace) {
			if now := w.DiskBytes(); now != before {
				t.Fatalf("a refused append changed the log from %d to %d bytes", before, now)
			}
			break
		}
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		admitted++
		switch grew := w.DiskBytes() - before; {
		case grew != cost:
			t.Fatalf("append %d added %d bytes, reservation charged %d: the budget is only a "+
				"bound if admission charges what the append really costs", i, grew, cost)
		case w.DiskBytes() > budget:
			t.Fatalf("append %d left the log at %d bytes, past its %d budget", i, w.DiskBytes(), budget)
		}
	}
	if admitted == 0 {
		t.Fatal("the budget refused every append")
	}

	w.mu.Lock()
	stranded := w.reserved
	rollover := w.segments[len(w.segments)-1].size >= segmentTargetBytes
	headroom := budget - w.diskBytesLocked()
	w.mu.Unlock()
	if stranded != 0 {
		t.Fatalf("%d reserved bytes survived the appends that settled them", stranded)
	}
	// Tightness: whatever headroom is left is genuinely usable.
	if !rollover && headroom >= frameHeaderSize+frameAlign {
		fit := make([]byte, (headroom-frameHeaderSize)/frameAlign*frameAlign)
		if _, err := w.appendMutationsWithin([][]byte{fit}, budget); err != nil {
			t.Fatalf("an append sized to the exact remaining headroom (%d bytes) was refused: %v",
				headroom, err)
		}
		if now := w.DiskBytes(); now != budget {
			t.Fatalf("the exactly-fitting append left the log at %d bytes, want the full %d budget", now, budget)
		}
	}
}

func fileName(w int) string { return "d/f" + string(rune('a'+w)) }

// walBytes reports the stream's current on-disk footprint — the quantity the
// budget bounds.
func walBytes(t *testing.T, e *Engine) int64 {
	t.Helper()
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.wal == nil {
		return 0
	}
	return e.wal.DiskBytes()
}
