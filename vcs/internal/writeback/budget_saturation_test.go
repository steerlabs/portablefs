package writeback

import (
	"context"
	"errors"
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

// TestStreamWALBudgetExhaustionIsDefiniteENOSPC pins the base contract: once
// the stream WAL is at budget and folding/reclaiming cannot relieve it, a
// data admission is refused with ErrNoSpace. It stays in the delegated lane
// (handled=true) and never drains, so the caller gets a definite POSIX
// outcome instead of a wait on the uplink that is behind.
func TestStreamWALBudgetExhaustionIsDefiniteENOSPC(t *testing.T) {
	f := newSaturationFixture(t, 1<<20)
	ctx := context.Background()
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	chunk := make([]byte, 64<<10)
	_, _, releasesBefore := f.auth.calls()

	var refused error
	for i := 0; i < 256 && refused == nil; i++ {
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		_, handled, err := f.e.WriteAppend(wctx, "d/f", chunk)
		elapsed := time.Since(start)
		cancel()
		if elapsed > 2*time.Second {
			t.Fatalf("append %d blocked for %s under budget pressure", i, elapsed)
		}
		switch {
		case err != nil && !handled:
			t.Fatalf("append %d changed lanes on an error: %v", i, err)
		case err != nil:
			refused = err
		case !handled:
			t.Fatalf("append %d left the delegated lane while the budget was the binding constraint", i)
		}
	}
	if !errors.Is(refused, ErrNoSpace) {
		t.Fatalf("budget exhaustion surfaced %v, want %v", refused, ErrNoSpace)
	}
	if _, _, releasesAfter := f.auth.calls(); releasesAfter != releasesBefore {
		t.Fatalf("budget exhaustion released %d delegations; a definite ENOSPC must not hand off",
			releasesAfter-releasesBefore)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("budget exhaustion dropped the covering delegation")
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
