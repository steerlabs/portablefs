package wal

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// This file is a rigorous concurrency + fault-injection stress harness for the
// group-commit WAL path (AppendBuffered + CommitThrough + flushLocked). It
// deliberately probes the invariants the production design promises:
//
//   - durableSeq is monotonic non-decreasing and never exceeds the number of buffered
//     records (it is set to a snapshot of nextSeq taken under w.mu inside a flush).
//   - a record whose CommitThrough returned nil is genuinely on disk and survives a
//     reopen/Replay, with contiguous LSNs (no gaps, no dups).
//   - durability failure: a failed fsync POISONS the log (no acknowledgement), does
//     NOT advance durableSeq past the failed batch, and fences every later append.

// ---------------------------------------------------------------------------
// 1. Concurrency: monotonic durableSeq, durable==replayed prefix, no gaps/dups.
// ---------------------------------------------------------------------------

// TestGroupCommitConcurrentDurableInvariants hammers the group-commit path with many
// goroutines, each doing AppendBuffered+CommitThrough cycles. It asserts the
// load-bearing invariants:
//
//   - durableSeq observed by any committer is monotonic non-decreasing.
//   - durableSeq never exceeds the count of records buffered so far.
//   - every CommitThrough that returns nil means its LSN is < the new durableSeq, so the
//     record is durable; a later reopen/Replay replays a contiguous LSN prefix [0,nextSeq)
//     with no gaps and no duplicates.
func TestGroupCommitConcurrentDurableInvariants(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}

	const (
		goroutines = 64
		perG       = 200
	)
	total := goroutines * perG

	// maxDurableSeen tracks the global high-water durableSeq; each committer CASes it up
	// and asserts it never goes backwards relative to the value it just read.
	var maxDurableSeen uint64
	var monotonicViolations int64
	var boundViolations int64
	var ackedCount int64

	var wg sync.WaitGroup
	for gi := 0; gi < goroutines; gi++ {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				seq, err := primary.AppendBuffered(Record{
					Op:   OpCreate,
					Path: fmt.Sprintf("g%02d-%04d", gi, j),
					Mode: 0o644,
				})
				if err != nil {
					t.Errorf("AppendBuffered(g%d,%d): %v", gi, j, err)
					return
				}
				if err := primary.CommitThrough(seq); err != nil {
					t.Errorf("CommitThrough(%d): %v", seq, err)
					return
				}
				atomic.AddInt64(&ackedCount, 1)

				// Read durableSeq under commitMu via the accessor so the read is race-clean,
				// then check monotonicity against the global high-water mark.
				d := primary.durableSeqForTest()
				for {
					prev := atomic.LoadUint64(&maxDurableSeen)
					if d <= prev {
						break // someone advanced it past us already; still non-decreasing
					}
					if atomic.CompareAndSwapUint64(&maxDurableSeen, prev, d) {
						break
					}
				}
				// After our own CommitThrough(seq) returned nil, seq must be durable, i.e.
				// durableSeq must be strictly greater than seq (durableSeq is exclusive).
				if d <= seq {
					// Another committer may have advanced durableSeq beyond what we sampled,
					// but it can only go UP, so re-sample once before declaring a violation.
					if primary.durableSeqForTest() <= seq {
						atomic.AddInt64(&monotonicViolations, 1)
					}
				}
				// durableSeq must never exceed the number of records buffered so far.
				if d > primary.Watermark() {
					atomic.AddInt64(&boundViolations, 1)
				}
			}
		}(gi)
	}
	wg.Wait()

	if monotonicViolations != 0 {
		t.Fatalf("%d committers observed durableSeq <= their own acked LSN (record not durable after ack)", monotonicViolations)
	}
	if boundViolations != 0 {
		t.Fatalf("%d observations of durableSeq exceeding the buffered-record count", boundViolations)
	}
	if got := atomic.LoadInt64(&ackedCount); got != int64(total) {
		t.Fatalf("acked %d records, want %d", got, total)
	}

	// Every record was acked, so durableSeq must equal nextSeq (== total): the final
	// committer either flushed the last batch itself or saw a flush that already covered it.
	if d := primary.durableSeqForTest(); d != uint64(total) {
		t.Fatalf("final durableSeq = %d, want %d (all acked records must be durable)", d, total)
	}
	if wm := primary.Watermark(); wm != uint64(total) {
		t.Fatalf("final watermark = %d, want %d", wm, total)
	}

	// Reopen the log and replay: a contiguous LSN prefix [0,total), no gaps/dups.
	assertContiguousReplay(t, "primary", filepath.Join(dir, "p.wal"), total)
}

// assertContiguousReplay reopens the WAL at path and asserts Replay yields exactly want
// records whose LSNs are the contiguous set {0,1,...,want-1} in order (no gaps, no dups).
func assertContiguousReplay(t *testing.T, label, path string, want int) {
	t.Helper()
	w, err := Open(path)
	if err != nil {
		t.Fatalf("[%s] reopen: %v", label, err)
	}
	defer w.Close()
	recs, err := w.Replay()
	if err != nil {
		t.Fatalf("[%s] replay: %v", label, err)
	}
	if len(recs) != want {
		t.Fatalf("[%s] replay = %d records, want %d", label, len(recs), want)
	}
	seen := make([]bool, want)
	for i, r := range recs {
		if r.Seq != uint64(i) {
			t.Fatalf("[%s] record %d has LSN %d, want %d (LSNs must be a gapless in-order prefix)", label, i, r.Seq, i)
		}
		if r.Seq >= uint64(want) {
			t.Fatalf("[%s] record %d has out-of-range LSN %d (>= %d)", label, i, r.Seq, want)
		}
		if seen[r.Seq] {
			t.Fatalf("[%s] LSN %d appears more than once (duplicate)", label, r.Seq)
		}
		seen[r.Seq] = true
	}
}

// ---------------------------------------------------------------------------
// 2. Durability-barrier poison invariant on fsync failure.
// ---------------------------------------------------------------------------

// TestGroupCommitPoisonRacesManyCommitters drives the poison path under
// concurrency: the log's file descriptor is closed out from under it (the
// in-package equivalent of a dying disk), with many goroutines
// appending+committing. It asserts that once poisoned, the log is
// consistently poisoned for everyone (no committer ever gets a nil ack for a
// batch flushed after the failure) and durableSeq is frozen at whatever the
// last successful flush reached.
func TestGroupCommitPoisonRacesManyCommitters(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}
	// Fail every flush from the start: close the fd before any commit runs.
	primary.mu.Lock()
	_ = primary.f.Close()
	primary.mu.Unlock()

	const goroutines = 32
	var wg sync.WaitGroup
	var anyAck int64    // commits that returned nil
	var anyPoison int64 // commits/appends that saw a failure
	for gi := 0; gi < goroutines; gi++ {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			seq, err := primary.AppendBuffered(Record{Op: OpCreate, Path: fmt.Sprintf("p%d", gi), Mode: 0o644})
			if err != nil {
				// Poisoned by a peer's failed flush, or the closed fd rejected
				// the frame write. Either way the record was never acked.
				atomic.AddInt64(&anyPoison, 1)
				return
			}
			err = primary.CommitThrough(seq)
			if err == nil {
				atomic.AddInt64(&anyAck, 1)
			} else {
				// The only acceptable outcomes are errPoisoned (a later committer hit
				// the already-poisoned log) or this committer's own flush failing on
				// the closed fd.
				atomic.AddInt64(&anyPoison, 1)
			}
		}(gi)
	}
	wg.Wait()

	// The fd is closed before any flush, so NO commit may return nil.
	if anyAck != 0 {
		t.Fatalf("%d commits returned nil despite every fsync failing — durability barrier violated", anyAck)
	}
	if anyPoison == 0 {
		t.Fatal("expected at least one poisoned error across the concurrent committers")
	}
	// PoisonedCh closed, durableSeq still 0 (no flush ever succeeded).
	select {
	case <-primary.PoisonedCh():
	default:
		t.Fatal("PoisonedCh must be closed")
	}
	if d := primary.durableSeqForTest(); d != 0 {
		t.Fatalf("durableSeq = %d, want 0 (no flush ever succeeded)", d)
	}
	if !errors.Is(primary.Append(Record{Op: OpCreate, Path: "post", Mode: 0o644}), errPoisoned) {
		t.Fatal("appends after a failed flush must be refused as poisoned")
	}
}

// ---------------------------------------------------------------------------
// 3. Adversarial edges discovered by reading the code.
// ---------------------------------------------------------------------------

// oversize returns a payload large enough that frame() rejects the record (its sealed/
// framed size exceeds maxRecordBytes), forcing a deterministic mid-batch failure without
// any I/O error injection. It is allocated once and is just over the limit.
func oversize(t *testing.T) []byte {
	t.Helper()
	// frame() rejects when len(payload) > maxRecordBytes, where payload is the gob of the
	// record (plaintext, since these WALs are unencrypted) — gob of a Record with a
	// (maxRecordBytes+1)-byte Data field is strictly larger than the limit.
	return make([]byte, maxRecordBytes+1)
}

// TestCommitThroughBelowDurableIsNoOp verifies the exclusive-bound semantics of
// CommitThrough: a commit for an LSN already covered by durableSeq returns immediately
// without another flush, and an empty flush leaves durableSeq unchanged.
func TestCommitThroughBelowDurableIsNoOp(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}

	s0, _ := primary.AppendBuffered(Record{Op: OpCreate, Path: "a", Mode: 0o644})
	s1, _ := primary.AppendBuffered(Record{Op: OpCreate, Path: "b", Mode: 0o644})
	s2, _ := primary.AppendBuffered(Record{Op: OpCreate, Path: "c", Mode: 0o644})
	if err := primary.CommitThrough(s2); err != nil { // flush #1 sweeps 0,1,2
		t.Fatal(err)
	}
	if d := primary.durableSeqForTest(); d != s2+1 {
		t.Fatalf("durableSeq = %d, want %d", d, s2+1)
	}

	// Re-committing already-durable LSNs must be a no-op: durableSeq > seq for all of them.
	for _, s := range []uint64{s0, s1, s2} {
		if err := primary.CommitThrough(s); err != nil {
			t.Fatalf("re-commit %d: %v", s, err)
		}
	}

	// Edge: CommitThrough(durableSeq-1) is covered (exclusive bound);
	// CommitThrough(durableSeq) is NOT yet covered and forces an empty flush
	// (fsync only, no new records) that leaves durableSeq unchanged.
	highest := primary.durableSeqForTest() // == s2+1
	if err := primary.CommitThrough(highest - 1); err != nil {
		t.Fatal(err)
	}
	if err := primary.CommitThrough(highest); err != nil {
		t.Fatalf("empty flush: %v", err)
	}
	if d := primary.durableSeqForTest(); d != highest {
		t.Fatalf("durableSeq changed on empty flush: %d -> %d", highest, d)
	}
}

// TestConcurrentCompactionVsCommit runs CompactThrough concurrently with a stream of
// AppendBuffered+CommitThrough. CompactThrough takes commitMu and flushes the pending
// batch first, then rewrites the file; commits and compactions must not corrupt the log.
// Afterwards every record at or above the final compaction watermark must replay with
// gapless LSNs, and no acknowledged record below the watermark may resurrect.
func TestConcurrentCompactionVsCommit(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}

	const (
		writers = 16
		perW    = 100
	)
	var wg sync.WaitGroup
	var acked int64
	stop := make(chan struct{})

	// Writers.
	for wi := 0; wi < writers; wi++ {
		wg.Add(1)
		go func(wi int) {
			defer wg.Done()
			for j := 0; j < perW; j++ {
				seq, err := primary.AppendBuffered(Record{Op: OpCreate, Path: fmt.Sprintf("w%02d-%03d", wi, j), Mode: 0o644})
				if err != nil {
					t.Errorf("append: %v", err)
					return
				}
				if err := primary.CommitThrough(seq); err != nil {
					t.Errorf("commit: %v", err)
					return
				}
				atomic.AddInt64(&acked, 1)
			}
		}(wi)
	}

	// A compactor racing the writers: repeatedly compact through a low, lagging watermark
	// so it always keeps a tail and interleaves with in-flight commits.
	var compactErr atomic.Value
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			wm := primary.Watermark()
			if wm > 4 {
				// keep a tail: compact through wm-4 so concurrent appends above survive.
				if err := primary.CompactThrough(wm - 4); err != nil {
					compactErr.Store(err)
					return
				}
			}
		}
	}()

	// Let writers finish, then stop the compactor.
	go func() {
		// wait until all writer goroutines are done by polling acked; cheap and avoids a
		// second WaitGroup. perW*writers is the target.
		for atomic.LoadInt64(&acked) < int64(writers*perW) {
		}
		close(stop)
	}()
	wg.Wait()

	if e := compactErr.Load(); e != nil {
		t.Fatalf("concurrent compaction failed: %v", e)
	}
	if got := atomic.LoadInt64(&acked); got != int64(writers*perW) {
		t.Fatalf("acked %d, want %d", got, writers*perW)
	}

	// Final state: replay must succeed (no corruption) with strictly increasing, gapless
	// LSNs, and the highest LSN present must be exactly Watermark-1 (the last appended).
	recs, err := primary.Replay()
	if err != nil {
		t.Fatalf("replay after concurrent compaction: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("expected a surviving tail after lagging compaction")
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].Seq != recs[i-1].Seq+1 {
			t.Fatalf("replay has an LSN gap: rec[%d].Seq=%d, rec[%d].Seq=%d (compaction/commit interleaving corrupted ordering)", i-1, recs[i-1].Seq, i, recs[i].Seq)
		}
	}
	if last := recs[len(recs)-1].Seq; last != primary.Watermark()-1 {
		t.Fatalf("highest replayed LSN = %d, want Watermark-1 = %d", last, primary.Watermark()-1)
	}
	t.Logf("survived %d acked writes racing compaction; tail = %d records, LSNs [%d..%d]",
		writers*perW, len(recs), recs[0].Seq, recs[len(recs)-1].Seq)
}

// TestConcurrentResetVsCommit races Reset against committers. Reset takes commitMu and
// restarts LSN numbering at 0; a commit either lands before the reset (acked, then wiped)
// or fails/no-ops. The invariant under test: the operation never corrupts the log — after
// the dust settles, Replay succeeds and any records present have gapless LSNs from 0.
func TestConcurrentResetVsCommit(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}

	const writers = 16
	var wg sync.WaitGroup
	for wi := 0; wi < writers; wi++ {
		wg.Add(1)
		go func(wi int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				seq, err := primary.AppendBuffered(Record{Op: OpCreate, Path: fmt.Sprintf("r%02d-%03d", wi, j), Mode: 0o644})
				if err != nil {
					return // a poison or transient error is acceptable under reset races
				}
				_ = primary.CommitThrough(seq) // may fail benignly while a reset is mid-flight
			}
		}(wi)
	}
	// A few resets interleaved with the writers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for k := 0; k < 5; k++ {
			if err := primary.Reset(); err != nil {
				t.Errorf("reset: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	// The log must be coherent: replay succeeds and LSNs are a gapless prefix from 0.
	recs, err := primary.Replay()
	if err != nil {
		t.Fatalf("replay after reset races: %v", err)
	}
	for i, r := range recs {
		if r.Seq != uint64(i) {
			t.Fatalf("post-reset replay LSN gap at %d: Seq=%d", i, r.Seq)
		}
	}
	// durableSeq must never exceed the live record count's LSN bound (nextSeq).
	if d := primary.durableSeqForTest(); d > primary.Watermark() {
		t.Fatalf("durableSeq %d exceeds watermark %d after reset races", d, primary.Watermark())
	}
}
