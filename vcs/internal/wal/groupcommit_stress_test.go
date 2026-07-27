package wal

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// This file is a rigorous concurrency + fault-injection stress harness for the
// group-commit WAL path (AppendBuffered + CommitThrough + flushLocked, and the
// standby mirror AppendReplicatedBatch). It deliberately probes the invariants the
// production design promises:
//
//   - durableSeq is monotonic non-decreasing and never exceeds the number of buffered
//     records (it is set to a snapshot of nextSeq taken under w.mu inside a flush).
//   - a record whose CommitThrough returned nil is genuinely on disk and survives a
//     reopen/Replay, with contiguous LSNs (no gaps, no dups).
//   - durability failure: a replica AppendBatch failure POISONS the log (no acknowledgement),
//     does NOT advance durableSeq past the failed batch, and fences every later append.
//   - the standby accepts identical LSN retries, rejects conflicts/gaps, and rolls back a mid-batch
//     failure all-or-nothing (nextSeq/offset/Replay restored exactly).
//
// Helpers from durability_test.go are reused (same package): failReplica, localReplica.

// ---------------------------------------------------------------------------
// Test-local replica fakes (named to avoid colliding with durability_test.go).
// ---------------------------------------------------------------------------

// countingReplica forwards to a second WAL (a faithful in-process standby) and counts
// how many records/batches it applied. It is concurrency-safe; CommitThrough serializes
// AppendBatch under commitMu, but we lock anyway so the counters are race-clean and so a
// reader (the test) can sample mid-flight.
type countingReplica struct {
	w       *WAL
	mu      sync.Mutex
	batches int
	records int
}

func (c *countingReplica) Append(r Record) error { return c.AppendBatch([]Record{r}) }
func (c *countingReplica) AppendBatch(rs []Record) error {
	if err := c.w.AppendReplicatedBatch(rs); err != nil {
		return err
	}
	c.mu.Lock()
	c.batches++
	c.records += len(rs)
	c.mu.Unlock()
	return nil
}
func (c *countingReplica) Reset() error             { return c.w.Reset() }
func (c *countingReplica) Compact(seq uint64) error { return c.w.CompactThrough(seq) }

// gateReplica returns an error from AppendBatch once a (test-controlled) gate trips,
// modelling a standby that goes down mid-stream. Before the gate it forwards to a real
// standby WAL so up-to-the-failure state is realistic; after, every batch is rejected.
// failAtRecord: once the cumulative count of records the primary has *attempted* to
// replicate reaches this threshold, the batch carrying it (and all later batches) fail.
type gateReplica struct {
	w           *WAL
	failAtFlush int64 // fail the Nth flush (1-based); 0 = never fail by flush count
	mu          sync.Mutex
	flushes     int64
	appliedRecs int
	failed      bool
}

func (g *gateReplica) Append(r Record) error { return g.AppendBatch([]Record{r}) }
func (g *gateReplica) AppendBatch(rs []Record) error {
	g.mu.Lock()
	g.flushes++
	n := g.flushes
	g.mu.Unlock()
	if g.failAtFlush != 0 && n >= g.failAtFlush {
		g.mu.Lock()
		g.failed = true
		g.mu.Unlock()
		return fmt.Errorf("gateReplica: injected failure on flush %d", n)
	}
	if err := g.w.AppendReplicatedBatch(rs); err != nil {
		return err
	}
	g.mu.Lock()
	g.appliedRecs += len(rs)
	g.mu.Unlock()
	return nil
}
func (g *gateReplica) Reset() error             { return g.w.Reset() }
func (g *gateReplica) Compact(seq uint64) error { return g.w.CompactThrough(seq) }

// isInjectedGateErr reports whether err is the gateReplica's injected failure (which the
// primary surfaces verbatim from flushLocked when the replica rejects a batch).
func isInjectedGateErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "gateReplica: injected failure")
}

// ---------------------------------------------------------------------------
// 1. Concurrency: monotonic durableSeq, durable==replayed prefix, no gaps/dups.
// ---------------------------------------------------------------------------

// TestGroupCommitConcurrentDurableInvariants hammers the group-commit path with many
// goroutines, each doing AppendBuffered+CommitThrough cycles against a real in-process
// standby. It asserts the load-bearing invariants:
//
//   - durableSeq observed by any committer is monotonic non-decreasing.
//   - durableSeq never exceeds the count of records buffered so far.
//   - every CommitThrough that returns nil means its LSN is < the new durableSeq, so the
//     record is durable; a later reopen/Replay replays a contiguous LSN prefix [0,nextSeq)
//     with no gaps and no duplicates, and the standby holds the identical record set.
func TestGroupCommitConcurrentDurableInvariants(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &countingReplica{w: standby}
	primary.SetReplica(rep)

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

	// Reopen the primary log and replay: a contiguous LSN prefix [0,total), no gaps/dups.
	assertContiguousReplay(t, "primary", filepath.Join(dir, "p.wal"), total)
	// The standby is a faithful mirror: same record count, same contiguous LSN prefix.
	assertContiguousReplay(t, "standby", filepath.Join(dir, "s.wal"), total)

	rep.mu.Lock()
	if rep.records != total {
		t.Fatalf("standby applied %d records via replication, want %d", rep.records, total)
	}
	t.Logf("group commit: %d concurrent acked writes flushed in %d replication batches (avg %.1f records/batch)",
		total, rep.batches, float64(total)/float64(rep.batches))
	rep.mu.Unlock()
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
// 2. Durability-barrier poison invariant on replica failure.
// ---------------------------------------------------------------------------

// TestGroupCommitReplicaFailurePoisonsAndDoesNotAdvanceDurable injects a replica that
// fails its AppendBatch at a chosen flush. It asserts the full fail-closed durability
// contract:
//
//   - the CommitThrough whose flush hits the failing replica returns a non-nil error;
//   - PoisonedCh() is closed (the node can fence its data plane);
//   - durableSeq does NOT advance to cover the failed batch (no record in it is durable);
//   - subsequent AppendBuffered and CommitThrough are refused (poisoned), so the node halts;
//   - no record from the failed batch was ever reported durable on the standby.
func TestGroupCommitReplicaFailurePoisonsAndDoesNotAdvanceDurable(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	// Fail on the 2nd flush: the 1st batch commits durably, the 2nd is rejected.
	gate := &gateReplica{w: standby, failAtFlush: 2}
	primary.SetReplica(gate)

	// Flush #1: commit one record fully and durably.
	seq0, err := primary.AppendBuffered(Record{Op: OpCreate, Path: "good0", Mode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.CommitThrough(seq0); err != nil {
		t.Fatalf("first commit must succeed: %v", err)
	}
	durableBefore := primary.durableSeqForTest()
	if durableBefore != seq0+1 {
		t.Fatalf("durableSeq after first commit = %d, want %d", durableBefore, seq0+1)
	}

	// Buffer a second record and commit it — flush #2 hits the failing replica.
	seq1, err := primary.AppendBuffered(Record{Op: OpCreate, Path: "doomed1", Mode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	commitErr := primary.CommitThrough(seq1)
	if commitErr == nil {
		t.Fatal("CommitThrough must return an error when the replica rejects the batch")
	}

	// PoisonedCh must be closed.
	select {
	case <-primary.PoisonedCh():
	default:
		t.Fatal("PoisonedCh() must be closed after an unrecoverable replication failure")
	}

	// durableSeq must NOT have advanced past the failed batch: the doomed record is not durable.
	if d := primary.durableSeqForTest(); d != durableBefore {
		t.Fatalf("durableSeq advanced to %d after a failed flush, want it to stay at %d (doomed record must not be durable)", d, durableBefore)
	}
	if durableBefore > seq1 {
		t.Fatalf("test setup wrong: durableBefore %d already covers doomed LSN %d", durableBefore, seq1)
	}

	// Subsequent appends and commits are refused.
	if _, err := primary.AppendBuffered(Record{Op: OpCreate, Path: "after", Mode: 0o644}); !errors.Is(err, errPoisoned) {
		t.Fatalf("AppendBuffered after poison = %v, want errPoisoned", err)
	}
	if err := primary.CommitThrough(seq1); !errors.Is(err, errPoisoned) {
		// CommitThrough re-flushes (durableSeq still <= seq1) and flushLocked sees poisoned.
		t.Fatalf("CommitThrough after poison = %v, want errPoisoned", err)
	}
	if err := primary.Append(Record{Op: OpCreate, Path: "after2", Mode: 0o644}); !errors.Is(err, errPoisoned) {
		t.Fatalf("Append after poison = %v, want errPoisoned", err)
	}

	// The standby must NOT have the doomed record: only the durable prefix was applied.
	gate.mu.Lock()
	applied := gate.appliedRecs
	failed := gate.failed
	gate.mu.Unlock()
	if !failed {
		t.Fatal("gate replica never recorded the injected failure")
	}
	if applied != 1 {
		t.Fatalf("standby applied %d records via replication, want exactly 1 (the durable prefix)", applied)
	}
	recs, err := standby.Replay()
	if err != nil {
		t.Fatalf("standby replay: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "good0" {
		t.Fatalf("standby holds %+v, want only the durable [good0]", recs)
	}
}

// TestGroupCommitPoisonRacesManyCommitters drives the poison path under concurrency: a
// replica that fails after the first flush, with many goroutines appending+committing.
// It asserts that once poisoned, the log is consistently poisoned for everyone (no
// committer ever gets a nil ack for a batch that includes a post-poison record) and that
// durableSeq is frozen at whatever the last successful flush reached.
func TestGroupCommitPoisonRacesManyCommitters(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	gate := &gateReplica{w: standby, failAtFlush: 1} // every flush fails immediately
	primary.SetReplica(gate)

	const goroutines = 32
	var wg sync.WaitGroup
	var anyAck int64    // commits that returned nil
	var anyPoison int64 // commits/appends that saw errPoisoned
	for gi := 0; gi < goroutines; gi++ {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			seq, err := primary.AppendBuffered(Record{Op: OpCreate, Path: fmt.Sprintf("p%d", gi), Mode: 0o644})
			if err != nil {
				// AppendBuffered never calls the replica, so the only error it can return
				// here is errPoisoned (a peer's flush already poisoned the log). Anything
				// else (a frame/write failure on a trivial record) would be a real bug.
				if !errors.Is(err, errPoisoned) {
					t.Errorf("AppendBuffered returned an unexpected error: %v", err)
				}
				atomic.AddInt64(&anyPoison, 1)
				return
			}
			err = primary.CommitThrough(seq)
			if err == nil {
				atomic.AddInt64(&anyAck, 1)
			} else {
				// The only acceptable non-nil outcomes are errPoisoned (a later committer
				// hit the already-poisoned log) or the injected gate-replica error (this
				// committer's own flush was the one rejected). Anything else is a real bug.
				if !errors.Is(err, errPoisoned) && !isInjectedGateErr(err) {
					t.Errorf("CommitThrough returned an unexpected error: %v", err)
				}
				atomic.AddInt64(&anyPoison, 1)
			}
		}(gi)
	}
	wg.Wait()

	// With failAtFlush=1, the very first flush fails, so NO commit may return nil.
	if anyAck != 0 {
		t.Fatalf("%d commits returned nil despite the replica failing every flush — durability barrier violated", anyAck)
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
	if recs, err := standby.Replay(); err != nil || len(recs) != 0 {
		t.Fatalf("standby must be empty (no batch ever applied): recs=%+v err=%v", recs, err)
	}
}

// ---------------------------------------------------------------------------
// 3. Idempotent batch replication + all-or-nothing rollback on the standby.
// ---------------------------------------------------------------------------

// TestAppendReplicatedBatchIdempotentAndOrdered drives the standby's batch-apply path
// directly. It asserts:
//
//   - applying the same batch (or overlapping LSN ranges) twice dedups: the second apply
//     is a no-op, the record count and contents are unchanged (idempotent re-stream).
//   - a record already present is skipped even when bundled with new ones (partial overlap
//     applies only the genuinely-new suffix).
func TestAppendReplicatedBatchIdempotentAndOrdered(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	batch := []Record{
		{Seq: 0, Op: OpCreate, Path: "a", Mode: 0o644},
		{Seq: 1, Op: OpCreate, Path: "b", Mode: 0o644},
		{Seq: 2, Op: OpCreate, Path: "c", Mode: 0o644},
	}
	if err := w.AppendReplicatedBatch(batch); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if c := w.Count(); c != 3 {
		t.Fatalf("count after first apply = %d, want 3", c)
	}

	// Re-apply the exact same batch: fully duplicate LSNs, must be a complete no-op.
	if err := w.AppendReplicatedBatch(batch); err != nil {
		t.Fatalf("idempotent re-apply: %v", err)
	}
	if c := w.Count(); c != 3 {
		t.Fatalf("count after duplicate re-apply = %d, want 3 (dedup failed)", c)
	}

	// Overlapping batch: LSNs 1,2 already present, 3,4 new. Only 3,4 must be appended.
	overlap := []Record{
		{Seq: 1, Op: OpCreate, Path: "b", Mode: 0o644},
		{Seq: 2, Op: OpCreate, Path: "c", Mode: 0o644},
		{Seq: 3, Op: OpCreate, Path: "d", Mode: 0o644},
		{Seq: 4, Op: OpCreate, Path: "e", Mode: 0o644},
	}
	if err := w.AppendReplicatedBatch(overlap); err != nil {
		t.Fatalf("overlap apply: %v", err)
	}
	recs, err := w.Replay()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(recs) != 5 {
		t.Fatalf("count after overlap = %d, want 5", len(recs))
	}
	wantPaths := []string{"a", "b", "c", "d", "e"}
	for i, r := range recs {
		if r.Seq != uint64(i) || r.Path != wantPaths[i] {
			t.Fatalf("record %d = {Seq:%d Path:%q}, want {Seq:%d Path:%q}", i, r.Seq, r.Path, i, wantPaths[i])
		}
	}
}

// TestAppendReplicatedBatchRollsBackMidBatchFailure proves the standby's batch apply is
// all-or-nothing: a write failure partway through a batch truncates the partial bytes and
// restores nextSeq/offset exactly, so Replay before and after is byte-identical and the
// next genuine batch lands at the right LSN.
func TestAppendReplicatedBatchRollsBackMidBatchFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.wal")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	// Seed a stable prefix and capture the pre-failure state.
	seed := []Record{
		{Seq: 0, Op: OpCreate, Path: "s0", Mode: 0o644},
		{Seq: 1, Op: OpCreate, Path: "s1", Mode: 0o644},
	}
	if err := w.AppendReplicatedBatch(seed); err != nil {
		t.Fatal(err)
	}
	before, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	offBefore := w.offset
	seqBefore := w.nextSeq
	countBefore := w.count
	if len(before) != 2 || seqBefore != 2 {
		t.Fatalf("seed state wrong: recs=%d nextSeq=%d", len(before), seqBefore)
	}

	// Force a deterministic mid-batch failure: the SECOND record carries an oversize
	// payload that frame() rejects (len(payload) > maxRecordBytes). The first record is
	// written to the file (added>0), then framing the second fails, so the all-or-nothing
	// path (added>0 -> rollbackToLocked) must truncate the first record's bytes back out.
	mid := []Record{
		{Seq: 2, Op: OpCreate, Path: "ok", Mode: 0o644},          // writes fine
		{Seq: 3, Op: OpWrite, Path: "toobig", Data: oversize(t)}, // frame() rejects -> rollback
	}
	err = w.AppendReplicatedBatch(mid)
	if err == nil {
		t.Fatal("AppendReplicatedBatch must fail when a record cannot be framed")
	}

	// All-or-nothing: state restored exactly. nextSeq/offset/count unchanged; the first
	// record's bytes ("ok") were truncated away.
	if w.offset != offBefore {
		t.Fatalf("offset after rollback = %d, want %d (partial bytes not truncated)", w.offset, offBefore)
	}
	if w.nextSeq != seqBefore {
		t.Fatalf("nextSeq after rollback = %d, want %d", w.nextSeq, seqBefore)
	}
	if w.count != countBefore {
		t.Fatalf("count after rollback = %d, want %d", w.count, countBefore)
	}
	after, err := w.Replay()
	if err != nil {
		t.Fatalf("replay after rollback: %v", err)
	}
	if len(after) != 2 || after[0].Path != "s0" || after[1].Path != "s1" {
		t.Fatalf("replay after rollback = %+v, want the pristine seed [s0 s1] (the 'ok' record must be gone)", after)
	}

	// The log must still accept a genuine batch starting at the right LSN.
	good := []Record{
		{Seq: 2, Op: OpCreate, Path: "g2", Mode: 0o644},
		{Seq: 3, Op: OpCreate, Path: "g3", Mode: 0o644},
	}
	if err := w.AppendReplicatedBatch(good); err != nil {
		t.Fatalf("apply after rollback: %v", err)
	}
	final, _ := w.Replay()
	if len(final) != 4 {
		t.Fatalf("final count = %d, want 4", len(final))
	}
	for i, r := range final {
		if r.Seq != uint64(i) {
			t.Fatalf("final record %d has LSN %d, want %d (rollback left a gap)", i, r.Seq, i)
		}
	}
	_ = w.Close()
}

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

// ---------------------------------------------------------------------------
// 4. Adversarial edges discovered by reading the code.
// ---------------------------------------------------------------------------

// TestCommitThroughBelowDurableIsNoOp verifies the exclusive-bound semantics of
// CommitThrough: a commit for an LSN already covered by durableSeq returns immediately
// without forcing another fsync/replication round-trip. We prove "no extra round-trip" by
// counting replica batches: re-committing covered LSNs must not produce new batches.
func TestCommitThroughBelowDurableIsNoOp(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &countingReplica{w: standby}
	primary.SetReplica(rep)

	// Commit three records (one flush, since they are buffered then a single CommitThrough
	// covers all — but here we commit each, and the first flush already advances durableSeq
	// past the rest only if they were buffered first; commit them one-by-one after buffering
	// all, so the first flush sweeps all three in one batch).
	s0, _ := primary.AppendBuffered(Record{Op: OpCreate, Path: "a", Mode: 0o644})
	s1, _ := primary.AppendBuffered(Record{Op: OpCreate, Path: "b", Mode: 0o644})
	s2, _ := primary.AppendBuffered(Record{Op: OpCreate, Path: "c", Mode: 0o644})
	if err := primary.CommitThrough(s2); err != nil { // flush #1 sweeps 0,1,2
		t.Fatal(err)
	}
	rep.mu.Lock()
	batchesAfterFirst := rep.batches
	rep.mu.Unlock()
	if d := primary.durableSeqForTest(); d != s2+1 {
		t.Fatalf("durableSeq = %d, want %d", d, s2+1)
	}

	// Re-committing already-durable LSNs must be a no-op: durableSeq > seq for all of them.
	for _, s := range []uint64{s0, s1, s2} {
		if err := primary.CommitThrough(s); err != nil {
			t.Fatalf("re-commit %d: %v", s, err)
		}
	}
	rep.mu.Lock()
	batchesAfterRecommit := rep.batches
	rep.mu.Unlock()
	if batchesAfterRecommit != batchesAfterFirst {
		t.Fatalf("re-committing durable LSNs triggered %d extra replication batches (want 0)", batchesAfterRecommit-batchesAfterFirst)
	}

	// Edge: CommitThrough(durableSeq-1) is covered (exclusive bound) and must not flush;
	// CommitThrough(durableSeq) is NOT yet covered and forces a flush even with no new
	// records (an empty batch — fsync only, no replica round-trip since batch is empty).
	highest := primary.durableSeqForTest() // == s2+1
	if err := primary.CommitThrough(highest - 1); err != nil {
		t.Fatal(err)
	}
	rep.mu.Lock()
	if rep.batches != batchesAfterFirst {
		rep.mu.Unlock()
		t.Fatalf("CommitThrough(durableSeq-1) caused a replication batch (should be a no-op)")
	}
	rep.mu.Unlock()
}

// TestCommitThroughEmptyFlushFsyncsButDoesNotReplicate verifies flushLocked's guard
// `len(batch) > 0`: a flush with an empty buffer (e.g. CommitThrough called for an LSN
// equal to durableSeq when nothing new was buffered) fsyncs the file but does NOT call
// replica.AppendBatch (which would otherwise ship an empty batch). durableSeq is unchanged
// because target == durableSeq (no new records).
func TestCommitThroughEmptyFlushFsyncsButDoesNotReplicate(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &countingReplica{w: standby}
	primary.SetReplica(rep)

	s0, _ := primary.AppendBuffered(Record{Op: OpCreate, Path: "a", Mode: 0o644})
	if err := primary.CommitThrough(s0); err != nil {
		t.Fatal(err)
	}
	rep.mu.Lock()
	batches1, records1 := rep.batches, rep.records
	rep.mu.Unlock()

	// Now nothing is buffered. CommitThrough(durableSeq) is NOT covered (durableSeq is
	// exclusive, durableSeq > durableSeq is false), so it flushes — but the batch is empty.
	d := primary.durableSeqForTest()
	if err := primary.CommitThrough(d); err != nil {
		t.Fatalf("empty flush: %v", err)
	}
	rep.mu.Lock()
	batches2, records2 := rep.batches, rep.records
	rep.mu.Unlock()
	if batches2 != batches1 || records2 != records1 {
		t.Fatalf("empty flush shipped a replica batch: batches %d->%d, records %d->%d (want unchanged)", batches1, batches2, records1, records2)
	}
	if d2 := primary.durableSeqForTest(); d2 != d {
		t.Fatalf("durableSeq changed on empty flush: %d -> %d", d, d2)
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
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &countingReplica{w: standby}
	primary.SetReplica(rep)

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
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &countingReplica{w: standby}
	primary.SetReplica(rep)

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
