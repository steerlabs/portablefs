package writeback

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// The flush batch size is the uplink amortization knob. These tests pin the two
// things raising it has to satisfy: it must stay inside every wire and journal
// bound that constrains it, and it must actually amortize the per-batch fixed
// cost against a rate-limited remote.

// TestFlushBatchStaysInsideEveryHardBound proves the constant is admissible by
// the bounds that constrain it rather than by assertion. The batch travels as
// ONE request frame and applies as one row PER RECORD, so it is the request
// frame — not the 8 MiB journal-entry bound — that caps it.
func TestFlushBatchStaysInsideEveryHardBound(t *testing.T) {
	// Worst case the build loop can produce: it admits records while
	// bytes < flushMaxBytes, so one whole record may cross the line.
	worstBulk := int64(flushMaxBytes) + int64(maxMutationPayload)
	// Per-record metadata (paths, envelopes, framing) for a full-count batch.
	worstMeta := int64(flushMaxRecords) * (wal.MaxPFR1PathBytes*2 + 1024)
	if worst := worstBulk + worstMeta; worst >= int64(fsproto.MaxWriteBytes)+(8<<20) {
		t.Fatalf("a worst-case %d-byte batch does not fit the %d-byte request frame",
			worst, int64(fsproto.MaxWriteBytes)+(8<<20))
	}
	if flushMaxRecords > fsproto.MaxBatchRecords {
		t.Fatalf("flushMaxRecords=%d exceeds the wire batch bound %d", flushMaxRecords, fsproto.MaxBatchRecords)
	}
	// Every INDIVIDUAL record still has to fit one journal entry; that bound
	// is per record and is what the batch bound is deliberately not confused
	// with.
	if maxMutationPayload >= wal.MaxPFR1RecordBytes {
		t.Fatalf("one %d-byte mutation payload does not fit the %d-byte record bound",
			maxMutationPayload, wal.MaxPFR1RecordBytes)
	}
}

// flushSizeRun drains a fixed payload through a remote that charges a fixed
// cost per batch plus a rate-limited transfer, and reports the batches the
// flusher shipped and the wall time it took.
func flushSizeRun(t *testing.T, maxBytes int, payload []byte, rate int64, fixed time.Duration) (batches int, elapsed time.Duration) {
	t.Helper()
	restore := flushMaxBytes
	flushMaxBytes = int64(maxBytes)
	t.Cleanup(func() { flushMaxBytes = restore })

	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushRateBps = rate
	auth.flushFixedCost = fixed
	auth.mu.Unlock()

	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 512 << 20,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _, _ = e.ForceClose("test teardown") }()

	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	chunk := 1 << 20 // the engine's own write chunking
	for off := 0; off < len(payload); off += chunk {
		end := min(off+chunk, len(payload))
		if _, handled, err := e.WriteAt(ctx, "d/f", int64(off), payload[off:end]); err != nil || !handled {
			t.Fatalf("write at %d: handled=%v err=%v", off, handled, err)
		}
	}
	before := auth.flushCount()
	start := time.Now()
	dctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if err := e.DrainAll(dctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	elapsed = time.Since(start)
	batches = auth.flushCount() - before
	if err := auth.equalFile("d/f", payload); err != nil {
		t.Fatalf("drained payload is not byte-exact: %v", err)
	}
	return batches, elapsed
}

// TestLargerFlushBatchesAmortizeThePerBatchFixedCost is the measurement behind
// the constant: against a remote whose per-batch fixed cost dominates its
// transfer time (the measured production shape), quadrupling the batch bound
// quarters the batch count and materially raises durable throughput.
func TestLargerFlushBatchesAmortizeThePerBatchFixedCost(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement")
	}
	// Scaled-down model of the MEASURED link shape: 1.52s per 8 MiB batch, of
	// which ~0.70s is transfer and ~0.82s is the per-batch fixed cost. Both
	// halves are divided by 4 so the test runs in seconds while keeping the
	// proportion — which is the only thing the amortization depends on.
	const (
		transferPer8MiB = 175 * time.Millisecond // 0.70s / 4
		fixed           = 205 * time.Millisecond // 0.82s / 4
	)
	rate := int64(float64(8<<20) / transferPer8MiB.Seconds())
	payload := bytes.Repeat([]byte("z"), 64<<20)

	smallBatches, smallElapsed := flushSizeRun(t, 8<<20, payload, rate, fixed)
	largeBatches, largeElapsed := flushSizeRun(t, 32<<20, payload, rate, fixed)

	t.Logf("8 MiB batches:  %2d batches, %s, %.2f MB/s durable",
		smallBatches, smallElapsed.Round(time.Millisecond), mbps(len(payload), smallElapsed))
	t.Logf("32 MiB batches: %2d batches, %s, %.2f MB/s durable",
		largeBatches, largeElapsed.Round(time.Millisecond), mbps(len(payload), largeElapsed))
	t.Logf("speedup %.2fx", float64(smallElapsed)/float64(largeElapsed))

	if largeBatches >= smallBatches {
		t.Fatalf("32 MiB bound shipped %d batches, not fewer than the %d an 8 MiB bound shipped",
			largeBatches, smallBatches)
	}
	// The arithmetic the constant is chosen on: 8 batches x (175ms + 205ms) vs
	// 2 x (700ms + 205ms) is 3.04s vs 1.81s, a 1.68x speedup. The threshold is
	// deliberately slack — the claim is that the fixed cost amortizes, not that
	// a wall-clock ratio reproduces exactly.
	if speedup := float64(smallElapsed) / float64(largeElapsed); speedup < 1.3 {
		t.Fatalf("32 MiB batches gave a %.2fx speedup (%s vs %s); the per-batch fixed "+
			"cost did not amortize", speedup, largeElapsed, smallElapsed)
	}
}

func mbps(n int, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / 1e6 / d.Seconds()
}

func (a *fakeAuthority) flushCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flushes
}
