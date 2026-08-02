package writeback

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// ── THE ACKNOWLEDGEMENT CONTRACT, STATED AS AN ARITHMETIC IDENTITY ───────────
//
// Round 18's live incident could only be described by SUBTRACTION: a writer
// proved >=1136 MiB of successful write(2), the reattached file held 1061 MiB,
// only ~34 MiB was ever parked, and the ~41 MiB difference was "neither at the
// authority nor in the WAL". Nothing in the engine could attribute it, because
// nothing in the engine counts what it ACKNOWLEDGED — every existing check is
// derived from the WAL, so bytes that never reached the WAL are invisible to
// all of them.
//
// These tests install the missing counter and assert the identity it makes
// checkable:
//
//	Σ bytes the engine reported committed on the delegated lane
//	  == Σ OpWrite payload bytes the stream WAL holds for that path
//
// It must hold under every lifecycle event that can interrupt a write in
// flight: a credit wait cut by a seal, a fence, a ForceClose racing appends, a
// hard-cap headroom retry, and teardown. A violation in the "acked > WAL"
// direction is silent data loss; a violation in the "WAL > acked" direction is
// a phantom write the application never asked for. Both are failures.

// walAdmittedDataBytes is the DURABLE side of the identity: the exact number of
// OpWrite payload bytes the stream directory holds for path, decoded from the
// frames themselves rather than from any in-memory bookkeeping. Reading it from
// the bytes on disk is the point — an accounting bug in the engine cannot hide
// from it.
func walAdmittedDataBytes(t *testing.T, dir, path string) int64 {
	t.Helper()
	scan, err := scanStreamReadOnly(dir)
	if err != nil {
		t.Fatalf("scan stream %q: %v", dir, err)
	}
	var total int64
	for i := range scan.frames {
		f := &scan.frames[i]
		if f.typ != frameMutation {
			continue
		}
		rec, derr := wal.DecodePFR1(f.payload)
		if derr != nil {
			t.Fatalf("decode retained mutation frame %d: %v", f.frameNo, derr)
		}
		if rec.Op == wal.OpWrite && rec.Path == path {
			total += int64(len(rec.Data))
		}
	}
	return total
}

// ackLedger is the FRONTEND side of the identity: every byte the engine
// reported as committed to a caller that could pass it on to the kernel.
//
// The rule it encodes is the whole acknowledgement contract in one place. A
// write is acknowledged when, and only when, the engine answers handled=true
// with a nil error and a positive Count — that is the exact tuple
// clientcore.WriteCommitted turns into a POSIX success (ops.go:1150-1161), and
// the exact tuple the daemon turns into a WriteReply the kernel believes
// (portablefsd/ops.go:1262-1315).
type ackLedger struct {
	acked  atomic.Int64
	errors atomic.Int64
	short  atomic.Int64
}

// writeAt runs one WriteAt and records what it acknowledged. want is what the
// caller asked for, so a short count is recorded as such rather than silently
// folded into the total.
func (l *ackLedger) writeAt(e *Engine, ctx context.Context, path string, off int64, data []byte) error {
	res, handled, err := e.WriteAt(ctx, path, off, data)
	switch {
	case err != nil:
		// An error acknowledges nothing, whatever handled says. Count>0 with a
		// non-nil error would itself be a contract violation; assert it here so
		// the ledger cannot be fooled by one.
		if res.Count != 0 {
			panic("writeback: the engine reported a positive count alongside an error")
		}
		l.errors.Add(1)
		return err
	case !handled:
		// Unhandled means "not my lane": the caller writes through to the
		// authority, and these bytes are that lane's promise, not the WAL's.
		return nil
	default:
		l.acked.Add(int64(res.Count))
		if res.Count < len(data) {
			l.short.Add(1)
		}
		return nil
	}
}

// requireAckIdentity is the assertion the whole file exists for.
func requireAckIdentity(t *testing.T, e *Engine, l *ackLedger, path, what string) {
	t.Helper()
	e.mu.Lock()
	w := e.wal
	e.mu.Unlock()
	if w == nil {
		if got := l.acked.Load(); got != 0 {
			t.Fatalf("%s: %d byte(s) acknowledged with no stream at all", what, got)
		}
		return
	}
	dir := w.Dir()
	// Flush the group-commit tail so the on-disk scan sees every acknowledged
	// record. This is deliberately NOT part of the identity — it is how the
	// test READS the durable side. A failure here would itself be the defect.
	if err := w.Sync(); err != nil {
		t.Fatalf("%s: sync the stream before reading it back: %v", what, err)
	}
	acked := l.acked.Load()
	durable := walAdmittedDataBytes(t, dir, path)
	if acked != durable {
		t.Fatalf(
			"%s: THE ACKNOWLEDGEMENT CONTRACT IS BROKEN.\n"+
				"  acknowledged to the frontend: %d byte(s)\n"+
				"  admitted to the WAL:          %d byte(s)\n"+
				"  difference:                   %+d byte(s)\n"+
				"A positive difference is acknowledged data that exists nowhere: the\n"+
				"park's claim is derived from the WAL, so these bytes are invisible to\n"+
				"every recovery check. A negative difference is a phantom write.\n"+
				"(%d error(s), %d short write(s) along the way)",
			what, acked, durable, acked-durable, l.errors.Load(), l.short.Load(),
		)
	}
}

// ackFixture is a saturation fixture with a created file and a live delegation.
func ackFixture(t *testing.T, budget int64) (*saturationFixture, string) {
	t.Helper()
	f := newSaturationFixture(t, budget)
	if _, handled, err := f.e.Create(context.Background(), "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("fixture did not take a delegation over d/f")
	}
	return f, "d/f"
}

// TestAckedBytesEqualWALBytesOnTheQuietPath pins the identity with nothing
// interfering, so a failure anywhere below is unambiguously about the
// interference and not about the accounting.
func TestAckedBytesEqualWALBytesOnTheQuietPath(t *testing.T) {
	f, path := ackFixture(t, 32<<20)
	ctx := WithResolvedLane(context.Background(), LaneDelegated)
	l := &ackLedger{}
	chunk := make([]byte, 128<<10)
	var off int64
	for range 16 {
		if err := l.writeAt(f.e, ctx, path, off, chunk); err != nil {
			t.Fatalf("quiet write at %d: %v", off, err)
		}
		off += int64(len(chunk))
	}
	if got := l.acked.Load(); got != off {
		t.Fatalf("quiet path acknowledged %d of %d bytes", got, off)
	}
	requireAckIdentity(t, f.e, l, path, "the quiet path")
}

// TestSealDuringCreditWaitNeverAcknowledgesLostBytes is round 18a's hypothesis,
// constructed rather than reasoned about: a write is parked in the credit gate
// with the ledger exhausted and the uplink gated shut, and the engine is sealed
// underneath it exactly as ForceClose seals it (credits.seal(ErrFenced)).
//
// The write must come back as an ERROR. What it must never do is come back
// acknowledged, because a seal has already stopped the flusher and the next
// thing that happens to this stream is a park whose claim is computed from the
// WAL — so an acknowledged byte that never reached the WAL is gone with no
// check anywhere able to see it.
func TestSealDuringCreditWaitNeverAcknowledgesLostBytes(t *testing.T) {
	pinCreditTimings(t, 10*time.Second, 25*time.Second, 30*time.Second)
	f, path := ackFixture(t, 8<<20)
	// An UNRESOLVED lane is what actually queues in the credit gate: a resolved
	// delegated write is answered ErrLaneChanged rather than parked (engine.go
	// admitDataBytes), and a frontend-granted one never queues at all. This is
	// the shape that waits.
	ctx := context.Background()
	l := &ackLedger{}
	exhaustCreditLedger(t, f.e)

	chunk := make([]byte, 256<<10)
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- l.writeAt(f.e, ctx, path, 0, chunk)
	}()
	<-started
	// Let the writer reach the queue. The gate publishes its occupancy, so this
	// is a fact rather than a sleep.
	deadline := time.Now().Add(5 * time.Second)
	for f.e.Status().CreditWaiters == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the write never entered the credit queue; the interleaving under test was not constructed")
		}
		time.Sleep(time.Millisecond)
	}

	f.e.credits.seal(ErrFenced)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a write sealed inside the credit gate returned success: the acknowledgement outran durability")
		}
		if !errors.Is(err, ErrFenced) {
			t.Logf("sealed write returned %v (not ErrFenced); any definite error is acceptable here", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a sealed credit wait never resolved")
	}
	if got := l.acked.Load(); got != 0 {
		t.Fatalf("a write sealed inside the credit gate acknowledged %d byte(s)", got)
	}
	requireAckIdentity(t, f.e, l, path, "a seal landing inside the credit wait")
}

// TestForceCloseRacingInFlightWritesKeepsTheIdentity is the teardown race the
// live incident actually ran: a flood of concurrent writers against a mount
// that is force-unmounted mid-flight.
//
// ForceClose's whole promise is that the undrained tail "will be verified and
// replayed exactly on the next attach", and that promise is computed from the
// WAL (AdmittedThrough = w.LastSeq()). Every byte acknowledged to a writer must
// therefore be inside that snapshot. A writer that is acknowledged while the
// park is being taken — or after it — is a byte the promise does not cover.
func TestForceCloseRacingInFlightWritesKeepsTheIdentity(t *testing.T) {
	pinCreditTimings(t, 2*time.Second, 25*time.Second, 30*time.Second)
	f, path := ackFixture(t, 64<<20)
	ctx := WithResolvedLane(context.Background(), LaneDelegated)
	l := &ackLedger{}

	const writers = 8
	const perWriter = 24
	chunk := make([]byte, 64<<10)
	var wg sync.WaitGroup
	release := make(chan struct{})
	for w := range writers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-release
			base := int64(w) * int64(perWriter) * int64(len(chunk))
			for i := range perWriter {
				_ = l.writeAt(f.e, ctx, path, base+int64(i)*int64(len(chunk)), chunk)
			}
		}(w)
	}
	// Read the stream directory BEFORE the force-close: ForceClose closes the
	// WAL, so the identity has to be checked against a path captured while it
	// is still reachable.
	f.e.mu.Lock()
	dir := f.e.wal.Dir()
	f.e.mu.Unlock()

	close(release)
	// Park mid-flight, not after: the whole question is what a write in flight
	// is told while the snapshot is being taken.
	time.Sleep(2 * time.Millisecond)
	_, ferr := f.e.ForceClose("test: forced unmount mid-flight")
	wg.Wait()
	if ferr != nil && !errors.Is(ferr, ErrParkNotReplayable) {
		t.Fatalf("force close: %v", ferr)
	}
	if errors.Is(ferr, ErrParkNotReplayable) {
		t.Fatalf("the forced unmount could not park a replayable snapshot: %v", ferr)
	}

	acked := l.acked.Load()
	durable := walAdmittedDataBytes(t, dir, path)
	if acked != durable {
		t.Fatalf(
			"FORCED UNMOUNT BROKE THE ACKNOWLEDGEMENT CONTRACT.\n"+
				"  acknowledged to writers: %d byte(s)\n"+
				"  parked in the WAL:       %d byte(s)\n"+
				"  difference:              %+d byte(s)\n"+
				"The park's replay promise is computed from the WAL, so a positive\n"+
				"difference is acknowledged data no recovery check can even see.\n"+
				"(%d refusal(s), %d short write(s))",
			acked, durable, acked-durable, l.errors.Load(), l.short.Load(),
		)
	}
	if acked == 0 {
		t.Fatal("no write was acknowledged at all: the race under test never happened")
	}
	t.Logf("forced unmount mid-flight: %d byte(s) acknowledged, %d parked, %d refused",
		acked, durable, l.errors.Load())
}

// TestCreditExhaustionAcknowledgesOnlyWhatItWrote covers the short-write half of
// the contract. Under a starved gate a write is granted a PREFIX, and the count
// it reports must be exactly that prefix — never the full request. Reporting
// full success for a prefix is the quietest form of the loss: the application
// advances its own offset past bytes that were never admitted, and the hole it
// leaves is the 0.94 MiB zero-filled gap the live incident found mid-file.
func TestCreditExhaustionAcknowledgesOnlyWhatItWrote(t *testing.T) {
	pinCreditTimings(t, 200*time.Millisecond, 25*time.Second, 30*time.Second)
	f, path := ackFixture(t, 8<<20)
	ctx := context.Background()
	l := &ackLedger{}

	// A frontend grant strictly smaller than the payload: the exact shape a
	// short acquisition produces, delivered through the same ctx the pre-lock
	// classifier uses.
	chunk := make([]byte, 512<<10)
	granted := len(chunk) / 4
	got, err := f.e.AcquireDataCredit(ctx, granted)
	if err != nil || got != granted {
		t.Fatalf("frontend acquire: granted=%d err=%v", got, err)
	}
	exhaustCreditLedger(t, f.e)
	opCtx := WithResolvedLane(WithDataCredit(ctx, got), LaneDelegated)

	res, handled, werr := f.e.WriteAt(opCtx, path, 0, chunk)
	if werr != nil || !handled {
		t.Fatalf("short-granted write: handled=%v err=%v", handled, werr)
	}
	if res.Count != granted {
		t.Fatalf("a write granted %d byte(s) acknowledged %d: a count larger than the grant "+
			"is data the application believes is durable and the WAL never saw",
			granted, res.Count)
	}
	l.acked.Add(int64(res.Count))
	requireAckIdentity(t, f.e, l, path, "a short credit grant")
}

// TestFrontendGrantedWriteRacingASealIsNeverSilentlyDropped is the one
// interleaving the pre-lock classifier makes possible and the credit gate
// cannot see: a write whose bytes were ALREADY paid for outside the locks
// bypasses admitDataBytes entirely (pacedWrite's havePre arm), so a seal that
// lands between the acquisition and the append never reaches it through the
// gate. The only thing standing between that write and a sealed engine is
// admit()'s own lifecycle check, and this test is what proves that check is
// load-bearing rather than incidental.
func TestFrontendGrantedWriteRacingASealIsNeverSilentlyDropped(t *testing.T) {
	pinCreditTimings(t, 2*time.Second, 25*time.Second, 30*time.Second)
	f, path := ackFixture(t, 16<<20)
	ctx := context.Background()
	l := &ackLedger{}

	chunk := make([]byte, 128<<10)
	granted, err := f.e.AcquireDataCredit(ctx, len(chunk))
	if err != nil || granted != len(chunk) {
		t.Fatalf("frontend acquire: granted=%d err=%v", granted, err)
	}
	opCtx := WithResolvedLane(WithDataCredit(ctx, granted), LaneDelegated)

	f.e.mu.Lock()
	dir := f.e.wal.Dir()
	f.e.mu.Unlock()

	// Seal first, then present the pre-paid write. A gate-only refusal would
	// let this one straight through.
	f.e.credits.seal(ErrFenced)
	f.e.mu.Lock()
	f.e.frozen = true
	f.e.mu.Unlock()

	res, handled, werr := f.e.WriteAt(opCtx, path, 0, chunk)
	if werr == nil && handled && res.Count > 0 {
		l.acked.Add(int64(res.Count))
	}
	if werr == nil && handled {
		t.Fatalf("a pre-paid write was acknowledged (%d byte(s)) by an engine that is frozen "+
			"and sealed: the frontend grant bypasses the credit gate, so nothing but "+
			"admit()'s lifecycle check can refuse it", res.Count)
	}
	// Thaw so the identity can be read back off a live stream.
	f.e.mu.Lock()
	f.e.frozen = false
	f.e.mu.Unlock()
	if got := walAdmittedDataBytes(t, dir, path); got != l.acked.Load() {
		t.Fatalf("pre-paid write racing a seal: acknowledged %d, WAL holds %d",
			l.acked.Load(), got)
	}
}
