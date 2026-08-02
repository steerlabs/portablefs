package writeback

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// InspectStreamTail is the proof the orphan-WAL sweep deletes on. It must
// answer from the stream's own frames, it must agree with the accounting
// force-park performs over the same bytes, and it must never answer "empty"
// for a stream it could not read.

func TestInspectStreamTailCountsAnUnshippedTail(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "d")
	f.auth.mu.Lock()
	f.auth.flushErr = errors.New("authority offline")
	f.auth.mu.Unlock()
	_, handled, err := f.engine.Create(ctx, "d/file", 0o644, false, false)
	mustHandle(t, "create d/file", handled, err)
	f.engine.Abandon()

	tail, err := InspectStreamTail(f.streamDir(1))
	if err != nil {
		t.Fatalf("inspect an undrained stream: %v", err)
	}
	if tail.Segments == 0 {
		t.Fatal("the fixture must leave real segments behind, or it proves nothing")
	}
	if tail.Records == 0 || tail.Bytes == 0 {
		t.Fatalf("records the authority never applied must be counted, got %+v", tail)
	}
	if tail.CleanlyClosed {
		t.Fatal("an abandoned stream carries no clean-close marker")
	}
}

// THE SWEEP AND FORCE-PARK MUST COUNT THE SAME BYTES. force-park is the
// product's authoritative statement of what an abandoned store still holds;
// a garbage collector that tallied it differently would be deciding deletion
// on a second, unreviewed definition of "pending".
func TestInspectStreamTailAgreesWithForceParkAccounting(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "d")
	f.auth.mu.Lock()
	f.auth.flushErr = errors.New("authority offline")
	f.auth.mu.Unlock()
	_, handled, err := f.engine.Create(ctx, "d/file", 0o644, false, false)
	mustHandle(t, "create d/file", handled, err)
	if _, handled, err := f.engine.WriteAt(ctx, "d/file", 0, []byte("payload")); err != nil || !handled {
		t.Fatalf("write d/file: handled=%v err=%v", handled, err)
	}
	f.engine.Abandon()

	tail, err := InspectStreamTail(f.streamDir(1))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if _, err := ForceParkAbandonedStore(f.dir, "vol", "main", "mnt_exact", "test"); err != nil {
		t.Fatalf("force park: %v", err)
	}
	job, ok := loadJob(f.streamDir(1))
	if !ok {
		t.Fatal("force park wrote no recovery registry")
	}
	if tail.Records != job.PendingRecords || tail.Bytes != job.PendingBytes {
		t.Fatalf("sweep measured %d record(s)/%d byte(s); force-park recorded %d/%d",
			tail.Records, tail.Bytes, job.PendingRecords, job.PendingBytes)
	}
}

// A stream whose registry's applied watermark covers its whole tail — the
// shape recovery and force-park write once everything shipped — is drained,
// even though it still carries segment bytes.
func TestInspectStreamTailReportsAFullyAppliedStreamAsDrained(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "d")
	f.auth.mu.Lock()
	f.auth.flushErr = errors.New("authority offline")
	f.auth.mu.Unlock()
	_, handled, err := f.engine.Create(ctx, "d/file", 0o644, false, false)
	mustHandle(t, "create d/file", handled, err)
	f.engine.Abandon()

	streamDir := f.streamDir(1)
	scan, err := scanStreamReadOnly(streamDir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	job, ok := loadJob(streamDir)
	if !ok {
		t.Fatal("missing recovery registry")
	}
	job.State = JobParked
	job.AppliedThrough = scan.lastSeq
	if err := newJobState(streamDir, job).persist(); err != nil {
		t.Fatalf("persist registry: %v", err)
	}

	tail, err := InspectStreamTail(streamDir)
	if err != nil {
		t.Fatalf("inspect a drained stream: %v", err)
	}
	if tail.SegmentBytes == 0 {
		t.Fatal("the fixture must retain segment bytes, or the case is trivial")
	}
	if tail.Records != 0 || tail.Bytes != 0 {
		t.Fatalf("a stream applied through its own tail must measure drained, got %+v", tail)
	}
}

// A REGISTRY MAY NOT CLAIM MORE THAN THE WAL HOLDS. validateJobIdentity makes
// the same refusal; a sweep that accepted the claim would measure an empty
// tail over records that exist and delete them.
func TestInspectStreamTailRefusesARegistryPastTheWALTail(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "d")
	f.auth.mu.Lock()
	f.auth.flushErr = errors.New("authority offline")
	f.auth.mu.Unlock()
	_, handled, err := f.engine.Create(ctx, "d/file", 0o644, false, false)
	mustHandle(t, "create d/file", handled, err)
	f.engine.Abandon()

	streamDir := f.streamDir(1)
	job, ok := loadJob(streamDir)
	if !ok {
		t.Fatal("missing recovery registry")
	}
	job.AppliedThrough = 1 << 40
	if err := newJobState(streamDir, job).persist(); err != nil {
		t.Fatalf("persist registry: %v", err)
	}

	if tail, err := InspectStreamTail(streamDir); err == nil {
		t.Fatalf("a registry past the WAL tail must be refused, got %+v", tail)
	}
}

// A DAMAGED STREAM IS NOT AN EMPTY ONE. The sweep deletes a whole store on a
// zero answer, so every unreadable shape must come back as an error.
func TestInspectStreamTailRefusesToMeasureADamagedStream(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wb-00000001.pfw"), make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	tail, err := InspectStreamTail(dir)
	if err == nil {
		t.Fatalf("4096 zero bytes are not a segment, got %+v", tail)
	}
	if tail.SegmentBytes != 4096 {
		t.Fatalf("a refusal must still report the bytes at risk, got %d", tail.SegmentBytes)
	}
}
