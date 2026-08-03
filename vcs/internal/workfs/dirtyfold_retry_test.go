package workfs

// RELIEF THAT ACTUALLY COMES BACK.
//
// A fold pass leaves foldable work behind for two ordinary reasons: it is
// BOUNDED (MaxInodes) and something TRANSIENT failed. Both are documented as
// coming back — FoldReport.Failed says "retried next pass", foldMaxInodesPerPass
// says "the next tick takes the rest". Neither did. The folded watermark
// advanced unconditionally, and the driver refuses a second pass at a
// watermark it has already folded, so both deferrals actually waited for the
// NEXT ADOPTION.
//
// On the one path whose entire job is relieving memory pressure that is not a
// documentation bug. It caps the relief RATE at MaxInodes inodes per cut
// however much memory is resident, and it turns a single object-store blip
// into however long the next cut takes — which, on a branch under a sustained
// writer, is minutes.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// TestFoldRetriesTheWatermarkItDidNotFinish pins the bounded-pass half: a
// pass that folds only its MaxInodes prefix must leave the watermark unfolded
// so the very next pass takes the rest, WITHOUT waiting for another cut.
func TestFoldRetriesTheWatermarkItDidNotFinish(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	const files = 6
	for i := 0; i < files; i++ {
		name := fmt.Sprintf("f%d.bin", i)
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := managedWrite(fs, name, 0, blockPayload(80+i, blockSize)); err != nil {
			t.Fatal(err)
		}
	}
	wantDirty(t, fs, files*blockSize, "every file holds one resident block")

	cut := takeCut(t, fs, blobs)
	base := cut.base()
	base.MaxInodes = 2

	report, err := fs.FoldToBase(context.Background(), base)
	if err != nil {
		t.Fatalf("bounded pass: %v", err)
	}
	if report.Inodes != 2 || report.Deferred != files-2 {
		t.Fatalf("report = %+v, want 2 folded and %d deferred", report, files-2)
	}
	if !report.Retryable {
		t.Fatalf("a bounded pass that made progress must ask to be retried: %+v", report)
	}
	if folded := fs.FoldedWatermark(); folded >= base.Watermark {
		t.Fatalf("folded watermark %d claims the unfinished watermark %d: the driver "+
			"refuses another pass at a folded watermark, so the remaining %d inodes' "+
			"blocks wait for the NEXT ADOPTION instead of the next tick",
			folded, base.Watermark, report.Deferred)
	}

	// Repeat passes at the SAME watermark drain the rest.
	for i := 0; i < files; i++ {
		report, err = fs.FoldToBase(context.Background(), base)
		if err != nil {
			t.Fatalf("follow-up pass %d: %v", i, err)
		}
		if !report.Retryable {
			break
		}
	}
	wantDirty(t, fs, 0, "repeat passes at one watermark drain every deferred inode")
	if folded := fs.FoldedWatermark(); folded != base.Watermark {
		t.Fatalf("folded watermark %d, want %d once the pass completed", folded, base.Watermark)
	}
}

// TestFoldRetriesAfterATransientResolveFailure pins the other half, and the
// exact wording of FoldReport.Failed: a resolve error defers those inodes to
// the NEXT PASS, not to the next cut.
func TestFoldRetriesAfterATransientResolveFailure(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.bin", "b.bin"} {
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := managedWrite(fs, name, 0, blockPayload(91, blockSize)); err != nil {
			t.Fatal(err)
		}
	}
	cut := takeCut(t, fs, blobs)
	failIno := inoOf(t, fs, "a.bin")

	base := cut.base()
	inner := base.Resolve
	outage := true
	base.Resolve = func(ctx context.Context, ino uint64) (content.Source, bool, error) {
		if outage && ino == failIno {
			return content.Source{}, false, errors.New("object store unavailable")
		}
		return inner(ctx, ino)
	}

	report, err := fs.FoldToBase(context.Background(), base)
	if err == nil {
		t.Fatal("a resolve failure must be reported")
	}
	if report.Failed != 1 || !report.Retryable {
		t.Fatalf("report = %+v, want one failure asking to be retried", report)
	}
	if folded := fs.FoldedWatermark(); folded >= base.Watermark {
		t.Fatalf("folded watermark %d claims a watermark a transient failure left "+
			"unfinished: the failed inode's block waits for the next ADOPTION, "+
			"not the next pass, contradicting FoldReport.Failed", folded)
	}
	wantDirty(t, fs, blockSize, "the unresolved inode kept its block")

	// The outage clears; the very next pass at the SAME watermark releases it.
	outage = false
	report, err = fs.FoldToBase(context.Background(), base)
	if err != nil {
		t.Fatalf("retry pass: %v", err)
	}
	if report.Inodes != 1 || report.Retryable {
		t.Fatalf("retry report = %+v, want the deferred inode folded and the pass complete", report)
	}
	wantDirty(t, fs, 0, "the retry pass released what the outage deferred")
	if folded := fs.FoldedWatermark(); folded != base.Watermark {
		t.Fatalf("folded watermark %d, want %d once the pass completed", folded, base.Watermark)
	}
}

// TestFoldDoesNotLoopOnCandidatesItCanNeverFold guards the other direction:
// holding the watermark back is only correct while progress is possible. A
// bounded pass whose whole prefix is absent from the base must still advance,
// or the driver spins at one watermark forever.
func TestFoldDoesNotLoopOnCandidatesItCanNeverFold(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.bin", "b.bin", "c.bin"} {
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := managedWrite(fs, name, 0, blockPayload(101, blockSize)); err != nil {
			t.Fatal(err)
		}
	}
	cut := takeCut(t, fs, blobs)
	base := cut.base()
	base.MaxInodes = 1
	base.Resolve = func(context.Context, uint64) (content.Source, bool, error) {
		return content.Source{}, false, nil // the base contains none of them
	}
	report, err := fs.FoldToBase(context.Background(), base)
	if err != nil {
		t.Fatalf("absent-only pass: %v", err)
	}
	if report.Retryable {
		t.Fatalf("a pass that folded nothing and failed nothing has no progress to "+
			"retry: %+v", report)
	}
	if folded := fs.FoldedWatermark(); folded != base.Watermark {
		t.Fatalf("folded watermark %d, want %d: an unfoldable candidate set must not "+
			"pin the watermark", folded, base.Watermark)
	}
}
