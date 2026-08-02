package workfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// ── the external history cut, faithfully faked ──────────────────────────────
//
// A real HistoryCut materialises the journal prefix below a watermark into a
// content-addressed base commit. takeCut does exactly that against the fake
// blob store: it captures the tree and the applied cursor in ONE fs.mu hold
// (Snapshot does both, which is what makes the watermark the exact boundary of
// the captured content), materialises every file, and hands back a FoldBase
// that resolves by stable inode identity.
//
// Nothing here reaches into fold internals: the fake cut sees exactly what the
// real materializer sees (committed bytes + watermark), so a fold that is
// correct against it is correct against the real one.

type fakeCut struct {
	watermark uint64
	sources   map[uint64]content.Source
	bytes     map[uint64][]byte
	resolves  int
	onResolve func(ino uint64)
}

func takeCut(t *testing.T, fs *FS, blobs *fakeBlobs) *fakeCut {
	t.Helper()
	snap := fs.Snapshot()
	cut := &fakeCut{
		watermark: snap.WALWatermark(),
		sources:   map[uint64]content.Source{},
		bytes:     map[uint64][]byte{},
	}
	for _, e := range snap.Entries {
		if e.Kind != "file" {
			continue
		}
		full, err := fs.MaterializeFull(e)
		if err != nil {
			t.Fatalf("materialise %s for the cut: %v", e.Path, err)
		}
		d := digestOf(full)
		blobs.data[d] = append([]byte(nil), full...)
		cut.bytes[e.Ino] = append([]byte(nil), full...)
		cut.sources[e.Ino] = content.Source{
			BlobDigest: d, BlobSize: int64(len(full)), Size: int64(len(full)),
		}
	}
	return cut
}

// base turns the captured cut into the FoldBase the child folds against.
func (c *fakeCut) base() FoldBase {
	return FoldBase{
		Watermark: c.watermark,
		CommitID:  fmt.Sprintf("commit-%d", c.watermark),
		Resolve: func(_ context.Context, ino uint64) (content.Source, bool, error) {
			c.resolves++
			if c.onResolve != nil {
				c.onResolve(ino)
			}
			src, ok := c.sources[ino]
			return src, ok, nil
		},
	}
}

// readAll reads a file through the ordinary read path (dirty blocks over the
// bound base), which is the only observation that matters after a fold.
func readAll(t *testing.T, fs *FS, name string, size int64) []byte {
	t.Helper()
	out := make([]byte, size)
	n, err := fs.ReadHandleAt(name, 0, out, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("read %s: %v", name, err)
	}
	return out[:n]
}

// blockPayload is a deterministic, position-dependent payload so a misplaced
// or stale block is caught by content, not just by length.
func blockPayload(round int, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(round*31 + i%251)
	}
	return out
}

// managedWriteBig writes data at off in journal-record-sized pieces (one block
// each), the way a real client's write-back stream does: a single PFR1 record
// cannot carry more than ~8 MiB.
func managedWriteBig(t *testing.T, fs *FS, path string, off int64, data []byte) {
	t.Helper()
	for done := 0; done < len(data); done += blockSize {
		end := min(done+blockSize, len(data))
		if err := managedWrite(fs, path, off+int64(done), data[done:end]); err != nil {
			t.Fatalf("write %s at %d: %v", path, off+int64(done), err)
		}
	}
}

// pinOpenFold takes a durable PFC2 open pin on ino so an unlinked-but-open
// inode stays PARKED (the async reap sweep only destroys pin-free orphans).
// Without it these tests would race the sweeper for the state they assert on.
func pinOpenFold(t *testing.T, fs *FS, ref pfc2.SessionRef, ino uint64) {
	t.Helper()
	pin := pfc2.Record{Kind: pfc2.KindOpenPinChange, OpenPinChange: &pfc2.OpenPinChange{Session: ref, Ino: ino}}
	if _, err := fs.CommitEntry(nil, []pfc2.Record{pin}, ""); err != nil {
		t.Fatalf("pin ino %d open: %v", ino, err)
	}
}

// ── 1. THE FINDING ──────────────────────────────────────────────────────────

// TestManagedDirtyResidencyIsMonotoneWithoutTheFold is the round-18g finding,
// reproduced in process: on a managed generation the resident dirty-block
// total NEVER decreases under a sustained write, no matter how many history
// cuts land and adopt underneath it, and the volume therefore wedges at
// VCS_DIRTY_RSS_MAX_MB after a fixed CUMULATIVE number of bytes rather than at
// any particular rate, file count, or wall-clock time.
//
// The cuts here adopt normally — takeCut captures exactly what the external
// materializer would, at a real watermark. Nothing else in the child changes,
// which is the whole point: adoption advances the journal base, and the child's
// inodes stay bound to the old one with every committed block still resident.
func TestManagedDirtyResidencyIsMonotoneWithoutTheFold(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, blobs, log)
	if err != nil {
		t.Fatal(err)
	}
	const bound = 8 * blockSize
	fs.SetDirtyRSSMax(bound)

	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "rss.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}

	chunk := blockPayload(0, blockSize)
	var resident int64
	var wedgedAt int64
	var off int64
	for round := 0; round < 64; round++ {
		werr := managedWrite(fs, "rss.bin", off, chunk)
		if werr != nil {
			if !errors.Is(werr, ErrDirtyRSSCapacity) {
				t.Fatalf("round %d: %v", round, werr)
			}
			wedgedAt = off
			break
		}
		off += int64(len(chunk))
		// A cut lands and is adopted after every write. This is the healthiest
		// possible maintenance cadence — far better than production's 60 s
		// loop — and it changes nothing.
		_ = takeCut(t, fs, blobs)
		got := fs.DirtyBlockBytes()
		if got < resident {
			t.Fatalf("round %d: residency DROPPED %d -> %d without a fold; "+
				"the finding this round is built on no longer holds", round, resident, got)
		}
		resident = got
	}
	if wedgedAt == 0 {
		t.Fatalf("64 rounds under a %d-byte bound never wedged (resident %d)", bound, resident)
	}
	if wedgedAt > bound {
		t.Fatalf("wedged at %d cumulative bytes, past the %d-byte bound: residency was not monotone", wedgedAt, bound)
	}
	// The ceiling is on CUMULATIVE writes, and it is exactly the bound.
	if resident != bound {
		t.Fatalf("resident at the wedge = %d, want the full bound %d", resident, bound)
	}
	// And every re-offer is refused identically: nothing relieves it.
	for i := 0; i < 3; i++ {
		if err := managedWrite(fs, "rss.bin", off, chunk); !errors.Is(err, ErrDirtyRSSCapacity) {
			t.Fatalf("re-offer %d: %v, want the identical definite refusal", i, err)
		}
		_ = takeCut(t, fs, blobs)
	}
	// Truncate is the documented relief, and remains admissible.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: "rss.bin", Size: 0}, nil, ""); err != nil {
		t.Fatalf("truncate at the bound must stay admissible: %v", err)
	}
	wantDirty(t, fs, 0, "truncate released everything")
}

// ── 2. THE FOLD ─────────────────────────────────────────────────────────────

// TestManagedDirtyResidencyBoundedByTheFoldWindow is the acceptance property
// in process: with a cut+fold landing on a cadence, ONE file takes far more
// cumulative writes than the bound would ever have allowed, resident dirty
// bytes stay inside the fold window instead of growing, and the bytes read
// back are exact.
//
// This is the in-process twin of the live gate (8 GiB on one branch under a
// 2 GiB bound), scaled by the same ratio: 64 blocks written under an 8-block
// bound is 8x the ceiling, at 1/256 the size.
func TestManagedDirtyResidencyBoundedByTheFoldWindow(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, blobs, log)
	if err != nil {
		t.Fatal(err)
	}
	const bound = 8 * blockSize
	const foldEvery = 4 // blocks written between cuts: the fold window
	fs.SetDirtyRSSMax(bound)

	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "rss.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}

	var want []byte
	var off int64
	var peak int64
	const rounds = 64
	for round := 0; round < rounds; round++ {
		chunk := blockPayload(round, blockSize)
		if err := managedWrite(fs, "rss.bin", off, chunk); err != nil {
			t.Fatalf("round %d at %d cumulative bytes: %v (the bound is %d — the fold is not keeping up)",
				round, off, err, bound)
		}
		off += int64(len(chunk))
		want = append(want, chunk...)
		if got := fs.DirtyBlockBytes(); got > peak {
			peak = got
		}
		if round%foldEvery == foldEvery-1 {
			cut := takeCut(t, fs, blobs)
			report, ferr := fs.FoldToBase(context.Background(), cut.base())
			if ferr != nil {
				t.Fatalf("round %d fold: %v", round, ferr)
			}
			if report.Inodes == 0 {
				t.Fatalf("round %d: the fold rebound nothing (candidates=%d absent=%d raced=%d)",
					round, report.Candidates, report.Absent, report.Raced)
			}
		}
	}

	// Far past the ceiling the un-folded volume had.
	if off <= bound {
		t.Fatalf("test wrote only %d bytes; it must exceed the %d-byte bound to prove anything", off, bound)
	}
	if off != rounds*blockSize {
		t.Fatalf("wrote %d bytes, want %d", off, rounds*blockSize)
	}
	// THE INVARIANT: residency is bounded by the fold window (the blocks
	// written since the last cut), not by the branch's lifetime. One extra
	// block of slack covers the round the fold runs on.
	windowBound := int64(foldEvery+1) * blockSize
	if peak > windowBound {
		t.Fatalf("peak residency %d exceeded the fold window bound %d", peak, windowBound)
	}
	if final := fs.DirtyBlockBytes(); final > windowBound {
		t.Fatalf("final residency %d exceeded the fold window bound %d", final, windowBound)
	}

	// BYTE EXACTNESS across the fold boundary: everything read back through
	// the ordinary path (surviving dirty blocks over folded base extents).
	if got := readAll(t, fs, "rss.bin", off); !bytes.Equal(got, want) {
		t.Fatalf("content diverged after folding: %d bytes read, first mismatch at %d",
			len(got), foldFirstDiff(got, want))
	}
}

func foldFirstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return min(len(a), len(b))
	}
	return -1
}

// ── 3. CORRECTNESS OF THE PROOF ─────────────────────────────────────────────

// TestFoldKeepsBlocksWrittenAfterTheCut is the partial-write case: an inode
// PARTLY folded and PARTLY newer. Blocks written before the cut are released
// and served from the base; blocks written after it keep their resident copies
// and keep overriding the base. Both halves must read back exactly.
func TestFoldKeepsBlocksWrittenAfterTheCut(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "f.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	old := blockPayload(1, 2*blockSize)
	managedWriteBig(t, fs, "f.bin", 0, old)
	wantDirty(t, fs, 2*blockSize, "two blocks before the cut")

	cut := takeCut(t, fs, blobs)

	// Two more blocks land AFTER the cut boundary, plus an in-place overwrite
	// of a block the cut already captured.
	fresh := blockPayload(2, 2*blockSize)
	managedWriteBig(t, fs, "f.bin", 2*blockSize, fresh)
	overwrite := blockPayload(3, 1024)
	if err := managedWrite(fs, "f.bin", 64, overwrite); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 4*blockSize, "four resident blocks")

	want := append([]byte(nil), old...)
	want = append(want, fresh...)
	copy(want[64:], overwrite)

	report, err := fs.FoldToBase(context.Background(), cut.base())
	if err != nil {
		t.Fatal(err)
	}
	// Block 0 was re-written after the cut, so only block 1 folds.
	if report.Blocks != 1 {
		t.Fatalf("folded %d blocks, want exactly 1 (block 0 re-written after the cut, blocks 2-3 born after it)", report.Blocks)
	}
	wantDirty(t, fs, 3*blockSize, "one block released, three newer blocks kept")

	if got := readAll(t, fs, "f.bin", int64(len(want))); !bytes.Equal(got, want) {
		t.Fatalf("partially folded file diverged at offset %d", foldFirstDiff(got, want))
	}
}

// TestFoldSkipsInodeTruncatedAfterTheCut pins the one transition the per-block
// proof cannot carry. A truncate monotonically caps the visible base so a
// regrow reads holes, not resurrected bytes; rebinding to a base cut BEFORE
// the truncate would undo that. The inode must be skipped WHOLE and the holes
// must still read as zeros.
func TestFoldSkipsInodeTruncatedAfterTheCut(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "t.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	managedWriteBig(t, fs, "t.bin", 0, blockPayload(7, 3*blockSize))
	cut := takeCut(t, fs, blobs)

	// Shrink to one block, then regrow. POSIX: the discarded region is GONE.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: "t.bin", Size: blockSize}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: "t.bin", Size: 3 * blockSize}, nil, ""); err != nil {
		t.Fatal(err)
	}
	before := fs.DirtyBlockBytes()

	report, err := fs.FoldToBase(context.Background(), cut.base())
	if err != nil {
		t.Fatal(err)
	}
	if report.Blocks != 0 || report.Inodes != 0 {
		t.Fatalf("a post-cut truncate must skip the inode whole: folded %d inodes / %d blocks",
			report.Inodes, report.Blocks)
	}
	if got := fs.DirtyBlockBytes(); got != before {
		t.Fatalf("skipped inode released %d bytes", before-got)
	}
	// The regrown region is a HOLE. A fold that rebound the source would have
	// resurrected the cut's bytes here.
	got := readAll(t, fs, "t.bin", 3*blockSize)
	if len(got) != 3*blockSize {
		t.Fatalf("read %d bytes, want %d", len(got), 3*blockSize)
	}
	for i := blockSize; i < 3*blockSize; i++ {
		if got[i] != 0 {
			t.Fatalf("truncate-discarded byte at %d resurrected as %#x", i, got[i])
		}
	}
}

// TestFoldLosesNothingToARacingWriter drives the exact interleaving the design
// has to survive: a write lands DURING the base resolve, i.e. between the
// candidate scan and the commit that would release its block. The commit phase
// re-derives every proof under fs.mu, sees the newer stamp, and keeps the
// block. Losing it would silently roll the file back to the cut.
func TestFoldLosesNothingToARacingWriter(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "r.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	stale := blockPayload(11, 2*blockSize)
	managedWriteBig(t, fs, "r.bin", 0, stale)
	cut := takeCut(t, fs, blobs)

	// The racer overwrites block 0 while the fold is resolving the base.
	racer := blockPayload(12, blockSize)
	cut.onResolve = func(uint64) {
		if err := managedWrite(fs, "r.bin", 0, racer); err != nil {
			t.Errorf("racing write: %v", err)
		}
		cut.onResolve = nil // exactly once
	}

	report, err := fs.FoldToBase(context.Background(), cut.base())
	if err != nil {
		t.Fatal(err)
	}
	if report.Blocks != 1 {
		t.Fatalf("folded %d blocks, want 1 (block 1 only; block 0 was raced)", report.Blocks)
	}

	want := append([]byte(nil), stale...)
	copy(want, racer)
	if got := readAll(t, fs, "r.bin", int64(len(want))); !bytes.Equal(got, want) {
		t.Fatalf("the racing write was lost to the fold at offset %d", foldFirstDiff(got, want))
	}
}

// TestFoldReleasesParkedOrphanBlocks is the relief `rm` never gave on a managed
// authority. An inode unlinked AFTER the cut is still in that base under its
// stable identity, and unlinking changed none of its bytes — so its parked
// blocks are exactly as foldable as a named file's, and the open handle keeps
// reading them from the base.
func TestFoldReleasesParkedOrphanBlocks(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "o.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	payload := blockPayload(21, 2*blockSize)
	managedWriteBig(t, fs, "o.bin", 0, payload)
	ino := inoOf(t, fs, "o.bin")
	pinOpenFold(t, fs, openManagedSession(t, fs, "pfs-fold-orphan", 1), ino)
	cut := takeCut(t, fs, blobs)

	// Unlink while open: the managed reducer PARKS, keeping every block.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpRemove, Path: "o.bin"}, nil, ""); err != nil {
		t.Fatal(err)
	}
	wantDirty(t, fs, 2*blockSize, "a parked orphan keeps every dirty block")

	report, err := fs.FoldToBase(context.Background(), cut.base())
	if err != nil {
		t.Fatal(err)
	}
	if report.Blocks != 2 {
		t.Fatalf("folded %d orphan blocks, want 2", report.Blocks)
	}
	wantDirty(t, fs, 0, "the parked orphan's committed blocks were released")

	// The open handle still reads the exact bytes, now from the base.
	out := make([]byte, len(payload))
	n, rerr := fs.ReadOrphanAt(ino, out, 0)
	if rerr != nil && rerr != io.EOF {
		t.Fatalf("orphan read after fold: %v", rerr)
	}
	if !bytes.Equal(out[:n], payload) {
		t.Fatalf("folded orphan diverged at offset %d", foldFirstDiff(out[:n], payload))
	}
}

// TestFoldRejectsStaleAndAheadWatermarks pins the two refusals that keep
// at-least-once adoption notifications free and keep a fold from ever binding
// content this authority has not reproduced.
func TestFoldRejectsStaleAndAheadWatermarks(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "s.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := managedWrite(fs, "s.bin", 0, blockPayload(31, blockSize)); err != nil {
		t.Fatal(err)
	}
	cut := takeCut(t, fs, blobs)
	if _, err := fs.FoldToBase(context.Background(), cut.base()); err != nil {
		t.Fatal(err)
	}
	if got := fs.FoldedWatermark(); got != cut.watermark {
		t.Fatalf("folded watermark = %d, want %d", got, cut.watermark)
	}

	// Re-offer: benign, changes nothing.
	before := fs.DirtyBlockBytes()
	if _, err := fs.FoldToBase(context.Background(), cut.base()); !errors.Is(err, ErrFoldStale) {
		t.Fatalf("re-offered adoption: %v, want ErrFoldStale", err)
	}
	if got := fs.DirtyBlockBytes(); got != before {
		t.Fatalf("a stale fold moved residency %d -> %d", before, got)
	}

	// Ahead of the applied cursor: refused, never applied.
	ahead := cut.base()
	ahead.Watermark = fs.AppliedWatermark() + 100
	if _, err := fs.FoldToBase(context.Background(), ahead); err == nil {
		t.Fatal("a fold ahead of the applied cursor was accepted")
	}
}

// TestFoldProvenanceSurvivesColdReplay proves the fold is generation-portable:
// a restarted child replaying the identical journal stamps the identical
// durable-order provenance, so it makes the identical fold decisions. If
// replay stamped differently, a restart would either lose a byte or stop
// releasing memory.
func TestFoldProvenanceSurvivesColdReplay(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, blobs, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "c.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	managedWriteBig(t, fs, "c.bin", 0, blockPayload(41, 2*blockSize))
	cut := takeCut(t, fs, blobs)
	managedWriteBig(t, fs, "c.bin", 0, blockPayload(42, blockSize))

	replayed, err := NewManaged(nil, blobs, log)
	if err != nil {
		t.Fatal(err)
	}
	wantDirty(t, replayed, fs.DirtyBlockBytes(), "cold replay residency")

	live, err := fs.FoldToBase(context.Background(), cut.base())
	if err != nil {
		t.Fatal(err)
	}
	cold, err := replayed.FoldToBase(context.Background(), cut.base())
	if err != nil {
		t.Fatal(err)
	}
	if live.Blocks != cold.Blocks || live.BytesReleased != cold.BytesReleased || live.Inodes != cold.Inodes {
		t.Fatalf("cold replay folded differently: live=%+v cold=%+v", live, cold)
	}
	if fs.DirtyBlockBytes() != replayed.DirtyBlockBytes() {
		t.Fatalf("residency diverged after the fold: live=%d cold=%d",
			fs.DirtyBlockBytes(), replayed.DirtyBlockBytes())
	}
}

// TestFoldSkipsInodesTheBaseDoesNotContain covers the two shapes of "not in
// the base", each of which must keep every byte:
//
//   - born AFTER the cut. Its blocks all carry post-cut provenance, so it is
//     never even a candidate — the base is never asked about it.
//   - PARKED BEFORE the cut. It holds pre-cut blocks (so it IS a candidate)
//     but the cut materialised no name for it, so the base does not contain
//     it. The resolver says so and the fold leaves it alone: an orphan the
//     base never captured must keep serving its open handle from RAM.
func TestFoldSkipsInodesTheBaseDoesNotContain(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"old.bin", "gone.bin"} {
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	oldData := blockPayload(51, blockSize)
	if err := managedWrite(fs, "old.bin", 0, oldData); err != nil {
		t.Fatal(err)
	}
	goneData := blockPayload(53, blockSize)
	if err := managedWrite(fs, "gone.bin", 0, goneData); err != nil {
		t.Fatal(err)
	}
	goneIno := inoOf(t, fs, "gone.bin")
	pinOpenFold(t, fs, openManagedSession(t, fs, "pfs-fold-absent", 1), goneIno)
	// Parked BEFORE the cut: the materializer captures no name for it.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpRemove, Path: "gone.bin"}, nil, ""); err != nil {
		t.Fatal(err)
	}
	cut := takeCut(t, fs, blobs)

	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "new.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	newData := blockPayload(52, blockSize)
	if err := managedWrite(fs, "new.bin", 0, newData); err != nil {
		t.Fatal(err)
	}

	report, err := fs.FoldToBase(context.Background(), cut.base())
	if err != nil {
		t.Fatal(err)
	}
	// new.bin never becomes a candidate (all-post-cut provenance); gone.bin
	// does, and comes back absent.
	if report.Candidates != 2 || report.Inodes != 1 || report.Absent != 1 {
		t.Fatalf("report = %+v, want 2 candidates, 1 folded, 1 absent", report)
	}
	wantDirty(t, fs, 2*blockSize, "the post-cut file and the uncaptured orphan stay resident")
	if got := readAll(t, fs, "old.bin", blockSize); !bytes.Equal(got, oldData) {
		t.Fatalf("folded file diverged at %d", foldFirstDiff(got, oldData))
	}
	if got := readAll(t, fs, "new.bin", blockSize); !bytes.Equal(got, newData) {
		t.Fatalf("post-cut file diverged at %d", foldFirstDiff(got, newData))
	}
	out := make([]byte, blockSize)
	n, rerr := fs.ReadOrphanAt(goneIno, out, 0)
	if rerr != nil && rerr != io.EOF {
		t.Fatalf("uncaptured orphan read: %v", rerr)
	}
	if !bytes.Equal(out[:n], goneData) {
		t.Fatalf("uncaptured orphan diverged at %d", foldFirstDiff(out[:n], goneData))
	}
}

// TestFoldResolveFailureIsPartialNotFatal: an object-store outage mid-pass
// leaves the unresolved inodes dirty for the next pass and reports the failure
// without discarding the progress it did make.
func TestFoldResolveFailureIsPartialNotFatal(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.bin", "b.bin"} {
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := managedWrite(fs, name, 0, blockPayload(61, blockSize)); err != nil {
			t.Fatal(err)
		}
	}
	cut := takeCut(t, fs, blobs)
	failIno := inoOf(t, fs, "a.bin")

	base := cut.base()
	inner := base.Resolve
	base.Resolve = func(ctx context.Context, ino uint64) (content.Source, bool, error) {
		if ino == failIno {
			return content.Source{}, false, errors.New("object store unavailable")
		}
		return inner(ctx, ino)
	}
	report, err := fs.FoldToBase(context.Background(), base)
	if err == nil {
		t.Fatal("a resolve failure must be reported")
	}
	if report.Inodes != 1 || report.Failed != 1 {
		t.Fatalf("report = %+v, want 1 folded and 1 failed", report)
	}
	wantDirty(t, fs, blockSize, "the unresolved inode kept its block")
}

// ── 4. THE PRODUCTION RESOLVER ──────────────────────────────────────────────

// TestFoldAgainstRealPft2Base exercises the path the child actually runs:
// Pft2FoldBase over a REAL immutable PFT2 base, resolving inodes through the
// numeric inode index and rebinding folded blocks to verified extent-tree
// Rangers. Every other fold test resolves through a hand-built content.Source,
// which proves the fold's algebra but not its production binding.
//
// The "cut" here is built through the SAME fstransition engine the HistoryCut
// materializer runs, from the SAME records the live authority applied, with
// the inode identity pinned on the records so both sides agree on it — which
// is exactly the correspondence a real cut has with the prefix it materialises.
func TestFoldAgainstRealPft2Base(t *testing.T) {
	payload := blockPayload(71, 2*blockSize)

	// The live authority: a fork-shaped PFT2 cold start, then the writes. The
	// AUTHORITY assigns the identity (a client record may not carry one), so
	// the cut is built against whatever it chose — which is what a real
	// materializer does when it replays the journal's logged identities.
	live := buildLazyTestBase(t, []wal.Record{{Op: wal.OpMkdir, Path: "d"}})
	fs, _ := newLazyFS(t, live, newFakeEntryLog())
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "d/f.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	fileIno := inoOf(t, fs, "d/f.bin")
	managedWriteBig(t, fs, "d/f.bin", 0, payload)
	wantDirty(t, fs, 2*blockSize, "two resident blocks before the cut")
	watermark := fs.AppliedWatermark()

	// The cut: the identical prefix materialised into an immutable PFT2 base.
	cutBase := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpMkdir, Path: "d"},
		{Op: wal.OpCreate, Path: "d/f.bin", Mode: 0o644, Ino: fileIno},
		{Op: wal.OpWrite, Path: "d/f.bin", Offset: 0, Data: payload[:blockSize]},
		{Op: wal.OpWrite, Path: "d/f.bin", Offset: blockSize, Data: payload[blockSize:]},
	})

	fetcher := &lazyTestFetcher{inner: cutBase.store}
	cache := NewPft2FoldCache(fetcher)
	base, err := Pft2FoldBase(cache, watermark, "cpft2-test", cutBase.root)
	if err != nil {
		t.Fatalf("open the adopted base: %v", err)
	}
	report, err := fs.FoldToBase(context.Background(), base)
	if err != nil {
		t.Fatalf("fold against a real pft2 base: %v", err)
	}
	if report.Inodes != 1 || report.Blocks != 2 || report.BytesReleased != 2*blockSize {
		t.Fatalf("report = %+v, want 1 inode / 2 blocks / %d bytes", report, 2*blockSize)
	}
	wantDirty(t, fs, 0, "both blocks folded into the committed base")

	// The bytes now come from the base's verified extent walk, not from RAM.
	if got := readAll(t, fs, "d/f.bin", int64(len(payload))); !bytes.Equal(got, payload) {
		t.Fatalf("folded file diverged at offset %d", foldFirstDiff(got, payload))
	}
	if fetcher.fetches() == 0 {
		t.Fatal("no object was fetched: the read did not go through the adopted base")
	}

	// A write after the fold read-modify-writes THROUGH the new base and stays
	// resident, so the mixture of folded and fresh content still reads exactly.
	tail := blockPayload(72, 4096)
	if err := managedWrite(fs, "d/f.bin", 100, tail); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), payload...)
	copy(want[100:], tail)
	if got := readAll(t, fs, "d/f.bin", int64(len(want))); !bytes.Equal(got, want) {
		t.Fatalf("post-fold write diverged at offset %d", foldFirstDiff(got, want))
	}
}
