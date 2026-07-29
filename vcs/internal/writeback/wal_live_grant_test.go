package writeback

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// TestWALReclaimPreservesLiveGrantForLaterTail pins the recovery shape that
// requires each retained segment to carry its own live delegation state:
//
//	delegation + applied mutation in segment 1
//	rotate, checkpoint, and reclaim segment 1
//	acknowledge another mutation under the same grant in segment 2
//	hard crash and recover from segment 2 alone
//
// The retained tail must decode under the original grant and rebuild the exact
// stream digest and mutation bytes from the APPLIED checkpoint.
func TestWALReclaimPreservesLiveGrantForLaterTail(t *testing.T) {
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 1 << 30
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	dir := t.TempDir()
	streamDir := filepath.Join(dir, streamDirName(1))
	var mountID [16]byte
	copy(mountID[:], "grant-reclaim---")
	w, err := createStreamWAL(streamDir, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}

	grant := delegationFrame{Scope: "d", Epoch: "epoch-1"}
	if err := w.appendControl(frameDelegation, grant); err != nil {
		t.Fatalf("append delegation: %v", err)
	}
	firstPayload := canonicalPayload(wal.Record{
		Op: wal.OpWrite, Path: "d/f", Offset: 0, Data: bytes.Repeat([]byte("a"), 512),
	})
	first, err := w.appendMutations([][]byte{firstPayload})
	if err != nil {
		t.Fatalf("append first mutation: %v", err)
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("sync first segment: %v", err)
	}

	// Force the production rotation path now that segment 1 contains both the
	// grant and applied traffic. The new segment must receive a copied grant
	// before CheckpointAndReclaim is allowed to delete segment 1.
	w.mu.Lock()
	segmentTargetBytes = w.segments[len(w.segments)-1].size
	err = w.rotateIfNeededLocked()
	w.mu.Unlock()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := len(w.segments); got != 2 {
		t.Fatalf("rotation produced %d segments, want 2", got)
	}
	if err := w.CheckpointAndReclaim(first[0].seq, first[0].digest, func(uint64) bool { return false }); err != nil {
		t.Fatalf("checkpoint and reclaim segment 1: %v", err)
	}
	if _, err := os.Stat(segmentPath(streamDir, 1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original grant segment survived reclaim: %v", err)
	}

	wantTail := []byte("tail-survives-reclaim")
	secondPayload := canonicalPayload(wal.Record{
		Op: wal.OpWrite, Path: "d/f", Offset: 512, Data: wantTail,
	})
	second, err := w.appendMutations([][]byte{secondPayload})
	if err != nil {
		t.Fatalf("append later mutation: %v", err)
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("sync later mutation: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("hard-crash close: %v", err)
	}

	scan, err := scanStream(streamDir)
	if err != nil {
		t.Fatalf("scan retained stream: %v", err)
	}
	live, mutations, marks, closed, err := decodeStreamFrames(scan.frames)
	if err != nil {
		t.Fatalf("decode retained stream: %v", err)
	}
	if closed {
		t.Fatal("hard-crash stream decoded as cleanly closed")
	}
	if got := live[grant.Scope]; got != grant.Epoch {
		t.Fatalf("retained live grant = %q, want %q", got, grant.Epoch)
	}
	if len(mutations) != 1 || mutations[0].seq != second[0].seq {
		t.Fatalf("retained mutations = %+v, want only sequence %d", mutations, second[0].seq)
	}
	rec, err := wal.DecodePFR1(mutations[0].payload)
	if err != nil {
		t.Fatalf("decode retained tail mutation: %v", err)
	}
	if rec.Path != "d/f" || !bytes.Equal(rec.Data, wantTail) {
		t.Fatalf("retained mutation = path %q data %q, want d/f %q", rec.Path, rec.Data, wantTail)
	}

	checkpointDigest, err := digestAt(scan, marks, first[0].seq)
	if err != nil {
		t.Fatalf("rebuild checkpoint digest: %v", err)
	}
	if checkpointDigest != first[0].digest {
		t.Fatalf("checkpoint digest = %x, want %x", checkpointDigest, first[0].digest)
	}
	tailDigest, err := digestAt(scan, marks, second[0].seq)
	if err != nil {
		t.Fatalf("rebuild tail digest: %v", err)
	}
	if tailDigest != second[0].digest {
		t.Fatalf("tail digest = %x, want %x", tailDigest, second[0].digest)
	}

	// scanStream already enforces dense frame numbers. Pin the retained
	// physical order too: copied grant, durable checkpoint, later mutation.
	if len(scan.frames) != 3 ||
		scan.frames[0].typ != frameDelegation ||
		scan.frames[1].typ != frameApplied ||
		scan.frames[2].typ != frameMutation {
		t.Fatalf("retained frame order = %+v, want DELEGATION, APPLIED, MUTATION", scan.frames)
	}
}

// TestWALRotationDoesNotReemitReleasedGrant proves the projection shrinks on a
// durable RELEASE. Once the original segment is reclaimed, recovery must not
// resurrect a grant that was already handed back to the authority.
func TestWALRotationDoesNotReemitReleasedGrant(t *testing.T) {
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 1 << 30
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	dir := t.TempDir()
	streamDir := filepath.Join(dir, streamDirName(1))
	var mountID [16]byte
	copy(mountID[:], "grant-release---")
	w, err := createStreamWAL(streamDir, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}
	grant := delegationFrame{Scope: "d", Epoch: "epoch-1"}
	if err := w.appendControl(frameDelegation, grant); err != nil {
		t.Fatalf("append delegation: %v", err)
	}
	if err := w.appendControl(frameRelease, grant); err != nil {
		t.Fatalf("append release: %v", err)
	}

	w.mu.Lock()
	segmentTargetBytes = w.segments[len(w.segments)-1].size
	err = w.rotateIfNeededLocked()
	w.mu.Unlock()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := w.CheckpointAndReclaim(0, digestZero(), func(uint64) bool { return false }); err != nil {
		t.Fatalf("checkpoint and reclaim: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	scan, err := scanStream(streamDir)
	if err != nil {
		t.Fatalf("scan retained stream: %v", err)
	}
	live, _, _, _, err := decodeStreamFrames(scan.frames)
	if err != nil {
		t.Fatalf("decode retained stream: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("released grant was re-emitted: %+v", live)
	}
	for _, fr := range scan.frames {
		if fr.typ == frameDelegation {
			t.Fatalf("released delegation frame survived into segment %d", fr.ordinal)
		}
	}
}
