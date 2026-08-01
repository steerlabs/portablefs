package writeback

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// A segment reclaim issues a sequence of unlinks and directory barriers. What a
// crash leaves behind is NOT decided by the order the unlinks were called in:
// an unlink is only durable once a directory fsync that follows it has itself
// reached media, and until then it may or may not have persisted, independently
// of its neighbours. The two types below record that sequence from the real
// reclaim code, and derive from it every set of unlinks a crash could have left
// persisted.

// reclaimOp is one durability-relevant step of a reclaim: an unlink of the
// named segment file, or (unlink == "") a directory barrier that makes every
// unlink issued BEFORE it durable.
type reclaimOp struct{ unlink string }

// reclaimRecorder swaps itself in for the reclaim seams and records the order.
type reclaimRecorder struct {
	ops     []reclaimOp
	onFirst func() // optional: runs once, before the first unlink reaches the disk
	fired   bool
}

func (r *reclaimRecorder) install(t *testing.T) {
	t.Helper()
	oldUnlink, oldSync := reclaimUnlinkSegment, reclaimSyncDir
	reclaimUnlinkSegment = func(path string) error {
		if !r.fired {
			r.fired = true
			if r.onFirst != nil {
				r.onFirst()
			}
		}
		r.ops = append(r.ops, reclaimOp{unlink: filepath.Base(path)})
		return oldUnlink(path)
	}
	reclaimSyncDir = func(dir string) error {
		r.ops = append(r.ops, reclaimOp{})
		return oldSync(dir)
	}
	t.Cleanup(func() { reclaimUnlinkSegment, reclaimSyncDir = oldUnlink, oldSync })
}

// unlinked is every segment the recorded reclaim issued an unlink for, in
// issue order.
func (r *reclaimRecorder) unlinked() []string {
	var out []string
	for _, op := range r.ops {
		if op.unlink != "" {
			out = append(out, op.unlink)
		}
	}
	return out
}

// reachable reports whether a crash could leave EXACTLY `subset` persisted.
//
// The crash model is the weakest one a POSIX filesystem entitles us to assume:
// pick any point k in the recorded sequence as the moment of the crash. An
// unlink issued at or after k never happened. An unlink issued before the last
// barrier that completed before k is durable. Every unlink in between was
// issued but not yet barriered, so it is free to have persisted or not,
// independently of the others.
func (r *reclaimRecorder) reachable(subset map[string]bool) bool {
	for k := 0; k <= len(r.ops); k++ {
		lastBarrier := -1
		for i := 0; i < k; i++ {
			if r.ops[i].unlink == "" {
				lastBarrier = i
			}
		}
		ok := true
		for i, op := range r.ops {
			if op.unlink == "" {
				continue
			}
			switch {
			case i < lastBarrier: // durable: must be in the subset
				ok = subset[op.unlink]
			case i >= k: // never issued: must not be in the subset
				ok = !subset[op.unlink]
			}
			if !ok {
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// persistedSubsets enumerates all 2^N subsets of `all`, each as a name set plus
// a stable label.
func persistedSubsets(all []string) []struct {
	label string
	set   map[string]bool
} {
	out := make([]struct {
		label string
		set   map[string]bool
	}, 0, 1<<len(all))
	for mask := 0; mask < 1<<len(all); mask++ {
		set := map[string]bool{}
		var names []string
		for i, name := range all {
			if mask&(1<<i) != 0 {
				set[name] = true
				names = append(names, name)
			}
		}
		label := "none"
		if len(names) > 0 {
			label = strings.Join(names, "+")
		}
		out = append(out, struct {
			label string
			set   map[string]bool
		}{label, set})
	}
	return out
}

// isContiguousPrefixOf reports whether `subset` is a prefix of `all` in issue
// order — the shape barrier B's comment claims every crash point leaves, and
// the only shape the reader's ordinal-continuity check accepts.
func isContiguousPrefixOf(subset map[string]bool, all []string) bool {
	seenGap := false
	for _, name := range all {
		if subset[name] {
			if seenGap {
				return false
			}
			continue
		}
		seenGap = true
	}
	return true
}

func copyDirFiles(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dst, err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read dir %s: %v", src, err)
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		buf, err := os.ReadFile(filepath.Join(src, ent.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", ent.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dst, ent.Name()), buf, 0o600); err != nil {
			t.Fatalf("write %s: %v", ent.Name(), err)
		}
	}
	if err := fsyncDir(dst); err != nil {
		t.Fatalf("sync %s: %v", dst, err)
	}
}

// buildFourSegmentLegacyStream lays down a legacy stream of exactly four
// segments — three reclaimable, one active — with the barrier-A APPLIED mark
// already durable in the active segment. That is the state barrier B of the
// recovery close-out operates on.
func buildFourSegmentLegacyStream(t *testing.T, stateDir string, epoch string) (dir string, mountID [16]byte, lastSeq uint64, digest [32]byte) {
	t.Helper()
	mountID, err := ensureMountID(stateDir)
	if err != nil {
		t.Fatalf("mount identity: %v", err)
	}
	s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
	s.segmentTarget = 8 << 10
	s.delegation("s0", epoch)
	for i := 0; s.ordinal < 4 || i < 4; i++ {
		s.mutation(wal.Record{
			Op: wal.OpWrite, Path: fmt.Sprintf("s0/f%03d", i), Data: make([]byte, 512),
		})
		if s.ordinal >= 4 && i >= 4 {
			break
		}
	}
	s.applied(s.seq, s.digest)
	lastSeq, digest = s.seq, s.digest
	s.finish()
	dir = filepath.Join(stateDir, streamDirName(1))
	if got := streamSegmentCount(t, dir); got != 4 {
		t.Fatalf("fixture produced %d segments, want 4", got)
	}
	return dir, mountID, lastSeq, digest
}

// TestCloseOutReclaimSurvivesEveryPersistedUnlinkSubset is the reordered-
// persistence half of the legacy close-out's crash contract.
//
// TestReclaimedCloseOutPrefixIsCrashSafe models a crash as an INTERRUPTION: the
// process stops between two whole steps, and every step before the stop is
// assumed to have landed. Real filesystems do not promise that. Barrier B
// issues its unlinks ascending and then syncs the directory ONCE, so a crash
// before that single fsync can persist the unlink of wb-00000002.pfw and not
// the unlink of wb-00000001.pfw. The retained set is then {0,2,3}: an ordinal
// HOLE, which scanStreamWithTailRepair rejects as ErrCorrupt ("segment chain
// broken"), which recoverStream maps to JobCorrupt, which attempt() treats as
// TERMINAL. The stream is parked forever with its delegation grants checked out.
//
// This test records the barriers barrier B actually issues, enumerates all 2^N
// persisted-unlink subsets a crash could leave under that barrier structure,
// materializes each one, and requires recovery to reach a definite non-corrupt
// outcome from every one of them.
func TestCloseOutReclaimSurvivesEveryPersistedUnlinkSubset(t *testing.T) {
	epoch := strings.Repeat("E", maxEpochBytes+64)

	// Probe run: drive the REAL barrier B once and record the order and the
	// barriers it issues.
	probeState := t.TempDir()
	probeDir, _, probeSeq, probeDigest := buildFourSegmentLegacyStream(t, probeState, epoch)
	scan, err := scanStreamReadOnly(probeDir)
	if err != nil {
		t.Fatalf("probe fixture does not scan: %v", err)
	}
	rec := &reclaimRecorder{}
	rec.install(t)
	// budget == the live footprint forces the legacy accommodation: the mark is
	// already durable in the tail segment (appliedBytes == 0), so the fast path
	// cannot fit the RELEASE frames and barrier B must reclaim first.
	budget := streamFootprint(t, probeDir)
	if err := appendRecoveryReleaseCertificate(probeDir, scan, legacyStreamMark(probeSeq, probeDigest),
		[]RebindScope{{Scope: "s0", Epoch: epoch}}, budget); err != nil {
		t.Fatalf("probe close-out: %v", err)
	}
	all := rec.unlinked()
	if len(all) != 3 {
		t.Fatalf("barrier B issued %d unlinks (%v), want 3", len(all), all)
	}

	for _, sub := range persistedSubsets(all) {
		if !rec.reachable(sub.set) {
			continue
		}
		t.Run("persisted="+sub.label, func(t *testing.T) {
			if !isContiguousPrefixOf(sub.set, all) {
				t.Errorf("a crash can leave the non-prefix persisted set %v, which is an ordinal HOLE; barrier B's ops were %v",
					sub.label, rec.ops)
			}
			stateDir := t.TempDir()
			dir, mountID, lastSeq, digest := buildFourSegmentLegacyStream(t, stateDir, epoch)
			reclaimSegmentSubset(t, dir, sub.set)

			wbID := streamID(mountID, 1)
			auth := newFakeAuthority()
			seedLegacyGrants(auth, wbID, map[string]string{"s0": epoch})
			auth.mu.Lock()
			auth.streams[wbID] = newFakeStreamAt(lastSeq, digest)
			auth.mu.Unlock()

			e, err := Open(context.Background(), Config{
				StateDir: stateDir, VolumeID: "vol", Branch: "main",
				Remote: auth, BudgetBytes: 1 << 30,
			})
			if err != nil {
				t.Fatalf("attach over persisted unlink subset %v: %v", sub.label, err)
			}
			defer func() { _, _ = e.ForceClose("teardown") }()

			if jobs := e.Status().Jobs; len(jobs) != 0 {
				t.Fatalf("persisted unlink subset %v parked the stream: %+v", sub.label, jobs)
			}
			if got := auth.grantCount(); got != 0 {
				t.Fatalf("persisted unlink subset %v left %d grants held on the authority", sub.label, got)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("persisted unlink subset %v did not resolve the stream directory (%v)", sub.label, err)
			}
		})
	}
}

// TestCheckpointReclaimSurvivesEveryPersistedUnlinkSubset is the same contract
// for the ONLINE reclaim. CheckpointAndReclaim has the identical shape — an
// ascending unlink loop with a single trailing fsyncDir — so the identical
// reordered-persistence hole applies, and the identical ErrCorrupt is what the
// stream comes back to after the crash.
func TestCheckpointReclaimSurvivesEveryPersistedUnlinkSubset(t *testing.T) {
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 4 << 10
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	root := t.TempDir()
	streamDir := filepath.Join(root, streamDirName(1))
	var mountID [16]byte
	copy(mountID[:], "reclaim-subset--")
	w, err := createStreamWAL(streamDir, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}
	if err := w.appendControl(frameDelegation, delegationFrame{Scope: "d", Epoch: "epoch-1"}); err != nil {
		t.Fatalf("append delegation: %v", err)
	}
	var through uint64
	var digest [32]byte
	for i := 0; len(w.segments) < 4; i++ {
		payload := canonicalPayload(wal.Record{
			Op: wal.OpWrite, Path: fmt.Sprintf("d/f%03d", i), Offset: 0,
			Data: bytes.Repeat([]byte("a"), 512),
		})
		acks, err := w.appendMutations([][]byte{payload})
		if err != nil {
			t.Fatalf("append mutation %d: %v", i, err)
		}
		through, digest = acks[0].seq, acks[0].digest
		if i > 4096 {
			t.Fatal("fixture never reached four segments")
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Snapshot the directory at the instant barrier B begins: the APPLIED
	// certificate is already durable, nothing has been unlinked yet. Every
	// crash state under test is that snapshot minus a persisted unlink subset.
	template := filepath.Join(root, "template")
	rec := &reclaimRecorder{onFirst: func() { copyDirFiles(t, streamDir, template) }}
	rec.install(t)
	if err := w.CheckpointAndReclaim(legacyStreamMark(through, digest), func(uint64) bool { return false }); err != nil {
		t.Fatalf("checkpoint and reclaim: %v", err)
	}
	_ = w.Close()
	// The checkpoint's own control append can trip a rotation, so the reclaim
	// covers three or four segments depending on where the last one landed.
	// Either way every subset of the unlinks it issued is enumerated below.
	all := rec.unlinked()
	if len(all) < 3 {
		t.Fatalf("CheckpointAndReclaim issued %d unlinks (%v), want at least 3", len(all), all)
	}

	for _, sub := range persistedSubsets(all) {
		if !rec.reachable(sub.set) {
			continue
		}
		t.Run("persisted="+sub.label, func(t *testing.T) {
			if !isContiguousPrefixOf(sub.set, all) {
				t.Errorf("a crash can leave the non-prefix persisted set %v, which is an ordinal HOLE; the reclaim's ops were %v",
					sub.label, rec.ops)
			}
			dir := filepath.Join(t.TempDir(), streamDirName(1))
			copyDirFiles(t, template, dir)
			reclaimSegmentSubset(t, dir, sub.set)

			scan, err := scanStreamReadOnly(dir)
			if err != nil {
				t.Fatalf("persisted unlink subset %v no longer scans: %v", sub.label, err)
			}
			live, _, marks, _, err := decodeStreamFrames(scan.frames)
			if err != nil {
				t.Fatalf("persisted unlink subset %v no longer decodes: %v", sub.label, err)
			}
			if got := live["d"]; got != "epoch-1" {
				t.Fatalf("persisted unlink subset %v lost the live grant (%q)", sub.label, got)
			}
			got, err := digestAt(scan, marks, through)
			if err != nil {
				t.Fatalf("persisted unlink subset %v cannot rebuild the checkpoint digest: %v", sub.label, err)
			}
			if got != digest {
				t.Fatalf("persisted unlink subset %v rebuilt digest %x at %d, want %x", sub.label, got, through, digest)
			}
		})
	}
}
