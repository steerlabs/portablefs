package portablefsd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func flockExclusiveNonBlockingForTest(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// writeEngineStore builds the write-back engine's ON-DISK STORE LAYOUT, which
// is what actually accumulated 2.2 GB across 95 directories: engine.lock,
// mount-id, wal-epoch and stream-<epoch>/ holding wb-*.pfw segments and a
// job.json recovery registry. The old sweep only knew the retired sess-*.wal
// layout, so it recognized none of this and reclaimed none of it.
func writeEngineStore(t *testing.T, walRoot, storeID string, job map[string]any, segmentBytes int) string {
	t.Helper()
	dir := filepath.Join(walRoot, storeID)
	streamDir := filepath.Join(dir, "stream-0000000000000001")
	if err := os.MkdirAll(streamDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"engine.lock": nil,
		"mount-id":    []byte("0123456789abcdef0123456789abcdef\n"),
		"wal-epoch":   []byte("1\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(streamDir, "wb-00000001.pfw"), make([]byte, segmentBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if job != nil {
		body, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(streamDir, "job.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A DRAINED STORE NO ATTACH CLAIMS IS GARBAGE, AND GARBAGE MUST BE COLLECTED.
//
// On the base revision this directory survived every daemon start forever: the
// sweep found no sess-*.wal files, concluded there was nothing to keep, called
// os.Remove(dir) — which failed ENOTEMPTY against engine.lock/mount-id/
// wal-epoch/stream-* — and discarded the error.
//
// The store's segment is stubbed as measuring drained: whether the WAL reader
// can measure a real stream is proven where the format lives
// (writeback.TestInspectStreamTailMeasuresARealStream). What is proven here is
// that a stream MEASURED drained is reclaimed whole.
func TestSweepReclaimsADrainedOrphanEngineStore(t *testing.T) {
	stateDir := privateTempDir(t)
	walRoot := filepath.Join(stateDir, "wal")
	dir := writeEngineStore(t, walRoot, "orphaned", map[string]any{
		"version": 1, "jobId": "job0123456789abcdef0123456789abcdef",
		"volumeId": "vol_gone", "branch": "main", "state": "parked",
		"admittedThrough": 12, "appliedThrough": 12,
		"pendingRecords": 0, "pendingBytes": 0,
	}, 4096)
	stubStreamTails(t, nil, nil)

	sweepWALRoot(stateDir, nil)

	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("a drained orphan write-back store must be reclaimed, %s survived (%v)", dir, err)
	}
}

// A STORE HOLDING THE USER'S WRITES IS NEVER DELETED — BUT IT MUST NOT BE
// UNREACHABLE EITHER. The 95 stranded stores had no identity.json, which is
// precisely why no attach could ever adopt them. Stamping the identity their own
// recovery registry already records makes them adoptable, so they drain on the
// next attach of that volume instead of accumulating forever.
func TestSweepPreservesAndMakesAdoptableAnOrphanStoreHoldingRecords(t *testing.T) {
	stateDir := privateTempDir(t)
	walRoot := filepath.Join(stateDir, "wal")
	dir := writeEngineStore(t, walRoot, "unshipped", map[string]any{
		"version": 1, "jobId": "job0123456789abcdef0123456789abcdef",
		"volumeId": "vol_live", "branch": "main", "state": "forced",
		"admittedThrough": 90, "appliedThrough": 12,
		"pendingRecords": 78, "pendingBytes": 1 << 20,
	}, 4096)

	sweepWALRoot(stateDir, nil)

	if _, err := os.Lstat(filepath.Join(dir, "stream-0000000000000001", "wb-00000001.pfw")); err != nil {
		t.Fatalf("a store holding unshipped records must be preserved intact: %v", err)
	}
	id, ok := readWALIdentity(dir)
	if !ok {
		t.Fatal("a preserved orphan store must be stamped with the identity that lets an attach adopt it")
	}
	if id.VolumeID != "vol_live" || id.Branch != "main" {
		t.Fatalf("stamped identity = %+v, want vol_live@main", id)
	}
	// And the very next sweep now leaves it to that volume's attach.
	sweepWALRoot(stateDir, []persistedAttachEntry{{VolumeID: "vol_live", Branch: "main", MountPath: "/mnt/x"}})
	if _, err := os.Lstat(dir); err != nil {
		t.Fatalf("a claimed store must be left for its attach: %v", err)
	}
}

func TestSweepNeverTouchesAStoreALiveEngineHolds(t *testing.T) {
	stateDir := privateTempDir(t)
	walRoot := filepath.Join(stateDir, "wal")
	dir := writeEngineStore(t, walRoot, "held", map[string]any{
		"version": 1, "jobId": "job0123456789abcdef0123456789abcdef",
		"volumeId": "vol_x", "branch": "main", "state": "parked",
		"admittedThrough": 3, "appliedThrough": 3,
		"pendingRecords": 0, "pendingBytes": 0,
	}, 128)

	held, err := os.OpenFile(filepath.Join(dir, "engine.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := flockExclusiveNonBlockingForTest(held); err != nil {
		t.Fatal(err)
	}

	sweepWALRoot(stateDir, nil)

	if _, err := os.Lstat(dir); err != nil {
		t.Fatalf("a store a live engine owns must never be reclaimed: %v", err)
	}
}
