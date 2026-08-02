package portablefsd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// stubStreamTails installs a deterministic answer for "what does this stream
// still hold", keyed by stream directory base name. The sweep's CLASSIFIER is
// what these tests are about; whether the WAL reader can measure a real stream
// is proven separately, in the package that owns the format
// (writeback.TestInspectStreamTail*).
func stubStreamTails(t *testing.T, tails map[string]writeback.StreamTail, errs map[string]error) {
	t.Helper()
	prev := inspectStreamTail
	t.Cleanup(func() { inspectStreamTail = prev })
	inspectStreamTail = func(dir string) (writeback.StreamTail, error) {
		key := filepath.Base(dir)
		if err, ok := errs[key]; ok {
			return writeback.StreamTail{}, err
		}
		if tail, ok := tails[key]; ok {
			return tail, nil
		}
		return writeback.StreamTail{}, nil
	}
}

func storeExists(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Lstat(dir)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatalf("stat %s: %v", dir, err)
	return false
}

// TWO DRAINED STORES THAT DIFFER ONLY IN admittedThrough MUST SHARE ONE FATE.
//
// The round-17e classifier derived "how much is pending" from
// admittedThrough - appliedThrough on uint64 with no guard. An ACTIVE stream
// never advances admittedThrough (only recovery and force-park write it) while
// appliedThrough climbs on every apply, so the subtraction wrapped and a fully
// drained store was reported as holding 18446744073709551205 records and
// preserved forever — the exact leak 17e existed to close. The live instance
// was {admittedThrough:0, appliedThrough:411, pendingRecords:0, pendingBytes:0}.
//
// The two stores below are byte-identical apart from that one field.
func TestSweepReclaimsDrainedStoresRegardlessOfWatermarkOrder(t *testing.T) {
	stateDir := privateTempDir(t)
	walRoot := filepath.Join(stateDir, "wal")
	job := func(admitted uint64) map[string]any {
		return map[string]any{
			"version": 1, "jobId": "job0123456789abcdef0123456789abcdef",
			"volumeId": "vol_gone", "branch": "main", "state": "active",
			"admittedThrough": admitted, "appliedThrough": 411,
			"pendingRecords": 0, "pendingBytes": 0,
		}
	}
	// The wrapping shape observed live, and its only difference: a watermark
	// pair that happens to be ordered the way the subtraction assumed.
	wrapped := writeEngineStore(t, walRoot, "wrapped", job(0), 4096)
	ordered := writeEngineStore(t, walRoot, "ordered", job(411), 4096)
	stubStreamTails(t, nil, nil) // both streams measure as fully drained

	sweepWALRoot(stateDir, nil)

	if storeExists(t, ordered) {
		t.Fatalf("a drained orphan store must be reclaimed, %s survived", ordered)
	}
	if storeExists(t, wrapped) {
		t.Fatalf("a drained orphan store whose appliedThrough exceeds its "+
			"admittedThrough must be reclaimed exactly like its ordered twin, "+
			"%s survived", wrapped)
	}
}

// AN ACTIVE REGISTRY CANNOT PROVE A STREAM DRAINED, AND MUST NOT BE BELIEVED
// WHEN IT SAYS SO.
//
// PendingRecords/PendingBytes are refreshed only when the authority APPLIES
// something (Engine.noteApplied). Appending does not touch them. So a stream
// that appended records and then died reports the pending count from its last
// apply — zero, over a tail that is not empty. The 17e classifier read that
// zero, saw admittedThrough == appliedThrough == 0, declared the store drained
// and deleted it whole, with the user's unshipped writes inside.
func TestSweepPreservesAStoreWhoseRegistryUnderreportsItsTail(t *testing.T) {
	stateDir := privateTempDir(t)
	walRoot := filepath.Join(stateDir, "wal")
	dir := writeEngineStore(t, walRoot, "underreported", map[string]any{
		"version": 1, "jobId": "job0123456789abcdef0123456789abcdef",
		"volumeId": "vol_live", "branch": "main", "state": "active",
		"admittedThrough": 0, "appliedThrough": 0,
		"pendingRecords": 0, "pendingBytes": 0,
	}, 4096)
	stubStreamTails(t, map[string]writeback.StreamTail{
		"stream-0000000000000001": {Segments: 1, SegmentBytes: 4096, Records: 7, Bytes: 3000},
	}, nil)

	sweepWALRoot(stateDir, nil)

	if !storeExists(t, dir) {
		t.Fatal("a store whose WAL still holds unshipped records must never be " +
			"reclaimed on a registry that only says it applied nothing")
	}
	if _, err := os.Lstat(filepath.Join(dir, "stream-0000000000000001", "wb-00000001.pfw")); err != nil {
		t.Fatalf("the preserved store's segments must be intact: %v", err)
	}
}

// A STREAM THE SWEEP CANNOT READ IS NOT AN EMPTY STREAM.
//
// streamPendingBytes reported drained=false for an unreadable or
// registry-less stream, but reported ZERO records with it — and the caller
// branched on the record COUNT rather than on the verdict, so the store was
// reclaimed anyway. Every byte of a damaged store was deleted by the path that
// exists to protect it.
func TestSweepPreservesAStoreWhoseTailCannotBeMeasured(t *testing.T) {
	stateDir := privateTempDir(t)
	walRoot := filepath.Join(stateDir, "wal")
	dir := writeEngineStore(t, walRoot, "unreadable", nil, 4096)
	stubStreamTails(t, nil, map[string]error{
		"stream-0000000000000001": errors.New("writeback: wal corruption: bad segment magic"),
	})

	sweepWALRoot(stateDir, nil)

	if !storeExists(t, dir) {
		t.Fatal("a store whose stream could not be read must be preserved and " +
			"reported, never reclaimed")
	}
}

// A JOB AWAITING AN OPERATOR DECISION IS EVIDENCE, NOT GARBAGE.
//
// conflict and corrupt are the two states force-park refuses to touch because
// they "require explicit recovery resolution". The sweep read none of that: a
// corrupt job whose counters happened to read zero was reclaimed whole,
// destroying the only copy of the damage an operator was meant to resolve.
func TestSweepPreservesAStoreAwaitingRecoveryResolution(t *testing.T) {
	for _, state := range []string{"conflict", "corrupt"} {
		t.Run(state, func(t *testing.T) {
			stateDir := privateTempDir(t)
			walRoot := filepath.Join(stateDir, "wal")
			dir := writeEngineStore(t, walRoot, "unresolved", map[string]any{
				"version": 1, "jobId": "job0123456789abcdef0123456789abcdef",
				"volumeId": "vol_x", "branch": "main", "state": state,
				"admittedThrough": 9, "appliedThrough": 9,
				"pendingRecords": 0, "pendingBytes": 0,
			}, 4096)
			stubStreamTails(t, nil, nil) // measures drained

			sweepWALRoot(stateDir, nil)

			if !storeExists(t, dir) {
				t.Fatalf("a %s recovery job must be preserved for the operator "+
					"who has to resolve it", state)
			}
		})
	}
}
