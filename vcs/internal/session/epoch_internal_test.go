package session

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestEpochFloorSurvivesRestart: a persisted generation floor must survive a "restart" so the
// next generation is issued ABOVE it — even when the wall clock has stepped backward. Without
// this, a restart re-floors the generation at the (now lower) clock, the live owner's flush
// looks stale against the watermark, and its writes strand behind a permanent ESTALE.
// Regression for the audit-found HIGH.
func TestEpochFloorSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".epoch")
	// A prior run issued a generation ABOVE the current in-process counter (model: it ran when
	// the clock was an hour ahead, before a backward step) and persisted it.
	high := atomic.LoadUint64(&lastEpoch) + uint64(time.Hour)
	if err := os.WriteFile(path, []byte(strconv.FormatUint(high, 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	// "Restart": seed the floor from the persisted file (NewManager does this from its walDir).
	ConfigureEpochFloor(path)

	// The next generation must exceed the persisted floor — not regress to the lower clock value.
	got := nextEpoch()
	if got <= high {
		t.Fatalf("nextEpoch()=%d after seeding floor %d: generation regressed (would ESTALE-strand writes)", got, high)
	}
	// ...and the floor file advanced to (at least) the freshly issued generation, so the NEXT
	// restart resumes above this one too.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatalf("floor file unreadable after persist: %q", b)
	}
	if stored < got {
		t.Fatalf("floor file=%d, want >= issued generation %d (persist must advance the floor)", stored, got)
	}
}

// TestPersistEpochFloorIsMonotonic: the floor file must never move backward, so a late persist of
// a lower generation can't undo a higher one (which would reopen the regression window).
func TestPersistEpochFloorIsMonotonic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".epoch")
	ConfigureEpochFloor(path)
	persistEpochFloor(5000)
	persistEpochFloor(9000)
	persistEpochFloor(7000) // lower: must be ignored
	b, _ := os.ReadFile(path)
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if v != 9000 {
		t.Fatalf("floor file=%d, want 9000 (a lower persist must not lower the floor)", v)
	}
}
