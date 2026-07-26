package wal

import (
	"fmt"
	"path/filepath"
	"testing"
)

// TestCompactThroughKeepsTail: compaction drops the committed prefix and keeps the
// rest, and the log keeps working (appends land after the kept tail).
func TestCompactThroughKeepsTail(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := w.Append(Record{Op: OpCreate, Path: fmt.Sprintf("f%d", i), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if w.Count() != 5 {
		t.Fatalf("count = %d, want 5", w.Count())
	}

	if err := w.CompactThrough(3); err != nil {
		t.Fatal(err)
	}
	if w.Count() != 2 {
		t.Fatalf("count after compact = %d, want 2", w.Count())
	}
	recs, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Path != "f3" || recs[1].Path != "f4" {
		t.Fatalf("kept = %+v, want [f3 f4]", recs)
	}

	if err := w.Append(Record{Op: OpCreate, Path: "f5", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	recs, _ = w.Replay()
	if len(recs) != 3 || recs[2].Path != "f5" {
		t.Fatalf("after append = %+v, want tail f5", recs)
	}
}

// TestCompactThroughAllEmpties: compacting at least the whole log empties it.
func TestCompactThroughAllEmpties(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Append(Record{Op: OpCreate, Path: "x", Mode: 0o644})
	_ = w.Append(Record{Op: OpCreate, Path: "y", Mode: 0o644})
	if err := w.CompactThrough(5); err != nil { // n > count
		t.Fatal(err)
	}
	if w.Count() != 0 {
		t.Fatalf("count = %d, want 0", w.Count())
	}
	if recs, _ := w.Replay(); len(recs) != 0 {
		t.Fatalf("records = %d, want 0", len(recs))
	}
}
