package wal

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)


// TestTornTailTruncatedSoLaterAppendsSurvive reproduces the bug where a torn tail
// was discarded on replay but its bytes were NOT truncated: the next append landed
// after the stale torn bytes, and a later replay read [valid][torn][new] and
// rejected the whole log as mid-log corruption — losing the new acknowledged write.
func TestTornTailTruncatedSoLaterAppendsSurvive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpCreate, Path: "A", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	// Simulate a torn trailing write (a crash mid-append): a partial frame header.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	_, _ = f.Write([]byte{0, 0, 0, 100, 1, 2, 3})
	_ = f.Close()

	// Replay discards AND truncates the torn tail.
	w2, _ := Open(path)
	recs, err := w2.Replay()
	if err != nil {
		t.Fatalf("replay should discard the torn tail, not error: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "A" {
		t.Fatalf("replay = %+v, want [A]", recs)
	}
	// A new acknowledged write after the torn tail...
	if err := w2.Append(Record{Op: OpCreate, Path: "B", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_ = w2.Close()

	// ...must survive a subsequent replay (the torn bytes were truncated, so the log
	// is [A][B], not [A][torn][B] which would be read as mid-log corruption).
	w3, _ := Open(path)
	recs, err = w3.Replay()
	if err != nil {
		t.Fatalf("replay after torn-tail + append must succeed: %v", err)
	}
	if len(recs) != 2 || recs[0].Path != "A" || recs[1].Path != "B" {
		t.Fatalf("replay = %+v, want [A B] — a torn tail must not corrupt later appends", recs)
	}
}

// TestMidLogCorruptionDetected: a corrupt record in the MIDDLE of the log (valid
// records follow it) is reported as an error, not silently truncated — otherwise
// the still-good acked writes after it would be lost without a trace. A torn tail
// (corrupt LAST record) is still discarded silently (the normal crash artifact).
func TestMidLogCorruptionDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Append(Record{Op: OpCreate, Path: fmt.Sprintf("f%d", i), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()

	// Flip a byte inside the SECOND record's data (frame layout: [4B len][4B crc][data]).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	len0 := binary.BigEndian.Uint32(raw[0:4])
	frame1Data := 8 + int(len0) + 8 // skip frame0, then frame1's [len][crc]
	raw[frame1Data] ^= 0xff
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Replay(); err == nil {
		t.Fatal("mid-log corruption was silently accepted; records after the fault would be lost")
	}
}
