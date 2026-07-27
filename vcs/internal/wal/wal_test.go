package wal

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendReplayAndDurability(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	recs := []Record{
		{Op: OpCreate, Path: "a.txt", Mode: 0o644},
		{Op: OpWrite, Path: "a.txt", Offset: 0, Data: []byte("hello\x00binary")},
		{Op: OpMkdir, Path: "dir", Mode: 0o755},
		{Op: OpRename, Path: "a.txt", NewPath: "b.txt"},
	}
	for _, r := range recs {
		if err := w.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(recs) {
		t.Fatalf("replay %d records, want %d", len(got), len(recs))
	}
	if got[1].Op != OpWrite || string(got[1].Data) != "hello\x00binary" {
		t.Fatalf("write record wrong (binary payload?): %+v", got[1])
	}
	if got[3].Op != OpRename || got[3].NewPath != "b.txt" {
		t.Fatalf("rename record wrong: %+v", got[3])
	}
	_ = w.Close()

	// Durability: reopen the same path and replay.
	w2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	got2, _ := w2.Replay()
	if len(got2) != len(recs) {
		t.Fatalf("after reopen, replay %d, want %d", len(got2), len(recs))
	}
}

func TestTornTailDiscarded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wal.log")
	w, _ := Open(p)
	for i := 0; i < 3; i++ {
		if err := w.Append(Record{Op: OpCreate, Path: "f", Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()

	// Simulate a crash mid-append: a full (intact) header claiming 1000 bytes, but
	// only 5 of those body bytes written before the crash. The length CRC is valid
	// (the header was fully flushed), so this is a torn tail, not length corruption.
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o644)
	var hdr [headerBytes]byte
	binary.BigEndian.PutUint32(hdr[0:4], 1000)
	binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(hdr[0:4]))
	binary.BigEndian.PutUint32(hdr[8:12], 12345)
	_, _ = f.Write(hdr[:])
	_, _ = f.Write([]byte("short"))
	_ = f.Close()

	w2, _ := Open(p)
	defer w2.Close()
	got, err := w2.Replay()
	if err != nil {
		t.Fatalf("torn tail must replay without error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("torn tail: replay %d, want 3 (torn frame must be discarded)", len(got))
	}
}

// TestCorruptLengthHeaderMidLogIsLoud verifies that a corrupted length field in a
// NON-tail record is reported as an error (so its valid successors are not silently
// consumed and truncated as a "torn tail"), rather than dropped without a word.
func TestCorruptLengthHeaderMidLogIsLoud(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wal.log")
	w, _ := Open(p)
	for i := 0; i < 3; i++ {
		if err := w.Append(Record{Op: OpCreate, Path: "f", Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()

	// Flip the very first record's length field to a large-but-plausible value
	// (<= maxRecordBytes) WITHOUT fixing its length CRC. The old reader trusted the
	// length, over-read across the following records to EOF, and silently truncated.
	raw, _ := os.ReadFile(p)
	binary.BigEndian.PutUint32(raw[0:4], 4096) // corrupt length; leave hdr[4:8] (lenCrc) stale
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	w2, _ := Open(p)
	defer w2.Close()
	if _, err := w2.Replay(); err == nil {
		t.Fatal("a corrupt mid-log length field must surface as a replay error, not silent truncation")
	}
}

func TestReset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wal.log")
	w, _ := Open(p)
	defer w.Close()
	_ = w.Append(Record{Op: OpCreate, Path: "x", Mode: 0o644})
	if err := w.Reset(); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.Replay(); len(got) != 0 {
		t.Fatalf("after reset, replay %d, want 0", len(got))
	}
	// Still usable after reset.
	_ = w.Append(Record{Op: OpCreate, Path: "y", Mode: 0o644})
	got, _ := w.Replay()
	if len(got) != 1 || got[0].Path != "y" {
		t.Fatalf("after reset+append: %+v", got)
	}
}

// TestRenumberStartsAtZeroAndPersists: Renumber rewrites a mid-stream tail to contiguous Seqs
// from 0, durably — so a recovered generation's first flush satisfies the authority's gap
// check. The rewrite is atomic (temp+rename), so unlike a Reset+append loop it can't truncate.
func TestRenumberStartsAtZeroAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.wal")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// A compacted survivor tail: records that begin mid-stream (non-zero Seqs).
	in := []Record{
		{Seq: 7, Op: OpCreate, Path: "a"},
		{Seq: 8, Op: OpWrite, Path: "a", Data: []byte("keep")},
	}
	out, err := w.Renumber(in)
	if err != nil {
		t.Fatalf("Renumber: %v", err)
	}
	if len(out) != 2 || out[0].Seq != 0 || out[1].Seq != 1 {
		t.Fatalf("renumbered Seqs = %d,%d, want 0,1", out[0].Seq, out[1].Seq)
	}
	// A subsequent append must continue after the renumbered tail (Seq 2), not collide.
	seq, err := w.AppendBuffered(Record{Op: OpWrite, Path: "a", Data: []byte("more")})
	if err != nil || seq != 2 {
		t.Fatalf("append after Renumber: seq=%d err=%v, want 2", seq, err)
	}
	_ = w.CommitThrough(seq)
	_ = w.Close()
	// Reopen + replay: the persisted records are contiguous from 0 with intact data.
	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	rec, rerr := w2.Replay()
	if rerr != nil {
		t.Fatalf("replay: %v", rerr)
	}
	if len(rec) != 3 || rec[0].Seq != 0 || rec[1].Seq != 1 || rec[2].Seq != 2 {
		t.Fatalf("replayed Seqs = %v, want 0,1,2", []uint64{rec[0].Seq, rec[1].Seq, rec[2].Seq})
	}
	if string(rec[1].Data) != "keep" || string(rec[2].Data) != "more" {
		t.Fatalf("replayed data = %q,%q, want keep,more", rec[1].Data, rec[2].Data)
	}
}
