package workfs

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// TestApplyBatchAtomicVisibility: a flushed write-back batch applies as ONE atomic unit
// — every record lands, and EXACTLY ONE invalidation is published for the whole batch
// (never per-record), so no other mount can observe a torn/partial flush.
func TestApplyBatchAtomicVisibility(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	sub, unsub := fs.Subscribe()
	defer unsub()

	batch := []wal.Record{
		{Op: wal.OpCreate, Path: "a", Mode: 0o644},
		{Op: wal.OpWrite, Path: "a", Offset: 0, Data: []byte("hello")},
		{Op: wal.OpCreate, Path: "b", Mode: 0o644},
	}
	if err := fs.ApplyBatch(batch, ""); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}

	// Exactly ONE publish covering the whole batch (atomic visibility).
	select {
	case batchInvs := <-sub:
		paths := batchInvs.Invs
		if len(paths) != 3 {
			t.Fatalf("batch published %d paths %v, want 3 (a, a, b)", len(paths), paths)
		}
	default:
		t.Fatal("batch must publish exactly one invalidation set; got none")
	}
	select {
	case extra := <-sub:
		t.Fatalf("batch published a SECOND time (%v) — per-record publish = torn visibility", extra)
	default:
	}

	// State applied: a == "hello", b exists.
	f, err := fs.Open("a")
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	buf := make([]byte, 5)
	n, err := f.ReadAt(buf, 0) // a 5-byte read of a 5-byte file may return io.EOF with n==5
	if err != nil && err != io.EOF {
		t.Fatalf("read a: %v", err)
	}
	_ = f.Close()
	if string(buf[:n]) != "hello" {
		t.Fatalf("a = %q, want hello", buf[:n])
	}
	if _, err := fs.Lstat("b"); err != nil {
		t.Fatalf("b should exist after batch: %v", err)
	}
}

// TestApplyCreateIsIdempotentNoClobber: a redundant OpCreate for a path that ALREADY EXISTS
// must NOT replace it with an empty inode — O_CREAT without O_TRUNC never truncates. Regression
// for a silent-data-loss bug found via the handoff trace: a second mount re-opening a handed-off
// file with O_CREAT (its cache momentarily showed the file absent, so the kernel issued CREATE
// not OPEN) flushed an OpCreate that zeroed the first mount's data.
func TestApplyCreateIsIdempotentNoClobber(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	// Mount A creates app.db with content.
	if err := fs.ApplyBatch([]wal.Record{
		{Op: wal.OpCreate, Path: "app.db", Mode: 0o644},
		{Op: wal.OpWrite, Path: "app.db", Offset: 0, Data: []byte("AAAAAAAA")},
	}, ""); err != nil {
		t.Fatalf("A create+write: %v", err)
	}
	// Mount B (stale cache → kernel issues CREATE) flushes a redundant OpCreate for the SAME path.
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "app.db", Mode: 0o644}}, ""); err != nil {
		t.Fatalf("B redundant create: %v", err)
	}
	// A's content MUST survive.
	f, err := fs.Open("app.db")
	if err != nil {
		t.Fatalf("open app.db: %v", err)
	}
	buf := make([]byte, 8)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	_ = f.Close()
	if string(buf[:n]) != "AAAAAAAA" {
		t.Fatalf("redundant OpCreate CLOBBERED existing data: got %q (n=%d), want AAAAAAAA — silent data loss", buf[:n], n)
	}
}

// TestApplyCreateDoesNotDestroyDirectory: a bare OpCreate at a path that already exists as a
// DIRECTORY (or any other kind) must NOT replace it — that would silently destroy the whole
// subtree. Audit-found HIGH.
func TestApplyCreateDoesNotDestroyDirectory(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.ApplyBatch([]wal.Record{
		{Op: wal.OpMkdir, Path: "d", Mode: 0o755},
		{Op: wal.OpCreate, Path: "d/child", Mode: 0o644},
		{Op: wal.OpWrite, Path: "d/child", Offset: 0, Data: []byte("KEEP")},
	}, ""); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// A bare file-create AT the directory's path must be a no-op, not a clobber.
	if err := fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "d", Mode: 0o644}}, ""); err != nil {
		t.Fatalf("create-over-dir: %v", err)
	}
	fi, err := fs.Lstat("d")
	if err != nil || !fi.IsDir() {
		t.Fatalf("d must still be a directory after create-over-dir: fi=%v err=%v", fi, err)
	}
	f, err := fs.Open("d/child")
	if err != nil {
		t.Fatalf("child destroyed by create-over-dir: %v", err)
	}
	buf := make([]byte, 4)
	n, rerr := f.ReadAt(buf, 0)
	_ = f.Close()
	if rerr != nil && rerr != io.EOF {
		t.Fatal(rerr)
	}
	if string(buf[:n]) != "KEEP" {
		t.Fatalf("child content lost: %q, want KEEP", buf[:n])
	}
}
