package workfs

import (
	"os"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/content"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// TestCheckpointPreservesRacingWrite proves the checkpoint-atomicity fix: a write
// that lands after the snapshot but before the WAL compaction survives in both
// the live view and a crash recovery. Without the per-file epoch guard +
// prefix-compaction it would be dropped (MarkClean would clear it, a full reset
// would erase its WAL record) — silently losing an acknowledged write.
func TestCheckpointPreservesRacingWrite(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{
		"dv1": []byte("v1"),
		"dAA": []byte("AA"),
	}}
	entries := []backend.Entry{{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 2, BlobDigest: "dv1"}}
	fs, walPath := newFS(t, entries, blobs)

	overwrite(t, fs, "a.txt", "AA") // pre-checkpoint edit
	snap := fs.Snapshot()           // the checkpoint captures "AA"
	overwrite(t, fs, "a.txt", "BB") // a write races the in-flight checkpoint

	// Finalize the checkpoint as if "AA" committed; the racing "BB" must survive.
	fs.MarkClean(snap, "a.txt", content.Source{BlobDigest: "dAA", BlobSize: 2, Size: 2})
	if err := fs.CompactWAL(snap); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, fs, "a.txt"); got != "BB" {
		t.Fatalf("live a.txt = %q, want BB (racing write was dropped!)", got)
	}

	// Crash recovery: the committed manifest ("AA") + the compacted WAL must
	// reconstruct "BB" — the racing write is durable.
	w2, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	committed := []backend.Entry{{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 2, BlobDigest: "dAA"}}
	fs2, err := New(committed, blobs, w2)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, fs2, "a.txt"); got != "BB" {
		t.Fatalf("recovered a.txt = %q, want BB (racing write lost on crash!)", got)
	}
}

func overwrite(t *testing.T, fs *FS, name, data string) {
	t.Helper()
	f, err := fs.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := f.Write([]byte(data)); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}
