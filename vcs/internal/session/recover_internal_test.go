package session

import (
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// TestRecoverRootMatchesFilenameHash: recoverRoot must find the TRUE checkout root by matching the
// WAL filename's hash, even when the first SURVIVING record sits deeper than the root (the original
// first write was compacted away) or targets the root dir itself. The naive
// governingSubtree(recs[0].Path) would mis-route and open the wrong (empty) WAL. Audit-found CRITICAL.
func TestRecoverRootMatchesFilenameHash(t *testing.T) {
	owner := "own"
	for _, tc := range []struct {
		name, root string
		firstPath  string
	}{
		{"deep-first-record", "proj", "proj/sub/deep.txt"}, // governingSubtree = "proj/sub" != root
		{"root-dir-op", "proj", "proj"},                    // a Mkdir/Chmod ON the root dir
		{"flat", "ws", "ws/app.db"},                        // the normal case still works
		{"volume-root", "", "top.txt"},                     // root == "" (volume root)
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			id := owner + "-" + hashHex(tc.root)
			walPath := filepath.Join(dir, "sess-"+id+".wal")
			w, err := wal.Open(walPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.AppendBuffered(wal.Record{Op: wal.OpWrite, Path: tc.firstPath, Data: []byte("x")}); err != nil {
				t.Fatal(err)
			}
			_ = w.CommitThrough(0)
			_ = w.Close()
			m := NewManager(nil, owner, dir, 0)
			got, ok := m.recoverRoot(walPath)
			if !ok || got.root != tc.root {
				t.Fatalf("recoverRoot(%s) = %q ok=%v, want %q", tc.name, got.root, ok, tc.root)
			}
		})
	}
}
