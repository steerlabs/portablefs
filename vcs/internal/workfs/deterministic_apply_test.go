package workfs

// Deterministic-apply coverage for the pieces both stores share. The managed
// store's park-always detach policy and record-timestamp determinism are
// covered by the managed_* suites and the fstransition differential; the
// WAL-backed store keeps its conditional-park semantics (its tests pin them),
// so only the store-neutral behaviors live here.

import (
	"errors"
	"os"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func TestLiveOrphanSourcesPinsBaseObjectsUntilReap(t *testing.T) {
	entries := []backend.Entry{
		{
			Path: "whole", Kind: "file", Mode: 0o644, Ino: 10, Size: 5,
			BlobDigest: "sha256:whole", BlobSize: 5,
		},
		{
			Path: "chunked", Kind: "file", Mode: 0o644, Ino: 20, Size: 8,
			Chunks: []backend.Chunk{
				{Digest: "sha256:chunk-a", Size: 4, Offset: 0},
				{Digest: "sha256:chunk-b", Size: 4, Offset: 4},
			},
		},
	}
	fs, _ := newFS(t, entries, &fakeBlobs{data: map[string][]byte{}})
	// Park through the explicit orphan transition (open-after-unlink): the
	// GC pin surface must retain every parked inode's committed source.
	if _, err := fs.Orphan("whole", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Orphan("chunked", ""); err != nil {
		t.Fatal(err)
	}
	if f, err := fs.Create("born"); err != nil {
		t.Fatal(err)
	} else {
		_ = f.Close()
	}
	if _, err := fs.Orphan("born", ""); err != nil {
		t.Fatal(err)
	}

	sources := fs.LiveOrphanSources()
	if len(sources) != 2 {
		t.Fatalf("live source count=%d, want 2 (born-only orphan omitted)", len(sources))
	}
	if sources[0].BlobDigest != "sha256:whole" {
		t.Fatalf("ino-ordered first source=%+v, want whole blob", sources[0])
	}
	if got := sources[1].Chunks; len(got) != 2 || got[0].Digest != "sha256:chunk-a" || got[1].Digest != "sha256:chunk-b" {
		t.Fatalf("chunk pins=%+v", got)
	}
	// Returned slices must be safe for a GC consumer to retain or mutate.
	sources[1].Chunks[0].Digest = "corrupted-copy"
	if got := fs.LiveOrphanSources()[1].Chunks[0].Digest; got != "sha256:chunk-a" {
		t.Fatalf("LiveOrphanSources aliased live chunk state: %q", got)
	}

	if err := fs.Reap(20, ""); err != nil {
		t.Fatal(err)
	}
	sources = fs.LiveOrphanSources()
	if len(sources) != 1 || sources[0].BlobDigest != "sha256:whole" {
		t.Fatalf("sources after chunked reap=%+v, want only whole", sources)
	}
}

func TestHardLinkAliasesSurviveReplay(t *testing.T) {
	fs, walPath := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	if f, err := fs.Create("a"); err != nil {
		t.Fatal(err)
	} else {
		_ = f.Close()
	}
	if err := fs.Link("a", "b"); err != nil {
		t.Fatal(err)
	}
	ino := inoAt(t, fs, "a")
	if got := inoAt(t, fs, "b"); got != ino {
		t.Fatalf("alias ino=%d, want %d", got, ino)
	}
	if err := fs.Link("a", "b"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("re-link over existing name: %v, want EEXIST", err)
	}
	if err := fileWAL(t, fs).Close(); err != nil {
		t.Fatal(err)
	}
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	if got := inoAt(t, replayed, "b"); got != ino {
		t.Fatalf("replayed alias ino=%d, want %d", got, ino)
	}
	fi, ferr := replayed.HandleInfo("a", 0)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if nlink := fi.Sys().(interface{ LinkCount() uint32 }).LinkCount(); nlink != 2 {
		t.Fatalf("replayed nlink=%d, want 2", nlink)
	}
}
