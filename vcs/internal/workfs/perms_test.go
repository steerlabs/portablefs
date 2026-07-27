package workfs

import (
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// TestChmodChtimesPersistAndReplay: chmod/chtimes take effect, are captured in the
// snapshot (so a checkpoint persists them), and survive a crash via WAL replay.
func TestChmodChtimesPersistAndReplay(t *testing.T) {
	fs, walPath := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.Create("s.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("#!/bin/sh"))
	_ = f.Close()

	if err := fs.Chmod("s.sh", 0o755); err != nil {
		t.Fatal(err)
	}
	mt := time.UnixMilli(1700000000000)
	if err := fs.Chtimes("s.sh", mt, mt); err != nil {
		t.Fatal(err)
	}

	fi, _ := fs.Stat("s.sh")
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %o, want 755", fi.Mode().Perm())
	}
	if fi.ModTime().UnixMilli() != mt.UnixMilli() {
		t.Fatalf("mtime = %d, want %d", fi.ModTime().UnixMilli(), mt.UnixMilli())
	}

	for _, e := range fs.Snapshot().Entries {
		if e.Path == "s.sh" {
			if e.Mode != 0o755 {
				t.Fatalf("snapshot mode = %o, want 755", e.Mode)
			}
			if e.MtimeMs != mt.UnixMilli() {
				t.Fatalf("snapshot mtime = %d, want %d", e.MtimeMs, mt.UnixMilli())
			}
		}
	}

	// Crash recovery: rebuild from the WAL.
	w2, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	fs2, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w2)
	if err != nil {
		t.Fatal(err)
	}
	if fi2, _ := fs2.Stat("s.sh"); fi2.Mode().Perm() != 0o755 {
		t.Fatalf("recovered mode = %o, want 755", fi2.Mode().Perm())
	}
}

func assertUnixMode(t *testing.T, fs *FS, name string, want uint32) {
	t.Helper()
	fi, err := fs.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if got := modeToUnix(fi.Mode()); got != want {
		t.Fatalf("%s mode = %04o, want %04o", name, got, want)
	}
}

func backendEntriesFromSnapshot(snap *Snapshot) []backend.Entry {
	out := make([]backend.Entry, 0, len(snap.Entries))
	for _, e := range snap.Entries {
		out = append(out, backend.Entry{
			Path:            e.Path,
			Kind:            e.Kind,
			Mode:            e.Mode,
			Size:            e.Size,
			MtimeMs:         e.MtimeMs,
			CtimeMs:         e.CtimeMs,
			AtimeMs:         e.AtimeMs,
			UID:             e.UID,
			GID:             e.GID,
			Ino:             e.Ino,
			BlobDigest:      e.Source.BlobDigest,
			BlobSize:        e.Source.BlobSize,
			BlobCompression: e.Source.BlobCompression,
			BlobPacked:      e.Source.BlobPacked,
			Chunks:          e.Source.Chunks,
			LinkTarget:      e.LinkTarget,
		})
	}
	return out
}

func TestChmodSpecialBitsSurviveSnapshotReconstruct(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.Create("special.sh")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	const want uint32 = 0o7755
	if err := fs.Chmod("special.sh", modeFromUnix(want)); err != nil {
		t.Fatal(err)
	}
	assertUnixMode(t, fs, "special.sh", want)

	snap := fs.Snapshot()
	var found bool
	for _, e := range snap.Entries {
		if e.Path == "special.sh" {
			found = true
			if e.Mode != want {
				t.Fatalf("snapshot mode = %04o, want %04o", e.Mode, want)
			}
		}
	}
	if !found {
		t.Fatal("special.sh missing from snapshot")
	}

	fs2, _ := newFS(t, backendEntriesFromSnapshot(snap), &fakeBlobs{data: map[string][]byte{}})
	assertUnixMode(t, fs2, "special.sh", want)
}

func TestChmod000RoundTrips(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.Create("zero")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if err := fs.Chmod("zero", modeFromUnix(0o7777)); err != nil {
		t.Fatal(err)
	}
	assertUnixMode(t, fs, "zero", 0o7777)

	if err := fs.Chmod("zero", modeFromUnix(0)); err != nil {
		t.Fatal(err)
	}
	assertUnixMode(t, fs, "zero", 0)

	snap := fs.Snapshot()
	for _, e := range snap.Entries {
		if e.Path == "zero" && e.Mode != 0 {
			t.Fatalf("snapshot mode = %04o, want 0000", e.Mode)
		}
	}

	fs2, _ := newFS(t, backendEntriesFromSnapshot(snap), &fakeBlobs{data: map[string][]byte{}})
	assertUnixMode(t, fs2, "zero", 0)
}

// TestConcurrentChownChgrpNoLostUpdate: a concurrent `chown uid` (gid unchanged) and
// `chgrp gid` (uid unchanged) on one file must end at BOTH new values. If the read of
// the current owner and the write are not atomic, both ops read the (0,0) baseline and
// the later writer clobbers the other's field — a lost update.
func TestConcurrentChownChgrpNoLostUpdate(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	owner := func(name string) (uint32, uint32) {
		fi, err := fs.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		o, ok := fi.Sys().(interface{ OwnerIDs() (uint32, uint32) })
		if !ok {
			t.Fatal("FileInfo does not expose ownership")
		}
		return o.OwnerIDs()
	}
	// Repeat to give any race many chances to surface under -race.
	for i := 0; i < 50; i++ {
		f, _ := fs.Create("f")
		_ = f.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = fs.Chown("f", 1000, -1) }() // set uid, leave gid
		go func() { defer wg.Done(); _ = fs.Chown("f", -1, 2000) }() // set gid, leave uid
		wg.Wait()
		if u, g := owner("f"); u != 1000 || g != 2000 {
			t.Fatalf("iter %d: owner = %d:%d, want 1000:2000 (a concurrent update was lost)", i, u, g)
		}
		_ = fs.Remove("f")
	}
}
