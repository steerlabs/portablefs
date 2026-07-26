package workfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// digestOf is the content address of b — the content layer verifies blobs against
// their address on read, so a backed-file fixture must use the real digest.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type fakeBlobs struct{ data map[string][]byte }

func (b *fakeBlobs) Blob(_ context.Context, d string) ([]byte, error) {
	v, ok := b.data[d]
	if !ok {
		return nil, fmt.Errorf("no blob %s", d)
	}
	return v, nil
}

func newFS(t *testing.T, entries []backend.Entry, blobs *fakeBlobs) (*FS, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wal.log")
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(entries, blobs, w)
	if err != nil {
		t.Fatal(err)
	}
	return fs, p
}

func readFile(t *testing.T, fs *FS, name string) string {
	t.Helper()
	f, err := fs.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestCreateWriteRead(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.Create("new.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got := readFile(t, fs, "new.txt"); got != "hello world" {
		t.Fatalf("read = %q, want %q", got, "hello world")
	}
	fi, err := fs.Stat("new.txt")
	if err != nil || fi.Size() != 11 || fi.IsDir() {
		t.Fatalf("stat = %+v %v", fi, err)
	}
}

func TestNameMax255ForIntroducedNames(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})

	create := func(name string) error {
		f, err := fs.Create(name)
		if err != nil {
			return err
		}
		return f.Close()
	}
	assertNameTooLong := func(op string, err error) {
		t.Helper()
		if !errors.Is(err, syscall.ENAMETOOLONG) {
			t.Fatalf("%s error = %v, want ENAMETOOLONG", op, err)
		}
	}

	maxName := strings.Repeat("a", nameMax)
	if err := create(maxName); err != nil {
		t.Fatalf("create 255-byte name: %v", err)
	}
	if _, err := fs.Stat(maxName); err != nil {
		t.Fatalf("stat 255-byte name: %v", err)
	}

	tooLong := strings.Repeat("b", nameMax+1)
	assertNameTooLong("create 256-byte name", create(tooLong))
	assertNameTooLong("create with 256-byte parent component", create(tooLong+"/leaf"))
	assertNameTooLong("mkdir 256-byte name", fs.MkdirAll(tooLong, 0o755))
	assertNameTooLong("symlink 256-byte name", fs.Symlink("target", tooLong))

	if err := create("rename-src"); err != nil {
		t.Fatalf("create rename source: %v", err)
	}
	assertNameTooLong("rename target 256-byte name", fs.Rename("rename-src", tooLong))
	if _, err := fs.Stat("rename-src"); err != nil {
		t.Fatalf("rename source should remain after rejected rename: %v", err)
	}

	assertNameTooLong("batched create 256-byte name", fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: tooLong, Mode: 0o644}}, ""))
}

func TestModifyBackedFilePartial(t *testing.T) {
	da := digestOf([]byte("ABCDEFGH"))
	blobs := &fakeBlobs{data: map[string][]byte{da: []byte("ABCDEFGH")}}
	entries := []backend.Entry{{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 8, BlobDigest: da}}
	fs, _ := newFS(t, entries, blobs)

	if got := readFile(t, fs, "a.txt"); got != "ABCDEFGH" {
		t.Fatalf("backed read = %q", got)
	}
	f, err := fs.OpenFile("a.txt", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("xyz")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got := readFile(t, fs, "a.txt"); got != "ABxyzFGH" {
		t.Fatalf("after partial overwrite = %q, want ABxyzFGH (unwritten bytes preserved)", got)
	}
}

func TestChownSurvivesReplayAndIsSnapshotted(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{}}
	p := filepath.Join(t.TempDir(), "wal.log")
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, blobs, w)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := fs.Create("owned.txt")
	_, _ = f.Write([]byte("hi"))
	_ = f.Close()
	if err := fs.Chown("owned.txt", 1000, 2000); err != nil {
		t.Fatal(err)
	}

	owner := func(fs *FS, name string) (uint32, uint32) {
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
	if u, g := owner(fs, "owned.txt"); u != 1000 || g != 2000 {
		t.Fatalf("stat owner = %d:%d, want 1000:2000", u, g)
	}

	// The snapshot carries ownership, so the checkpoint commits it to the manifest.
	var found bool
	for _, e := range fs.Snapshot().Entries {
		if e.Path == "owned.txt" {
			found = true
			if e.UID != 1000 || e.GID != 2000 {
				t.Fatalf("snapshot owner = %d:%d, want 1000:2000", e.UID, e.GID)
			}
		}
	}
	if !found {
		t.Fatal("owned.txt missing from snapshot")
	}

	// And it survives a crash (WAL replay rebuilds the ownership).
	_ = w.Close()
	w2, _ := wal.Open(p)
	fs2, err := New(nil, blobs, w2)
	if err != nil {
		t.Fatal(err)
	}
	if u, g := owner(fs2, "owned.txt"); u != 1000 || g != 2000 {
		t.Fatalf("owner after replay = %d:%d, want 1000:2000 (chown lost on crash recovery)", u, g)
	}
}

func TestRenameGuardsPreventClobber(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	mk := func(name, data string) {
		f, err := fs.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := f.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	if err := fs.MkdirAll("a", 0o755); err != nil {
		t.Fatal(err)
	}
	mk("a/x", "ax")
	if err := fs.MkdirAll("b", 0o755); err != nil {
		t.Fatal(err)
	}
	mk("b/y", "by")
	if err := fs.MkdirAll("empty", 0o755); err != nil {
		t.Fatal(err)
	}
	mk("f", "F")
	mk("g", "G")

	// Renaming a directory onto a NON-EMPTY directory must fail without clobbering it.
	if err := fs.Rename("a", "b"); err == nil {
		t.Fatal("rename dir onto a non-empty dir should fail (ENOTEMPTY)")
	}
	if got := readFile(t, fs, "b/y"); got != "by" {
		t.Fatalf("destination clobbered: b/y = %q, want by", got)
	}

	// Onto an EMPTY directory it succeeds.
	if err := fs.Rename("a", "empty"); err != nil {
		t.Fatalf("rename dir onto an empty dir should succeed: %v", err)
	}
	if got := readFile(t, fs, "empty/x"); got != "ax" {
		t.Fatalf("moved content = %q, want ax", got)
	}

	// Type mismatches are rejected.
	if err := fs.Rename("f", "b"); err == nil {
		t.Fatal("rename file onto a directory should fail (EISDIR)")
	}
	if err := fs.Rename("b", "g"); err == nil {
		t.Fatal("rename directory onto a file should fail (ENOTDIR)")
	}

	// Overwriting a regular file with another is valid POSIX.
	if err := fs.Rename("f", "g"); err != nil {
		t.Fatalf("file-over-file rename should succeed: %v", err)
	}
	if got := readFile(t, fs, "g"); got != "F" {
		t.Fatalf("g = %q, want F (overwritten)", got)
	}
	if _, err := fs.Stat("f"); err == nil {
		t.Fatal("source f should be gone after rename")
	}

	// A directory cannot be moved into its own subtree.
	if err := fs.MkdirAll("p/q", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.Rename("p", "p/q/r"); err == nil {
		t.Fatal("rename dir into its own subtree should fail (EINVAL)")
	}
}

// TestRejectedMutationDoesNotBrickReplay is the regression for the append-before-
// apply hazard: a mutation the apply guard rejects (e.g. "mv a b" onto a non-empty
// b) is still durably journalled before the guard runs. Re-opening the WAL must
// replay cleanly (skipping the rejected phantom) rather than re-reject it and fail
// construction — which would make the volume permanently unmountable.
func TestRejectedMutationDoesNotBrickReplay(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wal.log")
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.MkdirAll("a", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkdirAll("b", 0o755); err != nil {
		t.Fatal(err)
	}
	f, _ := fs.Create("b/keep")
	_, _ = f.Write([]byte("x"))
	_ = f.Close()

	// This rename is rejected (b is non-empty) — but it is appended to the WAL first.
	if err := fs.Rename("a", "b"); err == nil {
		t.Fatal("rename onto a non-empty dir should be rejected")
	}
	if w.Count() == 0 {
		t.Fatal("precondition: the rejected rename should have been journalled")
	}
	_ = w.Close()

	// Re-open: replay must NOT fail on the persisted-but-rejected rename.
	w2, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	fs2, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w2)
	if err != nil {
		t.Fatalf("replay bricked startup on a rejected mutation: %v", err)
	}
	// State is intact: a still exists, b still holds its file, the bad rename no-op'd.
	if _, err := fs2.Stat("a"); err != nil {
		t.Fatalf("a should still exist after replay: %v", err)
	}
	if got := readFile(t, fs2, "b/keep"); got != "x" {
		t.Fatalf("b/keep = %q, want x (destination must be intact)", got)
	}
}

func TestDirSymlinkRenameRemoveTruncate(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	if err := fs.MkdirAll("a/b/c", 0o755); err != nil {
		t.Fatal(err)
	}
	f, _ := fs.Create("a/b/c/f.txt")
	_, _ = f.Write([]byte("12345"))
	_ = f.Close()

	if err := fs.Symlink("a/b/c/f.txt", "link"); err != nil {
		t.Fatal(err)
	}
	if tgt, _ := fs.Readlink("link"); tgt != "a/b/c/f.txt" {
		t.Fatalf("readlink = %q", tgt)
	}
	if err := fs.Rename("a/b/c/f.txt", "a/b/c/g.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat("a/b/c/f.txt"); err == nil {
		t.Fatal("old name should not exist after rename")
	}
	if got := readFile(t, fs, "a/b/c/g.txt"); got != "12345" {
		t.Fatalf("renamed content = %q", got)
	}
	f2, _ := fs.OpenFile("a/b/c/g.txt", os.O_RDWR, 0)
	if err := f2.Truncate(3); err != nil {
		t.Fatal(err)
	}
	_ = f2.Close()
	if got := readFile(t, fs, "a/b/c/g.txt"); got != "123" {
		t.Fatalf("after truncate(3) = %q", got)
	}
	if err := fs.Remove("a/b/c/g.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat("a/b/c/g.txt"); err == nil {
		t.Fatal("removed file should not exist")
	}
	if err := fs.Remove("a/b"); err == nil {
		t.Fatal("removing a non-empty directory should fail")
	}
}

func TestCrashRecoveryViaWALReplay(t *testing.T) {
	da := digestOf([]byte("ABCDEFGH"))
	blobs := &fakeBlobs{data: map[string][]byte{da: []byte("ABCDEFGH")}}
	entries := []backend.Entry{{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 8, BlobDigest: da}}
	p := filepath.Join(t.TempDir(), "wal.log")

	w, _ := wal.Open(p)
	fs, err := New(entries, blobs, w)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := fs.OpenFile("a.txt", os.O_RDWR, 0)
	_, _ = f.Seek(2, io.SeekStart)
	_, _ = f.Write([]byte("xyz"))
	_ = f.Close()
	nf, _ := fs.Create("new.txt")
	_, _ = nf.Write([]byte("brand new"))
	_ = nf.Close()
	_ = fs.MkdirAll("d", 0o755)
	_ = w.Close()

	// "crash": rebuild from the same committed base + the same WAL.
	w2, _ := wal.Open(p)
	fs2, err := New(entries, blobs, w2)
	if err != nil {
		t.Fatalf("recovery New: %v", err)
	}
	if got := readFile(t, fs2, "a.txt"); got != "ABxyzFGH" {
		t.Fatalf("recovered a.txt = %q, want ABxyzFGH", got)
	}
	if got := readFile(t, fs2, "new.txt"); got != "brand new" {
		t.Fatalf("recovered new.txt = %q", got)
	}
	if fi, err := fs2.Stat("d"); err != nil || !fi.IsDir() {
		t.Fatalf("recovered dir d = %+v %v", fi, err)
	}
}

func TestSnapshotReflectsDirtyAndClean(t *testing.T) {
	blobs := &fakeBlobs{data: map[string][]byte{"d-a": []byte("AAA")}}
	entries := []backend.Entry{{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 3, BlobDigest: "d-a"}}
	fs, _ := newFS(t, entries, blobs)

	f, _ := fs.Create("b.txt")
	_, _ = f.Write([]byte("bb"))
	_ = f.Close()

	byPath := map[string]SnapshotEntry{}
	for _, e := range fs.Snapshot().Entries {
		byPath[e.Path] = e
	}
	a, ok := byPath["a.txt"]
	if !ok || a.Dirty || a.Source.BlobDigest != "d-a" {
		t.Fatalf("a.txt snapshot = %+v (want clean, backed by d-a)", a)
	}
	b, ok := byPath["b.txt"]
	if !ok || !b.Dirty {
		t.Fatalf("b.txt snapshot = %+v (want dirty)", b)
	}
	if full, err := fs.MaterializeFull(b); err != nil || string(full) != "bb" {
		t.Fatalf("b.txt full = %q (err %v), want bb", full, err)
	}
}
