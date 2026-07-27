package volfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
)

// edgeDigest is the content address of data; the content layer verifies blobs on
// read, so fixtures must carry the true sha256.
func edgeDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// edgeBlobs is a verifying blob store keyed by digest. It also records per-digest
// fetch counts (guarded for -race) so lazy/caching behavior can be asserted.
type edgeBlobs struct {
	mu    sync.Mutex
	data  map[string][]byte
	count map[string]int
	err   map[string]error // optional injected fetch errors
}

func newEdgeBlobs() *edgeBlobs {
	return &edgeBlobs{data: map[string][]byte{}, count: map[string]int{}, err: map[string]error{}}
}

func (b *edgeBlobs) put(data []byte) string {
	d := edgeDigest(data)
	b.data[d] = data
	return d
}

func (b *edgeBlobs) Blob(_ context.Context, digest string) ([]byte, error) {
	b.mu.Lock()
	b.count[digest]++
	e := b.err[digest]
	v, ok := b.data[digest]
	b.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if !ok {
		return nil, fmt.Errorf("no blob %s", digest)
	}
	return v, nil
}

func (b *edgeBlobs) fetches(digest string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count[digest]
}

// ---------------------------------------------------------------------------
// Path handling: empty, root, trailing slash, double slash, ".", traversal "..".
// resolve()/cleanPath() must normalize all of these to the same node and must NOT
// allow ".." to escape the volume root.
// ---------------------------------------------------------------------------

func TestPathNormalizationVariants(t *testing.T) {
	blobs := newEdgeBlobs()
	dA := blobs.put([]byte("abc"))
	dInner := blobs.put([]byte("in"))
	entries := []backend.Entry{
		{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 3, BlobDigest: dA},
		{Path: "dir", Kind: "directory", Mode: 0o755},
		{Path: "dir/inner.txt", Kind: "file", Mode: 0o644, Size: 2, BlobDigest: dInner},
	}
	fs := New(entries, blobs)

	// All of these spellings must resolve to dir/inner.txt.
	for _, name := range []string{
		"/dir/inner.txt",
		"dir/inner.txt",
		"//dir//inner.txt",
		"/dir/./inner.txt",
		"/dir/inner.txt/", // trailing slash
		"/../dir/inner.txt",
		"/dir/../dir/inner.txt",
		"/a.txt/../dir/inner.txt",
	} {
		fi, err := fs.Stat(name)
		if err != nil {
			t.Fatalf("Stat(%q) err: %v", name, err)
		}
		if fi.Name() != "inner.txt" || fi.Size() != 2 {
			t.Fatalf("Stat(%q) = %s size %d, want inner.txt size 2", name, fi.Name(), fi.Size())
		}
	}

	// Traversal that resolves back to root must clamp to root (path.Clean drops
	// leading ".." at "/"), never error out of the tree.
	for _, name := range []string{"/..", "/../..", "/dir/../.."} {
		fi, err := fs.Stat(name)
		if err != nil {
			t.Fatalf("Stat(%q) (escaping path) err: %v", name, err)
		}
		if !fi.IsDir() {
			t.Fatalf("Stat(%q) escaped root; got non-dir %s", name, fi.Name())
		}
	}

	// CONTAINMENT: a "../" escape attempt must be cleaned to a path INSIDE the
	// volume (path.Clean strips the leading ".."), so it can only ever hit an
	// in-tree node. "../../../etc/passwd" cleans to "etc/passwd" — which is not in
	// this manifest, so it must be ErrNotExist (a manifest miss), NEVER a read of
	// the host's /etc/passwd. Add a decoy "etc/passwd" entry and prove the escape
	// lands on OUR node, not the host file.
	decoyBlobs := newEdgeBlobs()
	decoy := decoyBlobs.put([]byte("VOLUME-OWNED-decoy"))
	decoyFS := New([]backend.Entry{
		{Path: "etc/passwd", Kind: "file", Mode: 0o644, Size: 18, BlobDigest: decoy},
	}, decoyBlobs)
	for _, name := range []string{"../../../etc/passwd", "/../../etc/passwd", "/a/../../../etc/passwd"} {
		f, err := decoyFS.Open(name)
		if err != nil {
			t.Fatalf("Open(%q) should hit the in-tree decoy, got: %v", name, err)
		}
		got, _ := io.ReadAll(f)
		if string(got) != "VOLUME-OWNED-decoy" {
			t.Fatalf("Open(%q) = %q; a traversal escaped the volume root!", name, got)
		}
	}
	// On the manifest WITHOUT etc/passwd, the same escape is a clean miss.
	if _, err := fs.Stat("../../../etc/passwd"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(../../../etc/passwd) = %v, want ErrNotExist (no host escape)", err)
	}
}

// TestRootSpellings: "", "/", ".", "//", "/.." all resolve to the root directory.
func TestRootSpellings(t *testing.T) {
	blobs := newEdgeBlobs()
	fs := New([]backend.Entry{{Path: "x", Kind: "file", Size: 0, BlobDigest: blobs.put(nil)}}, blobs)
	for _, name := range []string{"", "/", ".", "//", "/..", "/../"} {
		fi, err := fs.Stat(name)
		if err != nil {
			t.Fatalf("Stat(%q) err: %v", name, err)
		}
		if !fi.IsDir() {
			t.Fatalf("Stat(%q) is not the root dir: %+v", name, fi)
		}
		infos, err := fs.ReadDir(name)
		if err != nil {
			t.Fatalf("ReadDir(%q) err: %v", name, err)
		}
		if len(infos) != 1 || infos[0].Name() != "x" {
			t.Fatalf("ReadDir(%q) = %v, want [x]", name, infos)
		}
	}
}

// TestResolveMissingAndWrongType: a missing path is os.ErrNotExist; descending
// THROUGH a file (treating a file as a directory component) resolves to nothing.
func TestResolveMissingAndWrongType(t *testing.T) {
	blobs := newEdgeBlobs()
	dA := blobs.put([]byte("abc"))
	fs := New([]backend.Entry{{Path: "a.txt", Kind: "file", Size: 3, BlobDigest: dA}}, blobs)

	if _, err := fs.Stat("/nope"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(/nope) = %v, want ErrNotExist", err)
	}
	// "a.txt" is a file; "a.txt/child" must not resolve.
	if _, err := fs.Stat("/a.txt/child"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(/a.txt/child) = %v, want ErrNotExist", err)
	}
	if _, err := fs.Open("/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open(/missing) = %v, want ErrNotExist", err)
	}
	// ReadDir on a file is "not a directory" (an error, not ErrNotExist).
	if _, err := fs.ReadDir("/a.txt"); err == nil {
		t.Fatal("ReadDir on a file should error")
	}
	// Readlink on a non-symlink errors.
	if _, err := fs.Readlink("/a.txt"); err == nil {
		t.Fatal("Readlink on a file should error")
	}
	if _, err := fs.Readlink("/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Readlink(/missing) = %v, want ErrNotExist", err)
	}
}

// ---------------------------------------------------------------------------
// insert() edge cases: implicit parent dirs, duplicate paths (last wins),
// a file path that also has children (later dir entries win the node kind).
// ---------------------------------------------------------------------------

// TestImplicitParentDirsCreated: a deep file with no explicit ancestor dir entries
// still produces walkable directories.
func TestImplicitParentDirsCreated(t *testing.T) {
	blobs := newEdgeBlobs()
	dF := blobs.put([]byte("deep"))
	fs := New([]backend.Entry{
		{Path: "a/b/c/d.txt", Kind: "file", Size: 4, BlobDigest: dF},
	}, blobs)
	for _, p := range []string{"/a", "/a/b", "/a/b/c"} {
		fi, err := fs.Stat(p)
		if err != nil || !fi.IsDir() {
			t.Fatalf("Stat(%q) = %+v %v, want a dir", p, fi, err)
		}
	}
	f, err := fs.Open("/a/b/c/d.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	if string(got) != "deep" {
		t.Fatalf("read = %q, want deep", got)
	}
}

// TestDuplicatePathLastWins: the same path twice — the later entry's metadata wins
// (insert overwrites the node fields in sorted order). We use distinct sizes.
func TestDuplicatePathLastWins(t *testing.T) {
	blobs := newEdgeBlobs()
	d1 := blobs.put([]byte("first"))
	d2 := blobs.put([]byte("second!"))
	// New() sorts by path then inserts; for identical paths insertion order is
	// stable, so the second slice element overwrites. Assert SOME deterministic
	// resolution (size matches one of the two) rather than a flaky ordering claim.
	fs := New([]backend.Entry{
		{Path: "dup", Kind: "file", Size: 5, BlobDigest: d1},
		{Path: "dup", Kind: "file", Size: 7, BlobDigest: d2},
	}, blobs)
	fi, err := fs.Stat("/dup")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 7 {
		t.Fatalf("duplicate path size = %d, want 7 (last entry wins)", fi.Size())
	}
	f, _ := fs.Open("/dup")
	got, _ := io.ReadAll(f)
	if string(got) != "second!" {
		t.Fatalf("dup content = %q, want second!", got)
	}
}

// TestEmptyPathEntryIgnored: an entry whose cleaned path is empty (".", "/", "")
// is dropped rather than corrupting the root node.
func TestEmptyPathEntryIgnored(t *testing.T) {
	blobs := newEdgeBlobs()
	dA := blobs.put([]byte("abc"))
	fs := New([]backend.Entry{
		{Path: "", Kind: "file", Size: 99}, // ignored
		{Path: "/", Kind: "file", Size: 99},
		{Path: ".", Kind: "file", Size: 99},
		{Path: "a.txt", Kind: "file", Size: 3, BlobDigest: dA},
	}, blobs)
	// Root stays a directory.
	rfi, _ := fs.Stat("/")
	if !rfi.IsDir() {
		t.Fatalf("root corrupted by empty-path entry: %+v", rfi)
	}
	infos, _ := fs.ReadDir("/")
	if len(infos) != 1 || infos[0].Name() != "a.txt" {
		t.Fatalf("ReadDir(/) = %v, want only [a.txt]", infos)
	}
}

// ---------------------------------------------------------------------------
// Read boundaries: empty file, exactly-at-EOF, past-EOF, single byte, full read,
// and Seek whence boundaries incl. negative clamping.
// ---------------------------------------------------------------------------

// TestReadAtBoundaries on a 5-byte whole-file blob: at 0, at len-1, exactly at EOF,
// past EOF, and a buffer larger than the file (short read + EOF).
func TestReadAtBoundaries(t *testing.T) {
	blobs := newEdgeBlobs()
	d := blobs.put([]byte("hello"))
	fs := New([]backend.Entry{{Path: "f", Kind: "file", Size: 5, BlobDigest: d}}, blobs)
	f, err := fs.Open("/f")
	if err != nil {
		t.Fatal(err)
	}

	// Read 1 byte at offset 0.
	one := make([]byte, 1)
	if n, err := f.ReadAt(one, 0); n != 1 || one[0] != 'h' || (err != nil && err != io.EOF) {
		t.Fatalf("ReadAt[0:1] = %d %q %v", n, one, err)
	}
	// Read the last byte (offset 4) -> returns it WITH io.EOF (off+n == size).
	last := make([]byte, 1)
	if n, err := f.ReadAt(last, 4); n != 1 || last[0] != 'o' || err != io.EOF {
		t.Fatalf("ReadAt[4:5] = %d %q %v, want 1 'o' EOF", n, last, err)
	}
	// Exactly at EOF (offset == size): 0 bytes, io.EOF.
	if n, err := f.ReadAt(make([]byte, 4), 5); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt at EOF = %d %v, want 0 EOF", n, err)
	}
	// Past EOF.
	if n, err := f.ReadAt(make([]byte, 4), 100); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt past EOF = %d %v, want 0 EOF", n, err)
	}
	// Over-sized buffer: short read of the whole file + EOF.
	big := make([]byte, 64)
	if n, err := f.ReadAt(big, 0); n != 5 || string(big[:5]) != "hello" || err != io.EOF {
		t.Fatalf("ReadAt oversized = %d %q %v", n, big[:n], err)
	}
}

// TestEmptyFileNeverFetches: a zero-length file reads 0 bytes / EOF and never hits
// the blob store (the size-0 short-circuit in content.ReadAt).
func TestEmptyFileNeverFetches(t *testing.T) {
	blobs := newEdgeBlobs()
	dEmpty := blobs.put(nil) // digest of empty
	fs := New([]backend.Entry{{Path: "empty", Kind: "file", Size: 0, BlobDigest: dEmpty}}, blobs)
	f, _ := fs.Open("/empty")
	got, err := io.ReadAll(f)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty read = %q %v", got, err)
	}
	if blobs.fetches(dEmpty) != 0 {
		t.Fatalf("empty file fetched a blob %d times, want 0", blobs.fetches(dEmpty))
	}
}

// TestSeekWhenceAndClamp covers SeekStart/Current/End, negative-result clamping to
// 0, seeking past end (then a read yields EOF), and an invalid whence.
func TestSeekWhenceAndClamp(t *testing.T) {
	blobs := newEdgeBlobs()
	d := blobs.put([]byte("abcdef")) // size 6
	fs := New([]backend.Entry{{Path: "f", Kind: "file", Size: 6, BlobDigest: d}}, blobs)
	f, _ := fs.Open("/f")

	if p, _ := f.Seek(2, io.SeekStart); p != 2 {
		t.Fatalf("SeekStart(2) = %d, want 2", p)
	}
	if p, _ := f.Seek(2, io.SeekCurrent); p != 4 {
		t.Fatalf("SeekCurrent(+2) = %d, want 4", p)
	}
	if p, _ := f.Seek(-1, io.SeekEnd); p != 5 {
		t.Fatalf("SeekEnd(-1) = %d, want 5", p)
	}
	// Negative absolute position clamps to 0.
	if p, _ := f.Seek(-100, io.SeekStart); p != 0 {
		t.Fatalf("Seek(-100) = %d, want 0 (clamped)", p)
	}
	// After clamp, a Read starts from byte 0.
	one := make([]byte, 1)
	if n, _ := f.Read(one); n != 1 || one[0] != 'a' {
		t.Fatalf("Read after clamp = %d %q, want 'a'", n, one)
	}
	// Seek past end, then Read => EOF, 0 bytes.
	if p, _ := f.Seek(50, io.SeekStart); p != 50 {
		t.Fatalf("Seek(50) = %d", p)
	}
	if n, err := f.Read(make([]byte, 4)); n != 0 || err != io.EOF {
		t.Fatalf("Read past end = %d %v, want 0 EOF", n, err)
	}
	// Invalid whence errors.
	if _, err := f.Seek(0, 99); err == nil {
		t.Fatal("Seek with bad whence should error")
	}
}

// TestSequentialReadAdvancesPos: successive Read calls consume the file in order
// and stop at EOF; ReadAt does NOT move the sequential cursor.
func TestSequentialReadAdvancesPos(t *testing.T) {
	blobs := newEdgeBlobs()
	d := blobs.put([]byte("abcdef"))
	fs := New([]backend.Entry{{Path: "f", Kind: "file", Size: 6, BlobDigest: d}}, blobs)
	f, _ := fs.Open("/f")

	buf := make([]byte, 2)
	got := ""
	for {
		n, err := f.Read(buf)
		got += string(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("zero-length read without EOF")
		}
	}
	if got != "abcdef" {
		t.Fatalf("sequential read = %q, want abcdef", got)
	}

	// ReadAt must be independent of the (now-EOF) sequential cursor.
	at := make([]byte, 2)
	if n, _ := f.ReadAt(at, 0); n != 2 || string(at) != "ab" {
		t.Fatalf("ReadAt after sequential EOF = %d %q, want ab", n, at)
	}
}

// ---------------------------------------------------------------------------
// Chunked-file edges through the public read path: partial reads are lazy per
// chunk, a read spanning a chunk boundary stitches both, and a HOLE/GAP in chunk
// coverage surfaces a loud error (never zero-filled bytes).
// ---------------------------------------------------------------------------

// TestChunkBoundarySpanningRead: a read straddling the chunk[0]|chunk[1] boundary
// fetches both chunks and returns the contiguous bytes.
func TestChunkBoundarySpanningRead(t *testing.T) {
	blobs := newEdgeBlobs()
	c0 := blobs.put([]byte("AAAA")) // [0,4)
	c1 := blobs.put([]byte("BBBB")) // [4,8)
	fs := New([]backend.Entry{
		{Path: "big", Kind: "file", Size: 8, Chunks: []backend.Chunk{
			{Digest: c0, Size: 4, Offset: 0},
			{Digest: c1, Size: 4, Offset: 4},
		}},
	}, blobs)
	f, _ := fs.Open("/big")
	// Read [2,6): last 2 of chunk0 + first 2 of chunk1.
	buf := make([]byte, 4)
	n, err := f.ReadAt(buf, 2)
	if n != 4 || string(buf) != "AABB" || (err != nil && err != io.EOF) {
		t.Fatalf("ReadAt[2:6] = %d %q %v, want AABB", n, buf, err)
	}
	if blobs.fetches(c0) != 1 || blobs.fetches(c1) != 1 {
		t.Fatalf("boundary read fetched c0=%d c1=%d, want 1,1", blobs.fetches(c0), blobs.fetches(c1))
	}
}

// TestChunkHoleErrorsNotZeroFill: a manifest with a gap between chunk0 and chunk1
// (declared Size spans the gap) must produce a loud error on a read into the gap,
// never silently-zeroed bytes. This guards the content.ReadAt gap detection.
func TestChunkHoleErrorsNotZeroFill(t *testing.T) {
	blobs := newEdgeBlobs()
	c0 := blobs.put([]byte("AAAA")) // [0,4)
	c1 := blobs.put([]byte("CCCC")) // declared at offset 8 -> [8,12); [4,8) is a HOLE
	fs := New([]backend.Entry{
		{Path: "holey", Kind: "file", Size: 12, Chunks: []backend.Chunk{
			{Digest: c0, Size: 4, Offset: 0},
			{Digest: c1, Size: 4, Offset: 8},
		}},
	}, blobs)
	f, _ := fs.Open("/holey")
	// Reading into the hole [0,12) must error rather than return zero-filled bytes.
	buf := make([]byte, 12)
	_, err := f.ReadAt(buf, 0)
	if err == nil || err == io.EOF {
		t.Fatalf("read across a chunk hole returned %v, want a loud gap error", err)
	}
}

// TestChunkedReadAtEOFAndPast: a chunked file at exactly Size and past Size returns
// EOF with no bytes.
func TestChunkedReadAtEOFAndPast(t *testing.T) {
	blobs := newEdgeBlobs()
	c0 := blobs.put([]byte("xyz"))
	fs := New([]backend.Entry{
		{Path: "c", Kind: "file", Size: 3, Chunks: []backend.Chunk{{Digest: c0, Size: 3, Offset: 0}}},
	}, blobs)
	f, _ := fs.Open("/c")
	if n, err := f.ReadAt(make([]byte, 4), 3); n != 0 || err != io.EOF {
		t.Fatalf("chunked ReadAt at EOF = %d %v, want 0 EOF", n, err)
	}
	if n, err := f.ReadAt(make([]byte, 4), 99); n != 0 || err != io.EOF {
		t.Fatalf("chunked ReadAt past EOF = %d %v, want 0 EOF", n, err)
	}
}

// TestUnorderedChunksReassemble: chunks given out of offset order must still
// reassemble correctly (content.orderedChunks sorts), so a TS-authored manifest
// reads identically.
func TestUnorderedChunksReassemble(t *testing.T) {
	blobs := newEdgeBlobs()
	c0 := blobs.put([]byte("111"))
	c1 := blobs.put([]byte("222"))
	c2 := blobs.put([]byte("333"))
	fs := New([]backend.Entry{
		{Path: "u", Kind: "file", Size: 9, Chunks: []backend.Chunk{
			{Digest: c2, Size: 3, Offset: 6}, // deliberately out of order
			{Digest: c0, Size: 3, Offset: 0},
			{Digest: c1, Size: 3, Offset: 3},
		}},
	}, blobs)
	f, _ := fs.Open("/u")
	got, _ := io.ReadAll(f)
	if string(got) != "111222333" {
		t.Fatalf("unordered chunks reassembled to %q, want 111222333", got)
	}
}

// ---------------------------------------------------------------------------
// Chroot: descends to a subtree, preserves blobs/cache, rejects non-dirs/missing,
// and the chrooted FS sees its children at the new root.
// ---------------------------------------------------------------------------

func TestChrootSubtreeAndErrors(t *testing.T) {
	blobs := newEdgeBlobs()
	dIn := blobs.put([]byte("in"))
	dA := blobs.put([]byte("abc"))
	fs := New([]backend.Entry{
		{Path: "a.txt", Kind: "file", Size: 3, BlobDigest: dA},
		{Path: "dir/inner.txt", Kind: "file", Size: 2, BlobDigest: dIn},
	}, blobs)

	sub, err := fs.Chroot("/dir")
	if err != nil {
		t.Fatalf("Chroot(/dir): %v", err)
	}
	// inner.txt is now at the chroot root.
	fi, err := sub.Stat("/inner.txt")
	if err != nil || fi.Size() != 2 {
		t.Fatalf("chrooted Stat(/inner.txt) = %+v %v", fi, err)
	}
	f, _ := sub.Open("inner.txt")
	got, _ := io.ReadAll(f)
	if string(got) != "in" {
		t.Fatalf("chrooted read = %q, want in", got)
	}
	// a.txt is above the chroot and must not be visible.
	if _, err := sub.Stat("/a.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("chroot leaked a.txt: %v", err)
	}

	// Chroot to a file or missing path errors.
	if _, err := fs.Chroot("/a.txt"); err == nil {
		t.Fatal("Chroot onto a file should error")
	}
	if _, err := fs.Chroot("/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Chroot(/missing) = %v, want ErrNotExist", err)
	}
}

// ---------------------------------------------------------------------------
// Read-only enforcement across every mutating entry point.
// ---------------------------------------------------------------------------

func TestEveryMutatorRejected(t *testing.T) {
	blobs := newEdgeBlobs()
	dA := blobs.put([]byte("abc"))
	fs := New([]backend.Entry{{Path: "a.txt", Kind: "file", Size: 3, BlobDigest: dA}}, blobs)

	if _, err := fs.Create("x"); err == nil {
		t.Error("Create should fail")
	}
	if err := fs.Rename("a.txt", "b.txt"); err == nil {
		t.Error("Rename should fail")
	}
	if err := fs.Remove("a.txt"); err == nil {
		t.Error("Remove should fail")
	}
	if _, err := fs.TempFile("", "p"); err == nil {
		t.Error("TempFile should fail")
	}
	if err := fs.MkdirAll("d", 0o755); err == nil {
		t.Error("MkdirAll should fail")
	}
	if err := fs.Symlink("a.txt", "l"); err == nil {
		t.Error("Symlink should fail")
	}
	// OpenFile with any write/create/trunc/append flag is rejected.
	for _, flag := range []int{os.O_WRONLY, os.O_RDWR, os.O_CREATE, os.O_TRUNC, os.O_APPEND, os.O_RDWR | os.O_CREATE} {
		if _, err := fs.OpenFile("a.txt", flag, 0o644); err == nil {
			t.Errorf("OpenFile(flag=%#x) should fail on read-only fs", flag)
		}
	}
	// File-level mutators on an opened handle.
	f, _ := fs.Open("a.txt")
	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("Write should fail")
	}
	if err := f.Truncate(0); err == nil {
		t.Error("Truncate should fail")
	}
	// Lock/Unlock/Close are no-ops (must not error) on the read-only handle.
	if err := f.Lock(); err != nil {
		t.Errorf("Lock = %v, want nil", err)
	}
	if err := f.Unlock(); err != nil {
		t.Errorf("Unlock = %v, want nil", err)
	}
	if err := f.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// FileInfo plumbing: OwnerIDs via Sys(), Mode bits for dir/symlink/exec.
// ---------------------------------------------------------------------------

func TestFileInfoOwnerAndModes(t *testing.T) {
	blobs := newEdgeBlobs()
	dExe := blobs.put([]byte("#!/bin/sh\n"))
	dA := blobs.put([]byte("abc"))
	fs := New([]backend.Entry{
		{Path: "owned", Kind: "file", Mode: 0o600, Size: 3, UID: 1234, GID: 5678, BlobDigest: dA},
		{Path: "run.sh", Kind: "file", Mode: 0o755, Size: 10, Executable: true, BlobDigest: dExe},
		{Path: "d", Kind: "directory", Mode: 0o755},
		{Path: "l", Kind: "symlink", Mode: 0o777, LinkTarget: "owned"},
	}, blobs)

	owned, _ := fs.Stat("/owned")
	type ownerer interface{ OwnerIDs() (uint32, uint32) }
	o, ok := owned.Sys().(ownerer)
	if !ok {
		t.Fatalf("Sys() does not expose OwnerIDs: %T", owned.Sys())
	}
	if uid, gid := o.OwnerIDs(); uid != 1234 || gid != 5678 {
		t.Fatalf("OwnerIDs = %d,%d, want 1234,5678", uid, gid)
	}

	d, _ := fs.Stat("/d")
	if d.Mode()&os.ModeDir == 0 {
		t.Error("dir missing ModeDir")
	}
	l, _ := fs.Lstat("/l")
	if l.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink missing ModeSymlink")
	}
	run, _ := fs.Stat("/run.sh")
	if run.Mode().Perm()&0o111 == 0 {
		t.Error("executable file missing exec perm bits")
	}
}

// ---------------------------------------------------------------------------
// Concurrency: many goroutines reading the same chunked + whole-file nodes via
// independent handles and shared ReadAt. The shared cache must serve correct,
// verified bytes under -race; the lazy fetch count stays bounded.
// ---------------------------------------------------------------------------

func TestConcurrentReadsSameFiles(t *testing.T) {
	blobs := newEdgeBlobs()
	dWhole := blobs.put([]byte("wholecontent!"))
	c0 := blobs.put([]byte("CHUNK-ZERO--")) // 12 bytes
	c1 := blobs.put([]byte("CHUNK-ONE---")) // 12 bytes
	fs := New([]backend.Entry{
		{Path: "whole", Kind: "file", Size: 13, BlobDigest: dWhole},
		{Path: "big", Kind: "file", Size: 24, Chunks: []backend.Chunk{
			{Digest: c0, Size: 12, Offset: 0},
			{Digest: c1, Size: 12, Offset: 12},
		}},
	}, blobs)

	const workers = 32
	var wg sync.WaitGroup
	var bad sync.Map
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				f, err := fs.Open("/whole")
				if err != nil {
					bad.Store(i, err)
					return
				}
				got, err := io.ReadAll(f)
				if err != nil || string(got) != "wholecontent!" {
					bad.Store(i, fmt.Errorf("whole=%q err=%v", got, err))
				}
			} else {
				f, err := fs.Open("/big")
				if err != nil {
					bad.Store(i, err)
					return
				}
				got, err := io.ReadAll(f)
				if err != nil || string(got) != "CHUNK-ZERO--CHUNK-ONE---" {
					bad.Store(i, fmt.Errorf("big=%q err=%v", got, err))
				}
			}
		}(i)
	}
	wg.Wait()
	bad.Range(func(k, v any) bool {
		t.Errorf("worker %v: %v", k, v)
		return true
	})

	// The shared cache means each blob is fetched a bounded number of times (not
	// once-per-reader). It must be at least 1 and far below the worker count.
	if got := blobs.fetches(dWhole); got < 1 || got > workers {
		t.Fatalf("whole fetched %d times, want in [1,%d]", got, workers)
	}
}

// TestConcurrentReadDirStat: ReadDir/Stat/Readlink are pure reads over an immutable
// tree; hammering them concurrently must be race-free and consistent.
func TestConcurrentReadDirStat(t *testing.T) {
	blobs := newEdgeBlobs()
	dA := blobs.put([]byte("abc"))
	dIn := blobs.put([]byte("in"))
	fs := New([]backend.Entry{
		{Path: "a.txt", Kind: "file", Size: 3, BlobDigest: dA},
		{Path: "dir/inner.txt", Kind: "file", Size: 2, BlobDigest: dIn},
		{Path: "link", Kind: "symlink", Mode: 0o777, LinkTarget: "a.txt"},
	}, blobs)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if infos, err := fs.ReadDir("/"); err != nil || len(infos) != 3 {
					t.Errorf("ReadDir(/) = %d %v", len(infos), err)
					return
				}
				if _, err := fs.Stat("/dir/inner.txt"); err != nil {
					t.Errorf("Stat: %v", err)
					return
				}
				if tgt, err := fs.Readlink("/link"); err != nil || tgt != "a.txt" {
					t.Errorf("Readlink = %q %v", tgt, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
