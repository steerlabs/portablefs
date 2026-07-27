package volfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
)

// dg is the content address ("sha256:<hex>") of data — the content layer verifies
// blobs against their address on read, so test fixtures must use real digests.
func dg(data string) string {
	sum := sha256.Sum256([]byte(data))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	dgA     = dg("abc")
	dgC1    = dg("xyz")
	dgC2    = dg("123")
	dgIn    = dg("in")
	dgEmpty = dg("")
)

type fakeBlobs struct {
	data  map[string][]byte
	count map[string]int
}

func newFakeBlobs() *fakeBlobs {
	return &fakeBlobs{
		data: map[string][]byte{
			dgA: []byte("abc"), dgC1: []byte("xyz"), dgC2: []byte("123"), dgIn: []byte("in"),
		},
		count: map[string]int{},
	}
}

func (f *fakeBlobs) Blob(_ context.Context, digest string) ([]byte, error) {
	f.count[digest]++
	b, ok := f.data[digest]
	if !ok {
		return nil, fmt.Errorf("no blob %s", digest)
	}
	return b, nil
}

func sampleEntries() []backend.Entry {
	return []backend.Entry{
		{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 3, BlobDigest: dgA},
		{Path: "big.bin", Kind: "file", Mode: 0o644, Size: 6, Chunks: []backend.Chunk{
			{Digest: dgC1, Size: 3, Offset: 0}, {Digest: dgC2, Size: 3, Offset: 3},
		}},
		{Path: "dir", Kind: "directory", Mode: 0o755},
		{Path: "dir/inner.txt", Kind: "file", Mode: 0o644, Size: 2, BlobDigest: dgIn},
		{Path: "link", Kind: "symlink", Mode: 0o777, LinkTarget: "a.txt"},
		{Path: "empty.txt", Kind: "file", Mode: 0o644, Size: 0, BlobDigest: dgEmpty},
	}
}

func TestReadDirAndStat(t *testing.T) {
	fs := New(sampleEntries(), newFakeBlobs())
	infos, err := fs.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0)
	for _, fi := range infos {
		got = append(got, fi.Name())
	}
	want := []string{"a.txt", "big.bin", "dir", "empty.txt", "link"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("ReadDir(/) = %v, want %v", got, want)
	}
	fi, err := fs.Stat("/a.txt")
	if err != nil || fi.Size() != 3 || fi.IsDir() {
		t.Fatalf("Stat a.txt = %+v %v", fi, err)
	}
	di, _ := fs.Stat("/dir")
	if !di.IsDir() {
		t.Fatalf("dir not a dir: %+v", di)
	}
	sub, err := fs.ReadDir("/dir")
	if err != nil || len(sub) != 1 || sub[0].Name() != "inner.txt" {
		t.Fatalf("ReadDir(/dir) = %v %v", sub, err)
	}
}

func TestReadWholeFileCachedOnce(t *testing.T) {
	blobs := newFakeBlobs()
	fs := New(sampleEntries(), blobs)
	for i := 0; i < 3; i++ {
		f, err := fs.Open("/a.txt")
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "abc" {
			t.Fatalf("read %d = %q, want abc", i, b)
		}
	}
	if blobs.count[dgA] != 1 {
		t.Fatalf("d-a fetched %d times, want 1 (cache)", blobs.count[dgA])
	}
}

func TestChunkedFileLazyPerChunk(t *testing.T) {
	blobs := newFakeBlobs()
	fs := New(sampleEntries(), blobs)
	f, err := fs.Open("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	// read only the first 3 bytes -> only chunk 1 fetched
	buf := make([]byte, 3)
	n, err := f.ReadAt(buf, 0)
	if n != 3 || string(buf) != "xyz" || (err != nil && err != io.EOF) {
		t.Fatalf("ReadAt[0:3] = %d %q %v", n, buf, err)
	}
	if blobs.count[dgC1] != 1 || blobs.count[dgC2] != 0 {
		t.Fatalf("after partial read: c1=%d c2=%d, want 1,0", blobs.count[dgC1], blobs.count[dgC2])
	}
	// read the second half -> chunk 2 fetched
	n, err = f.ReadAt(buf, 3)
	if n != 3 || string(buf) != "123" || (err != nil && err != io.EOF) {
		t.Fatalf("ReadAt[3:6] = %d %q %v", n, buf, err)
	}
	if blobs.count[dgC2] != 1 {
		t.Fatalf("c2 fetched %d times, want 1", blobs.count[dgC2])
	}
	// full sequential read concatenates
	f2, _ := fs.Open("/big.bin")
	all, _ := io.ReadAll(f2)
	if string(all) != "xyz123" {
		t.Fatalf("full read = %q, want xyz123", all)
	}
}

func TestSymlinkEmptyAndReadOnly(t *testing.T) {
	blobs := newFakeBlobs()
	fs := New(sampleEntries(), blobs)
	target, err := fs.Readlink("/link")
	if err != nil || target != "a.txt" {
		t.Fatalf("Readlink = %q %v", target, err)
	}
	// empty file reads zero bytes and never fetches a blob
	ef, _ := fs.Open("/empty.txt")
	b, err := io.ReadAll(ef)
	if err != nil || len(b) != 0 {
		t.Fatalf("empty read = %q %v", b, err)
	}
	if blobs.count[dgEmpty] != 0 {
		t.Fatalf("empty file fetched a blob %d times, want 0", blobs.count[dgEmpty])
	}
	// writes are rejected
	if _, err := fs.Create("/new.txt"); err == nil {
		t.Fatal("Create should fail on read-only fs")
	}
	wf, _ := fs.Open("/a.txt")
	if _, err := wf.Write([]byte("x")); err == nil {
		t.Fatal("Write should fail on read-only fs")
	}
}
