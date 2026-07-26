package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/volfs"
	nfsclient "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
)

// dg is the content address of data; the content layer verifies blobs on read.
func dg(data string) string {
	sum := sha256.Sum256([]byte(data))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type e2eBlobs struct{ data map[string][]byte }

func (b *e2eBlobs) Blob(_ context.Context, d string) ([]byte, error) {
	v, ok := b.data[d]
	if !ok {
		return nil, fmt.Errorf("no blob %s", d)
	}
	return v, nil
}

// TestE2EReadThroughNFSProtocol drives the real NFSv3 wire protocol end-to-end:
// it serves a manifest-backed volfs and reads it back via a userspace NFS client
// (DialMount -> Mount -> ReadDirPlus/Open/Read/Readlink). No kernel mount / sudo.
func TestE2EReadThroughNFSProtocol(t *testing.T) {
	exerciseNFSProtocol(t, rpc.AuthNull)
}

func TestE2EReadThroughNFSProtocolWithAuthSys(t *testing.T) {
	exerciseNFSProtocol(t, rpc.NewAuthUnix("portablefs-test", 501, 20).Auth())
}

func exerciseNFSProtocol(t *testing.T, auth rpc.Auth) {
	t.Helper()

	entries := []backend.Entry{
		{Path: "a.txt", Kind: "file", Mode: 0o644, Size: 3, BlobDigest: dg("abc")},
		{Path: "big.bin", Kind: "file", Mode: 0o644, Size: 6, Chunks: []backend.Chunk{
			{Digest: dg("xyz"), Size: 3, Offset: 0}, {Digest: dg("123"), Size: 3, Offset: 3},
		}},
		{Path: "nested", Kind: "directory", Mode: 0o755},
		{Path: "nested/deep.txt", Kind: "file", Mode: 0o644, Size: 4, BlobDigest: dg("deep")},
		{Path: "link", Kind: "symlink", Mode: 0o777, LinkTarget: "a.txt"},
	}
	blobs := &e2eBlobs{data: map[string][]byte{
		dg("abc"): []byte("abc"), dg("xyz"): []byte("xyz"), dg("123"): []byte("123"), dg("deep"): []byte("deep"),
	}}
	fs := volfs.New(entries, blobs)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, ln, fs) }()

	// Connect directly to the listener port (go-nfs serves mount+nfs on one
	// port with no portmap), the way go-nfs's own interop tests do.
	c, err := rpc.DialTCP(ln.Addr().Network(), ln.Addr().(*net.TCPAddr).String(), false)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer c.Close()
	mounter := nfsclient.Mount{Client: c}
	target, err := mounter.Mount("/", auth)
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}

	ents, err := target.ReadDirPlus("/")
	if err != nil {
		t.Fatalf("ReadDirPlus: %v", err)
	}
	var names []string
	for _, e := range ents {
		if e.FileName == "." || e.FileName == ".." {
			continue
		}
		names = append(names, e.FileName)
	}
	sort.Strings(names)
	if fmt.Sprint(names) != "[a.txt big.bin link nested]" {
		t.Fatalf("ReadDirPlus(/) = %v", names)
	}

	readAll := func(path string) string {
		f, err := target.Open(path)
		if err != nil {
			t.Fatalf("Open %s: %v", path, err)
		}
		defer f.Close()
		buf := make([]byte, 64)
		n, _ := f.Read(buf)
		return string(buf[:n])
	}
	if got := readAll("a.txt"); got != "abc" {
		t.Fatalf("a.txt over NFS = %q, want abc", got)
	}
	if got := readAll("nested/deep.txt"); got != "deep" {
		t.Fatalf("nested/deep.txt over NFS = %q, want deep", got)
	}

	bf, err := target.Open("big.bin")
	if err != nil {
		t.Fatalf("Open big.bin: %v", err)
	}
	p := make([]byte, 3)
	if n, _ := bf.ReadAt(p, 0); string(p[:n]) != "xyz" {
		t.Fatalf("big.bin[0:3] over NFS = %q, want xyz", p[:n])
	}
	if n, _ := bf.ReadAt(p, 3); string(p[:n]) != "123" {
		t.Fatalf("big.bin[3:6] over NFS = %q, want 123", p[:n])
	}
	_ = bf.Close()

	lf, err := target.Open("link")
	if err != nil {
		t.Fatalf("Open link: %v", err)
	}
	tgt, err := lf.Readlink()
	_ = lf.Close()
	if err != nil || tgt != "a.txt" {
		t.Fatalf("Readlink over NFS = %q %v, want a.txt", tgt, err)
	}
}
