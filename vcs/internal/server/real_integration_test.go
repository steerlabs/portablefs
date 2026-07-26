package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"testing"

	nfsclient "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/volfs"
)

// TestRealVolumeOverNFS verifies the whole stack against a real volume-api +
// Railway-bucket backend: fetch the real manifest, serve it, and read files
// (including a chunked >8MB file reassembled from real chunk blobs) over NFS.
//
// Gated: set VOLUME_API_URL, VOLUME_API_TOKEN, VCS_E2E_VOLUME_ID (and optionally
// VCS_E2E_BIG_SHA) to run; otherwise skipped.
func TestRealVolumeOverNFS(t *testing.T) {
	url := os.Getenv("VOLUME_API_URL")
	volID := os.Getenv("VCS_E2E_VOLUME_ID")
	if url == "" || volID == "" {
		t.Skip("set VOLUME_API_URL, VOLUME_API_TOKEN, VCS_E2E_VOLUME_ID to run")
	}
	client := backend.NewClient(url, os.Getenv("VOLUME_API_TOKEN"))
	entries, err := client.Manifest(context.Background(), volID, "main")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	t.Logf("real manifest: %d entries", len(entries))
	fs := volfs.New(entries, client)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, ln, fs) }()

	c, err := rpc.DialTCP(ln.Addr().Network(), ln.Addr().(*net.TCPAddr).String(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target, err := (&nfsclient.Mount{Client: c}).Mount("/", rpc.AuthNull)
	if err != nil {
		t.Fatal(err)
	}

	hf, err := target.Open("hello.txt")
	if err != nil {
		t.Fatalf("Open hello.txt: %v", err)
	}
	hb, _ := io.ReadAll(hf)
	_ = hf.Close()
	if string(hb) != "hello vcs\n" {
		t.Fatalf("hello.txt over NFS = %q, want %q", hb, "hello vcs\n")
	}
	t.Logf("hello.txt read over NFS from real volume: %q", hb)

	bf, err := target.Open("big.bin")
	if err != nil {
		t.Fatalf("Open big.bin: %v", err)
	}
	bb, _ := io.ReadAll(bf)
	_ = bf.Close()
	sum := hex.EncodeToString(sha256Sum(bb))
	t.Logf("big.bin (chunked) read over NFS: %d bytes, sha256=%s", len(bb), sum)
	if want := os.Getenv("VCS_E2E_BIG_SHA"); want != "" && sum != want {
		t.Fatalf("big.bin sha256 = %s, want %s", sum, want)
	}

	lf, err := target.Open("link")
	if err != nil {
		t.Fatalf("Open link: %v", err)
	}
	tgt, err := lf.Readlink()
	_ = lf.Close()
	if err != nil || tgt != "hello.txt" {
		t.Fatalf("Readlink(link) = %q %v, want hello.txt", tgt, err)
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
