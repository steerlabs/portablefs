package server

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	nfsclient "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

type nopBlobs struct{}

func (nopBlobs) Blob(context.Context, string) ([]byte, error) {
	return nil, fmt.Errorf("no backed blobs in this test")
}

// TestE2EWriteThroughNFSProtocol drives the real NFSv3 write protocol end-to-end:
// it serves a writable working filesystem and creates a dir + file + writes bytes
// through a userspace NFS client (Mkdir/Create/Write), then reads them back over
// NFS. No kernel mount / sudo.
func TestE2EWriteThroughNFSProtocol(t *testing.T) {
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}

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

	if _, err := target.Mkdir("sub", 0o755); err != nil {
		t.Fatalf("Mkdir over NFS: %v", err)
	}
	wf, err := target.OpenFile("sub/hello.txt", 0o644)
	if err != nil {
		t.Fatalf("OpenFile(create) over NFS: %v", err)
	}
	if _, err := wf.Write([]byte("hello via nfs write")); err != nil {
		t.Fatalf("Write over NFS: %v", err)
	}
	if err := wf.Close(); err != nil {
		t.Fatalf("Close over NFS: %v", err)
	}

	// Read it back over NFS.
	rf, err := target.Open("sub/hello.txt")
	if err != nil {
		t.Fatalf("Open over NFS: %v", err)
	}
	buf := make([]byte, 64)
	n, _ := rf.Read(buf)
	_ = rf.Close()
	if string(buf[:n]) != "hello via nfs write" {
		t.Fatalf("read back over NFS = %q, want %q", string(buf[:n]), "hello via nfs write")
	}

	// The working FS reflects the NFS-written content.
	f, _ := fs.Open("sub/hello.txt")
	wn, _ := f.Read(buf)
	_ = f.Close()
	if string(buf[:wn]) != "hello via nfs write" {
		t.Fatalf("workfs read = %q", string(buf[:wn]))
	}
}
