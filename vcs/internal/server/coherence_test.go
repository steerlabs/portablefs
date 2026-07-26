package server

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	nfsclient "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

func mountClient(t *testing.T, addr string) *nfsclient.Target {
	t.Helper()
	c, err := rpc.DialTCP("tcp", addr, false)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	target, err := (&nfsclient.Mount{Client: c}).Mount("/", rpc.AuthNull)
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	return target
}

func writeNFS(t *testing.T, target *nfsclient.Target, path, data string) {
	t.Helper()
	f, err := target.OpenFile(path, 0o644)
	if err != nil {
		t.Fatalf("OpenFile %s: %v", path, err)
	}
	if _, err := f.Write([]byte(data)); err != nil {
		t.Fatalf("Write %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close %s: %v", path, err)
	}
}

func readNFS(t *testing.T, target *nfsclient.Target, path string) string {
	t.Helper()
	f, err := target.Open(path)
	if err != nil {
		t.Fatalf("Open %s: %v", path, err)
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// TestMultiClientCoherence mounts the SAME VCS authority from two NFS clients and
// checks that each sees the other's writes (read-after-write across mounts). The
// single-authority model makes coherence a local property of the shared tree.
func TestMultiClientCoherence(t *testing.T) {
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
	addr := ln.Addr().(*net.TCPAddr).String()

	a := mountClient(t, addr)
	b := mountClient(t, addr)

	// A writes -> B sees it.
	writeNFS(t, a, "from-a.txt", "hello from A")
	if got := readNFS(t, b, "from-a.txt"); got != "hello from A" {
		t.Fatalf("client B read %q, want 'hello from A'", got)
	}

	// B writes -> A sees it.
	writeNFS(t, b, "from-b.txt", "hello from B")
	if got := readNFS(t, a, "from-b.txt"); got != "hello from B" {
		t.Fatalf("client A read %q, want 'hello from B'", got)
	}

	// A creates a dir + nested file -> B sees the nested file.
	if _, err := a.Mkdir("shared", 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writeNFS(t, a, "shared/note.txt", "nested by A")
	if got := readNFS(t, b, "shared/note.txt"); got != "nested by A" {
		t.Fatalf("client B read nested %q, want 'nested by A'", got)
	}
}
