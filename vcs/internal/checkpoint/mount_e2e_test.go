package checkpoint

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	nfsclient "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"

	"github.com/trendup-ai/portablefs/vcs/internal/authority"
	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/server"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// TestRealWritableMountE2E is the capstone for the write path: write a file
// through the LIVE NFS server (userspace client) into a real-backed working
// tree, checkpoint to the real volume-api, then rebuild a fresh tree from the
// new head and confirm the write is durable. This exercises the whole writable
// mount: NFS write -> working tree -> WAL -> checkpoint -> commit -> bucket.
//
// Gated: set VOLUME_API_URL (+ VOLUME_API_TOKEN).
func TestRealWritableMountE2E(t *testing.T) {
	url := os.Getenv("VOLUME_API_URL")
	if url == "" {
		t.Skip("set VOLUME_API_URL (+ VOLUME_API_TOKEN) to run")
	}
	cli := backend.NewClient(url, os.Getenv("VOLUME_API_TOKEN"))
	ctx := context.Background()

	volID, err := cli.CreateVolume(ctx, "vcs_mount_e2e_"+time.Now().Format("20060102150405"), "main")
	if err != nil {
		t.Fatalf("create volume: %v", err)
	}
	t.Logf("volume %s", volID)

	entries, err := cli.Manifest(ctx, volID, "main")
	if err != nil {
		t.Fatal(err)
	}
	w, _ := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	fs, err := workfs.New(entries, cli, w)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	go func() { _ = server.Serve(sctx, ln, fs) }()

	c, err := rpc.DialTCP(ln.Addr().Network(), ln.Addr().(*net.TCPAddr).String(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	target, err := (&nfsclient.Mount{Client: c}).Mount("/", rpc.AuthNull)
	if err != nil {
		t.Fatal(err)
	}

	// Write through the live NFS server.
	if _, err := target.Mkdir("work", 0o755); err != nil {
		t.Fatalf("Mkdir over NFS: %v", err)
	}
	wf, err := target.OpenFile("work/agent.txt", 0o644)
	if err != nil {
		t.Fatalf("OpenFile over NFS: %v", err)
	}
	const payload = "agent wrote this via the mount"
	if _, err := wf.Write([]byte(payload)); err != nil {
		t.Fatalf("Write over NFS: %v", err)
	}
	_ = wf.Close()

	// Acquire authority + checkpoint (as the auto-loop in cmd/vcs would).
	auth, err := authority.Acquire(ctx, cli, volID, "main", "mount-e2e", 0)
	if err != nil {
		t.Fatalf("acquire authority: %v", err)
	}
	defer func() { _ = auth.Release(ctx) }()
	head, err := Run(ctx, fs, auth)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	t.Logf("checkpoint head=%s", head)

	// Fresh tree from the new head -> the NFS-written file is durable.
	entries2, err := cli.Manifest(ctx, volID, "main")
	if err != nil {
		t.Fatal(err)
	}
	w2, _ := wal.Open(filepath.Join(t.TempDir(), "wal2.log"))
	fs2, err := workfs.New(entries2, cli, w2)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readAll(t, fs2, "work/agent.txt")); got != payload {
		t.Fatalf("durable read = %q, want %q", got, payload)
	}
}
