package checkpoint

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/authority"
	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

func readAll(t *testing.T, fs *workfs.FS, name string) []byte {
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
	return b
}

// TestRealCheckpointRoundTrip writes through the working filesystem, checkpoints
// to the REAL volume-api (which validates the tree hash and stores the blobs in
// the bucket), then rebuilds a fresh working tree from the new head and verifies
// the writes are durable. This is the end-to-end proof that the VCS write path
// commits state the server accepts.
//
// Gated: set VOLUME_API_URL (+ VOLUME_API_TOKEN) to run.
func TestRealCheckpointRoundTrip(t *testing.T) {
	url := os.Getenv("VOLUME_API_URL")
	if url == "" {
		t.Skip("set VOLUME_API_URL (+ VOLUME_API_TOKEN) to run")
	}
	cli := backend.NewClient(url, os.Getenv("VOLUME_API_TOKEN"))
	ctx := context.Background()

	volID, err := cli.CreateVolume(ctx, "vcs_write_e2e_"+time.Now().Format("20060102150405"), "main")
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

	// Write a variety of things through the working FS.
	hf, _ := fs.Create("hello.txt")
	_, _ = hf.Write([]byte("written by vcs\n"))
	_ = hf.Close()
	if err := fs.MkdirAll("sub", 0o755); err != nil {
		t.Fatal(err)
	}
	df, _ := fs.Create("sub/deep.txt")
	_, _ = df.Write([]byte("deep"))
	_ = df.Close()
	if err := fs.Symlink("hello.txt", "link"); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), 100_000)
	bf, _ := fs.Create("big.bin")
	_, _ = bf.Write(big)
	_ = bf.Close()

	// Acquire the write authority, then checkpoint -> real commit (server validates the tree hash).
	auth, err := authority.Acquire(ctx, cli, volID, "main", "vcs-e2e", 0)
	if err != nil {
		t.Fatalf("acquire authority: %v", err)
	}
	defer func() { _ = auth.Release(ctx) }()
	head, err := Run(ctx, fs, auth)
	if err != nil {
		t.Fatalf("checkpoint (real commit): %v", err)
	}
	t.Logf("committed head=%s", head)
	if head == "" {
		t.Fatal("expected a new head commit")
	}

	// Fresh working tree from the new head -> writes must be durable.
	entries2, err := cli.Manifest(ctx, volID, "main")
	if err != nil {
		t.Fatal(err)
	}
	w2, _ := wal.Open(filepath.Join(t.TempDir(), "wal2.log"))
	fs2, err := workfs.New(entries2, cli, w2)
	if err != nil {
		t.Fatal(err)
	}

	if got := string(readAll(t, fs2, "hello.txt")); got != "written by vcs\n" {
		t.Fatalf("hello.txt = %q", got)
	}
	if got := string(readAll(t, fs2, "sub/deep.txt")); got != "deep" {
		t.Fatalf("sub/deep.txt = %q", got)
	}
	if tgt, err := fs2.Readlink("link"); err != nil || tgt != "hello.txt" {
		t.Fatalf("readlink = %q %v", tgt, err)
	}
	if got := readAll(t, fs2, "big.bin"); !bytes.Equal(got, big) {
		t.Fatalf("big.bin mismatch: got %d bytes", len(got))
	}
}
