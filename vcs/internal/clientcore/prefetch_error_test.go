package clientcore

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestPrefetchProgressSurfacesTerminalError pins the m5 prefetchTree cleanup: a readdir failure must
// be surfaced in the TERMINAL (Done) PrefetchProgress, not swallowed. The old code set Err per
// directory but overwrote it with a bare `Done: true` at the end, so a caller polling for Done could
// never tell a fully-walked tree from one that stopped on an error.
func TestPrefetchProgressSurfacesTerminalError(t *testing.T) {
	fs := newManagedTestFS(t, testBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := fsproto.NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()

	v := dialCoreNoCleanup(t, ln.Addr().String(), Options{})
	t.Cleanup(func() { _ = v.Close() })

	// Stop the authority: the existing connection drops and reconnects fail, so prefetch's root
	// readdir errors.
	cancel()
	_ = ln.Close()
	time.Sleep(50 * time.Millisecond)

	v.prefetchTree(10, 4)

	p := v.PrefetchProgress()
	if !p.Done {
		t.Fatalf("prefetch must report Done: %+v", p)
	}
	if p.Err == "" {
		t.Fatal("terminal prefetch progress must surface the readdir error, not swallow it")
	}
}
