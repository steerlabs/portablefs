package clientcore

// End-to-end proof for round 18g: the authority's resident dirty-block bound,
// seen by an application through a real mount.
//
// Everything in this file is the production chain — a real managed workfs
// authority, a real fsproto server over a real socket, a real clientcore
// Volume with a real write-back engine. The only thing the test does that
// production does not is LOWER the bound, so it is reached in milliseconds
// instead of after 2 GiB.
//
// What it pins is the answer the application receives. Before 18g the chain
// was: workfs refuses ErrDirtyRSSCapacity (definite) -> coordinate.go has no
// capacity arm and falls through to its EAGAIN catch-all (transient) ->
// writeback/flush.go retries EAGAIN forever -> the watermark never moves ->
// the no-progress watchdog EIOs the whole mount. The application was never
// told it had run out of space; it was told, eventually, that its filesystem
// had broken, which is a different and much less useful thing.

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// serveCoreBoundedFS is serveCoreServer with the authority's working FS handed
// back, so the test can move the dirty-block bound the way a real authority's
// VCS_DIRTY_RSS_MAX_MB does at startup.
func serveCoreBoundedFS(t *testing.T) (string, *workfs.FS) {
	t.Helper()
	fs := newManagedTestFS(t, testBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := fsproto.NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), fs
}

// TestAuthorityDirtyBoundReachesTheApplicationAsENOSPC drives a write-back
// mount into the authority's dirty-block bound and asserts the application is
// told, in the vocabulary POSIX reserves for it, that the volume is full.
func TestAuthorityDirtyBoundReachesTheApplicationAsENOSPC(t *testing.T) {
	addr, fs := serveCoreBoundedFS(t)
	v := dialCore(t, addr, Options{Owner: "dirty-bound", WALDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A subdirectory, exactly as the live repro writes: a top-level file's
	// parent is the un-delegable volume root, so only this shape exercises the
	// write-back flush path the bug lives on.
	if _, st := v.Mkdir(ctx, "sub", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir sub: %d", st)
	}
	attr, st := v.Create(ctx, "sub/rss.bin", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	state := NewNodeState(attr.Ino, attr.Ino != 0)

	// Healthy first: the volume is nowhere near any bound and the write is
	// durable on the authority. Without this the test could pass on a mount
	// that never worked at all.
	if n, wst := v.WriteAppend(ctx, "sub/rss.bin", state, 0, []byte("healthy")); wst != fsproto.OK || n != 7 {
		t.Fatalf("healthy append: n=%d st=%d", n, wst)
	}
	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatalf("healthy flush: %v", err)
	}

	// Now the bound is where the volume already is: every further write leaf
	// reserves at least one whole block, so the next flush is refused for
	// capacity and nothing this mount can do will change that — no fold runs
	// for a live generation.
	fs.SetDirtyRSSMax(fs.DirtyBlockBytes() + 1)

	// The write is ACCEPTED locally (that is what a write-back mount is for);
	// the refusal happens when the batch reaches the authority.
	if n, wst := v.WriteAppend(ctx, "sub/rss.bin", state, 0, []byte("over-bound")); wst != fsproto.OK || n != 10 {
		t.Fatalf("locally admitted append: n=%d st=%d", n, wst)
	}

	err := v.FlushToAuthority(ctx)
	if err == nil {
		t.Fatal("flush past the authority's dirty bound succeeded; the fixture never refuses")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("flush past the dirty bound was still retrying at the deadline: "+
			"the mount is holding a definite capacity refusal as a transient (%v)", err)
	}

	// THE CONTRACT. Not "the flush failed" — the application asked for space
	// and must be told there is none, by name.
	if wst := writeStatusAfter(t, v, state); wst != fsproto.ENOSPC {
		t.Fatalf("write past the authority's dirty bound answered status %d, want ENOSPC (%d). "+
			"EIO here is the mount telling an application its filesystem broke when in "+
			"fact it merely ran out of room", wst, fsproto.ENOSPC)
	}
}

// writeStatusAfter reports the status a fresh application write receives now.
func writeStatusAfter(t *testing.T, v *Volume, state *NodeState) Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, st := v.WriteAppend(ctx, "sub/rss.bin", state, 0, []byte("after"))
	return st
}
