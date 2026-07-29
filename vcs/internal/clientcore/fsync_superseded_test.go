package clientcore

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestFsyncErrorsOnFencedSession pins m1: fsync with acknowledged-but-
// unshippable state on a fenced mount session must return an error (EIO to
// the frontend), never success. A fenced generation's records never reach
// the authority; fsync always means authority-durable, so reporting success
// would be a false guarantee. The stream parks durably and recovers on the
// next attach instead.
func TestFsyncErrorsOnFencedSession(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:  "M",
		WALDir: t.TempDir(),
	})

	// A subtree path so the engine delegates and acknowledges locally (a
	// top-level file runs write-through and would just ESTALE immediately).
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	// Hold the file open so the engine's idle-release never hands the "d"
	// delegation back before the fence (a real fsync fires on an open fd).
	if st := v.RegisterOpened("d/f", n); st != fsproto.OK {
		t.Fatalf("open: %d", st)
	}
	if _, st := v.Write(ctx, "d/f", n, 0, []byte("FIRST")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	if err := v.FlushToAuthority(ctx); err != nil { // establish the stream watermark
		t.Fatalf("initial flush: %v", err)
	}

	// The mount session is fenced (as a supersession/lease loss would):
	// every later flush is rejected ESTALE and the stream parks terminally.
	v.Client().ExpireSession()

	// The engine still holds the delegation, so this write is acknowledged
	// locally — it can never ship under the fenced generation.
	if _, st := v.Write(ctx, "d/f", n, 5, []byte("MORE")); st != fsproto.OK {
		t.Fatalf("second write: %d", st)
	}

	// The KEY assertion: fsync must surface the failure (sticky), never a
	// false durability claim.
	if st := v.FsyncPath("d/f"); st != fsproto.EIO {
		t.Fatalf("fsync on a fenced session must EIO, got %d", st)
	}
	if st := v.FsyncPath("d/f"); st != fsproto.EIO {
		t.Fatalf("fsync must stay EIO while the tail is parked, got %d", st)
	}
	if recs, _ := v.WriteBackPending(); recs == 0 {
		t.Fatal("the unshippable tail must remain visible as pending write-back debt")
	}
}
