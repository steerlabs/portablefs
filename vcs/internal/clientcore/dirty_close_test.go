package clientcore

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func TestLastDirtyCloseSurfacesBarrierFailure(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{
		Owner:  "dirty-close",
		WALDir: t.TempDir(),
	})
	ctx := context.Background()
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened("d/f", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}
	if st := v.FsyncHandle("d/f", n); st != fsproto.OK {
		t.Fatalf("initial fsync: %d", st)
	}

	v.Client().ExpireSession()
	if _, st := v.Write(ctx, "d/f", n, 0, []byte("park me")); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}
	if st := v.CloseHandle("d/f", n); st != fsproto.EIO {
		t.Fatalf("last dirty close = %d, want EIO", st)
	}
	if n.IsOpen() {
		t.Fatal("a failed close barrier must still close the file descriptor")
	}
	if records, _ := v.WriteBackPending(); records == 0 {
		t.Fatal("failed close dropped the unshipped acknowledged tail")
	}
}

func TestSuccessfulFsyncClearsLastCloseBarrier(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{
		Owner:  "clean-close",
		WALDir: t.TempDir(),
	})
	ctx := context.Background()
	a, st := v.Create(ctx, "f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened("f", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}
	if st := v.FsyncHandle("f", n); st != fsproto.OK {
		t.Fatalf("fsync: %d", st)
	}

	// If close incorrectly ran a second barrier for a clean handle, this
	// definite fence would make it fail.
	v.Client().ExpireSession()
	if st := v.CloseHandle("f", n); st != fsproto.OK {
		t.Fatalf("clean last close ran an unnecessary barrier: %d", st)
	}
}
