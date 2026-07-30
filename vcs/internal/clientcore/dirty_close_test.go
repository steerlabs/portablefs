package clientcore

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func TestLastCloseDoesNotImplyAuthorityBarrier(t *testing.T) {
	addr := serveCore(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "dirty-close",
		WALDir: t.TempDir(),
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })
	ctx := context.Background()
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened(context.Background(), "d/f", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}
	if st := v.FsyncHandle("d/f", n); st != fsproto.OK {
		t.Fatalf("initial fsync: %d", st)
	}

	v.Client().ExpireSession()
	if _, st := v.Write(ctx, "d/f", n, 0, []byte("park me")); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}
	if st := v.CloseHandle("d/f", n); st != fsproto.OK {
		t.Fatalf("close = %d, want OK under standard filesystem semantics", st)
	}
	if n.IsOpen() {
		t.Fatal("close did not retire the file descriptor")
	}
	if records, _ := v.WriteBackPending(); records == 0 {
		t.Fatal("close dropped the locally accepted unshipped tail")
	}
}

func TestFsyncThenCloseDoesNotRunSecondBarrier(t *testing.T) {
	addr := serveCore(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "clean-close",
		WALDir: t.TempDir(),
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })
	ctx := context.Background()
	a, st := v.Create(ctx, "f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened(context.Background(), "f", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}
	if st := v.FsyncHandle("f", n); st != fsproto.OK {
		t.Fatalf("fsync: %d", st)
	}

	// close(2) is not a durability barrier. This definite fence after a
	// successful fsync must not make close fail or issue another barrier.
	v.Client().ExpireSession()
	if st := v.CloseHandle("f", n); st != fsproto.OK {
		t.Fatalf("close ran an unnecessary barrier: %d", st)
	}
}
