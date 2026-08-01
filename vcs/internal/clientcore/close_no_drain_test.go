package clientcore

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// The §6 close contract, from the handle lane's side of the boundary:
// close(2) is bounded LOCAL bookkeeping. Admitted write-back belongs to the
// engine and drains in the background; fsync, synchronize, unmount and recall
// remain the only drain barriers. These tests pin the observable consequences
// so a future close-path "helpfully flushes" change fails loudly.

func openHandle(t *testing.T, v *Volume, path string) *NodeState {
	t.Helper()
	a, st := v.Getattr(context.Background(), path, nil)
	if st != fsproto.OK {
		t.Fatalf("getattr %s: %d", path, st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened(context.Background(), path, n); st != fsproto.OK {
		t.Fatalf("register open %s: %d", path, st)
	}
	return n
}

// TestCloseWithAdmittedBacklogIsBoundedAndKeepsTheTail: the close of a handle
// carrying an admitted, unshipped backlog returns promptly with the backlog
// intact. A close that drained would both take the drain's time and empty the
// pending tail.
func TestCloseWithAdmittedBacklogIsBoundedAndKeepsTheTail(t *testing.T) {
	addr := serveCore(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "close-backlog",
		WALDir: t.TempDir(),
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })
	ctx := context.Background()
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/big", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened(ctx, "d/big", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}
	if st := v.FsyncHandle("d/big", n); st != fsproto.OK {
		t.Fatalf("initial fsync: %d", st)
	}

	// Fence the session so nothing this handle admits can reach the
	// authority: everything written from here is unshipped backlog.
	v.Client().ExpireSession()
	payload := make([]byte, 32<<10)
	for i := 0; i < 8; i++ {
		if _, st := v.Write(ctx, "d/big", n, int64(i)*int64(len(payload)), payload); st != fsproto.OK {
			t.Fatalf("delegated write %d: %d", i, st)
		}
	}
	before, _ := v.WriteBackPending()
	if before == 0 {
		t.Fatal("no admitted backlog to close over")
	}

	done := make(chan Status, 1)
	started := time.Now()
	go func() { done <- v.CloseHandle("d/big", n) }()
	select {
	case st := <-done:
		if st != fsproto.OK {
			t.Fatalf("close = %d, want OK", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("close(2) drained its admitted backlog inside the op pipeline")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("close took %s; close is bounded local bookkeeping", elapsed)
	}
	if n.IsOpen() {
		t.Fatal("close did not retire the descriptor")
	}
	if after, _ := v.WriteBackPending(); after == 0 {
		t.Fatal("close dropped the locally accepted unshipped tail")
	}
}

// TestCloseThenReopenStillReadsYourWrites: closing is a descriptor event, not
// an overlay event. A reopen must still see everything the closed handle
// admitted, even though none of it reached the authority.
func TestCloseThenReopenStillReadsYourWrites(t *testing.T) {
	addr := serveCore(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "close-reopen",
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
	if st := v.RegisterOpened(ctx, "d/f", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}
	if st := v.FsyncHandle("d/f", n); st != fsproto.OK {
		t.Fatalf("initial fsync: %d", st)
	}
	v.Client().ExpireSession()
	want := []byte("read your writes across close")
	if _, st := v.Write(ctx, "d/f", n, 0, want); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}
	if st := v.CloseHandle("d/f", n); st != fsproto.OK {
		t.Fatalf("close: %d", st)
	}

	reopened := openHandle(t, v, "d/f")
	got, st := v.Read(ctx, "d/f", reopened, 0, len(want))
	if st != fsproto.OK {
		t.Fatalf("read after reopen: %d", st)
	}
	if string(got) != string(want) {
		t.Fatalf("read after close+reopen = %q, want %q", got, want)
	}
	if st := v.CloseHandle("d/f", reopened); st != fsproto.OK {
		t.Fatalf("close reopened handle: %d", st)
	}
}

// TestClosingSomeOfManyHandlesKeepsTheFileOpen: many descriptors on one file,
// closing some. Only the last close retires the open state, and no close
// barriers.
func TestClosingSomeOfManyHandlesKeepsTheFileOpen(t *testing.T) {
	addr := serveCore(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "close-many",
		WALDir: t.TempDir(),
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })
	ctx := context.Background()
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/many", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	for i := 0; i < 3; i++ {
		if st := v.RegisterOpened(ctx, "d/many", n); st != fsproto.OK {
			t.Fatalf("register open %d: %d", i, st)
		}
	}
	if st := v.FsyncHandle("d/many", n); st != fsproto.OK {
		t.Fatalf("fsync: %d", st)
	}
	v.Client().ExpireSession()
	if _, st := v.Write(ctx, "d/many", n, 0, []byte("shared")); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}
	for i := 0; i < 2; i++ {
		if st := v.CloseHandle("d/many", n); st != fsproto.OK {
			t.Fatalf("close %d: %d", i, st)
		}
		if !n.IsOpen() {
			t.Fatalf("close %d retired a file that still has live descriptors", i)
		}
	}
	if st := v.CloseHandle("d/many", n); st != fsproto.OK {
		t.Fatalf("last close: %d", st)
	}
	if n.IsOpen() {
		t.Fatal("last close did not retire the file")
	}
	if records, _ := v.WriteBackPending(); records == 0 {
		t.Fatal("the last close drained or dropped the admitted tail")
	}
}

// TestOrphanedHandleCloseWithBacklogIsBounded: an unlinked-open handle whose
// backlog is unshipped still closes locally. The orphan transition already
// released the covering delegation; close must not re-enter a drain.
func TestOrphanedHandleCloseWithBacklogIsBounded(t *testing.T) {
	addr := serveCore(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "close-orphan",
		WALDir: t.TempDir(),
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })
	ctx := context.Background()
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/gone", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened(ctx, "d/gone", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}
	if _, st := v.Write(ctx, "d/gone", n, 0, []byte("unlinked but open")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	if st := v.Remove(ctx, "d/gone", n); st != fsproto.OK {
		t.Fatalf("unlink-while-open: %d", st)
	}
	v.Client().ExpireSession()

	done := make(chan Status, 1)
	go func() { done <- v.CloseHandle("d/gone", n) }()
	select {
	case st := <-done:
		if st != fsproto.OK {
			t.Fatalf("orphaned close = %d, want OK", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("closing an orphaned handle waited on a drain")
	}
	if n.IsOpen() {
		t.Fatal("orphaned close did not retire the descriptor")
	}
}
