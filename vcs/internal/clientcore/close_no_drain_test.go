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
//
// HOW THESE FIXTURES HOLD AN UNSHIPPED BACKLOG. Every close-over-backlog test
// here needs one precondition: records the engine has ADMITTED under a live
// delegation and has not yet shipped. The only sound way to build that is to
// break the TRANSPORT and leave ownership alone — see closeFixtureVolume, and
// the root-defect note on TestCloseWithAdmittedBacklogIsBoundedAndKeepsTheTail
// for what goes wrong when the session is fenced instead. A fenced session
// yields a state that merely LOOKS similar, and the difference between the two
// is the entire contract under test.

// closeFixtureVolume dials a mount whose authority link can be black-holed on
// demand. The proxy sits between the client and the authority, so freezing it
// stops write-back from SHIPPING without telling the authority anything: the
// session stays live, the delegation stays granted, the engine keeps admitting,
// and the pending tail simply grows. That is the state the §6 close contract is
// written about, and unlike a fence it is a steady state rather than a race.
func closeFixtureVolume(t *testing.T, owner string) (*Volume, *freezeProxy) {
	t.Helper()
	proxy := newFreezeProxy(t, serveCore(t))
	v := dialCoreNoCleanup(t, proxy.addr(), Options{
		Owner:  owner,
		WALDir: t.TempDir(),
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })
	return v, proxy
}

// requireOwnedBacklog asserts the precondition these fixtures are actually
// about: a delegation still OWNED, an engine still admitting, and a non-empty
// pending tail. It exists because losing ownership does not make a close
// fixture fail — it silently converts it into a test of the RELEASE path, which
// is precisely the defect this file was rewritten to make impossible. Stating
// the precondition out loud is what keeps that substitution loud.
func requireOwnedBacklog(t *testing.T, v *Volume, scope string) int {
	t.Helper()
	if !v.wb.Covers(scope) {
		t.Fatalf("the covering delegation on %q is gone: this fixture is about "+
			"closing over a backlog the mount still OWNS, and without the grant "+
			"it asserts the post-release path instead", scope)
	}
	if err := v.wb.MutationError(); err != nil {
		t.Fatalf("the engine failed closed (%v): a sealed engine refuses further "+
			"mutation, so any backlog still standing is an artefact of the seal "+
			"rather than of a live delegation with a blocked transport", err)
	}
	records, _ := v.WriteBackPending()
	if records == 0 {
		t.Fatal("no admitted backlog to close over")
	}
	return records
}

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
//
// THE ROOT DEFECT THIS FIXTURE USED TO CARRY. It produced its "unshipped"
// backlog by calling Client().ExpireSession(), which is not a transport fault
// but a durable RELEASE: the authority drops that session's lease-owned
// delegations immediately. That is a category error. The §6 close contract is a
// statement about a handle whose backlog is still OWNED — close must not drain
// what the engine remains entitled to ship later — so releasing ownership first
// deletes the very thing under test and leaves the assertions measuring the
// post-release path.
//
// It also made the fixture race its own setup. A fenced session makes the next
// flush attempt come back ESTALE, and ESTALE is a PROVEN fence, so the flusher
// parks the stream and park() seals mutation admission for the whole mount (see
// writeback.flusher.park). Every write issued after that seal then correctly
// returns EIO. The loop below was therefore racing the flusher's ~10ms poll
// against its own eight writes, and on a loaded machine the later ones lost —
// a product behaviour firing exactly as designed, surfacing as a close-path
// failure. Nothing about the close path was ever implicated.
//
// Blocking the TRANSPORT is the honest construction. The authority is told
// nothing, so it revokes nothing; the flusher's attempts fail as transport
// errors, which are retryable and leave admission open; and the backlog piles
// up under a grant the mount still holds. That is the state close(2) has to be
// bounded over, and it is stable rather than timed.
func TestCloseWithAdmittedBacklogIsBoundedAndKeepsTheTail(t *testing.T) {
	v, proxy := closeFixtureVolume(t, "close-backlog")
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

	// Black-hole the authority link. Nothing this handle admits from here can
	// SHIP, and nothing about the delegation changes.
	proxy.freeze()
	payload := make([]byte, 32<<10)
	for i := 0; i < 8; i++ {
		if _, st := v.Write(ctx, "d/big", n, int64(i)*int64(len(payload)), payload); st != fsproto.OK {
			t.Fatalf("delegated write %d: %d", i, st)
		}
	}
	before := requireOwnedBacklog(t, v, "d/big")

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
		t.Fatalf("close dropped the locally accepted unshipped tail (%d records stood before it)", before)
	}
	// The close retired a DESCRIPTOR, not the grant: the tail it left behind is
	// still the engine's to ship once the link returns.
	if !v.wb.Covers("d/big") {
		t.Fatal("close released the covering delegation; the tail it left behind has no owner to ship it")
	}
}

// TestCloseThenReopenStillReadsYourWrites: closing is a descriptor event, not
// an overlay event. A reopen must still see everything the closed handle
// admitted, even though none of it reached the authority.
//
// The clause that matters is "none of it reached the authority", not "the mount
// no longer owns it": read-your-writes across close is a property of the
// overlay a LIVE delegation is serving, so the backlog is held here by a
// blocked transport rather than a fence (see closeFixtureVolume).
func TestCloseThenReopenStillReadsYourWrites(t *testing.T) {
	v, proxy := closeFixtureVolume(t, "close-reopen")
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
	proxy.freeze()
	want := []byte("read your writes across close")
	if _, st := v.Write(ctx, "d/f", n, 0, want); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}
	requireOwnedBacklog(t, v, "d/f")
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
//
// The closing assertion is that the admitted tail survives the LAST close, so
// this is the owned-backlog contract too: the tail has to be one the engine
// still holds a grant for, which is why the transport is blocked rather than
// the session fenced (see closeFixtureVolume).
func TestClosingSomeOfManyHandlesKeepsTheFileOpen(t *testing.T) {
	v, proxy := closeFixtureVolume(t, "close-many")
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
	proxy.freeze()
	if _, st := v.Write(ctx, "d/many", n, 0, []byte("shared")); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}
	requireOwnedBacklog(t, v, "d/many")
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
//
// This one KEEPS ExpireSession, deliberately, and must not be converted to the
// blocked-transport construction its neighbours use. Those fixtures are about
// closing over a backlog the mount still OWNS; this one is the opposite case by
// definition — the unlink already handed the covering grant back, and the
// property being pinned is that close stays bounded with no delegation left to
// drain into. Releasing ownership is the precondition here rather than the bug,
// so the fence belongs, and requireOwnedBacklog would be the wrong assertion.
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
