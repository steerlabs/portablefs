package clientcore

import (
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestCloseDoesNotQueueBehindThePathlessExactLane completes the §6 close
// contract from the side close_no_drain_test.go cannot see.
//
// Those tests exercise path-bearing writes, which hold exactMu SHARED — so a
// close that also takes it shared runs straight through and the contract looks
// satisfied. The pathless exact lane is the case that breaks it. A detached
// descriptor has no trustworthy pathname, so beginExactOperation takes exactMu
// EXCLUSIVELY across Engine.BeginExact (drain + durable release of every
// delegation) and the inode-addressed authority round trip that follows — and
// hands the unlock to an exclusionRelease that a parked identity can hold
// until a session fence resolves it.
//
// Go's RWMutex is writer-preferring, so a merely PENDING exclusive acquirer is
// already enough to park every subsequent close. Close would then inherit an
// authority round trip's latency — unboundedly — for state it does not touch:
// its whole job is local bookkeeping under openStateMu, n.mu and the open
// registry, none of which is what exactMu guards. exactMu orders write-back
// admission against inode-addressed mutation; close neither admits, nor
// mutates an inode remotely, nor moves a delegation.
func TestCloseDoesNotQueueBehindThePathlessExactLane(t *testing.T) {
	addr := serveCore(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "close-exact-lane",
		WALDir: t.TempDir(),
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })

	a, st := v.Create(t.Context(), "f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened(t.Context(), "f", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}

	// Stand in for an exact operation parked in its authority round trip: the
	// exclusion is held and not coming back on any bound this test can wait on.
	v.exactMu.Lock()
	defer v.exactMu.Unlock()

	done := make(chan Status, 1)
	go func() { done <- v.CloseHandle("f", n) }()
	select {
	case st := <-done:
		if st != fsproto.OK {
			t.Fatalf("close = %d, want OK", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close(2) queued behind the pathless exact lane's authority round trip")
	}
}
