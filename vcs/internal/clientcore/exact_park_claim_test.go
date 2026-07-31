package clientcore

// The parkExact data-integrity window, at the layer where it matters.
//
// doExactOnce parks a possibly-sent exact identity for background replay and
// returns ErrMutationUnknown. Before the fix the frontend caller then released
// its delegation-transition claim and the volume's exact exclusion, so a new
// delegation over the same scope could be granted while the parked mutation
// was still able to execute. These tests pin the invariant: the exclusion the
// identity was issued under is not released to anyone until that identity has
// a definite outcome (reply, fence, or client teardown), and then exactly once.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// parkMutation drives one authority mutation to an UNKNOWN outcome by losing
// every reply while blocked is true.
func parkMutation(
	t *testing.T,
	server *fsproto.Server,
	v *Volume,
	authorityCtx context.Context,
	path string,
	blocked *atomic.Bool,
) {
	t.Helper()
	blocked.Store(true)
	server.SetDropReply(func(req *fsproto.Request, _ *fsproto.Response) bool {
		return req.Op == fsproto.OpMkdir && req.Path == path && blocked.Load()
	})
	if _, _, err := v.client.MkdirContext(authorityCtx, path, 0o755); !errors.Is(err, fsproto.ErrMutationUnknown) {
		t.Fatalf("mkdir with every reply lost: err=%v, want ErrMutationUnknown", err)
	}
}

// acquireBlocked reports whether a delegation acquisition over scope is
// excluded right now (the gate is cancellable, so a short deadline is the
// probe).
func acquireBlocked(t *testing.T, v *Volume, scope string, within time.Duration) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	claim, err := v.delegationTransitions.begin(ctx, acquireTransition, []string{scope}, nil)
	if err != nil {
		return true
	}
	claim.end()
	return false
}

// THE integrity property: while an exact identity issued under a path-bearing
// authority claim is parked, no delegation acquisition over that scope may be
// admitted — not even after the frontend caller returned and ran its end().
func TestParkedAuthorityIdentityRetainsTransitionClaimUntilDefinite(t *testing.T) {
	ctx := context.Background()
	addr, server := serveCoreServer(t)
	v := dialCore(t, addr, Options{
		Owner: "park-claim", VolumeID: "park-claim", Branch: "main", WALDir: t.TempDir(),
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}

	authorityCtx, end, err := v.beginAuthorityMutation(ctx, nil, "d/parked")
	if err != nil {
		t.Fatalf("begin authority mutation: %v", err)
	}
	var blocked atomic.Bool
	parkMutation(t, server, v, authorityCtx, "d/parked", &blocked)

	// The caller returns ErrMutationUnknown and releases, exactly as today.
	end()

	// ...but the claim is NOT free: the parked identity still owns it.
	if !acquireBlocked(t, v, "d/parked", 300*time.Millisecond) {
		blocked.Store(false)
		t.Fatal("a delegation acquisition was admitted over a scope with a parked, possibly-executing exact identity")
	}
	// An unrelated scope must stay fully concurrent (no over-blocking).
	if acquireBlocked(t, v, "elsewhere", 2*time.Second) {
		blocked.Store(false)
		t.Fatal("parked identity blocked an unrelated delegation acquisition")
	}

	// A definite outcome hands the claim over.
	blocked.Store(false)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if !acquireBlocked(t, v, "d/parked", 500*time.Millisecond) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("claim was never released after the parked identity resolved")
		}
	}
	// And the identity really did land exactly once.
	if a, st, err := v.client.Getattr("d/parked"); err != nil || st != fsproto.OK || a.Kind != "directory" {
		t.Fatalf("parked mkdir did not land: attr=%+v st=%d err=%v", a, st, err)
	}
}

// The exact (inode-addressed) exclusion is retained the same way, and a fence
// — a definite end for the parked generation — releases it exactly once. A
// double release would panic on the unlock of an unlocked RWMutex.
func TestFenceDuringParkedExactOperationReleasesExclusionExactlyOnce(t *testing.T) {
	ctx := context.Background()
	addr, server := serveCoreServer(t)
	v := dialCore(t, addr, Options{
		Owner: "park-exact-fence", VolumeID: "park-exact-fence", Branch: "main", WALDir: t.TempDir(),
	})

	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		t.Fatalf("begin exact operation: %v", err)
	}
	var blocked atomic.Bool
	parkMutation(t, server, v, authorityCtx, "exact-parked", &blocked)
	end()
	defer blocked.Store(false)

	if v.exactMu.TryLock() {
		v.exactMu.Unlock()
		t.Fatal("exact exclusion was released while an identity issued under it was parked")
	}

	// Fence the session: the parked generation can never execute again.
	v.client.ExpireSession()
	if !v.client.SessionFenced() {
		t.Fatal("ExpireSession did not fence the mount session")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if v.exactMu.TryLock() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fenced park never released the exact exclusion")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Hold it: a second (buggy) release would panic here rather than silently
	// double-unlocking.
	time.Sleep(200 * time.Millisecond)
	v.exactMu.Unlock()
}

// Client teardown during a park must not strand the exclusion: Close fences
// and joins the replayers, so the exclusion is free the moment Close returns.
func TestClientCloseDuringParkedExactOperationDoesNotStrandExclusion(t *testing.T) {
	ctx := context.Background()
	addr, server := serveCoreServer(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner: "park-exact-close", VolumeID: "park-exact-close", Branch: "main", WALDir: t.TempDir(),
	})
	var blocked atomic.Bool
	t.Cleanup(func() {
		blocked.Store(false)
		_, _ = v.CloseJournalDurable()
	})

	authorityCtx, end, err := v.beginExactOperation(ctx)
	if err != nil {
		t.Fatalf("begin exact operation: %v", err)
	}
	parkMutation(t, server, v, authorityCtx, "close-parked", &blocked)
	end()
	if v.exactMu.TryLock() {
		v.exactMu.Unlock()
		t.Fatal("exact exclusion was released while an identity issued under it was parked")
	}

	done := make(chan error, 1)
	go func() { done <- v.client.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("client close during park: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("client Close hung while an exact identity was parked")
	}
	if !v.exactMu.TryLock() {
		t.Fatal("client Close returned with the exact exclusion still owned by a parked identity")
	}
	v.exactMu.Unlock()
}
