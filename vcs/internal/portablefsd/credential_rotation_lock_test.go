package portablefsd

// ── THE ACCESS LEASE DIED BEHIND THE REGISTRY'S MUTATION LOCK ───────────────
//
// Round 15 established that a credential rotation into an already-live attach
// must not queue behind the mount's own traffic, and took the mount-wide
// namespace lock off it (attach.rotateLiveCredential). One level up, the
// registry's global mutationMu was left in place — and runUnmountTransaction
// holds mutationMu across the ENTIRE authority drain barrier plus the exact
// kernel detach, while registry.delete holds it across a whole detach.
//
// So under a flood the CLI's credential push still queued behind all of it,
// burned its full 60s control timeout, and was dropped. The daemon then went on
// using a credential the keeper believed it had delivered, and the ACCESS lease
// expired underneath a mount that was busy proving it was alive.

import (
	"context"
	"testing"
	"time"
)

// TestLiveCredentialRotationDoesNotQueueBehindTheRegistryMutationLock holds
// mutationMu exactly as a running unmount transaction does, and requires a
// rotation into a LIVE attach to complete anyway.
//
// It hangs against the pre-fix registry.activate, which takes mutationMu before
// it looks at the attach at all.
func TestLiveCredentialRotationDoesNotQueueBehindTheRegistryMutationLock(t *testing.T) {
	a, _, _, _ := newMutationSeqAttach(t)
	a.ref = "rotation-ref"
	a.key = "rotation-key"
	r := &registry{
		byRef: map[string]*attach{a.ref: a},
		byKey: map[string]*attach{a.key: a},
	}

	// Stand in for runUnmountTransaction: it owns mutationMu from the moment it
	// starts until the drain barrier and the kernel detach have both finished.
	// Nothing about this test depends on WHAT that transaction is doing, only
	// that it holds the lock for a long time — which is its whole design.
	r.mutationMu.Lock()
	defer r.mutationMu.Unlock()

	const rotated = "rotated-access-token"
	expiry := time.Now().Add(10 * time.Minute).UnixMilli()

	type result struct {
		found     bool
		activated bool
		err       error
	}
	done := make(chan result, 1)
	go func() {
		found, activated, err := r.activate(
			context.Background(), a.ref, rotated, expiry, false,
		)
		done <- result{found, activated, err}
	}()

	// The keeper's own control request gives up at 60s; anything remotely close
	// to that is the failure. A rotation into a live attach is a token write and
	// an InstallCredential — it is bounded by nothing at all.
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("rotating a live credential failed: %v", got.err)
		}
		if !got.found || !got.activated {
			t.Fatalf("rotation reported found=%v activated=%v, want true/true",
				got.found, got.activated)
		}
	case <-time.After(5 * time.Second):
		t.Fatal(
			"a credential rotation into a LIVE attach queued behind the " +
				"registry's global mutation lock, which a running unmount " +
				"transaction holds across the whole authority drain barrier and " +
				"the exact kernel detach.\n" +
				"Live, the keeper's push burns its full 60s control timeout and " +
				"is dropped: the daemon keeps using a credential the keeper " +
				"believes it delivered, and the ACCESS lease expires underneath a " +
				"mount that is busy proving it is alive.",
		)
	}

	// And it must really have installed the credential, not merely returned.
	a.credMu.Lock()
	gotToken, gotExpiry := a.token, a.tokenExpiresAtMs
	a.credMu.Unlock()
	if gotToken != rotated || gotExpiry != expiry {
		t.Fatalf("rotation installed token=%q expiry=%d, want %q/%d",
			gotToken, gotExpiry, rotated, expiry)
	}
}

// TestCredentialRotationStillSerializesForEveryStateItDoesNotHandle is the
// other half: the fast path may only skip mutationMu for the exact case the
// locked path reduced to one setCredential and an immediate return.
//
// A DETACHED attach is one of the states whose verdict belongs to the locked
// path, and it must still reach it — with the lock held, and with the same
// error — rather than being answered by the lock-free shortcut.
func TestCredentialRotationStillSerializesForEveryStateItDoesNotHandle(t *testing.T) {
	a, _, _, _ := newMutationSeqAttach(t)
	a.ref = "detached-ref"
	a.key = "detached-key"
	a.mu.Lock()
	a.detached = true
	a.mu.Unlock()
	r := &registry{
		byRef: map[string]*attach{a.ref: a},
		byKey: map[string]*attach{a.key: a},
	}

	// mutationMu is FREE here, so the locked path can run; what is asserted is
	// that the request reaches it at all and produces the locked path's verdict.
	// NOTE: this endpoint's `activated` return is unconditionally true on the
	// non-pending branch, before and after this change; the verdict that matters
	// is the error and whether anything was installed.
	_, _, err := r.activate(
		context.Background(), a.ref, "should-not-install", 0, false,
	)
	if err == nil {
		t.Fatal("rotating into a detached attach succeeded: the lock-free fast " +
			"path answered a state whose verdict belongs to the serialized path")
	}
	a.credMu.Lock()
	gotToken := a.token
	a.credMu.Unlock()
	if gotToken == "should-not-install" {
		t.Fatal("a detached attach had a rotated credential installed into it")
	}

	// A ref that does not exist is still not found, and the answer still comes
	// from the re-resolve under mutationMu rather than from the lock-free read.
	found, _, err := r.activate(context.Background(), "no-such-ref", "t", 0, false)
	if found || err != nil {
		t.Fatalf("unknown ref reported found=%v err=%v, want false/nil", found, err)
	}
}
