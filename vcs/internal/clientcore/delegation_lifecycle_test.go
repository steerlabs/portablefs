package clientcore

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestAdaptiveDelegationLifecycle pins the full adaptive loop against the
// REAL authority policy: grant on first uncontended write, zero-RPC local
// operation under the grant, a peer read that recalls (drain + exact bytes,
// never stale), contention degrading the scope to write-through, and the
// re-grant once the contention window clears.
func TestAdaptiveDelegationLifecycle(t *testing.T) {
	const contention = 500 * time.Millisecond
	fsproto.SetAdaptivePolicyContentionWindowForTest(contention)
	t.Cleanup(func() { fsproto.SetAdaptivePolicyContentionWindowForTest(30 * time.Second) })
	writeback.SetDenialBackoffForTest(50 * time.Millisecond)
	t.Cleanup(func() { writeback.SetDenialBackoffForTest(5 * time.Second) })

	addr := serveCore(t)
	ctx := context.Background()
	holder := dialCore(t, addr, Options{Owner: "holder", WALDir: t.TempDir()})
	watchInvalidationsForTest(t, holder) // recalls ride the invalidation stream

	if _, st := holder.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := holder.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(InoOf("d/f"), a.Ino != 0)
	if _, st := holder.Write(ctx, "d/f", n, 0, []byte("one")); st != fsproto.OK {
		t.Fatalf("write one: %d", st)
	}

	// Granted: local operations under the scope cost zero authority RPCs.
	rpc0 := opCount(holder)
	if _, st := holder.Create(ctx, "d/g", 0o644); st != fsproto.OK {
		t.Fatalf("create d/g: %d", st)
	}
	if _, st := holder.Write(ctx, "d/g", NewNodeState(InoOf("d/g"), false), 0, []byte("gg")); st != fsproto.OK {
		t.Fatalf("write d/g: %d", st)
	}
	if got := opCount(holder) - rpc0; got != 0 {
		t.Fatalf("delegated ops cost %d RPCs, want 0", got)
	}

	// Peer read: the gate recalls the delegation, the holder drains, and the
	// peer sees the exact acknowledged bytes — never the pre-grant state.
	peer := dialCore(t, addr, Options{Owner: "peer"})
	data, st := peer.Read(ctx, "d/f", NewNodeState(0, false), 0, 16)
	if st != fsproto.OK || string(data) != "one" {
		t.Fatalf("peer read after recall = %q st=%d, want exact \"one\"", data, st)
	}

	// Contention degrade: the recall put the scope in the contention window,
	// so the holder's next write runs write-through (costs authority RPCs)
	// instead of silently waiting for a delegation.
	rpc1 := opCount(holder)
	if _, st := holder.Write(ctx, "d/f", n, 0, []byte("two")); st != fsproto.OK {
		t.Fatalf("write two: %d", st)
	}
	if got := opCount(holder) - rpc1; got == 0 {
		t.Fatal("post-recall write cost 0 RPCs; it must run write-through under contention")
	}
	// Write-through means immediately visible to a fresh observer.
	obs := dialCore(t, addr, Options{Owner: "observer"})
	if data, st := obs.Read(ctx, "d/f", NewNodeState(0, false), 0, 16); st != fsproto.OK || string(data) != "two" {
		t.Fatalf("observer read = %q st=%d, want \"two\"", data, st)
	}

	// Re-grant: once the contention window clears, the authority delegates
	// again and the scope returns to zero-RPC local acknowledgment.
	time.Sleep(contention + 200*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for !holder.wb.Covers("d/f") {
		if _, st := holder.Write(ctx, "d/f", n, 0, []byte("three")); st != fsproto.OK {
			t.Fatalf("write three: %d", st)
		}
		if time.Now().After(deadline) {
			t.Fatal("scope never re-delegated after the contention window cleared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	rpc2 := opCount(holder)
	if _, st := holder.Write(ctx, "d/f", n, 0, []byte("four!")); st != fsproto.OK {
		t.Fatalf("write four: %d", st)
	}
	if got := opCount(holder) - rpc2; got != 0 {
		t.Fatalf("re-granted write cost %d RPCs, want 0", got)
	}
	if err := holder.FlushToAuthority(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	final := dialCore(t, addr, Options{Owner: "final"})
	if data, st := final.Read(ctx, "d/f", NewNodeState(0, false), 0, 16); st != fsproto.OK || string(data) != "four!" {
		t.Fatalf("final read = %q st=%d, want \"four!\"", data, st)
	}
}
