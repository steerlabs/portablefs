package clientcore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestSiblingWritersPushDelegationsDown proves the launch workload that the
// one-writer/one-reader lifecycle test does not cover: two live mounts create
// and fill sibling directory trees concurrently. A mount must not retain the
// common ancestor grant after it starts mutating a deeper directory; doing so
// serializes unrelated peers behind recalls and can turn a high-throughput
// sibling workload into a bounded-wait failure.
func TestSiblingWritersPushDelegationsDown(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	a := dialCore(t, addr, Options{
		Owner: "sibling-a", VolumeID: "vol-siblings", Branch: "main",
		WALDir: t.TempDir(),
	})
	b := dialCore(t, addr, Options{
		Owner: "sibling-b", VolumeID: "vol-siblings", Branch: "main",
		WALDir: t.TempDir(),
	})
	watchInvalidationsForTest(t, a)
	watchInvalidationsForTest(t, b)

	if _, st := a.Mkdir(ctx, "run", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir run: %d", st)
	}
	if _, st := a.Mkdir(ctx, "run/a", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir run/a: %d", st)
	}
	if _, st := a.Mkdir(ctx, "run/a/sequential", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir run/a/sequential: %d", st)
	}
	if _, st := a.Create(ctx, "run/a/sequential/seed", 0o644); st != fsproto.OK {
		t.Fatalf("create a seed: %d", st)
	}
	assertDelegationScopes(t, a, "run/a/sequential")

	// B's first directory is a sibling of A's narrow scope. It may be
	// created synchronously if the broad "run" checkout is ineligible, but
	// its deeper work must settle on its own non-overlapping scope.
	if _, st := b.Mkdir(ctx, "run/b", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir run/b: %d", st)
	}
	if _, st := b.Mkdir(ctx, "run/b/sequential", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir run/b/sequential: %d", st)
	}
	if _, st := b.Create(ctx, "run/b/sequential/seed", 0o644); st != fsproto.OK {
		t.Fatalf("create b seed: %d", st)
	}
	assertDelegationScopes(t, b, "run/b/sequential")

	const files = 500
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, writer := range []struct {
		name string
		vol  *Volume
	}{
		{name: "a", vol: a},
		{name: "b", vol: b},
	} {
		writer := writer
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < files; i++ {
				p := fmt.Sprintf("run/%s/sequential/file-%06d", writer.name, i)
				if _, st := writer.vol.Create(ctx, p, 0o644); st != fsproto.OK {
					errs <- fmt.Errorf("%s create %d: status %d", writer.name, i, st)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if err := a.FlushToAuthority(ctx); err != nil {
		t.Fatalf("flush a: %v", err)
	}
	if err := b.FlushToAuthority(ctx); err != nil {
		t.Fatalf("flush b: %v", err)
	}

	observer := dialCore(t, addr, Options{Owner: "sibling-observer"})
	for _, role := range []string{"a", "b"} {
		for i := 0; i < files; i++ {
			p := fmt.Sprintf("run/%s/sequential/file-%06d", role, i)
			if _, st := observer.Lookup(ctx, p); st != fsproto.OK {
				t.Fatalf("observer lookup %s: status %d", p, st)
			}
		}
	}
}

func assertDelegationScopes(t *testing.T, v *Volume, want ...string) {
	t.Helper()
	got := v.WritebackStatus().Delegations
	if len(got) != len(want) {
		t.Fatalf("delegations = %+v, want scopes %v", got, want)
	}
	for i := range want {
		if got[i].Scope != want[i] || got[i].Draining {
			t.Fatalf("delegations = %+v, want active scopes %v", got, want)
		}
	}
}

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
