package clientcore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
)

// TestReadFlushesKernelPerGenEvenWhenGetattrObservedGenFirst pins P1: the Read path's
// FOPEN_KEEP_CACHE kernel-flush backup must fire exactly once per new generation regardless of which
// op first re-anchored the version cache. A getattr that observes the (post-failover) generation first
// re-anchors the version cache without flushing the kernel; a subsequent read must STILL fire the
// full-flush callback, because kernel-flush-per-gen is tracked separately from the cache re-anchor.
func TestReadFlushesKernelPerGenEvenWhenGetattrObservedGenFirst(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	seed := dialCore(t, addr, Options{})
	a, st := seed.Create(ctx, "f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n0 := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := seed.Write(ctx, "f", n0, 0, []byte("hello")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	var fullFlushes int64
	var mu sync.Mutex // OnFlushAll may be invoked from goroutines
	v := dialCore(t, addr, Options{
		OnFlushAll: func(path string) {
			if path == "" {
				mu.Lock()
				atomic.AddInt64(&fullFlushes, 1)
				mu.Unlock()
			}
		},
	})

	// First post-"failover" op is a getattr: it observes the generation and re-anchors the version
	// cache (no kernel flush).
	la, st := v.Lookup(ctx, "f")
	if st != fsproto.OK {
		t.Fatalf("lookup: %d", st)
	}
	if got := atomic.LoadInt64(&fullFlushes); got != 0 {
		t.Fatalf("getattr must not fire a kernel full-flush, got %d", got)
	}

	// Now a read on the SAME generation must still fire the kernel flush backup exactly once.
	rn := NewNodeState(la.Ino, la.Ino != 0)
	if _, st := v.Read(ctx, "f", rn, 0, 5); st != fsproto.OK {
		t.Fatalf("read: %d", st)
	}
	waitFor(t, func() bool { return atomic.LoadInt64(&fullFlushes) == 1 }, "read did not fire the per-gen kernel flush")

	// A second read on the same generation must NOT fire it again (exactly once per gen).
	if _, st := v.Read(ctx, "f", rn, 0, 5); st != fsproto.OK {
		t.Fatalf("read2: %d", st)
	}
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt64(&fullFlushes); got != 1 {
		t.Fatalf("kernel full-flush must fire exactly once per gen, got %d", got)
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}
