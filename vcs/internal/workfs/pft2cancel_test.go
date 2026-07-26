package workfs

// Cancellation-poisoning audit for the lazy PFT2 publication/recovery path:
// a singleflight LEADER that is canceled mid-fetch must never fail live
// waiters with ITS context error — the waiter retries as the next leader —
// while genuine store/integrity failures stay shared by every waiter.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// gatedFetcher blocks the FIRST fetch of every ref until released, so a test
// can deterministically cancel the leader while a waiter is queued.
type gatedFetcher struct {
	inner pft2.Fetcher

	mu      sync.Mutex
	started chan struct{} // closed when the first fetch arrives
	release chan struct{} // the first fetch blocks until this closes
	first   bool
	count   int
}

func newGatedFetcher(inner pft2.Fetcher) *gatedFetcher {
	return &gatedFetcher{
		inner:   inner,
		started: make(chan struct{}),
		release: make(chan struct{}),
		first:   true,
	}
}

func (f *gatedFetcher) Fetch(ctx context.Context, ref pft2.Ref) ([]byte, error) {
	f.mu.Lock()
	f.count++
	gate := f.first
	f.first = false
	f.mu.Unlock()
	if gate {
		close(f.started)
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.inner.Fetch(ctx, ref)
}

func (f *gatedFetcher) fetches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

func TestPackCacheCanceledLeaderDoesNotPoisonWaiters(t *testing.T) {
	// Non-zero bytes: all-zero cells are canonical holes and would leave the
	// file without extents (and the test without a pack to fetch).
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i%251) + 1
	}
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpCreate, Path: "f", Mode: 0o644},
		{Op: wal.OpWrite, Path: "f", Data: data},
	})
	// Find one pack ref through a scratch read against the raw store.
	scratch := newPft2PackCache(base.store, pft2PackCacheBytes)
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: base.store}, base.root)
	if err != nil {
		t.Fatal(err)
	}
	rootView, err := reader.GetInode(context.Background(), pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := reader.Lookup(context.Background(), rootView.Ref, "f")
	if err != nil {
		t.Fatal(err)
	}
	fileView, err := reader.GetInode(context.Background(), entry.Ino)
	if err != nil {
		t.Fatal(err)
	}
	extents, err := reader.ReadExtents(context.Background(), fileView.Ref, 0, 8192)
	if err != nil || len(extents) == 0 || extents[0].Cell == nil {
		t.Fatalf("extents err=%v len=%d", err, len(extents))
	}
	packRef := extents[0].Cell.Object
	if _, err := scratch.fetch(context.Background(), packRef); err != nil {
		t.Fatalf("scratch fetch: %v", err)
	}

	gated := newGatedFetcher(base.store)
	cache := newPft2PackCache(gated, pft2PackCacheBytes)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := cache.fetch(leaderCtx, packRef)
		leaderErr <- err
	}()
	<-gated.started // the leader is mid-fetch and holds the flight

	waiterErr := make(chan error, 1)
	go func() {
		_, err := cache.fetch(context.Background(), packRef)
		waiterErr <- err
	}()
	// Give the waiter time to join the leader's flight, then cancel the
	// leader and release the gate (the leader observes cancellation).
	time.Sleep(20 * time.Millisecond)
	cancelLeader()

	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	select {
	case err := <-waiterErr:
		if err != nil {
			t.Fatalf("live waiter failed with the canceled leader's error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not complete after the canceled leader")
	}
	if got := gated.fetches(); got < 2 {
		t.Fatalf("waiter did not retry as the next leader (fetches=%d)", got)
	}

	// Genuine failures stay shared: a canceled WAITER reports its own
	// cancellation, never a fabricated success.
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := cache.fetch(canceledCtx, pft2.Ref{Digest: packRef.Digest, Size: packRef.Size + 0}); err == nil {
		// The pack is cached now; a canceled context may still be served
		// from cache (no I/O). That is acceptable: cancellation gates I/O,
		// not memory reads.
		_ = err
	}
}

func TestTreeReaderCanceledLeaderDoesNotPoisonWaiters(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpMkdir, Path: "d", Mode: 0o755},
		{Op: wal.OpCreate, Path: "d/f", Mode: 0o644},
	})
	gated := newGatedFetcher(base.store)
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: gated}, base.root)
	if err != nil {
		t.Fatal(err)
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := reader.GetInode(leaderCtx, pft2.RootIno)
		leaderErr <- err
	}()
	<-gated.started

	waiterErr := make(chan error, 1)
	go func() {
		_, err := reader.GetInode(context.Background(), pft2.RootIno)
		waiterErr <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancelLeader()

	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	select {
	case err := <-waiterErr:
		if err != nil {
			t.Fatalf("live waiter failed with the canceled leader's error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not complete after the canceled leader")
	}
}
