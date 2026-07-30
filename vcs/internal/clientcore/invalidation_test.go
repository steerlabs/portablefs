package clientcore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

type fakeSub struct {
	ch chan coherence.Batch
}

func (f *fakeSub) Subscribe() (<-chan coherence.Batch, fsproto.AckFunc, error) { return f.ch, nil, nil }

type fakeHandler struct {
	mu       sync.Mutex
	flushes  int
	invalids []coherence.Invalidation
	orphans  []uint64
	recalls  []string
}

func (h *fakeHandler) FlushAll() {
	h.mu.Lock()
	h.flushes++
	h.mu.Unlock()
}

func (h *fakeHandler) InvalidatePath(p string, inPlace bool) {
	h.mu.Lock()
	h.invalids = append(h.invalids, coherence.Invalidation{Path: p, InPlace: inPlace})
	h.mu.Unlock()
}

func (h *fakeHandler) MarkOrphan(_ string, ino uint64) {
	h.mu.Lock()
	h.orphans = append(h.orphans, ino)
	h.mu.Unlock()
}

func (h *fakeHandler) ReleaseSubtree(p string) {
	h.mu.Lock()
	h.recalls = append(h.recalls, p)
	h.mu.Unlock()
}

// TestNameChangeInvalidationBumpsParentVersion pins the P4 improvement: a name-change (not in-place)
// invalidation advances the PARENT directory's recorded version, so a cached negative for a sibling is
// evicted the moment any child of that directory is created/removed/renamed. (Documented as deliberate;
// this test guards the invariant against regression.)
func TestNameChangeInvalidationBumpsParentVersion(t *testing.T) {
	attrs := NewAttrCache()
	versions := NewVersionCache()
	sub := &fakeSub{ch: make(chan coherence.Batch, 4)}
	h := &fakeHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchInvalidations(ctx, sub, versions, attrs, h, InvalidationOptions{})

	deadline := time.Now().Add(time.Second)
	for {
		h.mu.Lock()
		f := h.flushes
		h.mu.Unlock()
		if f > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial refresh did not run")
		}
		time.Sleep(time.Millisecond)
	}
	versions.RefreshAll(7)
	versions.FillOK(7, "dir", 1)

	// A NAME change under "dir" (in-place false) must advance dir's recorded version to the event's.
	sub.ch <- coherence.Batch{Invs: []coherence.Invalidation{{Path: "dir/new", Version: 4, Gen: 7, InPlace: false}}}
	deadline = time.Now().Add(time.Second)
	for {
		if _, v := versions.GenAndVersion("dir"); v >= 4 {
			break
		}
		if time.Now().After(deadline) {
			_, v := versions.GenAndVersion("dir")
			t.Fatalf("name-change did not bump parent version: dir version=%d want >=4", v)
		}
		time.Sleep(time.Millisecond)
	}

	// A subsequent IN-PLACE change to a child must NOT advance the parent version.
	before := func() uint64 { _, v := versions.GenAndVersion("dir"); return v }()
	sub.ch <- coherence.Batch{Invs: []coherence.Invalidation{{Path: "dir/new", Version: 5, Gen: 7, InPlace: true}}}
	time.Sleep(50 * time.Millisecond)
	if _, v := versions.GenAndVersion("dir"); v != before {
		t.Fatalf("in-place change must not bump parent version: got %d want %d", v, before)
	}
}

func TestWatchInvalidationsAppliesVersionedEvents(t *testing.T) {
	attrs := NewAttrCache()
	versions := NewVersionCache()
	sub := &fakeSub{ch: make(chan coherence.Batch, 4)}
	h := &fakeHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchInvalidations(ctx, sub, versions, attrs, h, InvalidationOptions{})

	deadline := time.Now().Add(time.Second)
	for {
		h.mu.Lock()
		flushes := h.flushes
		h.mu.Unlock()
		if flushes > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial refresh did not run")
		}
		time.Sleep(time.Millisecond)
	}
	attrs.PutAttr(5, 1, "dir/file", fsproto.Attr{Kind: "file"})
	attrs.PutNegative(5, 1, "dir/.DS_Store")
	versions.RefreshAll(5)
	versions.FillOK(5, "dir/file", 1)
	versions.FillOK(5, "dir", 1)

	sub.ch <- coherence.Batch{Invs: []coherence.Invalidation{{Path: "dir/file", Version: 2, Gen: 5, Orphaned: true, OrphanIno: 99}}}
	deadline = time.Now().Add(time.Second)
	for {
		if _, ok := attrs.Get(5, 2, "dir/file"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("attr entry was not evicted")
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := attrs.GetLookup(5, 0, 2, "dir/.DS_Store"); ok {
		t.Fatal("negative should miss after parent version was recorded from name-change invalidation")
	}

	sub.ch <- coherence.Batch{Invs: []coherence.Invalidation{{Recall: true, Path: "dir"}}}
	deadline = time.Now().Add(time.Second)
	for {
		h.mu.Lock()
		recalls, orphans, invalids := len(h.recalls), len(h.orphans), len(h.invalids)
		h.mu.Unlock()
		if recalls == 1 && orphans == 1 && invalids == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("handler calls did not arrive: recalls=%d orphans=%d invalids=%d", recalls, orphans, invalids)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStaleInvalidationStreamCannotRollGenerationBack(t *testing.T) {
	attrs := NewAttrCache()
	versions := NewVersionCache()
	sub := &fakeSub{ch: make(chan coherence.Batch, 4)}
	h := &fakeHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchInvalidations(ctx, sub, versions, attrs, h, InvalidationOptions{})

	waitGen := func(want uint64) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for versions.CurrentGen() != want {
			if time.Now().After(deadline) {
				t.Fatalf("generation = %d, want %d", versions.CurrentGen(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	sub.ch <- coherence.Batch{Invs: []coherence.Invalidation{{Gen: 11}}}
	waitGen(11)

	readToken := versions.CaptureToken()
	if _, ok := versions.AcceptGeneration(readToken, 22); !ok {
		t.Fatal("new-generation read could not re-anchor cache")
	}
	waitGen(22)

	// The original stream still carries its generation-11 token. Its delayed
	// batch may flush conservatively, but it must not adopt 11 or publish the
	// old version after the generation-22 read.
	sub.ch <- coherence.Batch{Invs: []coherence.Invalidation{{
		Gen: 11, Path: "p", Version: 999, InPlace: true,
	}}}
	time.Sleep(50 * time.Millisecond)
	if got := versions.CurrentGen(); got != 22 {
		t.Fatalf("stale stream rolled generation back to %d", got)
	}
	if _, version := versions.GenAndVersion("p"); version != 0 {
		t.Fatalf("stale stream published version %d", version)
	}
}

func TestCurrentGenerationStreamFlushSurvivesConcurrentReadAdoption(t *testing.T) {
	attrs := NewAttrCache()
	versions := NewVersionCache()
	sub := &fakeSub{ch: make(chan coherence.Batch, 4)}
	h := &fakeHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchInvalidations(ctx, sub, versions, attrs, h, InvalidationOptions{})

	deadline := time.Now().Add(time.Second)
	for {
		h.mu.Lock()
		started := h.flushes > 0
		h.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("subscription did not start")
		}
		time.Sleep(time.Millisecond)
	}

	// Model a read that adopts the subscribed authority's generation before
	// the stream's first event. The stream token captured at Subscribe is now
	// stale, but a same-generation overflow FlushAll must still drop every
	// retained version floor.
	versions.RefreshAll(7)
	versions.FillOK(7, "dir/file", 99)
	sub.ch <- coherence.Batch{Invs: []coherence.Invalidation{{Gen: 7, FlushAll: true}}}
	deadline = time.Now().Add(time.Second)
	for {
		if _, version := versions.GenAndVersion("dir/file"); version == 0 {
			break
		}
		if time.Now().After(deadline) {
			_, version := versions.GenAndVersion("dir/file")
			t.Fatalf("same-generation FlushAll retained version %d", version)
		}
		time.Sleep(time.Millisecond)
	}
	if got := versions.CurrentGen(); got != 7 {
		t.Fatalf("same-generation FlushAll changed generation to %d", got)
	}
}
