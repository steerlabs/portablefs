package clientcore

import (
	"context"
	"sync"

	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// gatedSubscriber reproduces the production subscription gap exactly.
//
// fsproto.Client.Subscribe returns as soon as the OpSubscribe request has been
// WRITTEN; the authority only adds the mount to its subscriber set (and starts
// delivering) when it reads that request. Mutations committed by a peer in
// between are published to a subscriber set this mount is not in, and the
// stream has no replay — they are lost. The gate turns that millisecond-wide
// window into a test-controlled one without changing any of the real
// client/server code paths that run inside it.
type gatedSubscriber struct {
	cli   *fsproto.Client
	gate  chan struct{}
	calls atomic.Int64

	mu  sync.Mutex
	ack fsproto.AckFunc
}

// forwardAck relays barrier acknowledgments to the real stream once it exists.
// Nothing can be delivered (and therefore acknowledged) before then.
func (g *gatedSubscriber) forwardAck(pos uint64) {
	g.mu.Lock()
	ack := g.ack
	g.mu.Unlock()
	if ack != nil {
		ack(pos)
	}
}

func (g *gatedSubscriber) Subscribe() (<-chan coherence.Batch, fsproto.AckFunc, error) {
	g.calls.Add(1)
	out := make(chan coherence.Batch, 256)
	go func() {
		defer close(out)
		<-g.gate
		stream, ack, err := g.cli.Subscribe()
		if err != nil {
			return
		}
		g.mu.Lock()
		g.ack = ack
		g.mu.Unlock()
		for batch := range stream {
			out <- batch
		}
	}()
	return out, g.forwardAck, nil
}

// gapHandler is the real volume handler plus a flush counter, so the test can
// wait for the watcher's own resubscribe flush before filling caches.
type gapHandler struct {
	volumeInvalidationHandler
	flushes atomic.Int64
}

func (h *gapHandler) FlushAll() {
	h.volumeInvalidationHandler.FlushAll()
	h.flushes.Add(1)
}

func anchorWaitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func hasEntry(ents []DirEntry, name string) bool {
	for _, e := range ents {
		if e.Name == name {
			return true
		}
	}
	return false
}

// TestSubscriptionGapPeerCreateCannotServeStaleListing pins the cross-machine
// invalidation race that made a peer's create invisible for minutes: a
// directory listing cached BEFORE the authority registered this mount as an
// invalidation subscriber must never be served after the subscription is
// established, because no event for that window can ever arrive to evict it.
func TestSubscriptionGapPeerCreateCannotServeStaleListing(t *testing.T) {
	addr := serveCore(t)

	peer, err := fsproto.Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	peer.SetOwner("peer")
	if live, err := peer.EnsureExactSession(); err != nil || !live {
		t.Fatalf("peer exact session: live=%v err=%v", live, err)
	}

	mount := dialCore(t, addr, Options{Owner: "mount"})

	gate := make(chan struct{})
	sub := &gatedSubscriber{cli: mount.client, gate: gate}
	h := &gapHandler{volumeInvalidationHandler: volumeInvalidationHandler{v: mount}}
	ictx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchInvalidations(ictx, sub, mount.VersionCache, mount.AttrCache, h, InvalidationOptions{
		ClearRecent: mount.recent.clear,
	})
	// The watcher's own post-subscribe flush must land before the mount fills
	// any cache: the whole point is that the fill happens AFTER the client
	// thinks it subscribed and BEFORE the authority registered it.
	anchorWaitFor(t, "watcher subscribe flush", 5*time.Second, func() bool { return h.flushes.Load() >= 1 })

	ctx, cancelOps := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelOps()

	// The attach's first read (portablefsd does a root getattr + the frontend
	// enumerates) populates the mount's caches inside the gap.
	before, st := mount.Readdir(ctx, "")
	if st != fsproto.OK {
		t.Fatalf("pre-create readdir: %d", st)
	}
	if hasEntry(before, "sync") {
		t.Fatal("peer directory existed before the peer created it")
	}

	// The peer's create commits on the authority while this mount is still
	// unregistered: its invalidation is published to a subscriber set the
	// mount is not in and is lost forever.
	if _, st, err := peer.Mkdir("sync", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("peer mkdir: status=%d err=%v", st, err)
	}

	// Now let the subscription actually establish.
	close(gate)
	anchorWaitFor(t, "authority subscribe", 5*time.Second, func() bool { return sub.calls.Load() >= 1 })

	// The anchor must fence away the pre-registration listing. Poll: the fix
	// is event-ordered, not timer-driven, so this settles immediately — an
	// unfixed mount never converges (in production it stayed stale until an
	// unrelated authority round trip happened to bump the root version).
	deadline := time.Now().Add(5 * time.Second)
	for {
		ents, st := mount.Readdir(ctx, "")
		if st != fsproto.OK {
			t.Fatalf("post-create readdir: %d", st)
		}
		if hasEntry(ents, "sync") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("mount served the pre-subscription root listing after the "+
				"subscription was established: %v", ents)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSubscriptionAnchorDropsPreAnchorVersionFills is the unit-level statement
// of the same rule against VersionCache directly: the bootstrap message is a
// fence, not merely a generation announcement. A read that raced the subscribe
// and adopted the SAME generation used to make the bootstrap a no-op, which is
// precisely how a pre-registration fill survived.
func TestSubscriptionAnchorDropsPreAnchorVersionFills(t *testing.T) {
	const gen = uint64(7)

	attrs := NewAttrCache()
	versions := NewVersionCache()
	sub := &fakeSub{ch: make(chan coherence.Batch, 4)}
	h := &fakeHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchInvalidations(ctx, sub, versions, attrs, h, InvalidationOptions{})

	anchorWaitFor(t, "watcher start flush", 5*time.Second, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.flushes >= 1
	})

	// A frontend read racing the subscribe adopts the generation and fills a
	// version + attr for the root directory.
	token, ok := versions.AcceptGeneration(versions.CaptureToken(), gen)
	if !ok {
		t.Fatal("racing read could not adopt the authority generation")
	}
	if !versions.FillOKToken(token, gen, "", 41) {
		t.Fatal("racing read could not fill the root version")
	}
	attrs.PutAttr(gen, 41, "", fsproto.Attr{})
	if _, version, valid := versions.CacheState(""); !valid || version != 41 {
		t.Fatalf("pre-anchor fill did not take: version=%d valid=%v", version, valid)
	}

	// The authority's bootstrap message: from here on every event is
	// delivered, and nothing cached before it is ordered against the stream.
	sub.ch <- coherence.Batch{Pos: 12, Bootstrap: true, Invs: []coherence.Invalidation{{Gen: gen}}}

	anchorWaitFor(t, "anchor to drop the pre-anchor fill", 5*time.Second, func() bool {
		_, version, valid := versions.CacheState("")
		return valid && version == 0
	})
	if _, ok := attrs.Get(gen, 41, ""); ok {
		t.Fatal("attr cached before the subscription anchor survived it")
	}
}
