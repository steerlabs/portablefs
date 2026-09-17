package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTargetedWithdrawalCoversEveryCacheScope(t *testing.T) {
	id, parent, other := [16]byte{1}, [16]byte{2}, [16]byte{3}
	for _, tt := range []struct {
		name   string
		admit  CacheAdmission
		change ChangeEntry
	}{
		{"negative-name", CacheAdmission{Directories: [][16]byte{parent}}, ChangeEntry{Kind: NamespaceChanged, ParentIdentity: parent, Name: "missing"}},
		{"enumeration", CacheAdmission{Directories: [][16]byte{parent}}, ChangeEntry{Kind: DirectoryChanged, Identity: parent}},
		{"hardlink-attribute-through-other-parent", CacheAdmission{Directories: [][16]byte{other}, Attributes: [][16]byte{id}}, ChangeEntry{Kind: AttributesChanged, Identity: id}},
		{"parent-getattr", CacheAdmission{Attributes: [][16]byte{parent}}, ChangeEntry{Kind: AttributesChanged, Identity: parent}},
		{"resident-pages", CacheAdmission{Data: [][16]byte{id}}, ChangeEntry{Kind: DataChanged, Identity: id}},
		{"future-kind-fails-closed", CacheAdmission{}, ChangeEntry{Kind: ChangeKind(255), Identity: id}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCoherenceCoordinator(CoherenceConfig{})
			source, _ := c.Subscribe(SessionID{1})
			peer, _ := c.Subscribe(SessionID{2})
			unrelated, _ := c.Subscribe(SessionID{3})
			if err := c.AdmitCache(peer.Token, tt.admit); err != nil {
				t.Fatal(err)
			}
			if err := c.AdmitCache(unrelated.Token, CacheAdmission{Directories: [][16]byte{other}, Attributes: [][16]byte{other}, Data: [][16]byte{other}}); err != nil {
				t.Fatal(err)
			}
			w := c.OnCommitTargeted([]ChangeEntry{tt.change}, source.Token, CacheAdmission{})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			if err := c.WaitTargeted(ctx, w); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unwithdrawn cached fact returned %v", err)
			}
			events, err := c.Poll(t.Context(), peer.Token, peer.Position, nil, 8)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Ack(peer.Token, events[len(events)-1].Position); err != nil {
				t.Fatal(err)
			}
			if tt.change.Kind == ChangeKind(255) {
				events, err = c.Poll(t.Context(), unrelated.Token, unrelated.Position, nil, 8)
				if err != nil {
					t.Fatal(err)
				}
				if err = c.Ack(unrelated.Token, events[len(events)-1].Position); err != nil {
					t.Fatal(err)
				}
			}
			ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
			defer cancel2()
			if err := c.WaitTargeted(ctx2, w); err != nil {
				t.Fatalf("unrelated subscriber delayed withdrawal: %v", err)
			}
		})
	}
}

func TestCacheFootprintOverflowIsConservativeAndColdScoped(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{MaxCacheFootprint: 1})
	source, _ := c.Subscribe(SessionID{1})
	peer, _ := c.Subscribe(SessionID{2})
	if err := c.AdmitCache(peer.Token, CacheAdmission{Directories: [][16]byte{{1}, {2}}}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	s := c.subscribers[peer.Token.Session]
	if !s.directories.all || s.attributes.all || s.data.all || len(s.directories.identities) != 0 {
		t.Fatal("overflow is not bounded/per-scope")
	}
	c.mu.Unlock()
	w := c.OnCommitTargeted([]ChangeEntry{{Kind: NamespaceChanged, ParentIdentity: [16]byte{99}}}, source.Token, CacheAdmission{})
	if len(w.targets) != 1 {
		t.Fatal("overflow evicted an obligation")
	}
	replacement, err := c.Subscribe(peer.Token.Session)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WaitTargeted(t.Context(), w); err != nil {
		t.Fatal(err)
	}
	if err := c.AdmitCache(peer.Token, CacheAdmission{Data: [][16]byte{{9}}}); err == nil {
		t.Fatal("old reply admitted to cold successor")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s = c.subscribers[replacement.Token.Session]
	if s.directories.all || len(s.directories.identities) != 0 || len(s.data.identities) != 0 {
		t.Fatal("cold scope inherited old facts")
	}
}

func TestCacheDataFootprintSurvivesCloseAndColdLiveHandle(t *testing.T) {
	for _, closeHandle := range []bool{false, true} {
		t.Run(map[bool]string{false: "live-cold-handle", true: "closed-resident-pages"}[closeHandle], func(t *testing.T) {
			c := NewCoherenceCoordinator(CoherenceConfig{})
			source, _ := c.Subscribe(SessionID{1})
			peer, _ := c.Subscribe(SessionID{2})
			id := [16]byte{3}
			if allowed, err := c.OpenCacheCapable(peer.Token, id); err != nil || !allowed {
				t.Fatalf("open %v %v", allowed, err)
			}
			if closeHandle {
				if err := c.CloseCacheCapable(peer.Token, id); err != nil {
					t.Fatal(err)
				}
			} else {
				peer, _ = c.Subscribe(peer.Token.Session)
			}
			w := c.OnCommitTargeted([]ChangeEntry{{Kind: DataChanged, Identity: id}}, source.Token, CacheAdmission{})
			if len(w.targets) != 1 || w.targets[0] != peer.Token {
				t.Fatal("resident/refillable pages lost their withdrawal target")
			}
		})
	}
}

func TestTargetedSourceOwnershipUsesExactIncarnation(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{})
	old, _ := c.Subscribe(SessionID{1})
	current, _ := c.SubscribeWithCache(old.Token.Session, CacheAdmission{Attributes: [][16]byte{{2}}})
	w := c.OnCommitTargeted([]ChangeEntry{{Kind: AttributesChanged, Identity: [16]byte{2}}}, old.Token, CacheAdmission{Directories: [][16]byte{{9}}})
	if len(w.targets) != 1 || w.targets[0] != current.Token {
		t.Fatal("cold source successor inherited old source exclusion")
	}
	events, _, err := c.PollControl(t.Context(), current.Token, current.Position, nil, 8)
	if err != nil || len(events) != 1 || events[0].Kind != StreamChange {
		t.Fatalf("old-source event suppressed: %v %v", events, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.subscribers[current.Token.Session].directories.has([16]byte{9}) {
		t.Fatal("old source reply seeded successor")
	}
}

func TestTargetedSourceAdmissionWithoutCommitAndAfterCommitSnapshot(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{})
	a, _ := c.Subscribe(SessionID{1})
	b, _ := c.Subscribe(SessionID{2})
	id := [16]byte{3}
	if w := c.OnCommitTargeted(nil, a.Token, CacheAdmission{Directories: [][16]byte{id}}); w.Position != 0 {
		t.Fatal("unchanged source fabricated a commit")
	}
	w := c.OnCommitTargeted([]ChangeEntry{{Kind: NamespaceChanged, ParentIdentity: id}}, b.Token, CacheAdmission{})
	if len(w.targets) != 1 || w.targets[0] != a.Token {
		t.Fatal("zero-change CREATE cache admission missing")
	}
	late, _ := c.Subscribe(SessionID{3})
	if err := c.AdmitCache(late.Token, CacheAdmission{Directories: [][16]byte{id}}); err != nil {
		t.Fatal(err)
	}
	if len(w.targets) != 1 {
		t.Fatal("later read extended prior withdrawal cut")
	}
}

func TestTargetedWithdrawalDeadlineDoesNotMoveWithRenewal(t *testing.T) {
	clock := newCV2Clock()
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: clock})
	source, _ := c.Subscribe(SessionID{1})
	peer, _ := c.Subscribe(SessionID{2})
	id := [16]byte{7}
	if err := c.AdmitCache(peer.Token, CacheAdmission{Data: [][16]byte{id}}); err != nil {
		t.Fatal(err)
	}
	w := c.OnCommitTargeted([]ChangeEntry{{Kind: DataChanged, Identity: id}}, source.Token, CacheAdmission{})
	done := make(chan error, 1)
	go func() { done <- c.WaitTargeted(t.Context(), w) }()
	for range 3 {
		clock.Advance(3 * time.Second)
		if _, err := c.Renew(peer.Token); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("withdrawal completed before its fixed deadline: %v", err)
	default:
	}
	clock.Advance(time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("renewals extended withdrawal beyond its issue-time deadline")
	}
	if err := c.CheckSession(peer.Token); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("target after fixed withdrawal deadline = %v, want fenced", err)
	}
}

func TestCacheHandleCloseUsesSessionOwnershipAcrossColdSubscribe(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{})
	old, _ := c.Subscribe(SessionID{1})
	id := [16]byte{2}
	if allowed, err := c.OpenCacheCapable(old.Token, id); err != nil || !allowed {
		t.Fatal(allowed, err)
	}
	current, _ := c.Subscribe(old.Token.Session)
	c.CloseCacheCapableSession(old.Token.Session, id)
	c.mu.Lock()
	if c.subscribers[current.Token.Session].handles[id] != 0 || c.cacheHandles[id] != nil {
		t.Fatal("close stranded transferred cache handle")
	}
	if !c.subscribers[current.Token.Session].data.has(id) {
		t.Fatal("close erased retained-page footprint")
	}
	c.mu.Unlock()
	next, _ := c.Subscribe(old.Token.Session)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.subscribers[next.Token.Session].data.has(id) {
		t.Fatal("retired handle was carried through another cold boundary")
	}
}
