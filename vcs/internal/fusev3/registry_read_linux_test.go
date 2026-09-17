//go:build linux

package fusev3

import (
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type registryReadLocker interface {
	RLock()
	RUnlock()
}

func TestRegistryReadersCanOverlap(t *testing.T) {
	r := &rawFileSystem{replyLifecycleArmed: true, replyPublications: map[uint64]*replyPublication{1: {}}}
	id := writeback.Identity{1}
	s := &delegationState{}
	m := &delegationManager{byID: map[writeback.Identity]*delegationState{id: s}, identityLoss: map[writeback.Identity]uint64{id: 7}}
	var err error
	m.buf, err = writeback.New(m, writeback.Options{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	parent := publicationIdentity{2}
	child := publicationIdentity{3}
	n := &node{mount: &Mount{raw: r}, item: &authoritypb.Item{StableIdentity: parent[:]}}
	r.cachedStableNames = map[publicationNamespace]*inodeRecord{{parent: parent, name: "cached"}: {identity: child, node: &node{}}}
	r.cachedData = map[uint64]*inodeRecord{1: {}}
	for _, tc := range []struct {
		name string
		lock any
		read func() bool
	}{
		{"physical reply", &r.mu, func() bool { return r.ReplyWriteTracked(1) }},
		{"lifecycle", &r.mu, r.replyLifecycleReady},
		{"delegation", &m.mu, func() bool { return m.lookupState(id) == s }},
		{"existing delegation", &m.mu, func() bool { return m.state(id) == s }},
		{"binding", &r.mu, func() bool { got, ok := n.cachedBoundIdentity("cached"); return ok && got == child }},
		{"data obligation", &r.mu, func() bool { return r.cachedDataHolds(1) }},
		{"loss", &m.mu, func() bool { return m.IdentityLoss(id[:]) == 7 }},
		{"failure", &m.mu, func() bool { loss, errno := m.IdentityFailure(id[:], 0); return loss == 7 && errno == 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lock, ok := tc.lock.(registryReadLocker)
			if !ok {
				t.Fatal("read-only registry operations still require exclusive admission")
			}
			lock.RLock()
			done := make(chan bool, 1)
			go func() { done <- tc.read() }()
			select {
			case correct := <-done:
				lock.RUnlock()
				if !correct {
					t.Fatal("reader lost registry state")
				}
			case <-time.After(time.Second):
				lock.RUnlock()
				<-done
				t.Fatal("read-only operation waited for another reader")
			}
		})
	}
}

func BenchmarkPhysicalReplyRegistryRead(b *testing.B) {
	r := &rawFileSystem{replyPublications: map[uint64]*replyPublication{1: {}}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !r.ReplyWriteTracked(1) {
				b.Fatal("missing reply")
			}
		}
	})
}
