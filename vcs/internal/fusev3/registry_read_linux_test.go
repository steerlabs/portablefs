//go:build linux

package fusev3

import (
	"testing"
	"time"

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
	m := &delegationManager{byID: map[writeback.Identity]*delegationState{id: s}}
	for _, tc := range []struct {
		name string
		lock any
		read func() bool
	}{
		{"physical reply", &r.mu, func() bool { return r.ReplyWriteTracked(1) }},
		{"lifecycle", &r.mu, r.replyLifecycleReady},
		{"delegation", &m.mu, func() bool { return m.lookupState(id) == s }},
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
