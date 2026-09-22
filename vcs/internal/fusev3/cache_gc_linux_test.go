//go:build linux

package fusev3

import (
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func TestSlowMetadataCacheWaitsForCollectionAndRechecksOwnership(t *testing.T) {
	for _, operation := range []string{"lookup", "getattr"} {
		for _, ownsAfter := range []bool{false, true} {
			name := operation + "/collection"
			if ownsAfter {
				name = operation + "/new-grant"
			}
			t.Run(name, func(t *testing.T) {
				f := newStrictFixture(t)
				entry := f.lookup(t, 1, "file")
				parent, record := f.raw.acquire(1), f.raw.acquire(entry.NodeId)
				defer f.raw.release(parent)
				defer f.raw.release(record)
				unique := f.unique.Add(2)
				ctx, finish, status := f.raw.mutationContext(unique)
				if status != fuse.OK {
					t.Fatal(status)
				}
				defer func() { finish(); completeTestReply(t, f.raw, unique, fuse.OK) }()
				m := f.mount.delegations
				s := m.retainState(writeback.Identity(record.identity), true)
				defer m.releaseState(s)
				// Match the collector's index/admission lock order. The active
				// metadata request retains transition history if collection wins.
				m.mu.Lock()
				s.admission.Lock()
				done := make(chan bool, 1)
				go func() {
					if operation == "getattr" {
						attr, hit := f.raw.cachedAttrRecord(ctx, record)
						done <- hit && attr.GetInode() == record.key.inode
						return
					}
					found, attr, negative := f.raw.cachedLookup(ctx, parent, "file")
					done <- !negative && found == record && attr.GetInode() == record.key.inode
				}()
				var premature *bool
				select {
				case hit := <-done:
					premature = &hit
				case <-time.After(20 * time.Millisecond):
				}
				if ownsAfter {
					s.ref = &authoritypb.DelegationRef{Id: []byte("new"), Generation: 1}
				}
				s.admission.Unlock()
				m.mu.Unlock()
				if premature != nil {
					t.Fatalf("cache read did not join local ownership work: hit=%v", *premature)
				}
				select {
				case hit := <-done:
					if hit == ownsAfter {
						t.Fatalf("cache hit=%v after ownership=%v", hit, ownsAfter)
					}
				case <-time.After(time.Second):
					t.Fatal("cache read stayed blocked after local ownership work")
				}
			})
		}
	}
}

func TestColdSubscriptionInterruptsWaitingMetadataCacheReader(t *testing.T) {
	for _, operation := range []string{"lookup", "getattr"} {
		t.Run(operation, func(t *testing.T) {
			f := newStrictFixture(t)
			entry := f.lookup(t, 1, "file")
			parent, record := f.raw.acquire(1), f.raw.acquire(entry.NodeId)
			defer f.raw.release(parent)
			defer f.raw.release(record)
			unique := f.unique.Add(2)
			ctx, finish, status := f.raw.mutationContext(unique)
			if status != fuse.OK {
				t.Fatal(status)
			}
			m := f.mount.delegations
			s := m.retainState(writeback.Identity(record.identity), true)
			defer m.releaseState(s)
			s.admission.Lock()
			locked := true
			defer func() {
				if locked {
					s.admission.Unlock()
				}
			}()
			read := make(chan bool, 1)
			go func() {
				var hit bool
				if operation == "getattr" {
					_, hit = f.raw.cachedAttrRecord(ctx, record)
				} else {
					found, _, _ := f.raw.cachedLookup(ctx, parent, "file")
					hit = found != nil
				}
				finish()
				read <- hit
			}()
			waitFor(t, "metadata cache reader waiting on ownership", func() bool { return s.users.Load() == 2 })
			old := m.buf
			cold := make(chan error, 1)
			go func() { cold <- f.mount.subscription.subscribe(t.Context()) }()
			waitFor(t, "cold subscription interrupted cache reader", func() bool { return m.incarnation() == 0 })
			if m.buf != old {
				t.Fatal("ownership reset crossed the waiting metadata callback")
			}
			select {
			case err := <-cold:
				t.Fatalf("cold subscription crossed the waiting metadata callback: %v", err)
			default:
			}
			s.admission.Unlock()
			locked = false
			select {
			case hit := <-read:
				if hit {
					t.Fatal("interrupted metadata cache reader served the old incarnation")
				}
			case <-time.After(time.Second):
				t.Fatal("metadata cache reader did not leave after local ownership work")
			}
			completeTestReply(t, f.raw, unique, fuse.OK)
			select {
			case err := <-cold:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cold subscription did not follow metadata callback drain")
			}
			if m.incarnation() == 0 || m.buf == old || m.LossSequence() != 0 || f.mount.isRevoked() {
				t.Fatalf("cold completion incarnation=%d old-buffer=%v loss=%d revoked=%v", m.incarnation(), m.buf == old, m.LossSequence(), f.mount.isRevoked())
			}
		})
	}
}
