//go:build linux

package fusev3

import (
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"testing"
	"time"
)

// Post-state admission holds raw.mu. It cannot wait on a retiring grant: the
// old grant may be pinned by a physical reply whose settlement needs raw.mu.
func TestCacheAdmissionDoesNotWaitForDelegationOwnership(t *testing.T) {
	for _, kind := range []string{"epoch", "registry", "retirement"} {
		t.Run(kind, func(t *testing.T) {
			f, entry := dirtyHolderMetadataFixture(t)
			m := f.mount.delegations
			record := f.raw.nodesByID[entry.NodeId]
			s := m.lookupState(writeback.Identity(record.identity))
			stamp := f.mount.subscription.stamp()
			coordinate := publicationCoordinate{kind: publicationItemAttributes, item: record.identity}
			var unlock func()
			switch kind {
			case "epoch":
				m.epoch.Lock()
				unlock = m.epoch.Unlock
			case "registry":
				m.mu.Lock()
				unlock = m.mu.Unlock
			case "retirement":
				// Model the transferred physical-reply pin and a queued retirer.
				s.admission.RLock()
				acquired, release, released := make(chan struct{}), make(chan struct{}), make(chan struct{})
				go func() {
					s.admission.Lock()
					close(acquired)
					<-release
					s.admission.Unlock()
					close(released)
				}()
				unlock = func() { s.admission.RUnlock(); <-acquired; close(release); <-released }
				defer func() {
					if unlock != nil {
						unlock()
					}
				}()
				waitUntil(t, time.Second, "queued retirement writer", func() bool {
					if s.admission.TryRLock() {
						s.admission.RUnlock()
						return false
					}
					return true
				})
			}
			done := make(chan time.Duration, 1)
			go func() {
				f.raw.mu.Lock()
				remaining := f.mount.subscription.remaining(coordinate, stamp, stamp.version, time.Now())
				f.raw.mu.Unlock()
				done <- remaining
			}()
			select {
			case remaining := <-done:
				unlock()
				unlock = nil
				if remaining != 0 {
					t.Fatalf("uncertain ownership admitted cache for %v", remaining)
				}
			case <-time.After(100 * time.Millisecond):
				unlock()
				unlock = nil
				<-done
				t.Fatal("cache admission held raw registry while waiting for delegation ownership")
			}
		})
	}
}

func TestSharedCacheOwnershipRequiresKnownUnownedIdentity(t *testing.T) {
	id := writeback.Identity{1}
	for _, kind := range []string{"absent", "retired", "owned", "inactive", "invalid", "nil"} {
		t.Run(kind, func(t *testing.T) {
			m := &delegationManager{byID: make(map[writeback.Identity]*delegationState)}
			m.SetIncarnation(1)
			identity := id[:]
			switch kind {
			case "retired":
				_ = m.state(id)
			case "owned":
				m.state(id).ref = &authoritypb.DelegationRef{}
			case "inactive":
				m.SetIncarnation(0)
			case "invalid":
				identity = nil
			case "nil":
				m = nil
			}
			want := kind == "absent" || kind == "retired"
			if got := m.sharedCacheAllowed(identity); got != want {
				t.Fatalf("allowed=%v want %v", got, want)
			}
		})
	}
}

func TestSharedCacheAdmissionSurvivesUnrelatedRegistryWriter(t *testing.T) {
	for _, kind := range []string{"absent", "retired", "owned"} {
		t.Run(kind, func(t *testing.T) {
			m := newDelegationTestManager(t, &delegationFakeRPC{})
			id := writeback.Identity{31}
			if kind != "absent" {
				s := m.state(id)
				if kind == "owned" {
					s.ref = &authoritypb.DelegationRef{}
				}
			}
			m.mu.Lock()
			done := make(chan bool, 1)
			go func() { done <- m.sharedCacheAllowed(id[:]) }()
			select {
			case allowed := <-done:
				m.mu.Unlock()
				if allowed != (kind != "owned") {
					t.Fatalf("unrelated registry writer changed ownership admission: allowed=%v", allowed)
				}
			case <-time.After(time.Second):
				m.mu.Unlock()
				<-done
				t.Fatal("ownership observation waited for unrelated registry writer")
			}
		})
	}
}

func TestSharedCacheStateIndexClearsOnEpochReplacement(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := writeback.Identity{32}
	old := m.state(id)
	if value, ok := m.stateIndex.Load(id); !ok || value != old {
		t.Fatal("state was not indexed before publication")
	}
	m.EpochChanged("index epoch test")
	if _, ok := m.stateIndex.Load(id); ok {
		t.Fatal("old epoch state remains indexed")
	}
	if m.lookupState(id) != nil {
		t.Fatal("old epoch remains in canonical registry")
	}
	current := m.state(id)
	if current == old {
		t.Fatal("epoch reused old state")
	}
	if value, ok := m.stateIndex.Load(id); !ok || value != current {
		t.Fatal("new epoch index is inconsistent")
	}
	if allocations := testing.AllocsPerRun(1000, func() { _ = m.sharedCacheAllowed(id[:]) }); allocations != 0 {
		t.Fatalf("indexed ownership allocated %g times", allocations)
	}
}
