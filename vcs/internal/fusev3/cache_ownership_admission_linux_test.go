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
				m.byID[id] = &delegationState{}
			case "owned":
				m.byID[id] = &delegationState{ref: &authoritypb.DelegationRef{}}
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
