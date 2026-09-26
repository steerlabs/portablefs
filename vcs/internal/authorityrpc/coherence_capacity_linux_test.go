//go:build linux

package authorityrpc

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestCoherenceCreateCapacityRefusalPrecedesStorageAndReplays(t *testing.T) {
	for _, scope := range []string{"session", "volume"} {
		t.Run(scope, func(t *testing.T) {
			store := &coherenceCreateStore{entered: make(chan bool, 1), proceed: make(chan struct{})}
			close(store.proceed)
			h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 8, 8)
			store.h = h
			h.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{MaxDelegationsPerSession: 1, MaxDelegations: 1})
			_, token := subscribeCoherenceControlTest(t, h, cred.ID)
			owner, want := token, errnos.EMFILE
			if scope == "volume" {
				peer, err := h.Coherence.Subscribe(volumeserver.SessionID{0xee})
				if err != nil {
					t.Fatal(err)
				}
				owner, want = peer.Token, errnos.ENFILE
			}
			capacity, err := h.Coherence.ReserveDelegationCapacity(owner)
			if err != nil {
				t.Fatal(err)
			}
			request := coherenceExistingCreateRequest(cred, root)
			response := h.Handle(ctx, request)
			if response.GetErrno() != want || response.GetUncertain() || store.bound.Load() {
				t.Fatalf("capacity refusal crossed storage: response=%v bound=%v", response, store.bound.Load())
			}
			capacity.Release()
			response = h.Handle(ctx, request)
			if response.GetErrno() != want || store.bound.Load() {
				t.Fatalf("retry reapplied recorded capacity refusal: %v", response)
			}
			if stats := h.Coherence.Stats(); stats.DelegationCapacityReservations != 0 || stats.DelegationsReserved != 0 || stats.DelegationsActive != 0 {
				t.Fatalf("failed CREATE leaked authority: %+v", stats)
			}

		})
	}
}
