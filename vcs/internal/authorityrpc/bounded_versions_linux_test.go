//go:build linux

package authorityrpc

import (
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

func TestVersionExhaustionRefusesBeforeStorageApply(t *testing.T) {
	for _, profile := range []string{"linux", "fskit"} {
		t.Run(profile, func(t *testing.T) {
			var h *VolumeHandler
			var cred volumeserver.SessionCredential
			var target *writeTestTarget
			var syncs func() uint32
			if profile == "fskit" {
				var store *fskitDurabilityTestStore
				h, cred, store, target = newDirectFskitHarness(t)
				syncs = func() uint32 { return uint32(store.syncs.Load()) }
			} else {
				var store *writeTestStore
				h, cred, store = newWriteHarness(t)
				target = &writeTestTarget{}
				prepareOneShotTarget(t, h, cred, store, target)
				syncs = func() uint32 { return store.durableHandles.Load() }
			}
			h.initCoherence()
			h.coherenceVersion = math.MaxUint64
			req := directFskitRequest()
			response := h.handleWrite(t.Context(), req, cred, req.GetWrite())
			if response.GetErrno() == 0 || response.GetUncertain() || response.GetPostState() != nil {
				t.Fatalf("sequence exhaustion was not a pre-apply refusal: %v", response)
			}
			if calls, _ := target.directSnapshot(); calls != 0 || syncs() != 0 || h.coherenceVersion != math.MaxUint64 || h.coherencePending != 0 {
				t.Fatalf("exhausted sequence applied/synced/wrapped: calls=%d syncs=%d version=%d pending=%d", calls, syncs(), h.coherenceVersion, h.coherencePending)
			}
		})
	}
}

func TestLastCommitCapacityIsReservedAcrossConcurrentApplies(t *testing.T) {
	h := testVolumeHandler()
	h.initCoherence()
	h.coherenceVersion = math.MaxUint64 - 1
	var wg sync.WaitGroup
	releases := make(chan func(), 2)
	errorsSeen := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			release, err := h.reserveCoherenceCommit()
			if err == nil {
				releases <- release
			} else {
				errorsSeen <- err
			}
		})
	}
	wg.Wait()
	if len(releases) != 1 || len(errorsSeen) != 1 || !errors.Is(<-errorsSeen, volumeserver.ErrAdmission) {
		t.Fatal("concurrent applies overbooked the last sequence")
	}
	(<-releases)() // A no-op does not consume its reserved sequence.
	release, err := h.reserveCoherenceCommit()
	if err != nil {
		t.Fatal(err)
	}
	h.publishCoherenceCommit(&authoritypb.Request{}, volumeserver.SessionID{}, [16]byte{}, &authoritypb.Response{}, []volumeserver.MutationTarget{}, &mutationChanges{})
	release()
	if _, err := h.reserveCoherenceCommit(); !errors.Is(err, volumeserver.ErrMutationPoisoned) || h.coherenceVersion != math.MaxUint64 || h.coherencePending != 0 {
		t.Fatalf("last commit wrapped or leaked reservation: %v", err)
	}
}

func TestConservativeVersionsStayBoundedAcrossCompaction(t *testing.T) {
	h := testVolumeHandler()
	h.initCoherence()
	h.objectVersionLimit = 4
	retained := postStateTestIdentity(1)
	var last uint64
	var saved *authoritypb.Response
	for n := byte(1); n < 120; n++ {
		identity := postStateTestIdentity(n)
		changed := new(mutationChanges)
		response := &authoritypb.Response{PostState: h.mutationPostState(changed, 1,
			postStateSnapshot{identity: identity, attr: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(n), Size: int64(n)}, roles: postStateRoleCreated, changed: true},
			postStateSnapshot{identity: retained, attr: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 1, Size: 1}, roles: postStateRoleParent})}
		h.publishCoherenceCommit(&authoritypb.Request{}, volumeserver.SessionID{}, [16]byte{}, response, []volumeserver.MutationTarget{}, changed)
		if n == 1 {
			saved = proto.Clone(response).(*authoritypb.Response)
		}
		sequence, stamps := h.sampleVersions(retained, identity)
		if len(h.objectVersions) > 4 || stamps[0] < last || stamps[0] == 0 || stamps[0] > sequence || stamps[1] != sequence {
			t.Fatalf("n=%d occupancy=%d sequence=%d stamps=%v previous=%d", n, len(h.objectVersions), sequence, stamps, last)
		}
		last = stamps[0]
	}
	if h.objectVersionFloor <= 1 {
		t.Fatal("churn did not compact")
	}
	if saved.GetPostState().GetSnapshotSequence() != 2 || saved.GetPostState().GetObjects()[0].GetObjectVersion() != 2 {
		t.Fatal("compaction restamped retained outcome")
	}
	// A no-op carries current conservative stamps, without inventing a commit.
	before := h.coherenceVersionNow()
	changed := new(mutationChanges)
	response := &authoritypb.Response{PostState: h.mutationPostState(changed, 1, postStateSnapshot{identity: retained, attr: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 1}, roles: postStateRoleTarget})}
	h.publishCoherenceCommit(&authoritypb.Request{}, volumeserver.SessionID{}, [16]byte{}, response, nil, changed)
	if response.GetVolumeVersion() != before || h.coherenceVersionNow() != before {
		t.Fatal("no-op allocated a commit")
	}
}

func TestChangeStreamUsesExplicitChangedIdentities(t *testing.T) {
	changedID, unchangedID := postStateTestIdentity(1), postStateTestIdentity(2)
	changes := &mutationChanges{}
	changes.add(changedID)
	response := &authoritypb.Response{PostState: &authoritypb.PostState{Objects: []*authoritypb.ObjectPostState{
		{StableIdentity: changedID[:], ObjectVersion: 9}, {StableIdentity: unchangedID[:], ObjectVersion: 9},
	}}}
	targets := []volumeserver.MutationTarget{{Scope: volumeserver.MutationAttributes, Identity: unchangedID}, {Scope: volumeserver.MutationData, Identity: changedID}}
	entries := coherenceChanges(&authoritypb.Request{}, response, targets, 9, changes)
	if len(entries) != 2 {
		t.Fatalf("changes=%v", entries)
	}
	for _, entry := range entries {
		if entry.Identity != changedID {
			t.Fatal("unchanged identity emitted from conservative stamp equality")
		}
	}
}

func TestVersionExhaustionDoesNotWrap(t *testing.T) {
	h := testVolumeHandler()
	h.initCoherence()
	h.coherenceVersion = math.MaxUint64
	defer func() {
		if recover() == nil {
			t.Fatal("sequence exhaustion did not fail closed")
		}
		if h.coherenceVersion != math.MaxUint64 {
			t.Fatal("sequence wrapped")
		}
	}()
	h.publishCoherenceCommit(&authoritypb.Request{}, volumeserver.SessionID{}, [16]byte{}, &authoritypb.Response{}, []volumeserver.MutationTarget{}, &mutationChanges{})
}

func TestUncertainEffectWithoutPostStateStillAdvancesVersion(t *testing.T) {
	h := testVolumeHandler()
	h.initCoherence()
	identity := postStateTestIdentity(1)
	changed := new(mutationChanges)
	response := &authoritypb.Response{Uncertain: true}
	targets := []volumeserver.MutationTarget{{Scope: volumeserver.MutationData, Identity: identity}, {Scope: volumeserver.MutationAttributes, Identity: identity}}
	h.publishCoherenceCommit(&authoritypb.Request{}, volumeserver.SessionID{}, [16]byte{}, response, targets, changed)
	sequence, versions := h.sampleVersions(identity)
	if !changed.contains(identity) || versions[0] != sequence || len(coherenceChanges(&authoritypb.Request{}, response, targets, sequence, changed)) != 2 {
		t.Fatal("missing exact post-state erased a possibly applied inode effect")
	}
}
