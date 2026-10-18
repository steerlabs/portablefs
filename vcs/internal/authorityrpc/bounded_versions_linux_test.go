//go:build linux

package authorityrpc

import (
	"math"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

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
