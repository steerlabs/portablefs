//go:build linux

package authorityrpc

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type wireLeaseTestFencer struct{}

func (wireLeaseTestFencer) FenceSession(volumeserver.SessionID) {}

func TestLeaseCoordinateRejectsZeroIdentity(t *testing.T) {
	tests := []*authoritypb.LeaseCoordinate{
		{Family: authoritypb.LeaseFamily_LEASE_FAMILY_NAME, ParentIdentity: make([]byte, 16), Name: []byte("entry")},
		{Family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, Identity: make([]byte, 16)},
	}
	for _, coordinate := range tests {
		if _, err := leaseCoordinate(coordinate); err == nil {
			t.Fatalf("leaseCoordinate(%+v) accepted an all-zero identity", coordinate)
		}
	}
}

func TestLeaseGrantsProtoOmitsExpiredGrant(t *testing.T) {
	now := time.Unix(100, 0)
	coordinator, err := volumeserver.NewLeaseCoordinator(volumeserver.LeaseConfig{
		TTL: time.Second, RecallBudget: time.Second, MaxPerHolder: 4096, MaxTotal: 16384, PriorGrantsFenced: true,
		Now: func() time.Time { return now }, Fencer: wireLeaseTestFencer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var holder volumeserver.SessionID
	holder[0] = 1
	if err := coordinator.ActivateHolder(holder, make(chan struct{})); err != nil {
		t.Fatal(err)
	}
	var identity [16]byte
	identity[0] = 1
	grant, err := coordinator.Grant(context.Background(), holder, volumeserver.LeaseCoordinate{
		Family: volumeserver.LeaseFamilyAttributes, Identity: identity,
	}, volumeserver.LeaseRightAttributesRead)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if wire := leaseGrantsProto(coordinator, []volumeserver.LeaseGrant{grant}); len(wire) != 0 {
		t.Fatalf("leaseGrantsProto() = %+v, want expired grant omitted", wire)
	}
}

func TestLeaseMutationTargetsKeepDataAndAttributesIndependent(t *testing.T) {
	var identity [16]byte
	identity[0] = 1
	targets, err := normalizeLeaseVisibilityTargets([]volumeserver.VisibilityTarget{
		{Scope: volumeserver.VisibilityData, Identity: identity, KernelIno: 7, Device: 9, Size: 12},
		{Scope: volumeserver.VisibilityAttributes, Identity: identity, KernelIno: 7, Device: 9},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("normalizeLeaseVisibilityTargets() returned %d targets, want D and A", len(targets))
	}
	recalls, err := leaseRecallTargets(targets)
	if err != nil {
		t.Fatal(err)
	}
	families := map[volumeserver.LeaseFamily]bool{}
	for _, recall := range recalls {
		families[recall.Coordinate.Family] = true
	}
	if !families[volumeserver.LeaseFamilyData] || !families[volumeserver.LeaseFamilyAttributes] || len(families) != 2 {
		t.Fatalf("leaseRecallTargets() families = %v, want D and A", families)
	}
}

func TestLeaseCompleteEventUsesCommittedCutNotRecallCursor(t *testing.T) {
	var initiator volumeserver.SessionID
	initiator[0] = 1
	event := leaseEventProto(volumeserver.LeaseEvent{
		Cursor:           volumeserver.LeaseEventCursor{Sequence: 9, Phase: volumeserver.LeaseEventComplete},
		Initiator:        initiator,
		SnapshotSequence: 3,
		PostState: []volumeserver.VisibilityObjectPostState{{
			StableIdentity: [16]byte{2}, ObjectVersion: 3,
		}},
	})
	if event.GetCursor().GetSequence() != 9 {
		t.Fatalf("recall cursor = %d, want admission generation 9", event.GetCursor().GetSequence())
	}
	post := event.GetPostState()
	if post.GetVisibilitySequence() != 3 || post.GetSnapshotSequence() != 3 || post.GetObjects()[0].GetObjectVersion() != 3 {
		t.Fatalf("post-state = %+v, want committed storage cut 3", post)
	}
}

func TestLeaseAbortCompleteOmitsPostState(t *testing.T) {
	event := leaseEventProto(volumeserver.LeaseEvent{
		Cursor: volumeserver.LeaseEventCursor{Sequence: 4, Phase: volumeserver.LeaseEventComplete},
	})
	if event.GetPostState() != nil {
		t.Fatalf("abort COMPLETE post-state = %+v, want absent", event.GetPostState())
	}
}
