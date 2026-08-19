//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
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

// leaseBarrierFixture drives one lease recall transaction to the point the
// coherence barrier returns, leaving the source owing a discharge receipt.
type leaseBarrierFixture struct {
	coordinator *volumeserver.LeaseCoordinator
	source      volumeserver.SessionID
	peer        volumeserver.SessionID
	identity    [16]byte
	transaction *volumeserver.LeaseRecallTransaction
	discharge   *volumeserver.LeaseSourceDischarge
}

func newLeaseBarrierFixture(t *testing.T) *leaseBarrierFixture {
	t.Helper()
	coordinator, err := volumeserver.NewLeaseCoordinator(volumeserver.LeaseConfig{
		TTL: time.Second, RecallBudget: time.Second, MaxPerHolder: 4096, MaxTotal: 16384,
		PriorGrantsFenced: true, Fencer: wireLeaseTestFencer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &leaseBarrierFixture{coordinator: coordinator}
	f.source[0], f.peer[0], f.identity[0] = 1, 2, 7
	for _, id := range []volumeserver.SessionID{f.source, f.peer} {
		if err := coordinator.ActivateHolder(id, make(chan struct{})); err != nil {
			t.Fatal(err)
		}
	}
	coordinate := volumeserver.LeaseCoordinate{Family: volumeserver.LeaseFamilyAttributes, Identity: f.identity}
	for _, id := range []volumeserver.SessionID{f.source, f.peer} {
		if _, err := coordinator.Grant(context.Background(), id, coordinate, volumeserver.LeaseRightAttributesRead); err != nil {
			t.Fatal(err)
		}
	}
	prepared := make(chan *volumeserver.LeaseRecallTransaction, 1)
	go func() {
		transaction, prepareErr := coordinator.PrepareRecall(context.Background(), f.source,
			[]volumeserver.LeaseRecallTarget{{Coordinate: coordinate}})
		if prepareErr != nil {
			panic(prepareErr)
		}
		prepared <- transaction
	}()
	revoke, err := coordinator.Next(context.Background(), f.peer, volumeserver.LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AcknowledgeRevoke(f.peer, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	f.transaction = <-prepared

	completed := make(chan *volumeserver.LeaseSourceDischarge, 1)
	completeErr := make(chan error, 1)
	go func() {
		discharge, err := f.transaction.CompletePeers(context.Background(), nil, 1, true)
		completed <- discharge
		completeErr <- err
	}()
	complete, err := coordinator.Next(context.Background(), f.peer, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Discharge(f.peer, complete.Cursor, []volumeserver.LeaseDischarge{{
		Coordinate: coordinate, RevokeEpoch: complete.Recalls[0].RevokeEpoch, Mode: volumeserver.LeaseDischargeToNone,
	}}); err != nil {
		t.Fatal(err)
	}
	f.discharge = <-completed
	if err := <-completeErr; err != nil {
		t.Fatal(err)
	}
	if f.discharge == nil {
		t.Fatal("the barrier minted no source discharge obligation")
	}
	return f
}

func (f *leaseBarrierFixture) postState(t *testing.T) *authoritypb.PostState {
	t.Helper()
	return (&VolumeHandler{}).mutationPostState(f.transaction.Sequence(), postStateSnapshot{
		identity: f.identity,
		attr:     xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Mode: 0o600, Nlink: 1},
		roles:    postStateRoleTarget,
		changed:  true,
	})
}

func TestFailedCoherenceBarrierMintsNothingAndStillConveysTheSourceDischarge(t *testing.T) {
	f := newLeaseBarrierFixture(t)
	h := &VolumeHandler{Leases: f.coordinator}
	resp := h.success(0)
	resp.PostState = f.postState(t)
	failure := h.finishLeaseMutationReply(
		&authoritypb.Request{Body: &authoritypb.Request_SetAttr{}}, resp, f.transaction,
		f.discharge, errors.New("coherence barrier did not complete"), true,
	)
	if failure.GetErrno() == 0 {
		t.Fatal("a failed barrier produced a success reply")
	}
	if len(failure.GetLeaseGrants()) != 0 {
		t.Fatalf("failed barrier delivered %d successor grants", len(failure.GetLeaseGrants()))
	}
	if failure.GetSourceLeaseDischarge().GetSequence() != f.discharge.Sequence {
		t.Fatalf("failed barrier dropped the source discharge: %+v", failure.GetSourceLeaseDischarge())
	}
	// A phantom leaseGranted record would be a live successor in the authority
	// table with nothing on the wire that could ever discharge it.
	if held := f.coordinator.Held(f.source); len(held) != 0 {
		t.Fatalf("failed barrier retained authority records: %+v", held)
	}
}

func TestCompletedCoherenceBarrierMintsTheSuccessorGrant(t *testing.T) {
	f := newLeaseBarrierFixture(t)
	h := &VolumeHandler{Leases: f.coordinator}
	resp := h.success(0)
	resp.PostState = f.postState(t)
	reply := h.finishLeaseMutationReply(
		&authoritypb.Request{Body: &authoritypb.Request_SetAttr{}}, resp, f.transaction, f.discharge, nil, true,
	)
	if reply.GetErrno() != 0 {
		t.Fatalf("completed barrier returned errno %d", reply.GetErrno())
	}
	if len(reply.GetLeaseGrants()) != 1 {
		t.Fatalf("completed barrier delivered %d successor grants, want 1", len(reply.GetLeaseGrants()))
	}
	if reply.GetSourceLeaseDischarge().GetSequence() != f.discharge.Sequence {
		t.Fatalf("completed barrier dropped the source discharge: %+v", reply.GetSourceLeaseDischarge())
	}
	if held := f.coordinator.Held(f.source); len(held) != 1 {
		t.Fatalf("successor records = %+v, want exactly the minted grant", held)
	}
}
