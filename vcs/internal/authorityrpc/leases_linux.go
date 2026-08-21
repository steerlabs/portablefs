//go:build linux

package authorityrpc

import (
	"bytes"
	"sort"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func leaseCoordinate(wire *authoritypb.LeaseCoordinate) (volumeserver.LeaseCoordinate, error) {
	if wire == nil {
		return volumeserver.LeaseCoordinate{}, syscall.EINVAL
	}
	coordinate := volumeserver.LeaseCoordinate{}
	switch wire.GetFamily() {
	case authoritypb.LeaseFamily_LEASE_FAMILY_NAME:
		if !nonzeroLeaseIdentity(wire.GetParentIdentity()) || len(wire.GetIdentity()) != 0 || len(wire.GetName()) == 0 || len(wire.GetName()) > 255 || bytes.IndexByte(wire.GetName(), 0) >= 0 || bytes.Equal(wire.GetName(), []byte(".")) || bytes.Equal(wire.GetName(), []byte("..")) {
			return volumeserver.LeaseCoordinate{}, syscall.EINVAL
		}
		coordinate.Family = volumeserver.LeaseFamilyName
		copy(coordinate.ParentIdentity[:], wire.GetParentIdentity())
		coordinate.Name = bytes.Clone(wire.GetName())
	case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES,
		authoritypb.LeaseFamily_LEASE_FAMILY_DATA,
		authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
		if !nonzeroLeaseIdentity(wire.GetIdentity()) || len(wire.GetParentIdentity()) != 0 || len(wire.GetName()) != 0 {
			return volumeserver.LeaseCoordinate{}, syscall.EINVAL
		}
		switch wire.GetFamily() {
		case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES:
			coordinate.Family = volumeserver.LeaseFamilyAttributes
		case authoritypb.LeaseFamily_LEASE_FAMILY_DATA:
			coordinate.Family = volumeserver.LeaseFamilyData
		case authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
			coordinate.Family = volumeserver.LeaseFamilyEnumeration
		}
		copy(coordinate.Identity[:], wire.GetIdentity())
	default:
		return volumeserver.LeaseCoordinate{}, syscall.EINVAL
	}
	return coordinate, nil
}

func leaseCoordinateProto(coordinate volumeserver.LeaseCoordinate) *authoritypb.LeaseCoordinate {
	wire := &authoritypb.LeaseCoordinate{}
	switch coordinate.Family {
	case volumeserver.LeaseFamilyName:
		wire.Family = authoritypb.LeaseFamily_LEASE_FAMILY_NAME
		wire.ParentIdentity = append([]byte(nil), coordinate.ParentIdentity[:]...)
		wire.Name = bytes.Clone(coordinate.Name)
	case volumeserver.LeaseFamilyAttributes:
		wire.Family = authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES
		wire.Identity = append([]byte(nil), coordinate.Identity[:]...)
	case volumeserver.LeaseFamilyData:
		wire.Family = authoritypb.LeaseFamily_LEASE_FAMILY_DATA
		wire.Identity = append([]byte(nil), coordinate.Identity[:]...)
	case volumeserver.LeaseFamilyEnumeration:
		wire.Family = authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION
		wire.Identity = append([]byte(nil), coordinate.Identity[:]...)
	}
	return wire
}

func leaseRight(wire authoritypb.LeaseRight) (volumeserver.LeaseRight, error) {
	switch wire {
	case authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ:
		return volumeserver.LeaseRightNameRead, nil
	case authoritypb.LeaseRight_LEASE_RIGHT_NAME_EXCLUSIVE:
		return volumeserver.LeaseRightNameExclusive, nil
	case authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ:
		return volumeserver.LeaseRightAttributesRead, nil
	case authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_EXCLUSIVE:
		return volumeserver.LeaseRightAttributesExclusive, nil
	case authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ:
		return volumeserver.LeaseRightDataRead, nil
	case authoritypb.LeaseRight_LEASE_RIGHT_DATA_EXCLUSIVE:
		return volumeserver.LeaseRightDataExclusive, nil
	case authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ:
		return volumeserver.LeaseRightEnumerationRead, nil
	default:
		return 0, syscall.EINVAL
	}
}

func leaseRightProto(right volumeserver.LeaseRight) authoritypb.LeaseRight {
	switch right {
	case volumeserver.LeaseRightNameRead:
		return authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ
	case volumeserver.LeaseRightNameExclusive:
		return authoritypb.LeaseRight_LEASE_RIGHT_NAME_EXCLUSIVE
	case volumeserver.LeaseRightAttributesRead:
		return authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ
	case volumeserver.LeaseRightAttributesExclusive:
		return authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_EXCLUSIVE
	case volumeserver.LeaseRightDataRead:
		return authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ
	case volumeserver.LeaseRightDataExclusive:
		return authoritypb.LeaseRight_LEASE_RIGHT_DATA_EXCLUSIVE
	case volumeserver.LeaseRightEnumerationRead:
		return authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ
	default:
		return authoritypb.LeaseRight_LEASE_RIGHT_UNSPECIFIED
	}
}

func leaseGrantProto(grant volumeserver.LeaseGrant, validFor time.Duration) *authoritypb.LeaseGrant {
	return &authoritypb.LeaseGrant{
		Coordinate: leaseCoordinateProto(grant.Coordinate), Right: leaseRightProto(grant.Right), Epoch: grant.Epoch,
		ValidForNanos: uint64(validFor), IssuedSequence: grant.IssuedAt,
	}
}

func leaseGrantsProto(coordinator *volumeserver.LeaseCoordinator, grants []volumeserver.LeaseGrant) []*authoritypb.LeaseGrant {
	wire := make([]*authoritypb.LeaseGrant, 0, len(grants))
	for _, grant := range grants {
		validFor := coordinator.Remaining(grant)
		if validFor <= 0 {
			continue
		}
		wire = append(wire, leaseGrantProto(grant, validFor))
	}
	return wire
}

// postStateAttributeGrants selects the coordinates a mutation's own applied
// post-state authorizes its source to cache. A removed object has no attributes
// left to cache; every other object the reply describes is the exact state the
// authority just wrote, so a successor attribute grant over it covers nothing
// this transaction did not establish.
func postStateAttributeGrants(state *authoritypb.PostState) []volumeserver.LeaseGrantRequest {
	requests := make([]volumeserver.LeaseGrantRequest, 0, len(state.GetObjects()))
	for _, object := range state.GetObjects() {
		if object.GetRoles()&postStateRoleRemoved != 0 || !nonzeroLeaseIdentity(object.GetStableIdentity()) {
			continue
		}
		coordinate := volumeserver.LeaseCoordinate{Family: volumeserver.LeaseFamilyAttributes}
		copy(coordinate.Identity[:], object.GetStableIdentity())
		requests = append(requests, volumeserver.LeaseGrantRequest{
			Coordinate: coordinate, Right: volumeserver.LeaseRightAttributesRead,
			// A created identity has no recall entry because no peer could have
			// named it before this transaction made it exist.
			Created: object.GetRoles()&postStateRoleCreated != 0,
		})
	}
	return requests
}

func nonzeroLeaseIdentity(identity []byte) bool {
	return len(identity) == 16 && !bytes.Equal(identity, make([]byte, 16))
}

func leaseEventCursor(wire *authoritypb.LeaseEventCursor) (volumeserver.LeaseEventCursor, error) {
	if wire == nil {
		return volumeserver.LeaseEventCursor{}, nil
	}
	if wire.GetSequence() == 0 && wire.GetPhase() == authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_UNSPECIFIED {
		return volumeserver.LeaseEventCursor{}, nil
	}
	if wire.GetSequence() == 0 {
		return volumeserver.LeaseEventCursor{}, syscall.EINVAL
	}
	cursor := volumeserver.LeaseEventCursor{Sequence: wire.GetSequence()}
	switch wire.GetPhase() {
	case authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_REVOKE:
		cursor.Phase = volumeserver.LeaseEventRevoke
	case authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_COMPLETE:
		cursor.Phase = volumeserver.LeaseEventComplete
	default:
		return volumeserver.LeaseEventCursor{}, syscall.EINVAL
	}
	return cursor, nil
}

func leaseEventCursorProto(cursor volumeserver.LeaseEventCursor) *authoritypb.LeaseEventCursor {
	wire := &authoritypb.LeaseEventCursor{Sequence: cursor.Sequence}
	switch cursor.Phase {
	case volumeserver.LeaseEventRevoke:
		wire.Phase = authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_REVOKE
	case volumeserver.LeaseEventComplete:
		wire.Phase = authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_COMPLETE
	}
	return wire
}

func leaseEventProto(event volumeserver.LeaseEvent) *authoritypb.LeaseEvent {
	recalls := make([]*authoritypb.LeaseRecall, len(event.Recalls))
	for index, recall := range event.Recalls {
		recalls[index] = &authoritypb.LeaseRecall{
			Coordinate: leaseCoordinateProto(recall.Coordinate), Right: leaseRightProto(recall.Right),
			GrantEpoch: recall.GrantEpoch, RevokeEpoch: recall.RevokeEpoch,
		}
	}
	sort.Slice(recalls, func(i, j int) bool {
		left, right := recalls[i].GetCoordinate(), recalls[j].GetCoordinate()
		if left.GetFamily() != right.GetFamily() {
			return left.GetFamily() < right.GetFamily()
		}
		if compared := bytes.Compare(left.GetParentIdentity(), right.GetParentIdentity()); compared != 0 {
			return compared < 0
		}
		if compared := bytes.Compare(left.GetIdentity(), right.GetIdentity()); compared != 0 {
			return compared < 0
		}
		return bytes.Compare(left.GetName(), right.GetName()) < 0
	})
	objects := make([]*authoritypb.ObjectPostState, len(event.PostState))
	for index := range event.PostState {
		objects[index] = visibilityObjectPostStateProto(&event.PostState[index])
	}
	var postState *authoritypb.PostState
	if event.Cursor.Phase == volumeserver.LeaseEventComplete && event.SnapshotSequence != 0 {
		postState = &authoritypb.PostState{
			VisibilitySequence: event.SnapshotSequence, Objects: objects, SnapshotSequence: event.SnapshotSequence,
		}
	}
	return &authoritypb.LeaseEvent{
		Cursor: leaseEventCursorProto(event.Cursor), InitiatorSessionId: append([]byte(nil), event.Initiator[:]...),
		Recalls: recalls, PostState: postState,
	}
}

func sourceLeaseDischargeProto(discharge *volumeserver.LeaseSourceDischarge) *authoritypb.SourceLeaseDischarge {
	if discharge == nil {
		return nil
	}
	recalls := make([]*authoritypb.LeaseRecall, len(discharge.Recalls))
	for index, recall := range discharge.Recalls {
		recalls[index] = &authoritypb.LeaseRecall{
			Coordinate: leaseCoordinateProto(recall.Coordinate), Right: leaseRightProto(recall.Right),
			GrantEpoch: recall.GrantEpoch, RevokeEpoch: recall.RevokeEpoch,
		}
	}
	return &authoritypb.SourceLeaseDischarge{Sequence: discharge.Sequence, Recalls: recalls}
}

func leaseRenewals(wire []*authoritypb.LeaseRenewal) ([]volumeserver.LeaseRenewal, error) {
	if len(wire) == 0 || len(wire) > maxLeasesPerControlMessage {
		return nil, syscall.EINVAL
	}
	renewals := make([]volumeserver.LeaseRenewal, len(wire))
	for index, renewal := range wire {
		if renewal == nil || renewal.GetEpoch() == 0 {
			return nil, syscall.EINVAL
		}
		coordinate, err := leaseCoordinate(renewal.GetCoordinate())
		if err != nil {
			return nil, err
		}
		renewals[index] = volumeserver.LeaseRenewal{Coordinate: coordinate, Epoch: renewal.GetEpoch()}
	}
	return renewals, nil
}

func leaseRenewalsProto(renewals []volumeserver.LeaseRenewal) []*authoritypb.LeaseRenewal {
	wire := make([]*authoritypb.LeaseRenewal, len(renewals))
	for index, renewal := range renewals {
		wire[index] = &authoritypb.LeaseRenewal{Coordinate: leaseCoordinateProto(renewal.Coordinate), Epoch: renewal.Epoch}
	}
	return wire
}

func leaseDischarges(wire []*authoritypb.LeaseDischarge) ([]volumeserver.LeaseDischarge, error) {
	if len(wire) > maxLeasesPerControlMessage {
		return nil, syscall.EINVAL
	}
	discharges := make([]volumeserver.LeaseDischarge, len(wire))
	for index, discharge := range wire {
		if discharge == nil || discharge.GetRevokeEpoch() == 0 {
			return nil, syscall.EINVAL
		}
		coordinate, err := leaseCoordinate(discharge.GetCoordinate())
		if err != nil {
			return nil, err
		}
		var mode volumeserver.LeaseDischargeMode
		switch discharge.GetMode() {
		case authoritypb.LeaseDischargeMode_LEASE_DISCHARGE_MODE_TO_NONE:
			mode = volumeserver.LeaseDischargeToNone
		case authoritypb.LeaseDischargeMode_LEASE_DISCHARGE_MODE_CONTINUITY:
			mode = volumeserver.LeaseDischargeContinuity
		default:
			return nil, syscall.EINVAL
		}
		successor, err := leaseRight(discharge.GetSuccessorRight())
		if discharge.GetSuccessorRight() == authoritypb.LeaseRight_LEASE_RIGHT_UNSPECIFIED {
			successor, err = 0, nil
		}
		if err != nil {
			return nil, err
		}
		discharges[index] = volumeserver.LeaseDischarge{
			Coordinate: coordinate, RevokeEpoch: discharge.GetRevokeEpoch(), Mode: mode, SuccessorRight: successor,
		}
	}
	return discharges, nil
}
