package authorityrpc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

const maxLeasesPerControlMessage = 1024

// TimedLeaseGrant is a validated wire grant anchored to the client's monotonic
// clock. ValidUntil inherits requestStarted's monotonic component.
type TimedLeaseGrant struct {
	Grant      *authoritypb.LeaseGrant
	ValidUntil time.Time
}

type LeaseRenewalOutcome struct {
	Grants    []TimedLeaseGrant
	Withdrawn []*authoritypb.LeaseRenewal
}

// ValidateLeaseRenewalOutcome proves the reply is an exact partition of the
// requested coordinate+epoch tokens. Missing, duplicated, invented, or
// cross-coordinate results are protocol corruption; a named withdrawal is the
// sole nonterminal stale-token result.
func ValidateLeaseRenewalOutcome(requested []*authoritypb.LeaseRenewal, reply *authoritypb.RenewLeasesReply, requestStarted time.Time) (LeaseRenewalOutcome, error) {
	if reply == nil || len(requested) == 0 || len(requested) > maxLeasesPerControlMessage {
		return LeaseRenewalOutcome{}, errors.New("authorityrpc: invalid lease renewal envelope")
	}
	want := make(map[string]struct{}, len(requested))
	for _, renewal := range requested {
		key, err := wireLeaseRenewalKey(renewal)
		if err != nil {
			return LeaseRenewalOutcome{}, err
		}
		if _, duplicate := want[key]; duplicate {
			return LeaseRenewalOutcome{}, errors.New("authorityrpc: duplicate requested lease renewal")
		}
		want[key] = struct{}{}
	}
	grants, err := TimedLeaseGrants(reply.GetGrants(), requestStarted)
	if err != nil {
		return LeaseRenewalOutcome{}, err
	}
	seen := make(map[string]struct{}, len(want))
	for _, grant := range grants {
		key, err := wireLeaseCoordinateEpochKey(grant.Grant.GetCoordinate(), grant.Grant.GetEpoch())
		if err != nil {
			return LeaseRenewalOutcome{}, err
		}
		if _, requested := want[key]; !requested {
			return LeaseRenewalOutcome{}, errors.New("authorityrpc: renewal returned an unrequested grant")
		}
		seen[key] = struct{}{}
	}
	withdrawn := make([]*authoritypb.LeaseRenewal, len(reply.GetWithdrawn()))
	for index, renewal := range reply.GetWithdrawn() {
		key, err := wireLeaseRenewalKey(renewal)
		if err != nil {
			return LeaseRenewalOutcome{}, err
		}
		if _, requested := want[key]; !requested {
			return LeaseRenewalOutcome{}, errors.New("authorityrpc: renewal withdrew an unrequested token")
		}
		if _, duplicate := seen[key]; duplicate {
			return LeaseRenewalOutcome{}, errors.New("authorityrpc: duplicate lease renewal result")
		}
		seen[key] = struct{}{}
		withdrawn[index] = proto.Clone(renewal).(*authoritypb.LeaseRenewal)
	}
	if len(seen) != len(want) {
		return LeaseRenewalOutcome{}, errors.New("authorityrpc: lease renewal omitted a requested token")
	}
	return LeaseRenewalOutcome{Grants: grants, Withdrawn: withdrawn}, nil
}

func wireLeaseRenewalKey(renewal *authoritypb.LeaseRenewal) (string, error) {
	if renewal == nil || renewal.GetEpoch() == 0 || renewal.GetCoordinate() == nil || !validWireLeaseCoordinate(renewal.GetCoordinate()) {
		return "", errors.New("authorityrpc: malformed lease renewal token")
	}
	return wireLeaseCoordinateEpochKey(renewal.GetCoordinate(), renewal.GetEpoch())
}

func wireLeaseCoordinateEpochKey(coordinate *authoritypb.LeaseCoordinate, epoch uint64) (string, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(coordinate)
	if err != nil {
		return "", err
	}
	key := make([]byte, len(encoded)+8)
	copy(key, encoded)
	binary.BigEndian.PutUint64(key[len(encoded):], epoch)
	return string(key), nil
}

func TimedLeaseGrants(grants []*authoritypb.LeaseGrant, requestStarted time.Time) ([]TimedLeaseGrant, error) {
	if requestStarted.IsZero() || len(grants) > maxLeasesPerControlMessage {
		return nil, errors.New("authorityrpc: invalid lease grant envelope")
	}
	validated := make([]TimedLeaseGrant, len(grants))
	seen := make(map[string]struct{}, len(grants))
	for index, grant := range grants {
		if grant == nil || grant.GetEpoch() == 0 || grant.GetIssuedSequence() == 0 || grant.GetValidForNanos() == 0 || grant.GetValidForNanos() > uint64(volumeserver.Protocol6MaxLeaseTTL) {
			return nil, errors.New("authorityrpc: malformed lease grant")
		}
		coordinate := grant.GetCoordinate()
		if coordinate == nil || !validWireLeaseCoordinate(coordinate) || !validWireLeaseRight(coordinate.GetFamily(), grant.GetRight()) {
			return nil, errors.New("authorityrpc: malformed lease grant coordinate or right")
		}
		key, err := proto.MarshalOptions{Deterministic: true}.Marshal(coordinate)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[string(key)]; duplicate {
			return nil, errors.New("authorityrpc: duplicate lease grant coordinate")
		}
		seen[string(key)] = struct{}{}
		validated[index] = TimedLeaseGrant{
			Grant:      proto.Clone(grant).(*authoritypb.LeaseGrant),
			ValidUntil: requestStarted.Add(time.Duration(grant.GetValidForNanos())),
		}
	}
	return validated, nil
}

// TimedResponseLeaseGrants validates the common response envelope. Callers
// pass the monotonic timestamp sampled immediately before dispatching the
// request; transport delay can therefore only shorten local validity.
func TimedResponseLeaseGrants(response *authoritypb.Response, requestStarted time.Time) ([]TimedLeaseGrant, error) {
	if response == nil {
		return nil, errors.New("authorityrpc: nil lease grant response")
	}
	return TimedLeaseGrants(response.GetLeaseGrants(), requestStarted)
}

// TimedResponseLeaseGrantsAfterRecall also enforces the CONTROL-before-DATA
// high-water rule. A grant issued before an already-processed recall cannot be
// installed even if its response arrives late on DATA.
func TimedResponseLeaseGrantsAfterRecall(response *authoritypb.Response, requestStarted time.Time, processedRecall uint64) ([]TimedLeaseGrant, error) {
	grants, err := TimedResponseLeaseGrants(response, requestStarted)
	if err != nil {
		return nil, err
	}
	current := grants[:0]
	for _, grant := range grants {
		if grant.Grant.GetIssuedSequence() >= processedRecall {
			current = append(current, grant)
		}
	}
	return current, nil
}

// ValidateLeaseEvent enforces the exact protocol-6 coordinate-recall shape.
func ValidateLeaseEvent(event *authoritypb.LeaseEvent) error {
	if event == nil || event.GetCursor() == nil || event.GetCursor().GetSequence() == 0 {
		return errors.New("authorityrpc: malformed lease event cursor")
	}
	phase := event.GetCursor().GetPhase()
	if phase != authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_REVOKE && phase != authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_COMPLETE {
		return errors.New("authorityrpc: malformed lease event phase")
	}
	if !nonzeroWireLeaseIdentity(event.GetInitiatorSessionId()) || len(event.GetRecalls()) == 0 || len(event.GetRecalls()) > maxLeasesPerControlMessage {
		return errors.New("authorityrpc: malformed recall lease event")
	}
	if phase == authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_REVOKE && event.GetPostState() != nil {
		return errors.New("authorityrpc: REVOKE carried post-state")
	}
	if state := event.GetPostState(); state != nil {
		if phase != authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_COMPLETE || state.GetSnapshotSequence() == 0 || state.GetVisibilitySequence() != state.GetSnapshotSequence() {
			return errors.New("authorityrpc: malformed COMPLETE post-state")
		}
	}
	seen := make(map[string]struct{}, len(event.GetRecalls()))
	for _, recall := range event.GetRecalls() {
		if recall == nil || recall.GetGrantEpoch() == 0 || recall.GetRevokeEpoch() == 0 || recall.GetGrantEpoch() == recall.GetRevokeEpoch() ||
			recall.GetCoordinate() == nil || !validWireLeaseCoordinate(recall.GetCoordinate()) ||
			!validWireLeaseRight(recall.GetCoordinate().GetFamily(), recall.GetRight()) {
			return errors.New("authorityrpc: malformed lease recall")
		}
		key, err := proto.MarshalOptions{Deterministic: true}.Marshal(recall.GetCoordinate())
		if err != nil {
			return err
		}
		if _, duplicate := seen[string(key)]; duplicate {
			return errors.New("authorityrpc: duplicate lease recall")
		}
		seen[string(key)] = struct{}{}
	}
	return nil
}

func validWireLeaseCoordinate(coordinate *authoritypb.LeaseCoordinate) bool {
	switch coordinate.GetFamily() {
	case authoritypb.LeaseFamily_LEASE_FAMILY_NAME:
		name := coordinate.GetName()
		return nonzeroWireLeaseIdentity(coordinate.GetParentIdentity()) && len(coordinate.GetIdentity()) == 0 && len(name) > 0 && len(name) <= 255 &&
			bytes.IndexByte(name, 0) < 0 && bytes.IndexByte(name, '/') < 0 && !bytes.Equal(name, []byte(".")) && !bytes.Equal(name, []byte(".."))
	case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES,
		authoritypb.LeaseFamily_LEASE_FAMILY_DATA,
		authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
		return nonzeroWireLeaseIdentity(coordinate.GetIdentity()) && len(coordinate.GetParentIdentity()) == 0 && len(coordinate.GetName()) == 0
	default:
		return false
	}
}

func nonzeroWireLeaseIdentity(identity []byte) bool {
	return len(identity) == 16 && !bytes.Equal(identity, make([]byte, 16))
}

func validWireLeaseRight(family authoritypb.LeaseFamily, right authoritypb.LeaseRight) bool {
	switch family {
	case authoritypb.LeaseFamily_LEASE_FAMILY_NAME:
		return right == authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ || right == authoritypb.LeaseRight_LEASE_RIGHT_NAME_EXCLUSIVE
	case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES:
		return right == authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ || right == authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_EXCLUSIVE
	case authoritypb.LeaseFamily_LEASE_FAMILY_DATA:
		return right == authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ || right == authoritypb.LeaseRight_LEASE_RIGHT_DATA_EXCLUSIVE
	case authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
		return right == authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ
	default:
		return false
	}
}
