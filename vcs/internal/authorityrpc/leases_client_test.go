package authorityrpc

import (
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestTimedLeaseGrantsRejectZeroIdentity(t *testing.T) {
	tests := []struct {
		name       string
		coordinate *authoritypb.LeaseCoordinate
		right      authoritypb.LeaseRight
	}{
		{
			name: "name parent", coordinate: &authoritypb.LeaseCoordinate{
				Family: authoritypb.LeaseFamily_LEASE_FAMILY_NAME, ParentIdentity: make([]byte, 16), Name: []byte("entry"),
			}, right: authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ,
		},
		{
			name: "item", coordinate: &authoritypb.LeaseCoordinate{
				Family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, Identity: make([]byte, 16),
			}, right: authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := TimedLeaseGrants([]*authoritypb.LeaseGrant{{
				Coordinate: test.coordinate, Right: test.right, Epoch: 1, ValidForNanos: uint64(time.Second), IssuedSequence: 1,
			}}, time.Now())
			if err == nil {
				t.Fatal("TimedLeaseGrants() accepted an all-zero identity")
			}
		})
	}
}

func TestTimedLeaseGrantsEnforceAuthoritySafetyHorizon(t *testing.T) {
	identity := make([]byte, 16)
	identity[0] = 1
	grant := &authoritypb.LeaseGrant{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, Identity: identity},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, Epoch: 1, IssuedSequence: 1,
		ValidForNanos: uint64(volumeserver.Protocol6MaxLeaseTTL),
	}
	if _, err := TimedLeaseGrants([]*authoritypb.LeaseGrant{grant}, time.Now()); err != nil {
		t.Fatalf("exact authority horizon rejected: %v", err)
	}
	grant.ValidForNanos++
	if _, err := TimedLeaseGrants([]*authoritypb.LeaseGrant{grant}, time.Now()); err == nil {
		t.Fatal("grant beyond authority restart horizon was accepted")
	}
}

func TestTimedResponseLeaseGrantsRejectLateDataAfterRecall(t *testing.T) {
	identity := make([]byte, 16)
	identity[0] = 1
	response := &authoritypb.Response{LeaseGrants: []*authoritypb.LeaseGrant{{
		Coordinate: &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, Identity: identity},
		Right:      authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, Epoch: 1, ValidForNanos: uint64(time.Second), IssuedSequence: 5,
	}}}
	started := time.Now()
	if grants, err := TimedResponseLeaseGrantsAfterRecall(response, started, 6); err != nil || len(grants) != 0 {
		t.Fatalf("late DATA grant older than processed recall = %+v, %v; want silently dropped", grants, err)
	}
	if _, err := TimedResponseLeaseGrantsAfterRecall(response, started, 5); err != nil {
		t.Fatalf("grant at current recall generation was rejected: %v", err)
	}
}

func TestValidateLeaseRenewalOutcomeRequiresExactPartition(t *testing.T) {
	identityA := make([]byte, 16)
	identityA[0] = 1
	identityB := make([]byte, 16)
	identityB[0] = 2
	coordinateA := &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_DATA, Identity: identityA}
	coordinateB := &authoritypb.LeaseCoordinate{Family: authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES, Identity: identityB}
	requested := []*authoritypb.LeaseRenewal{{Coordinate: coordinateA, Epoch: 3}, {Coordinate: coordinateB, Epoch: 5}}
	reply := &authoritypb.RenewLeasesReply{
		Grants: []*authoritypb.LeaseGrant{{
			Coordinate: coordinateA, Right: authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ, Epoch: 3,
			ValidForNanos: uint64(time.Second), IssuedSequence: 7,
		}},
		Withdrawn: []*authoritypb.LeaseRenewal{{Coordinate: coordinateB, Epoch: 5}},
	}
	outcome, err := ValidateLeaseRenewalOutcome(requested, reply, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Grants) != 1 || len(outcome.Withdrawn) != 1 {
		t.Fatalf("outcome = %+v", outcome)
	}
	reply.Withdrawn = nil
	if _, err := ValidateLeaseRenewalOutcome(requested, reply, time.Now()); err == nil {
		t.Fatal("renewal outcome accepted an omitted token")
	}
	reply.Withdrawn = []*authoritypb.LeaseRenewal{{Coordinate: coordinateA, Epoch: 3}}
	if _, err := ValidateLeaseRenewalOutcome(requested, reply, time.Now()); err == nil {
		t.Fatal("renewal outcome accepted a token as both grant and withdrawal")
	}
}
