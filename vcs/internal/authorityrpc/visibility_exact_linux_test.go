//go:build linux

package authorityrpc

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestAttachExactRepairPostStateCarriesTheMutationRecord(t *testing.T) {
	const sequence = uint64(17)
	identity := [16]byte{1}
	state := &authoritypb.PostState{
		VisibilitySequence: sequence,
		SnapshotSequence:   sequence,
		Objects: []*authoritypb.ObjectPostState{{
			StableIdentity: identity[:],
			ObjectVersion:  sequence,
			Roles:          postStateRoleTarget,
			Attr: &authoritypb.Attr{
				Kind: authoritypb.Attr_REGULAR, Inode: 91, Size: 4096,
				Mode: 0o600, Flags: 0x10, BirthTimeNs: 123456789,
			},
		}},
	}
	for _, test := range []struct {
		name  string
		scope volumeserver.VisibilityScope
	}{
		{name: "attributes", scope: volumeserver.VisibilityAttributes},
		{name: "data", scope: volumeserver.VisibilityData},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := volumeserver.VisibilityTarget{
				Scope: test.scope, Identity: identity, KernelIno: 91,
			}
			if test.scope == volumeserver.VisibilityData {
				target.Size = 4096
			}
			targets := []volumeserver.VisibilityTarget{target}
			if err := attachExactRepairPostState(targets, state, sequence, map[[16]byte]struct{}{identity: {}}); err != nil {
				t.Fatal(err)
			}
			exact := targets[0].ExactPostState
			if exact == nil || exact.ObjectVersion != sequence ||
				exact.Attr.Flags != 0x10 || exact.Attr.BirthTimeNS != 123456789 ||
				exact.Attr.Size != 4096 {
				t.Fatalf("exact repair record = %+v", exact)
			}
		})
	}
}

func TestAttachExactRepairPostStateFailsClosedOnAMissingRecord(t *testing.T) {
	identity := [16]byte{1}
	targets := []volumeserver.VisibilityTarget{{
		Scope: volumeserver.VisibilityAttributes, Identity: identity, KernelIno: 91,
	}}
	state := &authoritypb.PostState{
		VisibilitySequence: 17,
		SnapshotSequence:   17,
		Objects: []*authoritypb.ObjectPostState{{
			StableIdentity: []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			ObjectVersion:  17,
			Roles:          postStateRoleTarget,
			Attr:           &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 91},
		}},
	}
	changed := map[[16]byte]struct{}{{2}: {}}
	if err := attachExactRepairPostState(targets, state, 17, changed); err == nil {
		t.Fatal("missing exact repair record was accepted")
	}
}

func TestAttachExactRepairPostStateRequiresEveryChangedRecordTarget(t *testing.T) {
	const sequence = uint64(17)
	source, destination := [16]byte{1}, [16]byte{2}
	state := &authoritypb.PostState{
		VisibilitySequence: sequence,
		SnapshotSequence:   sequence,
		Objects: []*authoritypb.ObjectPostState{
			{StableIdentity: source[:], ObjectVersion: sequence, Roles: postStateRoleSource,
				Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 91, Size: 4}},
			{StableIdentity: destination[:], ObjectVersion: sequence, Roles: postStateRoleDestination,
				Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 92, Size: 8}},
		},
	}
	targets := []volumeserver.VisibilityTarget{{
		Scope: volumeserver.VisibilityData, Identity: destination, KernelIno: 92, Size: 8,
	}}
	changed := map[[16]byte]struct{}{source: {}, destination: {}}
	if err := attachExactRepairPostState(targets, state, sequence, changed); err == nil {
		t.Fatal("COMPLETE without a target for the changed source record was accepted")
	}

	state.Objects[0].ObjectVersion = sequence - 1
	changed = map[[16]byte]struct{}{destination: {}}
	if err := attachExactRepairPostState(targets, state, sequence, changed); err != nil {
		t.Fatalf("unchanged source record incorrectly required a COMPLETE target: %v", err)
	}
	if targets[0].ExactPostState == nil || targets[0].ExactPostState.StableIdentity != destination {
		t.Fatalf("destination exact repair = %#v", targets[0].ExactPostState)
	}
}

func TestAttachExactRepairPostStateDoesNotInferChangeFromBaselineVersion(t *testing.T) {
	const sequence = uint64(1)
	identity := [16]byte{1}
	state := &authoritypb.PostState{
		VisibilitySequence: sequence,
		SnapshotSequence:   sequence,
		Objects: []*authoritypb.ObjectPostState{{
			StableIdentity: identity[:], ObjectVersion: sequence,
			Roles: postStateRoleTarget,
			Attr:  &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 91},
		}},
	}
	if err := attachExactRepairPostState(
		nil, state, sequence, map[[16]byte]struct{}{},
	); err != nil {
		t.Fatalf("unchanged baseline-version record required a COMPLETE target: %v", err)
	}
}
