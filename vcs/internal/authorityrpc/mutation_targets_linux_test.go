//go:build linux

package authorityrpc

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// Storage builders retain the complete independent observation footprint.
func TestMutationVisibilityBuildersExposeDependencyCoordinates(t *testing.T) {
	coordinate := func(identity byte) mutationCoordinate {
		return mutationCoordinate{identity: [16]byte{identity}, ino: uint64(identity), device: 1}
	}
	parent, otherParent := coordinate(1), coordinate(2)
	moved, replacement, source := coordinate(3), coordinate(4), coordinate(5)
	fresh := coordinate(6)

	type namespaceExpectation struct {
		parent  mutationCoordinate
		name    string
		related []mutationCoordinate
	}
	type operation struct {
		name       string
		targets    []volumeserver.MutationTarget
		namespaces []namespaceExpectation
		inodes     []mutationCoordinate
	}
	rename := &authoritypb.RenameRequest{OldName: []byte("old"), NewName: []byte("new")}
	operations := []operation{
		{
			name: "create or symlink",
			targets: []volumeserver.MutationTarget{
				namespaceTarget(parent, []byte("fresh")),
				inodeTarget(volumeserver.MutationAttributes, parent, 0),
			},
			namespaces: []namespaceExpectation{{parent: parent, name: "fresh"}},
			inodes:     []mutationCoordinate{parent},
		},
		{
			name: "unlink or rmdir",
			targets: []volumeserver.MutationTarget{
				namespaceTargetRelated(parent, []byte("victim"), moved),
				inodeTarget(volumeserver.MutationAttributes, parent, 0),
				inodeTarget(volumeserver.MutationAttributes, moved, 0),
			},
			namespaces: []namespaceExpectation{{parent: parent, name: "victim", related: []mutationCoordinate{moved}}},
			inodes:     []mutationCoordinate{parent, moved},
		},
		{
			name:       "link",
			targets:    linkMutationTargets([]byte("alias"), parent, source, false),
			namespaces: []namespaceExpectation{{parent: parent, name: "alias", related: []mutationCoordinate{source}}},
			inodes:     []mutationCoordinate{parent, source},
		},
		{
			name:    "rename over existing",
			targets: renameMutationTargets(rename, parent, otherParent, moved, replacement, true, mutationCoordinate{}, false, false),
			namespaces: []namespaceExpectation{
				{parent: parent, name: "old", related: []mutationCoordinate{moved}},
				{parent: otherParent, name: "new", related: []mutationCoordinate{moved, replacement}},
			},
			inodes: []mutationCoordinate{parent, otherParent, moved, replacement},
		},
		{
			name: "copy_file_range",
			targets: []volumeserver.MutationTarget{
				inodeTarget(volumeserver.MutationData, moved, 10),
				inodeTarget(volumeserver.MutationData, replacement, 20),
			},
			inodes: []mutationCoordinate{moved, replacement},
		},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			for _, expectation := range operation.namespaces {
				assertNamespaceTargetCoordinates(t, operation.targets, expectation.parent, expectation.name, expectation.related...)
			}
			for _, expectation := range operation.inodes {
				assertInodeTargetCoordinate(t, operation.targets, expectation)
			}
			if _, err := normalizeMutationTargets(operation.targets); err != nil {
				t.Fatalf("production visibility targets are not canonicalizable: %v", err)
			}
		})
	}

	// A created identity is unknown until apply and deliberately absent from the
	// PREPARE dependency footprint. Other operations cannot name it until the
	// binding above has completed publication.
	createTargets := operations[0].targets
	for _, target := range createTargets {
		if target.Identity == fresh.identity || target.PostIdentity == fresh.identity {
			t.Fatal("newly created inode leaked into the pre-apply dependency footprint")
		}
		for _, related := range target.RelatedIdentities {
			if related == fresh.identity {
				t.Fatal("newly created inode appeared as a pre-apply related identity")
			}
		}
	}
}

func assertNamespaceTargetCoordinates(t *testing.T, targets []volumeserver.MutationTarget, parent mutationCoordinate, name string, related ...mutationCoordinate) {
	t.Helper()
	for _, target := range targets {
		if target.Scope != volumeserver.MutationNamespace || target.ParentIdentity != parent.identity || string(target.Name) != name {
			continue
		}
		for _, expectation := range related {
			found := false
			for _, identity := range target.RelatedIdentities {
				found = found || identity == expectation.identity
			}
			if !found {
				t.Fatalf("namespace target (%x,%q) omitted related identity %x", parent.identity, name, expectation.identity)
			}
		}
		return
	}
	t.Fatalf("targets omitted namespace coordinate (%x,%q)", parent.identity, name)
}

func assertInodeTargetCoordinate(t *testing.T, targets []volumeserver.MutationTarget, coordinate mutationCoordinate) {
	t.Helper()
	for _, target := range targets {
		if target.Scope != volumeserver.MutationNamespace && target.Identity == coordinate.identity {
			return
		}
	}
	t.Fatalf("targets omitted inode coordinate %x", coordinate.identity)
}
