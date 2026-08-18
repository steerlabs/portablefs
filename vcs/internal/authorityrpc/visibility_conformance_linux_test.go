//go:build linux

package authorityrpc

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// TestEncodedVisibilityTargetsSatisfyTheWireContract is the conformance link
// between the one encoder and the two decoders. Both decoders admit targets
// only through visibilitywire.ValidateTarget, so the property that has to
// hold is exactly this one: every target this server can construct encodes to
// a shape that validator admits. The original defect — the unused identity of
// a fixed-size array serialized as sixteen zero bytes, shipped through every
// Linux gate because only the macOS-path decoder demanded absence — is the
// regression this test exists to keep dead.
func TestEncodedVisibilityTargetsSatisfyTheWireContract(t *testing.T) {
	parent := visibilityCoordinate{ino: 42, device: 0x700000001}
	object := visibilityCoordinate{ino: 7, device: 0x700000001}
	for i := range parent.identity {
		parent.identity[i] = byte(i + 1)
		object.identity[i] = byte(0x80 + i)
	}

	cases := []struct {
		name   string
		target volumeserver.VisibilityTarget
	}{
		{"namespace", namespaceTarget(parent, []byte("victim"))},
		{"namespace post-binding", namespaceTargetPost(parent, []byte("alias"), object)},
		{"data", inodeTarget(volumeserver.VisibilityData, object, 4096)},
		{"data at zero size", inodeTarget(volumeserver.VisibilityData, object, 0)},
		{"attributes", inodeTarget(volumeserver.VisibilityAttributes, object, 0)},
	}
	for _, tc := range cases {
		encoded := visibilityTargetProto(tc.target)
		if err := visibilitywire.ValidateTarget(encoded); err != nil {
			t.Fatalf("%s: the authority encoded a target its own frontends refuse: %v", tc.name, err)
		}
	}

	ns := visibilityTargetProto(namespaceTarget(parent, []byte("victim")))
	if len(ns.GetIdentity()) != 0 {
		t.Fatal("a namespace target put its unused object identity on the wire; absence and a zero value are different shapes and a decoder is entitled to refuse the latter")
	}
	post := visibilityTargetProto(namespaceTargetPost(parent, []byte("alias"), object))
	if got := post.GetPostIdentity(); len(got) != 16 || string(got) != string(object.identity[:]) {
		t.Fatalf("namespace post identity = %x, want %x", got, object.identity)
	}
	data := visibilityTargetProto(inodeTarget(volumeserver.VisibilityData, object, 4096))
	if len(data.GetParentIdentity()) != 0 || len(data.GetName()) != 0 {
		t.Fatal("an inode target put unused parent-scoped fields on the wire")
	}
}

// An unknown scope must encode to something every decoder refuses, never to a
// guessable coordinate.
func TestUnknownScopeEncodesToARefusedTarget(t *testing.T) {
	encoded := visibilityTargetProto(volumeserver.VisibilityTarget{Scope: volumeserver.VisibilityScope(99)})
	if err := visibilitywire.ValidateTarget(encoded); err == nil {
		t.Fatal("a target with an unknown scope encoded to an admissible shape")
	}
}

func TestNamespacePostBindingsAppearOnlyInSuccessfulCompleteTargets(t *testing.T) {
	parent := visibilityCoordinate{identity: [16]byte{1}, ino: 2, device: 3}
	object := visibilityCoordinate{identity: [16]byte{4}, ino: 5, device: 3}

	linkPrepare := linkVisibilityTargets([]byte("alias"), parent, object, false)
	linkComplete := linkVisibilityTargets([]byte("alias"), parent, object, true)
	if linkPrepare[0].PostIdentity != ([16]byte{}) {
		t.Fatalf("link PREPARE attested unapplied post-binding %x", linkPrepare[0].PostIdentity)
	}
	if linkComplete[0].PostIdentity != object.identity {
		t.Fatalf("link COMPLETE post-binding = %x, want %x", linkComplete[0].PostIdentity, object.identity)
	}

	rename := &authoritypb.RenameRequest{OldName: []byte("old"), NewName: []byte("new")}
	renamePrepare := renameVisibilityTargets(rename, parent, parent, object, visibilityCoordinate{}, false, visibilityCoordinate{}, false, false)
	renameComplete := renameVisibilityTargets(rename, parent, parent, object, visibilityCoordinate{}, false, visibilityCoordinate{}, false, true)
	if renamePrepare[1].PostIdentity != ([16]byte{}) {
		t.Fatalf("rename PREPARE attested unapplied post-binding %x", renamePrepare[1].PostIdentity)
	}
	if renameComplete[1].PostIdentity != object.identity {
		t.Fatalf("rename COMPLETE post-binding = %x, want %x", renameComplete[1].PostIdentity, object.identity)
	}
}

// TestMutationVisibilityBuildersExposeDependencyCoordinates is the authority
// half of the dependency-schema model. Execute checks these production PREPARE
// targets against an independently derived source gate; the volumeserver model
// applies the same split and converts the target side to VisibilityResolution
// keys. Keeping this test beside the builders catches an operation that stops
// exposing a parent, binding, endpoint, moved inode, or replacement inode.
func TestMutationVisibilityBuildersExposeDependencyCoordinates(t *testing.T) {
	coordinate := func(identity byte) visibilityCoordinate {
		return visibilityCoordinate{identity: [16]byte{identity}, ino: uint64(identity), device: 1}
	}
	parent, otherParent := coordinate(1), coordinate(2)
	moved, replacement, source := coordinate(3), coordinate(4), coordinate(5)
	fresh := coordinate(6)

	type namespaceExpectation struct {
		parent  visibilityCoordinate
		name    string
		related []visibilityCoordinate
	}
	type operation struct {
		name       string
		targets    []volumeserver.VisibilityTarget
		namespaces []namespaceExpectation
		inodes     []visibilityCoordinate
	}
	rename := &authoritypb.RenameRequest{OldName: []byte("old"), NewName: []byte("new")}
	operations := []operation{
		{
			name: "create or symlink",
			targets: []volumeserver.VisibilityTarget{
				namespaceTarget(parent, []byte("fresh")),
				inodeTarget(volumeserver.VisibilityAttributes, parent, 0),
			},
			namespaces: []namespaceExpectation{{parent: parent, name: "fresh"}},
			inodes:     []visibilityCoordinate{parent},
		},
		{
			name: "unlink or rmdir",
			targets: []volumeserver.VisibilityTarget{
				namespaceTargetRelated(parent, []byte("victim"), moved),
				inodeTarget(volumeserver.VisibilityAttributes, parent, 0),
				inodeTarget(volumeserver.VisibilityAttributes, moved, 0),
			},
			namespaces: []namespaceExpectation{{parent: parent, name: "victim", related: []visibilityCoordinate{moved}}},
			inodes:     []visibilityCoordinate{parent, moved},
		},
		{
			name:       "link",
			targets:    linkVisibilityTargets([]byte("alias"), parent, source, false),
			namespaces: []namespaceExpectation{{parent: parent, name: "alias", related: []visibilityCoordinate{source}}},
			inodes:     []visibilityCoordinate{parent, source},
		},
		{
			name:    "rename over existing",
			targets: renameVisibilityTargets(rename, parent, otherParent, moved, replacement, true, visibilityCoordinate{}, false, false),
			namespaces: []namespaceExpectation{
				{parent: parent, name: "old", related: []visibilityCoordinate{moved}},
				{parent: otherParent, name: "new", related: []visibilityCoordinate{moved, replacement}},
			},
			inodes: []visibilityCoordinate{parent, otherParent, moved, replacement},
		},
		{
			name: "copy_file_range",
			targets: []volumeserver.VisibilityTarget{
				inodeTarget(volumeserver.VisibilityData, moved, 10),
				inodeTarget(volumeserver.VisibilityData, replacement, 20),
			},
			inodes: []visibilityCoordinate{moved, replacement},
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
			if _, err := normalizeVisibilityTargets(operation.targets); err != nil {
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

func assertNamespaceTargetCoordinates(t *testing.T, targets []volumeserver.VisibilityTarget, parent visibilityCoordinate, name string, related ...visibilityCoordinate) {
	t.Helper()
	for _, target := range targets {
		if target.Scope != volumeserver.VisibilityNamespace || target.ParentIdentity != parent.identity || string(target.Name) != name {
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

func assertInodeTargetCoordinate(t *testing.T, targets []volumeserver.VisibilityTarget, coordinate visibilityCoordinate) {
	t.Helper()
	for _, target := range targets {
		if target.Scope != volumeserver.VisibilityNamespace && target.Identity == coordinate.identity {
			return
		}
	}
	t.Fatalf("targets omitted inode coordinate %x", coordinate.identity)
}
