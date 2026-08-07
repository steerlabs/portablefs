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
	renamePrepare := renameVisibilityTargets(rename, parent, parent, object, visibilityCoordinate{}, false, false)
	renameComplete := renameVisibilityTargets(rename, parent, parent, object, visibilityCoordinate{}, false, true)
	if renamePrepare[1].PostIdentity != ([16]byte{}) {
		t.Fatalf("rename PREPARE attested unapplied post-binding %x", renamePrepare[1].PostIdentity)
	}
	if renameComplete[1].PostIdentity != object.identity {
		t.Fatalf("rename COMPLETE post-binding = %x, want %x", renameComplete[1].PostIdentity, object.identity)
	}
}
