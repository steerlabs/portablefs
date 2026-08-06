//go:build linux

package authorityrpc

import (
	"testing"

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
