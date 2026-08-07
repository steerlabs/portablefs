package visibilitywire

import (
	"bytes"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func identity(fill byte) []byte { return bytes.Repeat([]byte{fill}, IdentityLen) }

func TestConstructorsProduceValidTargets(t *testing.T) {
	cases := []struct {
		name   string
		target *authoritypb.VisibilityTarget
	}{
		{"namespace", Namespace(identity(1), []byte("victim"), 42, 0x700000001)},
		{"namespace post-binding", func() *authoritypb.VisibilityTarget {
			target := Namespace(identity(1), []byte("alias"), 42, 0x700000001)
			target.PostIdentity = identity(4)
			return target
		}()},
		{"data", Data(identity(2), 7, 0x700000001, 4096)},
		{"data at zero size", Data(identity(2), 7, 0x700000001, 0)},
		{"attributes", Attributes(identity(3), 7, 0x700000001)},
	}
	for _, tc := range cases {
		if err := ValidateTarget(tc.target); err != nil {
			t.Fatalf("%s: the constructor and the validator disagree about the wire shape: %v", tc.name, err)
		}
	}
}

// TestUnusedFieldsAreAbsentNotZero pins the exact defect this package was
// created for: an encoder that serializes an unused fixed-size identity array
// puts sixteen zero bytes on the wire, and a decoder entitled to absence
// revokes the mount on its first mutation.
func TestUnusedFieldsAreAbsentNotZero(t *testing.T) {
	ns := Namespace(identity(1), []byte("victim"), 42, 0x700000001)
	if len(ns.GetIdentity()) != 0 || ns.GetKernelIno() != 0 || ns.GetSize() != 0 {
		t.Fatal("a namespace target carried object-scoped fields")
	}
	for _, target := range []*authoritypb.VisibilityTarget{
		Data(identity(2), 7, 0x700000001, 1),
		Attributes(identity(3), 7, 0x700000001),
	} {
		if len(target.GetParentIdentity()) != 0 || len(target.GetName()) != 0 || target.GetParentKernelIno() != 0 {
			t.Fatal("an inode target carried parent-scoped fields")
		}
	}

	zeroPadded := Namespace(identity(1), []byte("victim"), 42, 0x700000001)
	zeroPadded.Identity = make([]byte, IdentityLen)
	if ValidateTarget(zeroPadded) == nil {
		t.Fatal("a namespace target with a sixteen-zero-byte identity was admitted; absence and a zero value are different wire shapes")
	}
}

func TestValidateTargetRejectsEveryMalformedShape(t *testing.T) {
	mutate := func(f func(*authoritypb.VisibilityTarget)) *authoritypb.VisibilityTarget {
		target := Namespace(identity(1), []byte("victim"), 42, 0x700000001)
		f(target)
		return target
	}
	mutateData := func(f func(*authoritypb.VisibilityTarget)) *authoritypb.VisibilityTarget {
		target := Data(identity(2), 7, 0x700000001, 4096)
		f(target)
		return target
	}
	cases := []struct {
		name   string
		target *authoritypb.VisibilityTarget
	}{
		{"nil", nil},
		{"unspecified scope", &authoritypb.VisibilityTarget{}},
		{"unknown scope", &authoritypb.VisibilityTarget{Scope: 99}},
		{"namespace with object identity", mutate(func(t *authoritypb.VisibilityTarget) { t.Identity = identity(9) })},
		{"namespace with short post identity", mutate(func(t *authoritypb.VisibilityTarget) { t.PostIdentity = identity(9)[:8] })},
		{"namespace with short parent identity", mutate(func(t *authoritypb.VisibilityTarget) { t.ParentIdentity = t.ParentIdentity[:8] })},
		{"namespace without a name", mutate(func(t *authoritypb.VisibilityTarget) { t.Name = nil })},
		{"namespace with a path for a name", mutate(func(t *authoritypb.VisibilityTarget) { t.Name = []byte("a/b") })},
		{"namespace with self link name", mutate(func(t *authoritypb.VisibilityTarget) { t.Name = []byte(".") })},
		{"namespace with parent link name", mutate(func(t *authoritypb.VisibilityTarget) { t.Name = []byte("..") })},
		{"namespace with NUL in name", mutate(func(t *authoritypb.VisibilityTarget) { t.Name = []byte("a\x00b") })},
		{"namespace with overlong name", mutate(func(t *authoritypb.VisibilityTarget) { t.Name = bytes.Repeat([]byte{'a'}, 256) })},
		{"namespace with a size", mutate(func(t *authoritypb.VisibilityTarget) { t.Size = 1 })},
		{"namespace with object kernel inode", mutate(func(t *authoritypb.VisibilityTarget) { t.KernelIno = 7 })},
		{"namespace without parent kernel inode", mutate(func(t *authoritypb.VisibilityTarget) { t.ParentKernelIno = 0 })},
		{"namespace without a device", mutate(func(t *authoritypb.VisibilityTarget) { t.Device = 0 })},
		{"data without identity", mutateData(func(t *authoritypb.VisibilityTarget) { t.Identity = nil })},
		{"data with parent identity", mutateData(func(t *authoritypb.VisibilityTarget) { t.ParentIdentity = identity(1) })},
		{"data with post identity", mutateData(func(t *authoritypb.VisibilityTarget) { t.PostIdentity = identity(1) })},
		{"data with a name", mutateData(func(t *authoritypb.VisibilityTarget) { t.Name = []byte("victim") })},
		{"data with negative size", mutateData(func(t *authoritypb.VisibilityTarget) { t.Size = -1 })},
		{"data without kernel inode", mutateData(func(t *authoritypb.VisibilityTarget) { t.KernelIno = 0 })},
		{"data with parent kernel inode", mutateData(func(t *authoritypb.VisibilityTarget) { t.ParentKernelIno = 42 })},
		{"data without a device", mutateData(func(t *authoritypb.VisibilityTarget) { t.Device = 0 })},
		{"attributes with post identity", func() *authoritypb.VisibilityTarget {
			t := Attributes(identity(3), 7, 0x700000001)
			t.PostIdentity = identity(1)
			return t
		}()},
		{"attributes with a size", func() *authoritypb.VisibilityTarget {
			t := Attributes(identity(3), 7, 0x700000001)
			t.Size = 1
			return t
		}()},
	}
	for _, tc := range cases {
		if ValidateTarget(tc.target) == nil {
			t.Fatalf("%s was admitted; every decoder must fail closed on a shape the encoder cannot produce", tc.name)
		}
	}
}
