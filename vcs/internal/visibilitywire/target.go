// Package visibilitywire is the single definition of the visibility target
// wire shape. Exactly one process encodes targets (the authority) and exactly
// two decode them (the Linux FUSE frontend and portablefsd), and the shape is
// scope-exact: a field a scope does not define is absent, not zero-valued.
//
// This package exists because the encoder and the two decoders once each
// carried their own private idea of that shape. The encoder serialized the
// unused identity of a fixed-size array as sixteen zero bytes, the Linux
// decoder never looked at identities at all, and portablefsd correctly
// demanded absence — so the defect shipped through every Linux gate and broke
// the first real macOS mutation. The encoder now builds targets only through
// the constructors here, both decoders admit targets only through
// ValidateTarget, and a conformance test holds the two halves together.
package visibilitywire

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// IdentityLen is the exact length of a stable XFS export-handle identity on
// the wire: handle type, inode and generation. Never a device.
const IdentityLen = 16

// Namespace names one parent/name binding. The parent travels twice on
// purpose: the stable identity for frontends that index kernel state by item
// identity, and the kernel inode number plus backing device for frontends
// whose caches are keyed by the attr inode the authority publishes.
func Namespace(parentIdentity []byte, name []byte, parentKernelIno, device uint64) *authoritypb.VisibilityTarget {
	return &authoritypb.VisibilityTarget{
		Scope:           authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE,
		ParentIdentity:  append([]byte(nil), parentIdentity...),
		Name:            append([]byte(nil), name...),
		ParentKernelIno: parentKernelIno,
		Device:          device,
	}
}

// Data names one inode's content. Size is the authoritative post-mutation EOF.
func Data(identity []byte, kernelIno, device uint64, size int64) *authoritypb.VisibilityTarget {
	return &authoritypb.VisibilityTarget{
		Scope:     authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA,
		Identity:  append([]byte(nil), identity...),
		KernelIno: kernelIno,
		Device:    device,
		Size:      size,
	}
}

// Attributes names one inode's attributes.
func Attributes(identity []byte, kernelIno, device uint64) *authoritypb.VisibilityTarget {
	return &authoritypb.VisibilityTarget{
		Scope:     authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES,
		Identity:  append([]byte(nil), identity...),
		KernelIno: kernelIno,
		Device:    device,
	}
}

// ValidName reports whether a name is one the authority could have emitted in
// a namespace target: a single non-empty component with no NUL and no
// separator, and never a directory's self or parent link.
func ValidName(name []byte) bool {
	return len(name) > 0 && len(name) <= 255 && !bytes.Equal(name, []byte(".")) &&
		!bytes.Equal(name, []byte("..")) && !bytes.ContainsAny(name, "\x00/")
}

// ValidateTarget admits exactly the shapes the constructors above produce and
// nothing else. Both decoders call it before using a single field, and they
// fail closed on any violation: repairing a guessed coordinate would leave the
// real one stale, which is worse than revoking the mount.
func ValidateTarget(target *authoritypb.VisibilityTarget) error {
	if target == nil {
		return errors.New("visibilitywire: nil visibility target")
	}
	switch target.GetScope() {
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE:
		if len(target.GetIdentity()) != 0 {
			return errors.New("visibilitywire: namespace target carries an object identity")
		}
		if len(target.GetParentIdentity()) != IdentityLen {
			return errors.New("visibilitywire: namespace target parent identity is not an export handle")
		}
		if !ValidName(target.GetName()) {
			return errors.New("visibilitywire: namespace target name is not a single valid component")
		}
		if target.GetSize() != 0 {
			return errors.New("visibilitywire: namespace target carries a size")
		}
		if target.GetKernelIno() != 0 {
			return errors.New("visibilitywire: namespace target carries an object kernel inode")
		}
		if target.GetParentKernelIno() == 0 {
			return errors.New("visibilitywire: namespace target carries no parent kernel inode")
		}
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA:
		if err := validateInodeTarget(target); err != nil {
			return err
		}
		if target.GetSize() < 0 {
			return errors.New("visibilitywire: data target carries a negative size")
		}
	case authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES:
		if err := validateInodeTarget(target); err != nil {
			return err
		}
		if target.GetSize() != 0 {
			return errors.New("visibilitywire: attribute target carries a size")
		}
	default:
		return fmt.Errorf("visibilitywire: visibility target carries scope %d", target.GetScope())
	}
	if target.GetDevice() == 0 {
		return errors.New("visibilitywire: visibility target carries no backing device")
	}
	return nil
}

func validateInodeTarget(target *authoritypb.VisibilityTarget) error {
	if len(target.GetIdentity()) != IdentityLen {
		return errors.New("visibilitywire: inode target identity is not an export handle")
	}
	if len(target.GetParentIdentity()) != 0 {
		return errors.New("visibilitywire: inode target carries a parent identity")
	}
	if len(target.GetName()) != 0 {
		return errors.New("visibilitywire: inode target carries a name")
	}
	if target.GetKernelIno() == 0 {
		return errors.New("visibilitywire: inode target carries no kernel inode")
	}
	if target.GetParentKernelIno() != 0 {
		return errors.New("visibilitywire: inode target carries a parent kernel inode")
	}
	return nil
}
