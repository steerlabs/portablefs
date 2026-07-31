//go:build darwin

package cli

import (
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

// Mount identification reads the KERNEL MOUNT TABLE (getfsstat), never
// statfs/lstat of the mount path. A statfs of a mount point resolves that
// pathname, which enters the mounted filesystem's root: once a volume is dead
// the kernel answers EIO, and identification failed exactly when detaching was
// the remedy. getfsstat reports the same three facts (mount point, filesystem
// type, source) from the kernel's own table without ever entering the
// filesystem, so a dead volume with a live daemon classifies — and detaches —
// exactly like a live one. This mirrors portablefsd's exactFSKitMountPresent.

func verifyFSKitMountIdentity(mountPath, expectedFSType, expectedSource string) error {
	mount, err := exactKernelMountAt(mountPath)
	if err != nil {
		return err
	}
	if mount == nil {
		return fmt.Errorf("%w at %s", errRecordedMountAbsent, mountPath)
	}
	return validateFSKitKernelIdentity(mount.fsType, mount.source, expectedFSType, expectedSource)
}

func verifyRecordedMountIdentity(st *mountState) error {
	// Absence is decided FIRST, exactly as the statfs classifier did: with
	// nothing mounted at the recorded path there is no kernel object to own,
	// whatever the record says. Only a real mount is worth validating the
	// record against — a record that cannot describe one is then an error,
	// not a silent "absent".
	mount, err := exactKernelMountAt(st.MountPath)
	if err != nil {
		return err
	}
	if mount == nil {
		return fmt.Errorf("%w at %s", errRecordedMountAbsent, st.MountPath)
	}
	if st.Strategy != "fskit" || st.AttachRef == "" {
		return fmt.Errorf("recorded mount identity is incomplete: strategy=%q attachRef=%q", st.Strategy, st.AttachRef)
	}
	fsType := st.FSType
	if fsType == "" {
		fsType = defaultFskitType
	}
	return validateFSKitKernelIdentity(
		mount.fsType,
		mount.source,
		fsType,
		fskitidentity.ResourcePrefix+st.AttachRef,
	)
}
