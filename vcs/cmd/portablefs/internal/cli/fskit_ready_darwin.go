//go:build darwin

package cli

import (
	"fmt"
	"syscall"
)

func verifyFSKitMountIdentity(mountPath, expectedFSType, expectedSource string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mountPath, &stat); err != nil {
		return err
	}
	fsType := darwinStatfsString(stat.Fstypename[:])
	// FSKit's registration short name (the value passed to mount -t, "pfs"
	// by default) selects the extension. Once mounted, macOS 26 exposes the
	// framework's canonical runtime type "portablefs" through statfs rather
	// than echoing that registration name. The source below remains the
	// attach-specific identity check.
	const fskitRuntimeType = "portablefs"
	if fsType != fskitRuntimeType {
		return fmt.Errorf(
			"filesystem type is %q, want FSKit runtime type %q (registered as %q)",
			fsType,
			fskitRuntimeType,
			expectedFSType,
		)
	}
	source := darwinStatfsString(stat.Mntfromname[:])
	if source != expectedSource {
		return fmt.Errorf("mount source is %q, want %q", source, expectedSource)
	}
	return nil
}

func darwinStatfsString(chars []int8) string {
	buf := make([]byte, 0, len(chars))
	for _, char := range chars {
		if char == 0 {
			break
		}
		buf = append(buf, byte(char))
	}
	return string(buf)
}
