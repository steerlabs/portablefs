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
	if fsType != expectedFSType {
		return fmt.Errorf("filesystem type is %q, want %q", fsType, expectedFSType)
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
