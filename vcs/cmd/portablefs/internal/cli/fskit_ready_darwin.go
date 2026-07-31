//go:build darwin

package cli

import (
	"fmt"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

func verifyFSKitMountIdentity(mountPath, expectedFSType, expectedSource string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mountPath, &stat); err != nil {
		return err
	}
	mountedOn := darwinStatfsString(stat.Mntonname[:])
	if mountedOn != mountPath {
		return fmt.Errorf("%w at %s", errRecordedMountAbsent, mountPath)
	}
	fsType := darwinStatfsString(stat.Fstypename[:])
	source := darwinStatfsString(stat.Mntfromname[:])
	return validateFSKitKernelIdentity(fsType, source, expectedFSType, expectedSource)
}

func verifyRecordedMountIdentity(st *mountState) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(st.MountPath, &stat); err != nil {
		return err
	}
	if darwinStatfsString(stat.Mntonname[:]) != st.MountPath {
		return fmt.Errorf("%w at %s", errRecordedMountAbsent, st.MountPath)
	}
	if st.Strategy != "fskit" || st.AttachRef == "" {
		return fmt.Errorf("recorded mount identity is incomplete: strategy=%q attachRef=%q", st.Strategy, st.AttachRef)
	}
	fsType := st.FSType
	if fsType == "" {
		fsType = defaultFskitType
	}
	return verifyFSKitMountIdentity(
		st.MountPath,
		fsType,
		fskitidentity.ResourcePrefix+st.AttachRef,
	)
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
