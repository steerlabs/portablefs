package cli

import "fmt"

type kernelMountBoundary struct {
	path       string
	fsType     string
	source     string
	portableFS bool
}

// preflightKernelMountTarget classifies the candidate solely from the kernel
// mount table before any operation enters or enumerates the directory. It
// refuses exact mountpoints, directories that would cover a child mount, and
// paths nested under an unrecorded PortableFS mount.
func preflightKernelMountTarget(mountPath string) error {
	boundaries, err := kernelMountBoundaries()
	if err != nil {
		return fmt.Errorf("read kernel mount boundaries: %w", err)
	}
	return validateKernelMountTargetAgainst(mountPath, boundaries)
}

func validateKernelMountTargetAgainst(mountPath string, boundaries []kernelMountBoundary) error {
	for _, boundary := range boundaries {
		switch {
		case boundary.path == mountPath:
			return fmt.Errorf(
				"mount path %s is already a kernel mountpoint (%s from %s)",
				mountPath, boundary.fsType, boundary.source,
			)
		case pathContains(mountPath, boundary.path):
			return fmt.Errorf(
				"mount path %s would cover child kernel mount %s (%s from %s)",
				mountPath, boundary.path, boundary.fsType, boundary.source,
			)
		case boundary.portableFS && pathContains(boundary.path, mountPath):
			return fmt.Errorf(
				"mount path %s is nested under PortableFS kernel mount %s; nested mounts are not supported",
				mountPath, boundary.path,
			)
		}
	}
	return nil
}
