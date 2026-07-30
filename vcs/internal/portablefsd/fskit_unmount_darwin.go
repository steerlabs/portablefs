//go:build darwin

package portablefsd

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type fskitKernelMount struct {
	path   string
	fsType string
	source string
}

func hostFSKitKernelOps() fskitKernelOps {
	return fskitKernelOps{
		present: exactFSKitMountPresent,
		unmountExact: func(mountPath, attachRef string) error {
			present, err := exactFSKitMountPresent(mountPath, attachRef)
			if err != nil {
				return err
			}
			if !present {
				return fmt.Errorf("exact FSKit mount is absent at %s", mountPath)
			}
			if err := unix.Unmount(mountPath, 0); err != nil {
				return fmt.Errorf("unmount exact FSKit mount at %s: %w", mountPath, err)
			}
			present, err = exactFSKitMountPresent(mountPath, attachRef)
			if err != nil {
				return fmt.Errorf("verify exact FSKit unmount: %w", err)
			}
			if present {
				return fmt.Errorf("exact FSKit mount remains at %s after unmount", mountPath)
			}
			return nil
		},
	}
}

func exactFSKitMountPresent(mountPath, attachRef string) (bool, error) {
	mounts, err := fskitKernelMounts()
	if err != nil {
		return false, err
	}
	var atPath []fskitKernelMount
	for _, mount := range mounts {
		if mount.path == mountPath {
			atPath = append(atPath, mount)
		}
	}
	if len(atPath) == 0 {
		return false, nil
	}
	if len(atPath) != 1 {
		return false, fmt.Errorf("%d stacked kernel mounts exist at %s", len(atPath), mountPath)
	}
	expectedSource := "pfs://" + attachRef
	if atPath[0].fsType != "portablefs" || atPath[0].source != expectedSource {
		return false, fmt.Errorf(
			"kernel mount at %s is %s from %s, want portablefs from %s",
			mountPath, atPath[0].fsType, atPath[0].source, expectedSource,
		)
	}
	return true, nil
}

func fskitKernelMounts() ([]fskitKernelMount, error) {
	count, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, fmt.Errorf("read kernel mount count: %w", err)
	}
	for {
		stats := make([]unix.Statfs_t, count+8)
		n, err := unix.Getfsstat(stats, unix.MNT_NOWAIT)
		if err != nil {
			return nil, fmt.Errorf("read kernel mount table: %w", err)
		}
		if n < len(stats) {
			out := make([]fskitKernelMount, 0, n)
			for _, stat := range stats[:n] {
				out = append(out, fskitKernelMount{
					path:   unix.ByteSliceToString(stat.Mntonname[:]),
					fsType: unix.ByteSliceToString(stat.Fstypename[:]),
					source: unix.ByteSliceToString(stat.Mntfromname[:]),
				})
			}
			return out, nil
		}
		count = n
	}
}
