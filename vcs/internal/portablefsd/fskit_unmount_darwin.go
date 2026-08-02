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
		unmountExact: func(mountPath, attachRef string, force bool) error {
			present, err := exactFSKitMountPresent(mountPath, attachRef)
			if err != nil {
				return err
			}
			if !present {
				return fmt.Errorf("exact FSKit mount is absent at %s", mountPath)
			}
			// MNT_FORCE IS WHAT MAKES `umount --force` A FORCE.
			//
			// Every unmount used to reach the kernel with flags 0, so a single
			// remaining reference anywhere in the mount answered EBUSY to BOTH
			// the clean unmount and the escape hatch. The escape hatch's whole
			// premise is that in-flight work is being abandoned — the durable
			// tail has already been parked as a recovery job by the time this
			// runs — so a detach that stops for a busy vnode is not an escape
			// hatch at all. The clean path still passes no force flag: a mount
			// that needs forcing is not cleanly unmountable, and saying so is
			// the only way a leaked reference ever gets found.
			//
			// THE SYSCALL IS ISSUED OUT OF PROCESS. `umount -f` is exactly
			// unmount(2) with MNT_FORCE, and `umount` is exactly unmount(2) with
			// flags 0 — but in a child whose kernel wait cannot pin portablefsd.
			// See kerneldetach.go for why an in-process unmount(2) is the one
			// call that can make this daemon unkillable.
			args := []string{"--", mountPath}
			if force {
				args = append([]string{"-f"}, args...)
			}
			if err := runKernelDetach(kernelDetachBudget, mountPath, args...); err != nil {
				if abandonedKernelDetach(err) {
					return err
				}
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
	if err := validateExactFSKitKernelMount(atPath[0].fsType, atPath[0].source, attachRef); err != nil {
		return false, fmt.Errorf(
			"kernel mount at %s does not match attach %s: %w",
			mountPath,
			attachRef,
			err,
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
