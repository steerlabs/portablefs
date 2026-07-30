//go:build !darwin

package portablefsd

import "fmt"

func hostFSKitKernelOps() fskitKernelOps {
	unsupported := func(_, _ string) error {
		return fmt.Errorf("daemon-owned FSKit unmount is supported only on macOS")
	}
	return fskitKernelOps{
		present: func(_, _ string) (bool, error) {
			// FSKit kernel resources cannot exist on this platform. This
			// exact absence verdict lets daemon protocol tests and unsupported
			// hosts drain/remove an attach without inventing a path unmount.
			return false, nil
		},
		unmountExact: unsupported,
	}
}
