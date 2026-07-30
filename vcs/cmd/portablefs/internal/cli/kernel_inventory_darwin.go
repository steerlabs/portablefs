//go:build darwin

package cli

func portableFSKernelInventory() ([]string, error) {
	mounts, err := darwinMountTable()
	if err != nil {
		return nil, err
	}
	return portableFSKernelPaths(mounts)
}
