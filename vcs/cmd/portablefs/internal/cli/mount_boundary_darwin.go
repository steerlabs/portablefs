//go:build darwin

package cli

func kernelMountBoundaries() ([]kernelMountBoundary, error) {
	mounts, err := darwinMountTable()
	if err != nil {
		return nil, err
	}
	out := make([]kernelMountBoundary, 0, len(mounts))
	for _, mount := range mounts {
		out = append(out, kernelMountBoundary{
			path:       mount.path,
			fsType:     mount.fsType,
			source:     mount.source,
			portableFS: isPortableFSKernelType(mount.fsType),
		})
	}
	return out, nil
}
