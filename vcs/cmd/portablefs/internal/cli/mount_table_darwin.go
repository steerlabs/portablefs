//go:build darwin

package cli

// platformKernelMountsAt returns every kernel mount whose mount point is
// exactly path. getfsstat(2) reads the kernel's own mount table: it never
// resolves a pathname through a mounted filesystem, so it keeps answering
// while the filesystem at path is wedged and fails every request with EIO.
func platformKernelMountsAt(path string) ([]kernelMountIdentity, error) {
	mounts, err := darwinMountTable()
	if err != nil {
		return nil, err
	}
	var at []kernelMountIdentity
	for _, mount := range mounts {
		if mount.path == path {
			at = append(at, mount)
		}
	}
	return at, nil
}
