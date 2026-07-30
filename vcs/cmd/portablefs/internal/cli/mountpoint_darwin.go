//go:build darwin

package cli

func isMountpoint(path string) bool {
	mounts, err := darwinMountTable()
	if err != nil {
		return false
	}
	for _, mount := range mounts {
		if mount.path == path {
			return true
		}
	}
	return false
}
