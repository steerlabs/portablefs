//go:build linux

package cli

// platformKernelMountsAt returns every kernel mount whose mount point is
// exactly path, read from /proc/self/mountinfo. Like getfsstat(2) on Darwin
// it never resolves a pathname through a mounted filesystem, so it keeps
// answering while that filesystem is wedged.
func platformKernelMountsAt(path string) ([]kernelMountIdentity, error) {
	entries, err := linuxMountEntriesAt(path)
	if err != nil {
		return nil, err
	}
	at := make([]kernelMountIdentity, 0, len(entries))
	for _, entry := range entries {
		at = append(at, kernelMountIdentity{
			fsType: entry.fsType,
			path:   entry.mountPoint,
			source: entry.source,
		})
	}
	return at, nil
}
