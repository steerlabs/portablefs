//go:build !darwin

package portablefsd

// Non-darwin builds have no FSKit kernel state in front of the daemon; the
// FUSE mount path invalidates through NotifyContent instead.
// It issues no ftruncate, so it arms no provenance window either.
func refreshKernelFile(string, string, uint64, int64, func() (func(), error)) (kernelRefreshOutcome, error) {
	return kernelRefreshApplied, nil
}
