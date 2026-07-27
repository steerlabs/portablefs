//go:build !darwin

package portablefsd

// Non-darwin builds have no FSKit kernel state in front of the daemon; the
// FUSE mount path invalidates through NotifyContent instead.
func refreshKernelFile(string, string, uint64, int64) bool { return true }
