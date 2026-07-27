//go:build !linux

package confinedfs

// Go's os.Root uses component-wise openat traversal with O_NOFOLLOW on Darwin
// and other supported Unix hosts.
func platformProbe(string) error { return nil }
