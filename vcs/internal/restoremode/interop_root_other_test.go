//go:build !linux

package restoremode_test

import "testing"

// Outside Linux there is no name_to_handle_at, the hydrator derives stable
// identities from the documented dev+ino fallback, and any local filesystem
// hosts the fixture faithfully.
func interopVolumeRoot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
