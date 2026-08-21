//go:build !linux

package restorefixture

import "testing"

// Outside Linux there is no name_to_handle_at, the hydrator derives stable
// identities from the documented dev+ino fallback, and any local filesystem
// hosts a restore fixture faithfully.
func Root(t testing.TB) string {
	t.Helper()
	return t.TempDir()
}
