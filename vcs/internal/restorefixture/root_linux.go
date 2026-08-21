// Package restorefixture is test support: it places a test's materialized
// restore namespace on a filesystem whose stable identities the hydrator's
// restore path can actually derive.
//
// On Linux that derivation is pinned to XFS: identityFromHandle refuses an
// export handle that is not the 12 bytes an XFS handle carries, because
// production volumes are XFS-authoritative and a cell serving anything else is
// misprovisioned. A filesystem with no export handles at all (the darwin
// development path) uses the documented dev+ino fallback and works; a
// filesystem with differently shaped handles — ext4 on a stock CI runner —
// honestly cannot host such a fixture.
package restorefixture

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Root returns a directory for one materialized restore namespace. The
// provisioned XFS volume (PORTABLEFS_XFS_TEST_ROOT, exported by
// scripts/xfs-fuse-integration.sh) hosts it when present, and the privileged
// suite lists the tests that call this as required there, so the real-XFS
// proof cannot silently stop running. Anywhere else the local temp filesystem
// is probed first, and a handle shape the hydrator would refuse skips the
// test by name rather than failing it — unless PORTABLEFS_XFS_TEST_REQUIRED=1,
// where a missing root is a provisioning failure and must say so instead of
// skipping coverage away.
func Root(t testing.TB) string {
	t.Helper()
	if root := os.Getenv("PORTABLEFS_XFS_TEST_ROOT"); root != "" {
		directory, err := os.MkdirTemp(root, "restore-fixture-")
		if err != nil {
			t.Fatalf("create a restore fixture root on the provisioned XFS volume: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		return directory
	}
	if os.Getenv("PORTABLEFS_XFS_TEST_REQUIRED") == "1" {
		t.Fatal("PORTABLEFS_XFS_TEST_REQUIRED=1 but PORTABLEFS_XFS_TEST_ROOT is unset; restore fixtures need the provisioned XFS volume")
	}
	directory := t.TempDir()
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, directory, 0)
	if err == nil && len(handle.Bytes()) != 12 {
		t.Skipf("this filesystem answers %d-byte export handles, which the hydrator's XFS identity contract refuses; run scripts/xfs-fuse-integration.sh for the real-XFS proof", len(handle.Bytes()))
	}
	return directory
}
