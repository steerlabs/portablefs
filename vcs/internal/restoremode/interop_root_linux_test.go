package restoremode_test

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// interopVolumeRoot places the interop fixture's materialized namespace on a
// filesystem whose stable identities the REAL hydrator can derive. On Linux
// that derivation is pinned to XFS: identityFromHandle refuses an export
// handle that is not the 12 bytes an XFS handle carries, because production
// volumes are XFS-authoritative and a cell serving anything else is
// misprovisioned. A filesystem with no export handles at all (the darwin
// development path) uses the documented dev+ino fallback and works; a
// filesystem with differently shaped handles — ext4 on a stock CI runner —
// honestly cannot host this test.
//
// So: the provisioned XFS volume (PORTABLEFS_XFS_TEST_ROOT, exported by
// scripts/xfs-fuse-integration.sh) hosts the fixture when present, and the
// privileged suite lists the interop tests as required there. Anywhere else
// the local temp filesystem is probed first, and a handle shape the hydrator
// would refuse skips the test by name rather than failing it — unless
// PORTABLEFS_XFS_TEST_REQUIRED=1, where a missing root is a provisioning
// failure and must say so instead of skipping coverage away.
func interopVolumeRoot(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("PORTABLEFS_XFS_TEST_ROOT"); root != "" {
		directory, err := os.MkdirTemp(root, "interop-")
		if err != nil {
			t.Fatalf("create interop fixture root on the provisioned XFS volume: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		return directory
	}
	if os.Getenv("PORTABLEFS_XFS_TEST_REQUIRED") == "1" {
		t.Fatal("PORTABLEFS_XFS_TEST_REQUIRED=1 but PORTABLEFS_XFS_TEST_ROOT is unset; the interop fixture needs the provisioned XFS volume")
	}
	directory := t.TempDir()
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, directory, 0)
	if err == nil && len(handle.Bytes()) != 12 {
		t.Skipf("this filesystem answers %d-byte export handles, which the hydrator's XFS identity contract refuses; run scripts/xfs-fuse-integration.sh for the real-XFS interop proof", len(handle.Bytes()))
	}
	return directory
}
