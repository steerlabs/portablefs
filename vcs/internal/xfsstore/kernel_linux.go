//go:build linux

package xfsstore

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func checkAuthorityKernel() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return fmt.Errorf("xfsstore: read authority kernel release: %w", err)
	}
	return validateAuthorityKernel(unix.ByteSliceToString(uts.Release[:]))
}

// Linux 5.17 propagates both XFS log-force errors and VFS sync_fs errors to
// syncfs. A vendor backport is not a separately supported durability contract.
func validateAuthorityKernel(release string) error {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) == 3 {
		major, majorErr := strconv.ParseUint(parts[0], 10, 32)
		minor, minorErr := strconv.ParseUint(parts[1], 10, 32)
		if majorErr == nil && minorErr == nil && parts[2] != "" && (major > 5 || major == 5 && (minor > 17 || minor == 17 && !strings.Contains(parts[2], "-rc"))) {
			return nil
		}
	}
	return fmt.Errorf("xfsstore: authority requires Linux 5.17 or newer for XFS syncfs error reporting; kernel release %q is unsupported", release)
}
