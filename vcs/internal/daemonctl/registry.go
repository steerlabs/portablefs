package daemonctl

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// PersistedAttachesFilename is the lifecycle filesystem boundary. A daemon
// durably removes this entry when its registry is empty. Nonempty contents
// remain private to their owning release.
const PersistedAttachesFilename = "attaches.json"

// RequireRegistryAbsent inspects only the name in a validated, pinned state
// directory. The caller must retain singleton and lifecycle exclusion when
// using this as replacement authorization; an early check is only preflight.
func RequireRegistryAbsent(parent *os.File) error {
	if parent == nil {
		return fmt.Errorf("missing pinned daemon state directory")
	}
	var stat unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), PersistedAttachesFilename, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect daemon registry entry: %w", err)
	}
	return fmt.Errorf("daemon registry entry %s exists; reconcile it with its owning daemon before replacement", PersistedAttachesFilename)
}
