// Package mountrecord owns the machine-local basename shared by one mount's
// state, operation intent, and diagnostic log. The on-disk record format is
// internal, but every process in one paired release must derive the same name.
package mountrecord

import (
	"fmt"
	"hash/fnv"
	"path/filepath"
)

// Key returns the stable filesystem-safe key for a canonical mount path.
func Key(mountPath string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(mountPath))
	return fmt.Sprintf("%016x", h.Sum64())
}

func LogPath(dir, mountPath string) string {
	return filepath.Join(dir, Key(mountPath)+".log")
}
