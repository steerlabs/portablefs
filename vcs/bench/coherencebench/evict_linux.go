//go:build linux

package coherencebench

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// EvictFilePages flushes dirty data, then applies POSIX_FADV_DONTNEED to every
// regular file below root. This removes resident file contents for the direct
// XFS cold run. Linux has no unprivileged per-tree API for evicting dentries and
// inode metadata, so the direct baseline retains those metadata caches.
func EvictFilePages(root string) error {
	unix.Sync()
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		err = unix.Fadvise(int(file.Fd()), 0, 0, unix.FADV_DONTNEED)
		closeErr := file.Close()
		if err != nil {
			return fmt.Errorf("evict %s: %w", path, err)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s after eviction: %w", path, closeErr)
		}
		return nil
	})
}
