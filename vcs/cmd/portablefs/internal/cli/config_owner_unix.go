//go:build unix

package cli

import (
	"fmt"
	"os"
	"syscall"
)

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func verifyConfigFilePermissions(path string, info os.FileInfo) error {
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("refuse unsafe config %s: file is not owned by the current user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("refuse unsafe config %s: permissions must be 0600", path)
	}
	return nil
}

func verifyConfigDirectoryPermissions(dir string, info os.FileInfo, repair bool) error {
	if !ownedByCurrentUser(info) {
		return fmt.Errorf("refuse unsafe config directory %s: directory is not owned by the current user", dir)
	}
	if repair {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("secure config directory %s: %w", dir, err)
		}
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("refuse unsafe config directory %s: permissions must be 0700", dir)
	}
	return nil
}

func secureTemporaryConfigFile(path string, file *os.File) error {
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary config %s: %w", path, err)
	}
	return nil
}
