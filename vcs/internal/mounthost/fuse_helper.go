package mounthost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

var fuseHelperNames = []string{"fusermount3", "fusermount"}

// FUSEHelper mirrors go-fuse's resolution order, but returns only a
// root-managed executable whose file and complete path cannot be replaced by
// the invoking account.
func FUSEHelper() (string, bool) {
	return findFUSEHelper(exec.LookPath)
}

func findFUSEHelper(lookPath func(string) (string, error)) (string, bool) {
	return findFUSEHelperWith(lookPath, func(path string) bool {
		return ValidateFUSEHelper(path) == nil
	})
}

func findFUSEHelperWith(lookPath func(string) (string, error), trusted func(string) bool) (string, bool) {
	for _, name := range fuseHelperNames {
		if path, err := lookPath(name); err == nil && filepath.IsAbs(path) && trusted(path) {
			return path, true
		}
		fixed := filepath.Join("/bin", name)
		if path, err := lookPath(fixed); err == nil && filepath.IsAbs(path) && trusted(path) {
			return path, true
		}
	}
	return "", false
}

// ValidateFUSEHelper proves that path resolves to a root-owned regular
// executable and that neither its lexical nor resolved ancestry is
// group/world writable. Root-owned system symlinks such as /bin -> /usr/bin
// are accepted only after validating both sides of the link.
func ValidateFUSEHelper(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("FUSE helper %q is not a canonical absolute path", path)
	}
	if err := validateRootManagedPath(path, true); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve FUSE helper %s: %w", path, err)
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return fmt.Errorf("resolved FUSE helper %q is not canonical and absolute", resolved)
	}
	if err := validateRootManagedPath(resolved, false); err != nil {
		return err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("inspect resolved FUSE helper %s: %w", resolved, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("FUSE helper %s is not a root-owned, non-writable regular executable", resolved)
	}
	return nil
}

// validateRootManagedPath walks every lexical component. When symlinks are
// allowed, their inode must be root-owned; EvalSymlinks followed by a second
// walk proves the target ancestry separately.
func validateRootManagedPath(path string, allowSymlinks bool) error {
	current := string(filepath.Separator)
	rootInfo, err := os.Lstat(current)
	if err != nil {
		return fmt.Errorf("inspect FUSE helper root: %w", err)
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("FUSE helper root is not a root-owned non-writable directory")
	}
	parts := strings.Split(strings.TrimPrefix(path, current), current)
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect FUSE helper path component %s: %w", current, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("FUSE helper path component %s is not root-owned", current)
		}
		isLast := i == len(parts)-1
		if info.Mode()&os.ModeSymlink != 0 {
			if !allowSymlinks {
				return fmt.Errorf("resolved FUSE helper path still contains symlink %s", current)
			}
			continue
		}
		if isLast {
			continue
		}
		if !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("FUSE helper ancestor %s is not a root-owned non-writable directory", current)
		}
	}
	return nil
}
