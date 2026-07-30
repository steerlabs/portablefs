// Package accountpath resolves the effective user's account home without
// consulting mutable HOME environment state.
package accountpath

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// Home resolves the euid's account-database home and validates that it is an
// absolute, real directory owned by that uid.
func Home() (string, error) {
	uid := os.Geteuid()
	entry, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("resolve account database entry for uid %d: %w; provision a real passwd/NSS account before using PortableFS", uid, err)
	}
	home := entry.HomeDir
	if home == "" {
		return "", fmt.Errorf("account database returned no home for uid %d", uid)
	}
	return validateHome(home, uid)
}

func validateHome(home string, uid int) (string, error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", fmt.Errorf("account database returned non-canonical home %q for uid %d", home, uid)
	}
	info, err := os.Lstat(home)
	if err != nil {
		return "", fmt.Errorf("inspect account home %s: %w", home, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("account home %s is not a real directory", home)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(uid) {
		return "", fmt.Errorf("account home %s is not owned by uid %d", home, uid)
	}
	return home, nil
}
