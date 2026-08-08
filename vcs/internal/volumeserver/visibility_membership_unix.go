//go:build darwin || linux

package volumeserver

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func lockVisibilityFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open visibility membership lock: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("visibility membership lock must be a private regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("lock visibility membership: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

func unlockVisibilityFile(file *os.File) error {
	return file.Close()
}

func openVisibilityMembership(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
