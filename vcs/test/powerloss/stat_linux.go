//go:build linux

package powerloss

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func rawStatOf(info fs.FileInfo) (rawAttributes, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return rawAttributes{}, false
	}
	return rawAttributes{mode: uint32(stat.Mode) & 0o7777, links: uint64(stat.Nlink), atimeNs: stat.Atim.Nano()}, true
}

// openNoAtime keeps verification from rewriting the atime it checks. Replayed
// images are mounted noatime anyway; unit tests run on whatever filesystem
// holds the temporary directory. O_NOATIME needs ownership or CAP_FOWNER, and
// without either the plain open is the only option left.
func openNoAtime(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOATIME, 0)
	if errors.Is(err, syscall.EPERM) {
		return os.Open(name)
	}
	return file, err
}
