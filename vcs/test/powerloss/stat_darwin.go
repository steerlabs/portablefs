//go:build darwin

package powerloss

import (
	"io/fs"
	"os"
	"syscall"
)

func rawStatOf(info fs.FileInfo) (rawAttributes, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return rawAttributes{}, false
	}
	return rawAttributes{mode: uint32(stat.Mode) & 0o7777, links: uint64(stat.Nlink), atimeNs: stat.Atimespec.Nano()}, true
}

// openNoAtime has no Darwin equivalent of O_NOATIME. Verification checks
// timestamps before it reads content, so its own read cannot affect the
// comparison it is making.
func openNoAtime(name string) (*os.File, error) { return os.Open(name) }
