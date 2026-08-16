//go:build linux

package localdirs

import (
	"os"
	"syscall"
)

// Tmpfile creates one unnamed file in an existing graft directory. OpenFile
// resolves the directory with openat2 beneath the pinned root descriptor;
// there is no absolute-path or component-walk fallback. O_EXCL is preserved
// because it is the kernel's exact choice between linkable and permanently
// anonymous O_TMPFILE semantics.
func (g *Grafts) Tmpfile(directory string, flags, mode uint32) (int, syscall.Errno) {
	if g == nil || g.Owner(directory) == "" {
		return -1, syscall.EXDEV
	}
	file, err := g.root.OpenTmpfile(directory, flags, uint32(os.FileMode(mode)&os.ModePerm))
	if err != nil {
		return -1, errnoOf(err)
	}
	return transferFD(file)
}

// LinkTmpfile gives a non-O_EXCL unnamed file its first name inside the same
// graft. The source is the retained descriptor itself, not a synthetic path;
// the destination is confined beneath the pinned root by Root.LinkTmpfile.
func (g *Grafts) LinkTmpfile(sourceRoot string, fd int, destination string) syscall.Errno {
	if g == nil || sourceRoot == "" || g.Owner(destination) != sourceRoot {
		return syscall.EXDEV
	}
	if destination == sourceRoot {
		return syscall.EISDIR
	}
	return errnoOf(g.root.LinkTmpfile(fd, destination))
}
