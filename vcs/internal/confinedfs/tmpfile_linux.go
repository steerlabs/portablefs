//go:build linux

package confinedfs

import (
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenTmpfile creates an unnamed inode in a directory reached from this pinned
// root capability. os.Root intentionally rejects O_TMPFILE, so Linux uses the
// same openat2 primitive required at Root construction: RESOLVE_BENEATH makes
// the already-open root descriptor the hard boundary, while NO_MAGICLINKS
// excludes procfs-style descriptor substitution. There is no pathname retry.
func (r *Root) OpenTmpfile(name string, flags uint32, mode uint32) (*os.File, error) {
	name, err := clean(name)
	if err != nil {
		return nil, err
	}
	root, err := r.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fd, err := unix.Openat2(int(root.Fd()), name, &unix.OpenHow{
		Flags: uint64(flags) | unix.O_TMPFILE | unix.O_CLOEXEC,
		Mode:  uint64(mode & 0o7777),
		Resolve: unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "tmpfile:"+name), nil
}

// LinkTmpfile gives a linkable O_TMPFILE descriptor its first name beneath
// this root. AT_EMPTY_PATH is the kernel primitive for this operation; the
// destination directory is itself opened through the pinned os.Root before
// linkat, so neither endpoint is reconstructed through an ambient pathname.
func (r *Root) LinkTmpfile(fd int, newname string) error {
	newname, err := clean(newname)
	if err != nil || newname == "." {
		if err != nil {
			return err
		}
		return fs.ErrInvalid
	}
	directory, base := path.Split(newname)
	directory = strings.TrimSuffix(directory, "/")
	if directory == "" {
		directory = "."
	}
	if base == "" || base == "." || base == ".." {
		return fs.ErrInvalid
	}
	parent, err := r.root.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return unix.Linkat(fd, "", int(parent.Fd()), base, unix.AT_EMPTY_PATH)
}
