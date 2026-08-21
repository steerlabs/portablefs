package hydrator

import "fmt"

// The platform boundary. The restorer above it works in terms of open
// descriptors and one raw name component at a time; the syscalls that implement
// it live in sys_linux.go (the production path, openat2-confined, XFS export
// handles for inode identity) and sys_darwin.go (the development path).

// fileStat is the small part of stat the restorer needs: exactly enough to
// derive a fallback inode identity on a filesystem that cannot produce an XFS
// export handle. Everything else about a restored node is dictated by the
// manifest, never read back from the filesystem.
type fileStat struct {
	Ino      uint64
	DevMajor uint32
	DevMinor uint32
}

func errnoContext(operation, name string, err error) error {
	return fmt.Errorf("hydrator: %s %q: %w", operation, name, err)
}
