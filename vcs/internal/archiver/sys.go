package archiver

import "fmt"

// The platform boundary. Everything above this file works in terms of open
// descriptors, one raw name component at a time, and the normalized stat below;
// the syscalls that implement it live in sys_linux.go (the production path,
// openat2-confined) and sys_darwin.go (the development path, descriptor
// relative with O_NOFOLLOW). Nothing in the package ever builds a path string
// and hands it to a syscall.

// inodeKind is the file type of one walked entry. The authority's create
// surface makes exactly three kinds, so a fourth in the tree is a typed
// failure rather than something to skip.
type inodeKind uint8

const (
	kindOther inodeKind = iota
	kindRegular
	kindDirectory
	kindSymlink
)

func (k inodeKind) String() string {
	switch k {
	case kindRegular:
		return "regular file"
	case kindDirectory:
		return "directory"
	case kindSymlink:
		return "symlink"
	default:
		return "unsupported inode"
	}
}

// fileStat is the normalized subset of stat the archive format carries, plus
// the identity fields the walk needs: nlink and (dev, ino) form hardlink
// groups, and (dev, ino) is re-checked when a file is reopened for reading.
type fileStat struct {
	Kind       inodeKind
	Mode       uint32
	Size       int64
	MTimeNanos int64
	CTimeNanos int64
	Nlink      uint32
	Ino        uint64
	Dev        uint64
}

// UnsupportedInodeError names the one path that failed the archive because its
// inode kind is not one the format carries. It is typed because the operator
// needs the path, and because "some inode somewhere is a socket" is not an
// actionable failure.
type UnsupportedInodeError struct {
	Path string
	Kind string
}

func (e *UnsupportedInodeError) Error() string {
	return fmt.Sprintf("archiver: %q is a %s, which the volume tree cannot legitimately contain", e.Path, e.Kind)
}

func (e *UnsupportedInodeError) Is(target error) bool { return target == ErrInvalid }

// UnreadableInodeError names a path the archive could not read because its own
// mode denies the volume's service identity — a mode-0000 file, a
// non-searchable directory.
//
// The archiver holds no capability that overrides discretionary access, by
// design: it reads one volume tree as exactly the identity that owns it. So a
// tree containing a node its owner cannot read cannot be archived, and the
// archive fails with this error rather than sealing a manifest that quietly
// omits the node or its extended attributes. The operator's remedy is to relax
// the mode; the contract's remedy is to decide whether such modes may exist at
// all, which is above this component.
type UnreadableInodeError struct {
	Path string
	Mode uint32
	Err  error
}

func (e *UnreadableInodeError) Error() string {
	return fmt.Sprintf("archiver: %q has mode %#o, which denies the volume service identity that must archive it: %v",
		e.Path, e.Mode, e.Err)
}

func (e *UnreadableInodeError) Unwrap() error { return e.Err }

func (e *UnreadableInodeError) Is(target error) bool { return target == ErrInvalid }
