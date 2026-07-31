package portablefsd

import (
	"io/fs"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// graftFlagsMask is the subset of a graft backing file's st_flags PortableFS
// republishes. Everything outside it is kernel-managed state that does not
// describe the bytes the daemon serves. UF_COMPRESSED is the dangerous one:
// it would make the kernel run decmpfs decompression over content PortableFS
// hands back uncompressed, producing garbage reads. UF_TRACKED, UF_DATAVAULT,
// SF_RESTRICTED, SF_DATALESS, SF_FIRMLINK and SF_SYNTHETIC are likewise the
// backing volume's business, not this volume's.
const graftFlagsMask = uint32(unix.UF_NODUMP | unix.UF_IMMUTABLE | unix.UF_APPEND |
	unix.UF_OPAQUE | unix.UF_HIDDEN |
	unix.SF_ARCHIVED | unix.SF_IMMUTABLE | unix.SF_APPEND | unix.SF_NOUNLINK)

// applyLocalGraftFlags applies a chflags(2) to a graft's real backing file.
//
// A graft is machine-local disk, so the flag word lives in the host
// filesystem's inode, not in the authority's tree — chflags(2) IS the durable
// store here and no feature bit gates it.
//
// Two rules keep the write side symmetric with the read side
// (applyLocalStatTimes, which republishes only graftFlagsMask):
//
//   - bits OUTSIDE the mask are REFUSED with EINVAL rather than written. They
//     are the backing volume's kernel-managed business (UF_COMPRESSED would
//     make the kernel run decmpfs over content PortableFS serves
//     uncompressed), and a stat would never report them back, so writing them
//     would be a change the mount then denies having made.
//   - bits outside the mask that the backing file ALREADY carries are
//     preserved: the request is authoritative over the user-meaningful subset
//     only, and clobbering the rest to zero would strip host state this volume
//     never owned.
func applyLocalGraftFlags(fd int, fi fs.FileInfo, requested uint32) error {
	if requested&^graftFlagsMask != 0 {
		return unix.EINVAL
	}
	var current uint32
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		current = st.Flags
	}
	return unix.Fchflags(fd, int(current&^graftFlagsMask|requested))
}

// applyLocalStatTimes fills ctime/atime/nlink from the darwin stat shape
// (Ctimespec/Atimespec). The daemon only runs on macOS, but the package must
// keep compiling everywhere the repo's CI builds it.
func applyLocalStatTimes(fi fs.FileInfo, attr *fsproto.Attr) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	attr.CtimeMs = time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec).UnixMilli()
	attr.AtimeMs = time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec).UnixMilli()
	attr.BirthtimeMs = time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec).UnixMilli()
	attr.Nlink = uint32(st.Nlink)
	attr.Flags = st.Flags & graftFlagsMask
	// POSIX stat reports st_blocks in fixed 512-byte units; st_blksize is
	// only the filesystem's preferred I/O size and is not the multiplier.
	attr.AllocSize = st.Blocks * 512
}
