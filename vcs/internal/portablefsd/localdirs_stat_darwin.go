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
