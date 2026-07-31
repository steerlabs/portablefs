package portablefsd

import (
	"io/fs"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// applyLocalGraftFlags has no linux counterpart: there is no chflags(2) and
// applyLocalStatTimes below reports no flag word, so a flags change on a graft
// could only ever be a silent no-op here. Refuse it instead. The daemon only
// runs on macOS; this arm exists so the package keeps building on the linux CI
// runners.
func applyLocalGraftFlags(fd int, fi fs.FileInfo, requested uint32) error {
	return unix.ENOTSUP
}

// applyLocalStatTimes fills ctime/atime/nlink from the linux stat shape
// (Ctim/Atim). The daemon only runs on macOS, but the package must keep
// compiling on the linux CI runners.
func applyLocalStatTimes(fi fs.FileInfo, attr *fsproto.Attr) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	attr.CtimeMs = time.Unix(st.Ctim.Sec, st.Ctim.Nsec).UnixMilli()
	attr.AtimeMs = time.Unix(st.Atim.Sec, st.Atim.Nsec).UnixMilli()
	attr.Nlink = uint32(st.Nlink)
	// Linux also defines st_blocks in fixed 512-byte units.
	attr.AllocSize = st.Blocks * 512
}
