package portablefsd

import (
	"io/fs"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

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
	if st.Nlink > 0 {
		attr.Nlink = uint32(st.Nlink)
	}
}
