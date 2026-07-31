package portablefsd

import (
	"io/fs"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

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
