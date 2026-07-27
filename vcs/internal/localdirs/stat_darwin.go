package localdirs

import (
	"syscall"
	"time"
)

// Stat timestamp field names differ per GOOS (darwin: *timespec).

func statAtimeMs(st *syscall.Stat_t) int64 {
	return time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec).UnixMilli()
}

func statMtimeMs(st *syscall.Stat_t) int64 {
	return time.Unix(st.Mtimespec.Sec, st.Mtimespec.Nsec).UnixMilli()
}

func msToTime(ms int64) time.Time { return time.UnixMilli(ms) }
