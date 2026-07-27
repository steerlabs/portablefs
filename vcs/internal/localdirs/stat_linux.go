package localdirs

import (
	"syscall"
	"time"
)

// Stat timestamp field names differ per GOOS (linux: *tim).

func statAtimeMs(st *syscall.Stat_t) int64 {
	return time.Unix(st.Atim.Sec, st.Atim.Nsec).UnixMilli()
}

func statMtimeMs(st *syscall.Stat_t) int64 {
	return time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UnixMilli()
}

func msToTime(ms int64) time.Time { return time.UnixMilli(ms) }
