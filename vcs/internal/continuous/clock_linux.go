//go:build linux

package continuous

import (
	"time"

	"golang.org/x/sys/unix"
)

// Now reads CLOCK_BOOTTIME, which includes suspend on Linux.
func Now() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return timespec(ts.Sec, ts.Nsec)
}
