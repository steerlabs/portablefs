//go:build darwin

package continuous

import (
	"time"

	"golang.org/x/sys/unix"
)

// Now reads CLOCK_MONOTONIC_RAW, which includes suspend on Darwin.
func Now() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts); err != nil {
		return 0, err
	}
	return timespec(ts.Sec, ts.Nsec)
}
