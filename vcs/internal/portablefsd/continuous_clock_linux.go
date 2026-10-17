//go:build linux

package portablefsd

import (
	"errors"

	"golang.org/x/sys/unix"
)

// v3ContinuousNanos reads CLOCK_BOOTTIME, Linux's monotonic clock that keeps
// advancing across suspend.
func v3ContinuousNanos() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return 0, err
	}
	if now.Sec < 0 || now.Nsec < 0 || uint64(now.Sec) > (^uint64(0)-uint64(now.Nsec))/1e9 {
		return 0, errors.New("portablefsd: CLOCK_BOOTTIME is out of range")
	}
	return uint64(now.Sec)*1e9 + uint64(now.Nsec), nil
}
