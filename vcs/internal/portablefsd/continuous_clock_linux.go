//go:build linux

package portablefsd

import "golang.org/x/sys/unix"

// v3ContinuousNanos reads CLOCK_BOOTTIME, Linux's monotonic clock that keeps
// advancing across suspend.
func v3ContinuousNanos() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return 0, err
	}
	return v3TimespecNanos(now.Sec, now.Nsec)
}
