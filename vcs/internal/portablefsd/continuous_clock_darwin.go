//go:build darwin

package portablefsd

import "golang.org/x/sys/unix"

// Darwin's RAW clock advances across sleep, like mach_continuous_time.
// Linux's RAW clock does not; that platform uses BOOTTIME instead.
func v3ContinuousNanos() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &now); err != nil {
		return 0, err
	}
	return v3TimespecNanos(now.Sec, now.Nsec)
}
