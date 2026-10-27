package main

import "golang.org/x/sys/unix"

// Python's time.monotonic_ns uses mach_absolute_time on Darwin. UPTIME_RAW
// exposes the same nanosecond domain; MONOTONIC_RAW would include host sleep.
const referenceClock = "darwin.CLOCK_UPTIME_RAW"

func monotonicNow() (int64, error) {
	var stamp unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_UPTIME_RAW, &stamp)
	return stamp.Nano(), err
}
