package main

import "golang.org/x/sys/unix"

const referenceClock = "linux.CLOCK_MONOTONIC"

func monotonicNow() (int64, error) {
	var stamp unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp)
	return stamp.Nano(), err
}
