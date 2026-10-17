//go:build linux

package volumeserver

import (
	"errors"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

func continuousNow() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	if ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= 1e9 || ts.Sec > (math.MaxInt64-ts.Nsec)/1e9 {
		return 0, errors.New("volumeserver: continuous clock overflow")
	}
	return time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec), nil
}
