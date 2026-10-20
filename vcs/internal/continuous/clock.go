// Package continuous supplies the host monotonic clock which advances across
// suspend. Its timestamps are local elapsed time, never Unix wall time.
package continuous

import (
	"errors"
	"math"
	"time"
)

func timespec(sec, nsec int64) (time.Duration, error) {
	if sec < 0 || nsec < 0 || nsec >= 1e9 || sec > (math.MaxInt64-nsec)/1e9 {
		return 0, errors.New("continuous: clock timespec is out of range")
	}
	return time.Duration(sec)*time.Second + time.Duration(nsec), nil
}

// Time represents elapsed nanoseconds as a time.Time without a Go monotonic
// reading. Only timestamps from this domain may be compared with it. Failure is
// fatal: neither retaining nor expiring distributed permission is safe without
// the clock, and substituting a wall or active-time clock would grant permission.
func Time() time.Time {
	now, err := Now()
	if err != nil {
		panic(err)
	}
	return time.Unix(0, int64(now))
}
