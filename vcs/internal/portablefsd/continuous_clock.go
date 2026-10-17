package portablefsd

import (
	"errors"
	"math/bits"
)

// v3TicksToNanos converts mach ticks with the timebase numer/denom ratio in
// 128-bit arithmetic, refusing a result that does not fit 64 bits instead of
// wrapping into a time that could look valid.
func v3TicksToNanos(ticks, numer, denom uint64) (uint64, error) {
	if numer == 0 || denom == 0 {
		return 0, errors.New("portablefsd: invalid continuous clock timebase")
	}
	high, low := bits.Mul64(ticks, numer)
	if high >= denom {
		return 0, errors.New("portablefsd: continuous clock overflowed")
	}
	nanos, _ := bits.Div64(high, low, denom)
	return nanos, nil
}
