//go:build darwin && !cgo

package portablefsd

import "errors"

// v3ContinuousNanos needs mach_continuous_time, reachable only through cgo.
// Without it no cache horizon can be anchored, so a data plane refuses to start
// rather than serve without one.
func v3ContinuousNanos() (uint64, error) {
	return 0, errors.New("portablefsd: the Darwin continuous clock requires cgo")
}
