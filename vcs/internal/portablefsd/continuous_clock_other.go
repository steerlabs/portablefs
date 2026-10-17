//go:build !darwin && !linux

package portablefsd

import "errors"

// v3ContinuousNanos has no qualified sleep-inclusive clock on this platform,
// so a data plane refuses to start rather than serve without a horizon.
func v3ContinuousNanos() (uint64, error) {
	return 0, errors.New("portablefsd: no continuous clock is qualified on this platform")
}
