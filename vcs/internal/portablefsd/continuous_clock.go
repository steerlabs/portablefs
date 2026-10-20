package portablefsd

import "github.com/steerlabs/portablefs/vcs/internal/continuous"

// The daemon and Linux/authority permission owners share the qualified host
// clock: CLOCK_MONOTONIC_RAW on Darwin and CLOCK_BOOTTIME on Linux.
func v3ContinuousNanos() (uint64, error) {
	now, err := continuous.Now()
	return uint64(now), err
}
