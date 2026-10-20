//go:build !linux

package volumeserver

import (
	"errors"
	"time"
)

// Only the shipping Linux authority has a qualified sleep-aware clock.
// Coordination tests on other platforms must inject their clock explicitly.
func continuousNow() (time.Duration, error) {
	return 0, errors.New("volumeserver: sleep-aware authority clock requires Linux")
}
