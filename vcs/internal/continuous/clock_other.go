//go:build !linux && !darwin

package continuous

import (
	"errors"
	"time"
)

func Now() (time.Duration, error) {
	return 0, errors.New("continuous: no qualified suspend-inclusive clock on this platform")
}
