//go:build !darwin && !linux

package portablefsd

import (
	"errors"
	"time"
)

func startV3RenewalBudget(time.Duration, func()) (func(), error) {
	return nil, errors.New("portablefsd: continuous renewal deadlines are unsupported on this platform")
}
