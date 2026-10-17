//go:build !linux

package volumeserver

import "time"

// The authority ships only on Linux. Other platforms exercise coordination in
// unit tests; controlled-clock tests inject ContinuousNow explicitly.
var continuousOrigin = time.Now()

func continuousNow() (time.Duration, error) { return time.Since(continuousOrigin), nil }
