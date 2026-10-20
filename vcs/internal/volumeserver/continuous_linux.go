//go:build linux

package volumeserver

import (
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/continuous"
)

func continuousNow() (time.Duration, error) { return continuous.Now() }
