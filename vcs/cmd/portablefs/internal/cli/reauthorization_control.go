package cli

import (
	"context"
	"time"
)

type fuseReauthorizationHandler func(context.Context, string, uint64, []byte) (time.Time, error)

// fuseLossSnapshotHandler reads the live mount counter; no persisted/logged sample.
type fuseLossSnapshotHandler func() (mountLossSnapshot, error)

type mountLossSnapshot struct {
	MountInstanceID string `json:"mountInstanceId"`
	LossSequence    string `json:"lossSequence"`
}

type fuseReauthorizationControl interface {
	Close() error
	SocketPath() string
}
