package cli

import (
	"context"
	"github.com/steerlabs/portablefs/vcs/internal/mountlog"
	"time"
)

type fuseReauthorizationHandler func(context.Context, string, uint64, []byte) (time.Time, error)

// fuseLossSnapshotHandler reads the live mount counter; no persisted/logged sample.
type fuseLossSnapshotHandler func() (mountLossSnapshot, error)

type mountLossSnapshot struct {
	Metadata        *mountlog.MetadataStats `json:"metadata,omitempty"`
	MountInstanceID string                  `json:"mountInstanceId"`
	LossSequence    string                  `json:"lossSequence"`
}

type fuseReauthorizationControl interface {
	Close() error
	SocketPath() string
}
