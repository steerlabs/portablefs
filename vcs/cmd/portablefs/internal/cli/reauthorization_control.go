package cli

import (
	"context"
	"time"
)

type fuseReauthorizationHandler func(context.Context, string, uint64, []byte) (time.Time, error)

type fuseReauthorizationControl interface {
	Close() error
	SocketPath() string
}
