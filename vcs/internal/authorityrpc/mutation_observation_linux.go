//go:build linux

package authorityrpc

import (
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
)

// MutationObservation joins the transport request to its replay identity. It
// contains no paths, data, tokens or unbounded collections. Observers must be
// nonblocking, safe concurrently, and account for dropped records themselves.
type MutationObservation struct {
	RequestID   uint64
	Session     [16]byte
	Slot        uint32
	Sequence    uint64
	Operation   authoritymetrics.Operation
	Disposition string // executed, replayed, or refused
	Started     time.Time
	Duration    time.Duration
}
