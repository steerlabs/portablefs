//go:build linux

package authorityrpc

import (
	"context"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
)

// MutationObservation joins the transport request to its replay identity. It
// contains no paths, data, tokens or unbounded collections. Observers must be
// nonblocking, safe concurrently, and account for dropped records themselves.
type MutationObservation struct {
	RequestID          uint64
	Session            [16]byte
	Slot               uint32
	Sequence           uint64
	Operation          authoritymetrics.Operation
	Disposition        string // executed, replayed, or refused
	Started            time.Time
	Duration           time.Duration
	StorageWait        time.Duration
	ApplyDuration      time.Duration
	WithdrawalWait     time.Duration
	DurabilityWait     time.Duration
	DurabilityKind     string
	DetachedWithdrawal bool
}

type mutationPhase uint8

const (
	phaseStorageWait mutationPhase = iota
	phaseApply
	phaseWithdrawal
	phaseDurability
)

func noMutationPhase() {}

func beginMutationPhase(ctx context.Context, phase mutationPhase) func() {
	op, _ := ctx.Value(coherenceOperationKey{}).(*coherenceOperation)
	if op == nil || op.measurement == nil {
		return noMutationPhase
	}
	started := time.Now()
	return func() {
		elapsed := time.Since(started)
		switch phase {
		case phaseStorageWait:
			op.measurement.StorageWait += elapsed
		case phaseApply:
			op.measurement.ApplyDuration += elapsed
		case phaseWithdrawal:
			op.measurement.WithdrawalWait += elapsed
		case phaseDurability:
			op.measurement.DurabilityWait += elapsed
		}
	}
}
