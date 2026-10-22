//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type workspaceCutResult struct{ durability, release string }

// SuspendCut uses only the captured buffer, incarnation and old conservative
// deadline. Partial outcomes survive a later failed join or release.
func (m *delegationManager) SuspendCut(ctx context.Context, p workspaceDrainPermit) (result workspaceCutResult, err error) {
	result = workspaceCutResult{"unresolved", "unresolved"}
	if p.manager != m || !p.allows(p.buffer, p.incarnation, m.subscription.config.clock.Now()) {
		return result, errSubscriptionExpired
	}
	ctx, cancel := context.WithTimeout(ctx, p.deadline.Sub(m.subscription.config.clock.Now()))
	defer cancel()
	m.epoch.RLock()
	current := m.buf == p.buffer
	m.epoch.RUnlock()
	if !current {
		return result, writeback.ErrLost
	}
	// Only the lifecycle owner can retire this buffer. Barrier's epoch reader
	// therefore cannot select a successor after the captured identity check.
	barrierErr := m.Barrier(ctx, 0)
	if barrierErr != nil && !errors.Is(barrierErr, writeback.ErrLost) {
		return result, fmt.Errorf("fusev3: suspend accepted cut: %w", barrierErr)
	}
	result.durability = "durable"
	if barrierErr != nil {
		result.durability = "lost"
	}
	m.mu.RLock()
	states := make([]*delegationState, 0, len(m.byID))
	for _, s := range m.byID {
		s.users.Add(1)
		states = append(states, s)
	}
	m.mu.RUnlock()
	defer func() {
		for _, s := range states {
			m.releaseState(s)
		}
	}()
	groups := make([]*delegationReleaseGroup, 0, len(states))
	for _, s := range states {
		groups = append(groups, &delegationReleaseGroup{state: s, release: true})
	}
	m.epoch.RLock()
	serial := m.epochSerial
	m.epoch.RUnlock()
	batch, err := m.prepareReleaseBatch(ctx, p.buffer, serial, p.incarnation, groups)
	if err != nil {
		return result, err
	}
	defer batch.finish()
	if err = batch.applyAndRelease(ctx); err != nil {
		var finalized delegationReleaseFinalizedError
		if errors.As(err, &finalized) {
			result.release = "abandoned"
		}
		return result, err
	}
	result.release = "released"
	return result, p.buffer.StopContext(ctx)
}
