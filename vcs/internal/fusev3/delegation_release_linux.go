//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"sort"
)

type delegationLockMask uint8

const (
	delegationAcquire delegationLockMask = 1 << iota
	delegationTransition
	delegationOperation
)

type delegationReleaseFlight struct{ done chan struct{} }

// A release owns a logical transition while its RPC runs, but holds none of
// the state's physical locks. Joining it must release every requested lock:
// the flight's completion needs transition to publish the canonical result.
func (s *delegationState) lockAfterRelease(ctx context.Context, mask delegationLockMask) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mask&delegationAcquire != 0 {
			s.acquire.Lock()
		}
		s.transition.Lock()
		if mask&delegationOperation != 0 {
			s.operation.Lock()
		}
		flight := s.releaseFlight
		if flight == nil {
			if mask&delegationTransition == 0 {
				s.transition.Unlock()
			}
			return nil
		}
		if mask&delegationOperation != 0 {
			s.operation.Unlock()
		}
		s.transition.Unlock()
		if mask&delegationAcquire != 0 {
			s.acquire.Unlock()
		}
		select {
		case <-flight.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *delegationState) unlockAfterRelease(mask delegationLockMask) {
	if mask&delegationOperation != 0 {
		s.operation.Unlock()
	}
	if mask&delegationTransition != 0 {
		s.transition.Unlock()
	}
	if mask&delegationAcquire != 0 {
		s.acquire.Unlock()
	}
}

type delegationReleaseGroup struct {
	state   *delegationState
	closing map[string]struct{}
	release bool
	ref     *authoritypb.DelegationRef
	retire  *writeback.Retirement
	applied uint64
}

type delegationReleaseBatch struct {
	manager *delegationManager
	groups  []*delegationReleaseGroup
	flight  *delegationReleaseFlight
}

// The caller retains the epoch reader until finish. Epoch replacement cannot
// redirect old handle capabilities, and no flight waits for an epoch writer.
func (m *delegationManager) prepareReleaseBatch(ctx context.Context, groups []*delegationReleaseGroup) (*delegationReleaseBatch, error) {
	sort.Slice(groups, func(i, j int) bool {
		return bytes.Compare(groups[i].state.identity[:], groups[j].state.identity[:]) < 0
	})
	for {
		for _, g := range groups {
			g.state.acquire.Lock()
		}
		for _, g := range groups {
			g.state.transition.Lock()
			g.state.operation.Lock()
		}
		unlock := func() {
			for i := len(groups) - 1; i >= 0; i-- {
				groups[i].state.operation.Unlock()
				groups[i].state.transition.Unlock()
			}
			for i := len(groups) - 1; i >= 0; i-- {
				groups[i].state.acquire.Unlock()
			}
		}
		var previous *delegationReleaseFlight
		for _, g := range groups {
			if g.state.releaseFlight != nil {
				previous = g.state.releaseFlight
				break
			}
		}
		if previous != nil {
			unlock()
			select {
			case <-previous.done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		batch := &delegationReleaseBatch{manager: m, groups: groups, flight: &delegationReleaseFlight{done: make(chan struct{})}}
		var prepareErr error
		for _, g := range groups {
			s := g.state
			s.admission.RLock()
			g.ref = cloneDelegationRef(s.ref)
			if g.closing != nil {
				g.release = len(s.handles) > 0
				for handle := range s.handles {
					if _, closing := g.closing[handle]; !closing {
						g.release = false
						break
					}
				}
			}
			s.admission.RUnlock()
			if g.ref != nil {
				g.retire, prepareErr = m.beginRetire(ctx, s)
				if prepareErr != nil {
					break
				}
			}
		}
		for _, g := range groups {
			g.state.releaseFlight = batch.flight
		}
		unlock()
		if prepareErr != nil {
			batch.finish()
			return nil, prepareErr
		}
		return batch, nil
	}
}

func (b *delegationReleaseBatch) finish() {
	for _, g := range b.groups {
		g.state.transition.Lock()
	}
	for _, g := range b.groups {
		s := g.state
		s.admission.Lock()
		if g.retire != nil && s.retire == g.retire && s.ref != nil {
			g.retire.Cancel()
			s.retire = nil
		}
		s.admission.Unlock()
		s.releaseFlight = nil
	}
	close(b.flight.done)
	for i := len(b.groups) - 1; i >= 0; i-- {
		b.groups[i].state.transition.Unlock()
	}
}

func (b *delegationReleaseBatch) applyAndRelease(ctx context.Context) error {
	m := b.manager
	var releases []*authoritypb.DelegationRelease
	for _, g := range b.groups {
		if g.ref == nil {
			continue
		}
		applied, err := m.buf.FlushIdentity(ctx, g.state.identity, g.retire.Cut())
		if err != nil {
			return err
		}
		g.applied = delegationApplied(g.state, applied)
		if g.release {
			releases = append(releases, &authoritypb.DelegationRelease{Delegation: g.ref, AppliedSequence: g.applied})
		}
	}
	if len(releases) == 0 {
		return nil
	}
	sort.Slice(releases, func(i, j int) bool { return bytes.Compare(releases[i].Delegation.Id, releases[j].Delegation.Id) < 0 })
	response, err := m.rpc.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{Incarnation: m.incarnation(), Delegations: releases}}})

	if err != nil || response == nil || response.GetUncertain() || response.GetFailure() != 0 || response.GetErrno() == 0 && response.GetDelegationRelease() == nil {
		m.SetIncarnation(0)
		if err == nil {
			err = errors.New("fusev3: delegation release has no valid ownership outcome")
		}
		for _, g := range b.groups {
			if g.ref != nil && g.release {
				g.state.transition.Lock()
				if response.GetFailure() != 0 {
					m.loseDelegation(g.state, "delegation release fenced")
				} else {
					g.state.admission.Lock()
					detachErr := g.retire.DetachOverlay()
					g.state.clearGrantLocked()
					g.state.admission.Unlock()
					if detachErr != nil {
						m.loseDelegation(g.state, "uncertain released overlay could not be detached")
					}
				}
				g.state.transition.Unlock()
			}
		}
		return delegationReleaseFinalizedError{err}
	}
	if err := successfulDelegationResponse(response); err != nil {
		return err
	}
	// The Authority committed all releases. Complete every local transition even
	// if one overlay invariant fails; none may reopen its surrendered grant.
	var firstErr error

	for _, g := range b.groups {
		if g.ref == nil || !g.release {
			continue
		}
		s := g.state
		s.transition.Lock()
		s.admission.Lock()
		err := g.retire.DetachOverlay()
		s.clearGrantLocked()
		s.admission.Unlock()
		s.transition.Unlock()
		if err != nil {
			m.loseDelegation(s, "released overlay could not be detached")
			if firstErr == nil {
				firstErr = fmt.Errorf("fusev3: detach released overlay: %w", err)
			}
		}
	}
	if firstErr != nil {
		return delegationReleaseFinalizedError{firstErr}
	}
	return nil
}

type delegationReleaseFinalizedError struct{ error }

// Descriptor cleanup failure cannot erase already-applied writeback records.
// Their bytes remain charged until a durable receipt or a real fencing loss.
type delegationCleanupError struct{ error }

// Unknown cleanup owns an Authority descriptor until terminal session cleanup.
// End the mounted session rather than silently discharging its admission debt.
func (m *delegationManager) unknownCloseOutcome(err error) error {
	m.hookMu.RLock()
	report := m.cleanupFailure
	m.hookMu.RUnlock()
	if report != nil {
		report(fmt.Errorf("fusev3: unresolved frontend-owned descriptor cleanup: %w", err))
	}
	return delegationCleanupError{err}
}
func (m *delegationManager) SetCleanupFailureReporter(report func(error)) {
	m.hookMu.Lock()
	m.cleanupFailure = report
	m.hookMu.Unlock()
}
