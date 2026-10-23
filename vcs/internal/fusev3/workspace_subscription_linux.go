//go:build linux

package fusev3

import (
	"context"
	"errors"
)

// The runner and lifecycle share this ownership lock, never a lock needed by
// reply settlement. Taking ownership precedes deactivation. CONTROL remains
// available until the captured cut finishes; renewal and Subscribe do not.
func (s *subscriptionRegistry) takeWorkspaceOwnership(ctx context.Context) error {
	s.mu.Lock()
	s.workspaceOwned = true
	if s.subscribeCancel != nil {
		s.subscribeCancel()
	}
	if s.renewCancel != nil {
		s.renewCancel()
	}
	subscribe, renewal := s.subscribeDone, s.renewDone
	epilogue := s.ordinaryWithdrawalDone
	close(s.pauseChanged)
	s.pauseChanged = make(chan struct{})
	s.mu.Unlock()
	if err := joinWorkspaceOwner(ctx, subscribe); err != nil {
		return err
	}
	if err := joinWorkspaceOwner(ctx, renewal); err != nil {
		return err
	}
	return joinWorkspaceOwner(ctx, epilogue)
}

func joinWorkspaceOwner(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *subscriptionRegistry) parkWorkspaceControl(ctx context.Context) error {
	s.mu.Lock()
	if !s.workspaceOwned {
		s.mu.Unlock()
		return errors.New("fusev3: subscription lifecycle is not owned")
	}
	pollCancel, pollDone, q := s.pollCancel, s.pollDone, s.controlQueue
	s.mu.Unlock()
	if pollCancel != nil {
		pollCancel()
	}
	if err := joinWorkspaceOwner(ctx, pollDone); err != nil {
		return err
	}
	if q != nil {
		for {
			s.mu.RLock()
			reset := s.workspaceReset
			s.mu.RUnlock()
			if reset {
				break
			} // Cache withdrawal/fencing accounts the unprovable tail.
			q.mu.Lock()
			if q.completed >= q.accepted {
				q.mu.Unlock()
				break
			}
			if q.progress == nil {
				q.progress = make(chan struct{})
			}
			changed := q.progress
			q.mu.Unlock()
			s.mu.RLock()
			done := s.serveDone
			failure := s.workspaceFailure
			s.mu.RUnlock()
			if failure != nil {
				return failure
			}
			select {
			case <-changed:
			case <-done:
				s.mu.RLock()
				reset := s.workspaceReset
				failure := s.workspaceFailure
				s.mu.RUnlock()
				if failure != nil {
					return failure
				}
				if !reset {
					return errors.New("fusev3: CONTROL cut did not settle")
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	s.mu.Lock()
	if s.controlCancel != nil {
		s.controlCancel()
	}
	done := s.serveDone
	s.mu.Unlock()
	if err := joinWorkspaceOwner(ctx, done); err != nil {
		return err
	}
	s.mu.RLock()
	failure := s.workspaceFailure
	s.mu.RUnlock()
	if failure != nil {
		return failure
	}
	// pollLoop has stopped producing handlers before this wait begins.
	joined := make(chan struct{})
	go func() {
		if m, ok := s.control.(*delegationManager); ok {
			m.controlWG.Wait()
		}
		close(joined)
	}()
	return joinWorkspaceOwner(ctx, joined)
}

func (s *subscriptionRegistry) releaseWorkspaceOwnership() {
	s.mu.Lock()
	s.workspaceOwned = false
	close(s.pauseChanged)
	s.pauseChanged = make(chan struct{})
	s.mu.Unlock()
}
