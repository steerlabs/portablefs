package volumeserver

import "context"

// StorageSequencer is the handler's atomic binding-publication exclusion.
// It is separate from delegation request turns: flush application must remain
// possible while a peer waits for a recall. Release it before any peer wait.
type StorageSequencer struct{ sequencer *mutationSequencer }

func NewStorageSequencer() *StorageSequencer {
	return &StorageSequencer{sequencer: newMutationSequencer()}
}

func (s *StorageSequencer) Acquire(ctx context.Context, dependencies MutationDependencies) (func(), error) {
	turn, err := s.sequencer.acquire(ctx, dependencies)
	if err != nil {
		return nil, err
	}
	return turn.settle, nil
}

// AcquireRead excludes storage mutations without claiming a binding changed.
// Identity probes may otherwise invalidate each other's declarations forever.
func (s *StorageSequencer) AcquireRead(ctx context.Context, dependencies MutationDependencies) (func(), error) {
	turn, err := s.sequencer.acquire(ctx, dependencies)
	if err != nil {
		return nil, err
	}
	turn.readOnly = true
	return turn.settle, nil
}

func (d MutationDependencies) Equal(other MutationDependencies) bool { return d.equal(other) }

// StorageDeclaration watches bindings while an identity-only probe resolves
// the complete footprint. It holds no turn across delegation break or recall.
type StorageDeclaration struct{ snapshot *dependencySnapshot }

func (s *StorageSequencer) Declare(dependencies MutationDependencies) *StorageDeclaration {
	return &StorageDeclaration{snapshot: s.sequencer.snapshot(dependencies)}
}
func (d *StorageDeclaration) Release() {
	if d != nil {
		d.snapshot.release()
	}
}

// AcquireDeclared consumes the declaration only while the complete footprint
// is held. A binding changed since the probe requires a fresh resolution.
func (s *StorageSequencer) AcquireDeclared(ctx context.Context, dependencies MutationDependencies, d *StorageDeclaration) (func(), bool, error) {
	if d == nil || d.snapshot == nil || d.snapshot.sequencer != s.sequencer {
		return nil, false, ErrVisibilityTargets
	}
	for key := range d.snapshot.versions {
		found := false
		for _, held := range dependencies.keys {
			if key == held {
				found = true
				break
			}
		}
		if !found {
			return nil, false, ErrVisibilityTargets
		}
	}
	release, err := s.AcquireRead(ctx, dependencies)
	if err != nil {
		d.Release()
		return nil, false, err
	}
	return release, s.sequencer.unchanged(d.snapshot), nil
}

// StorageReadTurn can add a discovered child only without waiting. A failed
// expansion requires dropping the partial footprint before a blocking acquire.
type StorageReadTurn struct{ turn *mutationSequencerWaiter }

func (s *StorageSequencer) AcquireReadTurn(ctx context.Context, deps MutationDependencies) (*StorageReadTurn, error) {
	turn, err := s.sequencer.acquire(ctx, deps)
	if err != nil {
		return nil, err
	}
	turn.readOnly = true
	return &StorageReadTurn{turn}, nil
}
func (r *StorageReadTurn) Release() {
	if r != nil {
		r.turn.settle()
	}
}
func (r *StorageReadTurn) TryExpand(deps MutationDependencies) bool {
	if r == nil || !deps.valid() {
		return false
	}
	w := r.turn
	s := w.sequencer
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.settled || !w.granted {
		return false
	}
	contains := func(keys []string, key string) bool {
		for _, k := range keys {
			if k == key {
				return true
			}
		}
		return false
	}
	for _, key := range w.keys {
		if !contains(deps.keys, key) {
			return false
		}
	}
	for _, key := range deps.keys {
		if owner := s.held[key]; owner != nil && owner != w {
			return false
		}
		if contains(w.keys, key) {
			continue
		}
		for e := s.waiters.Front(); e != nil; e = e.Next() {
			older := e.Value.(*mutationSequencerWaiter)
			if older.ordinal >= w.ordinal {
				break
			}
			if contains(older.keys, key) {
				return false
			}
		}
	}
	for _, key := range deps.keys {
		s.held[key] = w
	}
	w.keys = append(w.keys[:0], deps.keys...)
	return true
}
