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

func (d MutationDependencies) Equal(other MutationDependencies) bool { return d.equal(other) }
