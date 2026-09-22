//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

const epochRecoveryRetryDelay = 100 * time.Millisecond

// discardAll abandons capabilities owned by the ended session. Detach is the
// only release edge for that session; sending any of these opaque tokens after
// the replacement is published would apply old authority state to a new epoch.
// Wake any producer waiting for queue admission because the whole backlog has
// ceased to be cleanup debt.
func (q *reclaimQueue) discardAll() {
	q.mu.Lock()
	for index := q.head; index < len(q.tokens); index++ {
		q.tokens[index] = queuedReclaim{}
	}
	q.tokens = q.tokens[:0]
	q.head = 0
	if q.room != nil {
		close(q.room)
		q.room = nil
	}
	q.mu.Unlock()
	for {
		select {
		case <-q.wake:
		default:
			return
		}
	}
}

func (m *Mount) recoverEpoch(ctx context.Context) error {
	// Deny cache admission before changing any epoch-owned state. The runner's
	// poll, renewal, and change workers are drained after handle staling. The
	// writer boundary first lets every callback admitted in the old epoch finish,
	// then prevents any later callback from retaining old capabilities or
	// entering the old delegation buffer while state is retired.
	m.subscription.suspend()
	// Capacity-blocked admissions own callback readers. Wake them before
	// waiting for that boundary; retire their retained bytes only afterward.
	m.delegations.InterruptSubscription()
	m.epochMu.Lock()
	m.raw.mu.Lock()
	for _, record := range m.raw.nodesByID {
		if record != nil {
			record.stale.Store(true)
		}
		if record != nil && record.node != nil {
			record.node.stale.Store(true)
			record.node.epochStale.Store(true)
		}
	}
	for _, handle := range m.raw.handles {
		if handle.file != nil {
			handle.file.stale.Store(true)
		}
		if handle.dir != nil {
			handle.dir.stale.Store(true)
		}
	}
	m.raw.mu.Unlock()
	m.delegations.EpochChanged("authority epoch changed before durability")
	m.reclaim.discardAll()
	m.epochMu.Unlock()
	if err := m.subscription.drainSuspended(ctx); err != nil {
		return err
	}

	// A failed reverse notification cannot be treated as a cold boundary. Keep
	// the mount attached but stale and retry until the kernel confirms every
	// cache withdrawal or the operator unmounts it.
	for {
		if err := m.subscription.invalidateAll(ctx); err == nil {
			break
		}
		if err := waitEpochRecovery(ctx); err != nil {
			return err
		}
	}
	transport, ok := m.rpc.(*epochRPC)
	if !ok {
		return errors.New("fusev3: transport cannot recover an epoch")
	}
	for {
		if err := transport.recover(ctx); err == nil {
			break
		}
		if err := waitEpochRecovery(ctx); err != nil {
			return err
		}
	}
	root := m.rpc.Root()
	if !validItem(root) {
		return errors.New("fusev3: epoch attach omitted root")
	}
	m.epochMu.Lock()
	m.raw.mu.Lock()
	record := m.raw.nodesByID[1]
	if record == nil {
		m.raw.mu.Unlock()
		m.epochMu.Unlock()
		return errors.New("fusev3: epoch recovery lost the kernel root record")
	}
	record.node = m.raw.newNode(root)
	record.key = itemKey(root)
	record.identity, _ = publicationIdentityFromItem(root)
	record.stale.Store(false)
	m.raw.nodesByKey = map[inodeKey]*inodeRecord{record.key: record}
	m.raw.nodesByIdentity = map[publicationIdentity]*inodeRecord{record.identity: record}
	m.raw.mu.Unlock()
	m.epochMu.Unlock()
	// The independent runner can now cold-invalidate once more and subscribe on
	// the replacement transport. No old handle can acquire the new epoch's
	// tokens because every pre-bound node and handle remains permanently stale.
	m.subscription.resume()
	return nil
}

func waitEpochRecovery(ctx context.Context) error {
	timer := time.NewTimer(epochRecoveryRetryDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Mount) watchEpochSession(ctx context.Context, done <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
		}
		cause := m.rpc.SessionEndCause()
		if errors.Is(cause, authorityrpc.ErrAuthorityChanged) {
			if m.requireRemountOnEpochChange {
				// A hosted enrollment cannot authorize another session, and its
				// original attach grant may already have expired. Never publish a
				// replacement behind a supervisor's persisted session identity.
				m.revoke(fmt.Errorf("fusev3: remount with fresh authorization after authority epoch change: %w", cause))
				return
			}
			err := m.recoverEpoch(ctx)
			if err == nil {
				done = m.rpc.SessionEndPending()
				continue
			}
			if ctx.Err() != nil {
				return
			}
			// A non-transient local recovery defect still cannot turn an epoch
			// boundary into revocation. Leave every old handle stale until the
			// operator unmounts; transient attach and invalidation failures are
			// already retried inside recoverEpoch.
			for ctx.Err() == nil {
				if waitEpochRecovery(ctx) != nil {
					return
				}
			}
			return
		}
		if ctx.Err() == nil {
			if cause == nil {
				cause = errors.New("authority session ended")
			}
			m.failAsync(cause)
		}
		return
	}
}
