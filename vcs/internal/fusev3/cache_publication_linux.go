//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"time"
)

func (r *rawFileSystem) closeCacheCoordinate(ctx context.Context, coordinate publicationCoordinate) error {
	r.mu.Lock()
	r.repairingCoordinates[coordinate] = true
	pending := make([]<-chan struct{}, 0)
	candidates := make(map[*replyPublication]struct{})
	for reservation := range r.cacheReservations[coordinate] {
		reservation.revoked = true
		candidates[reservation.publication] = struct{}{}
	}
	if coordinate.kind == publicationItemData {
		for publication := range r.dataPublications[coordinate.item] {
			candidates[publication] = struct{}{}
		}
	}
	for publication := range candidates {
		for index := range publication.data {
			if publication.data[index].coordinate == coordinate && !publication.originalFinalized {
				publication.data[index].revoked = true
			}
		}
		if publication.originalFinalized && !publication.originalWrote {
			pending = append(pending, publication.originalDone)
		}
	}
	r.signalSourceChangedLocked()
	r.mu.Unlock()
	for _, done := range pending {
		select {
		case <-done:
		case <-ctx.Done():
			return fmt.Errorf("fusev3: drain finalized cache reply for cache withdrawal: %w", ctx.Err())
		}
	}
	return nil
}

func publicationInstallsCoordinate(publication *replyPublication, coordinate publicationCoordinate) bool {
	if publication == nil {
		return false
	}
	for _, name := range publication.names {
		if name.coordinate == coordinate {
			return true
		}
	}
	for _, attr := range publication.attrs {
		if attr.coordinate == coordinate {
			return true
		}
	}
	for _, data := range publication.data {
		if data.coordinate == coordinate {
			return true
		}
	}
	return false
}

// drainDataPublications orders one whole-file invalidation after every buffered
// READ this mount had already admitted for the inode. Those reads may be
// carrying pre-mutation bytes into folios the kernel has locked, so a purge that
// ran ahead of their replies would miss exactly the pages it exists to remove.
//
// It is a snapshot, not a quiescence wait. A read admitted after this cut was
// issued after the mutation applied, so its bytes are the new state and the
// purge has no business waiting for it -- which is also what keeps a steady
// stream of readers from starving the purge indefinitely.
func (r *rawFileSystem) drainDataPublications(coordinate publicationCoordinate) error {
	return r.drainDataPublicationsContext(r.mount.ctx, coordinate)
}

func (r *rawFileSystem) drainDataPublicationsContext(ctx context.Context, coordinate publicationCoordinate) error {
	r.mu.Lock()
	pending := make(map[*replyPublication]struct{})
	for publication := range r.dataPublications[coordinate.item] {
		pending[publication] = struct{}{}
	}
	deadline := time.Now().Add(r.mount.repairBudget)
	for {
		for publication := range pending {
			if r.replyPublications[publication.requestUnique] != publication {
				delete(pending, publication)
			}
		}
		if len(pending) == 0 {
			r.mu.Unlock()
			return nil
		}
		changed := r.sourceChangedWaitLocked()
		r.mu.Unlock()
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-changed:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("%w: buffered reads did not drain before a whole-file invalidation", errRepairBudgetExceeded)
		}
		r.mu.Lock()
	}
}

func (r *rawFileSystem) openCacheCoordinate(coordinate publicationCoordinate) {
	r.mu.Lock()
	delete(r.repairingCoordinates, coordinate)
	r.signalSourceChangedLocked()
	r.mu.Unlock()
}

func (p *replyPublication) subscriptionCacheStamp() subscriptionStamp {
	if p == nil {
		return subscriptionStamp{}
	}
	stamp := p.stamp
	stamp.version = p.servedVersion
	return stamp
}

func (r *rawFileSystem) publicationRemaining(p *replyPublication, coordinate publicationCoordinate) time.Duration {
	if p == nil {
		return 0
	}
	return r.mount.subscription.remaining(coordinate, p.stamp, p.servedVersion, time.Now())
}
