//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

func (r *rawFileSystem) closeCacheCoordinate(ctx context.Context, coordinate publicationCoordinate) (*cacheRepairLease, error) {
	return r.closeCacheCoordinates(ctx, []publicationCoordinate{coordinate})
}

func (r *rawFileSystem) closeCacheCoordinates(ctx context.Context, coordinates []publicationCoordinate) (*cacheRepairLease, error) {
	set := make(map[publicationCoordinate]struct{}, len(coordinates))
	for _, coordinate := range coordinates {
		set[coordinate] = struct{}{}
	}
	lease := &cacheRepairLease{raw: r, coordinates: make([]publicationCoordinate, 0, len(set))}
	r.mu.Lock()
	pending := make([]<-chan struct{}, 0)
	candidates := make(map[*replyPublication]struct{})
	for coordinate := range set {
		r.repairingCoordinates[coordinate] = true
		if r.repairOwners[coordinate] == nil {
			r.repairOwners[coordinate] = make(map[*cacheRepairLease]struct{})
		}
		r.repairOwners[coordinate][lease] = struct{}{}
		lease.coordinates = append(lease.coordinates, coordinate)
		for reservation := range r.cacheReservations[coordinate] {
			reservation.revoked = true
			candidates[reservation.publication] = struct{}{}
		}
		if coordinate.kind == publicationItemData {
			for publication := range r.dataPublications[coordinate.item] {
				candidates[publication] = struct{}{}
			}
		}
	}
	for _, publication := range r.replyPublications {
		for _, cached := range publication.cachedCoordinates[:publication.cachedCount] {
			if _, ok := set[cached]; ok {
				candidates[publication] = struct{}{}
			}
		}
	}
	for publication := range candidates {
		for index := range publication.data {
			if _, ok := set[publication.data[index].coordinate]; ok && !publication.originalFinalized {
				publication.data[index].revoked = true
			}
		}
		if publication.originalFinalized && !publication.originalWrote {
			pending = append(pending, publication.originalDoneLocked())
		}
	}
	r.signalSourceChangedLocked()
	r.mu.Unlock()
	for _, done := range pending {
		select {
		case <-done:
		case <-ctx.Done():
			return lease, fmt.Errorf("fusev3: drain finalized cache reply for cache withdrawal: %w", ctx.Err())
		}
	}
	return lease, nil
}

func publicationInstallsCoordinate(publication *replyPublication, coordinate publicationCoordinate) bool {
	if publication == nil {
		return false
	}
	for _, cached := range publication.cachedCoordinates[:publication.cachedCount] {
		if cached == coordinate {
			return true
		}
	}
	for _, candidate := range publication.completeDirectories[:publication.completeDirectoryCount] {
		if coordinate == (publicationCoordinate{kind: publicationItemEnumeration, item: candidate.identity}) {
			return true
		}
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
	return r.drainDataPublicationsSet(ctx, []publicationCoordinate{coordinate})
}
func (r *rawFileSystem) drainDataPublicationsSet(ctx context.Context, coordinates []publicationCoordinate) error {
	r.mu.Lock()
	pending := make(map[*replyPublication]struct{})
	for _, coordinate := range coordinates {
		for publication := range r.dataPublications[coordinate.item] {
			pending[publication] = struct{}{}
		}
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
			return errors.New("fusev3: buffered reads did not drain before a whole-file invalidation deadline")
		}
		r.mu.Lock()
	}
}

// Exact owner identity survives a cold clear. A delayed local opener can
// release only its own cut, never a successor subscription's withdrawal.
type cacheRepairLease struct {
	raw         *rawFileSystem
	coordinates []publicationCoordinate
	once        sync.Once
}

func (lease *cacheRepairLease) Open() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		r := lease.raw
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, coordinate := range lease.coordinates {
			owners := r.repairOwners[coordinate]
			if _, present := owners[lease]; !present {
				continue
			}
			delete(owners, lease)
			if len(owners) == 0 {
				delete(r.repairOwners, coordinate)
				delete(r.repairingCoordinates, coordinate)
			}
		}
		r.signalSourceChangedLocked()
	})
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

// waitFinalizedCacheCoordinateLocked closes the interval between the kernel
// waking a caller and ReplyWritten settling the preceding daemon payload. Only
// finalized, unrevoked candidates can make this miss a hit; a callback still
// constructing a reply might itself depend on the new request. Returns with
// r.mu held, including on cancellation.
func (r *rawFileSystem) waitFinalizedCacheCoordinateLocked(ctx context.Context, current *replyPublication, coordinate publicationCoordinate) bool {
	for {
		var done <-chan struct{}
		for reservation := range r.cacheReservations[coordinate] {
			prior := reservation.publication
			if !reservation.revoked && prior != current && prior.originalFinalized && !prior.originalWrote {
				superseded := false
				for _, name := range prior.names {
					if name.reservation == reservation && name.negativeState != nil && name.negativeState.superseded {
						superseded = true
						break
					}
				}
				if superseded {
					continue
				}
				done = prior.originalDoneLocked()
				break
			}
		}
		if done == nil {
			return true
		}
		r.mu.Unlock()
		var canceled bool
		select {
		case <-done:
		case <-ctx.Done():
			canceled = true
		}
		r.mu.Lock()
		if canceled {
			return false
		}
	}
}
