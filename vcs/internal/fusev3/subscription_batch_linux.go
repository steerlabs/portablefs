//go:build linux

package fusev3

import (
	"context"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type cacheWithdrawal interface{ Open() }

type subscriptionWithdrawal struct {
	coordinate publicationCoordinate
	byteRange  *authoritypb.ByteRange
}

func (i mountSubscriptionInvalidator) CloseCacheCoordinates(ctx context.Context, coordinates []publicationCoordinate) (cacheWithdrawal, error) {
	raw, err := i.raw()
	if err != nil {
		return nil, err
	}
	return raw.closeCacheCoordinates(ctx, coordinates)
}
func (i mountSubscriptionInvalidator) InvalidateCacheCoordinates(ctx context.Context, withdrawals []subscriptionWithdrawal) error {
	raw, err := i.raw()
	if err != nil {
		return err
	}
	return raw.invalidateCacheCoordinatesContext(ctx, withdrawals)
}

func (s *subscriptionRegistry) applyChangeBatch(ctx context.Context, incarnation uint64, batch *authoritypb.ChangeBatch) error {
	withdrawals := make([]subscriptionWithdrawal, 0, len(batch.GetEntries()))
	indexes := make(map[publicationCoordinate]int)
	bases := make(map[publicationIdentity]uint64)
	releases := make(map[publicationIdentity]uint64)
	for _, entry := range batch.GetEntries() {
		coordinates, identity, _, release, err := validateChangeEntry(entry)
		if err != nil {
			return fmt.Errorf("%w: %v", errSubscriptionInvalid, err)
		}
		if release {
			releases[identity] = max(releases[identity], entry.GetPosition())
		}
		if entry.GetKind() == authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED || entry.GetKind() == authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED {
			bases[identity] = max(bases[identity], entry.GetVolumeVersion())
		}
		for _, coordinate := range coordinates {
			if index, ok := indexes[coordinate]; ok {
				withdrawals[index].byteRange = nil
				continue
			}
			indexes[coordinate] = len(withdrawals)
			withdrawals = append(withdrawals, subscriptionWithdrawal{coordinate: coordinate, byteRange: entry.GetByteRange()})
		}
	}
	if invalidator, ok := s.control.(interface{ InvalidateBaseAttr([]byte, uint64) }); ok {
		for identity, version := range bases {
			invalidator.InvalidateBaseAttr(identity[:], version)
		}
	}
	if len(withdrawals) != 0 {
		if err := s.withdrawCoordinates(ctx, withdrawals); err != nil {
			for _, withdrawal := range withdrawals {
				s.markChangeStale(withdrawal.coordinate)
			}
			return err
		}
	}
	// A grant registered by the poller after this release position remains an
	// exclusion even if its own batch is still waiting for physical withdrawal.
	s.mu.Lock()
	if s.active && s.incarnation == incarnation {
		for identity, position := range releases {
			if grant, ok := s.delegated[identity]; ok && grant <= position {
				delete(s.delegated, identity)
			}
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *subscriptionRegistry) withdrawCoordinates(ctx context.Context, withdrawals []subscriptionWithdrawal) error {
	deadline := s.config.clock.Now().Add(s.config.repairLead)
	s.mu.RLock()
	if s.cacheUntil.Before(deadline) {
		deadline = s.cacheUntil
	}
	s.mu.RUnlock()
	remaining := deadline.Sub(s.config.clock.Now())
	if remaining <= 0 {
		return errSubscriptionExpired
	}
	repairCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	coordinates := make([]publicationCoordinate, len(withdrawals))
	for i, w := range withdrawals {
		coordinates[i] = w.coordinate
	}
	lease, err := s.config.invalidator.CloseCacheCoordinates(repairCtx, coordinates)
	if err != nil {
		return fmt.Errorf("fusev3: close cache coordinates: %w", err)
	}
	if err := s.retry(repairCtx, deadline, func() error { return s.config.invalidator.InvalidateCacheCoordinates(repairCtx, withdrawals) }); err != nil {
		return fmt.Errorf("fusev3: invalidate cache coordinates: %w", err)
	}
	lease.Open()
	return nil
}
