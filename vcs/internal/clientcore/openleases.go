package clientcore

import (
	"context"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// InodeSet tracks inode identities that need periodic authority lease renewal.
type InodeSet struct {
	mu sync.Mutex
	m  map[uint64]struct{}
}

// NewInodeSet returns an empty inode set.
func NewInodeSet() *InodeSet { return &InodeSet{m: map[uint64]struct{}{}} }

// Add records ino when it is non-zero.
func (s *InodeSet) Add(ino uint64) {
	if ino == 0 {
		return
	}
	s.mu.Lock()
	s.m[ino] = struct{}{}
	s.mu.Unlock()
}

// Remove drops ino.
func (s *InodeSet) Remove(ino uint64) {
	s.mu.Lock()
	delete(s.m, ino)
	s.mu.Unlock()
}

// Contains reports whether ino is currently recorded.
func (s *InodeSet) Contains(ino uint64) bool {
	if ino == 0 {
		return false
	}
	s.mu.Lock()
	_, ok := s.m[ino]
	s.mu.Unlock()
	return ok
}

// Snapshot returns a copy of the current set.
func (s *InodeSet) Snapshot() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint64, 0, len(s.m))
	for ino := range s.m {
		out = append(out, ino)
	}
	return out
}

// OpenLeaseRenewer is the authority protocol surface for open-after-unlink and open-inode leases.
type OpenLeaseRenewer interface {
	RenewOrphanLeases([]uint64) (int32, error)
	RenewOpenInodes([]uint64) (int32, error)
}

// RenewOpenLeases renews parked-orphan and still-named open-inode leases until ctx is cancelled.
func RenewOpenLeases(ctx context.Context, auth OpenLeaseRenewer, orphanInos, openInos *InodeSet, every time.Duration, debugf func(string, ...any)) {
	if every <= 0 {
		every = 20 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if inos := orphanInos.Snapshot(); len(inos) > 0 {
				if st, err := auth.RenewOrphanLeases(inos); err != nil || st != fsproto.OK {
					if debugf != nil {
						debugf("RenewOrphanLeases(%d inos): st=%d err=%v", len(inos), st, err)
					}
				}
			}
			if inos := openInos.Snapshot(); len(inos) > 0 {
				if st, err := auth.RenewOpenInodes(inos); err != nil || st != fsproto.OK {
					if debugf != nil {
						debugf("RenewOpenInodes(%d inos): st=%d err=%v", len(inos), st, err)
					}
				}
			}
		}
	}
}
