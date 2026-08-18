package xfsstore

import (
	"io/fs"
	"math"
	"sync"
)

type fsyncWaiter struct {
	requiredGeneration uint64
	full               bool
	fd                 int
	lead               chan []*fsyncWaiter
	done               chan error
}

// inodeFsyncState is shared by every open handle for one stable incarnation.
// Arrivals during an active sync form the next batch. That conservative cutoff
// makes completion membership exact: only requests present before the syscall
// starts can be released by it.
type inodeFsyncState struct {
	identity [16]byte

	mu                sync.Mutex
	appliedGeneration uint64
	inFlight          bool
	pending           []*fsyncWaiter
	refs              int

	// PortableFS rejects every xattr mutation, and the authority exclusively
	// owns the cell, so no supported operation can add security.capability after
	// this lazy first-pin inspection. Removal changes the cached bit to false.
	// The cache dies with this state when the last handle or pinned target drops
	// its reference; a later open-state lifetime probes again.
	privilegeMu               sync.Mutex
	securityCapabilityKnown   bool
	securityCapabilityPresent bool
}

func (s *inodeFsyncState) inspectWritePrivileges(fd int, inspect func(int) (bool, error)) error {
	s.privilegeMu.Lock()
	defer s.privilegeMu.Unlock()
	if s.securityCapabilityKnown {
		return nil
	}
	present, err := inspect(fd)
	if err != nil {
		return err
	}
	s.securityCapabilityPresent = present
	s.securityCapabilityKnown = true
	return nil
}

func (s *inodeFsyncState) removeWritePrivileges(fd int, beforeMode uint32, killSUIDGID bool, remove func(int, uint32, bool, *bool) error) error {
	s.privilegeMu.Lock()
	defer s.privilegeMu.Unlock()
	if !s.securityCapabilityKnown {
		return fs.ErrInvalid
	}
	return remove(fd, beforeMode, killSUIDGID, &s.securityCapabilityPresent)
}

func (s *inodeFsyncState) applied() {
	s.mu.Lock()
	if s.appliedGeneration != math.MaxUint64 {
		s.appliedGeneration++
	}
	s.mu.Unlock()
}

func (s *inodeFsyncState) barrier(fd int, dataOnly bool, fsync, fdatasync func(int) error) (int, error) {
	waiter := &fsyncWaiter{
		full: !dataOnly, fd: fd,
		lead: make(chan []*fsyncWaiter, 1), done: make(chan error, 1),
	}
	s.mu.Lock()
	waiter.requiredGeneration = s.appliedGeneration
	if !s.inFlight {
		s.inFlight = true
		s.mu.Unlock()
		return s.runFsyncBatch(waiter, []*fsyncWaiter{waiter}, fsync, fdatasync)
	}
	s.pending = append(s.pending, waiter)
	s.mu.Unlock()

	select {
	case batch := <-waiter.lead:
		return s.runFsyncBatch(waiter, batch, fsync, fdatasync)
	case err := <-waiter.done:
		return 0, err
	}
}

func (s *inodeFsyncState) runFsyncBatch(leader *fsyncWaiter, batch []*fsyncWaiter, fsync, fdatasync func(int) error) (int, error) {
	coveredGeneration := uint64(0)
	full := false
	for _, waiter := range batch {
		if waiter.requiredGeneration > coveredGeneration {
			coveredGeneration = waiter.requiredGeneration
		}
		full = full || waiter.full
	}
	var err error
	if full {
		err = fsync(leader.fd)
	} else {
		err = fdatasync(leader.fd)
	}

	s.mu.Lock()
	for _, waiter := range batch {
		if waiter.requiredGeneration > coveredGeneration || waiter.full && !full {
			panic("xfsstore: fsync batch released an uncovered waiter")
		}
		if waiter != leader {
			waiter.done <- err
		}
	}
	if len(s.pending) == 0 {
		s.inFlight = false
	} else {
		next := s.pending
		s.pending = nil
		next[0].lead <- next
	}
	s.mu.Unlock()
	return len(batch), err
}
