package xfsstore

import (
	"io/fs"
	"sync"
)

type syncWaiter struct {
	full bool
	fd   int
	lead chan []*syncWaiter
	done chan error
}

// inodeFsyncState is shared by every open handle for one stable incarnation.
// Arrivals during an active sync form the next batch. That conservative cutoff
// makes completion membership exact: only requests present before the syscall
// starts can be released by it.
type inodeFsyncState struct {
	identity [16]byte

	syncGroup
	refs int

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

// syncGroup serializes a persistence description's error cursor. The syscall
// functions must fence their store before returning an error. A failed batch
// releases all pending waiters with that same failure without another syscall.
// Arrivals during a successful syscall share the next batch, never this one.
type syncGroup struct {
	mu          sync.Mutex
	inFlight    bool
	pending     []*syncWaiter
	syncFailure error
}

func (s *syncGroup) barrier(fd int, dataOnly bool, fsync, fdatasync func(int) error) (int, error) {
	waiter := &syncWaiter{full: !dataOnly, fd: fd,
		lead: make(chan []*syncWaiter, 1), done: make(chan error, 1)}
	s.mu.Lock()
	if s.syncFailure != nil {
		err := s.syncFailure
		s.mu.Unlock()
		return 0, err
	}
	if !s.inFlight {
		s.inFlight = true
		s.mu.Unlock()
		return s.runBatch(waiter, []*syncWaiter{waiter}, fsync, fdatasync)
	}
	s.pending = append(s.pending, waiter)
	s.mu.Unlock()
	select {
	case batch := <-waiter.lead:
		return s.runBatch(waiter, batch, fsync, fdatasync)
	case err := <-waiter.done:
		return 0, err
	}
}

func (s *syncGroup) runBatch(leader *syncWaiter, batch []*syncWaiter, fsync, fdatasync func(int) error) (int, error) {
	full := false
	for _, waiter := range batch {
		full = full || waiter.full
	}
	var err error
	if full {
		err = fsync(leader.fd)
	} else {
		err = fdatasync(leader.fd)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.syncFailure = err
	}
	for _, waiter := range batch {
		if waiter != leader {
			waiter.done <- err
		}
	}
	if err != nil {
		for _, waiter := range s.pending {
			waiter.done <- err
		}
		s.pending = nil
		s.inFlight = false
	} else if len(s.pending) == 0 {
		s.inFlight = false
	} else {
		next := s.pending
		s.pending = nil
		next[0].lead <- next
	}
	return len(batch), err
}
