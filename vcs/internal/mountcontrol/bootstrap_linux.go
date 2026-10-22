//go:build linux

package mountcontrol

import (
	"reflect"
	"sync"

	"golang.org/x/sys/unix"
)

// Bootstrap owns the root's once-only mount attempt and original descriptions.
// It is a control boundary for the future protected-path driver, not a mount
// implementation. Begin must precede the syscall; Finish retains even partial
// effects. Socket loss never calls OwnerLost or ChildLost.
type Bootstrap struct {
	mu                                      sync.Mutex
	action                                  *Phase
	finished, childOwns, stopped, finalized bool
	rights                                  *Rights
	removal                                 [2]ActionStatus
}

func (b *Bootstrap) Begin(p Phase) error {
	if !action(&p) || p.Mode != "" || p.Reason != "" || p.Removal != nil || len(p.Options) == 0 || !boundedPhase(&p) {
		return ErrGrammar
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return ErrRetired
	}
	if b.action != nil {
		return ErrActionConsumed
	}
	b.action = clonePhase(&p)
	return nil
}

// Finish moves the original descriptions into the root even on syscall
// failure or owner loss. An uncertain attempt can only take exact cleanup.
func (b *Bootstrap) Finish(rights *Rights, w Witness) error {
	b.mu.Lock()
	if b.action == nil || b.finished {
		b.mu.Unlock()
		rights.Close()
		return ErrGrammar
	}
	b.finished = true
	b.rights = &Rights{FDs: rights.FDs}
	rights.FDs = nil
	merged, err := mergeWitness(b.action.Witness, w)
	b.action.Witness = merged
	if err != nil || w.Kernel == "" || b.rights.Validate("workspace-install-kernel") != nil {
		b.stopped = true
		b.mu.Unlock()
		return ErrGrammar
	}
	b.mu.Unlock()
	return nil
}

// Handoff copies only the original descriptions. An unknown delivery never
// authorizes Begin again. Confirmation of child ownership ends retransmission.
func (b *Bootstrap) Handoff() (*Rights, error) {
	b.mu.Lock()
	if b.stopped || b.finalized {
		b.mu.Unlock()
		return nil, ErrRetired
	}
	if !b.finished || b.rights == nil {
		b.mu.Unlock()
		return nil, ErrOccupied
	}
	if b.childOwns {
		b.mu.Unlock()
		return nil, ErrActionConsumed
	}
	original := b.rights
	b.mu.Unlock()
	original.mu.Lock()
	defer original.mu.Unlock()
	if len(original.FDs) != 2 {
		return nil, ErrGrammar
	}
	copy := &Rights{}
	for _, fd := range original.FDs {
		x, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			copy.Close()
			return nil, err
		}
		copy.FDs = append(copy.FDs, x)
	}
	return copy, nil
}

// ObserveInstall is based on owner state, never a command acknowledgment. The
// original abort description survives after the redundant root FUSE copy ends.
func (b *Bootstrap) ObserveInstall(s ActionStatus, w Witness) error {
	b.mu.Lock()
	if b.stopped || b.finalized {
		b.mu.Unlock()
		return ErrRetired
	}
	if b.action == nil || s.Action == nil || !reflect.DeepEqual(s.Action, kernelAction(*b.action)) || w.Process != b.action.Witness.Process || w.Source != b.action.Witness.Source || w.Target != b.action.Witness.Target || w.Kernel != b.action.Witness.Kernel {
		b.mu.Unlock()
		return ErrGrammar
	}
	switch s.Progress {
	case "offered":
		b.mu.Unlock()
		return nil
	case "failed":
		if s.Failure == "stopped" {
			// The offering worker ended before accepting the handoff. The root
			// still owns both descriptions, but must stop retransmission.
			b.stopped = true
			b.mu.Unlock()
			return nil
		}
	case "running", "complete":
	default:
		b.mu.Unlock()
		return ErrGrammar
	}
	rights := b.rights
	if rights == nil {
		b.mu.Unlock()
		return ErrGrammar
	}
	rights.mu.Lock()
	if len(rights.FDs) != 2 {
		rights.mu.Unlock()
		b.mu.Unlock()
		return ErrGrammar
	}
	b.childOwns = true
	fd := -1
	if len(rights.FDs) == 2 {
		fd = rights.FDs[0]
		rights.FDs[0] = -1
	}
	rights.mu.Unlock()
	b.mu.Unlock()
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	return nil
}
func (b *Bootstrap) OwnerLost() { b.mu.Lock(); b.stopped = true; b.mu.Unlock() }
func (b *Bootstrap) ChildLost() { b.mu.Lock(); b.stopped = true; b.mu.Unlock() }

// Absence is independent root observation, not a child cleanup acknowledgment.
type Absence struct{ ProcessExited, KernelAbsent, SourceAbsent, AliasesAbsent bool }

func (b *Bootstrap) Finalize(proof Absence) error {
	if !proof.ProcessExited || !proof.KernelAbsent || !proof.SourceAbsent || !proof.AliasesAbsent {
		return ErrGrammar
	}
	b.mu.Lock()
	if b.action != nil && !b.finished {
		b.mu.Unlock()
		return ErrOccupied
	}
	for _, s := range b.removal {
		if s.Progress == "running" {
			b.mu.Unlock()
			return ErrOccupied
		}
	}
	b.stopped = true
	b.finalized = true
	rights := b.rights
	b.rights = nil
	b.mu.Unlock()
	if rights != nil {
		rights.Close()
	}
	return nil
}

// BeginRemoval reserves the root action before any unmount/abort effect. A
// terminal escalation cannot overtake a voluntary syscall still owned here.
func (b *Bootstrap) BeginRemoval(s ActionStatus, w Witness) error {
	if s.Progress != "offered" || s.Action == nil {
		return ErrGrammar
	}
	p := s.Action.WithWitness(w)
	if !action(p) || !mode(p.Mode) || p.Reason == "" || len(p.Options) != 0 || p.Removal != nil || !boundedPhase(p) {
		return ErrGrammar
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.action != nil && !b.finished {
		return ErrOccupied
	}
	if b.finalized || b.action == nil || w.Process != b.action.Witness.Process || w.Source != b.action.Witness.Source || w.Target != b.action.Witness.Target || w.Kernel != b.action.Witness.Kernel || p.ActionID == b.action.ActionID {
		return ErrGrammar
	}
	index := 0
	if p.Mode == "terminal" {
		index = 1
	}
	for _, old := range b.removal {
		if old.Progress == "running" {
			return ErrOccupied
		}
		if old.Progress == "complete" {
			return ErrActionConsumed
		}
		if old.Action != nil && old.Action.ActionID == p.ActionID {
			return ErrActionConsumed
		}
	}
	if b.removal[index].Progress != "" || index == 0 && b.removal[1].Progress != "" {
		return ErrActionConsumed
	}
	s.Action = kernelAction(*p)
	s.Progress = "running"
	s.Failure = ""
	b.removal[index] = s
	return nil
}

// FinishRemoval preserves real EBUSY/abort failures and consumes the mode even
// on error. Finalize separately requires process/source/alias absence.
func (b *Bootstrap) FinishRemoval(removalMode string, proof Removal, cause error) error {
	if !mode(removalMode) {
		return ErrGrammar
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	index := 0
	if removalMode == "terminal" {
		index = 1
	}
	s := &b.removal[index]
	if s.Progress != "running" {
		return ErrActionConsumed
	}
	if cause == nil && (!proof.KernelAbsent || index == 1 && !proof.AbortCompleted) {
		cause = ErrGrammar
	}
	if cause != nil {
		s.Progress = "failed"
		s.Failure = "handler-failed"
		return cause
	}
	s.Progress = "complete"
	s.Action.Removal = &proof
	return nil
}
