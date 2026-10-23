package workspaceguest

import (
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

// ConfigureWitnessPersistence is installed before the paired stream starts.
// Persistence runs without mu: closure must never wait for disk I/O.
func (s *Supervisor) ConfigureWitnessPersistence(persist func(*pb.MountID, Witness) error) {
	s.persistWitness = persist
}

// MergeWitness retains every nonconflicting acquisition, even when another
// field conflicts. A refusal cannot discard evidence of an acquired resource.
func MergeWitness(old, next Witness) (Witness, error) {
	w, err := workspacemount.MergeWitness(old, next)
	if err != nil {
		err = errors.Join(ErrState, err)
	}
	return w, err
}

// BindWitness serializes progressive acquisitions independently of lifecycle
// calls. The in-memory binding takes ownership before persistence, including
// when a newer Close overtakes that commit. Readiness waits for the commit;
// cleanup always compares the resulting binding rather than registration.
func (s *Supervisor) BindWitness(id *pb.MountID, next Witness) (Witness, error) {
	s.mu.Lock()
	e := s.mounts[control.MountKey(id)]
	s.mu.Unlock()
	if e == nil {
		return Witness{}, refused("bind unknown mount")
	}
	e.witnessLane.Lock()
	defer e.witnessLane.Unlock()
	s.mu.Lock()
	if s.mounts[control.MountKey(id)] != e || e.cleaned {
		s.mu.Unlock()
		return Witness{}, refused("bind retired mount")
	}
	w, mergeErr := MergeWitness(e.witness, next)
	if w == e.witness && mergeErr == nil {
		s.mu.Unlock()
		return w, nil
	}
	e.witness, e.binding = w, true
	g, serial := s.generation, e.gateSerial
	persist := s.persistWitness
	s.mu.Unlock()
	var persistErr error
	if persist != nil {
		persistErr = persist(clone(id), w)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e.binding = false
	err := errors.Join(mergeErr, persistErr)
	if err != nil {
		e.terminal = true
		e.gateSerial = e.driver.CloseAdmission(s.generation)
		e.setStatus("terminal", "ownership witness persistence or binding failed", "")
	}
	if s.generation != g || e.gateSerial != serial || s.mounts[control.MountKey(id)] != e {
		err = errors.Join(err, refused("witness commit overtaken"))
	}
	return w, err
}

func (s *Supervisor) BoundWitness(id *pb.MountID) (Witness, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e == nil {
		return Witness{}, refused("witness unknown mount")
	}
	return e.witness, nil
}

// RecoveryRequired closes a serving interval without inventing an authority
// expiry. A host-owned cold transaction supplies fresh Resume authority.
func (s *Supervisor) RecoveryRequired(id *pb.MountID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e == nil {
		return refused("recovery-required unknown mount")
	}
	e.gateSerial = e.driver.CloseAdmission(s.generation)
	if !e.terminal {
		e.setStatus("closed", reason, "")
	}
	return nil
}
