// Package workspaceguest owns workspace membership and cold-suspend admission.
// It is not a cache engine, session renewer, or authority client.
package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

const MaxRetired = 128

var ErrState = errors.New("workspace guest: transition refused")

// Mount is the Stage 1c boundary. CloseAdmission is synchronous, nonblocking,
// and generation-monotone; it covers workers and physical reply publication.
// Suspend leaves only drain/control running and returns only after full kernel
// withdrawal, operation/reply settlement, renewal quiescence and delegation
// release. Failed invalidation returns an error, never ColdComplete. A lost
// accepted tail is recorded separately from successful cold withdrawal.
// Recover prepares a live, authorized cold subscription without opening it.
// OpenAdmission atomically publishes that preparation for the same generation.
// No method may replay uncertain mutations into a replacement mount.
type Mount interface {
	CloseAdmission(generation uint64)
	Suspend(context.Context, *pb.Suspension) (ColdResult, error)
	Recover(context.Context, *pb.ResumeToken) (Recovery, error)
	OpenAdmission(generation uint64) error
}

// Loss carries a cumulative snapshot for this mount incarnation. Delayed
// snapshots may repeat an earlier prefix but must never contradict it.
type ColdResult struct {
	ColdComplete bool
	Loss         []*pb.Loss
}
type Recovery struct {
	State, Reason                                                                                string
	SessionValidated, AuthorizationValidated, InitialRenewalInstalled, ColdSubscriptionInstalled bool
	Loss                                                                                         []*pb.Loss
}

func (r Recovery) ready() bool {
	return r.State == "ready" && r.SessionValidated && r.AuthorizationValidated && r.InitialRenewalInstalled && r.ColdSubscriptionInstalled
}

// Witness retains exact process, kernel, authorization and route identities.
// Stage 1a keeps this model in memory; durable inventory integration is pending.
type Witness struct {
	Process, Kernel, Session, Enrollment string
	RoutesRevision                       [32]byte
}
type CleanupProof struct {
	Witness                     Witness
	ProcessExited, KernelAbsent bool
}
type entry struct {
	status   *pb.MountStatus
	driver   Mount
	witness  Witness
	cleaned  bool
	draining bool
	inflight int
	cold     bool
	terminal bool
}
type Supervisor struct {
	mu                sync.Mutex
	boot, host, guest []byte
	generation        uint64
	phase             string
	suspension        *pb.Suspension
	mounts            map[string]*entry
	retired           []*pb.MountStatus
}

// Only a proven fresh boot can start running. A restarted service cannot infer
// safety from a missing record while the old VM or mount processes may survive.
func New(boot, host, guest []byte, freshBoot bool) (*Supervisor, error) {
	if !control.ID(boot) || !control.ID(host) || !control.ID(guest) {
		return nil, control.ErrGrammar
	}
	phase := "discard-only"
	if freshBoot {
		phase = "running"
	}
	return &Supervisor{boot: append([]byte(nil), boot...), host: append([]byte(nil), host...), guest: append([]byte(nil), guest...), phase: phase, mounts: map[string]*entry{}}, nil
}
func clone[T proto.Message](v T) T { return proto.Clone(v).(T) }
func (s *Supervisor) rosterLocked() []*pb.MountID {
	var ids []*pb.MountID
	for _, e := range s.mounts {
		ids = append(ids, clone(e.status.Mount))
	}
	sort.Slice(ids, func(i, j int) bool { return control.MountKey(ids[i]) < control.MountKey(ids[j]) })
	return ids
}
func (s *Supervisor) matchesLocked(x *pb.Suspension) bool {
	return x != nil && string(x.BootId) == string(s.boot) && string(x.HostServiceId) == string(s.host) && string(x.GuestServiceId) == string(s.guest)
}

// Registration closes the daemon before membership becomes visible. A racing
// start/restart is refused and remains closed; it cannot join a fixed roster.
func (s *Supervisor) Register(id *pb.MountID, w Witness, m Mount) error {
	if control.Mount(id) != nil || m == nil {
		return control.ErrGrammar
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m.CloseAdmission(s.generation)
	if s.phase != "running" || len(s.mounts) >= control.MaxMounts {
		return ErrState
	}
	for _, e := range s.mounts {
		if string(e.status.Mount.AuthorityId) == string(id.AuthorityId) && e.status.Mount.VolumeId == id.VolumeId {
			return ErrState
		}
	}
	s.mounts[control.MountKey(id)] = &entry{driver: m, witness: w, status: &pb.MountStatus{Mount: clone(id), State: "closed", Cleanup: "retained"}}
	return nil
}
func (s *Supervisor) Activate(id *pb.MountID, generation uint64, r Recovery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e == nil || s.phase != "running" || generation != s.generation || e.inflight != 0 || e.terminal || e.status.State != "closed" || !r.ready() {
		return ErrState
	}
	if err := e.driver.OpenAdmission(generation); err != nil {
		return fmt.Errorf("workspace initial admission: %w", err)
	}
	e.status.State = "ready"
	return nil
}
func (s *Supervisor) BeginSuspend(x *pb.Suspension) error {
	if err := control.Suspension(x); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == "discard-only" || s.generation == math.MaxUint64 || !s.matchesLocked(x) || x.Generation != s.generation+1 {
		return ErrState
	}
	roster := s.rosterLocked()
	if len(roster) != len(x.Roster) {
		return ErrState
	}
	for i := range roster {
		if !proto.Equal(roster[i], x.Roster[i]) {
			return ErrState
		}
	}
	s.generation = x.Generation
	s.phase = "suspending"
	s.suspension = clone(x)
	for _, e := range s.mounts {
		e.driver.CloseAdmission(s.generation)
		if !e.terminal {
			e.status.State = "closed"
		}
		e.cold = false
		e.draining = false
	}
	return nil
}
func mergeLoss(e *entry, loss []*pb.Loss) error {
	if len(loss) > 128 {
		return ErrState
	}
	var last uint64
	for _, l := range loss {
		if l == nil || l.Sequence <= last || len(l.Reason) == 0 || len(l.Reason) > 4096 {
			return control.ErrGrammar
		}
		last = l.Sequence
	}
	shared := min(len(e.status.Loss), len(loss))
	for i := 0; i < shared; i++ {
		if !proto.Equal(e.status.Loss[i], loss[i]) {
			return ErrState
		}
	}
	for i := len(e.status.Loss); i < len(loss); i++ {
		e.status.Loss = append(e.status.Loss, clone(loss[i]))
	}
	return nil
}

// Drain can run concurrently per mount. A late result never certifies a newer
// generation, even if the daemon ignored cancellation while withdrawing.
func (s *Supervisor) Drain(ctx context.Context, x *pb.Suspension, id *pb.MountID) error {
	s.mu.Lock()
	e := s.mounts[control.MountKey(id)]
	if e == nil || s.phase != "suspending" || !proto.Equal(s.suspension, x) || e.draining || e.cold {
		s.mu.Unlock()
		return ErrState
	}
	e.draining = true
	e.inflight++
	m := e.driver
	s.mu.Unlock()
	result, err := m.Suspend(ctx, clone(x))
	s.mu.Lock()
	defer s.mu.Unlock()
	e.inflight--
	// Loss is independent of cold proof and belongs to this exact mount even
	// when a newer generation overtook the request or withdrawal failed.
	if lossErr := mergeLoss(e, result.Loss); lossErr != nil {
		return lossErr
	}
	if s.phase != "suspending" || !proto.Equal(s.suspension, x) {
		return ErrState
	}
	e.draining = false
	if err != nil {
		return fmt.Errorf("workspace suspend %s: %w", id.VolumeId, err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("workspace suspend %s: %w", id.VolumeId, ctx.Err())
	}
	if !result.ColdComplete {
		return ErrState
	}
	e.cold = true
	if !e.terminal {
		e.status.State = "suspended-cold"
	}
	return nil
}
func (s *Supervisor) SuspendAck(x *pb.Suspension) (*pb.SuspendAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "suspending" || !proto.Equal(s.suspension, x) {
		return nil, ErrState
	}
	a := &pb.SuspendAck{Suspension: clone(x)}
	for _, id := range x.Roster {
		e := s.mounts[control.MountKey(id)]
		if !e.cold || e.inflight != 0 {
			return nil, ErrState
		}
		a.Mounts = append(a.Mounts, &pb.MountCold{Mount: clone(id), ColdComplete: true, Loss: cloneLoss(e.status.Loss)})
	}
	s.phase = "suspended-cold"
	return a, nil
}
func cloneLoss(loss []*pb.Loss) []*pb.Loss {
	out := make([]*pb.Loss, 0, len(loss))
	for _, l := range loss {
		out = append(out, clone(l))
	}
	return out
}

// Resume consumes the one authorization for this generation before any I/O.
// A second suspend wins over delayed Recover results and closes every daemon.
func (s *Supervisor) Resume(ctx context.Context, t *pb.ResumeToken) (*pb.ResumeAck, error) {
	if err := control.Token(t); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.phase != "suspended-cold" || !proto.Equal(s.suspension, t.Suspension) {
		s.mu.Unlock()
		return nil, ErrState
	}
	s.phase = "recovering"
	for _, e := range s.mounts {
		if !e.terminal {
			e.status.State = "recovering"
		}
	}
	s.mu.Unlock()
	for _, id := range t.Suspension.Roster {
		s.mu.Lock()
		if s.phase != "recovering" || !proto.Equal(s.suspension, t.Suspension) {
			s.mu.Unlock()
			return nil, ErrState
		}
		e := s.mounts[control.MountKey(id)]
		if e.terminal {
			s.mu.Unlock()
			continue
		}
		m := e.driver
		e.inflight++
		s.mu.Unlock()
		r, err := m.Recover(ctx, clone(t))
		s.mu.Lock()
		e.inflight--
		lossErr := mergeLoss(e, r.Loss)
		if s.phase != "recovering" || !proto.Equal(s.suspension, t.Suspension) {
			s.mu.Unlock()
			return nil, ErrState
		}
		e.status.State = "closed"
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = lossErr
		}
		if err != nil {
			e.status.Reason = err.Error()
		} else if r.ready() {
			if err = m.OpenAdmission(s.generation); err != nil {
				e.status.Reason = err.Error()
			} else {
				e.status.State = "ready"
				e.status.Reason = ""
			}
		} else if r.State == "terminal" || r.State == "authorization-required" {
			e.status.State = r.State
			e.terminal = true
			e.status.Reason = r.Reason
		} else {
			e.status.Reason = "fresh authority recovery not proven"
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "recovering" || !proto.Equal(s.suspension, t.Suspension) {
		return nil, ErrState
	}
	s.phase = "running"
	a := &pb.ResumeAck{Token: clone(t)}
	for _, id := range t.Suspension.Roster {
		a.Mounts = append(a.Mounts, clone(s.mounts[control.MountKey(id)].status))
	}
	return a, nil
}
func (s *Supervisor) Discard() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase = "discard-only"
	s.suspension = nil
	for _, e := range s.mounts {
		e.driver.CloseAdmission(s.generation)
		if !e.terminal {
			e.status.State = "closed"
		}
	}
}
func (s *Supervisor) Status() *pb.StatusReply {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &pb.StatusReply{BootId: append([]byte(nil), s.boot...), HostServiceId: append([]byte(nil), s.host...), GuestServiceId: append([]byte(nil), s.guest...), Generation: s.generation, State: s.phase}
	for _, id := range s.rosterLocked() {
		out.Mounts = append(out.Mounts, clone(s.mounts[control.MountKey(id)].status))
	}
	return out
}
func (s *Supervisor) Terminal(id *pb.MountID, reason string, loss []*pb.Loss) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e == nil || s.phase != "running" || reason == "" || len(reason) > 4096 {
		return ErrState
	}
	e.driver.CloseAdmission(s.generation)
	e.status.State = "terminal"
	e.terminal = true
	e.status.Reason = reason
	return mergeLoss(e, loss)
}
func (s *Supervisor) Cleanup(id *pb.MountID, p CleanupProof) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e == nil || (e.status.State != "terminal" && e.status.State != "authorization-required") || p.Witness != e.witness {
		return ErrState
	}
	if p.ProcessExited {
		e.status.Cleanup = "process-exited"
	}
	if p.KernelAbsent {
		e.status.Cleanup = "kernel-absent"
	}
	if !p.ProcessExited || !p.KernelAbsent {
		return ErrState
	}
	e.status.Cleanup = "complete"
	e.cleaned = true
	return nil
}

// Replacement retains the old loss outcome, and admits no new mount until exact
// cleanup and fresh product authorization/initial renewal have been proven.
func (s *Supervisor) Replace(old, id *pb.MountID, w Witness, m Mount, r Recovery) error {
	if control.Mount(id) != nil || m == nil {
		return control.ErrGrammar
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m.CloseAdmission(s.generation)
	e := s.mounts[control.MountKey(old)]
	if s.phase != "running" || e == nil || !e.cleaned || e.inflight != 0 || len(s.retired) >= MaxRetired || !r.ready() || string(old.AuthorityId) != string(id.AuthorityId) || old.VolumeId != id.VolumeId || string(old.Incarnation) == string(id.Incarnation) {
		return ErrState
	}
	if err := m.OpenAdmission(s.generation); err != nil {
		return fmt.Errorf("workspace replacement admission: %w", err)
	}
	s.retired = append(s.retired, clone(e.status))
	delete(s.mounts, control.MountKey(old))
	s.mounts[control.MountKey(id)] = &entry{driver: m, witness: w, status: &pb.MountStatus{Mount: clone(id), State: "ready", Cleanup: "retained"}}
	return nil
}
func (s *Supervisor) Retired() []*pb.MountStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*pb.MountStatus, 0, len(s.retired))
	for _, v := range s.retired {
		out = append(out, clone(v))
	}
	return out
}
