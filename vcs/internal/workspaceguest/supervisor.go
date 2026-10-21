// Package workspaceguest owns workspace membership and cold-suspend admission.
// It is not a cache engine, session renewer, or authority client.
package workspaceguest

import (
	"bytes"
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

func refused(why string) error { return fmt.Errorf("%s: %w", why, ErrState) }

// Mount is the Stage 1c boundary. Daemons start closed and cannot acquire any
// permission before registration and Prepare. CloseAdmission is synchronous,
// nonblocking and generation-monotone, covering workers and physical replies.
// It may interrupt any other call. Every installation in Prepare/Recover must
// atomically recheck cancellation and the latest CloseAdmission generation;
// an overtaken call must install nothing, including background renewal.
// The supervisor serializes all other driver calls per mount. Suspend waits
// for full kernel withdrawal, reply settlement, renewal quiescence and exact
// delegation release. A terminal daemon with a retained kernel mount must still
// withdraw it; only exact process exit AND kernel absence make it trivially cold.
// Cleanup terminates a refused, never-admitted daemon using its exact witness.
// No method may replay uncertain mutations into a replacement mount.
// Cold and recovery proofs carry the exact generation that the driver validated.
type Mount interface {
	CloseAdmission(generation uint64)
	Prepare(context.Context, uint64) (Recovery, error)
	Suspend(context.Context, *pb.Suspension) (ColdResult, error)
	Recover(context.Context, *pb.ResumeToken) (Recovery, error)
	OpenAdmission(generation uint64) error
	Cleanup(context.Context, Witness) (CleanupProof, error)
}
type ColdResult struct {
	Generation   uint64
	ColdComplete bool
	Loss         []*pb.Loss
}
type Recovery struct {
	Generation                                                                                   uint64
	State, Reason                                                                                string
	SessionValidated, AuthorizationValidated, InitialRenewalInstalled, ColdSubscriptionInstalled bool
	Loss                                                                                         []*pb.Loss
}

func (r Recovery) ready(g uint64) bool {
	return r.Generation == g && r.State == "ready" && r.SessionValidated && r.AuthorizationValidated && r.InitialRenewalInstalled && r.ColdSubscriptionInstalled
}

type Witness struct {
	Process, Kernel, Session, Enrollment string
	RoutesRevision                       [32]byte
}
type CleanupProof struct {
	Witness                     Witness
	ProcessExited, KernelAbsent bool
}
type entry struct {
	status                  *pb.MountStatus
	driver                  Mount
	witness                 Witness
	registration            uint64
	cleaned, terminal, cold bool
	draining                uint64
	serial                  chan struct{}
}

func newEntry(id *pb.MountID, w Witness, m Mount, generation uint64) *entry {
	return &entry{driver: m, witness: w, registration: generation, serial: make(chan struct{}, 1),
		status: &pb.MountStatus{Mount: clone(id), State: "closed", Cleanup: "retained"}}
}

type Supervisor struct {
	mu                sync.Mutex
	boot, host, guest []byte
	generation        uint64
	phase             string
	suspension        *pb.Suspension
	generationContext context.Context
	cancel            context.CancelFunc
	mounts            map[string]*entry
	retired           []*pb.MountStatus
}

// A restarted service cannot infer safety while old mount processes may survive.
func New(boot, host, guest []byte, freshBoot bool) (*Supervisor, error) {
	if !control.ID(boot) || !control.ID(host) || !control.ID(guest) {
		return nil, fmt.Errorf("new supervisor identity: %w", control.ErrGrammar)
	}
	phase := "discard-only"
	if freshBoot {
		phase = "running"
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Supervisor{boot: bytes.Clone(boot), host: bytes.Clone(host), guest: bytes.Clone(guest),
		phase: phase, mounts: map[string]*entry{}, generationContext: ctx, cancel: cancel}, nil
}
func clone[T proto.Message](v T) T { return proto.Clone(v).(T) }
func (s *Supervisor) rosterLocked() []*pb.MountID {
	ids := make([]*pb.MountID, 0, len(s.mounts))
	for _, e := range s.mounts {
		ids = append(ids, clone(e.status.Mount))
	}
	sort.Slice(ids, func(i, j int) bool { return control.MountKey(ids[i]) < control.MountKey(ids[j]) })
	return ids
}
func (s *Supervisor) matchesLocked(x *pb.Suspension) bool {
	return x != nil && bytes.Equal(x.BootId, s.boot) && bytes.Equal(x.HostServiceId, s.host) && bytes.Equal(x.GuestServiceId, s.guest)
}
func cleanupRefused(ctx context.Context, m Mount, w Witness, cause error) error {
	p, err := m.Cleanup(ctx, w)
	if err != nil {
		return errors.Join(cause, fmt.Errorf("cleanup refused daemon: %w", err))
	}
	if p.Witness != w || !p.ProcessExited || !p.KernelAbsent {
		return errors.Join(cause, refused("refused daemon cleanup not proven"))
	}
	return cause
}

// Register is the only membership owner. Refusal performs exact cleanup; callers
// retain the witness and retry cleanup if the returned error says it is unproven.
func (s *Supervisor) Register(ctx context.Context, id *pb.MountID, w Witness, m Mount) error {
	if m == nil {
		return fmt.Errorf("register missing driver: %w", control.ErrGrammar)
	}
	s.mu.Lock()
	m.CloseAdmission(s.generation)
	var err error
	if invalid := control.Mount(id); invalid != nil {
		err = fmt.Errorf("register identity: %w", invalid)
	} else if s.phase != "running" {
		err = refused("register outside running phase")
	} else if len(s.mounts) >= control.MaxMounts {
		err = refused("register mount capacity reached")
	} else {
		for _, e := range s.mounts {
			if bytes.Equal(e.status.Mount.AuthorityId, id.AuthorityId) && e.status.Mount.VolumeId == id.VolumeId {
				err = refused("register duplicate volume")
				break
			}
		}
	}
	if err == nil {
		s.mounts[control.MountKey(id)] = newEntry(id, w, m, s.generation)
	}
	s.mu.Unlock()
	if err != nil {
		return cleanupRefused(ctx, m, w, err)
	}
	return nil
}
func callContext(parent, generation context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(generation)
	stop := context.AfterFunc(parent, cancel)
	if parent.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}
func acquire(ctx context.Context, e *entry) error {
	select {
	case e.serial <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func release(e *entry) { <-e.serial }

// Initial activation can only use a driver proof for the registration generation.
// It cannot be reused to bypass a failed token-bound post-wake recovery.
func (s *Supervisor) Activate(ctx context.Context, id *pb.MountID, generation uint64) error {
	s.mu.Lock()
	e := s.mounts[control.MountKey(id)]
	if e == nil {
		s.mu.Unlock()
		return refused("activate unknown mount")
	}
	if s.phase != "running" || generation != s.generation || generation != e.registration {
		s.mu.Unlock()
		return refused("activate stale registration generation")
	}
	if e.terminal || e.status.State != "closed" {
		s.mu.Unlock()
		return refused("activate mount not initially closed")
	}
	ctx, done := callContext(ctx, s.generationContext)
	s.mu.Unlock()
	defer done()
	if err := acquire(ctx, e); err != nil {
		return fmt.Errorf("activate wait: %w", err)
	}
	defer release(e)
	s.mu.Lock()
	if s.phase != "running" || generation != s.generation || e.status.State != "closed" || e.terminal {
		s.mu.Unlock()
		return refused("activate overtaken before prepare")
	}
	e.status.State = "recovering"
	s.mu.Unlock()
	r, err := e.driver.Prepare(ctx, generation)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "running" || generation != s.generation {
		return refused("activate overtaken during prepare")
	}
	return s.publishRecoveryLocked(ctx, e, generation, r, err)
}

// An identity-matching request closes and cancels EVERY daemon before grammar,
// phase or generation checks. Refusal cannot leave a previous recovery live.
// The request has no roster: the guest fixes membership and returns it to its
// dispatcher; SuspendAck binds that exact roster for the host's resume token.
func (s *Supervisor) BeginSuspend(request *pb.Suspension) (*pb.Suspension, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.matchesLocked(request) {
		return nil, refused("suspend service identity mismatch")
	}
	s.cancel()
	for _, e := range s.mounts {
		e.driver.CloseAdmission(max(s.generation, request.Generation))
		e.cold = false
		if !e.terminal {
			e.status.State = "closed"
		}
	}
	previous := s.phase
	s.phase = "discard-only"
	s.suspension = nil
	if err := control.Suspension(request); err != nil {
		return nil, fmt.Errorf("suspend identity: %w", err)
	}
	if previous == "discard-only" || s.generation == math.MaxUint64 || request.Generation != s.generation+1 {
		return nil, refused("suspend generation or phase mismatch")
	}
	if len(request.Roster) != 0 {
		return nil, refused("suspend roster belongs to guest")
	}
	s.generation = request.Generation
	s.phase = "suspending"
	s.generationContext, s.cancel = context.WithCancel(context.Background())
	s.suspension = clone(request)
	s.suspension.Roster = s.rosterLocked()
	return clone(s.suspension), nil
}
func cloneLoss(loss []*pb.Loss) []*pb.Loss {
	out := make([]*pb.Loss, 0, len(loss))
	for _, l := range loss {
		out = append(out, clone(l))
	}
	return out
}
func (s *Supervisor) mergeLossLocked(e *entry, loss []*pb.Loss) error {
	if len(loss) == 0 {
		return nil
	}
	bounded, overflow, err := control.BoundLoss(loss)
	if err != nil {
		return fmt.Errorf("mount loss snapshot: %w", err)
	}
	if !control.RetainsLoss(bounded, e.status.Loss) {
		if control.RetainsLoss(e.status.Loss, bounded) {
			return nil
		}
		return refused("contradictory cumulative loss snapshot")
	}
	e.status.Loss = bounded
	if overflow {
		e.terminal = true
		e.driver.CloseAdmission(s.generation)
		e.status.State = "terminal"
		e.status.Reason = "loss ledger capacity reached; exact cleanup and replacement required"
	}
	return nil
}

// Waiting for the per-mount lane also waits for overtaken driver calls. No cold
// proof can precede their completion, even if an adapter ignores cancellation.
func (s *Supervisor) Drain(parent context.Context, x *pb.Suspension, id *pb.MountID) error {
	s.mu.Lock()
	e := s.mounts[control.MountKey(id)]
	if e == nil || s.phase != "suspending" || !proto.Equal(s.suspension, x) || e.draining == s.generation || e.cold {
		s.mu.Unlock()
		return refused("drain not in current fixed roster")
	}
	generation := s.generation
	e.draining = generation
	ctx, done := callContext(parent, s.generationContext)
	s.mu.Unlock()
	defer done()
	if err := acquire(ctx, e); err != nil {
		return fmt.Errorf("drain wait: %w", err)
	}
	defer release(e)
	s.mu.Lock()
	if s.phase != "suspending" || !proto.Equal(s.suspension, x) {
		s.mu.Unlock()
		return refused("drain overtaken before withdrawal")
	}
	cleaned := e.cleaned
	s.mu.Unlock()
	result := ColdResult{Generation: generation, ColdComplete: true}
	var err error
	if !cleaned {
		result, err = e.driver.Suspend(ctx, clone(x))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if lossErr := s.mergeLossLocked(e, result.Loss); lossErr != nil {
		return lossErr
	}
	if s.phase != "suspending" || !proto.Equal(s.suspension, x) {
		return refused("drain overtaken during withdrawal")
	}
	e.draining = 0
	if err != nil {
		return fmt.Errorf("suspend mount %s: %w", id.VolumeId, err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("suspend mount %s: %w", id.VolumeId, ctx.Err())
	}
	if !result.ColdComplete || result.Generation != generation {
		return refused("kernel cold withdrawal not proven")
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
		return nil, refused("ack outside current suspension")
	}
	a := &pb.SuspendAck{Suspension: clone(x)}
	for _, id := range x.Roster {
		e := s.mounts[control.MountKey(id)]
		if !e.cold {
			return nil, refused("ack waiting for whole roster cold proof")
		}
		a.Mounts = append(a.Mounts, &pb.MountCold{Mount: clone(id), Loss: cloneLoss(e.status.Loss)})
	}
	s.phase = "suspended-cold"
	return a, nil
}
func (s *Supervisor) publishRecoveryLocked(ctx context.Context, e *entry, g uint64, r Recovery, err error) error {
	// Terminalization wins admission, but cannot erase a late cumulative loss
	// snapshot from the driver call it overtook.
	if lossErr := s.mergeLossLocked(e, r.Loss); lossErr != nil {
		err = errors.Join(err, lossErr)
	}
	if e.terminal {
		return errors.Join(refused("recovery mount is terminal"), err)
	}
	e.status.State = "closed"
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && r.ready(g) {
		err = e.driver.OpenAdmission(g)
		if err == nil {
			e.status.State = "ready"
			e.status.Reason = ""
			e.cold = false
			return nil
		}
	}
	if err == nil && (r.State == "terminal" || r.State == "authorization-required") && r.Generation == g {
		e.terminal = true
		e.status.State = r.State
		e.status.Reason = control.BoundedReason(r.Reason)
		if e.status.Reason == "" {
			e.status.Reason = "fresh authorization required"
		}
		return nil
	}
	if err == nil {
		err = refused("fresh generation-tagged authority recovery not proven")
	}
	e.status.Reason = control.BoundedReason(err.Error())
	return fmt.Errorf("prepare mount %s: %w", e.status.Mount.VolumeId, err)
}

// Resume consumes authorization and immediately reports per-mount recovering
// status. Independent mount lanes recover without a workspace-wide deadline.
// Status is the subsequent observation surface; no mount blocks another.
// The caller context bounds token consumption only. Once consumed, recovery
// belongs to the generation, not to the lifetime of its completed control RPC.
func (s *Supervisor) Resume(parent context.Context, t *pb.ResumeToken) (*pb.ResumeAck, error) {
	if err := parent.Err(); err != nil {
		return nil, fmt.Errorf("resume before token consumption: %w", err)
	}
	if err := control.Token(t); err != nil {
		return nil, fmt.Errorf("resume token: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "suspended-cold" || !proto.Equal(s.suspension, t.Suspension) {
		return nil, refused("resume token consumed or suspension mismatch")
	}
	s.phase = "running"
	a := &pb.ResumeAck{Token: clone(t)}
	for _, id := range t.Suspension.Roster {
		e := s.mounts[control.MountKey(id)]
		if !e.terminal {
			e.status.State = "recovering"
			ctx, done := context.WithCancel(s.generationContext)
			go s.recoverMount(ctx, done, e, clone(t))
		}
		a.Mounts = append(a.Mounts, clone(e.status))
	}
	return a, nil
}
func (s *Supervisor) recoverMount(ctx context.Context, done func(), e *entry, t *pb.ResumeToken) {
	defer done()
	if err := acquire(ctx, e); err != nil {
		return
	}
	defer release(e)
	s.mu.Lock()
	if s.phase != "running" || e.terminal || s.mounts[control.MountKey(e.status.Mount)] != e || ctx.Err() != nil || !proto.Equal(s.suspension, t.Suspension) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	r, err := e.driver.Recover(ctx, t)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "running" || !proto.Equal(s.suspension, t.Suspension) {
		_ = s.mergeLossLocked(e, r.Loss)
		return
	}
	_ = s.publishRecoveryLocked(ctx, e, t.Suspension.Generation, r, err)
}
func (s *Supervisor) Status() *pb.StatusReply {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &pb.StatusReply{BootId: bytes.Clone(s.boot), HostServiceId: bytes.Clone(s.host),
		GuestServiceId: bytes.Clone(s.guest), Generation: s.generation, State: s.phase}
	for _, id := range s.rosterLocked() {
		out.Mounts = append(out.Mounts, clone(s.mounts[control.MountKey(id)].status))
	}
	for _, v := range s.retired[:min(len(s.retired), control.MaxRetiredBatch)] {
		out.Retired = append(out.Retired, clone(v))
	}
	return out
}
func (s *Supervisor) Terminal(id *pb.MountID, reason string, loss []*pb.Loss) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e == nil || s.phase != "running" || reason == "" {
		return refused("terminal unknown mount, phase or missing reason")
	}
	e.driver.CloseAdmission(s.generation)
	e.terminal = true
	e.status.State = "terminal"
	e.status.Reason = control.BoundedReason(reason)
	return s.mergeLossLocked(e, loss)
}
func (s *Supervisor) Cleanup(id *pb.MountID, p CleanupProof) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e == nil || !e.terminal || p.Witness != e.witness {
		return refused("cleanup terminal identity mismatch")
	}
	if p.ProcessExited {
		e.status.Cleanup = "process-exited"
	}
	if p.KernelAbsent {
		e.status.Cleanup = "kernel-absent"
	}
	if !p.ProcessExited || !p.KernelAbsent {
		return refused("cleanup requires process exit and kernel absence")
	}
	e.status.Cleanup = "complete"
	e.cleaned = true
	return nil
}

// Replace registers a closed daemon after exact old cleanup. Activate obtains
// its proof from Prepare; callers cannot supply a recovery proof. Retired
// outcomes are removed only after explicit observation acknowledgement.
func (s *Supervisor) Replace(ctx context.Context, old, id *pb.MountID, w Witness, m Mount) error {
	if m == nil {
		return fmt.Errorf("replace missing driver: %w", control.ErrGrammar)
	}
	s.mu.Lock()
	m.CloseAdmission(s.generation)
	e := s.mounts[control.MountKey(old)]
	var err error
	if invalid := control.Mount(id); invalid != nil {
		err = fmt.Errorf("replace identity: %w", invalid)
	} else if s.phase != "running" || e == nil || !e.cleaned {
		err = refused("replace requires running phase and exact cleanup")
	} else if len(s.retired) >= MaxRetired {
		err = refused("replace waiting for retired outcome acknowledgement")
	} else if !bytes.Equal(old.AuthorityId, id.AuthorityId) || old.VolumeId != id.VolumeId || bytes.Equal(old.Incarnation, id.Incarnation) {
		err = refused("replace authority, volume or incarnation mismatch")
	} else {
		select {
		case e.serial <- struct{}{}:
			release(e)
		default:
			err = refused("replace waiting for old driver calls")
		}
	}
	if err == nil {
		s.retired = append(s.retired, clone(e.status))
		delete(s.mounts, control.MountKey(old))
		s.mounts[control.MountKey(id)] = newEntry(id, w, m, s.generation)
	}
	s.mu.Unlock()
	if err != nil {
		return cleanupRefused(ctx, m, w, err)
	}
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
func (s *Supervisor) AcknowledgeRetired(observed []*pb.MountStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(observed) == 0 || len(observed) > control.MaxRetiredBatch || len(observed) > len(s.retired) {
		return refused("retired acknowledgement exceeds retained outcomes")
	}
	for i, v := range observed {
		if !proto.Equal(v, s.retired[i]) {
			return refused("retired acknowledgement differs from exact outcome")
		}
	}
	s.retired = append([]*pb.MountStatus(nil), s.retired[len(observed):]...)
	return nil
}
