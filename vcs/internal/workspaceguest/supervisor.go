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

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
	"time"
)

// The 128 reservations permit a full 64-key rollover. Each active key owns
// its final evidence slot until acknowledgement; active membership stays at 64.
const MaxReservations = 2 * control.MaxMounts

var ErrState = errors.New("workspace guest: transition refused")

func refused(why string) error { return fmt.Errorf("%s: %w", why, ErrState) }

// Mount is the Stage 1c boundary. CloseAdmission immediately advances a serial
// (even on repeated same-generation Close), clears prepared publication and
// closes new serving admission without I/O or joins. It does not retract an
// already admitted callback or physical reply; Suspend joins that fixed cohort.
// OpenAdmission only CAS-publishes the exact prepared generation/serial proof.
// It performs no I/O and never calls the supervisor. Raced local assignments
// remain inert under a later Close and are retired before Suspend acknowledges.
// Prepare/Recover retry classified transient failures inside one generation-
// owned job with bounded attempts/backoff and no logical recovery timeout.
// Real failure ends the incarnation. Recovery never attaches a replacement
// session or resets an existing renewal owner's sequence. Cancellation closes
// permission, then joins the actual job; it cannot erase assigned work.
// Suspend proves withdrawal, physical settlement and worker dispositions.
// Cleanup uses the exact retained witness. No method may replay an uncertain
// mutation into a replacement. No real driver is enabled by this interface.
type Mount interface {
	CloseAdmission(generation uint64) uint64
	Prepare(context.Context, uint64) (Recovery, error)
	Suspend(context.Context, *pb.Suspension) (ColdResult, error)
	Recover(context.Context, *pb.ResumeToken) (Recovery, error)
	OpenAdmission(generation, gateSerial uint64) error
	Cleanup(context.Context, Witness) (CleanupProof, error)
}
type ColdResult struct {
	Generation   uint64
	ColdComplete bool
	Loss         []*pb.Loss
	Outcome      *pb.MountOutcome
}
type Recovery struct {
	Generation, GateSerial                                              uint64
	State, Reason                                                       string
	SessionValidated, AuthorizationValidated, ColdSubscriptionInstalled bool
	Standalone                                                          bool
	Renewal                                                             mountenrollment.RenewalReadiness
	SessionID                                                           string
	AuthorizationDeadline                                               time.Time
	Loss                                                                []*pb.Loss
	Outcome                                                             *pb.MountOutcome
}

func (r Recovery) ready(g, serial uint64) bool {
	return r.Generation == g && r.GateSerial == serial && r.State == "ready" && r.SessionValidated && r.AuthorizationValidated && r.ColdSubscriptionInstalled &&
		r.Renewal.Ready(r.Standalone, mountenrollment.Permit{Generation: g, GateSerial: serial}, r.SessionID, r.AuthorizationDeadline)
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
	gateSerial              uint64
	cleaned, terminal, cold bool
	draining                uint64
	serial                  chan struct{}
}

func newEntry(id *pb.MountID, w Witness, m Mount, generation, serial uint64) *entry {
	return &entry{driver: m, witness: w, registration: generation, gateSerial: serial, serial: make(chan struct{}, 1),
		status: initialStatus(id)}
}

// setStatus is the sole state, reason and cleanup writer. Empty cleanup retains
// its previous value. Reasons belong to this transition;
// only terminal states and closed may carry one on the paired wire.
func (e *entry) setStatus(state, reason, cleanup string) {
	if cleanup != "" {
		e.status.Cleanup = cleanup
	}
	e.status.State = state
	if state != "ready" {
		e.status.Renewal = &pb.RenewalReadiness{State: "pending"}
	}
	e.status.Reason = ""
	if state == "terminal" || state == "authorization-required" || state == "closed" {
		e.status.Reason = control.BoundedReason(reason)
		if e.status.Reason == "" && (state == "terminal" || state == "authorization-required") {
			if state == "authorization-required" {
				e.status.Reason = "fresh authorization required"
			} else {
				e.status.Reason = "mount ended; exact cleanup and replacement required"
			}
		}
	}
}
func initialStatus(id *pb.MountID) *pb.MountStatus {
	e := &entry{status: &pb.MountStatus{Mount: clone(id), Outcome: control.UnknownOutcome(), Renewal: &pb.RenewalReadiness{State: "pending"}}}
	e.setStatus("closed", "", "retained")
	return e.status
}

type Supervisor struct {
	identities           *workspacemount.Store
	clock                guestClock
	waitClock            func(context.Context, uint64) error
	mu                   sync.Mutex
	boot, host, guest    []byte
	generation           uint64
	phase                string
	suspension           *pb.Suspension
	generationContext    context.Context
	cancel               context.CancelFunc
	mounts               map[string]*entry
	retired              []*pb.RetiredOutcome
	retirementSequence   uint64
	acknowledgedSequence uint64
	jobs                 map[string]*mountJob
	jobDriver            MountJobDriver
}

// A restarted service cannot infer safety while old mount processes may survive.
func New(boot, host, guest []byte, freshBoot bool, driver MountJobDriver) (*Supervisor, error) {
	if !control.ID(boot) || !control.ID(host) || !control.ID(guest) {
		return nil, fmt.Errorf("new supervisor identity: %w", control.ErrGrammar)
	}
	phase := "discard-only"
	if freshBoot {
		phase = "running"
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Supervisor{boot: bytes.Clone(boot), host: bytes.Clone(host), guest: bytes.Clone(guest),
		phase: phase, mounts: map[string]*entry{}, jobs: map[string]*mountJob{}, jobDriver: driver, generationContext: ctx, cancel: cancel}, nil
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
	serial := m.CloseAdmission(s.generation)
	var err error
	if invalid := control.Mount(id); invalid != nil {
		err = fmt.Errorf("register identity: %w", invalid)
	} else if s.retainedIncarnationLocked(id) {
		err = refused("register previously retired incarnation")
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
		err = s.desiredCapacityLocked(id)
	}
	if err == nil {
		s.mounts[control.MountKey(id)] = newEntry(id, w, m, s.generation, serial)
	}
	s.mu.Unlock()
	if err != nil {
		return cleanupRefused(ctx, m, w, err)
	}
	return nil
}
func callContext(parent, generation context.Context) (context.Context, func()) {
	// Preserve Deadline for adapters forwarding the shrinking local allowance.
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(generation, cancel)
	if generation.Err() != nil {
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

// Late driver evidence is merged before releasing the lane. Only then may an
// exact joined removal publish its final immutable retirement.
func (s *Supervisor) release(e *entry) {
	release(e)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := control.MountKey(e.status.Mount)
	if s.mounts[key] == e {
		s.retireJoinedLocked(key)
	}
}

// Initial activation can only use a driver proof for the registration generation.
// It cannot be reused to bypass a failed token-bound post-wake recovery.
func (s *Supervisor) Activate(ctx context.Context, id *pb.MountID, generation uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	ctx, done := context.WithCancel(s.generationContext)
	s.mu.Unlock()
	defer done()
	if err := acquire(ctx, e); err != nil {
		return fmt.Errorf("activate wait: %w", err)
	}
	defer s.release(e)
	s.mu.Lock()
	if s.phase != "running" || generation != s.generation || e.status.State != "closed" || e.terminal {
		s.mu.Unlock()
		return refused("activate overtaken before prepare")
	}
	e.setStatus("recovering", "", "")
	s.mu.Unlock()
	r, err := e.driver.Prepare(ctx, generation)
	s.mu.Lock()
	defer s.mu.Unlock()
	if evidenceErr := s.mergeEvidenceLocked(e, r.Loss, r.Outcome); evidenceErr != nil {
		err = errors.Join(err, evidenceErr)
	}
	if s.phase != "running" || generation != s.generation {
		return errors.Join(refused("activate overtaken during prepare"), err)
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
	if s.clock != nil {
		s.clock.Pause()
	}
	for _, e := range s.mounts {
		e.gateSerial = e.driver.CloseAdmission(max(s.generation, request.Generation))
		e.cold = false
		if !e.terminal {
			e.setStatus("closed", "", "")
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
func (s *Supervisor) mergeEvidenceLocked(e *entry, loss []*pb.Loss, outcome *pb.MountOutcome) error {
	var outcomeErr error
	if outcome != nil {
		outcomeErr = control.Outcome(outcome)
		if outcomeErr == nil {
			old := e.status.Outcome
			merged := clone(old)
			merged.CleanupDebt = max(old.CleanupDebt, outcome.CleanupDebt)
			if outcome.Observation == "observed" {
				merged.Observation = "observed"
				for _, pair := range [][2]*string{{&merged.Durability, &outcome.Durability}, {&merged.Release, &outcome.Release}} {
					if *pair[0] == "unresolved" {
						*pair[0] = *pair[1]
					} else if *pair[1] != "unresolved" && *pair[0] != *pair[1] {
						outcomeErr = refused("contradictory outcome evidence")
					}
				}
			}
			// Debt survives even a contradictory snapshot; it is cumulative evidence.
			if outcomeErr != nil {
				old.CleanupDebt = merged.CleanupDebt
			} else {
				e.status.Outcome = merged
			}
		}
	}
	return errors.Join(outcomeErr, s.mergeLossLocked(e, loss))
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
		e.gateSerial = e.driver.CloseAdmission(s.generation)
		e.setStatus("terminal", "loss ledger capacity reached; exact cleanup and replacement required", "")
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
	job := s.jobs[control.MountKey(id)]
	s.mu.Unlock()
	defer done()
	if err := waitJob(ctx, job); err != nil {
		return fmt.Errorf("drain desired job join: %w", err)
	}
	if err := acquire(ctx, e); err != nil {
		return fmt.Errorf("drain wait: %w", err)
	}
	defer s.release(e)
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
	if lossErr := s.mergeEvidenceLocked(e, result.Loss, result.Outcome); lossErr != nil {
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
		e.setStatus("suspended-cold", "", "")
	}
	return nil
}
func (s *Supervisor) SuspendAck(x *pb.Suspension) (*pb.SuspendAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != "suspending" || !proto.Equal(s.suspension, x) {
		return nil, refused("ack outside current suspension")
	}
	for _, j := range s.jobs {
		select {
		case <-j.done:
		default:
			return nil, refused("ack waiting for desired job owner")
		}
	}
	a := &pb.SuspendAck{Suspension: clone(x)}
	for _, id := range x.Roster {
		e := s.mounts[control.MountKey(id)]
		if !e.cold {
			return nil, refused("ack waiting for whole roster cold proof")
		}
		a.Mounts = append(a.Mounts, &pb.MountCold{Mount: clone(id), Loss: cloneLoss(e.status.Loss), Outcome: clone(e.status.Outcome)})
	}
	s.phase = "suspended-cold"
	return a, nil
}
func (s *Supervisor) publishRecoveryLocked(ctx context.Context, e *entry, g uint64, r Recovery, err error) error {
	// Terminalization wins admission, but cannot erase a late cumulative loss
	// snapshot from the driver call it overtook.
	if lossErr := s.mergeEvidenceLocked(e, r.Loss, r.Outcome); lossErr != nil {
		err = errors.Join(err, lossErr)
	}
	if e.terminal {
		return errors.Join(refused("recovery mount is terminal"), err)
	}
	e.setStatus("closed", "", "")
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && r.ready(g, e.gateSerial) {
		err = e.driver.OpenAdmission(g, e.gateSerial)
		if err == nil {
			// Only a published serving interval starts fresh disposition evidence.
			outcome := control.UnknownOutcome()
			outcome.CleanupDebt = e.status.Outcome.CleanupDebt
			e.status.Outcome = outcome
			e.status.Renewal = &pb.RenewalReadiness{State: r.Renewal.State, InstalledSequence: r.Renewal.InstalledSequence}
			e.setStatus("ready", "", "")
			e.cold = false
			return nil
		}
	}
	if err == nil && (r.State == "terminal" || r.State == "authorization-required") && r.Generation == g {
		e.terminal = true
		e.gateSerial = e.driver.CloseAdmission(g)
		e.setStatus(r.State, r.Reason, "")
		return nil
	}
	if err == nil {
		err = refused("fresh generation-tagged authority recovery not proven")
	}
	// A failed Prepare/Recover ends this incarnation. There is no current-
	// generation retry: exact cleanup and a newly registered replacement obtain
	// a fresh Prepare proof through the same supervised path as other failures.
	e.gateSerial = e.driver.CloseAdmission(g)
	e.terminal = true
	e.setStatus("terminal", err.Error(), "")
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
	if s.clock != nil {
		if err := s.clock.Begin(s.generation); err != nil {
			return nil, err
		}
	}
	s.phase = "running"
	a := &pb.ResumeAck{Token: clone(t)}
	for _, id := range t.Suspension.Roster {
		e := s.mounts[control.MountKey(id)]
		if !e.terminal {
			e.setStatus("recovering", "", "")
			ctx, done := context.WithCancel(s.generationContext)
			go s.recoverMount(ctx, done, e, clone(t))
		}
		a.Mounts = append(a.Mounts, clone(e.status))
	}
	// ResumeAck first consumes the exact fixed roster. Joined exact removals
	// can now transfer membership into their already reserved retirement.
	for key := range s.jobs {
		s.retireJoinedLocked(key)
	}
	return a, nil
}
func (s *Supervisor) recoverMount(ctx context.Context, done func(), e *entry, t *pb.ResumeToken) {
	defer done()
	if err := acquire(ctx, e); err != nil {
		return
	}
	defer s.release(e)
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
		_ = s.mergeEvidenceLocked(e, r.Loss, r.Outcome)
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
	for _, job := range s.jobs {
		out.Jobs = append(out.Jobs, clone(job.status))
	}
	sort.Slice(out.Jobs, func(i, j int) bool { return control.MountKey(out.Jobs[i].Mount) < control.MountKey(out.Jobs[j].Mount) })
	return out
}
func (s *Supervisor) Terminal(id *pb.MountID, reason string, loss []*pb.Loss) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e != nil {
		if err := s.mergeLossLocked(e, loss); err != nil {
			return err
		}
	}
	if e == nil || reason == "" {
		return refused("terminal unknown mount or missing reason")
	}
	e.gateSerial = e.driver.CloseAdmission(s.generation)
	e.terminal = true
	e.setStatus("terminal", reason, "")
	return s.mergeLossLocked(e, loss)
}
func (s *Supervisor) Cleanup(id *pb.MountID, p CleanupProof) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mounts[control.MountKey(id)]
	if e == nil || !e.terminal {
		return refused("cleanup terminal identity mismatch")
	}
	if e.cleaned {
		return nil
	}
	if p.Witness != e.witness {
		return refused("cleanup terminal identity mismatch")
	}
	if !p.ProcessExited || !p.KernelAbsent {
		return refused("cleanup requires process exit and kernel absence")
	}
	e.setStatus(e.status.State, e.status.Reason, "complete")
	e.cleaned = true
	s.retireJoinedLocked(control.MountKey(id))
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
	serial := m.CloseAdmission(s.generation)
	e := s.mounts[control.MountKey(old)]
	var err error
	if invalid := control.Mount(id); invalid != nil {
		err = fmt.Errorf("replace identity: %w", invalid)
	} else if s.phase == "running" && e == nil {
		err = refused("replace old incarnation already absent; Register the new incarnation separately")
	} else if s.phase != "running" || !e.cleaned {
		err = refused("replace requires running phase and exact cleanup")
	} else if s.retainedIncarnationLocked(id) {
		err = refused("replace previously retired incarnation")
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
		if j := s.jobs[control.MountKey(old)]; j != nil {
			select {
			case <-j.done:
			default:
				err = refused("replace waiting for desired job owner")
			}
		}
	}
	if err == nil {
		s.retireLocked(e.status, s.jobs[control.MountKey(old)])
		delete(s.mounts, control.MountKey(old))
		delete(s.jobs, control.MountKey(old))
		// The old owner has finished using its reservation. Only admission of
		// the new incarnation may need an acknowledgement or sequence space.
		if err = s.desiredCapacityLocked(id); err == nil {
			s.mounts[control.MountKey(id)] = newEntry(id, w, m, s.generation, serial)
		} else {
			err = fmt.Errorf("replace old incarnation retired; new admission failed: %w", err)
		}
	}
	s.mu.Unlock()
	if err != nil {
		return cleanupRefused(ctx, m, w, err)
	}
	return nil
}
func (s *Supervisor) Retired() []*pb.RetiredOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*pb.RetiredOutcome, 0, len(s.retired))
	for _, v := range s.retired {
		out = append(out, clone(v))
	}
	return out
}
func (s *Supervisor) retainedIncarnationLocked(id *pb.MountID) bool {
	for _, outcome := range s.retired {
		if outcome.MountStatus != nil && proto.Equal(outcome.MountStatus.Mount, id) {
			return true
		}
	}
	return false
}

// Duplicate and older acknowledgements are harmless. A future sequence cannot
// free anything, and one request cannot skip the bounded batch Status exposed.
func (s *Supervisor) AcknowledgeRetired(through uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if through == 0 || through > s.retirementSequence {
		return refused("retired acknowledgement exceeds exposed outcomes")
	}
	if through <= s.acknowledgedSequence {
		return nil
	}
	if through-s.acknowledgedSequence > control.MaxRetiredBatch {
		return refused("retired acknowledgement exceeds exposed batch")
	}
	count := int(through - s.acknowledgedSequence)
	s.retired = append([]*pb.RetiredOutcome(nil), s.retired[count:]...)
	s.acknowledgedSequence = through
	return nil
}

// ChannelLost permanently withdraws this boot's control authorization. No
// replacement stream can restore eligibility or reopen a daemon.
func (s *Supervisor) ChannelLost() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discardLocked()
}
func (s *Supervisor) discardLocked() {
	s.cancel()
	s.phase = "discard-only"
	s.suspension = nil
	for _, e := range s.mounts {
		e.gateSerial = e.driver.CloseAdmission(s.generation)
		e.cold = false
		if !e.terminal {
			e.setStatus("closed", "", "")
		}
	}
}
