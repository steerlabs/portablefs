package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"syscall"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

var ErrUnavailable = errors.New("workspace real mount driver unavailable")

// MountJobDriver owns provisioning, initial activation and exact removal. It
// must join its actual work before returning, including on cancellation. The
// shipping Stage 1b guest supplies nil until the real root driver exists.
type MountJobDriver interface {
	Run(context.Context, *pb.MountJob, *pb.Provision) error
}

type mountJob struct {
	status   *pb.MountJob
	done     chan struct{}
	observed bool
}

func sameVolume(a, b *pb.MountID) bool {
	return string(a.AuthorityId) == string(b.AuthorityId) && a.VolumeId == b.VolumeId
}

// Every admitted key reserves its final retirement before work starts. Active
// membership has a separate bound; turning a key into evidence cannot allocate.
func (s *Supervisor) activeKeysLocked() map[string]bool {
	keys := make(map[string]bool, len(s.mounts)+len(s.jobs))
	for key := range s.mounts {
		keys[key] = true
	}
	for key := range s.jobs {
		keys[key] = true
	}
	return keys
}
func (s *Supervisor) slotsLocked() int { return len(s.activeKeysLocked()) + len(s.retired) }

func (s *Supervisor) retirementAvailableLocked() bool {
	return math.MaxUint64-s.retirementSequence > uint64(len(s.activeKeysLocked()))
}

// Callers transfer a key's reservation under mu, after its actual owners join.
func (s *Supervisor) retireLocked(mount *pb.MountStatus, job *mountJob) {
	s.retirementSequence++
	outcome := &pb.RetiredOutcome{RetirementSequence: s.retirementSequence}
	if mount != nil {
		outcome.MountStatus = clone(mount)
	}
	if job != nil {
		outcome.Job = clone(job.status)
	}
	s.retired = append(s.retired, outcome)
}

// Observation is committed only after the paired dispatcher writes the exact
// snapshot. Internal inspection and a terminal result published during I/O do
// not grant a successor permission to erase that result.
var ErrPredecessorUnobserved = errors.New("observe predecessor result with Status before retry")

func (s *Supervisor) observeWrittenStatus(snapshot *pb.StatusReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, result := range snapshot.Retired {
		if result.RetirementSequence <= s.exposedSequence {
			continue
		}
		index := result.RetirementSequence - s.acknowledgedSequence - 1
		if result.RetirementSequence != s.exposedSequence+1 || index >= uint64(len(s.retired)) || !proto.Equal(result, s.retired[index]) {
			break
		}
		s.exposedSequence = result.RetirementSequence
	}
	for _, result := range snapshot.Jobs {
		j := s.jobs[control.MountKey(result.Mount)]
		if j == nil || (result.Phase != "complete" && result.Phase != "failed") || !proto.Equal(j.status, result) {
			continue
		}
		select {
		case <-j.done:
			j.observed = true
		default:
		}
	}
}

// Registered membership and desired intents share 64 active slots. A second
// incarnation cannot hide behind a different job key for the same volume.
func (s *Supervisor) desiredCapacityLocked(id *pb.MountID) error {
	keys := map[string]bool{}
	for _, e := range s.mounts {
		if sameVolume(e.status.Mount, id) && control.MountKey(e.status.Mount) != control.MountKey(id) {
			return refused("desired mount incarnation conflict")
		}
		keys[control.MountKey(e.status.Mount)] = true
	}
	for key, j := range s.jobs {
		if sameVolume(j.status.Mount, id) && key != control.MountKey(id) {
			return refused("desired job incarnation conflict")
		}
		keys[key] = true
	}
	// Retirement moves observation ownership to RetireAck, including records
	// beyond the current Status page. No admission path may reuse that key
	// before the host consumes and acknowledges its exact predecessor.
	for _, outcome := range s.retired {
		if j := outcome.Job; j != nil && proto.Equal(j.Mount, id) {
			return refused("new key waiting for retired outcome acknowledgement")
		}
	}
	if !keys[control.MountKey(id)] {
		if len(keys) >= control.MaxMounts {
			return refused("desired mount capacity reached")
		}
		if s.slotsLocked() >= MaxReservations {
			return refused("new key waiting for retired outcome acknowledgement")
		}
		if !s.retirementAvailableLocked() {
			return refused("retired outcome sequence exhausted")
		}
	}
	return nil
}

// AcceptJob reserves one current slot under the state lock. The response only
// acknowledges that reservation; Status observes execution and retained failure.
// Neither a response waiter nor a retrying driver runs on the paired dispatcher.
func (s *Supervisor) AcceptJob(request *pb.Envelope) error {
	if err := control.Validate(request); err != nil {
		return fmt.Errorf("accept desired job: %w", err)
	}
	var id *pb.MountID
	var provision *pb.Provision
	var operation string
	switch b := request.Body.(type) {
	case *pb.Envelope_Mount:
		id, operation = b.Mount.Mount, "mount"
	case *pb.Envelope_Umount:
		id, operation = b.Umount.Mount, "umount"
	case *pb.Envelope_Provision:
		id, operation, provision = b.Provision.Mount, "provision", clone(b.Provision)
	default:
		return refused("not a desired mount operation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.phase != "running" {
		return refused("desired job outside running phase")
	}
	if s.retainedIncarnationLocked(id) {
		return refused("desired job previously retired incarnation")
	}
	if err := s.desiredCapacityLocked(id); err != nil {
		return err
	}
	key := control.MountKey(id)
	previous := s.jobs[key]
	if previous != nil {
		if request.RequestId <= previous.status.RequestId {
			return refused("desired job request retired or consumed")
		}
		select {
		case <-previous.done:
		default:
			return refused("desired job lane occupied")
		}
		if !previous.observed {
			return ErrPredecessorUnobserved
		}
	}
	j := &mountJob{status: &pb.MountJob{Mount: clone(id), RequestId: request.RequestId, Generation: s.generation, Operation: operation, Phase: "offered"}, done: make(chan struct{})}
	s.jobs[key] = j
	go s.runJob(s.generationContext, j, provision)
	return nil
}

func (s *Supervisor) runJob(ctx context.Context, j *mountJob, provision *pb.Provision) {
	s.mu.Lock()
	j.status.Phase = "running"
	request := clone(j.status)
	s.mu.Unlock()
	var err error
	if ctx.Err() != nil {
		err = ctx.Err()
	} else if request.Operation == "provision" && (s.identities != nil || s.jobDriver == nil) {
		err = s.provision(ctx, request.Generation, provision)
	} else if s.jobDriver == nil {
		err = ErrUnavailable
	} else {
		err = s.jobDriver.Run(ctx, request, provision)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var startup *workspacemount.StartupFailure
	if errors.As(err, &startup) && s.mounts[control.MountKey(request.Mount)] == nil {
		p := startup.Proof
		e := newEntry(request.Mount, p.Witness, startup.Owner, request.Generation, startup.Owner.CloseAdmission(s.generation))
		e.terminal, e.startup = true, true
		e.setStatus("terminal", "workspace startup failed; exact cleanup required", "retained")
		s.mounts[control.MountKey(request.Mount)] = e
		evidenceErr := s.mergeEvidenceLocked(e, p.Loss, p.Outcome)
		if evidenceErr == nil && p.ProcessExited && p.KernelAbsent {
			e.cleaned = true
			e.status.Cleanup = "complete"
		}
		err = errors.Join(err, evidenceErr)
	}
	// Cancellation defeats late success, but never erases an independent failure
	// or releases the slot while the old driver still owns resources.
	if err == nil {
		err = ctx.Err()
	}
	j.status.Phase = "complete"
	if err != nil {
		j.status.Phase, j.status.Failure = "failed", "handler-failed"
		switch {
		case errors.Is(err, syscall.EBUSY):
			j.status.Failure = "busy"
		case errors.Is(err, ErrUnavailable), errors.Is(err, ErrIdentityUnavailable):
			j.status.Failure = "unavailable"
		case errors.Is(err, ErrState):
			j.status.Failure = "refused"
		case errors.Is(err, context.DeadlineExceeded):
			j.status.Failure = "deadline"
		case errors.Is(err, context.Canceled):
			j.status.Failure = "stopped"
		}
		j.status.Reason = control.BoundedReason(err.Error())
		if j.status.Reason == "" {
			j.status.Reason = j.status.Failure
		}
	}
	close(j.done)
	s.retireJoinedLocked(control.MountKey(j.status.Mount))
}

func (s *Supervisor) retireJoinedLocked(key string) {
	j := s.jobs[key]
	if j == nil {
		return
	}
	select {
	case <-j.done:
	default:
		return
	}
	e := s.mounts[key]
	if e != nil {
		if (j.status.Operation != "umount" && !(e.startup && j.status.Operation == "mount" && j.status.Phase == "failed")) || !e.terminal || !e.cleaned {
			return
		}
		select {
		case e.serial <- struct{}{}:
			release(e)
		default:
			return
		}
		// The fixed cold roster remains intact through token consumption. Its
		// cleaned owners need no driver calls, and keep their own reservation.
		if s.phase == "suspending" || s.phase == "suspended-cold" {
			return
		}
	}
	var status *pb.MountStatus
	if e != nil {
		status = e.status
		delete(s.mounts, key)
	}
	s.retireLocked(status, j)
	delete(s.jobs, key)
}

func waitJob(ctx context.Context, j *mountJob) error {
	if j == nil {
		return ctx.Err()
	}
	select {
	case <-j.done:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Suspend closes every admission and cancels generation work before waiting.
// All roster lanes, including desired-only work, share the receipt deadline.
// A bounded waiter may return while an uncooperative driver remains owned; it
// cannot create a cold acknowledgment or free that driver's lane.
func (s *Supervisor) Suspend(parent context.Context, request *pb.Suspension, deadline time.Time) (ack *pb.SuspendAck, err error) {
	x, err := s.BeginSuspend(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			s.mu.Lock()
			if proto.Equal(s.suspension, x) {
				s.discardLocked()
			}
			s.mu.Unlock()
		}
	}()
	s.mu.Lock()
	if !proto.Equal(s.suspension, x) {
		s.mu.Unlock()
		return nil, refused("parallel drain overtaken before dispatch")
	}
	generation := s.generationContext
	jobs := make(map[string]*mountJob, len(s.jobs))
	for key, j := range s.jobs {
		jobs[key] = j
	}
	s.mu.Unlock()
	ctx, done := callContext(parent, generation)
	defer done()
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	results := make(chan error, control.MaxMounts)
	count := 0
	for _, id := range x.Roster {
		delete(jobs, control.MountKey(id))
		count++
		go func() { results <- s.Drain(ctx, x, id) }()
	}
	for _, j := range jobs {
		count++
		go func() { results <- waitJob(ctx, j) }()
	}
	for range count {
		select {
		case err := <-results:
			if err != nil {
				return nil, fmt.Errorf("parallel workspace drain: %w", err)
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("workspace drain deadline: %w", ctx.Err())
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !time.Now().Before(deadline) {
		return nil, context.DeadlineExceeded
	}
	// SuspendAck collects the fixed roster canonically, never completion order.
	ack, err = s.SuspendAck(x)
	if err == nil && (!time.Now().Before(deadline) || ctx.Err() != nil) {
		return nil, context.DeadlineExceeded
	}
	return ack, err
}
