package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
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
	status *pb.MountJob
	done   chan struct{}
}

func sameVolume(a, b *pb.MountID) bool {
	return string(a.AuthorityId) == string(b.AuthorityId) && a.VolumeId == b.VolumeId
}

// Registered membership and desired intents share the same 64 slots. A second
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
	if !keys[control.MountKey(id)] && len(keys) >= control.MaxMounts {
		return refused("desired mount capacity reached")
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
	if err := s.desiredCapacityLocked(id); err != nil {
		return err
	}
	key := control.MountKey(id)
	if previous := s.jobs[key]; previous != nil {
		if request.RequestId <= previous.status.RequestId {
			return refused("desired job request retired or consumed")
		}
		select {
		case <-previous.done:
		default:
			return refused("desired job lane occupied")
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
	} else if s.jobDriver == nil {
		err = ErrUnavailable
	} else {
		err = s.jobDriver.Run(ctx, request, provision)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Cancellation defeats late success, but never erases an independent failure
	// or releases the slot while the old driver still owns resources.
	if err == nil {
		err = ctx.Err()
	}
	j.status.Phase = "complete"
	if err != nil {
		j.status.Phase, j.status.Failure = "failed", "handler-failed"
		switch {
		case errors.Is(err, ErrUnavailable):
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
