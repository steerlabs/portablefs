package workspaceguest

import (
	"context"
	"errors"

	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

var ErrIdentityUnavailable = errors.New("guest identity unavailable")

type guestClock interface {
	Begin(uint64) error
	Pause()
}

// ConfigureGuest installs real identity and clock owners before pairing. It
// enables provisioning only; mount and removal still require PR 6's root driver.
func (s *Supervisor) ConfigureGuest(identity *workspacemount.Store, clock guestClock, wait func(context.Context, uint64) error) {
	s.identities = identity
	s.clock = clock
	s.waitClock = wait
}
func (s *Supervisor) Identity(request *pb.IdentityRequest) (*pb.IdentityReply, error) {
	s.mu.Lock()
	allowed := s.phase == "running"
	s.mu.Unlock()
	if !allowed {
		return nil, refused("identity outside running phase")
	}
	if s.identities == nil {
		return nil, ErrIdentityUnavailable
	}
	reply, err := s.identities.EnsureIdentity(request)
	if err != nil {
		return nil, ErrIdentityUnavailable
	}
	return reply, nil
}
func (s *Supervisor) provision(ctx context.Context, generation uint64, p *pb.Provision) error {
	if s.identities == nil {
		return ErrIdentityUnavailable
	}
	if s.waitClock == nil {
		return ErrUnavailable
	}
	return s.identities.AcceptProvision(ctx, p, func(ctx context.Context) error { return s.waitClock(ctx, generation) })
}
