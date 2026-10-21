package workspaceguest

import (
	"context"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

// NoMount exercises the transport/coordinator transaction without creating a
// filesystem or claiming authority validation. It can prove cold absence, but
// can never open filesystem admission. Stage 1c replaces this boundary.
type NoMount struct{}

func (NoMount) CloseAdmission(uint64) {}
func (NoMount) Suspend(context.Context, *pb.Suspension) (ColdResult, error) {
	return ColdResult{ColdComplete: true}, nil
}
func (NoMount) Recover(context.Context, *pb.ResumeToken) (Recovery, error) {
	return Recovery{State: "authorization-required", Reason: "no mount; real mount integration pending"}, nil
}
func (NoMount) OpenAdmission(uint64) error { return ErrState }
