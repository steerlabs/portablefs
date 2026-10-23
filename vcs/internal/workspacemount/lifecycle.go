package workspacemount

import (
	"context"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"time"
)

type Mount interface {
	CloseAdmission(uint64) uint64
	Prepare(context.Context, uint64) (Recovery, error)
	Suspend(context.Context, *pb.Suspension) (ColdResult, error)
	Recover(context.Context, *pb.ResumeToken) (Recovery, error)
	OpenAdmission(uint64, uint64) error
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

func (r Recovery) Ready(g, serial uint64) bool {
	return r.Generation == g && r.GateSerial == serial && r.State == "ready" && r.SessionValidated && r.AuthorizationValidated && r.ColdSubscriptionInstalled && r.Renewal.Ready(r.Standalone, mountenrollment.Permit{Generation: g, GateSerial: serial}, r.SessionID, r.AuthorizationDeadline)
}

type CleanupProof struct {
	Witness                     Witness
	ProcessExited, KernelAbsent bool
}
