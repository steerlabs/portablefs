package workspacecontrol

import (
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

func TestAwakeRecoveryExactModeRosterAndBudget(t *testing.T) {
	for _, mode := range []string{"missing-mode", "host-roster", "power-budget", "normal-resume", "normal-suspend"} {
		t.Run(mode, func(t *testing.T) {
			e := proto.Clone(fixtures()["awake_recover"]).(*pb.Envelope)
			tok := e.GetAwakeRecover()
			switch mode {
			case "missing-mode":
				tok.Suspension.AwakeRecovery = false
			case "host-roster":
				tok.Suspension.Roster = []*pb.MountID{fixtureMount()}
			case "power-budget":
				e.DrainBudgetNanos = 1
			case "normal-resume":
				e.Body = &pb.Envelope_Resume{Resume: tok}
			case "normal-suspend":
				e.Body = &pb.Envelope_Suspend{Suspend: tok.Suspension}
				e.DrainBudgetNanos = 1
			}
			if Validate(e) == nil {
				t.Fatal("unequal awake grammar accepted")
			}
		})
	}
}
