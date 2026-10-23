//go:build linux

package fusev3

import (
	"context"
	"errors"
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

type finalizationRPC struct {
	RPC
	refusal error
}

func (r finalizationRPC) DetachAfterUnmount(ctx context.Context, p MountAbsenceProof) error {
	if r.refusal != nil {
		return r.refusal
	}
	return r.RPC.DetachAfterUnmount(ctx, p)
}

func TestWorkspaceFinalizationRetainsTerminalOutcomeAndRefusesCleanupDebt(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal-only", true: "cleanup-refused"}[refuse], func(t *testing.T) {
			m, _ := testMount(t, 8)
			bindWorkspaceTestGate(t, m)
			terminal := errors.New("retained terminal authorization verdict")
			debt := errors.New("exact session detach refused")
			m.fatalErr = terminal
			var refusal error
			if refuse {
				refusal = debt
			}
			m.rpc.(*epochRPC).rpc = finalizationRPC{RPC: m.rpc.(*epochRPC).rpc, refusal: refusal}
			var persisted *WorkspaceObservation
			m.workspaceLifecycle = &workspaceLifecycle{persist: func(o WorkspaceObservation) error { persisted = &o; return nil }}
			m.workspaceLifecycle.evidence.Store(&workspaceEvidence{loss: []*pb.Loss{{Sequence: 1, AcceptedEntries: 2, AcceptedBytes: 7, Reason: "known terminal tail"}}})
			o, err := m.FinalizeWorkspace()
			if (err != nil) != refuse || refuse && !errors.Is(err, debt) {
				t.Fatal("terminal diagnostic confused exact cleanup", err)
			}
			if persisted == nil || len(persisted.Loss) != 1 || persisted.Loss[0].AcceptedBytes != 7 || o.Outcome.Observation != "unobserved" || o.Outcome.Durability != "unresolved" {
				t.Fatal("finalization erased/invented run evidence", persisted)
			}
			if ordinary := m.Close(); !errors.Is(ordinary, terminal) || refuse && !errors.Is(ordinary, debt) {
				t.Fatal("ordinary close lost its combined diagnostic", ordinary)
			}
		})
	}
}
