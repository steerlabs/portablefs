//go:build linux

package fusev3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

type finalizationRPC struct {
	RPC
	refusal     error
	cause       error
	closeError  error
	detachCalls *int
}

func (r finalizationRPC) DetachAfterUnmount(ctx context.Context, p MountAbsenceProof) error {
	if r.detachCalls != nil {
		*r.detachCalls++
	}
	if r.refusal != nil {
		return r.refusal
	}
	return r.RPC.DetachAfterUnmount(ctx, p)
}

func (r finalizationRPC) SessionEndCause() error { return r.cause }
func (r finalizationRPC) Close() error {
	if r.closeError != nil {
		return r.closeError
	}
	return r.RPC.Close()
}

func TestWorkspaceFinalizationRetainsTerminalOutcomeAndRefusesCleanupDebt(t *testing.T) {
	for _, tc := range []struct {
		name                                                        string
		refusal, ended, badProof, closeFailed, wantError, abandoned bool
	}{
		{name: "terminal-only"},
		{name: "live-release-refused", refusal: true, wantError: true},
		{name: "ended-release-abandoned", refusal: true, ended: true, abandoned: true},
		{name: "ended-local-proof-refused", ended: true, badProof: true, wantError: true},
		{name: "ended-transport-close-failed", refusal: true, ended: true, closeFailed: true, wantError: true, abandoned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := testMount(t, 8)
			bindWorkspaceTestGate(t, m)
			terminal := errors.New("retained terminal authorization verdict")
			debt := errors.New("exact session detach refused")
			m.fatalErr = terminal
			var refusal error
			if tc.refusal {
				refusal = debt
			}
			var cause, closeError error
			if tc.ended {
				cause = terminal
			}
			if tc.closeFailed {
				closeError = debt
			}
			if tc.badProof {
				m.plannedFSName = ""
				m.plannedMountpoint = ""
			}
			calls := 0
			m.rpc.(*epochRPC).rpc = finalizationRPC{RPC: m.rpc.(*epochRPC).rpc, refusal: refusal, cause: cause, closeError: closeError, detachCalls: &calls}
			var persisted *WorkspaceObservation
			m.workspaceLifecycle = &workspaceLifecycle{persist: func(o WorkspaceObservation) error { persisted = &o; return nil }}
			m.workspaceLifecycle.evidence.Store(&workspaceEvidence{loss: []*pb.Loss{{Sequence: 1, AcceptedEntries: 2, AcceptedBytes: 7, Reason: "known terminal tail"}}})
			o, err := m.FinalizeWorkspace()
			if (err != nil) != tc.wantError || tc.closeFailed && !errors.Is(err, debt) {
				t.Fatal("terminal diagnostic confused exact cleanup", err)
			}
			if persisted == nil || len(persisted.Loss) != 1 || persisted.Loss[0].AcceptedBytes != 7 || o.Outcome.Durability != "unresolved" || control.Outcome(o.Outcome) != nil {
				t.Fatal("finalization erased/invented run evidence", persisted)
			}
			if (calls == 0) != tc.badProof {
				t.Fatal("local proof refusal was confused with remote abandonment", calls)
			}
			if (o.Outcome.Observation == "observed") != tc.abandoned {
				t.Fatal("observation did not describe actual abandonment", o.Outcome)
			}
			if (o.Outcome.Release == "abandoned") != tc.abandoned {
				t.Fatal("remote release outcome invented or lost", o.Outcome)
			}
			if ordinary := m.Close(); !errors.Is(ordinary, terminal) || tc.refusal && !errors.Is(ordinary, debt) {
				t.Fatal("ordinary close lost its combined diagnostic", ordinary)
			}
		})
	}
}

// An accepted cut remains owned after serving closure and exact
// local kernel removal. The production transport also checks serving at send.
type closeCutRPC struct {
	*coldTestRPC
	permission func() error
	drains     int
}

func (r *closeCutRPC) DrainDispatch(check func() error) error {
	r.permission = check
	r.drains++
	return nil
}
func (r *closeCutRPC) CallMutationSegments(ctx context.Context, q *authoritypb.Request, spans [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	if err := r.permission(); err != nil {
		return nil, err
	}
	return r.coldTestRPC.RPC.CallMutationSegments(ctx, q, spans, assigned)
}
func (r *closeCutRPC) CallMutation(ctx context.Context, q *authoritypb.Request) (*authoritypb.Response, error) {
	if err := r.permission(); err != nil {
		return nil, err
	}
	return r.coldTestRPC.RPC.CallMutation(ctx, q)
}
func TestWorkspaceFinalizationDrainsAcceptedCutAfterServingClosure(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "live-original-horizon"
		if expired {
			name = "expired-original-horizon"
		}
		t.Run(name, func(t *testing.T) {
			f, g, base := coldFixture(t)
			r := &closeCutRPC{coldTestRPC: base, permission: func() error { _, err := f.mount.workspace.Check(); return err }}
			f.mount.rpc.(*epochRPC).rpc = r
			e := f.lookup(t, 1, "close-cut")
			opened := openDelegatedWriter(t, f, e.NodeId)
			payload := []byte("accepted before removal")
			writeDelegated(t, f, e.NodeId, opened.Fh, 0, payload)
			old := f.mount.delegations.buf
			if old.Stats().Entries != 1 || old.Stats().Bytes != int64(len(payload)) {
				t.Fatal("no exact retained accepted cut", old.Stats())
			}
			f.mount.plannedFSName = "portablefs:" + f.mount.workspace.MountInstanceID()
			f.mount.plannedMountpoint = t.TempDir()
			g.Close(1)
			if r.permission() == nil {
				t.Fatal("serving permission survived Close")
			}
			if expired {
				f.mount.subscription.mu.Lock()
				f.mount.subscription.cacheUntil = f.mount.subscription.config.clock.Now().Add(-time.Second)
				f.mount.subscription.mu.Unlock()
			}
			o, err := f.mount.FinalizeWorkspace()
			if err != nil {
				t.Fatal("local finalization refused", err)
			}
			f.rpc.mu.Lock()
			applied := f.rpc.applied
			f.rpc.mu.Unlock()
			if expired {
				if applied != 0 || len(o.Loss) != 1 || o.Loss[0].AcceptedBytes != uint64(len(payload)) || o.Loss[0].AcceptedEntries != 1 {
					t.Fatal("expired old cut was extended or not exactly accounted", applied, o.Loss)
				}
			} else if applied == 0 || len(o.Loss) != 0 {
				t.Fatalf("accepted live cut discarded behind closed serving predicate; drains=%d applied=%d loss=%v", r.drains, applied, o.Loss)
			}
		})
	}
}
