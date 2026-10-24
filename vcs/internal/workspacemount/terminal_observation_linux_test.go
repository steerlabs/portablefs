//go:build linux

package workspacemount

import (
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

type terminalObservationHost struct {
	Host
	mu      sync.Mutex
	reasons []string
	proofs  chan CleanupProof
}

func (h *terminalObservationHost) Terminal(_ *pb.MountID, reason string, _ []*pb.Loss) error {
	h.mu.Lock()
	h.reasons = append(h.reasons, reason)
	h.mu.Unlock()
	return nil
}
func (h *terminalObservationHost) Cleanup(_ *pb.MountID, proof CleanupProof) error {
	h.proofs <- proof
	return nil
}

func TestRootTerminalObservationRetainsHostCleanupAfterKernelCompletion(t *testing.T) {
	for _, progress := range []string{"offered", "running", "complete", "failed"} {
		t.Run(progress, func(t *testing.T) {
			h := &terminalObservationHost{proofs: make(chan CleanupProof, 32)}
			run := desired(1)
			d := &Driver{id: run.Mount, witness: run.Witness, manager: &Manager{Host: h, Inventory: inventory(t)}}
			// Root resource reconciliation can already be complete while its host
			// publication remains owed. The child's phase cannot discharge it.
			d.cleaned.Store(true)
			d.observeState(mountcontrol.Workspace{}, &mountcontrol.WorkspaceResponse{State: "prepared",
				Phases: &mountcontrol.PhaseFacts{TerminalRemoval: mountcontrol.ActionStatus{Progress: "absent"}}})
			if d.terminalCleanup.Load() {
				t.Fatal("absent terminal action started cleanup")
			}
			const reason = "authorityrpc: authority session ended; remount is required"
			r := &mountcontrol.WorkspaceResponse{State: "failed", Phases: &mountcontrol.PhaseFacts{
				TerminalRemoval: mountcontrol.ActionStatus{Progress: progress,
					Action: &mountcontrol.KernelAction{ActionID: "3", Mode: "terminal", Reason: reason}},
			}}
			var observers sync.WaitGroup
			for range 32 {
				observers.Go(func() { d.observeState(mountcontrol.Workspace{}, r) })
			}
			observers.Wait()
			select {
			case proof := <-h.proofs:
				if !proof.ProcessExited || !proof.KernelAbsent || proof.Witness != run.Witness {
					t.Fatal("host lost the exact retained cleanup proof", proof)
				}
			case <-time.After(time.Second):
				t.Fatal("terminal kernel phase stranded root/host cleanup")
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.reasons) != 1 || h.reasons[0] != reason || len(h.proofs) != 0 {
				t.Fatal("concurrent observations duplicated cleanup or erased cause", h.reasons)
			}
		})
	}
}
