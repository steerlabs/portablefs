//go:build linux

package fusev3

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

type remountRequiredRPC struct {
	*terminalEnforcementRPC
	recovered atomic.Bool
}

func (r *remountRequiredRPC) RecoverEpoch(context.Context) (RPC, error) {
	r.recovered.Store(true)
	return newFakeRPC(), nil
}

func TestSupervisedEpochChangeWithdrawsBeforeAnyReplacementAttach(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "epoch change", true: "concurrent shutdown"}[canceled], func(t *testing.T) {
			rpc := &remountRequiredRPC{terminalEnforcementRPC: &terminalEnforcementRPC{
				fakeRPC: newFakeRPC(), pending: make(chan struct{}), done: make(chan struct{}),
				cause: authorityrpc.ErrAuthorityChanged,
			}}
			reports := make(chan RevocationReport, 1)
			cfg := testConfig(32)
			cfg.RequireRemountOnEpochChange = true
			cfg.OnRevoked = func(report RevocationReport) { reports <- report }
			mount := newMount(context.Background(), rpc, cfg)
			kernel := &fakeWithdrawal{installed: true}
			mount.kernelMount = kernelMount{id: "271", device: "0:57", point: t.TempDir()}
			mount.withdrawal = kernel.ops()
			t.Cleanup(func() { _ = mount.Close() })
			close(rpc.pending)
			if canceled {
				mount.cancel()
			}
			mount.watchEpochSession(mount.ctx, rpc.pending)
			if rpc.recovered.Load() {
				t.Fatal("supervised mount spent its original grant to create an unowned replacement session")
			}
			if canceled {
				return
			}
			if !mount.isRevoked() {
				t.Fatal("epoch change returned before closing frontend admission")
			}
			select {
			case report := <-reports:
				if !report.KernelStateWithdrawn || report.Reason != RevocationSessionTerminal {
					t.Fatalf("withdrawal report = %+v", report)
				}
			case <-time.After(time.Second):
				t.Fatal("epoch change did not publish its exact withdrawal verdict")
			}
			select {
			case <-rpc.done:
			default:
				t.Fatal("reported withdrawal without finishing old session enforcement")
			}
		})
	}
}
