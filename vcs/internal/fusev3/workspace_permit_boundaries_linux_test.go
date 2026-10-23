//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
)

type workspacePermitHookRPC struct {
	*coldTestRPC
	onKeepAlive func()
	onSubscribe func()
}

func (r *workspacePermitHookRPC) CallRead(ctx context.Context, q *authoritypb.Request) (*authoritypb.Response, error) {
	if q.GetKeepAlive() != nil && r.onKeepAlive != nil {
		r.onKeepAlive()
	}
	return r.coldTestRPC.CallRead(ctx, q)
}
func (r *workspacePermitHookRPC) Subscribe(ctx context.Context, a, b []byte) (*authoritypb.SubscribeReply, time.Time, error) {
	if r.onSubscribe != nil {
		r.onSubscribe()
	}
	return r.coldTestRPC.Subscribe(ctx, a, b)
}

// A newer Close can defeat readiness, validation, Subscribe or the retained
// cut before the successor frame arrives. Independent evidence must still fail.
func TestWorkspaceCloseDuringRecoveryValidation(t *testing.T) {
	for _, boundary := range []string{"clock-wait", "keepalive", "subscribe-rpc", "stale-start"} {
		for _, independent := range []bool{false, true} {
			name := boundary
			if independent {
				name += "-independent"
			}
			t.Run(name, func(t *testing.T) {
				f, gate, base := coldFixture(t)
				rpc := &workspacePermitHookRPC{coldTestRPC: base}
				f.mount.rpc.(*epochRPC).rpc = rpc
				clock := &workspaceTestClockOwner{refused: make(chan struct{})}
				f.mount.workspaceLifecycle.clock = clock
				f.lookup(t, 1, "warm")
				serial := gate.Close(1)
				if o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second)); err != nil || !o.ColdComplete {
					t.Fatal("initial cold", o, err)
				}
				var newer uint64
				var closeGate sync.Once
				closed := make(chan struct{})
				closeOnce := func() {
					closeGate.Do(func() {
						if independent {
							f.mount.workspaceLifecycle.evidence.Store(&workspaceEvidence{failure: syscall.ENOSPC})
						}
						newer = gate.Close(2)
						close(closed)
					})
				}
				switch boundary {
				case "keepalive":
					rpc.onKeepAlive = closeOnce
				case "subscribe-rpc":
					rpc.onSubscribe = closeOnce
				case "stale-start":
					closeOnce()
				case "clock-wait":
					clock.unavailable.Store(true)
					go func() {
						<-clock.refused
						closeOnce()
						clock.unavailable.Store(false)
					}()
				}
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				o, err := f.mount.RecoverWorkspace(ctx, 1, serial)
				t.Logf("%s: disposition=%v permitLoss=%+v prepared=%v err=%v", name, o.Result.Disposition, o.Result.PermitLoss, o.Prepared, err)
				select {
				case <-closed:
				case <-ctx.Done():
					t.Fatal("boundary not reached")
				}
				if o.Prepared {
					t.Fatal("overtaken job published prepared")
				}
				if independent {
					if o.Result.Disposition != authorityrpc.LifecycleFailed || !errors.Is(err, syscall.ENOSPC) {
						t.Fatal("independent failure erased by Close", o.Result)
					}
					return
				}
				if o.Result.Disposition != authorityrpc.LifecycleOvertaken || o.Result.PermitLoss == nil || *o.Result.PermitLoss != (authorityrpc.LifecyclePermitLoss{Generation: 1, Serial: serial, Successor: newer}) {
					t.Fatal("pure gate Close was not attributed Overtaken", o.Result)
				}
				rpc.onKeepAlive, rpc.onSubscribe = nil, nil
				o, err = f.mount.SuspendWorkspace(t.Context(), 2, newer, continuous.Time().Add(5*time.Second))
				if err != nil || !o.ColdComplete {
					t.Fatal("successor Suspend", o, err)
				}
				o, err = f.mount.RecoverWorkspace(t.Context(), 2, newer)
				if err != nil || !o.Prepared {
					t.Fatal("successor Recover", o, err)
				}
			})
		}
	}
}
