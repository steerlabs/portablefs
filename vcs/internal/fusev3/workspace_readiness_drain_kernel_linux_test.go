//go:build linux

package fusev3

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// An unassigned WRITE parked at the pre-assignment readiness fence must not be
// counted lost when readiness returns before the (live) drain deadline, and a
// canceled cut retained behind it must complete on Recover without loss or a
// duplicate WRITE.
func TestWorkspaceKernelReadinessReturnsDuringDrain(t *testing.T) {
	opusKernelParent(t, func(t *testing.T) { workspaceReadinessDrainChild(t, "restore") })
}
func TestWorkspaceKernelRecoverCompletesCanceledCut(t *testing.T) {
	opusKernelParent(t, func(t *testing.T) { workspaceReadinessDrainChild(t, "cancel") })
}

func workspaceReadinessDrainChild(t *testing.T, mode string) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	clock := &workspaceTestClockOwner{refused: make(chan struct{})}
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: clock, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v0", 0644)
	c.recover(c.suspend())
	file, err := os.OpenFile(f.join(0, "e"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.WriteAt([]byte("v0"), 0); err != nil {
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	loss0 := c.m.delegations.LossSequence()
	beforeWrites := f.counter.count("write")
	preAssignment, admit := workspaceHoldBeforeAssignment(t, f)
	assigned, released := make(chan struct{}), make(chan struct{})
	var assignedOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(released) }) }
	defer release()
	if mode == "cancel" {
		f.counter.setBeforeHandle(func(q *authoritypb.Request) {
			if w := q.GetWrite(); w != nil && w.GetFlushSequence() != 0 {
				assignedOnce.Do(func() { close(assigned) })
				<-released
			}
		})
		defer f.counter.setBeforeHandle(nil)
	}
	if _, err := file.WriteAt([]byte("w1"), 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-preAssignment:
	case <-time.After(5 * time.Second):
		t.Fatal("accepted WRITE did not reach pre-assignment hold")
	}
	clock.unavailable.Store(true)
	admit()
	waitUntil(t, 5*time.Second, "pre-assignment wait", func() bool { return f.clients[0].DispatchSnapshot().WaitingApplying > 0 })
	serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
	var o WorkspaceObservation
	switch mode {
	case "restore":
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		completed := make(chan struct{})
		go func() {
			defer close(completed)
			o, err = c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(8*time.Second))
		}()
		waitUntil(t, 5*time.Second, "drain captured", func() bool {
			c.m.subscription.mu.RLock()
			defer c.m.subscription.mu.RUnlock()
			return c.m.subscription.workspaceDrain != nil
		})
		clock.unavailable.Store(false)
		select {
		case <-completed:
		case <-ctx.Done():
			t.Fatal("cut with restored readiness did not finish", ctx.Err())
		}
		if err != nil || !o.ColdComplete {
			t.Fatal("cut with restored readiness", o, err)
		}
	case "cancel":
		ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
		o, err = c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(8*time.Second))
		cancel()
		fmt.Printf("canceled cut: cold=%v disposition=%v err=%v snapshot=%+v\n", o.ColdComplete, o.Result.Disposition, err, f.clients[0].DispatchSnapshot().WaitingApplying)
		if o.ColdComplete || o.Result.Disposition != authorityrpc.LifecycleOvertaken || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("canceled cut did not retain incomplete work", o.Result, err)
		}
		select {
		case <-assigned:
		case <-time.After(5 * time.Second):
			t.Fatal("captured drain never assigned retained WRITE")
		}
		clock.unavailable.Store(false)
		release()
	}
	fmt.Printf("%s: loss=%v writes=%d->%d\n", mode, o.Loss, beforeWrites, f.counter.count("write"))
	c.recover(serial)
	o = c.m.WorkspaceObservation()
	if len(o.Loss) != 0 || c.m.delegations.LossSequence() != loss0 {
		t.Error("restored-readiness cut over-accounted loss", o.Loss, c.m.delegations.LossSequence())
	}
	if n := f.counter.count("write"); n != beforeWrites+1 {
		t.Error("WRITE count", beforeWrites, n)
	}
	if data, err := os.ReadFile(filepath.Join(f.volumeRoot, "e")); err != nil || string(data) != "w1" {
		t.Error("accepted bytes not at authority", string(data), err)
	}
	if err := file.Sync(); err != nil {
		t.Error("old fsync after lossless cut", err)
	}
	if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Error("old close after lossless cut", err)
	}
	c.write(f.join(0, "fresh"), "ok", 0644)
	for _, b := range c.bad {
		t.Error(b)
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}
