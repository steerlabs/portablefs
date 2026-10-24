//go:build linux

package fusev3

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// K2: an incomplete Suspend (its propagated drain deadline already elapsed on
// arrival, or a cancelled sleep), then the natural old horizon passes.
func opusKernelIncompleteSuspendChild(t *testing.T) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v", 0644)
	held, err := os.OpenFile(f.join(0, "e"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Pwrite(int(held.Fd()), []byte("D"), 0); err != nil {
		t.Fatal(err)
	}
	serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	o, err := c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(-time.Second))
	cancel()
	fmt.Printf("Suspend with elapsed propagated deadline: cold=%v result=%v err=%v\n", o.ColdComplete, o.Result.Disposition, err)
	time.Sleep(12 * time.Second) // the old subscription horizon passes naturally
	serial2, _ := strconv.ParseUint(c.req("close"), 10, 64)
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Second)
	o, err = c.m.SuspendWorkspace(ctx, 1, serial2, c.now().Add(8*time.Second))
	cancel()
	fmt.Printf("next sleep's Suspend: cold=%v result=%v err=%v loss=%d outcome=%v\n", o.ColdComplete, o.Result.Disposition, err, len(o.Loss), o.Outcome)
	ctx, cancel = context.WithTimeout(t.Context(), 30*time.Second)
	o2, err2 := c.m.RecoverWorkspace(ctx, 1, serial2)
	cancel()
	fmt.Printf("Recover: prepared=%v result=%v err=%v\n", o2.Prepared, o2.Result.Disposition, err2)
	if err != nil || !o.ColdComplete || err2 != nil || !o2.Prepared {
		t.Fatalf("incomplete Suspend stranded the incarnation: suspend=%v recover=%v", err, err2)
	}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data := make([]byte, 4)
		n, err := unix.Pread(int(held.Fd()), data, 0)
		read <- readResult{data[:max(n, 0)], err}
	}()
	select {
	case result := <-read:
		t.Fatal("prepared read completed before serving permission", result)
	case <-time.After(25 * time.Millisecond):
	}
	if r := c.req("open"); r != "<nil>" {
		t.Fatal("open recovered cut", r)
	}
	var result readResult
	select {
	case result = <-read:
	case <-time.After(5 * time.Second):
		t.Fatal("held read did not finish after fresh permission")
	}
	data, rerr := os.ReadFile(f.join(1, "e"))
	fmt.Printf("held fd pread=%v; peer sees %q %v; revoked=%v sessionEnd=%v\n", result.err, data, rerr, c.m.isRevoked(), c.m.rpc.SessionEndCause())
	if result.err != nil || rerr != nil || string(result.data) != string(data) {
		t.Fatal("recovered held read disagrees with independent peer", result, string(data), rerr)
	}
	_ = held.Close()
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
func TestOpusR2KernelIncompleteSuspend(t *testing.T) {
	opusKernelParent(t, opusKernelIncompleteSuspendChild)
}

// K3: round-1 clock-readiness schedule with the cleanup-failure trail exposed.
func opusKernelClockDiagChild(t *testing.T) {
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
	c.write(f.join(0, "e"), "v", 0644)
	c.recover(c.suspend())
	t0 := time.Now()
	dm := c.m.delegations
	dm.hookMu.RLock()
	orig := dm.cleanupFailure
	dm.hookMu.RUnlock()
	dm.SetCleanupFailureReporter(func(err error) {
		fmt.Printf("CLEANUP-FAILURE +%v: %v\n", time.Since(t0).Round(time.Millisecond), err)
		if orig != nil {
			orig(err)
		}
	})
	held, err := os.OpenFile(f.join(0, "e"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Write([]byte("w")); err != nil {
		t.Fatal(err)
	}
	clock.unavailable.Store(true)
	corrected := clock.restoreAfter(3 * time.Second)
	cerr := held.Close()
	fmt.Printf("+%v close while unready: %v\n", time.Since(t0).Round(time.Millisecond), cerr)
	{
		file, err := os.OpenFile(f.join(0, "e"), os.O_RDWR, 0)
		fmt.Printf("+%v open while unready: %v\n", time.Since(t0).Round(time.Millisecond), err)
		if err == nil {
			_ = file.Close()
		}
		_, serr := os.Stat(f.join(0, "fresh-name"))
		fmt.Printf("+%v lookup while unready: %v\n", time.Since(t0).Round(time.Millisecond), serr)
	}
	<-corrected
	fmt.Printf("+%v before ready: revoked=%v fatal=%v sessionEnd=%v loss=%d\n", time.Since(t0).Round(time.Millisecond), c.m.isRevoked(), c.m.fatalError(), c.m.rpc.SessionEndCause(), c.m.delegations.LossSequence())
	time.Sleep(2 * time.Second)
	data, rerr := os.ReadFile(f.join(1, "e"))
	fmt.Printf("+%v after ready: revoked=%v sessionEnd=%v loss=%d peer=%q %v\n", time.Since(t0).Round(time.Millisecond), c.m.isRevoked(), c.m.rpc.SessionEndCause(), c.m.delegations.LossSequence(), data, rerr)
	if c.m.isRevoked() || c.m.delegations.LossSequence() != 0 || string(data) != "w" {
		t.Errorf("a %v readiness gap lost accepted data or revoked the mount", 3*time.Second)
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}
func TestOpusR2KernelClockDiag(t *testing.T) {
	opusKernelParent(t, opusKernelClockDiagChild)
}

// K5: cancelled sleep. The drain fails (here: its propagated deadline had
// already elapsed at receipt), the host's sleep is cancelled, and the
// generation reconciles with a fresh Recover while the old horizon is live.
func opusKernelCancelledSleepChild(t *testing.T) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v", 0644)
	serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	o, err := c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(-time.Millisecond))
	cancel()
	fmt.Printf("failed drain: cold=%v result=%v err=%v\n", o.ColdComplete, o.Result.Disposition, err)
	ctx, cancel = context.WithTimeout(t.Context(), 30*time.Second)
	o2, err2 := c.m.RecoverWorkspace(ctx, 1, serial)
	cancel()
	fmt.Printf("cancelled-sleep Recover (old horizon still live): prepared=%v result=%v err=%v\n", o2.Prepared, o2.Result.Disposition, err2)
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Second)
	o3, err3 := c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(8*time.Second))
	cancel()
	fmt.Printf("immediate retry Suspend with a fresh deadline: cold=%v err=%v\n", o3.ColdComplete, err3)
	if err2 != nil || !o2.Prepared || err3 != nil || !o3.ColdComplete {
		t.Fatalf("cancelled sleep stranded the incarnation: recover=%v retry=%v", err2, err3)
	}
	kernelStatAcrossColdRecovery(t, func() (os.FileInfo, error) { return os.Stat(f.join(0, "e")) }, 1, 0644, func() { c.recover(serial) })
	_, serr := os.Stat(f.join(0, "e"))
	fmt.Printf("mount0 stat=%v revoked=%v sessionEnd=%v fatal=%v\n", serr, c.m.isRevoked(), c.m.rpc.SessionEndCause(), c.m.fatalError())
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
func TestOpusR2KernelCancelledSleep(t *testing.T) {
	opusKernelParent(t, opusKernelCancelledSleepChild)
}
