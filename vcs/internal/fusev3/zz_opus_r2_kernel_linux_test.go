//go:build linux

package fusev3

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// K1: a readiness gap longer than every bounded attempt (request timeout,
// subscription TTL, KeepAlive interval) while dirty data and cleanup are owned.
func opusKernelLongClockUnreadyChild(t *testing.T) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	clock := &workspaceTestClockOwner{}
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: clock, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v", 0644)
	c.write(f.join(0, "g"), "g0", 0644)
	c.recover(c.suspend())
	held, err := os.OpenFile(f.join(0, "e"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Write([]byte("w1")); err != nil {
		t.Fatal(err)
	}
	other, err := os.OpenFile(f.join(0, "g"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Pwrite(int(other.Fd()), []byte("g1"), 0); err != nil {
		t.Fatal(err)
	}
	goroutines0 := runtime.NumGoroutine()
	clock.unavailable.Store(true)
	begin := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- held.Close() }()
	synced := make(chan error, 1)
	go func() { synced <- other.Sync() }()
	gap := 45 * time.Second
	ticker := time.NewTicker(5 * time.Second)
	for time.Since(begin) < gap {
		<-ticker.C
		fmt.Printf("unready +%v: revoked=%v fatal=%v sessionEnd=%v loss=%d goroutines=%d\n", time.Since(begin).Round(time.Second), c.m.isRevoked(), c.m.fatalError(), c.m.rpc.SessionEndCause(), c.m.delegations.LossSequence(), runtime.NumGoroutine())
	}
	ticker.Stop()
	clock.unavailable.Store(false)
	fmt.Printf("clock ready after %v (goroutines %d -> %d)\n", time.Since(begin).Round(time.Second), goroutines0, runtime.NumGoroutine())
	for name, ch := range map[string]chan error{"close": closed, "fsync": synced} {
		select {
		case err := <-ch:
			fmt.Printf("%s settled after %v: %v\n", name, time.Since(begin).Round(100*time.Millisecond), err)
			if err != nil {
				c.fail("%s returned %v across a readiness gap", name, err)
			}
		case <-time.After(30 * time.Second):
			c.fail("%s did not settle 30s after readiness returned", name)
		}
	}
	_ = other.Close()
	time.Sleep(2 * time.Second)
	data, err := os.ReadFile(f.join(1, "e"))
	gdata, gerr := os.ReadFile(f.join(1, "g"))
	_, serr := os.Stat(f.join(0, "e"))
	fresh := f.join(0, "fresh")
	werr := os.WriteFile(fresh, []byte("z"), 0644)
	fmt.Printf("after gap: peer e=%q %v g=%q %v; m0 stat=%v write=%v revoked=%v sessionEnd=%v loss=%d\n", data, err, gdata, gerr, serr, werr, c.m.isRevoked(), c.m.rpc.SessionEndCause(), c.m.delegations.LossSequence())
	if string(data) != "w1" || string(gdata) != "g1" || c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil || c.m.delegations.LossSequence() != 0 {
		c.fail("readiness gap lost accepted data or terminated the mount")
	}
	if serr != nil || werr != nil {
		c.fail("serving did not resume after readiness returned: stat=%v write=%v", serr, werr)
	}
	// Cold transition still works afterwards.
	c.recover(c.suspend())
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
func TestOpusR2KernelLongClockUnready(t *testing.T) {
	opusKernelParent(t, opusKernelLongClockUnreadyChild)
}

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
	_, perr := unix.Pread(int(held.Fd()), make([]byte, 4), 0)
	data, rerr := os.ReadFile(f.join(1, "e"))
	fmt.Printf("held fd pread=%v; peer sees %q %v; revoked=%v sessionEnd=%v\n", perr, data, rerr, c.m.isRevoked(), c.m.rpc.SessionEndCause())
	if !o.ColdComplete || !o2.Prepared {
		c.fail("incomplete Suspend stranded the incarnation: suspend=%v recover=%v (result %v)", err, err2, o2.Result.Disposition)
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
	variant := os.Getenv("OPUS_CLOCK_VARIANT")
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
	if variant != "close-only" {
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
		t.Errorf("FINDING (%s): a %v readiness gap lost accepted data or revoked the mount", variant, 3*time.Second)
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
	_, serr := os.Stat(f.join(0, "e"))
	fmt.Printf("mount0 stat=%v revoked=%v sessionEnd=%v fatal=%v\n", serr, c.m.isRevoked(), c.m.rpc.SessionEndCause(), c.m.fatalError())
	if err2 != nil || !o2.Prepared || err3 != nil || !o3.ColdComplete {
		c.fail("cancelled sleep stranded the incarnation: recover=%v retry=%v", err2, err3)
	}
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
