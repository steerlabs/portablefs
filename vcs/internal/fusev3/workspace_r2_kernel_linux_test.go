//go:build linux

package fusev3

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"golang.org/x/sys/unix"
)

// RELEASE adds real descriptor cleanup after cold acknowledgment. Recovery
// settles it while publication is held; the next park must observe its removal.
func r2KernelReparkEvidenceChild(t *testing.T) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	var hold atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	var persisted WorkspaceObservation
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(o WorkspaceObservation) error {
		persisted = o
		if o.Prepared && hold.CompareAndSwap(true, false) {
			close(entered)
			<-release
		}
		return nil
	}}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "held"), "v", 0644)
	held, err := os.Open(f.join(0, "held"))
	if err != nil {
		t.Fatal(err)
	}
	pending := func() int { m := c.m.delegations; m.closeMu.Lock(); defer m.closeMu.Unlock(); return m.closePending }
	waitUntil(t, 3*time.Second, "initial close cleanup", func() bool { return pending() == 0 })
	serial := c.suspend()
	if persisted.Outcome.CleanupDebt != 0 {
		t.Fatal("unexpected initial cleanup debt", persisted.Outcome)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 3*time.Second, "cold RELEASE cleanup owner", func() bool { return pending() == 1 })
	o, err := c.m.SuspendWorkspace(t.Context(), 1, serial, c.now().Add(-time.Second))
	if err != nil || !o.ColdComplete || o.Outcome.CleanupDebt < 1 || persisted.Outcome.CleanupDebt != o.Outcome.CleanupDebt {
		t.Fatal("re-ack lost real RELEASE debt", o, err, persisted.Outcome)
	}
	ctx, owner := authorityrpc.WithLifecycleOwner(t.Context())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hold.Store(true)
	recovered := make(chan WorkspaceObservation, 1)
	go func() { o, _ := c.m.RecoverWorkspace(ctx, 1, serial); recovered <- o }()
	<-entered
	waitUntil(t, 3*time.Second, "retained CLOSE settlement during recovery", func() bool { return pending() == 0 && c.m.reclaim.debt() == 0 })
	next, _ := strconv.ParseUint(c.req("close"), 10, 64)
	owner.Overtake()
	cancel()
	close(release)
	if o := <-recovered; o.Prepared || o.Result.Disposition != authorityrpc.LifecycleOvertaken {
		t.Fatal("publication ignored newer Close", o.Result)
	}
	o, err = c.m.SuspendWorkspace(t.Context(), 1, next, c.now().Add(-time.Second))
	if err != nil || !o.ColdComplete || o.Outcome.CleanupDebt != 0 || persisted.Outcome.CleanupDebt != 0 {
		t.Fatal("re-park retained settled CLOSE debt", o, err, persisted.Outcome)
	}
	for _, request := range o.ParkedRequests {
		if len(request.Body) == 0 || request.Applying {
			t.Fatal("invalid parked request evidence", request)
		}
	}
	c.m.subscription.mu.RLock()
	active, proofPresent := c.m.subscription.active, c.m.subscription.workspaceProof != nil
	c.m.subscription.mu.RUnlock()
	c.m.delegations.epoch.RLock()
	writeback := c.m.delegations.writebackStarted
	c.m.delegations.epoch.RUnlock()
	if active || proofPresent || writeback {
		t.Fatal("re-park retained cache ownership", active, proofPresent, writeback)
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("owner EOF stranded connection")
	}
}

func TestWorkspaceKernelReparkResnapshotsRealCleanup(t *testing.T) {
	opusKernelParent(t, r2KernelReparkEvidenceChild)
}

// A Recover owner outlives the per-request timeout while clock readiness is
// unavailable. Kernel, TLS, authority grants and request clocks all advance;
// fresh frontend operations refuse until root republishes admission.
func r2KernelReadinessBudgetChild(t *testing.T, budget time.Duration) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	ready := &workspaceTestClockOwner{refused: make(chan struct{})}
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: ready, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{
		Mounts: 1, RequestTimeout: budget, SessionLease: 2 * time.Minute,
		workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true,
		workspaceLifecycle: life, workspaceDispatch: true,
	})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "close"), "v0", 0644)
	c.write(f.join(0, "sync"), "g0", 0644)
	c.recover(c.suspend())
	held := mustOpenFile(t, f.join(0, "close"), os.O_RDWR, 0)
	other := mustOpenFile(t, f.join(0, "sync"), os.O_RDWR, 0)
	for file, data := range map[*os.File]string{held: "w1", other: "g1"} {
		if _, err := unix.Pwrite(int(file.Fd()), []byte(data), 0); err != nil {
			t.Fatal(err)
		}
	}
	serial := c.suspend()
	session := string(c.m.rpc.SessionID())
	ready.unavailable.Store(true)
	completed := make(chan struct{})
	go func() { defer close(completed); c.recover(serial) }()
	select {
	case <-ready.refused:
	case <-time.After(5 * time.Second):
		t.Fatal("no recovery readiness refusal")
	}
	time.Sleep(budget + time.Second)
	select {
	case <-completed:
		t.Fatal("Recover spent a request timeout before clock admission")
	default:
	}
	if _, err := reader.Check(); err == nil {
		t.Fatal("root admission opened during invalid clock proof")
	}
	if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil || c.m.delegations.LossSequence() != 0 || string(c.m.rpc.SessionID()) != session {
		t.Fatal("readiness wait lost accepted data or session ownership", c.m.fatalError())
	}
	ready.unavailable.Store(false)
	select {
	case <-completed:
	case <-time.After(10 * time.Second):
		t.Fatal("Recover did not settle after clock readiness")
	}
	if err := other.Sync(); err != nil {
		t.Fatal("old handle fsync after recovery", err)
	}
	if err := held.Close(); err != nil {
		t.Fatal("old handle close after recovery", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "exact cleanup settlement", func() bool {
		c.m.delegations.closeMu.Lock()
		defer c.m.delegations.closeMu.Unlock()
		return c.m.delegations.closePending == 0
	})
	for name, want := range map[string]string{"close": "w1", "sync": "g1"} {
		data, err := os.ReadFile(filepath.Join(f.volumeRoot, name))
		if err != nil || string(data) != want {
			t.Fatalf("authority %s=%q, want %q: %v", name, data, want, err)
		}
	}
	if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil || c.m.delegations.LossSequence() != 0 {
		t.Fatal("readiness correction lost data or ownership", c.m.fatalError())
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("owner EOF stranded connection")
	}
}

func TestWorkspaceKernelReadinessBudget10Seconds(t *testing.T) {
	opusKernelParent(t, func(t *testing.T) { r2KernelReadinessBudgetChild(t, 10*time.Second) })
}

func TestWorkspaceKernelReadinessBudget45Seconds(t *testing.T) {
	opusKernelParent(t, func(t *testing.T) { r2KernelReadinessBudgetChild(t, 45*time.Second) })
}
