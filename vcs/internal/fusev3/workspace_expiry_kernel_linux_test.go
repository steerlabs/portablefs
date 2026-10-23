//go:build linux

package fusev3

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Both expiry cases retain known accepted records before the real clock gap.
// Visible authority bytes never decide whether the forfeited cut was durable.
func TestOpusR3KernelLongGapAccounted(t *testing.T) {
	opusKernelParent(t, func(t *testing.T) { workspaceHeldCutChild(t, "expiry") })
}
func TestWorkspaceKernelUnassignedWriteColdCut(t *testing.T) {
	opusKernelParent(t, func(t *testing.T) { workspaceHeldCutChild(t, "unassigned") })
}
func TestWorkspaceKernelAssignedWriteColdCut(t *testing.T) {
	opusKernelParent(t, func(t *testing.T) { workspaceHeldCutChild(t, "assigned") })
}

// Hold accepted delegated data before the real transport can assign a request.
// Clock readiness changes only after the kernel's Write has been acknowledged.
func workspaceHoldBeforeAssignment(t *testing.T, f *integrationFixture) (<-chan struct{}, func()) {
	t.Helper()
	entered, released := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(released) }) }
	transport := f.transports[0]
	transport.hookMu.Lock()
	transport.beforeDelegatedMutation = func(ctx context.Context, q *authoritypb.Request) error {
		if w := q.GetWrite(); w != nil && w.GetDelegation() != nil {
			enteredOnce.Do(func() { close(entered) })
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-released:
			}
		}
		return nil
	}
	transport.hookMu.Unlock()
	t.Cleanup(func() {
		release()
		transport.hookMu.Lock()
		transport.beforeDelegatedMutation = nil
		transport.hookMu.Unlock()
	})
	return entered, release
}

func workspaceHeldCutChild(t *testing.T, mode string) {
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
	c.write(f.join(0, "g"), "g0", 0644)
	c.recover(c.suspend())
	root, err := os.Open(f.mountPath(0))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	names := []string{"e", "g"}
	if mode != "expiry" {
		names = names[:1]
	}
	var files []*os.File
	for _, name := range names {
		file, err := os.OpenFile(f.join(0, name), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		// Establish the grant before readiness is lost; the next write is local.
		if _, err = file.WriteAt([]byte("v0"), 0); err != nil {
			t.Fatal(err)
		}
		if err = file.Sync(); err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
		defer file.Close()
	}
	session := bytes.Clone(c.m.rpc.SessionID())
	incarnation := c.m.subscription.stamp().incarnation
	loss0 := c.m.delegations.LossSequence()
	var reportsMu sync.Mutex
	var reports []writeback.DropReport
	c.m.delegations.SetDropReporter(func(r writeback.DropReport) {
		life.recordDrop(r)
		reportsMu.Lock()
		reports = append(reports, r)
		reportsMu.Unlock()
	})
	ordinals := map[*delegationState]uint64{}
	c.m.delegations.mu.RLock()
	for _, s := range c.m.delegations.byID {
		s.meta.Lock()
		ordinals[s] = s.flushOrdinal
		s.meta.Unlock()
	}
	c.m.delegations.mu.RUnlock()
	expirations := f.coherence.Stats().SubscriptionExpirations
	beforeWrites := f.counter.count("write")
	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var unassigned <-chan struct{}
	var admit func()
	if mode == "assigned" {
		f.counter.setBeforeHandle(func(q *authoritypb.Request) {
			if q.GetWrite() != nil && q.GetWrite().GetFlushSequence() != 0 {
				once.Do(func() { close(entered); <-release })
			}
		})
		defer f.counter.setBeforeHandle(nil)
	} else {
		unassigned, admit = workspaceHoldBeforeAssignment(t, f)
	}
	for _, file := range files {
		if _, err := file.WriteAt([]byte("w1"), 0); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "assigned" {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("assigned background WRITE did not reach authority")
		}
	} else {
		select {
		case <-unassigned:
		case <-time.After(5 * time.Second):
			t.Fatal("accepted WRITE did not reach pre-assignment hold")
		}
		clock.unavailable.Store(true)
		admit()
		waitUntil(t, 5*time.Second, "background WRITE at pre-assignment readiness fence", func() bool { return f.clients[0].DispatchSnapshot().WaitingApplying > 0 })
		if f.counter.count("write") != beforeWrites {
			t.Fatal("unassigned WRITE crossed transport")
		}
		if len(workspaceApplyingOwners(f.clients[0].DispatchSnapshot())) != 0 {
			t.Fatal("unassigned work acquired an owner")
		}
		c.m.delegations.mu.RLock()
		for _, s := range c.m.delegations.byID {
			s.meta.Lock()
			if s.flushOrdinal != ordinals[s] {
				t.Errorf("unassigned cut consumed ordinal %d", s.flushOrdinal)
			}
			s.meta.Unlock()
		}
		c.m.delegations.mu.RUnlock()
	}
	stats := c.m.delegations.buf.Stats()
	if stats.Entries != len(files) || stats.Bytes != int64(2*len(files)) {
		t.Fatal("cut was not retained exactly", stats)
	}
	if mode == "expiry" {
		// Neither side's elapsed clock is frozen. The session/auth lease remains two
		// minutes; the real subscription and grant have only ten seconds.
		waitUntil(t, 12*time.Second, "authority expires the real subscription", func() bool { f.coherence.Sweep(); return f.coherence.Stats().SubscriptionExpirations > expirations })
		_, _, _, live := c.m.subscription.currentIncarnation()
		if live {
			t.Fatal("expired subscription still live")
		}
		if c.m.WorkspaceObservation().State != WorkspaceRecoveryRequired {
			t.Fatal("supervisor cannot observe lost serving", c.m.WorkspaceObservation())
		}
		if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil || c.m.fatalError() != nil {
			t.Fatal("grant expiry terminalized valid session", c.m.rpc.SessionEndCause(), c.m.fatalError())
		}
	}
	serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	type cutResult struct {
		o   WorkspaceObservation
		err error
	}
	done := make(chan cutResult, 1)
	var assigned authorityrpc.DispatchSnapshot
	if mode == "assigned" {
		assigned = f.clients[0].DispatchSnapshot()
		assigned.Owners = workspaceApplyingOwners(assigned)
		if len(assigned.Owners) != 1 || !assigned.Owners[0].Applying {
			t.Fatal("missing applying owner", assigned)
		}
	}
	go func() {
		o, err := c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(-time.Millisecond))
		done <- cutResult{o, err}
	}()
	if mode == "assigned" {
		select {
		case r := <-done:
			t.Fatal("cold cut escaped applying owner", r)
		case <-time.After(100 * time.Millisecond):
		}
		during := f.clients[0].DispatchSnapshot()
		during.Owners = workspaceApplyingOwners(during)
		if len(during.Owners) != 1 || during.Owners[0].Identity != assigned.Owners[0].Identity || !bytes.Equal(during.Owners[0].Body, assigned.Owners[0].Body) {
			t.Fatal("assigned identity/body changed", during)
		}
		releaseOnce.Do(func() { close(release) })
	}
	var result cutResult
	select {
	case result = <-done:
	case <-ctx.Done():
		t.Fatal("cold cut deadlocked pre-assignment worker", ctx.Err())
	}
	if result.err != nil || !result.o.ColdComplete {
		t.Fatal("cold cut incomplete", result.o, result.err)
	}
	if mode == "assigned" && f.counter.count("write") != beforeWrites+1 {
		t.Fatal("assigned WRITE was resubmitted")
	}
	wantEntries := uint64(len(files))
	var entries, totalBytes uint64
	for i, l := range result.o.Loss {
		if l.Sequence != loss0+uint64(i)+1 {
			t.Fatal("loss sequence is not exact/monotonic", result.o.Loss)
		}
		entries += l.AcceptedEntries
		totalBytes += l.AcceptedBytes
	}
	if entries != wantEntries || totalBytes != 2*wantEntries || c.m.delegations.LossSequence() != loss0+wantEntries {
		t.Fatal("held cut loss was not accounted exactly once", result.o.Loss, entries, totalBytes, c.m.delegations.LossSequence())
	}
	reportsMu.Lock()
	if len(reports) != len(files) {
		t.Error("identity report count", reports)
	}
	ids := map[writeback.Identity]bool{}
	for _, r := range reports {
		if ids[r.Identity] || r.Entries != 1 || r.Bytes != 2 {
			t.Error("identity cut not exact", r)
		}
		ids[r.Identity] = true
	}
	reportsMu.Unlock()
	clock.unavailable.Store(false)
	c.recover(serial) // real Recover, persisted preparation and root Open
	if !bytes.Equal(session, c.m.rpc.SessionID()) || c.m.subscription.stamp().incarnation <= incarnation {
		t.Fatal("cold recovery did not preserve session/change subscription")
	}
	c.write(f.join(0, "fresh"), "durable", 0644)
	if data, err := os.ReadFile(filepath.Join(f.volumeRoot, "fresh")); err != nil || string(data) != "durable" {
		t.Fatal("fresh service not durable", string(data), err)
	}
	freshRoot, err := os.Open(f.mountPath(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := freshRoot.Sync(); err != nil {
		t.Fatal("new root inherited old run loss", err)
	}
	freshRoot.Close()
	for i, file := range files {
		if i%2 == 0 {
			if err := file.Sync(); !errors.Is(err, syscall.EIO) {
				t.Error("old fsync lost its ticket", err)
			}
			// The per-description error cursor consumed this ticket at fsync.
			if err := file.Close(); err != nil {
				t.Error("consumed loss repeated at close", err)
			}
		} else if err := file.Close(); !errors.Is(err, syscall.EIO) {
			t.Error("unobserved old FLUSH/close lost its ticket", err)
		}
	}
	if err := root.Sync(); !errors.Is(err, syscall.EIO) {
		t.Error("pre-run root barrier lost its ticket", err)
	}
	if c.m.delegations.LossSequence() != loss0+wantEntries || len(c.m.WorkspaceObservation().Loss) != len(result.o.Loss) {
		t.Fatal("publication changed cumulative loss")
	}
	if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil {
		t.Fatal("recovery terminalized session")
	}
	fmt.Printf("controlled %s: loss=%v entries=%d bytes=%d same-session=true fresh-service=true old-file-and-root=EIO\n", mode, result.o.Loss, entries, totalBytes)
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

func workspaceApplyingOwners(s authorityrpc.DispatchSnapshot) (owners []authorityrpc.DispatchOwner) {
	for _, o := range s.Owners {
		if o.Applying {
			owners = append(owners, o)
		}
	}
	return
}
