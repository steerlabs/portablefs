//go:build linux

package fusev3

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type workspaceTestClockOwner struct {
	unavailable atomic.Bool
	refused     chan struct{}
	once        sync.Once
}

func (c *workspaceTestClockOwner) Wait(ctx context.Context, p mountenrollment.Permit) error {
	return c.Check(p)
}
func (c *workspaceTestClockOwner) Check(mountenrollment.Permit) error {
	if c.unavailable.Load() {
		if c.refused != nil {
			c.once.Do(func() { close(c.refused) })
		}
		return errors.New("clock not qualified")
	}
	return nil
}

// Start the gap at a real readiness refusal, before timing its correction.
func (c *workspaceTestClockOwner) restoreAfter(gap time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		<-c.refused
		time.Sleep(gap)
		c.unavailable.Store(false)
		close(done)
	}()
	return done
}

type coldTestRPC struct {
	RPC
	parked          atomic.Bool
	subscriptions   atomic.Uint64
	validations     atomic.Uint64
	deadline        time.Time
	outageUntil     time.Time
	validationError error
	releaseError    error
}

func (r *coldTestRPC) ParkDispatch(context.Context) error { r.parked.Store(true); return nil }
func (r *coldTestRPC) ResumeDispatch(check func() error) error {
	if err := check(); err != nil {
		return err
	}
	r.parked.Store(false)
	return nil
}
func (r *coldTestRPC) DispatchSnapshot() authorityrpc.DispatchSnapshot {
	return authorityrpc.DispatchSnapshot{Parked: r.parked.Load()}
}
func (r *coldTestRPC) AuthorizationDeadline() time.Time { return r.deadline }
func (r *coldTestRPC) CallRead(ctx context.Context, q *authoritypb.Request) (*authoritypb.Response, error) {
	if q.GetKeepAlive() != nil {
		r.validations.Add(1)
		if r.validationError != nil {
			return nil, r.validationError
		}
		if time.Now().Before(r.outageUntil) {
			return nil, &net.DNSError{Err: "transient DNS outage"}
		}
	}
	return r.RPC.CallRead(ctx, q)
}
func (r *coldTestRPC) Subscribe(context.Context, []byte, []byte) (*authoritypb.SubscribeReply, time.Time, error) {
	n := r.subscriptions.Add(1)
	return &authoritypb.SubscribeReply{Incarnation: 100 + n, Watermark: 1, SnapshotId: []byte{byte(n)}, HorizonNanos: uint64(time.Minute)}, continuous.Time().Add(time.Minute), nil
}
func coldFixture(t *testing.T) (*stockFixture, *workspaceadmission.Supervisor, *coldTestRPC) {
	t.Helper()
	f := newStockFixture(t)
	g := bindWorkspaceTestGate(t, f.mount)
	f.mount.workspaceLifecycle = &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	rpc := &coldTestRPC{RPC: f.rpc, deadline: time.Now().Add(2 * time.Minute)}
	f.mount.rpc.(*epochRPC).rpc = rpc

	return f, g, rpc
}
func TestWorkspaceLifecycleColdRecover(t *testing.T) {
	f, g, rpc := coldFixture(t)
	f.lookup(t, 1, "warm")
	serial := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
	if err != nil || !o.ColdComplete || !rpc.parked.Load() {
		t.Fatal("cold cut not proven", o, err)
	}
	for _, w := range o.Workers {
		if w.Disposition == "unresolved" {
			t.Fatal("cold acknowledged unresolved worker", w)
		}
	}
	old := o.SubscriptionIncarnation
	o, err = f.mount.RecoverWorkspace(t.Context(), 1, serial)
	if err != nil || !o.Prepared || rpc.validations.Load() != 1 || o.SubscriptionIncarnation == old {
		t.Fatal("fresh recovery not proven", o, err)
	}
	proof, err := g.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Prepared(proof); err != nil {
		t.Fatal(err)
	}
	if err = g.Open(1, serial); err != nil {
		t.Fatal(err)
	}
	if !f.mount.workspaceServing() {
		t.Fatal("prepared proof did not open")
	}
	if _, err = f.mount.PrepareWorkspace(t.Context(), 1, serial); err == nil {
		t.Fatal("Prepare reused after recovery")
	}
}
func TestWorkspaceLifecycleRetryBeyond45Seconds(t *testing.T) {
	for _, phase := range []string{"Prepare", "Recover"} {
		t.Run(phase, func(t *testing.T) {
			f, g, rpc := coldFixture(t)
			serial := g.Close(1)
			if phase == "Recover" {
				o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
				if err != nil || !o.ColdComplete {
					t.Fatal(o, err)
				}
			}
			rpc.outageUntil = time.Now().Add(46 * time.Second)
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			var o WorkspaceObservation
			var err error
			if phase == "Prepare" {
				o, err = f.mount.PrepareWorkspace(ctx, 1, serial)
			} else {
				o, err = f.mount.RecoverWorkspace(ctx, 1, serial)
			}
			if err != nil || !o.Prepared || rpc.validations.Load() < 2 || rpc.subscriptions.Load() != 1 {
				t.Fatal("transient outage ended or repeated logical preparation", o, err, rpc.validations.Load(), rpc.subscriptions.Load())
			}
		})
	}
}
func TestWorkspaceColdFailureRetainsLossAndNotificationOwner(t *testing.T) {
	for _, kind := range []string{"failed-notify", "blocked-notify", "persistence"} {
		t.Run(kind, func(t *testing.T) {
			f, g, _ := coldFixture(t)
			f.lookup(t, 1, "warm")
			w := f.mount.workspaceLifecycle
			report := writeback.DropReport{LossSequence: 7, Entries: 2, Bytes: 11, Reason: "accepted tail discarded"}
			w.recordDrop(report)
			w.recordDrop(report)
			var release chan struct{}
			switch kind {
			case "failed-notify":
				f.notify.entryST = fuse.EIO
			case "blocked-notify":
				release = make(chan struct{})
				f.notify.block = release
				defer close(release)
			case "expired-horizon":
				f.mount.subscription.mu.Lock()
				f.mount.subscription.cacheUntil = continuous.Time().Add(-time.Second)
				f.mount.subscription.mu.Unlock()
			case "persistence":
				w.persist = func(WorkspaceObservation) error { return syscall.ENOSPC }
			}
			serial := g.Close(1)
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			o, err := f.mount.SuspendWorkspace(ctx, 1, serial, continuous.Time().Add(time.Second))
			if err == nil || o.ColdComplete || len(o.Loss) != 1 || o.Loss[0].AcceptedBytes != 11 {
				t.Fatal("failed cold cut erased loss or acknowledged", o, err)
			}
			if release != nil {
				if w.withdrawal == nil {
					t.Fatal("blocked notification lost owner")
				}
				select {
				case <-w.withdrawal.done:
					t.Fatal("wait cancellation fabricated completion")
				default:
				}
			}
		})
	}
}
func TestWorkspaceLifecycleCancellationKeepsPhysicalOwner(t *testing.T) {
	f, g, _ := coldFixture(t)
	u := f.unique.Add(2)
	entry, st := f.mount.workspaceFS().beginWorkspaceEntry(u)
	if st != fuse.OK {
		t.Fatal(st)
	}
	f.mount.workspaceFS().finishWorkspaceEntry(u, entry)
	serial := g.Close(1)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	o, err := f.mount.SuspendWorkspace(ctx, 1, serial, continuous.Time().Add(time.Second))
	if !errors.Is(err, context.DeadlineExceeded) || o.ColdComplete {
		t.Fatal(o, err)
	}
	f.raw.mu.RLock()
	p := f.raw.replyPublications[u]
	f.raw.mu.RUnlock()
	if p == nil {
		t.Fatal("waiter cancellation erased physical reply")
	}
	f.raw.PrepareReplyPayload(u, 1, 20, nil, nil, 0)
	f.raw.ReplyWritten(u, fuse.EIO)
}
func TestWorkspaceClosedFlushReobservesResetLoss(t *testing.T) {
	f, g, _ := coldFixture(t)
	e := f.lookup(t, 1, "file")
	opened := openDelegatedWriter(t, f, e.NodeId)
	writeDelegated(t, f, e.NodeId, opened.Fh, 0, []byte("accepted"))
	f.raw.mu.RLock()
	h := f.raw.handles[opened.Fh].file
	f.raw.mu.RUnlock()
	g.Close(1)
	f.mount.workspaceLifecycle.afterFlushLoss = func(flushed *fileHandle) {
		if flushed == h {
			f.mount.delegations.FenceSubscription("reset after first loss observation")
		}
	}
	if got := h.node.Flush(t.Context(), h, 0); got != syscall.EIO {
		t.Fatal("closed FLUSH hid reset loss", got)
	}
	if cut := h.acceptedCut.Load(); cut != nil {
		cut.mu.Lock()
		defer cut.mu.Unlock()
		if cut.buffer != nil {
			t.Fatal("retired resolved description retained old buffer")
		}
	}
}

func TestWorkspaceOvertakenColdRetainsLoss(t *testing.T) {
	f, g, _ := coldFixture(t)
	f.mount.workspaceLifecycle.recordDrop(writeback.DropReport{LossSequence: 9, Entries: 3, Bytes: 17, Reason: "known old loss"})
	f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
		if o.ColdComplete {
			g.Close(1)
		}
		return nil
	}
	serial := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
	if err == nil || o.ColdComplete || len(o.Loss) != 1 || o.Loss[0].AcceptedBytes != 17 {
		t.Fatal("overtaken cold proof erased outcome", o, err)
	}
	if !f.mount.workspaceLifecycle.cold {
		t.Fatal("publication refusal erased the completed physical cut")
	}
}
func TestWorkspaceRecoveryClassifiesTerminalEvidence(t *testing.T) {
	for _, phase := range []string{"Prepare", "Recover"} {
		for _, cause := range []error{authorityrpc.ErrSessionEnded, authorityrpc.ErrAuthorityChanged, mountenrollment.ErrDefinitiveDenial} {
			t.Run(phase+cause.Error(), func(t *testing.T) {
				f, g, rpc := coldFixture(t)
				serial := g.Close(1)
				if phase == "Recover" {
					if _, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
				}
				rpc.validationError = cause
				var o WorkspaceObservation
				var err error
				if phase == "Prepare" {
					o, err = f.mount.PrepareWorkspace(t.Context(), 1, serial)
				} else {
					o, err = f.mount.RecoverWorkspace(t.Context(), 1, serial)
				}
				if !errors.Is(err, cause) || o.Prepared || rpc.validations.Load() != 1 || rpc.subscriptions.Load() != 0 {
					t.Fatal("terminal evidence retried or became ready", o, err, rpc.validations.Load())
				}
			})
		}
	}
}

func TestWorkspacePersistenceCannotPublishStaleClock(t *testing.T) {
	f, g, rpc := coldFixture(t)
	serial := g.Close(1)
	clock := f.mount.workspaceLifecycle.clock.(*workspaceTestClockOwner)
	refused := make(chan struct{})
	var once atomic.Bool
	f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
		if o.Prepared && once.CompareAndSwap(false, true) {
			clock.unavailable.Store(true)
		}
		if !o.Prepared && once.Load() {
			select {
			case <-refused:
			default:
				close(refused)
			}
		}
		return nil
	}
	done := make(chan WorkspaceObservation, 1)
	go func() { o, _ := f.mount.PrepareWorkspace(t.Context(), 1, serial); done <- o }()
	<-refused
	if f.mount.WorkspaceObservation().Prepared {
		t.Fatal("persistence outlived clock proof")
	}
	select {
	case o := <-done:
		t.Fatal("clock unreadiness ended logical Prepare", o)
	default:
	}
	clock.unavailable.Store(false)
	select {
	case o := <-done:
		if !o.Prepared || o.Result.Disposition != authorityrpc.LifecycleCompleted || rpc.subscriptions.Load() < 2 {
			t.Fatal(o)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("original Prepare did not finish after clock correction")
	}
}

func (r *coldTestRPC) CallIdempotent(ctx context.Context, q *authoritypb.Request) (*authoritypb.Response, error) {
	if q.GetDelegationRelease() != nil {
		if r.releaseError != nil {
			return nil, r.releaseError
		}
		return &authoritypb.Response{Body: &authoritypb.Response_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseReply{}}}, nil
	}
	return r.RPC.CallIdempotent(ctx, q)
}
func TestWorkspaceFailedReleaseRetainsDurabilityOutcome(t *testing.T) {
	f, g, rpc := coldFixture(t)
	e := f.lookup(t, 1, "file")
	opened := openDelegatedWriter(t, f, e.NodeId)
	writeDelegated(t, f, e.NodeId, opened.Fh, 0, []byte("accepted"))
	rpc.releaseError = authorityrpc.ErrTransportUncertain
	serial := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
	if err == nil || o.ColdComplete || o.Outcome.Durability != "durable" || o.Outcome.Release != "abandoned" || o.Outcome.Observation != "observed" {
		t.Fatal("failed release erased known durability or fabricated release", o, err)
	}
}

func TestWorkspaceLifecycleDrainsAcceptedDirtyCut(t *testing.T) {
	f, g, _ := coldFixture(t)
	e := f.lookup(t, 1, "file")
	opened := openDelegatedWriter(t, f, e.NodeId)
	writeDelegated(t, f, e.NodeId, opened.Fh, 0, []byte("accepted before Close"))
	old := f.mount.delegations.buf
	serial := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
	if err != nil || !o.ColdComplete || o.Outcome.Durability != "durable" || o.Outcome.Release != "released" || old.Stats().Entries != 0 {
		t.Fatal("captured dirty cut failed to settle", o, err, old.Stats())
	}
	f.rpc.mu.Lock()
	applied := f.rpc.applied
	f.rpc.mu.Unlock()
	if applied == 0 {
		t.Fatal("accepted write was never applied")
	}
}
