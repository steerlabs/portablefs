//go:build linux

package fusev3

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
	"google.golang.org/protobuf/proto"
)

type workspaceHeldKeepAlive struct {
	*coldTestRPC
	entered chan struct{}
	once    sync.Once
}

func (r *workspaceHeldKeepAlive) CallRead(ctx context.Context, q *authoritypb.Request) (*authoritypb.Response, error) {
	if q.GetKeepAlive() != nil {
		r.once.Do(func() { close(r.entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.coldTestRPC.CallRead(ctx, q)
}
func TestWorkspaceKeepAliveParkJoinsDisposition(t *testing.T) {
	f, g, rpc := coldFixture(t)
	r := &workspaceHeldKeepAlive{coldTestRPC: rpc, entered: make(chan struct{})}
	f.mount.rpc.(*epochRPC).rpc = r
	returned, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.mount.workspaceLifecycle.keepalive.beforeDisposition = func() { once.Do(func() { close(returned) }); <-release }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.mount.wg.Add(1)
	go f.mount.keepAlive(ctx, 30*time.Millisecond)
	<-r.entered
	serial := g.Close(1)
	done := make(chan WorkspaceObservation, 1)
	go func() {
		o, _ := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
		done <- o
	}()
	<-returned
	select {
	case <-done:
		t.Fatal("cold acknowledged before KeepAlive disposition")
	case <-time.After(20 * time.Millisecond):
	}
	if f.mount.isRevoked() {
		t.Fatal("park cancellation revoked the mount")
	}
	close(release)
	select {
	case o := <-done:
		if !o.ColdComplete {
			t.Fatal(o)
		}
	case <-time.After(time.Second):
		t.Fatal("cold did not join KeepAlive")
	}
	cancel()
	f.mount.wg.Wait()
	if f.mount.isRevoked() || f.mount.rpc.SessionEndCause() != nil {
		t.Fatal("late KeepAlive revoked acknowledged cold mount")
	}
}

func TestWorkspaceControlHandoffHasNoPermissionGap(t *testing.T) {
	f, g, _ := coldFixture(t)
	s := f.mount.subscription
	timers := make(chan *subscriptionTestTimer, 16)
	clock := &subscriptionTestClock{now: continuous.Time(), timers: timers}
	rpc := &workspaceRunnerRPC{subscriptionTestRPC: &subscriptionTestRPC{horizon: clock.Now().Add(time.Minute)}, events: make(chan *authoritypb.ControlEvent), polled: make(chan struct{}), renewEntered: make(chan struct{}), renewRelease: make(chan struct{})}
	s.rpc = rpc
	s.config.clock = clock
	s.mu.Lock()
	s.horizon = rpc.horizon
	s.cacheUntil = rpc.horizon
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	serving := make(chan error, 1)
	go func() { serving <- s.serveIncarnation(ctx) }()
	<-rpc.polled
	for {
		timer := <-timers
		if timer.duration == volumeserver.SubscriptionRenewInterval {
			timer.fired <- clock.Now()
			break
		}
	}
	<-rpc.renewEntered
	// Hold KeepAlive as well; both joins must keep the captured CONTROL proof.
	_, finish, ok := f.mount.workspaceLifecycle.keepalive.start(t.Context())
	if !ok {
		t.Fatal("no KeepAlive owner")
	}
	serial := g.Close(1)
	if _, _, _, live := s.currentIncarnation(); !live {
		t.Fatal("Close revoked old CONTROL before takeover")
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, clock.Now().Add(5*time.Second))
		done <- err
	}()
	var captured *workspaceDrainPermit
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		s.mu.RLock()
		captured = s.workspaceDrain
		s.mu.RUnlock()
		if captured != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if captured == nil {
		t.Fatal("handoff not captured before join")
	}
	oldDeadline := captured.deadline
	check := func() {
		sample, stop := context.WithCancel(t.Context())
		stop()
		if err := s.horizonLoop(sample, s.incarnation); !errors.Is(err, context.Canceled) {
			t.Fatal("horizon worker lost old CONTROL during join", err)
		}
	}
	check()
	close(rpc.renewRelease)
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		a := &f.mount.workspaceLifecycle.keepalive
		a.mu.Lock()
		parked := a.parked
		a.mu.Unlock()
		if parked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	check()
	if !s.workspaceDrain.deadline.Equal(oldDeadline) {
		t.Fatal("handoff extended old horizon")
	}
	finish(func(bool) {})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-serving
}

func TestWorkspacePersistenceRetryKeepsPhysicalColdCut(t *testing.T) {
	f, g, _ := coldFixture(t)
	var calls int
	var persisted WorkspaceObservation
	f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
		calls++
		if calls == 1 {
			return errors.New("temporary persistence failure")
		}
		persisted = o
		return nil
	}
	serial := g.Close(1)
	if o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second)); err == nil || o.ColdComplete {
		t.Fatal(o, err)
	}
	f.mount.subscription.mu.Lock()
	f.mount.subscription.cacheUntil = continuous.Time().Add(-time.Second)
	f.mount.subscription.mu.Unlock()
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
	if err != nil || !o.ColdComplete || !persisted.ColdComplete {
		t.Fatal("retry required an expired old horizon", o, err)
	}
}

func TestWorkspacePersistenceRecordsPublicationRefusal(t *testing.T) {
	for _, phase := range []string{"cold", "prepared"} {
		t.Run(phase, func(t *testing.T) {
			f, g, _ := coldFixture(t)
			serial := g.Close(1)
			var persisted WorkspaceObservation
			f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
				persisted = o
				if o.ColdComplete || o.Prepared {
					g.Close(1)
				}
				return nil
			}
			var o WorkspaceObservation
			var err error
			if phase == "cold" {
				o, err = f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
			} else {
				o, err = f.mount.PrepareWorkspace(t.Context(), 1, serial)
			}
			if err == nil || o.Prepared || o.ColdComplete || persisted.Prepared || persisted.ColdComplete || persisted.Result.Disposition != o.Result.Disposition {
				t.Fatal("durable record disagrees with refusal", o, persisted, err)
			}
		})
	}
}

func TestWorkspaceRetainedSizeAndAttributesBeforeReset(t *testing.T) {
	m := newDelegationTestManager(t, &delegationFakeRPC{})
	id := installDelegationForTest(t, m, 31, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("accepted"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetAttr(t.Context(), id, writeback.Attributes{HasSize: true, Size: 3, HasMode: true, Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	m.InterruptSubscription()
	if size, err := m.Size(id, 99); err != nil || size != 3 {
		t.Fatal("interruption hid retained truncation", size, err)
	}
	attrs, err := m.OverlayAttributes(id, writeback.Attributes{HasSize: true, Size: 99, HasMode: true, Mode: 0644})
	if err != nil || attrs.Size != 3 || attrs.Mode != 0600 {
		t.Fatal("interruption hid retained attributes", attrs, err)
	}
	m.FenceSubscription("test reset boundary")
	if size, err := m.Size(id, 99); err != nil || size != 99 {
		t.Fatal("reset retained old logical size", size, err)
	}
	attrs, err = m.OverlayAttributes(id, writeback.Attributes{HasSize: true, Size: 99, HasMode: true, Mode: 0644})
	if err != nil || attrs.Size != 99 || attrs.Mode != 0644 || m.LossSequence() == 0 {
		t.Fatal("reset/loss boundary not reflected", attrs, err)
	}
}

func TestWorkspaceColdPOSIXFlushIsPrompt(t *testing.T) {
	f, g, _ := coldFixture(t)
	entry := f.lookup(t, 1, "locked")
	opened := openDelegatedWriter(t, f, entry.NodeId)
	f.raw.mu.RLock()
	h := f.raw.handles[opened.Fh].file
	f.raw.mu.RUnlock()
	owner := uint64(77)
	key := h.node.posixLockKey(owner)
	// A tracked owner is sufficient: this test verifies dispatch admission, not
	// lock-manager exclusion (the kernel suite exercises real lock acquisition).
	f.mount.notePOSIXLock(key)
	serial := g.Close(1)
	if o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second)); err != nil || !o.ColdComplete {
		t.Fatal(o, err)
	}
	start := time.Now()
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Flush(nil, &fuse.FlushIn{InHeader: fuse.InHeader{Unique: unique}, Fh: opened.Fh, LockOwner: owner})
	})
	if status != fuse.Status(syscall.EAGAIN) || time.Since(start) > 100*time.Millisecond || f.mount.possiblePOSIXLock(key) == 0 {
		t.Fatal("cold FLUSH blocked or forgot unlock obligation", status)
	}
}

func TestWorkspaceBoundLossFailureRetainsEvidence(t *testing.T) {
	f, g, _ := coldFixture(t)
	w := f.mount.workspaceLifecycle
	w.recordDrop(writeback.DropReport{LossSequence: 1, Entries: 1, Bytes: 3, Reason: "earlier accepted loss"})
	w.recordDrop(writeback.DropReport{LossSequence: 0, Entries: 1, Bytes: 2, Reason: "invalid source sequence"})
	serial := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
	if err == nil || o.ColdComplete || len(o.Loss) != 2 {
		t.Fatal("BoundLoss error erased evidence or certified cold", o, err)
	}
}

type workspaceFailedValidation struct {
	*coldTestRPC
	entered, release chan struct{}
	cause            error
}

func (r *workspaceFailedValidation) CallRead(ctx context.Context, q *authoritypb.Request) (*authoritypb.Response, error) {
	if q.GetKeepAlive() != nil {
		close(r.entered)
		<-r.release
		return nil, r.cause
	}
	return r.coldTestRPC.CallRead(ctx, q)
}
func TestWorkspaceLifecycleResultRetainsIndependentFailure(t *testing.T) {
	reset := workspaceSubscribeAttempt(authorityrpc.ErrSubscriptionReset)
	if reset.Disposition != authorityrpc.AttemptColdReset || reset.Err != authorityrpc.ErrSubscriptionReset {
		t.Fatal("cache reset lost its explicit phase", reset)
	}
	mixed := workspaceSubscribeAttempt(errors.Join(authorityrpc.ErrSubscriptionReset, errors.New("independent local failure")))
	if mixed.Disposition != authorityrpc.AttemptFailed {
		t.Fatal("cold reset hid an independent failure", mixed)
	}
	for _, cause := range []error{errors.New("independent local failure"), authorityrpc.ErrTransportBinding, authorityrpc.ErrSessionEnded, errors.Join(io.EOF, errors.New("independent local failure")), context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			f, g, rpc := coldFixture(t)
			r := &workspaceFailedValidation{coldTestRPC: rpc, entered: make(chan struct{}), release: make(chan struct{}), cause: cause}
			f.mount.rpc.(*epochRPC).rpc = r
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			serial := g.Close(1)
			done := make(chan WorkspaceObservation, 1)
			go func() { o, _ := f.mount.PrepareWorkspace(ctx, 1, serial); done <- o }()
			<-r.entered
			cancel()
			close(r.release)
			o := <-done
			want := authorityrpc.LifecycleFailed
			if cause == context.Canceled {
				want = authorityrpc.LifecycleOvertaken
			}
			if o.Prepared || o.Result.Disposition != want || !errors.Is(o.Result.Err, cause) {
				t.Fatal("frontend erased lifecycle disposition", o.Result)
			}
		})
	}
}

func TestWorkspaceCleanupDebtCountsObligationsOnce(t *testing.T) {
	f, g, rpc := coldFixture(t)
	// Queue a reclaim before a lane dequeues it: debt must survive that move.
	f.mount.reclaim.push(queuedReclaim{token: []byte("one"), transport: rpc})
	f.mount.reclaim.push(queuedReclaim{token: []byte("two"), transport: rpc})
	if _, ok := f.mount.reclaim.pop(t.Context()); !ok {
		t.Fatal("no queued reclaim")
	}
	f.mount.delegations.closeMu.Lock()
	f.mount.delegations.closePending = 2
	f.mount.delegations.closeMu.Unlock()
	owners := []*authoritypb.Request{
		{Body: &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{CutSequence: 7}}},
		{Body: &authoritypb.Request_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityRequest{CutSequence: 7}}},
		{Body: &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{}}},
		{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{[]byte("one"), []byte("two")}}}},
	}
	r := &workspaceDebtRPC{coldTestRPC: rpc}
	for _, request := range owners {
		body, err := proto.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		r.owners = append(r.owners, authorityrpc.DispatchOwner{Body: body})
	}
	f.mount.rpc.(*epochRPC).rpc = r
	serial := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
	if err != nil || !o.ColdComplete || o.Outcome.CleanupDebt != 4 {
		t.Fatal("cleanup debt is not exact", o, err)
	}
	exact := 0
	for _, worker := range o.Workers {
		if strings.Contains(worker.Disposition, "retained exact request") {
			exact++
		}
	}
	if exact != len(owners) || len(o.ParkedRequests) != len(owners) {
		t.Fatal("worker dispositions lacked per-instance evidence", o.Workers)
	}
	// New cleanup obligations arrive after the first cold acknowledgment.
	f.mount.delegations.closeMu.Lock()
	f.mount.delegations.closePending++
	f.mount.delegations.closeMu.Unlock()
	f.mount.reclaim.push(queuedReclaim{token: []byte("three"), transport: rpc})
	var persisted WorkspaceObservation
	f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error { persisted = o; return nil }
	again, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(-time.Second))
	if err != nil || !again.ColdComplete || again.Outcome.CleanupDebt != 6 || persisted.Outcome.CleanupDebt != 6 {
		t.Fatal("re-ack reused old cleanup debt", again, err)
	}
	// Recovery settles one request while publication is held, then a newer
	// Close defeats it. Inventory cannot be erased before final publication.
	ctx, cancel := context.WithCancel(t.Context())
	entered, release := make(chan struct{}), make(chan struct{})
	var held sync.Once
	f.mount.workspaceLifecycle.persist = func(o WorkspaceObservation) error {
		persisted = o
		if o.Prepared {
			held.Do(func() { close(entered); <-release })
		}
		return nil
	}
	recovered := make(chan WorkspaceObservation, 1)
	go func() { o, _ := f.mount.RecoverWorkspace(ctx, 1, serial); recovered <- o }()
	<-entered
	if len(f.mount.workspaceLifecycle.parkedRequests) != len(owners) {
		t.Fatal("recovery erased retained inventory before publication")
	}
	r.owners = r.owners[1:]
	f.mount.delegations.closeMu.Lock()
	f.mount.delegations.closePending--
	f.mount.delegations.closeMu.Unlock()
	f.mount.reclaim.complete(1)
	serial = g.Close(1)
	cancel()
	close(release)
	<-recovered
	again, err = f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
	if err != nil || !again.ColdComplete || again.Outcome.CleanupDebt != 4 || len(again.ParkedRequests) != len(owners)-1 || len(persisted.ParkedRequests) != len(owners)-1 {
		t.Fatal("re-park reused settled request/debt evidence", again, err)
	}
	f.mount.delegations.closeMu.Lock()
	f.mount.delegations.closePending = 0
	f.mount.delegations.closeMu.Unlock()
	f.mount.reclaim.complete(2)
}

type workspaceDebtRPC struct {
	*coldTestRPC
	owners []authorityrpc.DispatchOwner
}

func (r *workspaceDebtRPC) DispatchSnapshot() authorityrpc.DispatchSnapshot {
	return authorityrpc.DispatchSnapshot{Parked: r.parked.Load(), Owners: r.owners}
}

func TestWorkspaceKeepAliveParkRetainsIndependentFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		errno    syscall.Errno
		cause    error
		terminal bool
	}{
		{"terminal joined with cancellation", 0, authorityrpc.ErrSessionEnded, true},
		{"ECANCELED refusal", syscall.ECANCELED, nil, false},
		{"EINTR refusal", syscall.EINTR, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _ := coldFixture(t)
			a := &f.mount.workspaceLifecycle.keepalive
			attempt, finish, ok := a.start(t.Context())
			if !ok {
				t.Fatal("no attempt")
			}
			joined := make(chan error, 1)
			go func() { joined <- a.park(t.Context()) }()
			<-attempt.Done()
			var response *authoritypb.Response
			var failure error
			if tc.cause != nil {
				failure = errors.Join(attempt.Err(), tc.cause)
			} else {
				response = &authoritypb.Response{Errno: int32(tc.errno)}
			}
			finish(func(parked bool) { f.mount.settleKeepAlive(t.Context(), attempt, response, failure, parked) })
			if err := <-joined; err != nil {
				t.Fatal(err)
			}
			if f.mount.isRevoked() != tc.terminal {
				t.Fatal("park misclassified cancellation/refusal evidence", f.mount.isRevoked(), tc.terminal)
			}
		})
	}
}
