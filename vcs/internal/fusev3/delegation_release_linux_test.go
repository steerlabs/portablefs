//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

type releaseOutcomeRPC struct {
	delegationFakeRPC
	release func(context.Context) (*authoritypb.Response, error)
	close   func(*authoritypb.CloseBatchRequest) (*authoritypb.Response, error)
}

func (f *releaseOutcomeRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetDelegationRelease() != nil && f.release != nil {
		return f.release(ctx)
	}
	return f.delegationFakeRPC.CallIdempotent(ctx, request)
}
func (f *releaseOutcomeRPC) CallMutationSegments(ctx context.Context, request *authoritypb.Request, segments [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	return waveWrite(ctx, &f.waveOrder, f.CallMutation, request, segments, assigned)
}

func (f *releaseOutcomeRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		// These cases inspect retained obligations after ownership transfer.
		// A background durable prefix would race the assertion itself.
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if batch := request.GetCloseBatch(); batch != nil && f.close != nil {
		return f.close(batch)
	}
	return f.delegationFakeRPC.CallMutation(ctx, request)
}
func releaseSuccess() *authoritypb.Response {
	return &authoritypb.Response{Body: &authoritypb.Response_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseReply{}}}
}

func TestDelegationReleaseOutcomeControlsAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response *authoritypb.Response
		err      error
		lost     bool
	}{
		{"definite refusal", &authoritypb.Response{Errno: int32(syscall.EINVAL)}, nil, false},
		{"transport uncertainty", nil, authorityrpc.ErrTransportUncertain, false},
		{"missing body", &authoritypb.Response{}, nil, false},
		{"coherence refusal", &authoritypb.Response{Errno: int32(syscall.EIO), Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &releaseOutcomeRPC{release: func(context.Context) (*authoritypb.Response, error) { return tc.response, tc.err }}
			m := newDelegationTestManager(t, fake)
			id := installDelegationForTest(t, m, 81, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			if _, err := m.Write(t.Context(), id, 0, []byte("old"), false); err != nil {
				t.Fatal(err)
			}
			if err := m.ReleaseBatch(t.Context(), [][]byte{id}); err == nil {
				t.Fatal("failed release succeeded")
			}
			if got := m.LossSequence() != 0; got != tc.lost {
				t.Fatalf("loss=%v want=%v", got, tc.lost)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err := m.Write(ctx, id, 3, []byte("new"), false)
			if tc.name != "definite refusal" {
				if !tc.lost && m.buf.Stats().Entries != 1 {
					t.Fatal("uncertain release discarded applied records")
				}
				if err == nil {
					t.Fatal("uncertain old grant admitted a write")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				parsed, _ := delegationIdentity(id)
				data, err := m.buf.Read(ctx, parsed, 0, 6, func(context.Context, int64, int) ([]byte, error) {
					return []byte("xxxxxx"), nil
				})
				if err != nil || string(data) != "oldnew" {
					t.Fatalf("refusal lost overlay: %q %v", data, err)
				}
			}
		})
	}
}

func TestDelegationReleaseCommitsEveryGrantAfterLocalDetachFailure(t *testing.T) {
	fake := &releaseOutcomeRPC{}
	m := newDelegationTestManager(t, fake)
	var ids [][]byte
	for _, seed := range []byte{82, 83} {
		id := installDelegationForTest(t, m, seed, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
		ids = append(ids, id)
		if _, err := m.Write(t.Context(), id, 0, []byte("old"), false); err != nil {
			t.Fatal(err)
		}
	}
	fake.release = func(context.Context) (*authoritypb.Response, error) {
		id, _ := delegationIdentity(ids[0])
		m.state(id).retire.Cancel()
		return releaseSuccess(), nil
	}
	if err := m.ReleaseBatch(t.Context(), ids); err == nil {
		t.Fatal("detach invariant failure hidden")
	}
	for _, id := range ids {
		parsed, _ := delegationIdentity(id)
		if delegationStateOwned(m.state(parsed)) {
			t.Fatal("committed batch left a live old grant")
		}
	}
	if m.LossSequence() != 1 || m.buf.Stats().Entries != 1 {
		t.Fatalf("commit failed to isolate local loss: loss=%d stats=%+v", m.LossSequence(), m.buf.Stats())
	}
}

func TestDelegationReleaseRPCDoesNotHoldStateLocks(t *testing.T) {
	fake := &releaseOutcomeRPC{}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 84, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	parsed, _ := delegationIdentity(id)
	state := m.state(parsed)
	entered, proceed := make(chan struct{}), make(chan struct{})
	fake.release = func(ctx context.Context) (*authoritypb.Response, error) {
		close(entered)
		select {
		case <-proceed:
			return releaseSuccess(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.ReleaseBatch(ctx, [][]byte{id}) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("release never started")
	}
	for _, check := range []struct {
		name   string
		lock   func() bool
		unlock func()
	}{
		{"acquire", state.acquire.TryLock, state.acquire.Unlock}, {"transition", state.transition.TryLock, state.transition.Unlock}, {"operation", state.operation.TryLock, state.operation.Unlock},
	} {
		if !check.lock() {
			t.Fatalf("release RPC holds %s", check.name)
		}
		check.unlock()
	}
	joined := make(chan error, 1)
	go func() { joined <- m.AddHandle(id, delegationTestToken(84, 1), delegationTestToken(84, 3), false) }()
	select {
	case err := <-joined:
		t.Fatalf("join passed an unresolved release: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	other := installDelegationForTest(t, m, 85, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(ctx, other, 0, []byte("peer"), false); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-joined; !errors.Is(err, errDelegationRetired) {
		t.Fatalf("join=%v", err)
	}
}

func TestDelegationLockAcquisitionHonorsContext(t *testing.T) {
	state := &delegationState{}
	state.operation.Lock()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := state.lockAfterRelease(ctx, delegationOperation); !errors.Is(err, context.Canceled) {
		t.Fatalf("lockAfterRelease = %v, want context cancellation", err)
	}
	state.operation.Unlock()
	if !state.operation.TryLock() {
		t.Fatal("canceled lock acquisition leaked the operation mutex")
	}
	state.operation.Unlock()
}

func TestDelegationCloseFailureRetainsAppliedRecords(t *testing.T) {
	for _, retired := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "retired"}[retired], func(t *testing.T) {
			fake := &releaseOutcomeRPC{close: func(batch *authoritypb.CloseBatchRequest) (*authoritypb.Response, error) {
				if !retired {
					return nil, authorityrpc.ErrTransportUncertain
				}
				return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: []*authoritypb.CloseBatchResult{{Errno: int32(syscall.EIO), Retired: true}}}}}, nil
			}}
			m := newDelegationTestManager(t, fake)
			id := installDelegationForTest(t, m, 86, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			if _, err := m.Write(t.Context(), id, 0, []byte("retained"), false); err != nil {
				t.Fatal(err)
			}
			var reported atomic.Bool
			m.SetCleanupFailureReporter(func(error) { reported.Store(true) })
			if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(86, 2)}}); err == nil {
				t.Fatal("cleanup error hidden")
			}
			parsed, _ := delegationIdentity(id)
			s := m.state(parsed)
			if delegationStateOwned(s) || m.LossSequence() != 0 || m.buf.Stats().Entries != 1 {
				t.Fatal("cleanup failure lost applied data or reopened grant")
			}
			// An unknown batch outcome owns its descriptors until terminal
			// session cleanup, so it must reach the mount's terminal policy.
			if reported.Load() != !retired {
				t.Fatalf("terminal cleanup report=%v, want %v", reported.Load(), !retired)
			}
			if got := len(s.handles) == 0; got != retired {
				t.Fatalf("retired handle removal=%v want=%v", got, retired)
			}
			data, err := m.buf.Read(t.Context(), parsed, 0, 4, func(context.Context, int64, int) ([]byte, error) { return []byte("peer"), nil })
			if err != nil || string(data) != "peer" {
				t.Fatalf("retained record hid peer data: %q %v", data, err)
			}
		})
	}
}

func TestDeferredCoherenceCloseWaitsForColdSubscriptionAndRetries(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	fake := &releaseOutcomeRPC{close: func(batch *authoritypb.CloseBatchRequest) (*authoritypb.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		result := &authoritypb.CloseBatchResult{}
		if calls == 1 {
			result.Errno = int32(syscall.EIO)
			result.Failure = authoritypb.FailureClass_FAILURE_CLASS_COHERENCE
		}
		return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: []*authoritypb.CloseBatchResult{result}}}}, nil
	}}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 88, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("retained"), false); err != nil {
		t.Fatal(err)
	}
	retry := make(chan struct{})
	m.SetCleanupRetryWaiter(func(ctx context.Context) error {
		select {
		case <-retry:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	reported := make(chan error, 1)
	m.SetCleanupFailureReporter(func(err error) { reported <- err })
	if err := m.QueueClose(id, delegationTestToken(88, 2), 0, false); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-reported:
		var classified cleanupClassified
		if !errors.As(err, &classified) || classified.cleanupFailureClass() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
			t.Fatalf("reported cleanup = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("coherence close refusal was not reported")
	}
	m.closeMu.Lock()
	pending := m.closePending
	m.closeMu.Unlock()
	if pending != 1 {
		t.Fatalf("pending close retired before cold retry: %d", pending)
	}
	close(retry)
	waitUntil(t, time.Second, "deferred close retry", func() bool {
		m.closeMu.Lock()
		defer m.closeMu.Unlock()
		return m.closePending == 0
	})
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("close calls = %d, want coherence refusal plus retry", calls)
	}
}

func TestMountDeferredCoherenceCloseUsesReplacementSubscription(t *testing.T) {
	mount, rpc := testMount(t, 64)
	id := installDelegationForTest(t, mount.delegations, 89, authoritypb.DelegationMode_DELEGATION_MODE_FULL)

	closeCalls := 0
	rpc.mu.Lock()
	rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetDelegationRelease() != nil {
			return releaseSuccess(), nil
		}
		batch := request.GetCloseBatch()
		if batch == nil {
			return &authoritypb.Response{}, nil
		}
		closeCalls++
		if closeCalls == 1 {
			return &authoritypb.Response{
				Errno:   int32(syscall.EIO),
				Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE,
			}, nil
		}
		results := make([]*authoritypb.CloseBatchResult, len(batch.GetCloses()))
		for i := range results {
			results[i] = &authoritypb.CloseBatchResult{}
		}
		return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: results}}}, nil
	}
	rpc.mu.Unlock()

	if err := mount.delegations.QueueClose(id, delegationTestToken(89, 2), 0, false); err != nil {
		t.Fatal(err)
	}
	// The fake counts the refusal before its reply reaches the close
	// dispatcher, which deactivates the subscription only afterwards. Wait for
	// that deactivation itself, not for the RPC, before asserting on it.
	waitUntil(t, time.Second, "coherence close refusal to deactivate the subscription", func() bool {
		return mount.subscription.stamp() == (subscriptionStamp{})
	})
	rpc.mu.Lock()
	refusals := closeCalls
	rpc.mu.Unlock()
	if refusals != 1 {
		t.Fatalf("close calls before replacement subscription = %d, want 1", refusals)
	}
	mount.delegations.closeMu.Lock()
	pending := mount.delegations.closePending
	mount.delegations.closeMu.Unlock()
	if pending != 1 {
		t.Fatalf("pending close retired before replacement subscription: %d", pending)
	}

	if err := mount.subscription.subscribe(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, time.Second, "close retry after replacement subscription", func() bool {
		mount.delegations.closeMu.Lock()
		defer mount.delegations.closeMu.Unlock()
		return mount.delegations.closePending == 0
	})
	rpc.mu.Lock()
	defer rpc.mu.Unlock()
	if closeCalls != 2 {
		t.Fatalf("close calls = %d, want refusal plus retry", closeCalls)
	}
}

func TestCloseBatchRejectsMalformedOutcomesBeforeRemovingHandles(t *testing.T) {
	for name, results := range map[string][]*authoritypb.CloseBatchResult{
		"nil": {nil}, "short": {}, "long": {{}, {}}, "negative": {{Errno: -1}}, "range": {{Errno: 4096}}, "failure with success": {{Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE}}, "unknown class": {{Errno: 5, Failure: authoritypb.FailureClass(99)}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &releaseOutcomeRPC{close: func(*authoritypb.CloseBatchRequest) (*authoritypb.Response, error) {
				return &authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: results}}}, nil
			}}
			m := newDelegationTestManager(t, fake)
			id := installDelegationForTest(t, m, 87, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			reported := false
			m.SetCleanupFailureReporter(func(error) { reported = true })
			if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(87, 2)}}); err == nil {
				t.Fatal("malformed result succeeded")
			}
			parsed, _ := delegationIdentity(id)
			if !reported || len(m.state(parsed).handles) != 1 {
				t.Fatal("unknown close outcome lost terminal cleanup ownership")
			}
		})
	}
}

func TestCloseBatchEpochChangeLeavesMountRecoveryInCharge(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		revoke bool
	}{
		{"epoch", authorityrpc.ErrAuthorityChanged, false},
		{"uncertain", authorityrpc.ErrTransportUncertain, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &releaseOutcomeRPC{close: func(*authoritypb.CloseBatchRequest) (*authoritypb.Response, error) { return nil, tc.err }}
			m := newDelegationTestManager(t, fake)
			id := installDelegationForTest(t, m, 91, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			if _, err := m.Write(t.Context(), id, 0, []byte("retained"), false); err != nil {
				t.Fatal(err)
			}
			var revoked bool
			m.SetCleanupFailureReporter(func(error) { revoked = true })
			if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(91, 2)}}); err == nil {
				t.Fatal("cleanup error hidden")
			}
			if revoked != tc.revoke {
				t.Fatalf("mount revoke=%v want=%v", revoked, tc.revoke)
			}
			if m.LossSequence() != 0 || m.buf.Stats().Entries != 1 {
				t.Fatal("cleanup discarded retained durability obligation")
			}
			if !tc.revoke {
				m.EpochChanged("test epoch replacement")
				if m.LossSequence() != 1 || m.buf.Stats().Entries != 0 {
					t.Fatal("epoch recovery failed to discharge old retained obligation")
				}
			}
		})
	}
}

// Release pressure: a burst of deferred closes larger than one batch is
// carried only in CLOSE_BATCH requests of at most MaxCloseBatch descriptors,
// each descriptor closed exactly once and none through an individual CLOSE.
func TestDeferredCloseBurstIsCarriedInBoundedBatches(t *testing.T) {
	fake := &delegationFakeRPC{}
	m := newDelegationTestManager(t, fake)
	const closes = 2*authorityrpc.MaxCloseBatch + 37
	identity := delegationTestIdentity(40)
	for i := range closes {
		if err := m.QueueClose(identity, delegationTestToken(40, byte(i>>8), byte(i)), 0, false); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, 5*time.Second, "every queued close to retire", func() bool {
		m.closeMu.Lock()
		defer m.closeMu.Unlock()
		return m.closePending == 0
	})
	fake.mu.Lock()
	defer fake.mu.Unlock()
	seen := make(map[string]int, closes)
	for _, request := range fake.mutations {
		if request.GetClose() != nil {
			t.Fatal("a deferred close used an individual CLOSE")
		}
		batch := request.GetCloseBatch()
		if batch == nil {
			continue
		}
		if n := len(batch.GetCloses()); n == 0 || n > authorityrpc.MaxCloseBatch {
			t.Fatalf("close batch carried %d descriptors, bound %d", n, authorityrpc.MaxCloseBatch)
		}
		for _, close := range batch.GetCloses() {
			seen[string(close.GetHandle())]++
		}
	}
	if len(seen) != closes {
		t.Fatalf("closed %d distinct descriptors, want %d", len(seen), closes)
	}
	for handle, count := range seen {
		if count != 1 {
			t.Fatalf("descriptor %x closed %d times", handle, count)
		}
	}
}
