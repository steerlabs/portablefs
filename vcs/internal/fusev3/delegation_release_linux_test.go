//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"sync"
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
func (f *releaseOutcomeRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		// These cases inspect retained obligations after ownership transfer.
		// A background durable prefix would race the assertion itself.
		return nil, errors.New("durability withheld while checking retained records")
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
			if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(86, 2)}}); err == nil {
				t.Fatal("cleanup error hidden")
			}
			parsed, _ := delegationIdentity(id)
			s := m.state(parsed)
			if delegationStateOwned(s) || m.LossSequence() != 0 || m.buf.Stats().Entries != 1 {
				t.Fatal("cleanup failure lost applied data or reopened grant")
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

type serialCloseRPC struct {
	releaseOutcomeRPC
	closeErr error
}

func (*serialCloseRPC) SupportsBatchedClose() bool { return false }
func (f *serialCloseRPC) CallMutation(ctx context.Context, req *authoritypb.Request) (*authoritypb.Response, error) {
	if req.GetClose() != nil && f.closeErr != nil {
		return nil, f.closeErr
	}
	return f.releaseOutcomeRPC.CallMutation(ctx, req)
}

func TestDelegationCloseFallsBackToOrderedSerialRequests(t *testing.T) {
	fake := &serialCloseRPC{}
	m := newDelegationTestManager(t, fake)
	var closes []delegationClose
	for _, seed := range []byte{92, 93} {
		id := installDelegationForTest(t, m, seed, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
		closes = append(closes, delegationClose{identity: id, handle: delegationTestToken(seed, 2), lockOwner: uint64(seed), flockUnlock: true})
	}
	if err := m.CloseHandles(t.Context(), closes); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.controls) != 1 || len(fake.controls[0].GetDelegationRelease().GetDelegations()) != 2 || len(fake.mutations) != 2 {
		t.Fatal("serial cleanup did not batch release then close both handles")
	}
	for i, req := range fake.mutations {
		close := req.GetClose()
		if close == nil || !bytes.Equal(close.Handle, closes[i].handle) || close.LockOwner != closes[i].lockOwner || !close.FlockUnlock {
			t.Fatalf("serial close %d lost ordered capability/lock state: %v", i, req)
		}
		id, _ := delegationIdentity(closes[i].identity)
		if len(m.state(id).handles) != 0 {
			t.Fatal("serial success retained handle debt")
		}
	}
}

func TestSerialCloseUncertaintyKeepsAppliedRecordsForTerminalCleanup(t *testing.T) {
	fake := &serialCloseRPC{closeErr: authorityrpc.ErrTransportUncertain}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 94, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("retained"), false); err != nil {
		t.Fatal(err)
	}
	var reported bool
	m.SetCleanupFailureReporter(func(error) { reported = true })
	if err := m.CloseHandles(t.Context(), []delegationClose{{identity: id, handle: delegationTestToken(94, 2)}}); err == nil {
		t.Fatal("unknown CLOSE succeeded")
	}
	parsed, _ := delegationIdentity(id)
	if !reported || len(m.state(parsed).handles) != 1 || m.buf.Stats().Entries != 1 || m.LossSequence() != 0 {
		t.Fatal("serial uncertainty erased cleanup or data obligations")
	}
}

type closeCapabilityRPC struct {
	*fakeRPC
	enabled bool
}

func (f *closeCapabilityRPC) SupportsBatchedClose() bool { return f.enabled }
func TestEpochRPCReadsCloseCapabilityFromCurrentTransport(t *testing.T) {
	_, rpc := testMount(t, 8)
	e := newEpochRPC(&closeCapabilityRPC{fakeRPC: rpc})
	if e.SupportsBatchedClose() {
		t.Fatal("old transport acquired absent capability")
	}
	e.mu.Lock()
	e.rpc = &closeCapabilityRPC{fakeRPC: rpc, enabled: true}
	e.mu.Unlock()
	if !e.SupportsBatchedClose() {
		t.Fatal("replacement capability was not observed")
	}
}
