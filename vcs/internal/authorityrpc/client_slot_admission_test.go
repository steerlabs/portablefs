package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestReplaySlotWaitCancellationAfterUnevenCompletion(t *testing.T) {
	handler := &mutationSettlementTestHandler{fskitProofTestHandler: newFskitProofTestHandler()}
	handler.set(uint64(time.Second), nil, 0)
	client, err := dialFskitProofTestClient(t, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Two permits permit the second slot to complete while the first is held.
	// The next round-robin admission then revisits that still-busy first slot.
	client.ordinary = lane{permits: make(chan struct{}, 2), slots: make([]clientSlot, 2)}
	assigned, resume, firstDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	defer close(resume)
	go func() {
		_, err := client.CallMutationWithIdentity(t.Context(), settlementTestMkdir(), func(MutationIdentity) error { close(assigned); <-resume; return nil })
		firstDone <- err
	}()
	<-assigned
	var second MutationIdentity
	if _, err := client.CallMutationWithIdentity(t.Context(), settlementTestMkdir(), func(id MutationIdentity) error { second = id; return nil }); err != nil {
		t.Fatal(err)
	}
	if second.Slot != 1 {
		t.Fatalf("second slot=%d", second.Slot)
	}
	cache, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	request := settlementTestMkdir()
	go func() {
		_, err := client.CallMutationWithIdentity(RetainMutationForSession(cache, t.Context()), request, func(MutationIdentity) error { t.Error("canceled slot waiter assigned"); return nil })
		done <- err
	}()
	deadline := time.After(time.Second)
	for client.ordinary.nextSlot.Load() != 3 {
		select {
		case <-deadline:
			t.Fatal("waiter never selected busy slot")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slot mutex ignored cancellation")
	}
	if request.Mutation != nil || handler.mutations.Load() != 1 || len(client.ordinary.permits) != 1 || client.SessionEndCause() != nil {
		t.Fatal("undispatched waiter retained ownership or changed session")
	}
	resume <- struct{}{}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if len(client.ordinary.permits) != 0 {
		t.Fatal("permit leak")
	}
	// Slot 1 remains usable, followed by the canceled slot 0 without a gap.
	for range 2 {
		if r, err := client.CallMutation(t.Context(), settlementTestMkdir()); err != nil || r.GetErrno() == 0 {
			t.Fatalf("next refusal=%v %v", r, err)
		}
	}
	if client.SessionEndCause() != nil {
		t.Fatal(client.SessionEndCause())
	}
}

func TestSessionOwnedAssignmentPreservesCallbackError(t *testing.T) {
	handler := &mutationSettlementTestHandler{fskitProofTestHandler: newFskitProofTestHandler()}
	client, err := dialFskitProofTestClient(t, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache, cancel := context.WithCancel(t.Context())
	defer cancel()
	want := errors.New("assignment refused")
	_, err = client.CallMutationWithIdentity(RetainMutationForSession(cache, t.Context()), settlementTestMkdir(), func(MutationIdentity) error { cancel(); return want })
	if !errors.Is(err, want) || handler.mutations.Load() != 0 || len(client.ordinary.permits) != 0 || client.SessionEndCause() != nil {
		t.Fatalf("callback error=%v", err)
	}
}

type assignmentOrderedHandler struct {
	*replayHandler
	coordinator *volumeserver.CoherenceCoordinator
	token       volumeserver.SubscriptionToken
	grant       volumeserver.Delegation
	entered     chan uint64
}

func (h *assignmentOrderedHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	if w := r.GetWrite(); w != nil {
		h.entered <- w.FlushSequence
		ticket, err := h.coordinator.BeginOrderedFlush(h.token, h.grant.ID, h.grant.Generation, w.FlushSequence, volumeserver.MutationID{Slot: r.Mutation.Slot, Sequence: r.Mutation.Sequence})
		if err != nil {
			return &authoritypb.Response{Errno: int32(syscall.EIO)}
		}
		defer ticket.Complete()
		if err := ticket.Wait(ctx); err != nil {
			return &authoritypb.Response{Errno: int32(syscall.EIO)}
		}
	}
	return h.replayHandler.Handle(ctx, r)
}

func TestSessionResolutionStartsBeforeAssignmentPublication(t *testing.T) {
	runtime, err := volumeserver.New("assignment-boundary", volumeserver.Config{ContinuousNow: func() (time.Duration, error) { return 0, nil }, SessionLease: time.Minute, MaxReplaySlots: 9, MaxSessions: 4, MaxLockRecords: 16})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{})
	snapshot, err := coordinator.SubscribeWithCache(volumeserver.SessionID{1}, volumeserver.CacheAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	token := snapshot.Token
	grant, err := coordinator.DataMutated(t.Context(), token, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	handler := &assignmentOrderedHandler{replayHandler: &replayHandler{runtime: runtime, access: volumeserver.AccessRead | volumeserver.AccessWrite}, coordinator: coordinator, token: token, grant: grant, entered: make(chan uint64, 2)}
	address, tlsConfig, stop := startTestServer(t, handler, testMaxInFlight, time.Minute)
	defer stop()
	client, err := DialClient(t.Context(), coherentTestClientConfig(address, tlsConfig, "assignment-boundary", 9, 9))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cache, cancelCache := context.WithCancel(t.Context())
	defer cancelCache()
	session, cancelSession := context.WithCancel(t.Context())
	defer cancelSession()
	published, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	done := make(chan error, 2)
	identities := make(chan MutationIdentity, 2)
	spans := [][][]byte{{[]byte("A"), []byte("a")}, {[]byte("B"), []byte("b")}}
	launch := func(i int) {
		go func() {
			request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: bytes.Repeat([]byte{1}, 16), Size: 2, Delegation: &authoritypb.DelegationRef{Id: bytes.Repeat([]byte{2}, 16), Generation: 1}}}}
			r, err := client.CallMutationSegments(RetainMutationForSession(cache, session), request, spans[i], func(id MutationIdentity) error {
				request.GetWrite().FlushSequence = uint64(i + 1)
				identities <- id
				if i == 0 {
					close(published)
					<-resume
				}
				return nil
			})
			if err == nil && r.GetMutation().GetAcceptedSequence() != 1 {
				err = fmt.Errorf("identity did not resolve: %v", r)
			}
			done <- err
		}()
	}
	launch(0)
	<-published
	launch(1)
	select {
	case ordinal := <-handler.entered:
		if ordinal != 2 {
			t.Fatalf("first authority arrival=%d", ordinal)
		}
	case <-time.After(time.Second):
		t.Fatal("successor did not reach authority")
	}
	cancelCache()
	if len(client.flush.permits) != 2 {
		t.Fatal("assigned spans/permits released before resolution")
	}
	release()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("assigned predecessor left an ordinal gap")
		}
	}
	first, second := <-identities, <-identities
	if first.Slot == second.Slot || first.Sequence != 1 || second.Sequence != 1 || handler.applyCalls.Load() != 2 {
		t.Fatalf("identities=%v %v applications=%d", first, second, handler.applyCalls.Load())
	}
	if string(bytes.Join(spans[0], nil)) != "Aa" || string(bytes.Join(spans[1], nil)) != "Bb" {
		t.Fatal("immutable spans changed")
	}
	client.fatalMu.Lock()
	receipts := len(client.responseConsumptions)
	client.fatalMu.Unlock()
	if receipts != 0 || len(client.flush.permits) != 0 || client.SessionEndCause() != nil {
		t.Fatal("resolution leaked spans, receipts or permits, or ended session")
	}
	// Reusing every flush slot proves no old wave owner remains.
	for range 4 {
		if _, err := client.CallMutation(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{bytes.Repeat([]byte{3}, 16)}}}}); err != nil {
			t.Fatal(err)
		}
	}
	ticket, err := coordinator.BeginOrderedFlush(token, grant.ID, grant.Generation, 3, volumeserver.MutationID{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ticket.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	ticket.Complete()
	if _, err := client.KeepAlive(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionOwnedAssignmentPreservesTerminalCancellation(t *testing.T) {
	c := newTerminalDrainTestClient(nil, nil, time.Second)
	defer c.Close()
	cache, cancelCache := context.WithCancel(t.Context())
	defer cancelCache()
	session, cancelSession := context.WithCancel(t.Context())
	defer cancelSession()
	request := settlementTestMkdir()
	response, err := c.CallMutationWithIdentity(RetainMutationForSession(cache, session), request, func(MutationIdentity) error {
		c.signalSessionEnd(ErrAuthorityChanged)
		cancelSession()
		cancelCache()
		return nil
	})
	if response != nil || err != ErrAuthorityChanged || request.GetRequestId() != 0 || c.ordinary.slots[0].sequence != 0 || len(c.ordinary.permits) != 0 {
		t.Fatalf("terminal assignment=(%v, %v)", response, err)
	}
}
