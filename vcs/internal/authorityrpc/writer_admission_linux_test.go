//go:build linux

package authorityrpc

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/restorefixture"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestFskitApplyDoesNotTakeSharedProfileAdmission(t *testing.T) {
	h, cred, _, target := newDirectFskitHarness(t)
	h.coherenceProfileAdmission.Lock()
	done := make(chan *authoritypb.Response, 1)
	go func() { r := directFskitRequest(); done <- h.handleWrite(t.Context(), r, cred, r.GetWrite()) }()
	select {
	case response := <-done:
		if response.GetWrite().GetCommittedSize() != 4 {
			t.Fatal(response)
		}
	case <-time.After(time.Second):
		h.coherenceProfileAdmission.Unlock()
		t.Fatal("Mac apply waited for profile admission")
	}
	h.coherenceProfileAdmission.Unlock()
	if calls, _ := target.directSnapshot(); calls != 1 {
		t.Fatalf("applies=%d", calls)
	}
}

func TestSecondMacRefusedBeforeExclusiveProfileQueue(t *testing.T) {
	h, ctx, _, _ := newAuthorityTestHandler(t, nil)
	attachAndActivateHandler(t, h, ctx, 1, fskitAttachRequest(1).GetAttach())
	attached := h.Handle(ctx, fskitAttachRequest(50))
	if attached.GetErrno() != 0 {
		t.Fatal(attached)
	}
	// A queued exclusive permit would wait for this shared side. The registry
	// already knows a second Mac cannot be admitted, so it must never queue.
	h.coherenceProfileAdmission.RLock()
	done := make(chan *authoritypb.Response, 1)
	go func() {
		done <- h.Handle(ctx, &authoritypb.Request{RequestId: 51, Epoch: attached.GetEpoch(), Session: proofFromAttach(attached), Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{AttachAttemptId: testAttachAttempt(50), DataBindingGeneration: 1, ControlBindingGeneration: 1}}})
	}()
	select {
	case response := <-done:
		if response.GetErrno() != int32(syscall.EBUSY) {
			t.Fatal(response)
		}
	case <-time.After(time.Second):
		h.coherenceProfileAdmission.RUnlock()
		t.Fatal("second Mac queued exclusive profile admission")
	}
	h.coherenceProfileAdmission.RUnlock()
}

func TestHandlerProofRetainsWriterExclusionThroughApplyDrainOnXFS(t *testing.T) {
	for _, absence := range []bool{false, true} {
		name := "expiry"
		if absence {
			name = "exact-absence"
		}
		t.Run(name, func(t *testing.T) {
			store := openTakeoverTestStore(t, restorefixture.Root(t))
			var elapsed atomic.Int64
			elapsed.Store(int64(time.Second))
			continuous := func() (time.Duration, error) { return time.Duration(elapsed.Load()), nil }
			runtime, err := volumeserver.New("writer-proof", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 16, MaxSessions: 4, MaxLockRecords: 16, ContinuousNow: continuous})
			if err != nil {
				t.Fatal(err)
			}
			h := testVolumeHandler()
			h.Store, h.Runtime, h.Authorizer = store, runtime, allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
			coordination, err := NewCoordination(CoordinationConfig{Store: store, Fencer: runtime, Locks: runtime.Locks(), Membership: noopMembership{}, Prior: volumeserver.PriorEpochStrictMountsFenced, ContinuousNow: continuous})
			if err != nil {
				t.Fatal(err)
			}
			coordination.Bind(h)
			ctx := context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1})
			attach := func(id uint64, profile authoritypb.FrontendProfile) (*authoritypb.ActivateReply, []byte, *authoritypb.SessionProof) {
				return attachAndActivateHandler(t, h, ctx, id, &authoritypb.AttachRequest{VolumeId: "writer-proof", AccessToken: []byte("test"), ReplaySlots: 9, Purpose: authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT, FrontendProfile: profile, RoutesRevision: emptyRoutesRevision(), AttachAttemptId: testAttachAttempt(id)})
			}
			linux, epoch, linuxProof := attach(1, authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX)
			var linuxID volumeserver.SessionID
			copy(linuxID[:], linuxProof.GetId())
			subscribe := h.Handle(ctx, &authoritypb.Request{RequestId: 3, Epoch: epoch, Session: linuxProof, Body: &authoritypb.Request_Subscribe{Subscribe: &authoritypb.SubscribeRequest{}}})
			if subscribe.GetErrno() != 0 {
				t.Fatal(subscribe)
			}
			created := h.Handle(ctx, &authoritypb.Request{RequestId: 4, Epoch: epoch, Session: linuxProof, Mutation: &authoritypb.Mutation{Sequence: 1}, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: linux.GetRoot().GetToken(), Name: []byte("file"), Mode: 0600, Flags: &authoritypb.OpenFlags{Read: true, Write: true}, Exclusive: true}}})
			if created.GetErrno() != 0 {
				t.Fatal(created)
			}
			mac, _, macProof := attach(10, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE)
			var macID volumeserver.SessionID
			copy(macID[:], macProof.GetId())
			t.Cleanup(func() { runtime.FenceSession(macID); runtime.FenceSession(linuxID) })
			lookup := h.Handle(ctx, &authoritypb.Request{RequestId: 12, Epoch: epoch, Session: macProof, Mutation: &authoritypb.Mutation{Sequence: 1}, Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: mac.GetRoot().GetToken(), Name: []byte("file")}}})
			if lookup.GetErrno() != 0 {
				t.Fatal(lookup)
			}
			opened := h.Handle(ctx, &authoritypb.Request{RequestId: 13, Epoch: epoch, Session: macProof, Mutation: &authoritypb.Mutation{Sequence: 2}, Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: lookup.GetLookup().GetItem().GetToken(), Flags: &authoritypb.OpenFlags{Write: true}}}})
			if opened.GetErrno() != 0 {
				t.Fatal(opened)
			}
			proof := h.Handle(ctx, &authoritypb.Request{RequestId: 14, Epoch: epoch, Session: macProof, Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
			if proof.GetErrno() != 0 || proof.GetSessionValidForNanos() == 0 {
				t.Fatalf("KeepAlive proof=%v", proof)
			}
			backend := &handoffApplyStore{Volume: store, entered: make(chan struct{}), release: make(chan struct{})}
			h.Store = backend
			released := false
			defer func() {
				if !released {
					close(backend.release)
				}
			}()
			oldDone := make(chan *authoritypb.Response, 1)
			go func() {
				oldDone <- h.Handle(ctx, &authoritypb.Request{RequestId: 15, Epoch: epoch, Session: macProof, Mutation: &authoritypb.Mutation{Sequence: 3}, Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: opened.GetOpen().GetHandle(), Size: 4, Data: []byte("data")}}})
			}()
			waitWriteTestSignal(t, backend.entered, "admitted Mac storage apply")
			if absence {
				detached := h.Handle(ctx, &authoritypb.Request{RequestId: 16, Epoch: epoch, Session: macProof, Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{MountAbsence: &authoritypb.MountAbsenceProof{ObservedUnixNanos: time.Now().UnixNano(), Observation: []byte("original kernel mount absent"), Component: "test-supervisor"}}}})
				if detached.GetErrno() != 0 {
					t.Fatal(detached)
				}
			} else {
				h.Writers.Fence(macID)
				elapsed.Store(int64(time.Second + volumeserver.MaxCacheProof))
			}
			write := &authoritypb.Request{RequestId: 20, Epoch: epoch, Session: linuxProof, Mutation: &authoritypb.Mutation{Slot: 1, Sequence: 1}, Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: created.GetCreate().GetHandle(), Size: 4, Data: []byte("peer")}}}
			open := &authoritypb.Request{RequestId: 21, Epoch: epoch, Session: linuxProof, Mutation: &authoritypb.Mutation{Slot: 1, Sequence: 1}, Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: created.GetCreate().GetItem().GetToken(), Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true}}}
			for _, request := range []*authoritypb.Request{write, open} {
				if response := h.Handle(ctx, request); response.GetErrno() != int32(syscall.EBUSY) || response.GetMutation() != nil {
					t.Fatalf("old apply did not retain exclusion for %T: %v", request.GetBody(), response)
				}
			}
			close(backend.release)
			released = true
			token, err := h.coherenceToken(linuxID)
			if err != nil {
				t.Fatal(err)
			}
			poll, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			events, _, err := h.Coherence.PollControl(poll, token, 0, nil, 32)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) == 0 {
				t.Fatal("Mac write did not publish Linux withdrawal")
			}
			if err := h.Coherence.Ack(token, events[len(events)-1].Position); err != nil {
				t.Fatal(err)
			}
			select {
			case <-oldDone:
			case <-time.After(2 * time.Second):
				t.Fatal("admitted apply did not drain after withdrawal/durability")
			}
			h.SweepCoherence()
			write.RequestId++
			response := h.Handle(ctx, write)
			if response.GetErrno() != 0 || response.GetWrite().GetCommittedSize() != 4 {
				t.Fatalf("writer not readmitted after time AND drain: %v", response)
			}
			open.Mutation.Sequence = 2
			open.RequestId += 10
			if response := h.Handle(ctx, open); response.GetErrno() != 0 || response.GetOpen() == nil {
				t.Fatalf("write-intent open not readmitted: %v", response)
			}
		})
	}
}
