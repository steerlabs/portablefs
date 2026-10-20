//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/restorefixture"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

type writerAdmissionCutStore struct {
	*fskitDurabilityTestStore
	cut func()
}

func (s *writerAdmissionCutStore) Identity(item xfsstore.Capability) ([16]byte, error) {
	s.cut()
	return s.fskitDurabilityTestStore.Identity(item)
}

func (s *writerAdmissionCutStore) PinWriteTarget(handle xfsstore.Capability) (xfsstore.WriteTarget, error) {
	target, err := s.fskitDurabilityTestStore.PinWriteTarget(handle)
	s.cut()
	return target, err
}

func TestFskitRegistryFenceBeforeApplyRefusesMutationAndWriteOpen(t *testing.T) {
	for _, action := range []string{"fence", "poison"} {
		for _, operation := range []string{"write", "write-open"} {
			t.Run(action+"/"+operation, func(t *testing.T) {
				h, cred, store, target := newDirectFskitHarness(t)
				// Leave the runtime live to prove the registry check itself is
				// necessary, independently of Runtime.Begin's liveness check.
				registry, err := volumeserver.NewWriterRegistry(volumeserver.WriterRegistryConfig{Prior: volumeserver.PriorEpochStrictMountsFenced})
				if err != nil {
					t.Fatal(err)
				}
				terminal, err := h.Runtime.SessionTerminal(cred.ID)
				if err != nil {
					t.Fatal(err)
				}
				// An independent exclusion prevents its closed bit from making
				// Runtime.Begin mask a missing registry owner check.
				exclusion := new(volumeserver.WriterExclusion)
				if err := registry.Activate(cred.ID, terminal, exclusion, func() error { return nil }, func() {}); err != nil {
					t.Fatal(err)
				}
				h.Writers = registry
				cutReached := false
				h.Store = &writerAdmissionCutStore{fskitDurabilityTestStore: store, cut: func() {
					if cutReached {
						return
					}
					cutReached = true
					if action == "fence" {
						registry.Fence(cred.ID)
					} else {
						registry.Poison(errors.New("test completion defect"))
					}
				}}
				req := directFskitRequest()
				var response *authoritypb.Response
				if operation == "write" {
					response = h.handleWrite(t.Context(), req, cred, req.GetWrite())
				} else {
					root := xfsstore.Capability{0x70}
					req.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: root[:], Flags: &authoritypb.OpenFlags{Write: true}}}
					response = h.coherenceOpen(t.Context(), req, cred)
				}
				if !cutReached || response.GetErrno() == 0 || response.GetPostState() != nil {
					t.Fatalf("registry refusal=%v, cut=%v", response, cutReached)
				}
				if calls, _ := target.directSnapshot(); calls != 0 || store.open.Load() != 0 || store.syncs.Load() != 0 || h.coherencePending != 0 {
					t.Fatalf("applies/opens/syncs=%d/%d/%d", calls, store.open.Load(), store.syncs.Load())
				}
				use, err := h.Runtime.Begin(cred)
				if err != nil {
					t.Fatalf("runtime hid a missing owner check: %v", err)
				}
				use.End()
			})
		}
	}
}

func TestLinuxReplaySyncAndLocksSurviveMacWriterExclusionOnXFS(t *testing.T) {
	store := openTakeoverTestStore(t, restorefixture.Root(t))
	h, ctx, _, _ := newAuthorityTestHandler(t, nil)
	h.Store = store
	linux, epoch, linuxProof := attachAndActivateHandler(t, h, ctx, 1, &authoritypb.AttachRequest{VolumeId: "handler-fskit", AccessToken: []byte("test"), ReplaySlots: 9, Purpose: authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT, FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, RoutesRevision: emptyRoutesRevision(), AttachAttemptId: testAttachAttempt(1)})
	subscribe := h.Handle(ctx, &authoritypb.Request{RequestId: 3, Epoch: epoch, Session: linuxProof, Body: &authoritypb.Request_Subscribe{Subscribe: &authoritypb.SubscribeRequest{}}})
	if subscribe.GetErrno() != 0 {
		t.Fatal(subscribe)
	}
	create := &authoritypb.Request{RequestId: 4, Epoch: epoch, Session: linuxProof, Mutation: &authoritypb.Mutation{Sequence: 1}, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: linux.GetRoot().GetToken(), Name: []byte("replay-file"), Mode: 0600, Flags: &authoritypb.OpenFlags{Write: true}, Exclusive: true}}}
	created := h.Handle(ctx, create)
	if created.GetErrno() != 0 {
		t.Fatal(created)
	}
	_, _, macProof := attachAndActivateHandler(t, h, ctx, 10, fskitAttachRequest(10).GetAttach())
	var macID, linuxID volumeserver.SessionID
	copy(macID[:], macProof.GetId())
	copy(linuxID[:], linuxProof.GetId())
	t.Cleanup(func() { h.Runtime.FenceSession(macID); h.Runtime.FenceSession(linuxID) })
	proof := h.Handle(ctx, &authoritypb.Request{RequestId: 12, Epoch: epoch, Session: macProof, Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if proof.GetErrno() != 0 || proof.GetSessionValidForNanos() == 0 {
		t.Fatal(proof)
	}
	for i, phase := range []string{"live", "retained"} {
		t.Run(phase, func(t *testing.T) {
			if i != 0 {
				h.Writers.Fence(macID)
			}
			if err := h.Writers.CheckWriter(linuxID); !errors.Is(err, volumeserver.ErrWriterExcluded) {
				t.Fatalf("fixture lacks writer exclusion: %v", err)
			}
			before := h.coherenceVersionNow()
			create.RequestId++
			replay := h.Handle(ctx, create)
			want := proto.Clone(created).(*authoritypb.Response)
			want.RequestId = replay.RequestId
			if !proto.Equal(want, replay) || h.coherenceVersionNow() != before {
				t.Fatalf("writer exclusion replaced or reapplied exact replay: %v", replay)
			}
			for slot, req := range []*authoritypb.Request{
				{Body: &authoritypb.Request_SyncFs{SyncFs: &authoritypb.SyncFSRequest{}}},
				{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{Lock: &authoritypb.LockSpec{Item: created.GetCreate().GetItem().GetToken(), Owner: 1, Write: true, Range: &authoritypb.LockRange{}}}}},
			} {
				req.RequestId, req.Epoch, req.Session = uint64(20+i*2+slot), epoch, linuxProof
				req.Mutation = &authoritypb.Mutation{Slot: uint32(slot + 1), Sequence: uint64(i + 1)}
				if response := h.Handle(ctx, req); response.GetErrno() != 0 {
					t.Fatalf("%T refused under %s exclusion: %v", req.Body, phase, response)
				}
			}
			write := stockWriteTestRequest(uint64(30+i), 3, 1, xfsstore.Capability{}, []byte("blocked"), 0, 0)
			write.Epoch, write.Session, write.GetWrite().Handle = epoch, linuxProof, created.GetCreate().GetHandle()
			if response := h.Handle(ctx, write); response.GetErrno() != int32(syscall.EBUSY) || response.GetMutation() != nil {
				t.Fatalf("new writer bypassed exclusion: %v", response)
			}
		})
	}
}

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
			// The Linux peer must remain live while the Mac cache proof expires;
			// otherwise session refusal hides the apply-drain exclusion under test.
			runtime, err := volumeserver.New("writer-proof", volumeserver.Config{SessionLease: 2 * time.Minute, MaxReplaySlots: 16, MaxSessions: 4, MaxLockRecords: 16, ContinuousNow: continuous})
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
