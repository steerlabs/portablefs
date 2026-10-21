//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

// Both authority clocks move explicitly. No timer delivery supplies expiry proof.
func replayAdmissionHarness(t *testing.T, deadline time.Duration) (*VolumeHandler, context.Context, volumeserver.SessionCredential, xfsstore.Capability, *applicationClock, *replayAdmissionStore) {
	t.Helper()
	clock := newApplicationClock()
	base := clock.Now()
	a, err := volumeserver.New("replay-admission", volumeserver.Config{Now: clock.Now, ContinuousNow: func() (time.Duration, error) { return clock.Now().Sub(base), nil }, SessionLease: 2 * time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8})
	if err != nil {
		t.Fatal(err)
	}
	peer := volumeserver.PeerIdentity{0x71}
	cred, err := a.AttachActiveForTest(2, peer, volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: base.Add(deadline)})
	if err != nil {
		t.Fatal(err)
	}
	h := testVolumeHandler()
	loadedCoordinationFor("", noopFencer{}, noopMembership{}, 16).Bind(h)
	store := &replayAdmissionStore{applicationOpenStore: applicationOpenStore{exists: true, size: 8, handles: make(map[xfsstore.Capability]xfsstore.Capability)}}
	h.Runtime, h.Store, h.Authorizer = a, store, allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
	h.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: clock})
	root := xfsstore.Capability{0x72}
	if err := h.startSessionResources(cred.ID, root, 2, routesRevisionOf("")); err != nil {
		t.Fatal(err)
	}
	if r := h.handleCoherenceSubscribe(0, cred.ID, &authoritypb.SubscribeRequest{}); r.GetErrno() != 0 {
		t.Fatal(r)
	}
	if err := h.trackItem(cred.ID, xfsstore.Capability{0x22}, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.FenceSession(cred.ID) })
	return h, context.WithValue(t.Context(), peerIdentityKey{}, [32]byte(peer)), cred, root, clock, store
}

type replayAdmissionStore struct {
	applicationOpenStore
	target    *writeTestTarget
	pages     int
	ioFailure error
}

func (s *replayAdmissionStore) LookupOpen(h xfsstore.Capability, n string) (xfsstore.Capability, xfsstore.Attr, error) {
	return s.Lookup(h, n)
}
func (s *replayAdmissionStore) ReadDirOpen(_ xfsstore.Capability, _ uint64, _ int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	s.pages++
	if s.ioFailure != nil {
		return nil, 0, [16]byte{}, false, xfsstore.Capability{}, s.ioFailure
	}
	return []xfsstore.Dirent{{Name: "file", Kind: xfsstore.KindRegular, Ino: 0x22, NextCookie: 1}}, 1, [16]byte{1}, true, xfsstore.Capability{0x72}, nil
}
func (s *replayAdmissionStore) PinWriteTarget(xfsstore.Capability) (xfsstore.WriteTarget, error) {
	return s.target, nil
}

func (s *replayAdmissionStore) CoordinateOpen(handle xfsstore.Capability) (xfsstore.ObjectCoordinate, error) {
	id, err := s.IdentityOpen(handle)
	return xfsstore.ObjectCoordinate{Stable: id, Ino: uint64(id[0]), DeviceMinor: 1}, err
}

func (s *replayAdmissionStore) CloseOpen(handle xfsstore.Capability) error {
	_ = s.applicationOpenStore.CloseOpen(handle)
	return s.ioFailure
}
func (s *replayAdmissionStore) Forget(item xfsstore.Capability) error {
	_ = s.resourceAdmissionFaultStore.Forget(item)
	return s.ioFailure
}
func (s *replayAdmissionStore) storageCalls() [7]uint32 {
	calls := [7]uint32{s.open.Load(), s.create.Load(), uint32(s.pages), s.closes.Load(), s.forget.Load(), s.durableVolumes.Load()}
	if s.target != nil {
		n, _ := s.target.commitSnapshot()
		calls[6] = uint32(n)
	}
	return calls
}

func replayAdmissionRequest(t *testing.T, h *VolumeHandler, ctx context.Context, cred volumeserver.SessionCredential, root xfsstore.Capability, s *replayAdmissionStore, kind string, failed bool) *authoritypb.Request {
	t.Helper()
	r := applicationRequest(cred, root, "open", false)
	handle := xfsstore.Capability{0x81}
	s.handles[handle] = xfsstore.Capability{0x22}
	if kind == "readdir" {
		s.handles[handle] = root
	}
	if err := h.trackOpen(cred.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	switch kind {
	case "open", "create":
		r = applicationRequest(cred, root, kind, false)
		if failed {
			s.preError = syscall.EACCES
		}
	case "readdir":
		r.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: handle[:], MaxEntries: 8, WantItems: true}}
		if failed {
			s.ioFailure = syscall.EACCES
		}
	case "close", "close_batch":
		target := handle[:]
		if failed {
			s.ioFailure = syscall.EINTR
		}
		closeRequest := &authoritypb.CloseRequest{Handle: target}
		if kind == "close" {
			r.Body = &authoritypb.Request_Close{Close: closeRequest}
		} else {
			r.Body = &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{Closes: []*authoritypb.CloseRequest{closeRequest}}}
		}
	case "reclaim":
		item := xfsstore.Capability{0x22}
		if failed {
			s.ioFailure = syscall.EACCES
		}
		r.Body = &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{item[:]}}}
	case "barrier":
		cut := uint64(0)
		if failed {
			cut = 1
		}
		r.Body = &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{CutSequence: cut}}
	case "ordered_write":
		token, _ := h.coherenceToken(cred.ID)
		grant, err := h.Coherence.DataMutated(ctx, token, [16]byte{0x22})
		if err != nil {
			t.Fatal(err)
		}
		s.target = &writeTestTarget{coordinate: xfsstore.ObjectCoordinate{Stable: [16]byte{0x22}, Ino: 0x22, DeviceMinor: 1}, committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x22, Size: 8, Mode: 0600, Nlink: 1, DeviceMinor: 1}}
		if failed {
			s.target.committed = 0
			s.target.err = syscall.ENOSPC
		}
		r.Body = &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: handle[:], Data: []byte("data"), Size: 4, Delegation: coherenceDelegationRefProto(grant), FlushSequence: 1}}
	default:
		t.Fatal(kind)
	}
	return r
}

// Inverted from the stopped-client reproduction: a lost recorded reply must
// settle before current subscription admission, in either cold-Subscribe order.
func TestMutationReplayPrecedesCoherenceAdmission(t *testing.T) {
	for _, elapsed := range []time.Duration{10 * time.Second, 15 * time.Second, 45 * time.Second, 119 * time.Second} {
		for _, coldFirst := range []bool{false, true} {
			for _, kind := range []string{"open", "create", "readdir", "close", "close_batch", "reclaim", "barrier", "ordered_write"} {
				for _, failed := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/cold_first_%t/%s/error_%t", elapsed, coldFirst, kind, failed), func(t *testing.T) {
						h, ctx, cred, root, clock, store := replayAdmissionHarness(t, time.Hour)
						request := replayAdmissionRequest(t, h, ctx, cred, root, store, kind, failed)
						executions := 0
						h.OnMutation = func(o MutationObservation) {
							if o.Disposition == "executed" {
								executions++
							}
						}
						first := h.Handle(ctx, request)
						if first.GetMutation().GetAcceptedSequence() != 1 {
							t.Fatalf("initial outcome not retained: %v", first)
						}
						errno := first.GetErrno()
						if kind == "close_batch" && len(first.GetCloseBatch().GetResults()) == 1 {
							errno = first.GetCloseBatch().Results[0].Errno
						}
						if kind == "ordered_write" && first.GetWrite() != nil {
							errno = -first.GetWrite().GetError()
						}
						if (errno != 0) != failed {
							t.Fatalf("unexpected initial outcome: %v", first)
						}
						storageCalls := store.storageCalls()
						if kind == "ordered_write" && storageCalls[6] != 1 {
							t.Fatalf("ordered flush storage executions=%d", storageCalls[6])
						}
						terminal, err := h.Runtime.SessionTerminal(cred.ID)
						if err != nil {
							t.Fatal(err)
						}
						oldToken, _ := h.coherenceToken(cred.ID)
						clock.advance(elapsed)
						if err := h.Coherence.CheckSession(oldToken); err == nil {
							t.Fatal("subscription did not expire")
						}
						cold := func() {
							if r := h.handleCoherenceSubscribe(90, cred.ID, &authoritypb.SubscribeRequest{}); r.GetErrno() != 0 {
								t.Fatal(r)
							}
						}
						if coldFirst {
							cold()
						}
						request.RequestId++
						replay := h.Handle(ctx, request)
						want := proto.Clone(first).(*authoritypb.Response)
						want.RequestId = request.RequestId
						if !proto.Equal(want, replay) {
							t.Fatalf("retained outcome changed\nwant %v\ngot  %v", want, replay)
						}
						local := clientSlot{}
						if err := synchronizeSlot(&local, 0, 1, replay.GetMutation()); err != nil || local.sequence != 1 {
							t.Fatalf("slot not settled: %d %v", local.sequence, err)
						}
						if store.storageCalls() != storageCalls {
							t.Fatalf("storage re-executed: before=%v after=%v", storageCalls, store.storageCalls())
						}
						if executions != 1 {
							t.Fatalf("storage executions=%d", executions)
						}
						if grant := applicationGrant(replay); grant != nil {
							id, err := parseCoherenceDelegationID(grant.Id)
							if err != nil {
								t.Fatal(err)
							}
							token, _ := h.coherenceToken(cred.ID)
							if _, err = h.Coherence.LookupOwnedDelegation(token, id, grant.Generation); err == nil {
								t.Fatal("retained grant revived")
							}
						}
						if !coldFirst {
							next := proto.Clone(request).(*authoritypb.Request)
							next.Mutation.Sequence = 2
							refused := h.Handle(ctx, next)
							if refused.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || refused.GetMutation() != nil || executions != 1 {
								t.Fatalf("new cold operation reached execution: %v", refused)
							}
							read := coherenceReadRequest(cred)
							read.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: root[:]}}
							if r := h.Handle(ctx, read); r.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
								t.Fatalf("cold read admitted: %v", r)
							}
							cold()
						}
						store.ioFailure = nil
						next := coherenceReadRequest(cred)
						next.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: local.sequence + 1}
						next.Body = &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{}}
						if result := h.Handle(ctx, next); result.GetErrno() != 0 || result.GetMutation().GetAcceptedSequence() != 2 {
							t.Fatalf("next operation: %v", result)
						}
						select {
						case <-terminal:
							t.Fatal("live runtime fenced")
						default:
						}
					})
				}
			}
		}
	}
}

func TestReplayAdmissionTerminalControls(t *testing.T) {
	for _, kind := range []string{"changed_body", "authentication", "epoch", "lease_120s", "authorization"} {
		t.Run(kind, func(t *testing.T) {
			deadline := time.Hour
			if kind == "authorization" {
				deadline = 15 * time.Second
			}
			h, ctx, cred, root, clock, _ := replayAdmissionHarness(t, deadline)
			r := applicationRequest(cred, root, "open", false)
			if first := h.Handle(ctx, r); first.GetMutation() == nil {
				t.Fatal(first)
			}
			terminal, _ := h.Runtime.SessionTerminal(cred.ID)
			clock.advance(15 * time.Second)
			switch kind {
			case "changed_body":
				r.GetOpen().Flags.Truncate = true
			case "authentication":
				r.Session.ResumeSecret = make([]byte, 32)
			case "epoch":
				r.Epoch = make([]byte, 16)
			case "lease_120s":
				clock.advance(105 * time.Second)
			}

			response := h.Handle(ctx, r)
			if response.GetErrno() == 0 || response.GetMutation() != nil {
				t.Fatalf("terminal/refused replay succeeded: %v", response)
			}
			if kind == "changed_body" || kind == "lease_120s" || kind == "authorization" {
				select {
				case <-terminal:
				default:
					t.Fatal("terminal condition left session live")
				}
			}
		})
	}
}

func TestReplayRuntimeLeaseBoundary(t *testing.T) {
	for _, elapsed := range []time.Duration{45 * time.Second, 119 * time.Second, 120 * time.Second, 121 * time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			h, _, cred, _, clock, _ := replayAdmissionHarness(t, time.Hour)
			terminal, _ := h.Runtime.SessionTerminal(cred.ID)
			clock.advance(elapsed)
			err := h.Runtime.Resume(cred)
			if elapsed < 2*time.Minute {
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-terminal:
					t.Fatal("live session ended")
				default:
				}
			} else if !errors.Is(err, volumeserver.ErrSessionExpired) {
				t.Fatalf("expired resume=%v", err)
			}
		})
	}
}

func TestColdReplayRejectsSequenceGapAndMutationHeaderReads(t *testing.T) {
	for _, kind := range []string{"gap", "getattr", "read"} {
		t.Run(kind, func(t *testing.T) {
			h, ctx, cred, root, clock, _ := replayAdmissionHarness(t, time.Hour)
			first := coherenceReadRequest(cred)
			first.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: 1}
			first.Body = &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{}}
			if r := h.Handle(ctx, first); r.GetMutation().GetAcceptedSequence() != 1 {
				t.Fatal(r)
			}
			clock.advance(15 * time.Second)
			r := proto.Clone(first).(*authoritypb.Request)
			r.Mutation.Sequence = 3
			switch kind {
			case "getattr":
				r.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: root[:]}}
			case "read":
				r.Body = &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: make([]byte, 16), Length: 1}}
			}
			terminal, _ := h.Runtime.SessionTerminal(cred.ID)
			response := h.Handle(ctx, r)
			if response.GetErrno() == 0 || response.GetMutation() != nil {
				t.Fatalf("cold request admitted: %v", response)
			}
			if kind == "gap" {
				select {
				case <-terminal:
				default:
					t.Fatal("cold sequence gap did not fence session")
				}
			} else {
				if response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
					t.Fatalf("header bypassed cold read admission: %v", response)
				}
				select {
				case <-terminal:
					t.Fatal("cold read ended live session")
				default:
				}
			}
		})
	}
}

func TestReplayOverlapsColdSubscribeRecallAndFence(t *testing.T) {
	for _, fence := range []bool{false, true} {
		t.Run(fmt.Sprintf("fence_%t", fence), func(t *testing.T) {
			h, ctx, cred, root, _, store := replayAdmissionHarness(t, time.Hour)
			r := applicationRequest(cred, root, "open", false)
			first := h.Handle(ctx, r)
			if first.GetErrno() != 0 || first.GetMutation() == nil || applicationGrant(first) == nil {
				t.Fatal(first)
			}
			calls := store.storageCalls()
			token, _ := h.coherenceToken(cred.ID)
			recallDone := make(chan error, 1)
			go func() { recallDone <- h.Coherence.Recall(ctx, [16]byte{0x22}) }()
			pollCtx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			events, _, err := h.Coherence.PollControl(pollCtx, token, 0, nil, 8)
			if err != nil || len(events) == 0 {
				t.Fatalf("recall did not enter: %v %v", events, err)
			}
			resolved, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			h.OnMutation = func(o MutationObservation) {
				if o.Disposition == "replayed" {
					close(resolved)
					<-release
				}
			}
			replayDone := make(chan *authoritypb.Response, 1)
			go func() { replayDone <- h.Handle(ctx, proto.Clone(r).(*authoritypb.Request)) }()
			select {
			case <-resolved:
			case <-time.After(time.Second):
				t.Fatal("recall blocked retained replay")
			}
			coldDone := make(chan *authoritypb.Response, 1)
			go func() { coldDone <- h.handleCoherenceSubscribe(0, cred.ID, &authoritypb.SubscribeRequest{}) }()
			select {
			case cold := <-coldDone:
				if cold.GetErrno() != 0 {
					t.Fatal(cold)
				}
			case <-time.After(time.Second):
				t.Fatal("cold subscribe blocked on retained replay/recall")
			}
			select {
			case err := <-recallDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cold subscribe did not settle recall")
			}
			fenced := make(chan struct{})
			if fence {
				go func() { h.Runtime.FenceSession(cred.ID); close(fenced) }()
			} else {
				close(fenced)
			}
			unblock()
			select {
			case replay := <-replayDone:
				if !proto.Equal(first, replay) {
					t.Fatalf("retained outcome changed: %v", replay)
				}
			case <-time.After(time.Second):
				t.Fatal("overlapped replay did not finish")
			}
			<-fenced
			h.OnMutation = nil
			after := store.storageCalls()
			for _, i := range []int{0, 1, 2, 5, 6} {
				if after[i] != calls[i] {
					t.Fatal("overlap re-executed storage")
				}
			}
			if fence {
				if replay := h.Handle(ctx, r); replay.GetErrno() == 0 || replay.GetMutation() != nil {
					t.Fatal("terminal fence admitted replay")
				}
			} else if replay := h.Handle(ctx, r); !proto.Equal(first, replay) {
				t.Fatal("cold subscribe rewrote retained outcome")
			}
		})
	}
}
