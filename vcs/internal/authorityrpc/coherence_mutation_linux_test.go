//go:build linux

package authorityrpc

import (
	"context"
	"io/fs"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

func TestCoherenceStaleFlushRefusedWhole(t *testing.T) {
	for _, kind := range []string{"write", "setattr", "fallocate"} {
		t.Run(kind, func(t *testing.T) {
			h, cred, store := newWriteHarness(t)
			target := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}}
			handle := prepareOneShotTarget(t, h, cred, store, target)
			token, _ := h.coherenceToken(cred.ID)
			delegation, err := h.Coherence.DataMutated(t.Context(), token, [16]byte{0x41})
			if err != nil {
				t.Fatal(err)
			}
			stale := &authoritypb.DelegationRef{Id: coherenceDelegationID(delegation.ID), Generation: delegation.Generation + 1}
			req := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
			req.GetWrite().Delegation = stale
			var result *authoritypb.Response
			switch kind {
			case "write":
				result = h.handleWrite(t.Context(), req, cred, req.GetWrite())
			case "setattr":
				req.Body = &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Handle: handle[:], Size: proto.Int64(0), Delegation: stale}}
				result = h.mutateCoherenceVisibleSequenceResolved(t.Context(), req, cred, func(*operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
					t.Fatal("stale SETATTR reached storage preparation")
					return nil, nil
				}, func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
					t.Fatal("stale SETATTR applied")
					return nil, nil
				})
			case "fallocate":
				req.Body = &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{Handle: handle[:], Length: 4, Delegation: stale}}
				result = h.mutateCoherenceVisibleSequenceResolved(t.Context(), req, cred, func(*operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
					t.Fatal("stale FALLOCATE reached storage preparation")
					return nil, nil
				}, func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
					t.Fatal("stale FALLOCATE applied")
					return nil, nil
				})
			}
			if result.GetErrno() != int32(syscall.EIO) || result.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || result.GetAppliedSequence() != 0 {
				t.Fatalf("stale refusal = %v", result)
			}
			if calls, _ := target.commitSnapshot(); calls != 0 {
				t.Fatalf("stale flush applied %d times", calls)
			}
		})
	}
}

func TestCoherenceAppliedReceiptPrecedesPeerWithdrawal(t *testing.T) {
	h, cred, store := newWriteHarness(t)
	token, _ := h.coherenceToken(cred.ID)
	delegation, err := h.Coherence.DataMutated(t.Context(), token, [16]byte{0x41})
	if err != nil {
		t.Fatal(err)
	}
	target := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}}
	handle := prepareOneShotTarget(t, h, cred, store, target)
	peer, err := h.Coherence.Subscribe(volumeserver.SessionID{9})
	if err != nil {
		t.Fatal(err)
	}
	req := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
	req.GetWrite().Delegation = coherenceDelegationRefProto(delegation)
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.handleWrite(t.Context(), req, cred, req.GetWrite()) }()
	var result *authoritypb.Response
	select {
	case result = <-done:
	case <-time.After(time.Second):
		t.Fatal("application receipt waited for peer withdrawal")
	}
	if result.GetErrno() != 0 || result.GetAppliedSequence() != 1 || result.GetWrite().GetCommittedSize() != 4 {
		t.Fatalf("applied result = %v", result)
	}
	events, err := h.Coherence.Poll(t.Context(), peer.Token, peer.Position, nil, 32)
	if err != nil || len(events) == 0 {
		t.Fatalf("changes=%v, err=%v", events, err)
	}
	position := events[len(events)-1].Position
	waiting := make(chan error, 1)
	go func() { waiting <- h.Coherence.WaitWithdrawn(context.Background(), position, cred.ID) }()
	select {
	case err := <-waiting:
		t.Fatalf("unacked peer became visible: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if err := h.Coherence.Ack(peer.Token, position); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiting:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("acked change did not become visible")
	}
	replay := h.handleWrite(t.Context(), req, cred, req.GetWrite())
	if replay.GetAppliedSequence() != 1 {
		t.Fatalf("replay ticket = %d", replay.GetAppliedSequence())
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("replay applied %d times", calls)
	}
}

func TestCoherenceChangeCoordinates(t *testing.T) {
	parent, child := [16]byte{1}, [16]byte{2}
	targets := []volumeserver.VisibilityTarget{{Scope: volumeserver.VisibilityNamespace, ParentIdentity: parent, Name: []byte("child")}, {Scope: volumeserver.VisibilityAttributes, Identity: parent}, {Scope: volumeserver.VisibilityData, Identity: child}}
	req := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{}}}
	resp := &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{AssignedOffset: 3, CommittedSize: 7}}}
	entries := coherenceChanges(req, resp, targets, 8)
	if len(entries) != 4 {
		t.Fatalf("changes = %+v", entries)
	}
	for _, e := range entries {
		if e.VolumeVersion != 8 {
			t.Fatalf("wrong version %+v", e)
		}
		if e.Kind == volumeserver.DataChanged && (!e.HasRange || e.Offset != 3 || e.Length != 7) {
			t.Fatalf("wrong range %+v", e)
		}
	}
}

func TestCoherenceSynchronousWriteLeavesNoUnknownDelegation(t *testing.T) {
	h, cred, store := newWriteHarness(t)
	target := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}}
	handle := prepareOneShotTarget(t, h, cred, store, target)
	req := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
	reply := h.handleWrite(t.Context(), req, cred, req.GetWrite())
	if reply.GetErrno() != 0 || reply.GetAppliedSequence() != 1 {
		t.Fatalf("write = %v", reply)
	}
	if grant, ok := h.Coherence.LookupDelegation([16]byte{0x41}); ok {
		t.Fatalf("synchronous write leaked grant %+v", grant)
	}
}

func BenchmarkCoherenceHandlerOnCommit(b *testing.B) {
	c := volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{})
	request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{}}}
	response := &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{CommittedSize: 4096}}}
	targets := []volumeserver.VisibilityTarget{{Scope: volumeserver.VisibilityData, Identity: [16]byte{1}}, {Scope: volumeserver.VisibilityAttributes, Identity: [16]byte{1}}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.OnCommit(coherenceChanges(request, response, targets, uint64(i+1)))
	}
}

type coherenceOpenStore struct {
	resourceAdmissionFaultStore
	closes int
}

func (s *coherenceOpenStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.open.Add(1)
	return xfsstore.Capability{0x22}, nil
}
func (s *coherenceOpenStore) CloseOpen(xfsstore.Capability) error { s.closes++; return nil }

func TestCoherenceCacheOpenCloseReplayAccounting(t *testing.T) {
	store := &coherenceOpenStore{}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	req := coherenceReadRequest(cred)
	req.Mutation = &authoritypb.Mutation{Sequence: 1}
	req.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: root[:], Flags: &authoritypb.OpenFlags{Read: true}, CacheCapable: true}}
	first := h.Handle(ctx, req)
	if first.GetErrno() != 0 || !first.GetOpen().GetCacheCapable() {
		t.Fatalf("open = %v", first)
	}
	replay := h.Handle(ctx, req)
	if !proto.Equal(first, replay) || store.open.Load() != 1 {
		t.Fatalf("open replay %v, calls=%d", replay, store.open.Load())
	}
	closeReq := coherenceReadRequest(cred)
	closeReq.Mutation = &authoritypb.Mutation{Sequence: 2}
	closeReq.Body = &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: first.GetOpen().GetHandle()}}
	if r := h.Handle(ctx, closeReq); r.GetErrno() != 0 {
		t.Fatal(r)
	}
	if r := h.Handle(ctx, closeReq); r.GetErrno() != 0 {
		t.Fatal(r)
	}
	if store.closes != 1 {
		t.Fatalf("close replay retired handle %d times", store.closes)
	}
	h.resourcesMu.Lock()
	count := len(h.resources[cred.ID].cacheOpens)
	h.resourcesMu.Unlock()
	if count != 0 {
		t.Fatalf("%d cache handles survived close", count)
	}
}

type coherenceCreateStore struct {
	resourceAdmissionFaultStore
	h       *VolumeHandler
	entered chan bool
	proceed chan struct{}
	bound   atomic.Bool
	lookups atomic.Uint32
}

func (s *coherenceCreateStore) Create(xfsstore.Capability, string, fs.FileMode, bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.bound.Store(true)
	return xfsstore.Capability{0x22}, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x22, Mode: 0600, Nlink: 1, DeviceMinor: 1}, nil
}
func (s *coherenceCreateStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	d, ok := s.h.Coherence.LookupDelegation([16]byte{0x22})
	s.entered <- ok && d.State == volumeserver.DelegationReserved
	<-s.proceed
	return xfsstore.Capability{0x23}, nil
}
func (s *coherenceCreateStore) Lookup(xfsstore.Capability, string) (xfsstore.Capability, xfsstore.Attr, error) {
	s.lookups.Add(1)
	if !s.bound.Load() {
		return xfsstore.Capability{}, xfsstore.Attr{}, syscall.ENOENT
	}
	return xfsstore.Capability{0x22}, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x22, Mode: 0600, Nlink: 1, DeviceMinor: 1}, nil
}
func (s *coherenceCreateStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if item[0] == 0x22 {
		return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x22, Mode: 0600, Nlink: 1, DeviceMinor: 1}, nil
	}
	return xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: uint64(item[0]), Mode: 0700, Nlink: 1, DeviceMinor: 1}, nil
}
func (s *coherenceCreateStore) CloseOpen(xfsstore.Capability) error { return nil }

func TestCoherenceCreateReservesBeforeBindingPublication(t *testing.T) {
	store := &coherenceCreateStore{entered: make(chan bool, 1), proceed: make(chan struct{})}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	store.h = h
	create := coherenceReadRequest(cred)
	create.Mutation = &authoritypb.Mutation{Sequence: 1}
	create.Body = &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: root[:], Name: []byte("new"), Mode: 0600, Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true, CacheCapable: true}}
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.Handle(ctx, create) }()
	select {
	case reserved := <-store.entered:
		if !reserved {
			t.Fatal("created identity was exposed to open before ReserveNew")
		}
	case <-time.After(time.Second):
		t.Fatal("create did not enter store")
	}
	before := store.lookups.Load()
	lookup := coherenceReadRequest(cred)
	lookup.RequestId++
	lookup.Mutation = &authoritypb.Mutation{Slot: 1, Sequence: 1}
	lookup.Body = &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: root[:], Name: []byte("new")}}
	looked := make(chan *authoritypb.Response, 1)
	go func() { looked <- h.Handle(ctx, lookup) }()
	select {
	case r := <-looked:
		t.Fatalf("lookup crossed CREATE publication exclusion: %v", r)
	case <-time.After(20 * time.Millisecond):
	}
	if store.lookups.Load() != before {
		t.Fatal("peer resolved new binding before publication exclusion released")
	}
	close(store.proceed)
	select {
	case r := <-done:
		if r.GetErrno() != 0 || r.GetCreate().GetDelegation() == nil || r.GetCreate().GetCacheCapable() {
			t.Fatalf("create reply=%v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("create did not finish")
	}
	select {
	case r := <-looked:
		if r.GetErrno() != 0 || r.GetLookup().GetItem() == nil {
			t.Fatalf("lookup reply=%v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("lookup did not finish")
	}
}

func TestCoherenceNoOpWriteReportsExistingDurablePrefix(t *testing.T) {
	h := &VolumeHandler{}
	h.initCoherence()
	session, identity := volumeserver.SessionID{1}, [16]byte{2}
	h.coherenceDurability.recordApplied(session, identity, 1)
	h.Coherence.DurableSequence(1)
	request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{}}}
	response := &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{}}}
	if position := h.publishCoherenceCommit(request, session, identity, 1, response, nil); position != 0 {
		t.Fatalf("no-op position = %d", position)
	}
	if response.GetAppliedSequence() != 0 || response.GetWrite().GetDurableSequence() != 1 {
		t.Fatalf("no-op receipt = %v", response)
	}
}

func TestCoherenceRecallFlushPassesPendingMacActivation(t *testing.T) {
	h, cred, store := newWriteHarness(t)
	token, _ := h.coherenceToken(cred.ID)
	identity := [16]byte{0x41}
	grant, err := h.Coherence.DataMutated(t.Context(), token, identity)
	if err != nil {
		t.Fatal(err)
	}
	target := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}}
	handle := prepareOneShotTarget(t, h, cred, store, target)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	recalled := make(chan error, 1)
	go func() {
		h.coherenceProfileAdmission.Lock()
		defer h.coherenceProfileAdmission.Unlock()
		recalled <- h.Coherence.Recall(ctx, identity)
	}()
	var event volumeserver.StreamEvent
	var cursor uint64
	for event.Kind != volumeserver.StreamRecall {
		events, err := h.Coherence.Poll(ctx, token, cursor, nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		for _, next := range events {
			cursor = next.Position
			if next.Kind == volumeserver.StreamRecall {
				event = next
			}
		}
	}
	req := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
	req.GetWrite().Delegation = coherenceDelegationRefProto(grant)
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.handleWrite(ctx, req, cred, req.GetWrite()) }()
	var response *authoritypb.Response
	select {
	case response = <-done:
	case <-ctx.Done():
		t.Fatal("Mac activation blocked the flush needed by its recall")
	}
	if response.GetErrno() != 0 || response.GetAppliedSequence() != 1 {
		t.Fatalf("flush = %v", response)
	}
	if err := h.Coherence.AckDelegation(token, identity, grant.ID, grant.Generation, event.Request, response.GetAppliedSequence()); err != nil {
		t.Fatal(err)
	}
	if err := <-recalled; err != nil {
		t.Fatal(err)
	}
	if _, live := h.Coherence.LookupDelegation(identity); live {
		t.Fatal("Mac activation left a live Linux delegation")
	}
}

func TestLinuxV7MutationRefusedBeforeApplyByActiveMacCompatibilityWriter(t *testing.T) {
	h, cred, store := newWriteHarness(t)
	mac, err := h.Runtime.AttachActiveForTest(4, volumeserver.PeerIdentity{2}, volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := h.Runtime.SessionTerminal(mac.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Visibility.Register(mac.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 16, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairCallbackSerializedPipelined, CompatibilityWriter: true,
	}); err != nil {
		t.Fatal(err)
	}
	target := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}}
	handle := prepareOneShotTarget(t, h, cred, store, target)
	req := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
	response := h.handleWrite(t.Context(), req, cred, req.GetWrite())
	if response.GetErrno() != int32(syscall.EBUSY) || response.GetAppliedSequence() != 0 || response.GetMutation() != nil {
		t.Fatalf("Mac exclusion=%v", response)
	}
	if calls, _ := target.commitSnapshot(); calls != 0 {
		t.Fatal("excluded Linux write reached storage")
	}
	h.Visibility.Fence(mac.ID, volumeserver.ErrVisibilityLost)
	response = h.handleWrite(t.Context(), req, cred, req.GetWrite())
	if response.GetErrno() != 0 || response.GetAppliedSequence() != 1 {
		t.Fatalf("write after Mac departure=%v", response)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("applies=%d", calls)
	}
	if h.strictCache(cred.ID) != nil {
		t.Fatal("Linux entered Mac read repair")
	}
}

func TestLinuxV7MutationHoldsMacAdmissionThroughStorageApply(t *testing.T) {
	h, cred, store := newWriteHarness(t)
	target := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}, started: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-target.release:
		default:
			close(target.release)
		}
	}()
	handle := prepareOneShotTarget(t, h, cred, store, target)
	req := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.handleWrite(t.Context(), req, cred, req.GetWrite()) }()
	waitWriteTestSignal(t, target.started, "Linux storage apply")
	admitted := make(chan struct{})
	attempting := make(chan struct{})
	go func() {
		close(attempting)
		h.coherenceProfileAdmission.Lock()
		close(admitted)
		h.coherenceProfileAdmission.Unlock()
	}()
	<-attempting
	select {
	case <-admitted:
		t.Fatal("Mac activation passed live Linux apply")
	case <-time.After(20 * time.Millisecond):
	}
	close(target.release)
	select {
	case response := <-done:
		if response.GetErrno() != 0 {
			t.Fatal(response)
		}
	case <-time.After(time.Second):
		t.Fatal("Linux write did not finish")
	}
	waitWriteTestSignal(t, admitted, "Mac admission after Linux apply")
}

func TestLinuxV7PreparationCannotEscapeStorageDependencies(t *testing.T) {
	h, cred, store := newWriteHarness(t)
	handle := prepareOneShotTarget(t, h, cred, store, &writeTestTarget{})
	req := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
	response := h.mutateCoherenceVisibleSequenceResolved(t.Context(), req, cred, func(*operationResolutionContext) ([]volumeserver.VisibilityTarget, error) {
		return []volumeserver.VisibilityTarget{{Scope: volumeserver.VisibilityAttributes, Identity: [16]byte{0x99}}}, nil
	}, func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		t.Fatal("uncovered preparation applied")
		return nil, nil
	})
	if response.GetErrno() == 0 || response.GetAppliedSequence() != 0 {
		t.Fatalf("uncovered preparation=%v", response)
	}
}

func TestCoherenceSetAttrRequiresItemOrHandle(t *testing.T) {
	for _, test := range []struct {
		name string
		set  *authoritypb.SetAttrRequest
	}{
		{"mode", &authoritypb.SetAttrRequest{Mode: proto.Uint32(0600)}},
		{"uid", &authoritypb.SetAttrRequest{Uid: proto.Uint32(1000)}},
		{"gid", &authoritypb.SetAttrRequest{Gid: proto.Uint32(1000)}},
		{"atime", &authoritypb.SetAttrRequest{AtimeNs: proto.Int64(1)}},
		{"mtime", &authoritypb.SetAttrRequest{MtimeNs: proto.Int64(1)}},
		{"atime-now", &authoritypb.SetAttrRequest{AtimeNow: true}},
		{"mtime-now", &authoritypb.SetAttrRequest{MtimeNow: true}},
		{"size", &authoritypb.SetAttrRequest{Size: proto.Int64(0)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &resourceAdmissionFaultStore{}
			h, ctx, credential, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
			request := coherenceReadRequest(credential)
			request.Mutation = &authoritypb.Mutation{Sequence: 1}
			request.Body = &authoritypb.Request_SetAttr{SetAttr: test.set}
			response := h.Handle(ctx, request)
			if response.GetErrno() != int32(syscall.EINVAL) || response.GetAppliedSequence() != 0 || response.GetPostState() != nil {
				t.Fatalf("unauthorized SETATTR = %v, want unapplied EINVAL", response)
			}
		})
	}
}
