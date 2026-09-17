//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

func TestOrderedFlushMutationAppliesInAcceptedOrderAndReplaysOnce(t *testing.T) {
	h, cred, _ := newWriteHarness(t)
	token, _ := h.coherenceToken(cred.ID)
	grant, err := h.Coherence.DataMutated(t.Context(), token, [16]byte{0x41})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var mu sync.Mutex
	var order []uint64
	requests := make([]*authoritypb.Request, 4)
	replies := make(chan *authoritypb.Response, 4)
	entered := make(chan uint64, 4)
	for i := range requests {
		requests[i] = stockWriteTestRequest(uint64(i+1), uint32(i), 1, [16]byte{0x41}, []byte("data"), 0, 0)
		requests[i].GetWrite().Delegation = coherenceDelegationRefProto(grant)
		requests[i].GetWrite().FlushSequence = uint64(i + 1)
	}
	call := func(req *authoritypb.Request) *authoritypb.Response {
		return h.mutateOperation(ctx, req, cred, func(volumeserver.MutationID) *authoritypb.Response {
			seq := req.GetWrite().GetFlushSequence()
			mu.Lock()
			order = append(order, seq)
			mu.Unlock()
			entered <- seq
			return h.success(req.GetRequestId())
		}, nil)
	}
	for i := 3; i > 0; i-- {
		req := requests[i]
		go func() { replies <- call(req) }()
	}
	select {
	case n := <-entered:
		t.Fatalf("successor %d overtook missing first ordinal", n)
	case <-time.After(20 * time.Millisecond):
	}
	go func() { replies <- call(requests[0]) }()
	for range requests {
		select {
		case reply := <-replies:
			if reply.GetErrno() != 0 || reply.GetMutation() == nil {
				t.Fatalf("ordered result: %v", reply)
			}
		case <-ctx.Done():
			t.Fatal("ordered mutations stranded", ctx.Err())
		}
	}
	mu.Lock()
	for i, n := range order {
		if n != uint64(i+1) {
			t.Fatalf("storage order: %v", order)
		}
	}
	mu.Unlock()
	if reply := call(requests[1]); reply.GetErrno() != 0 || reply.GetMutation().GetAcceptedSequence() != 1 {
		t.Fatalf("exact replay: %v", reply)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 4 {
		t.Fatalf("replay applied a second time: %v", order)
	}
}

func TestOrderedFlushRecordedCapacityRefusalConsumesOrdinal(t *testing.T) {
	h, cred, _ := newWriteHarness(t)
	token, _ := h.coherenceToken(cred.ID)
	grant, err := h.Coherence.DataMutated(t.Context(), token, [16]byte{0x41})
	if err != nil {
		t.Fatal(err)
	}
	request := func(n uint64) *authoritypb.Request {
		r := stockWriteTestRequest(n, uint32(n-1), 1, [16]byte{0x41}, []byte("data"), 0, 0)
		r.GetWrite().Delegation, r.GetWrite().FlushSequence = coherenceDelegationRefProto(grant), n
		return r
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	later := make(chan *authoritypb.Response, 1)
	var applied atomic.Int32
	go func() {
		r := request(2)
		later <- h.mutateOperation(ctx, r, cred, func(volumeserver.MutationID) *authoritypb.Response { applied.Add(1); return h.success(r.RequestId) }, nil)
	}()
	first := request(1)
	reply := h.mutateOperation(ctx, first, cred, func(volumeserver.MutationID) *authoritypb.Response {
		return h.errorResponse(first.RequestId, syscall.ENOSPC, false)
	}, nil)
	if reply.GetErrno() != int32(syscall.ENOSPC) || reply.GetMutation() == nil {
		t.Fatalf("capacity outcome not retained: %v", reply)
	}
	select {
	case reply = <-later:
		if reply.GetErrno() != 0 || reply.GetMutation() == nil || applied.Load() != 1 {
			t.Fatalf("successor not applied: %v", reply)
		}
	case <-ctx.Done():
		t.Fatal("recorded capacity refusal stranded successor")
	}
	if got, ok := h.Coherence.LookupDelegation(grant.Identity); !ok || got.ID != grant.ID {
		t.Fatal("recorded capacity refusal retired the grant")
	}
}

func TestOrderedFlushReplyAdmissionRefusalRetiresPendingSuccessors(t *testing.T) {
	h, cred, _ := newWriteHarness(t)
	token, _ := h.coherenceToken(cred.ID)
	grant, err := h.Coherence.DataMutated(t.Context(), token, [16]byte{0x41})
	if err != nil {
		t.Fatal(err)
	}
	successor, err := h.Coherence.BeginOrderedFlush(token, grant.ID, grant.Generation, 2, volumeserver.MutationID{Slot: 1, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Abort()
	h.MaxRetainedReplyBytes = 0
	r := stockWriteTestRequest(1, 0, 1, [16]byte{0x41}, []byte("data"), 0, 0)
	r.GetWrite().Delegation, r.GetWrite().FlushSequence = coherenceDelegationRefProto(grant), 1
	reply := h.mutateOperation(t.Context(), r, cred, func(volumeserver.MutationID) *authoritypb.Response {
		t.Error("unadmitted ordinal reached storage")
		return h.success(1)
	}, nil)
	if reply.GetWrite().GetError() != -int32(syscall.ENOMEM) || reply.GetMutation() != nil {
		t.Fatalf("expected unrecorded admission refusal: %v", reply)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := successor.Wait(ctx); !errors.Is(err, volumeserver.ErrDelegationStale) {
		t.Fatalf("successor not retired: %v", err)
	}
	if _, ok := h.Coherence.LookupDelegation(grant.Identity); ok {
		t.Fatal("unrecorded gap retained grant")
	}
}

func TestOrderedFlushAuthenticatedPreReplayRefusalRetiresGrant(t *testing.T) {
	for _, negotiated := range []bool{false, true} {
		t.Run(fmt.Sprint(negotiated), func(t *testing.T) {
			h, cred, _ := newWriteHarness(t)
			h.Authorizer, h.Routes = allowAuthorizer{access: volumeserver.AccessRead | volumeserver.AccessWrite}, &RoutesController{Mounts: h.Lifecycle, loaded: true}
			token, _ := h.coherenceToken(cred.ID)
			grant, err := h.Coherence.DataMutated(t.Context(), token, [16]byte{0x41})
			if err != nil {
				t.Fatal(err)
			}
			r := stockWriteTestRequest(1, 0, 1, [16]byte{0x41}, []byte("data"), 0, 0)
			r.Epoch, r.Session, r.Mutation = cred.Epoch[:], &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]}, nil
			r.GetWrite().Delegation, r.GetWrite().FlushSequence = coherenceDelegationRefProto(grant), 1
			ctx := withTransportConnection(context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{1}), &transportConnection{orderedFlush: negotiated})
			reply := h.Handle(ctx, r)
			want := syscall.EINVAL
			if !negotiated {
				want = syscall.EOPNOTSUPP
			}
			if reply.GetErrno() != int32(want) || reply.GetMutation() != nil {
				t.Fatalf("pre-replay refusal: %v", reply)
			}
			if _, ok := h.Coherence.LookupDelegation(grant.Identity); ok {
				t.Fatal("refused ordinal retained a permanent gap")
			}
		})
	}
}

func TestOrderedFlushStorageCannotPinSuccessorBeforePredecessorCompletes(t *testing.T) {
	h, cred, store := newWriteHarness(t)
	token, _ := h.coherenceToken(cred.ID)
	grant, err := h.Coherence.DataMutated(t.Context(), token, [16]byte{0x41})
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	first := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}, started: entered, release: release}
	second := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}}
	handle := prepareOneShotTarget(t, h, cred, store, first)
	store.targets = append(store.targets, second)
	request := func(n uint64) *authoritypb.Request {
		r := stockWriteTestRequest(n, uint32(n-1), 1, handle, []byte("data"), 0, 0)
		r.GetWrite().Delegation, r.GetWrite().FlushSequence = coherenceDelegationRefProto(grant), n
		return r
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	responses := make(chan *authoritypb.Response, 2)
	go func() { r := request(2); responses <- h.handleWrite(ctx, r, cred, r.GetWrite()) }()
	select {
	case <-entered:
		close(release)
		t.Fatal("successor reached storage before missing predecessor")
	case <-time.After(20 * time.Millisecond):
	}
	go func() { r := request(1); responses <- h.handleWrite(ctx, r, cred, r.GetWrite()) }()
	waitWriteTestSignal(t, entered, "predecessor storage")
	store.mu.Lock()
	remaining := len(store.targets)
	store.mu.Unlock()
	if remaining != 1 {
		close(release)
		t.Fatal("successor pinned storage while predecessor remained active")
	}
	close(release)
	for range 2 {
		select {
		case r := <-responses:
			if r.GetErrno() != 0 || r.GetWrite().GetCommittedSize() != 4 || r.GetMutation() == nil {
				t.Fatalf("write failed: %v", r)
			}
		case <-ctx.Done():
			t.Fatal("storage wave stranded")
		}
	}
	r := request(1)
	if reply := h.handleWrite(ctx, r, cred, r.GetWrite()); reply.GetErrno() != 0 || reply.GetAppliedSequence() != 1 {
		t.Fatalf("replay: %v", reply)
	}
	for _, target := range []*writeTestTarget{first, second} {
		if n, _ := target.commitSnapshot(); n != 1 {
			t.Fatalf("storage calls=%d", n)
		}
	}
}
