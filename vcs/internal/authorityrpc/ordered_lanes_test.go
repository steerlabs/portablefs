package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type recallProgressHandler struct {
	orderedCapabilityHandler
	entered chan struct{}
	release chan struct{}
}

func (h *recallProgressHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	if r.GetRead() != nil {
		h.entered <- struct{}{}
		select {
		case <-h.release:
		case <-ctx.Done():
		}
		return &authoritypb.Response{RequestId: r.RequestId, Epoch: h.Epoch(), Errno: int32(syscall.EIO)}
	}
	if r.GetWrite() != nil {
		return &authoritypb.Response{RequestId: r.RequestId, Epoch: h.Epoch(), Mutation: &authoritypb.MutationState{Slot: r.GetMutation().GetSlot(), AcceptedSequence: r.GetMutation().GetSequence()}, Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{CommittedSize: 1}}}
	}
	return h.orderedCapabilityHandler.Handle(ctx, r)
}

func TestDelegatedFlushProgressUnderOrdinarySaturation(t *testing.T) {
	for _, limit := range []int{9, 128} {
		{
			t.Run(fmt.Sprintf("slots=%d", limit), func(t *testing.T) {
				h := &recallProgressHandler{
					orderedCapabilityHandler: orderedCapabilityHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: limit}},
					entered:                  make(chan struct{}, limit), release: make(chan struct{}),
				}
				address, tls, stop := startTestServer(t, h, limit, time.Minute)
				defer stop()
				c, err := DialClient(t.Context(), coherentTestClientConfig(address, tls, "volume", uint32(limit), limit))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				var reads sync.WaitGroup
				defer func() { close(h.release); reads.Wait() }()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				for range cap(c.ordinary.permits) {
					reads.Go(func() {
						_, _ = c.Call(ctx, &authoritypb.Request{Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: make([]byte, 16), Length: 1}}})
					})
					select {
					case <-h.entered:
					case <-ctx.Done():
						t.Fatal("ordinary calls exceeded the server's matching lane")
					}
				}
				for _, request := range []*authoritypb.Request{
					{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Delegation: &authoritypb.DelegationRef{}}}},
					{Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{Delegation: &authoritypb.DelegationRef{}}}},
				} {
					if c.laneFor(request) != &c.flush {
						t.Fatal("delegated metadata did not share independent flush admission")
					}
				}
				reply, err := c.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: make([]byte, 16), Data: []byte("x"), Size: 1, Delegation: &authoritypb.DelegationRef{Id: make([]byte, 16), Generation: 1}}}})
				if err != nil || reply.GetWrite().GetCommittedSize() != 1 {
					t.Fatalf("flush could not progress while ordinary calls waited: %v, %v", reply, err)
				}
				ordinary, blocking, flush := executionLanes(limit, c.cfg.FrontendProfile, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
				if cap(c.ordinary.permits) != ordinary || cap(c.blocking.permits) != blocking || cap(c.flush.permits) != flush || ordinary+blocking+flush != limit {
					t.Fatal("client and server execution budgets differ")
				}
			})
		}
	}
}

type orderedCapabilityHandler struct{ clientTestHandler }

func (h *orderedCapabilityHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	return h.clientTestHandler.Handle(ctx, r)
}

type orderedSocketHandler struct {
	orderedCapabilityHandler
	entered     chan uint64
	predecessor [5]chan struct{}
	mu          sync.Mutex
	received    map[uint64]*authoritypb.Request
	replayOne   bool
}

func (h *orderedSocketHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	w := r.GetWrite()
	if w == nil {
		return h.orderedCapabilityHandler.Handle(ctx, r)
	}
	n := w.GetFlushSequence()
	h.mu.Lock()
	prior := h.received[n]
	if prior == nil {
		h.received[n] = proto.Clone(r).(*authoritypb.Request)
	}
	h.mu.Unlock()
	if prior == nil {
		h.entered <- n
		select {
		case <-h.predecessor[n-1]:
		case <-ctx.Done():
			return &authoritypb.Response{RequestId: r.RequestId, Epoch: h.Epoch(), Errno: int32(syscall.EIO)}
		}
		close(h.predecessor[n])
		if h.replayOne && n == 1 {
			entry, _ := transportConnectionFromContext(ctx)
			_ = entry.close()
		}
	}
	return &authoritypb.Response{RequestId: r.RequestId, Epoch: h.Epoch(), Mutation: &authoritypb.MutationState{Slot: r.GetMutation().GetSlot(), AcceptedSequence: r.GetMutation().GetSequence()}, Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{CommittedSize: uint64(len(w.Data))}}}
}
func newOrderedSocketHandler(replay bool) *orderedSocketHandler {
	h := &orderedSocketHandler{orderedCapabilityHandler: orderedCapabilityHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}}, entered: make(chan uint64, 8), received: make(map[uint64]*authoritypb.Request), replayOne: replay}
	for i := range h.predecessor {
		h.predecessor[i] = make(chan struct{})
	}
	close(h.predecessor[0])
	return h
}
func TestOrderedFlushSocketLanesAdmitMissingPredecessor(t *testing.T) {
	h := newOrderedSocketHandler(false)
	address, tls, stop := startTestServer(t, h, 9, time.Minute)
	defer stop()
	c, err := DialClient(t.Context(), coherentTestClientConfig(address, tls, "volume", 9, 9))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 4)
	for _, n := range []uint64{2, 3, 4, 1} {
		go func() {
			r := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Size: 4, FlushSequence: n, Delegation: &authoritypb.DelegationRef{Id: make([]byte, 16), Generation: 1}}}}
			reply, err := c.CallMutationSegments(ctx, r, [][]byte{[]byte("ab"), []byte("cd")}, nil)
			if err == nil && reply.GetWrite().GetCommittedSize() != 4 {
				err = errors.New("scatter payload lost")
			}
			done <- err
		}()
		select {
		case got := <-h.entered:
			if got != n {
				t.Fatalf("arrival=%d want %d", got, n)
			}
		case <-ctx.Done():
			t.Fatal("server lane starvation before predecessor", n)
		}
	}
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for n, r := range h.received {
		if string(r.GetWrite().Data) != "abcd" {
			t.Fatalf("ordinal %d payload=%q", n, r.GetWrite().Data)
		}
	}
}
func TestSegmentedMutationRetainsPayloadAndIdentityAcrossReconnect(t *testing.T) {
	h := newOrderedSocketHandler(true)
	address, tls, stop := startTestServer(t, h, 9, time.Minute)
	defer stop()
	c, err := DialClient(t.Context(), coherentTestClientConfig(address, tls, "volume", 9, 9))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	r := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Size: 6, FlushSequence: 1, Delegation: &authoritypb.DelegationRef{Id: make([]byte, 16), Generation: 1}}}}
	assigned := 0
	reply, err := c.CallMutationSegments(ctx, r, [][]byte{[]byte("one"), []byte("two")}, func(MutationIdentity) error { assigned++; return nil })
	if err != nil || reply.GetWrite().GetCommittedSize() != 6 || assigned != 1 {
		t.Fatalf("replayed scatter: %v %v assigned=%d", reply, err, assigned)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	original := h.received[1]
	if string(original.GetWrite().Data) != "onetwo" || !proto.Equal(original.Mutation, r.Mutation) || len(r.GetWrite().Data) != 0 {
		t.Fatal("reconnect changed immutable payload or replay identity")
	}
}
