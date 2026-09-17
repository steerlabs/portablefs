package authorityrpc

import (
	"context"
	"errors"
	"google.golang.org/protobuf/proto"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type orderedCapabilityHandler struct {
	clientTestHandler
	enabled bool
}

func (h *orderedCapabilityHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	response := h.clientTestHandler.Handle(ctx, r)
	if h.enabled {
		if hello := response.GetHello(); hello != nil && hasFeatures(r.GetHello().Features, []string{orderedDelegatedFlushFeature}) {
			hello.Features = append(hello.Features, orderedDelegatedFlushFeature)
		}
		if active := response.GetActivate(); active != nil {
			active.Features = append(active.Features, orderedDelegatedFlushFeature)
		}
	}
	return response
}
func TestOrderedFlushNegotiatesIsolatedClientAndServerLanes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client int
		server bool
		want   bool
	}{{"legacy", 9, false, false}, {"ordered", 9, true, true}, {"small client", 3, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := &orderedCapabilityHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, enabled: tc.server}
			address, tls, stop := startTestServer(t, h, 9, time.Minute)
			defer stop()
			c, err := DialClient(t.Context(), coherentTestClientConfig(address, tls, "volume", uint32(tc.client), tc.client))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.SupportsOrderedFlush() != tc.want {
				t.Fatal("ordered capability ignored Hello/lane bound")
			}
			request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{FlushSequence: 1, Delegation: &authoritypb.DelegationRef{}}}}
			if tc.want {
				for _, metadata := range []*authoritypb.Request{
					{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Delegation: &authoritypb.DelegationRef{}}}},
					{Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{Delegation: &authoritypb.DelegationRef{}}}},
				} {
					if c.laneFor(metadata) != &c.ordered {
						t.Fatal("metadata bypassed shared server flush bound")
					}
				}
				if c.laneFor(request) != &c.ordered || cap(c.ordered.permits) != 4 || len(c.ordered.slots) != 4 || cap(c.ordinary.permits) != 1 || cap(c.blocking.permits) != 4 {
					t.Fatal("client lanes overlap or exceed negotiated bound")
				}
			} else if _, err := c.CallMutation(t.Context(), request); !errors.Is(err, syscall.EOPNOTSUPP) {
				t.Fatalf("unnegotiated ordinal dispatched: %v", err)
			}
		})
	}
	for _, ordered := range []bool{false, true} {
		ordinary, blocking, flush := serverExecutionLanes(9, authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES, ordered)
		wantFlush := 1
		if ordered {
			wantFlush = 4
		}
		if flush != wantFlush || ordinary+blocking+flush != 9 || ordinary < 1 || blocking != 4 {
			t.Fatalf("server lane mismatch: %d %d %d", ordinary, blocking, flush)
		}
	}
}
func TestTransportPairRefusesOrderedLaneModeMismatch(t *testing.T) {
	r, err := newTransportRegistry(4)
	if err != nil {
		t.Fatal(err)
	}
	peer, set := volumeserver.PeerIdentity{1}, connectionSetID{1}
	profile := authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES
	if _, err := r.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_DATA, profile, func() {}, func() error { return nil }, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, profile, func() {}, func() error { return nil }, false); !errors.Is(err, ErrTransportBinding) {
		t.Fatal("CONTROL changed ordered mode", err)
	}
	if _, err := r.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, profile, func() {}, func() error { return nil }, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_DATA, profile, func() {}, func() error { return nil }, false); !errors.Is(err, ErrTransportBinding) {
		t.Fatal("replacement changed ordered mode", err)
	}
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
	h := &orderedSocketHandler{orderedCapabilityHandler: orderedCapabilityHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 9}, enabled: true}, entered: make(chan uint64, 8), received: make(map[uint64]*authoritypb.Request), replayOne: replay}
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
