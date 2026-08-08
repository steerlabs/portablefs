package authorityrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

type shortWriter struct {
	bytes.Buffer
	max int
}

func (w *shortWriter) Write(value []byte) (int, error) {
	if len(value) > w.max {
		value = value[:w.max]
	}
	return w.Buffer.Write(value)
}

func TestWriteFrameCompletesShortWrites(t *testing.T) {
	writer := &shortWriter{max: 2}
	want := &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}
	if err := writeFrame(writer, 4096, want); err != nil {
		t.Fatal(err)
	}
	var got authoritypb.Request
	if err := readFrame(bytes.NewReader(writer.Bytes()), 4096, nil, 0, &got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(want, &got) {
		t.Fatalf("round trip = %v, want %v", &got, want)
	}
}

func TestFrameRoundTripAndBound(t *testing.T) {
	request := &authoritypb.Request{RequestId: 42, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: 1}}}
	var frame bytes.Buffer
	if err := writeFrame(&frame, 1024, request); err != nil {
		t.Fatal(err)
	}
	var decoded authoritypb.Request
	if err := readFrame(&frame, 1024, nil, 0, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetRequestId() != 42 || decoded.GetHello().GetProtocolMajor() != 1 {
		t.Fatalf("decoded=%v", &decoded)
	}

	var oversized bytes.Buffer
	_ = binary.Write(&oversized, binary.BigEndian, uint32(1025))
	if err := readFrame(&oversized, 1024, nil, 0, &decoded); !errors.Is(err, ErrFrameBounds) {
		t.Fatalf("readFrame=%v", err)
	}
}

// Defect 10: post-authentication payload allocation had no worker-wide byte
// bound, only MaxConnections multiplied by the largest legal frame.
func TestFrameBudgetBoundsConcurrentAllocation(t *testing.T) {
	request := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: 1}}}
	var frame bytes.Buffer
	if err := writeFrame(&frame, 1024, request); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(frame.Bytes()[:4])

	budget := newFrameBudget(uint64(size))
	if err := budget.acquire(context.Background(), size, time.Second); err != nil {
		t.Fatal(err)
	}
	var decoded authoritypb.Request
	if err := readFrame(bytes.NewReader(frame.Bytes()), 1024, budget, 20*time.Millisecond, &decoded); !errors.Is(err, ErrFrameBudget) {
		t.Fatalf("readFrame with an exhausted budget = %v, want ErrFrameBudget", err)
	}
	budget.release(size)
	if err := readFrame(bytes.NewReader(frame.Bytes()), 1024, budget, time.Second, &decoded); err != nil {
		t.Fatalf("readFrame after release = %v", err)
	}
	if decoded.GetRequestId() != 1 {
		t.Fatalf("decoded = %v", &decoded)
	}
}

type echoHandler struct{ epoch []byte }

func (h echoHandler) Epoch() []byte { return append([]byte(nil), h.epoch...) }
func (h echoHandler) Bounds() TransportBounds {
	return TransportBounds{MaxFrame: 4096, MaxRequestFrame: 4096, MaxInFlight: 4}
}
func (h echoHandler) Handle(_ context.Context, req *authoritypb.Request) *authoritypb.Response {
	return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
}

func testServeSession(t *testing.T, s *Server, conn net.Conn) chan error {
	t.Helper()
	bounds, err := s.validate()
	if err != nil {
		t.Fatal(err)
	}
	s.budget = newFrameBudget(s.MaxFrameBytesInFlight)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		defer cancel()
		done <- s.serveSession(ctx, cancel, conn, bounds, [32]byte{9})
	}()
	return done
}

func TestServerMultiplexesRequestIDs(t *testing.T) {
	client, server := net.Pipe()
	s := &Server{
		Handler: echoHandler{epoch: []byte("epoch")}, MaxFrame: 4096, MaxInFlight: 4, MaxConnections: 4,
		MaxFrameBytesInFlight: 1 << 20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second,
	}
	done := testServeSession(t, s, server)
	for _, id := range []uint64{9, 3} {
		if err := writeFrame(client, 4096, &authoritypb.Request{RequestId: id, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: 1}}}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uint64]bool{}
	for range 2 {
		var response authoritypb.Response
		if err := readFrame(client, 4096, nil, 0, &response); err != nil {
			t.Fatal(err)
		}
		seen[response.GetRequestId()] = true
	}
	if !seen[9] || !seen[3] {
		t.Fatalf("seen=%v", seen)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type nilResponseHandler struct{ epoch []byte }

func (h nilResponseHandler) Epoch() []byte { return append([]byte(nil), h.epoch...) }
func (h nilResponseHandler) Bounds() TransportBounds {
	return TransportBounds{MaxFrame: 4096, MaxRequestFrame: 4096, MaxInFlight: 4}
}
func (h nilResponseHandler) Handle(context.Context, *authoritypb.Request) *authoritypb.Response {
	return nil
}

// Defect 7: the substitute for a nil handler response carried no epoch, so the
// client read an internal failure as an authority failover and the operator was
// told to remount after a failover that never happened.
func TestNilHandlerResponseKeepsTheAuthorityEpoch(t *testing.T) {
	epoch := bytes.Repeat([]byte{0xA5}, 16)
	client, server := net.Pipe()
	s := &Server{
		Handler: nilResponseHandler{epoch: epoch}, MaxFrame: 4096, MaxInFlight: 4, MaxConnections: 4,
		MaxFrameBytesInFlight: 1 << 20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second,
	}
	done := testServeSession(t, s, server)
	if err := writeFrame(client, 4096, &authoritypb.Request{RequestId: 5, Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}); err != nil {
		t.Fatal(err)
	}
	var response authoritypb.Response
	if err := readFrame(client, 4096, nil, 0, &response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.GetEpoch(), epoch) {
		t.Fatalf("epoch = %x, want %x: a nil handler response must never look like a failover", response.GetEpoch(), epoch)
	}
	if response.GetRequestId() != 5 || !response.GetUncertain() ||
		response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_INTERNAL {
		t.Fatalf("response = %v, want an internal, uncertain failure for request 5", &response)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type disagreeingHandler struct{ echoHandler }

func (disagreeingHandler) Bounds() TransportBounds {
	return TransportBounds{MaxFrame: 1 << 20, MaxRequestFrame: 4096, MaxInFlight: 64}
}

// Defect 9: the transport's real admission bounds and the bounds advertised to
// clients were independent values with nothing forcing agreement.
func TestServerRefusesToRunWithBoundsItDoesNotEnforce(t *testing.T) {
	s := &Server{
		Handler: disagreeingHandler{}, MaxFrame: 4096, MaxInFlight: 4, MaxConnections: 4,
		MaxFrameBytesInFlight: 1 << 20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second,
	}
	if _, err := s.validate(); err == nil {
		t.Fatal("server accepted a handler advertising bounds it does not enforce")
	}
	agreeing := &Server{
		Handler: echoHandler{}, MaxFrame: 4096, MaxInFlight: 4, MaxConnections: 4,
		MaxFrameBytesInFlight: 1 << 20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second,
	}
	if _, err := agreeing.validate(); err != nil {
		t.Fatalf("agreeing bounds refused: %v", err)
	}
}

// Defect 4a: a reply that passed the pre-envelope size check could still be too
// large once writeFrame restored the request ID, epoch and slot state, and the
// oversized body was already in the replay slot, so remounting reproduced the
// substituted EOVERFLOW forever.
func TestRetainedReplyEnvelopeFitsItsReserve(t *testing.T) {
	const maxFrame uint32 = 64 << 10
	body := make([]byte, maxFrame-responseEnvelopeReserve)
	build := func() ([]byte, error) {
		return proto.Marshal(&authoritypb.Response{Body: &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: body}}})
	}
	encoded, err := build()
	if err != nil {
		t.Fatal(err)
	}
	// Grow the retained body to exactly the largest one the new size check
	// admits, then confirm the reply that finally reaches the wire still fits.
	for uint32(len(encoded)) > maxFrame-responseEnvelopeReserve {
		body = body[:len(body)-1]
		if encoded, err = build(); err != nil {
			t.Fatal(err)
		}
	}
	stamped := new(authoritypb.Response)
	if err := proto.Unmarshal(encoded, stamped); err != nil {
		t.Fatal(err)
	}
	stamped.RequestId = ^uint64(0)
	stamped.Epoch = bytes.Repeat([]byte{0xFF}, 16)
	stamped.Errno = 0x7FFFFFFF
	stamped.Mutation = &authoritypb.MutationState{Slot: ^uint32(0), AcceptedSequence: ^uint64(0)}
	if delta := proto.Size(stamped) - len(encoded); uint32(delta) > responseEnvelopeReserve {
		t.Fatalf("envelope delta %d exceeds responseEnvelopeReserve %d", delta, responseEnvelopeReserve)
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, maxFrame, stamped); err != nil {
		t.Fatalf("a reply at the retained-size limit did not fit the wire frame: %v", err)
	}
}

func TestBlockingWaitClassification(t *testing.T) {
	wait := &authoritypb.Request{Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{Wait: true, Lock: &authoritypb.LockSpec{}}}}
	if !blockingWait(wait) {
		t.Fatal("a waiting SetLock must use the blocking lane")
	}
	for name, req := range map[string]*authoritypb.Request{
		"unlock":  {Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{Wait: true, Unlock: true}}},
		"trylock": {Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{}}},
		"other":   {Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}},
	} {
		if blockingWait(req) {
			t.Fatalf("%s must not use the blocking lane", name)
		}
	}
	for _, limit := range []int{2, 3, 8, 128, 256} {
		ordinary, blocking := blockingWaitLane(limit)
		if ordinary < 1 || blocking < 1 || ordinary+blocking != limit {
			t.Fatalf("blockingWaitLane(%d) = %d, %d", limit, ordinary, blocking)
		}
	}
}
