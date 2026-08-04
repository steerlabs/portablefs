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
	if err := readFrame(bytes.NewReader(writer.Bytes()), 4096, &got); err != nil {
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
	if err := readFrame(&frame, 1024, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetRequestId() != 42 || decoded.GetHello().GetProtocolMajor() != 1 {
		t.Fatalf("decoded=%v", &decoded)
	}

	var oversized bytes.Buffer
	_ = binary.Write(&oversized, binary.BigEndian, uint32(1025))
	if err := readFrame(&oversized, 1024, &decoded); !errors.Is(err, ErrFrameBounds) {
		t.Fatalf("readFrame=%v", err)
	}
}

type echoHandler struct{}

func (echoHandler) Handle(_ context.Context, req *authoritypb.Request) *authoritypb.Response {
	return &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: []byte("epoch")}
}

func TestServerMultiplexesRequestIDs(t *testing.T) {
	client, server := net.Pipe()
	s := &Server{Handler: echoHandler{}, MaxFrame: 4096, MaxInFlight: 4, MaxConnections: 4, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- s.serveConn(context.Background(), server) }()
	for _, id := range []uint64{9, 3} {
		if err := writeFrame(client, 4096, &authoritypb.Request{RequestId: id, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: 1}}}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uint64]bool{}
	for range 2 {
		var response authoritypb.Response
		if err := readFrame(client, 4096, &response); err != nil {
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
