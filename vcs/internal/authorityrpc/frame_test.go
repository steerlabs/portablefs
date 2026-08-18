package authorityrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/encoding/protowire"
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

var errInjectedFrameWrite = errors.New("injected frame write failure")

type failAfterWriter struct {
	bytes.Buffer
	remaining int
}

type countedWriteConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *countedWriteConn) Write(payload []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(payload)
}

type deadlineWriteConn struct {
	bytes.Buffer
	deadline time.Time
	writes   int
}

func (c *deadlineWriteConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *deadlineWriteConn) Close() error             { return nil }
func (c *deadlineWriteConn) LocalAddr() net.Addr      { return nil }
func (c *deadlineWriteConn) RemoteAddr() net.Addr     { return nil }
func (c *deadlineWriteConn) SetDeadline(deadline time.Time) error {
	c.deadline = deadline
	return nil
}
func (c *deadlineWriteConn) SetReadDeadline(time.Time) error { return nil }
func (c *deadlineWriteConn) SetWriteDeadline(deadline time.Time) error {
	c.deadline = deadline
	return nil
}
func (c *deadlineWriteConn) Write(payload []byte) (int, error) {
	c.writes++
	if !c.deadline.IsZero() && !c.deadline.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	return c.Buffer.Write(payload)
}

func (w *failAfterWriter) Write(value []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errInjectedFrameWrite
	}
	if len(value) <= w.remaining {
		w.remaining -= len(value)
		return w.Buffer.Write(value)
	}
	value = value[:w.remaining]
	w.remaining = 0
	n, _ := w.Buffer.Write(value)
	return n, errInjectedFrameWrite
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
	_ = binary.Write(&oversized, binary.BigEndian, uint32(0))
	if err := readFrame(&oversized, 1024, nil, 0, &decoded); !errors.Is(err, ErrFrameBounds) {
		t.Fatalf("readFrame=%v", err)
	}
}

func TestTLSFrameRoundTripBatchesSocketWrites(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	serverTLS = serverTLS.Clone()
	clientTLS = clientTLS.Clone()
	serverTLS.NextProtos = []string{protocolALPN}
	clientTLS.NextProtos = []string{protocolALPN}
	serverTLS.DynamicRecordSizingDisabled = true
	clientTLS.DynamicRecordSizingDisabled = true

	clientRaw, serverRaw := net.Pipe()
	clientCounted := &countedWriteConn{Conn: clientRaw}
	serverCounted := &countedWriteConn{Conn: serverRaw}
	client := newAuthorityTLSClient(clientCounted, clientTLS)
	server := newAuthorityTLSServer(serverCounted, serverTLS)
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- server.HandshakeContext(t.Context()) }()
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatal(err)
	}
	clientCounted.writes.Store(0)
	serverCounted.writes.Store(0)

	payload := bytes.Repeat([]byte{0x5C}, 1<<20)
	want := &authoritypb.Request{
		RequestId: 41,
		Body: &authoritypb.Request_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteRequest{
			Handle: bytes.Repeat([]byte{0x71}, 16), Size: uint32(len(payload)), Data: payload,
		}},
	}
	serverDone := make(chan error, 1)
	go func() {
		got := new(authoritypb.Request)
		if err := readFrame(server, 2<<20, nil, 0, got); err != nil {
			serverDone <- err
			return
		}
		if !proto.Equal(got, want) {
			serverDone <- errors.New("buffered TLS request did not round trip exactly")
			return
		}
		serverDone <- writeFrame(server, 2<<20, &authoritypb.Response{
			RequestId: want.GetRequestId(),
			Body:      &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: payload}},
		})
	}()
	if err := writeFrame(client, 2<<20, want); err != nil {
		t.Fatal(err)
	}
	var response authoritypb.Response
	if err := readFrame(client, 2<<20, nil, 0, &response); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.GetRead().GetData(), payload) {
		t.Fatal("buffered TLS response did not round trip exactly")
	}
	if writes := clientCounted.writes.Load(); writes > 6 {
		t.Fatalf("1 MiB TLS request used %d socket writes, want at most 6", writes)
	}
	if writes := serverCounted.writes.Load(); writes > 6 {
		t.Fatalf("1 MiB TLS response used %d socket writes, want at most 6", writes)
	}
}

func TestWriteRequestDeadlineCoversBufferedFlush(t *testing.T) {
	raw := new(deadlineWriteConn)
	conn := newFrameSocket(raw)
	client := &Client{cfg: ClientConfig{CancelDrainTimeout: time.Second}}
	transport := newClientTransport(authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	transport.frameMax.Store(4096)
	request := &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}
	if err := client.writeRequest(t.Context(), transport, conn, request); err != nil {
		t.Fatal(err)
	}
	if raw.deadline.IsZero() || raw.writes != 1 || raw.Len() == 0 {
		t.Fatalf("buffered frame returned before its deadline-covered flush: deadline=%v writes=%d bytes=%d", raw.deadline, raw.writes, raw.Len())
	}

	expiredRaw := new(deadlineWriteConn)
	expiredConn := newFrameSocket(expiredRaw)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := client.writeRequest(ctx, transport, expiredConn, request); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired buffered flush = %v, want deadline exceeded", err)
	}
}

func TestFrameCarriesWriteTransactionDataOutsideProtobuf(t *testing.T) {
	data := bytes.Repeat([]byte{0xA5}, 64<<10)
	want := &authoritypb.Request{
		RequestId: 8,
		Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: 17, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, Data: data,
		}},
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, 128<<10, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want.GetWriteTransaction().GetData(), data) {
		t.Fatal("writeFrame did not restore the caller-owned request payload")
	}
	metadataSize := binary.BigEndian.Uint32(frame.Bytes()[:4])
	bulkSize := binary.BigEndian.Uint32(frame.Bytes()[4:8])
	if bulkSize != uint32(len(data)) {
		t.Fatalf("bulk size = %d, want %d", bulkSize, len(data))
	}
	var metadata authoritypb.Request
	if err := proto.Unmarshal(frame.Bytes()[frameHeaderBytes:frameHeaderBytes+int(metadataSize)], &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.GetWriteTransaction().GetData()) != 0 {
		t.Fatal("write data was duplicated inside protobuf metadata")
	}

	var got authoritypb.Request
	if err := readFrame(bytes.NewReader(frame.Bytes()), 128<<10, nil, 0, &got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(want, &got) {
		t.Fatalf("round trip differs: got %v", &got)
	}
}

func TestFrameCarriesOneShotWriteDataOutsideProtobufAndRetainsIt(t *testing.T) {
	data := bytes.Repeat([]byte{0x5A}, 64<<10)
	want := &authoritypb.Request{
		RequestId: 9,
		Body: &authoritypb.Request_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteRequest{
			Handle: bytes.Repeat([]byte{0x41}, 16), Size: uint32(len(data)), Data: data,
		}},
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, 128<<10, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want.GetOneShotWrite().GetData(), data) {
		t.Fatal("writeFrame did not restore the caller-owned one-shot payload")
	}
	metadataSize := binary.BigEndian.Uint32(frame.Bytes()[:4])
	bulkSize := binary.BigEndian.Uint32(frame.Bytes()[4:8])
	if bulkSize != uint32(len(data)) {
		t.Fatalf("one-shot bulk size = %d, want %d", bulkSize, len(data))
	}
	var metadata authoritypb.Request
	if err := proto.Unmarshal(frame.Bytes()[frameHeaderBytes:frameHeaderBytes+int(metadataSize)], &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.GetOneShotWrite().GetData()) != 0 {
		t.Fatal("one-shot data was duplicated inside protobuf metadata")
	}

	var got authoritypb.Request
	release, err := readFrameRetained(bytes.NewReader(frame.Bytes()), 128<<10, nil, 0, &got)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(want, &got) {
		release()
		t.Fatalf("one-shot retained round trip differs: got %v", &got)
	}
	if &got.GetOneShotWrite().GetData()[0] == &data[0] {
		release()
		t.Fatal("decoded one-shot payload aliases the caller's original slice")
	}
	release()
	if got.GetOneShotWrite().GetData() != nil {
		t.Fatal("released one-shot payload remains reachable from its carrier")
	}
}

func TestWriteFramePartialPrefixAndBulkFailuresPreserveExactReplayBody(t *testing.T) {
	data := bytes.Repeat([]byte{0x6D}, 4096)
	request := &authoritypb.Request{
		RequestId: 81,
		Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: 23, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, Data: data,
		}},
	}
	var complete bytes.Buffer
	if err := writeFrame(&complete, 8192, request); err != nil {
		t.Fatal(err)
	}
	metadataSize := int(binary.BigEndian.Uint32(complete.Bytes()[:4]))
	prefixSize := frameHeaderBytes + metadataSize
	for _, limit := range []int{0, 1, prefixSize - 1, prefixSize, prefixSize + len(data)/2} {
		t.Run(fmt.Sprintf("after-%d", limit), func(t *testing.T) {
			writer := &failAfterWriter{remaining: limit}
			if err := writeFrame(writer, 8192, request); !errors.Is(err, errInjectedFrameWrite) {
				t.Fatalf("writeFrame = %v, want injected failure", err)
			}
			if !bytes.Equal(request.GetWriteTransaction().GetData(), data) {
				t.Fatal("failed write changed the caller-owned replay body")
			}
			if !bytes.Equal(writer.Bytes(), complete.Bytes()[:limit]) {
				t.Fatal("partial frame differs from the exact successful frame prefix")
			}
			var replay bytes.Buffer
			if err := writeFrame(&replay, 8192, request); err != nil {
				t.Fatalf("replay after partial write: %v", err)
			}
			var decoded authoritypb.Request
			if err := readFrame(&replay, 8192, nil, 0, &decoded); err != nil {
				t.Fatalf("decode replay: %v", err)
			}
			if !proto.Equal(request, &decoded) {
				t.Fatal("replay body changed after partial write")
			}
		})
	}
}

func TestFrameCarriesReadDataOutsideProtobuf(t *testing.T) {
	data := bytes.Repeat([]byte{0x3C}, 64<<10)
	want := &authoritypb.Response{
		RequestId: 9,
		Body:      &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: data}},
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, 128<<10, want); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(frame.Bytes()[4:8]) != uint32(len(data)) {
		t.Fatal("read data was not encoded as the frame bulk body")
	}
	var got authoritypb.Response
	if err := readFrame(bytes.NewReader(frame.Bytes()), 128<<10, nil, 0, &got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(want, &got) {
		t.Fatal("read frame did not reconstruct the response")
	}
}

func TestFrameRejectsBulkWithoutItsExactCarrier(t *testing.T) {
	metadata, err := proto.Marshal(&authoritypb.Request{
		RequestId: 10,
		Body:      &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	_ = binary.Write(&frame, binary.BigEndian, uint32(len(metadata)))
	_ = binary.Write(&frame, binary.BigEndian, uint32(3))
	frame.Write(metadata)
	frame.WriteString("bad")
	var got authoritypb.Request
	if err := readFrame(&frame, 4096, nil, 0, &got); !errors.Is(err, ErrFramePayload) {
		t.Fatalf("readFrame = %v, want ErrFramePayload", err)
	}
}

func TestFrameRejectsInlineBulkCopy(t *testing.T) {
	metadata, err := proto.Marshal(&authoritypb.Request{
		RequestId: 10,
		Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
			Data: []byte("inline is not protocol 5"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	_ = binary.Write(&frame, binary.BigEndian, uint32(len(metadata)))
	_ = binary.Write(&frame, binary.BigEndian, uint32(0))
	frame.Write(metadata)
	var got authoritypb.Request
	if err := readFrame(&frame, 4096, nil, 0, &got); !errors.Is(err, ErrFramePayload) {
		t.Fatalf("readFrame = %v, want ErrFramePayload", err)
	}
}

func encodedRawFrame(metadata, bulk []byte) []byte {
	frame := make([]byte, frameHeaderBytes, frameHeaderBytes+len(metadata)+len(bulk))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(metadata)))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(bulk)))
	frame = append(frame, metadata...)
	return append(frame, bulk...)
}

func TestFrameRejectsNonCanonicalMetadataBeforeDecode(t *testing.T) {
	valid, err := proto.Marshal(&authoritypb.Request{
		RequestId: 17,
		Body:      &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		metadata []byte
	}{
		{
			name: "unknown top-level field",
			metadata: protowire.AppendVarint(
				protowire.AppendTag(append([]byte(nil), valid...), 63, protowire.VarintType), 1,
			),
		},
		{
			name: "duplicate singular field",
			metadata: protowire.AppendVarint(
				protowire.AppendTag(append([]byte(nil), valid...), 1, protowire.VarintType), 18,
			),
		},
		{
			name: "two oneof bodies",
			metadata: protowire.AppendBytes(
				protowire.AppendTag(append([]byte(nil), valid...), 10, protowire.BytesType), nil,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded authoritypb.Request
			err := readFrame(bytes.NewReader(encodedRawFrame(test.metadata, nil)), 4096, nil, 0, &decoded)
			if !errors.Is(err, ErrFrameEncoding) {
				t.Fatalf("readFrame = %v, want ErrFrameEncoding", err)
			}
			if decoded.GetRequestId() != 0 || decoded.GetBody() != nil {
				t.Fatalf("non-canonical metadata reached protobuf decode: %+v", &decoded)
			}
		})
	}
}

func TestFrameBoundsRepeatedDecodedAllocationsBeforeUnmarshal(t *testing.T) {
	features := make([]string, maxWireFeatureElements+1)
	request := &authoritypb.Request{
		RequestId: 19,
		Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{
			ProtocolMajor: ProtocolMajor,
			Features:      features,
		}},
	}
	metadata, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded authoritypb.Request
	if err := readFrame(bytes.NewReader(encodedRawFrame(metadata, nil)), 4096, nil, 0, &decoded); !errors.Is(err, ErrFrameEncoding) {
		t.Fatalf("oversized repeated field = %v, want ErrFrameEncoding", err)
	}
	if decoded.GetHello() != nil {
		t.Fatal("repeated-field amplification reached protobuf decode")
	}
	// The sender runs the exact same grammar, so an internal producer cannot
	// put a frame on the wire that every conforming receiver must reject.
	if err := writeFrame(io.Discard, 4096, request); !errors.Is(err, ErrFrameEncoding) {
		t.Fatalf("writeFrame oversized repeated field = %v, want ErrFrameEncoding", err)
	}
}

func TestFrameBoundsPackedRepeatedElements(t *testing.T) {
	atLimit := &authoritypb.Request{
		RequestId: 20,
		Body: &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{
			BlockedParentKernelInos: make([]uint64, maxWireRepeatedElements),
		}},
	}
	var atLimitFrame bytes.Buffer
	if err := writeFrame(&atLimitFrame, 1<<20, atLimit); err != nil {
		t.Fatalf("writeFrame at exact repeated bound: %v", err)
	}
	var atLimitDecoded authoritypb.Request
	if err := readFrame(&atLimitFrame, 1<<20, nil, 0, &atLimitDecoded); err != nil {
		t.Fatalf("readFrame at exact repeated bound: %v", err)
	}
	if got := len(atLimitDecoded.GetAckVisibility().GetBlockedParentKernelInos()); got != maxWireRepeatedElements {
		t.Fatalf("decoded repeated elements = %d, want %d", got, maxWireRepeatedElements)
	}

	request := &authoritypb.Request{
		RequestId: 21,
		Body: &authoritypb.Request_AckVisibility{AckVisibility: &authoritypb.AckVisibilityRequest{
			BlockedParentKernelInos: make([]uint64, maxWireRepeatedElements+1),
		}},
	}
	metadata, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded authoritypb.Request
	if err := readFrame(bytes.NewReader(encodedRawFrame(metadata, nil)), uint32(len(metadata)+frameHeaderBytes), nil, 0, &decoded); !errors.Is(err, ErrFrameEncoding) {
		t.Fatalf("oversized packed field = %v, want ErrFrameEncoding", err)
	}
}

func TestFrameBoundsApplyAcrossNestedMessageTree(t *testing.T) {
	targets := make([]*authoritypb.VisibilityTarget, maxWireRepeatedElements+1)
	for i := range targets {
		targets[i] = &authoritypb.VisibilityTarget{
			Scope:    authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA,
			Identity: []byte{byte(i)},
		}
	}
	response := &authoritypb.Response{
		RequestId: 22,
		Body: &authoritypb.Response_Visibility{Visibility: &authoritypb.VisibilityEvent{
			Targets: targets,
		}},
	}
	metadata, err := proto.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded authoritypb.Response
	if err := readFrame(bytes.NewReader(encodedRawFrame(metadata, nil)), 1<<20, nil, 0, &decoded); !errors.Is(err, ErrFrameEncoding) {
		t.Fatalf("nested allocation amplification = %v, want ErrFrameEncoding", err)
	}
	if decoded.GetBody() != nil {
		t.Fatal("nested allocation amplification reached protobuf decode")
	}
	if err := writeFrame(io.Discard, 1<<20, response); !errors.Is(err, ErrFrameEncoding) {
		t.Fatalf("writeFrame nested allocation amplification = %v, want ErrFrameEncoding", err)
	}
}

func TestFrameBudgetIsRetainedThroughBulkUse(t *testing.T) {
	request := &authoritypb.Request{
		RequestId: 11,
		Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, Data: bytes.Repeat([]byte{7}, 4096),
		}},
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, 8192, request); err != nil {
		t.Fatal(err)
	}
	total := binary.BigEndian.Uint32(frame.Bytes()[:4]) + binary.BigEndian.Uint32(frame.Bytes()[4:8])
	budget := newFrameBudget(uint64(total))
	var got authoritypb.Request
	release, err := readFrameRetained(bytes.NewReader(frame.Bytes()), 8192, budget, time.Second, &got)
	if err != nil {
		t.Fatal(err)
	}
	if err := budget.acquire(context.Background(), 1, 20*time.Millisecond); !errors.Is(err, ErrFrameBudget) {
		t.Fatalf("budget while handler owns bulk = %v, want ErrFrameBudget", err)
	}
	release()
	if err := budget.acquire(context.Background(), total, time.Second); err != nil {
		t.Fatalf("budget after handler release = %v", err)
	}
	budget.release(total)
}

func TestFramePayloadClassesCoverEveryLegalFrame(t *testing.T) {
	for _, tc := range []struct {
		size  int
		class int
	}{
		{size: 1, class: -1},
		{size: (64 << 10) - 1, class: -1},
		{size: 64 << 10, class: 0},
		{size: (64 << 10) + 1, class: 1},
		{size: 128 << 10, class: 1},
		{size: (1 << 20) + int(FramePayloadReserve), class: 16},
		{size: 4 << 20, class: framePoolClasses - 1},
		{size: (4 << 20) + 1, class: -1},
	} {
		if got := framePoolClass(tc.size); got != tc.class {
			t.Fatalf("framePoolClass(%d) = %d, want %d", tc.size, got, tc.class)
		}
		payload, class := acquireFramePayload(tc.size)
		if len(payload) != tc.size || class != tc.class {
			t.Fatalf("acquireFramePayload(%d) = (len %d, class %d), want (len %d, class %d)",
				tc.size, len(payload), class, tc.size, tc.class)
		}
		if class >= 0 {
			if cap(payload) != framePoolBytes(class) {
				t.Fatalf("acquireFramePayload(%d) capacity = %d, want the exact class size %d",
					tc.size, cap(payload), framePoolBytes(class))
			}
			// A class must never round a frame up by more than its own width, or
			// a pool miss costs more than the allocation it replaces.
			if over := cap(payload) - tc.size; over >= framePoolGranularity {
				t.Fatalf("acquireFramePayload(%d) over-allocated by %d bytes", tc.size, over)
			}
		}
		releaseFramePayload(payload, class)
	}
}

func TestFramePayloadIsRecycledAtItsClass(t *testing.T) {
	// A smaller frame in the same class draws the released buffer back; the
	// class exists so that a megabyte of write staging is allocated once rather
	// than once per frame. Every garbage collection empties the pool, so a
	// single put/get pair may legitimately miss — recycling has to be the
	// ordinary outcome, not a guaranteed one.
	for attempt := range 32 {
		payload, class := acquireFramePayload(1 << 20)
		base := &payload[0]
		releaseFramePayload(payload, class)
		again, againClass := acquireFramePayload((1 << 20) - 4096)
		reused := againClass == class && &again[0] == base
		releaseFramePayload(again, againClass)
		if againClass != class {
			t.Fatalf("attempt %d: 1 MiB and 1 MiB - 4 KiB took classes %d and %d", attempt, class, againClass)
		}
		if reused {
			return
		}
	}
	t.Fatal("a released frame payload was never recycled into its own class")
}

// A retained frame hands its decoded message a slice of the payload buffer.
// That slice is exactly as alive as the release hook, so release both drops it
// from the message and returns the buffer: a carrier that survived release would
// be reading another connection's frame.
func TestReleasedFramePayloadIsNotAliasedByALiveCarrier(t *testing.T) {
	encode := func(t *testing.T, fill byte) []byte {
		t.Helper()
		request := &authoritypb.Request{
			RequestId: 21,
			Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
				TransactionId: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
				Data: bytes.Repeat([]byte{fill}, 64<<10),
			}},
		}
		var frame bytes.Buffer
		if err := writeFrame(&frame, 128<<10, request); err != nil {
			t.Fatal(err)
		}
		return frame.Bytes()
	}

	first := new(authoritypb.Request)
	release, err := readFrameRetained(bytes.NewReader(encode(t, 0xA5)), 128<<10, nil, 0, first)
	if err != nil {
		t.Fatal(err)
	}
	bulk := first.GetWriteTransaction().GetData()
	if len(bulk) != 64<<10 || bulk[0] != 0xA5 {
		t.Fatalf("retained bulk = %d bytes, want the exact out-of-line body", len(bulk))
	}
	release()
	if got := first.GetWriteTransaction().GetData(); got != nil {
		t.Fatalf("released payload is still reachable through its carrier: %d bytes", len(got))
	}

	// The recycled buffer is not cleared, so the next frame is only correct if
	// every byte of it was read over the previous frame's contents.
	second := new(authoritypb.Request)
	secondRelease, err := readFrameRetained(bytes.NewReader(encode(t, 0x3C)), 128<<10, nil, 0, second)
	if err != nil {
		t.Fatal(err)
	}
	defer secondRelease()
	next := second.GetWriteTransaction().GetData()
	if len(next) != 64<<10 {
		t.Fatalf("recycled frame decoded %d bulk bytes, want %d", len(next), 64<<10)
	}
	if want := bytes.Repeat([]byte{0x3C}, 64<<10); !bytes.Equal(next, want) {
		t.Fatal("a recycled payload buffer left stale bytes in the decoded frame")
	}
}

func TestConcurrentRetainedFramesNeverShareAPayload(t *testing.T) {
	const readers = 16
	const rounds = 24
	frames := make([][]byte, readers)
	for reader := range frames {
		request := &authoritypb.Request{
			RequestId: uint64(reader) + 1,
			Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
				TransactionId: uint64(reader) + 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
				Data: bytes.Repeat([]byte{byte(reader)}, (reader+1)<<10),
			}},
		}
		var frame bytes.Buffer
		if err := writeFrame(&frame, 128<<10, request); err != nil {
			t.Fatal(err)
		}
		frames[reader] = frame.Bytes()
	}
	budget := newFrameBudget(uint64(readers) * (128 << 10))
	var failures sync.WaitGroup
	errs := make(chan error, readers*rounds)
	for reader := range readers {
		failures.Add(1)
		go func(reader int) {
			defer failures.Done()
			want := bytes.Repeat([]byte{byte(reader)}, (reader+1)<<10)
			for range rounds {
				decoded := new(authoritypb.Request)
				release, err := readFrameRetained(bytes.NewReader(frames[reader]), 128<<10, budget, time.Second, decoded)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(decoded.GetWriteTransaction().GetData(), want) {
					errs <- fmt.Errorf("reader %d decoded another reader's payload", reader)
					release()
					return
				}
				release()
			}
		}(reader)
	}
	failures.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func BenchmarkReadRetainedBulkFrame1MiB(b *testing.B) {
	request := &authoritypb.Request{
		RequestId: 14,
		Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, Data: make([]byte, 1<<20),
		}},
	}
	var encoded bytes.Buffer
	if err := writeFrame(&encoded, 2<<20, request); err != nil {
		b.Fatal(err)
	}
	wire := encoded.Bytes()
	b.ReportAllocs()
	b.SetBytes(1 << 20)
	for b.Loop() {
		var got authoritypb.Request
		release, err := readFrameRetained(bytes.NewReader(wire), 2<<20, nil, 0, &got)
		if err != nil {
			b.Fatal(err)
		}
		release()
	}
}

// BenchmarkWriteBulkFrameAllocations1MiB isolates framing allocations. The
// discard sink accepts the bulk slice without copying it, so bytes/second from
// this benchmark would be fictitious transport throughput and is deliberately
// not reported.
func BenchmarkWriteBulkFrameAllocations1MiB(b *testing.B) {
	request := &authoritypb.Request{
		RequestId: 12,
		Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, Data: make([]byte, 1<<20),
		}},
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := writeFrame(io.Discard, 2<<20, request); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadBulkFrame1MiB(b *testing.B) {
	request := &authoritypb.Request{
		RequestId: 13,
		Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
			TransactionId: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, Data: make([]byte, 1<<20),
		}},
	}
	var encoded bytes.Buffer
	if err := writeFrame(&encoded, 2<<20, request); err != nil {
		b.Fatal(err)
	}
	wire := encoded.Bytes()
	b.ReportAllocs()
	b.SetBytes(1 << 20)
	for b.Loop() {
		var got authoritypb.Request
		if err := readFrame(bytes.NewReader(wire), 2<<20, nil, 0, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTLSFrameLoopback1MiB(b *testing.B) {
	serverTLS, clientTLS := testTLSConfigs(b)
	serverTLS = serverTLS.Clone()
	clientTLS = clientTLS.Clone()
	serverTLS.NextProtos = []string{protocolALPN}
	clientTLS.NextProtos = []string{protocolALPN}
	serverTLS.DynamicRecordSizingDisabled = true
	clientTLS.DynamicRecordSizingDisabled = true
	clientRaw, serverRaw := net.Pipe()
	counted := &countedWriteConn{Conn: clientRaw}
	client := newAuthorityTLSClient(counted, clientTLS)
	server := newAuthorityTLSServer(serverRaw, serverTLS)
	b.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- server.HandshakeContext(context.Background()) }()
	if err := client.HandshakeContext(context.Background()); err != nil {
		b.Fatal(err)
	}
	if err := <-serverHandshake; err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 1<<20)
	request := &authoritypb.Request{
		RequestId: 1,
		Body: &authoritypb.Request_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteRequest{
			Handle: make([]byte, 16), Size: uint32(len(payload)), Data: payload,
		}},
	}
	response := &authoritypb.Response{RequestId: 1}
	serverDone := make(chan error, 1)
	go func() {
		for {
			var got authoritypb.Request
			if err := readFrame(server, 2<<20, nil, 0, &got); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					serverDone <- nil
				} else {
					serverDone <- err
				}
				return
			}
			if err := writeFrame(server, 2<<20, response); err != nil {
				serverDone <- err
				return
			}
		}
	}()
	counted.writes.Store(0)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	iterations := int64(0)
	for b.Loop() {
		if err := writeFrame(client, 2<<20, request); err != nil {
			b.Fatal(err)
		}
		var got authoritypb.Response
		if err := readFrame(client, 2<<20, nil, 0, &got); err != nil {
			b.Fatal(err)
		}
		iterations++
	}
	b.StopTimer()
	_ = clientRaw.Close()
	if err := <-serverDone; err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(counted.writes.Load())/float64(iterations), "socket-writes/op")
}

// Defect 10: post-authentication payload allocation had no worker-wide byte
// bound, only MaxConnections multiplied by the largest legal frame.
func TestFrameBudgetBoundsConcurrentAllocation(t *testing.T) {
	request := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{ProtocolMajor: 1}}}
	var frame bytes.Buffer
	if err := writeFrame(&frame, 1024, request); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(frame.Bytes()[:4]) + binary.BigEndian.Uint32(frame.Bytes()[4:8])

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

var frameTestNeverTerminal = make(chan struct{})

func (h echoHandler) Epoch() []byte                                     { return append([]byte(nil), h.epoch...) }
func (echoHandler) RegisterSessionEndHook(func(volumeserver.SessionID)) {}
func (echoHandler) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionStateProvisional, true
}
func (echoHandler) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	return frameTestNeverTerminal, true
}
func (h echoHandler) Bounds() TransportBounds {
	return TransportBounds{MaxFrame: 4096, MaxRequestFrame: 4096, MaxInFlight: 4}
}
func (h echoHandler) Handle(_ context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: h.Epoch()}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{ProtocolMajor: ProtocolMajor}}
	case *authoritypb.Request_Attach:
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{
			SessionId: make([]byte, 16), Generation: 1, ResumeSecret: make([]byte, 32),
			ProvisionalDeadlineUnixNanos: time.Now().Add(time.Minute).UnixNano(),
		}}
		response.GetAttach().SessionId[0] = 1
		response.GetAttach().ResumeSecret[0] = 2
	case *authoritypb.Request_Activate:
		response.Body = &authoritypb.Response_Activate{Activate: &authoritypb.ActivateReply{State: authoritypb.SessionState_SESSION_STATE_ACTIVE}}
	}
	return response
}

func testServeSession(t *testing.T, s *Server, conn net.Conn) chan error {
	t.Helper()
	bounds, err := s.validate()
	if err != nil {
		t.Fatal(err)
	}
	if s.budget == nil {
		s.budget = newFrameBudget(s.MaxFrameBytesInFlight)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		defer cancel()
		done <- s.serveSession(ctx, cancel, conn, bounds, [32]byte{9})
	}()
	return done
}

type activeTestPair struct {
	data, control net.Conn
	dataDone      chan error
	controlDone   chan error
	epoch         []byte
	proof         *authoritypb.SessionProof
}

func startActiveTestPair(t *testing.T, s *Server) activeTestPair {
	t.Helper()
	dataClient, dataServer := net.Pipe()
	controlClient, controlServer := net.Pipe()
	pair := activeTestPair{
		data: dataClient, control: controlClient,
		dataDone: testServeSession(t, s, dataServer), controlDone: testServeSession(t, s, controlServer),
		epoch: s.Handler.Epoch(),
	}
	setID := make([]byte, 32)
	setID[0] = 7
	hello := func(conn net.Conn, role authoritypb.TransportRole) {
		t.Helper()
		request := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{
			ProtocolMajor: ProtocolMajor, Role: role, ConnectionSetId: append([]byte(nil), setID...),
		}}}
		if err := writeFrame(conn, 4096, request); err != nil {
			t.Fatal(err)
		}
		var response authoritypb.Response
		if err := readFrame(conn, 4096, nil, 0, &response); err != nil {
			t.Fatal(err)
		}
		if response.GetHello() == nil || response.GetHello().GetRole() != role ||
			!bytes.Equal(response.GetHello().GetConnectionSetId(), setID) {
			t.Fatalf("%s Hello response = %v", role, &response)
		}
	}
	hello(dataClient, authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	hello(controlClient, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	attempt := make([]byte, 32)
	attempt[0] = 8
	if err := writeFrame(dataClient, 4096, &authoritypb.Request{RequestId: 2, Body: &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{
		AttachAttemptId: attempt,
	}}}); err != nil {
		t.Fatal(err)
	}
	var attachResponse authoritypb.Response
	if err := readFrame(dataClient, 4096, nil, 0, &attachResponse); err != nil {
		t.Fatal(err)
	}
	attach := attachResponse.GetAttach()
	if attach == nil || attach.GetDataBindingGeneration() == 0 || attach.GetControlBindingGeneration() == 0 {
		t.Fatalf("Attach response = %v", &attachResponse)
	}
	pair.proof = &authoritypb.SessionProof{Id: append([]byte(nil), attach.GetSessionId()...), Generation: attach.GetGeneration(), ResumeSecret: append([]byte(nil), attach.GetResumeSecret()...)}
	activate := &authoritypb.Request{
		RequestId: 2, Epoch: append([]byte(nil), pair.epoch...), Session: proto.Clone(pair.proof).(*authoritypb.SessionProof),
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: attempt, DataBindingGeneration: attach.GetDataBindingGeneration(), ControlBindingGeneration: attach.GetControlBindingGeneration(),
		}},
	}
	if err := writeFrame(controlClient, 4096, activate); err != nil {
		t.Fatal(err)
	}
	var activateResponse authoritypb.Response
	if err := readFrame(controlClient, 4096, nil, 0, &activateResponse); err != nil {
		t.Fatal(err)
	}
	if activateResponse.GetActivate().GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		t.Fatalf("Activate response = %v", &activateResponse)
	}
	return pair
}

func (p activeTestPair) close(t *testing.T) {
	t.Helper()
	_ = p.data.Close()
	_ = p.control.Close()
	for _, done := range []chan error{p.dataDone, p.controlDone} {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestServerMultiplexesRequestIDs(t *testing.T) {
	s := &Server{
		Handler: echoHandler{epoch: []byte("epoch")}, MaxFrame: 4096, MaxInFlight: 4, MaxConnections: 4,
		MaxFrameBytesInFlight: 1 << 20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second,
	}
	pair := startActiveTestPair(t, s)
	defer pair.close(t)
	for _, id := range []uint64{9, 3} {
		if err := writeFrame(pair.data, 4096, &authoritypb.Request{
			RequestId: id, Epoch: append([]byte(nil), pair.epoch...), Session: proto.Clone(pair.proof).(*authoritypb.SessionProof),
			Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uint64]bool{}
	for range 2 {
		var response authoritypb.Response
		if err := readFrame(pair.data, 4096, nil, 0, &response); err != nil {
			t.Fatal(err)
		}
		seen[response.GetRequestId()] = true
	}
	if !seen[9] || !seen[3] {
		t.Fatalf("seen=%v", seen)
	}
}

type nilResponseHandler struct{ epoch []byte }

func (h nilResponseHandler) Epoch() []byte                                     { return append([]byte(nil), h.epoch...) }
func (nilResponseHandler) RegisterSessionEndHook(func(volumeserver.SessionID)) {}
func (nilResponseHandler) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionStateProvisional, true
}
func (nilResponseHandler) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	return frameTestNeverTerminal, true
}
func (h nilResponseHandler) Bounds() TransportBounds {
	return TransportBounds{MaxFrame: 4096, MaxRequestFrame: 4096, MaxInFlight: 4}
}
func (h nilResponseHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	if request.GetHello() != nil || request.GetAttach() != nil || request.GetActivate() != nil {
		return (echoHandler{epoch: h.epoch}).Handle(ctx, request)
	}
	return nil
}

// Defect 7: the substitute for a nil handler response carried no epoch, so the
// client read an internal failure as an authority failover and the operator was
// told to remount after a failover that never happened.
func TestNilHandlerResponseKeepsTheAuthorityEpoch(t *testing.T) {
	epoch := bytes.Repeat([]byte{0xA5}, 16)
	s := &Server{
		Handler: nilResponseHandler{epoch: epoch}, MaxFrame: 4096, MaxInFlight: 4, MaxConnections: 4,
		MaxFrameBytesInFlight: 1 << 20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second,
	}
	pair := startActiveTestPair(t, s)
	defer pair.close(t)
	if err := writeFrame(pair.data, 4096, &authoritypb.Request{
		RequestId: 5, Epoch: append([]byte(nil), pair.epoch...), Session: proto.Clone(pair.proof).(*authoritypb.SessionProof),
		Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{}},
	}); err != nil {
		t.Fatal(err)
	}
	var response authoritypb.Response
	if err := readFrame(pair.data, 4096, nil, 0, &response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.GetEpoch(), epoch) {
		t.Fatalf("epoch = %x, want %x: a nil handler response must never look like a failover", response.GetEpoch(), epoch)
	}
	if response.GetRequestId() != 5 || !response.GetUncertain() ||
		response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_INTERNAL {
		t.Fatalf("response = %v, want an internal, uncertain failure for request 5", &response)
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
	stamped.TerminalDeliveryToken = bytes.Repeat([]byte{0xFF}, 16)
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
