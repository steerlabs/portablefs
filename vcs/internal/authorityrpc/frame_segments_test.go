package authorityrpc

import (
	"bytes"
	"errors"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

type segmentedBoundaryWriter struct {
	shortWriter
	begins, ends int
	inside       bool
}

func (w *segmentedBoundaryWriter) beginFrameWrite() error { w.begins++; w.inside = true; return nil }
func (w *segmentedBoundaryWriter) endFrameWrite() error   { w.ends++; w.inside = false; return nil }
func (w *segmentedBoundaryWriter) Write(p []byte) (int, error) {
	if !w.inside {
		return 0, errors.New("write outside frame boundary")
	}
	return w.shortWriter.Write(p)
}

func TestSegmentedWriteFrameMatchesContiguousAndReplaysAfterPartialFailure(t *testing.T) {
	segments := [][]byte{[]byte("first"), nil, []byte(" second"), []byte(" third")}
	data := bytes.Join(segments, nil)
	request := &authoritypb.Request{RequestId: 17, Mutation: &authoritypb.Mutation{Slot: 2, Sequence: 9}, Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: bytes.Repeat([]byte{1}, 16), Position: 33, Size: uint32(len(data))}}}
	original := proto.Clone(request)
	contiguous := proto.Clone(request).(*authoritypb.Request)
	contiguous.GetWrite().Data = data
	var expected bytes.Buffer
	if err := writeFrame(&expected, 4096, contiguous); err != nil {
		t.Fatal(err)
	}
	// Every byte boundary, including inside each span, can be the transport loss.
	for at := 0; at < expected.Len(); at++ {
		writer := &failAfterWriter{remaining: at}
		if err := writeFrameBulk(writer, 4096, request, segments); !errors.Is(err, errInjectedFrameWrite) {
			t.Fatalf("offset %d: %v", at, err)
		}
		if !proto.Equal(request, original) || !bytes.Equal(bytes.Join(segments, nil), data) {
			t.Fatal("partial failure mutated borrowed request")
		}
		replay := &segmentedBoundaryWriter{shortWriter: shortWriter{max: 3}}
		if err := writeFrameBulk(replay, 4096, request, segments); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(replay.Bytes(), expected.Bytes()) || replay.begins != 1 || replay.ends != 1 || replay.inside {
			t.Fatal("scatter/replay changed bytes or split frame boundary")
		}
		decoded := new(authoritypb.Request)
		if err := readFrame(bytes.NewReader(replay.Bytes()), 4096, nil, 0, decoded); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(decoded, contiguous) {
			t.Fatal("receiver changed segmented WRITE")
		}
	}
}

func TestSegmentedWriteFrameRejectsInvalidBulkBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		req   *authoritypb.Request
		spans [][]byte
		max   uint32
	}{
		{"wrong operation", &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}, [][]byte{{1}}, 4096},
		{"size mismatch", &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Size: 2}}}, [][]byte{{1}}, 4096},
		{"double payload", &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Size: 1, Data: []byte{2}}}}, [][]byte{{1}}, 4096},
		{"frame overflow", &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Size: 2}}}, [][]byte{{1, 2}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeFrameBulk(&out, tc.max, tc.req, tc.spans); err == nil || out.Len() != 0 {
				t.Fatalf("invalid frame: bytes=%d err=%v", out.Len(), err)
			}
		})
	}
}
