package authorityrpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

func TestCloseBatchWireBoundsAndCanonicalTags(t *testing.T) {
	for _, count := range []int{MaxCloseBatch, MaxCloseBatch + 1} {
		request := &authoritypb.Request{RequestId: ^uint64(0), Epoch: bytes.Repeat([]byte{1}, 16), Session: &authoritypb.SessionProof{Id: bytes.Repeat([]byte{2}, 16), Generation: ^uint64(0), ResumeSecret: bytes.Repeat([]byte{3}, 32)}, Mutation: &authoritypb.Mutation{Slot: ^uint32(0), Sequence: ^uint64(0)}, Body: &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{}}}
		response := &authoritypb.Response{RequestId: ^uint64(0), Epoch: bytes.Repeat([]byte{1}, 16), Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{}}}
		for i := 0; i < count; i++ {
			handle := bytes.Repeat([]byte{byte(i + 1)}, 16)
			request.GetCloseBatch().Closes = append(request.GetCloseBatch().Closes, &authoritypb.CloseRequest{Handle: handle, LockOwner: ^uint64(0), FlockUnlock: true})
			response.GetCloseBatch().Results = append(response.GetCloseBatch().Results, &authoritypb.CloseBatchResult{Errno: -1, Failure: authoritypb.FailureClass_FAILURE_CLASS_COHERENCE, Retired: true})
		}
		for _, message := range []proto.Message{request, response} {
			encoded, err := canonicalBytes(message.ProtoReflect())
			if err != nil {
				t.Fatal(err)
			}
			err = validateWireMessage(encoded, message.ProtoReflect().Descriptor())
			if (err == nil) != (count == MaxCloseBatch) {
				t.Fatalf("count=%d grammar=%v", count, err)
			}
			if count == MaxCloseBatch {
				assertFrameRoundTrip(t, message)
			}
		}
		if count == MaxCloseBatch && (proto.Size(request) > int(MinimumFrameBytes) || proto.Size(response) > int(fixedMutationReplyBytes)) {
			t.Fatalf("batch exceeds reserve: request=%d response=%d", proto.Size(request), proto.Size(response))
		}
	}
	for _, tc := range []struct {
		message proto.Message
		want    string
	}{
		{&authoritypb.Request{Body: &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{Closes: []*authoritypb.CloseRequest{{Handle: []byte{1}}, {Handle: []byte{2}}}}}}, "d2040a0a030a01010a030a0102"},
		{&authoritypb.Response{Body: &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: []*authoritypb.CloseBatchResult{{Retired: true}, {Errno: 5, Retired: true}}}}}, "a2040a0a0218010a0408051801"},
	} {
		encoded, err := canonicalBytes(tc.message.ProtoReflect())
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(encoded) != tc.want {
			t.Fatalf("canonical batch=%x want=%s", encoded, tc.want)
		}
		assertCanonicalRoundTrip(t, tc.message)
	}
}
