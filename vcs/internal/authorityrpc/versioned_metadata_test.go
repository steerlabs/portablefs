package authorityrpc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestKeepAliveProofCanonicalFrame(t *testing.T) {
	reply := &authoritypb.Response{RequestId: 1, SessionValidForNanos: uint64(MaxCacheProof)}
	raw, err := canonicalBytes(reply.ProtoReflect())
	if err != nil {
		t.Fatal(err)
	}
	const golden = "0801c00480b09dc2df01"
	if hex.EncodeToString(raw) != golden {
		t.Fatalf("canonical proof = %x", raw)
	}
	assertCanonicalRoundTrip(t, reply)
	assertFrameRoundTrip(t, reply)
	for _, value := range []uint64{0, 1, uint64(time.Millisecond) - 1, uint64(MaxCacheProof) + 1, math.MaxUint64} {
		raw := protowire.AppendTag(nil, 72, protowire.VarintType)
		raw = protowire.AppendVarint(raw, value)
		if err := validateWireMessage(raw, reply.ProtoReflect().Descriptor()); !errors.Is(err, ErrFrameEncoding) {
			t.Fatalf("proof %d grammar accepted: %v", value, err)
		}
	}
	for _, reply := range []*authoritypb.Response{
		{SessionValidForNanos: uint64(MaxCacheProof), Errno: 5},
		{SessionValidForNanos: uint64(MaxCacheProof), Body: &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{}}},
		{SessionValidForNanos: uint64(MaxCacheProof) + uint64(time.Millisecond)},
		{SessionValidForNanos: uint64(MaxCacheProof), Uncertain: true},
		{SessionValidForNanos: uint64(MaxCacheProof), SessionTerminal: true},
		{SessionValidForNanos: uint64(MaxCacheProof), Failure: authoritypb.FailureClass_FAILURE_CLASS_STORAGE},
		{SessionValidForNanos: uint64(MaxCacheProof), Mutation: &authoritypb.MutationState{AcceptedSequence: 1}},
		{SessionValidForNanos: uint64(MaxCacheProof), PostState: &authoritypb.PostState{}},
		{SessionValidForNanos: uint64(MaxCacheProof), TerminalDeliveryToken: []byte{1}},
		{SessionValidForNanos: uint64(MaxCacheProof), RestoreDetail: "failure"},
		{SessionValidForNanos: uint64(MaxCacheProof), AppliedSequence: 1},
		{SessionValidForNanos: uint64(MaxCacheProof), VolumeVersion: 1},
		{SessionValidForNanos: uint64(MaxCacheProof), VisibleSequence: 1},
	} {
		var frame bytes.Buffer
		if err := writeFrame(&frame, 1<<20, reply); !errors.Is(err, ErrFrameEncoding) {
			t.Fatalf("invalid proof envelope accepted: %v", err)
		}
	}
}
