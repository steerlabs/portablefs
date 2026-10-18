package authorityrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func encodedRawFrame(metadata, bulk []byte) []byte {
	frame := make([]byte, frameHeaderBytes, frameHeaderBytes+len(metadata)+len(bulk))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(metadata)))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(bulk)))
	frame = append(frame, metadata...)
	return append(frame, bulk...)
}

func TestProtocol8RejectsUnknownDuplicateUnorderedAndOverlongFields(t *testing.T) {
	for _, test := range []struct {
		name    string
		raw     []byte
		message proto.Message
	}{
		{"unknown body", protowire.AppendBytes(protowire.AppendTag(nil, 62, 2), nil), &authoritypb.Request{}},
		{"unknown envelope", protowire.AppendBytes(protowire.AppendTag(nil, 60, 2), nil), &authoritypb.Request{}},
		{"unknown nested", protowire.AppendBytes(protowire.AppendTag(nil, 10, 2), []byte{0x10, 1}), &authoritypb.Request{}},
		{"duplicate scalar", []byte{8, 1, 8, 1}, &authoritypb.Request{}},
		{"duplicate body", []byte{0x6a, 0, 0x72, 0}, &authoritypb.Request{}},
		{"unordered", []byte{0x6a, 0, 8, 1}, &authoritypb.Request{}},
		{"overlong tag", []byte{0x88, 0, 1}, &authoritypb.Request{}},
		{"overlong scalar", []byte{8, 0x81, 0}, &authoritypb.Request{}},
		{"overlong length", []byte{0x6a, 0x80, 0}, &authoritypb.Request{}},
		{"overflow uint32", protowire.AppendBytes([]byte{0x52}, protowire.AppendVarint([]byte{8}, math.MaxUint64)), &authoritypb.Request{}},
		{"unknown profile", protowire.AppendBytes([]byte{0x52}, []byte{0x50, 99}), &authoritypb.Request{}},
		{"unknown failure", []byte{0x38, 5}, &authoritypb.Response{}},
		{"invalid bool", []byte{0x20, 2}, &authoritypb.Response{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := readFrame(bytes.NewReader(encodedRawFrame(test.raw, nil)), 1<<20, nil, 0, test.message); !errors.Is(err, ErrFrameEncoding) {
				t.Fatalf("accepted malformed frame: %v", err)
			}
		})
	}
}

func TestProtocol8RejectsEveryRemovedField(t *testing.T) {
	tests := []struct {
		message proto.Message
		fields  []protowire.Number
	}{
		{&authoritypb.Request{}, []protowire.Number{56, 57, 58, 59, 60, 61, 62, 63, 64}},
		{&authoritypb.Response{}, []protowire.Number{46, 47, 48, 49, 50, 51, 52, 53, 54}},
		{&authoritypb.HelloRequest{}, []protowire.Number{2}},
		{&authoritypb.HelloReply{}, []protowire.Number{2, 11}},
		{&authoritypb.AttachRequest{}, []protowire.Number{13, 14, 15}},
		{&authoritypb.ActivateReply{}, []protowire.Number{2, 8, 11}},
		{&authoritypb.ApplyRoutesReply{}, []protowire.Number{3}},
		{&authoritypb.ReclaimRequest{}, []protowire.Number{1}},
	}
	for _, test := range tests {
		for _, field := range test.fields {
			raw := protowire.AppendBytes(protowire.AppendTag(nil, field, 2), nil)
			if err := validateWireMessage(raw, test.message.ProtoReflect().Descriptor()); !errors.Is(err, ErrFrameEncoding) {
				t.Fatalf("%T field %d: %v", test.message, field, err)
			}
		}
	}
}

func TestProtocol8WritePayloadFingerprintAndFrameAccounting(t *testing.T) {
	runtime, err := volumeserver.New("wire", volumeserver.Config{ContinuousNow: func() (time.Duration, error) { return 0, nil }, SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1})
	if err != nil {
		t.Fatal(err)
	}
	request := &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: []byte{1}, Size: 7, Data: []byte("payload")}}}
	initial, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, 1<<20, request); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(frame.Bytes()[4:8]) != 7 {
		t.Fatal("payload not out of line")
	}
	var decoded authoritypb.Request
	release, digest, err := readRequestFrameRetained(context.Background(), &frame, 1<<20, nil, 0, &decoded, true)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if digest == nil || *digest != sha256.Sum256([]byte("payload")) {
		t.Fatal("frame digest mismatch")
	}
	replay, err := canonicalFingerprintFromFrame(withFramePayloadDigest(context.Background(), digest), runtime, &decoded)
	if err != nil || initial != replay {
		t.Fatalf("replay differs: %v", err)
	}
	request.GetWrite().Data[0] ^= 1
	changed, err := canonicalFingerprint(runtime, request)
	if err != nil || changed == initial {
		t.Fatal("changed bytes reused replay identity")
	}
}

func TestProtocol8ExecutionLanePartition(t *testing.T) {
	for _, max := range []int{9, 10, 32, 127} {
		ordinary, blocking, flush := executionLanes(max, authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX)
		if ordinary < 1 || blocking < 1 || flush != 4 || ordinary+blocking+flush != max {
			t.Fatalf("max=%d lanes=%d/%d/%d", max, ordinary, blocking, flush)
		}
	}
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE, authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER} {
		ordinary, blocking, flush := executionLanes(2, profile)
		if ordinary != 1 || blocking != 1 || flush != 0 {
			t.Fatalf("profile=%s lanes=%d/%d/%d", profile, ordinary, blocking, flush)
		}
	}
}

func TestProtocol8BothRolesRequireExactMajor(t *testing.T) {
	for _, role := range []authoritypb.TransportRole{authoritypb.TransportRole_TRANSPORT_ROLE_DATA, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL} {
		for _, major := range []uint32{0, ProtocolMajor - 1, ProtocolMajor, ProtocolMajor + 1, math.MaxUint32} {
			request := &authoritypb.HelloRequest{Role: role, ProtocolMajor: major}
			if err := validateProtocolMajor(request.GetProtocolMajor()); (err == nil) != (major == ProtocolMajor) {
				t.Fatalf("role=%s major=%d: %v", role, major, err)
			}
		}
	}
}

func TestProtocol8ReplayIdentityIsKeyedAndEnvelopeIndependent(t *testing.T) {
	buildRuntime := func() *volumeserver.Authority {
		runtime, err := volumeserver.New("wire-key", volumeserver.Config{ContinuousNow: func() (time.Duration, error) { return 0, nil }, SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1})
		if err != nil {
			t.Fatal(err)
		}
		return runtime
	}
	runtime := buildRuntime()
	request := &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{{1, 2, 3}}}}}
	initial, err := canonicalFingerprint(runtime, request)
	if err != nil {
		t.Fatal(err)
	}
	request.RequestId = 42
	request.Epoch = []byte{8}
	request.Session = &authoritypb.SessionProof{Id: []byte{1}, Generation: 9}
	request.Mutation = &authoritypb.Mutation{Slot: 3, Sequence: 4}
	replay, err := canonicalFingerprint(runtime, request)
	if err != nil || replay != initial {
		t.Fatalf("envelope changed fingerprint: %v", err)
	}
	other, err := canonicalFingerprint(buildRuntime(), request)
	if err != nil || other == initial {
		t.Fatal("fingerprint is not epoch-keyed")
	}
}

func TestProtocol8ProfileIsImmutableAcrossRolesAndRecovery(t *testing.T) {
	registry, err := newTransportRegistry(4)
	if err != nil {
		t.Fatal(err)
	}
	peer, set := volumeserver.PeerIdentity{1}, connectionSetID{2}
	profile := authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE
	data, err := registry.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_DATA, profile, func() {}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, func() {}, func() error { return nil }); !errors.Is(err, ErrTransportBinding) {
		t.Fatal("CONTROL changed profile", err)
	}
	if _, err := registry.register(peer, set, authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL, profile, func() {}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	data.pair.session = volumeserver.SessionID{3}
	data.pair.state = authoritypb.SessionState_SESSION_STATE_ACTIVE
	registry.mu.Unlock()
	if _, err := registry.register(peer, set, data.role, authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER, func() {}, func() error { return nil }); !errors.Is(err, ErrTransportBinding) {
		t.Fatal("recovery changed profile", err)
	}
	if _, err := registry.register(peer, set, data.role, profile, func() {}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
