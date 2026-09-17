package authorityrpc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func coherenceV2DelegationRef() *authoritypb.DelegationRef {
	// Most encoding fixtures intentionally abbreviate fixed-width identities.
	// These tests exercise protobuf structure; semantic validation belongs to
	// the protocol consumers that require 16-byte identities.
	return &authoritypb.DelegationRef{Id: []byte{0xaa}, Generation: 2}
}

func coherenceV2Delegation() *authoritypb.Delegation {
	return &authoritypb.Delegation{
		Id:         []byte{0xaa},
		Generation: 2,
		Mode:       authoritypb.DelegationMode_DELEGATION_MODE_FULL,
	}
}

func assertCanonicalRoundTrip(t *testing.T, message proto.Message) {
	t.Helper()
	encoded, err := canonicalBytes(message.ProtoReflect())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWireMessage(encoded, message.ProtoReflect().Descriptor()); err != nil {
		t.Fatalf("canonical encoding rejected by frame grammar: %v", err)
	}
	decoded := message.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(message, decoded) {
		t.Fatalf("canonical round trip differs:\n got %v\nwant %v", decoded, message)
	}
}

func assertFrameRoundTrip(t *testing.T, message proto.Message) {
	t.Helper()
	var frame bytes.Buffer
	if err := writeFrame(&frame, 1<<20, message); err != nil {
		t.Fatal(err)
	}
	decoded := message.ProtoReflect().New().Interface()
	if err := readFrame(&frame, 1<<20, nil, 0, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(message, decoded) {
		t.Fatalf("frame round trip differs:\n got %v\nwant %v", decoded, message)
	}
}

func TestCoherenceV2CanonicalMessageRoundTrips(t *testing.T) {
	ref := coherenceV2DelegationRef()
	entry := &authoritypb.ChangeEntry{
		Position:       11,
		VolumeVersion:  12,
		Kind:           authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED,
		Identity:       bytes.Repeat([]byte{0x11}, 16),
		ParentIdentity: bytes.Repeat([]byte{0x22}, 16),
		Name:           []byte("entry"),
		ByteRange:      &authoritypb.ByteRange{Offset: 13, Length: 14},
	}
	tests := []struct {
		name    string
		message proto.Message
	}{
		{"subscribe request", &authoritypb.SubscribeRequest{SnapshotId: bytes.Repeat([]byte{0x31}, 16), AfterIdentity: bytes.Repeat([]byte{0x32}, 16)}},
		{"subscribe reply", &authoritypb.SubscribeReply{Watermark: 1, DelegatedIdentities: [][]byte{bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)}, Incarnation: 2, HorizonNanos: 3, SnapshotId: bytes.Repeat([]byte{3}, 16), NextAfterIdentity: bytes.Repeat([]byte{4}, 16)}},
		{"renew subscription request", &authoritypb.RenewSubscriptionRequest{Incarnation: 2}},
		{"renew subscription reply", &authoritypb.RenewSubscriptionReply{Incarnation: 2, HorizonNanos: 3}},
		{"next control event request", &authoritypb.NextControlEventRequest{Incarnation: 2, AfterSequence: 3, CompletedEventThrough: 2}},
		{"byte range", &authoritypb.ByteRange{Offset: 4, Length: 5}},
		{"change entry", entry},
		{"change batch", &authoritypb.ChangeBatch{Incarnation: 2, Entries: []*authoritypb.ChangeEntry{entry, {Position: 12, VolumeVersion: 13, Kind: authoritypb.ChangeKind_CHANGE_KIND_DIRECTORY_CHANGED, Identity: bytes.Repeat([]byte{0x33}, 16)}}}},
		{"change ack", &authoritypb.ChangeAck{Position: 11, Incarnation: 2}},
		{"change ack reply", &authoritypb.ChangeAckReply{}},
		{"delegation ref", ref},
		{"delegation", coherenceV2Delegation()},
		{"delegation recall", &authoritypb.DelegationRecall{Delegation: ref, Identity: bytes.Repeat([]byte{0x44}, 16), BudgetNanos: 5}},
		{"delegation break", &authoritypb.DelegationBreak{Delegation: ref, Identity: bytes.Repeat([]byte{0x44}, 16), BudgetNanos: 5}},
		{"delegation mode change", &authoritypb.DelegationModeChange{Delegation: ref, Identity: bytes.Repeat([]byte{0x44}, 16), Mode: authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH, BudgetNanos: 5}},
		{"delegation recall ack", &authoritypb.DelegationRecallAck{Incarnation: 2, EventSequence: 3, Delegation: ref, AppliedSequence: 4}},
		{"delegation recall ack reply", &authoritypb.DelegationRecallAckReply{}},
		{"delegation break ack", &authoritypb.DelegationBreakAck{Incarnation: 2, EventSequence: 3, Delegation: ref, AppliedSequence: 4}},
		{"delegation break ack reply", &authoritypb.DelegationBreakAckReply{}},
		{"delegation mode change ack", &authoritypb.DelegationModeChangeAck{Incarnation: 2, EventSequence: 3, Delegation: ref, AppliedSequence: 4}},
		{"delegation mode change ack reply", &authoritypb.DelegationModeChangeAckReply{}},
		{"delegation release", &authoritypb.DelegationRelease{Delegation: ref, AppliedSequence: 4}},
		{"delegation release request", &authoritypb.DelegationReleaseRequest{Incarnation: 2, ReleaseSequence: 4, CompletedReleaseThrough: 3, Delegations: []*authoritypb.DelegationRelease{{Delegation: ref, AppliedSequence: 4}}}},
		{"delegation release reply", &authoritypb.DelegationReleaseReply{}},
		{"barrier request", &authoritypb.BarrierRequest{CutSequence: 6}},
		{"barrier reply", &authoritypb.BarrierReply{AppliedSequence: 6, DurableSequence: 5}},
		{"wait visibility request", &authoritypb.WaitVisibilityRequest{CutSequence: 6}},
		{"wait visibility reply", &authoritypb.WaitVisibilityReply{AppliedSequence: 6, VisibleSequence: 5}},
		{"control change batch", &authoritypb.ControlEvent{Incarnation: 2, Sequence: 3, Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{Incarnation: 2, Entries: []*authoritypb.ChangeEntry{entry}}}}},
		{"control delegation recall", &authoritypb.ControlEvent{Incarnation: 2, Sequence: 3, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{Delegation: ref, Identity: bytes.Repeat([]byte{0x44}, 16), BudgetNanos: 5}}}},
		{"control delegation break", &authoritypb.ControlEvent{Incarnation: 2, Sequence: 3, Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{Delegation: ref, Identity: bytes.Repeat([]byte{0x44}, 16), BudgetNanos: 5}}}},
		{"control delegation mode change", &authoritypb.ControlEvent{Incarnation: 2, Sequence: 3, Event: &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{Delegation: ref, Identity: bytes.Repeat([]byte{0x44}, 16), Mode: authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH, BudgetNanos: 5}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCanonicalRoundTrip(t, test.message)
		})
	}
}

func TestCoherenceV2RequestFrameRoundTrips(t *testing.T) {
	ref := coherenceV2DelegationRef()
	tests := []struct {
		name    string
		request *authoritypb.Request
	}{
		{"subscribe", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_Subscribe{Subscribe: &authoritypb.SubscribeRequest{SnapshotId: bytes.Repeat([]byte{1}, 16), AfterIdentity: bytes.Repeat([]byte{2}, 16)}}}},
		{"renew subscription", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionRequest{Incarnation: 2}}}},
		{"next control event", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_NextControlEvent{NextControlEvent: &authoritypb.NextControlEventRequest{Incarnation: 2, AfterSequence: 3, CompletedEventThrough: 2}}}},
		{"change ack", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_ChangeAck{ChangeAck: &authoritypb.ChangeAck{Position: 4, Incarnation: 2}}}},
		{"delegation recall ack", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAck{Incarnation: 2, EventSequence: 3, Delegation: ref, AppliedSequence: 4}}}},
		{"delegation break ack", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAck{Incarnation: 2, EventSequence: 3, Delegation: ref, AppliedSequence: 4}}}},
		{"delegation mode change ack", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_DelegationModeChangeAck{DelegationModeChangeAck: &authoritypb.DelegationModeChangeAck{Incarnation: 2, EventSequence: 3, Delegation: ref, AppliedSequence: 4}}}},
		{"barrier", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{CutSequence: 5}}}},
		{"wait visibility", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityRequest{CutSequence: 5}}}},
		{"delegation release", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{Incarnation: 2, ReleaseSequence: 4, CompletedReleaseThrough: 3, Delegations: []*authoritypb.DelegationRelease{{Delegation: ref, AppliedSequence: 4}}}}}},
		{"create delegation intent", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: bytes.Repeat([]byte{1}, 16), Name: []byte("new"), Mode: 0o644, Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true, CacheCapable: true}}}},
		{"open delegation intent", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: bytes.Repeat([]byte{1}, 16), Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true, CacheCapable: true}}}},
		{"delegated write", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: bytes.Repeat([]byte{1}, 16), Position: 7, Size: 3, Data: []byte("abc"), Delegation: ref}}}},
		{"delegated setattr", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: bytes.Repeat([]byte{1}, 16), Size: proto.Int64(0), Delegation: ref}}}},
		{"delegated fallocate", &authoritypb.Request{RequestId: 7, Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{Handle: bytes.Repeat([]byte{1}, 16), Offset: 8, Length: 9, Delegation: ref}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCanonicalRoundTrip(t, test.request)
			assertFrameRoundTrip(t, test.request)
		})
	}
}

func TestCoherenceV2ResponseFrameRoundTrips(t *testing.T) {
	ref := coherenceV2DelegationRef()
	changeBatch := &authoritypb.ChangeBatch{Incarnation: 2, Entries: []*authoritypb.ChangeEntry{{
		Position: 1, VolumeVersion: 10, Kind: authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED,
		Identity: bytes.Repeat([]byte{0x11}, 16), ByteRange: &authoritypb.ByteRange{Offset: 4, Length: 8},
	}}}
	tests := []struct {
		name     string
		response *authoritypb.Response
	}{
		{"subscribe", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_Subscribe{Subscribe: &authoritypb.SubscribeReply{Watermark: 10, DelegatedIdentities: [][]byte{bytes.Repeat([]byte{1}, 16)}, Incarnation: 2, HorizonNanos: 3}}}},
		{"renew subscription", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionReply{Incarnation: 2, HorizonNanos: 3}}}},
		{"control change batch", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{Incarnation: 2, Sequence: 4, Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: changeBatch}}}}},
		{"control delegation recall", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{Incarnation: 2, Sequence: 4, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{Delegation: ref, Identity: bytes.Repeat([]byte{2}, 16), BudgetNanos: 5}}}}}},
		{"control delegation break", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{Incarnation: 2, Sequence: 4, Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{Delegation: ref, Identity: bytes.Repeat([]byte{2}, 16), BudgetNanos: 5}}}}}},
		{"control delegation mode change", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{Incarnation: 2, Sequence: 4, Event: &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{Delegation: ref, Identity: bytes.Repeat([]byte{2}, 16), Mode: authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH, BudgetNanos: 5}}}}}},
		{"change ack", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_ChangeAck{ChangeAck: &authoritypb.ChangeAckReply{}}}},
		{"delegation recall ack", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAckReply{}}}},
		{"delegation break ack", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAckReply{}}}},
		{"delegation mode change ack", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_DelegationModeChangeAck{DelegationModeChangeAck: &authoritypb.DelegationModeChangeAckReply{}}}},
		{"barrier", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{AppliedSequence: 6, DurableSequence: 5}}}},
		{"wait visibility", &authoritypb.Response{RequestId: 7, VisibleSequence: 5, Body: &authoritypb.Response_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityReply{AppliedSequence: 6, VisibleSequence: 5}}}},
		{"delegation release", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseReply{}}}},
		{"create delegation", &authoritypb.Response{RequestId: 7, VolumeVersion: 10, Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Delegation: coherenceV2Delegation(), CacheCapable: true}}}},
		{"open delegation", &authoritypb.Response{RequestId: 7, VolumeVersion: 10, Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: bytes.Repeat([]byte{3}, 16), Delegation: coherenceV2Delegation(), CacheCapable: true}}}},
		{"write durability", &authoritypb.Response{RequestId: 7, AppliedSequence: 6, VolumeVersion: 10, Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{CommittedSize: 4, AssignedOffset: 8, DurableSequence: 5}}}},
		{"fsync durability", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_Fsync{Fsync: &authoritypb.FsyncReply{DurableSequence: 5}}}},
		{"syncfs durability", &authoritypb.Response{RequestId: 7, Body: &authoritypb.Response_SyncFs{SyncFs: &authoritypb.SyncFSReply{DurableSequence: 5}}}},
		{"negative lookup served version", &authoritypb.Response{RequestId: 7, VolumeVersion: 10, Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: 9}}}},
		{"read served version", &authoritypb.Response{RequestId: 7, VolumeVersion: 10, Body: &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: []byte("abc"), VolumeVersion: 10}}}},
		{"empty readdir served version", &authoritypb.Response{RequestId: 7, VolumeVersion: 10, Body: &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Eof: true}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCanonicalRoundTrip(t, test.response)
			assertFrameRoundTrip(t, test.response)
		})
	}
}

func TestCoherenceV2CanonicalGoldenEncodings(t *testing.T) {
	ref := coherenceV2DelegationRef()
	tests := []struct {
		name    string
		message proto.Message
		wantHex string
	}{
		{"subscribe request", &authoritypb.SubscribeRequest{SnapshotId: []byte{0xaa}, AfterIdentity: []byte{0xbb}}, "0a01aa1201bb"},
		{"subscribe reply", &authoritypb.SubscribeReply{Watermark: 1, DelegatedIdentities: [][]byte{{0xaa}, {0xbb}}, Incarnation: 2, HorizonNanos: 3, SnapshotId: []byte{0xcc}, NextAfterIdentity: []byte{0xdd}}, "08011201aa1201bb180220032a01cc3201dd"},
		{"renew subscription request", &authoritypb.RenewSubscriptionRequest{Incarnation: 1}, "0801"},
		{"renew subscription reply", &authoritypb.RenewSubscriptionReply{Incarnation: 1, HorizonNanos: 2}, "08011002"},
		{"next control event request", &authoritypb.NextControlEventRequest{Incarnation: 1, AfterSequence: 2, CompletedEventThrough: 2}, "080110021802"},
		{"byte range", &authoritypb.ByteRange{Offset: 1, Length: 2}, "08011002"},
		{"change entry", &authoritypb.ChangeEntry{Position: 1, VolumeVersion: 2, Kind: authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED, Identity: []byte{0xaa}, ParentIdentity: []byte{0xbb}, Name: []byte{0xcc}, ByteRange: &authoritypb.ByteRange{Offset: 1, Length: 2}}, "0801100218032201aa2a01bb3201cc3a0408011002"},
		{"change batch", &authoritypb.ChangeBatch{Incarnation: 1, Entries: []*authoritypb.ChangeEntry{{Position: 1}}}, "080112020801"},
		{"change ack", &authoritypb.ChangeAck{Position: 1, Incarnation: 2}, "08011002"},
		{"delegation ref", ref, "0a01aa1002"},
		{"delegation", &authoritypb.Delegation{Id: []byte{0xaa}, Generation: 2, Mode: authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH}, "0a01aa10021802"},
		{"delegation recall", &authoritypb.DelegationRecall{Delegation: ref, Identity: []byte{0xbb}, BudgetNanos: 3}, "0a050a01aa10021201bb1803"},
		{"delegation break", &authoritypb.DelegationBreak{Delegation: ref, Identity: []byte{0xbb}, BudgetNanos: 3}, "0a050a01aa10021201bb1803"},
		{"delegation mode change", &authoritypb.DelegationModeChange{Delegation: ref, Identity: []byte{0xbb}, Mode: authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH, BudgetNanos: 3}, "0a050a01aa10021201bb18022003"},
		{"delegation recall ack", &authoritypb.DelegationRecallAck{Incarnation: 1, EventSequence: 2, Delegation: ref, AppliedSequence: 3}, "080110021a050a01aa10022003"},
		{"delegation break ack", &authoritypb.DelegationBreakAck{Incarnation: 1, EventSequence: 2, Delegation: ref, AppliedSequence: 3}, "080110021a050a01aa10022003"},
		{"delegation mode change ack", &authoritypb.DelegationModeChangeAck{Incarnation: 1, EventSequence: 2, Delegation: ref, AppliedSequence: 3}, "080110021a050a01aa10022003"},
		{"delegation release", &authoritypb.DelegationRelease{Delegation: ref, AppliedSequence: 3}, "0a050a01aa10021003"},
		{"delegation release request", &authoritypb.DelegationReleaseRequest{Incarnation: 1, ReleaseSequence: 4, CompletedReleaseThrough: 3, Delegations: []*authoritypb.DelegationRelease{{Delegation: ref, AppliedSequence: 3}}}, "080112090a050a01aa1002100318042003"},
		{"barrier request", &authoritypb.BarrierRequest{CutSequence: 1}, "0801"},
		{"barrier reply", &authoritypb.BarrierReply{AppliedSequence: 1, DurableSequence: 2}, "08011002"},
		{"wait visibility request", &authoritypb.WaitVisibilityRequest{CutSequence: 1}, "0801"},
		{"wait visibility reply", &authoritypb.WaitVisibilityReply{AppliedSequence: 1, VisibleSequence: 2}, "08011002"},
		{"control change tag", &authoritypb.ControlEvent{Incarnation: 1, Sequence: 2, Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{}}}, "080110021a00"},
		{"control recall tag", &authoritypb.ControlEvent{Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{}}}, "2200"},
		{"control break tag", &authoritypb.ControlEvent{Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{}}}, "2a00"},
		{"control mode change tag", &authoritypb.ControlEvent{Event: &authoritypb.ControlEvent_DelegationModeChange{DelegationModeChange: &authoritypb.DelegationModeChange{}}}, "3200"},
		{"setattr delegation tag", &authoritypb.SetAttrRequest{Delegation: ref}, "5a050a01aa1002"},
		{"create request intent tags", &authoritypb.CreateRequest{WriteIntent: true, CacheCapable: true}, "30013801"},
		{"create reply delegation tags", &authoritypb.CreateReply{Delegation: coherenceV2Delegation(), CacheCapable: true}, "1a070a01aa100218012001"},
		{"open request intent tags", &authoritypb.OpenRequest{WriteIntent: true, CacheCapable: true}, "18012001"},
		{"open reply delegation tags", &authoritypb.OpenReply{Delegation: coherenceV2Delegation(), CacheCapable: true}, "12070a01aa100218011801"},
		{"write delegation tag", &authoritypb.WriteRequest{Delegation: ref}, "6a050a01aa1002"},
		{"write durable sequence tag", &authoritypb.WriteReply{DurableSequence: 1}, "4001"},
		{"fallocate delegation tag", &authoritypb.FallocateRequest{Delegation: ref}, "42050a01aa1002"},
		{"fsync durable sequence tag", &authoritypb.FsyncReply{DurableSequence: 1}, "0801"},
		{"syncfs durable sequence tag", &authoritypb.SyncFSReply{DurableSequence: 1}, "0801"},
		{"response applied sequence tag", &authoritypb.Response{AppliedSequence: 1}, "c00301"},
		{"response volume version tag", &authoritypb.Response{VolumeVersion: 1}, "980401"},
		{"response visible sequence tag", &authoritypb.Response{VisibleSequence: 1}, "b00401"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want, err := hex.DecodeString(test.wantHex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalBytes(test.message.ProtoReflect())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("canonical encoding differs:\n got %x\nwant %x", got, want)
			}
		})
	}
}

func TestCoherenceV2EnvelopeBodyTagsAreFrozen(t *testing.T) {
	tests := []struct {
		name    string
		message proto.Message
		wantHex string
	}{
		{"request subscribe 65", &authoritypb.Request{Body: &authoritypb.Request_Subscribe{Subscribe: &authoritypb.SubscribeRequest{}}}, "8a0400"},
		{"request renew subscription 66", &authoritypb.Request{Body: &authoritypb.Request_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionRequest{}}}, "920400"},
		{"request next control event 67", &authoritypb.Request{Body: &authoritypb.Request_NextControlEvent{NextControlEvent: &authoritypb.NextControlEventRequest{}}}, "9a0400"},
		{"request change ack 68", &authoritypb.Request{Body: &authoritypb.Request_ChangeAck{ChangeAck: &authoritypb.ChangeAck{}}}, "a20400"},
		{"request recall ack 69", &authoritypb.Request{Body: &authoritypb.Request_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAck{}}}, "aa0400"},
		{"request break ack 70", &authoritypb.Request{Body: &authoritypb.Request_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAck{}}}, "b20400"},
		{"request mode change ack 71", &authoritypb.Request{Body: &authoritypb.Request_DelegationModeChangeAck{DelegationModeChangeAck: &authoritypb.DelegationModeChangeAck{}}}, "ba0400"},
		{"request barrier 72", &authoritypb.Request{Body: &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{}}}, "c20400"},
		{"request delegation release 73", &authoritypb.Request{Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{}}}, "ca0400"},
		{"request wait visibility 75", &authoritypb.Request{Body: &authoritypb.Request_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityRequest{}}}, "da0400"},
		{"response subscribe 57", &authoritypb.Response{Body: &authoritypb.Response_Subscribe{Subscribe: &authoritypb.SubscribeReply{}}}, "ca0300"},
		{"response renew subscription 58", &authoritypb.Response{Body: &authoritypb.Response_RenewSubscription{RenewSubscription: &authoritypb.RenewSubscriptionReply{}}}, "d20300"},
		{"response control event 59", &authoritypb.Response{Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{}}}, "da0300"},
		{"response change ack 60", &authoritypb.Response{Body: &authoritypb.Response_ChangeAck{ChangeAck: &authoritypb.ChangeAckReply{}}}, "e20300"},
		{"response recall ack 61", &authoritypb.Response{Body: &authoritypb.Response_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAckReply{}}}, "ea0300"},
		{"response break ack 62", &authoritypb.Response{Body: &authoritypb.Response_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAckReply{}}}, "f20300"},
		{"response mode change ack 63", &authoritypb.Response{Body: &authoritypb.Response_DelegationModeChangeAck{DelegationModeChangeAck: &authoritypb.DelegationModeChangeAckReply{}}}, "fa0300"},
		{"response barrier 64", &authoritypb.Response{Body: &authoritypb.Response_Barrier{Barrier: &authoritypb.BarrierReply{}}}, "820400"},
		{"response delegation release 65", &authoritypb.Response{Body: &authoritypb.Response_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseReply{}}}, "8a0400"},
		{"response fsync 66", &authoritypb.Response{Body: &authoritypb.Response_Fsync{Fsync: &authoritypb.FsyncReply{}}}, "920400"},
		{"response wait visibility 71", &authoritypb.Response{Body: &authoritypb.Response_WaitVisibility{WaitVisibility: &authoritypb.WaitVisibilityReply{}}}, "ba0400"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want, err := hex.DecodeString(test.wantHex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := canonicalBytes(test.message.ProtoReflect())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("body tag differs: got %x, want %x", got, want)
			}
		})
	}
}

func TestCoherenceV2ByteRangePresenceDistinguishesWholeFileFromZeroRange(t *testing.T) {
	absent := &authoritypb.ChangeEntry{Position: 1}
	presentZero := &authoritypb.ChangeEntry{Position: 1, ByteRange: &authoritypb.ByteRange{}}
	absentBytes, err := canonicalBytes(absent.ProtoReflect())
	if err != nil {
		t.Fatal(err)
	}
	presentBytes, err := canonicalBytes(presentZero.ProtoReflect())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(absentBytes, presentBytes) {
		t.Fatal("absent whole-file range and present zero range have the same encoding")
	}
	if !bytes.Equal(absentBytes, []byte{0x08, 0x01}) || !bytes.Equal(presentBytes, []byte{0x08, 0x01, 0x3a, 0x00}) {
		t.Fatalf("range presence encodings: absent=%x present-zero=%x", absentBytes, presentBytes)
	}

	response := &authoritypb.Response{Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{
		Incarnation: 1,
		Sequence:    2,
		Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{
			Incarnation: 1,
			Entries:     []*authoritypb.ChangeEntry{absent, presentZero},
		}},
	}}}
	assertFrameRoundTrip(t, response)
	if got := response.GetControlEvent().GetChangeBatch().GetEntries(); got[0].GetByteRange() != nil || got[1].GetByteRange() == nil {
		t.Fatalf("test fixture lost presence before encoding: %v", got)
	}
}

func TestCoherenceV2EnumNumbersAreFrozen(t *testing.T) {
	changeKinds := map[authoritypb.ChangeKind]int32{
		authoritypb.ChangeKind_CHANGE_KIND_UNSPECIFIED:         0,
		authoritypb.ChangeKind_CHANGE_KIND_NAMESPACE_CHANGED:   1,
		authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED:  2,
		authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED:        3,
		authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_GRANTED:  4,
		authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_RELEASED: 5,
		authoritypb.ChangeKind_CHANGE_KIND_DIRECTORY_CHANGED:   6,
	}
	for value, want := range changeKinds {
		if got := int32(value); got != want {
			t.Fatalf("ChangeKind %s=%d, want %d", value, got, want)
		}
		assertCanonicalRoundTrip(t, &authoritypb.ChangeEntry{Kind: value})
	}
	delegationModes := map[authoritypb.DelegationMode]int32{
		authoritypb.DelegationMode_DELEGATION_MODE_UNSPECIFIED:  0,
		authoritypb.DelegationMode_DELEGATION_MODE_FULL:         1,
		authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH: 2,
	}
	for value, want := range delegationModes {
		if got := int32(value); got != want {
			t.Fatalf("DelegationMode %s=%d, want %d", value, got, want)
		}
		assertCanonicalRoundTrip(t, &authoritypb.Delegation{Mode: value})
	}
}

func TestCoherenceV2RejectsUnknownAndDuplicateWireFields(t *testing.T) {
	unknown := &authoritypb.Response{Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{
		Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{Entries: []*authoritypb.ChangeEntry{{Position: 1}}}},
	}}}
	unknown.GetControlEvent().GetChangeBatch().GetEntries()[0].ProtoReflect().SetUnknown(
		protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1),
	)
	if _, err := canonicalBytes(unknown.ProtoReflect()); !errors.Is(err, errNonCanonical) {
		t.Fatalf("canonical nested unknown field = %v, want errNonCanonical", err)
	}

	tests := []struct {
		name   string
		nested []byte
	}{
		{
			name: "unknown nested change ack field",
			nested: protowire.AppendVarint(
				protowire.AppendTag(nil, 99, protowire.VarintType), 1,
			),
		},
		{
			name: "duplicate nested change ack position",
			nested: protowire.AppendVarint(
				protowire.AppendTag(
					protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1),
					1, protowire.VarintType,
				),
				2,
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := protowire.AppendBytes(protowire.AppendTag(nil, 68, protowire.BytesType), test.nested)
			var decoded authoritypb.Request
			err := readFrame(bytes.NewReader(encodedRawFrame(metadata, nil)), 4096, nil, 0, &decoded)
			if !errors.Is(err, ErrFrameEncoding) {
				t.Fatalf("readFrame = %v, want ErrFrameEncoding", err)
			}
			if decoded.GetBody() != nil {
				t.Fatalf("non-canonical nested body reached protobuf decode: %v", &decoded)
			}
		})
	}
}

func TestCoherenceV2RepeatedCollectionsRespectFrameBound(t *testing.T) {
	makeIdentities := func(count int) [][]byte {
		values := make([][]byte, count)
		for i := range values {
			values[i] = []byte{byte(i)}
		}
		return values
	}
	makeEntries := func(count int) []*authoritypb.ChangeEntry {
		values := make([]*authoritypb.ChangeEntry, count)
		for i := range values {
			values[i] = &authoritypb.ChangeEntry{}
		}
		return values
	}
	makeReleases := func(count int) []*authoritypb.DelegationRelease {
		values := make([]*authoritypb.DelegationRelease, count)
		for i := range values {
			values[i] = &authoritypb.DelegationRelease{}
		}
		return values
	}
	tests := []struct {
		name  string
		atMax proto.Message
		over  proto.Message
	}{
		{
			name:  "delegated identities",
			atMax: &authoritypb.Response{Body: &authoritypb.Response_Subscribe{Subscribe: &authoritypb.SubscribeReply{DelegatedIdentities: makeIdentities(maxWireRepeatedElements)}}},
			over:  &authoritypb.Response{Body: &authoritypb.Response_Subscribe{Subscribe: &authoritypb.SubscribeReply{DelegatedIdentities: makeIdentities(maxWireRepeatedElements + 1)}}},
		},
		{
			name:  "change entries",
			atMax: &authoritypb.Response{Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{Entries: makeEntries(maxWireRepeatedElements)}}}}},
			over:  &authoritypb.Response{Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{Event: &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: &authoritypb.ChangeBatch{Entries: makeEntries(maxWireRepeatedElements + 1)}}}}},
		},
		{
			name:  "delegation releases",
			atMax: &authoritypb.Request{Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{Delegations: makeReleases(maxWireRepeatedElements)}}},
			over:  &authoritypb.Request{Body: &authoritypb.Request_DelegationRelease{DelegationRelease: &authoritypb.DelegationReleaseRequest{Delegations: makeReleases(maxWireRepeatedElements + 1)}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := writeFrame(io.Discard, 1<<20, test.atMax); err != nil {
				t.Fatalf("collection at frame bound: %v", err)
			}
			var frame bytes.Buffer
			if err := writeFrame(&frame, 1<<20, test.over); err != nil {
				t.Fatal(err)
			}
			decoded := test.over.ProtoReflect().Type().New().Interface()
			if err := readFrame(&frame, 1<<20, nil, 0, decoded); !errors.Is(err, ErrFrameEncoding) {
				t.Fatalf("collection over ingress frame bound = %v, want ErrFrameEncoding", err)
			}
		})
	}
}

var coherenceV2BenchmarkEncoding []byte

func BenchmarkChangeBatchEncoding(b *testing.B) {
	entries := make([]*authoritypb.ChangeEntry, 256)
	for i := range entries {
		entries[i] = &authoritypb.ChangeEntry{
			Position:      uint64(i + 1),
			VolumeVersion: uint64(1000 + i),
			Kind:          authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED,
			Identity:      bytes.Repeat([]byte{byte(i)}, 16),
			ByteRange:     &authoritypb.ByteRange{Offset: uint64(i) * 4096, Length: 4096},
		}
	}
	batch := &authoritypb.ChangeBatch{Incarnation: 7, Entries: entries}
	b.Run("canonical", func(b *testing.B) {
		b.SetBytes(int64(proto.Size(batch)))
		b.ReportAllocs()
		for range b.N {
			encoded, err := canonicalBytes(batch.ProtoReflect())
			if err != nil {
				b.Fatal(err)
			}
			coherenceV2BenchmarkEncoding = encoded
		}
	})
	response := &authoritypb.Response{Body: &authoritypb.Response_ControlEvent{ControlEvent: &authoritypb.ControlEvent{
		Incarnation: 7,
		Sequence:    19,
		Event:       &authoritypb.ControlEvent_ChangeBatch{ChangeBatch: batch},
	}}}
	b.Run("control-frame", func(b *testing.B) {
		b.SetBytes(int64(proto.Size(response)))
		b.ReportAllocs()
		for range b.N {
			if err := writeFrame(io.Discard, 1<<20, response); err != nil {
				b.Fatal(err)
			}
		}
	})
}
