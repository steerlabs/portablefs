package pfslocal

import (
	"bytes"
	"reflect"
	"testing"
)

func TestProtocolMinorIncludesV3CoherenceAndLiveness(t *testing.T) {
	if ProtocolMinor != 9 {
		t.Fatalf("ProtocolMinor = %d, want 9", ProtocolMinor)
	}
	if VisibilityPhasePrepare != 1 || VisibilityPhaseComplete != 2 {
		t.Fatalf("visibility phase values changed: prepare=%d complete=%d", VisibilityPhasePrepare, VisibilityPhaseComplete)
	}
	if VisibilityScopeNamespace != 1 || VisibilityScopeData != 2 || VisibilityScopeAttributes != 3 {
		t.Fatalf("visibility scope values changed: namespace=%d data=%d attributes=%d",
			VisibilityScopeNamespace, VisibilityScopeData, VisibilityScopeAttributes)
	}
}

func TestV3CoherenceResolveReplyRoundTrip(t *testing.T) {
	want := &ResolveReply{
		Root:       Item{ItemID: 11, ItemGeneration: 13},
		RootAttr:   Attr{Item: Item{ItemID: 11, ItemGeneration: 13}, Kind: ItemKindDirectory},
		VolumeID:   "vol-17",
		Branch:     "main",
		VolumeName: "Shared",
		Capabilities: Capabilities{
			Symlinks: true, HardLinks: true, Xattrs: true, CaseSensitive: true,
			MaxNameBytes: 255, PreferredIOSize: 1 << 20,
		},
		V3Coherence: &V3CoherenceContract{
			AuthorityProtocolMajor: 2,
			AuthorityEpoch:         bytes.Repeat([]byte{0xa1}, 16),
			SessionID:              bytes.Repeat([]byte{0xb2}, 16),
			CachePolicy:            "macos26-synchronous-vfs-repair-v1",
			RepairBudgetMillis:     15_000,
			InitialCursor:          &VisibilityCursor{Sequence: 41, Phase: VisibilityPhaseComplete},
		},
	}

	decoded := roundTripBody(t, want)
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("resolve reply round trip:\n got  %#v\n want %#v", decoded, want)
	}

	encoded := marshalResolveReply(want)
	assertWireField(t, encoded, 7, wireBytes)
	assertWireFields(t, marshalV3CoherenceContract(want.V3Coherence), 1, 2, 3, 4, 5, 6)
}

func TestResolveReplyWithoutV3CoherenceKeepsLegacyShape(t *testing.T) {
	want := &ResolveReply{Root: Item{ItemID: 1, ItemGeneration: 2}, VolumeID: "legacy"}
	decoded := roundTripBody(t, want).(*ResolveReply)
	if decoded.V3Coherence != nil {
		t.Fatalf("absent v3 coherence decoded as %#v", decoded.V3Coherence)
	}

	encoded := marshalResolveReply(want)
	assertWireFieldAbsent(t, encoded, 7)
}

func TestItemStableIdentityWireIsExactAndLegacyOptional(t *testing.T) {
	want := Item{ItemID: 7, ItemGeneration: 9, StableIdentity: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	got, err := parseItemField(wireBytes, marshalItem(&want))
	if err != nil || got != want {
		t.Fatalf("stable item round trip = %#v, %v; want %#v", got, err, want)
	}
	assertWireField(t, marshalItem(&want), 3, wireBytes)
	legacy := marshalItem(&Item{ItemID: 7, ItemGeneration: 9})
	assertWireFieldAbsent(t, legacy, 3)
	if _, err := parseItemField(wireBytes, appendBytesField(nil, 3, []byte{1, 2, 3})); err != ErrMalformed {
		t.Fatalf("short stable identity = %v, want ErrMalformed", err)
	}
}

func TestV3LivenessBodiesRoundTripAndPinEnvelopeFields(t *testing.T) {
	want := &V3LivenessRequest{
		AuthorityEpoch: bytes.Repeat([]byte{0x81}, 16),
		SessionID:      bytes.Repeat([]byte{0x82}, 16),
	}
	decoded := roundTripBody(t, want)
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("liveness request round trip:\n got  %#v\n want %#v", decoded, want)
	}
	wire, err := MarshalEnvelope(&Envelope{RequestID: 9, Body: want})
	if err != nil {
		t.Fatal(err)
	}
	assertWireField(t, wire, 38, wireBytes)
	assertWireFields(t, marshalV3LivenessRequest(want), 1, 2)

	reply := &V3LivenessReply{
		AuthorityEpoch: bytes.Repeat([]byte{0x81}, 16),
		SessionID:      bytes.Repeat([]byte{0x82}, 16),
	}
	if got := roundTripBody(t, reply); !reflect.DeepEqual(got, reply) {
		t.Fatalf("liveness reply round trip: got %#v, want %#v", got, reply)
	}
	replyWire, err := MarshalEnvelope(&Envelope{RequestID: 9, Body: reply})
	if err != nil {
		t.Fatal(err)
	}
	assertWireField(t, replyWire, 87, wireBytes)
}

func TestV3VisibilityEventRoundTrip(t *testing.T) {
	want := &Event{Kind: &V3VisibilityEvent{
		AuthorityEpoch:     bytes.Repeat([]byte{0x11}, 16),
		Cursor:             VisibilityCursor{Sequence: 73, Phase: VisibilityPhasePrepare},
		InitiatorSessionID: bytes.Repeat([]byte{0x22}, 16),
		MutationSlot:       5,
		Targets: []VisibilityTarget{
			{
				Scope:          VisibilityScopeNamespace,
				ParentIdentity: bytes.Repeat([]byte{0x33}, 16),
				Name:           []byte("renamed"),
			},
			{
				Scope:    VisibilityScopeData,
				Identity: bytes.Repeat([]byte{0x44}, 16),
				Size:     4_096,
			},
			{
				Scope:    VisibilityScopeAttributes,
				Identity: bytes.Repeat([]byte{0x55}, 16),
			},
		},
		MutationSequence: 89,
		LocalOperationID: 144,
	}}

	decoded := roundTripBody(t, want)
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("visibility event round trip:\n got  %#v\n want %#v", decoded, want)
	}

	encoded := marshalEvent(want)
	assertWireField(t, encoded, 3, wireBytes)
	visibility := want.Kind.(*V3VisibilityEvent)
	assertWireFields(t, marshalV3VisibilityEvent(visibility), 1, 2, 3, 4, 5, 6, 8)
	assertWireFields(t, marshalVisibilityCursor(&visibility.Cursor), 1, 2)
	assertWireFields(t, marshalVisibilityTarget(&visibility.Targets[0]), 1, 3, 4)
	assertWireFields(t, marshalVisibilityTarget(&visibility.Targets[1]), 1, 2, 5)
	assertWireFields(t, marshalVisibilityTarget(&visibility.Targets[2]), 1, 2)
}

func TestV3RoutesVisibilityEventRoundTrip(t *testing.T) {
	want := &Event{Kind: &V3VisibilityEvent{
		AuthorityEpoch:   bytes.Repeat([]byte{0x61}, 16),
		Cursor:           VisibilityCursor{Sequence: 97, Phase: VisibilityPhaseComplete},
		MutationSequence: 103,
		Routes: &RoutesChange{
			Revision: bytes.Repeat([]byte{0x66}, 32),
			Rules:    []byte("/local/cache\n"),
		},
	}}

	decoded := roundTripBody(t, want)
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("routes visibility event round trip:\n got  %#v\n want %#v", decoded, want)
	}

	visibility := want.Kind.(*V3VisibilityEvent)
	assertWireFields(t, marshalV3VisibilityEvent(visibility), 1, 2, 6, 7)
	assertWireFields(t, marshalRoutesChange(visibility.Routes), 1, 2)
}

func TestVisibilityAckBodiesRoundTripAndPinEnvelopeFields(t *testing.T) {
	want := &VisibilityAckRequest{
		AuthorityEpoch: bytes.Repeat([]byte{0x71}, 16),
		Cursor:         VisibilityCursor{Sequence: 101, Phase: VisibilityPhaseComplete},
		Blocked:        true,
		Reason:         "namespace repair waits on a callback lock",
	}
	decoded := roundTripBody(t, want)
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("visibility ack round trip:\n got  %#v\n want %#v", decoded, want)
	}

	requestWire, err := MarshalEnvelope(&Envelope{RequestID: 7, Body: want})
	if err != nil {
		t.Fatal(err)
	}
	assertWireField(t, requestWire, 37, wireBytes)
	assertWireFields(t, marshalVisibilityAckRequest(want), 1, 2, 3, 4)

	reply := &VisibilityAckReply{}
	if got := roundTripBody(t, reply); !reflect.DeepEqual(got, reply) {
		t.Fatalf("visibility ack reply round trip: got %#v, want %#v", got, reply)
	}
	replyWire, err := MarshalEnvelope(&Envelope{RequestID: 7, Body: reply})
	if err != nil {
		t.Fatal(err)
	}
	assertWireField(t, replyWire, 86, wireBytes)
}

func roundTripBody(t *testing.T, body any) any {
	t.Helper()
	wire, err := MarshalEnvelope(&Envelope{RequestID: 1, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := UnmarshalEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.Body
}

func assertWireField(t *testing.T, b []byte, wantNum, wantType int) {
	t.Helper()
	found := false
	if err := scan(b, func(num int, wt int, _ []byte) error {
		if num == wantNum {
			found = true
			if wt != wantType {
				t.Fatalf("field %d wire type = %d, want %d", wantNum, wt, wantType)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("field %d absent from %x", wantNum, b)
	}
}

func assertWireFieldAbsent(t *testing.T, b []byte, unwantedNum int) {
	t.Helper()
	if err := scan(b, func(num int, _ int, _ []byte) error {
		if num == unwantedNum {
			t.Fatalf("unexpected field %d in %x", unwantedNum, b)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertWireFields(t *testing.T, b []byte, want ...int) {
	t.Helper()
	counts := make(map[int]int)
	if err := scan(b, func(num int, _ int, _ []byte) error {
		counts[num]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, num := range want {
		if counts[num] == 0 {
			t.Fatalf("field %d absent from %x", num, b)
		}
		delete(counts, num)
	}
	if len(counts) != 0 {
		t.Fatalf("unexpected fields %v in %x", counts, b)
	}
}
