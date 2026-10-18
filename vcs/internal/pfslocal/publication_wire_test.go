package pfslocal

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestPublicationAckSemanticCommitRoundTripAndValidation(t *testing.T) {
	for _, verdict := range []PublicationSemanticCommit{
		PublicationSemanticCommitPublished,
		PublicationSemanticCommitNotPublished,
	} {
		want := &PublicationAck{OperationID: 41, SemanticCommit: verdict}
		if got := roundTripBody(t, want); !reflect.DeepEqual(got, want) {
			t.Fatalf("publication ack round trip: got %#v, want %#v", got, want)
		}
		assertWireFields(t, marshalPublicationAck(want), 2, 3)
	}

	for _, verdict := range []PublicationSemanticCommit{
		PublicationSemanticCommitUnspecified,
		PublicationSemanticCommit(3),
	} {
		wire, err := MarshalEnvelope(&Envelope{Body: &PublicationAck{
			OperationID: 41, SemanticCommit: verdict,
		}})
		if errors.Is(err, ErrMalformed) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalEnvelope(wire); !errors.Is(err, ErrMalformed) {
			t.Fatalf("semantic commit %d decoded with err %v, want ErrMalformed", verdict, err)
		}
	}
}

func TestRenameReplyPostIdentitiesRoundTrip(t *testing.T) {
	want := &RenameReply{
		NewPostIdentity: bytes.Repeat([]byte{0xa1}, 16),
		OldPostIdentity: bytes.Repeat([]byte{0xb2}, 16),
	}
	if got := roundTripBody(t, want); !reflect.DeepEqual(got, want) {
		t.Fatalf("rename post identities round trip: got %#v, want %#v", got, want)
	}
	assertWireFields(t, marshalRenameReply(want), 1, 2)
}

func TestResourceReplyDispositionRoundTrip(t *testing.T) {
	for _, want := range []*ResourceReplyDisposition{
		{TargetRequestID: 41},
		{TargetRequestID: 41, AcceptHandles: true},
		{TargetRequestID: 41, AcceptedItemCount: 2},
		{TargetRequestID: 41, AcceptHandles: true, AcceptedItemCount: 1},
	} {
		decoded := roundTripBody(t, want)
		if !reflect.DeepEqual(decoded, want) {
			t.Fatalf("resource reply disposition round trip: got %#v, want %#v", decoded, want)
		}
		wire, err := MarshalEnvelope(&Envelope{RequestID: 0, Body: want})
		if err != nil {
			t.Fatal(err)
		}
		assertWireField(t, wire, 39, wireBytes)
		fields := []int{1}
		if want.AcceptHandles {
			fields = append(fields, 2)
		}
		if want.AcceptedItemCount != 0 {
			fields = append(fields, 3)
		}
		assertWireFields(t, marshalResourceReplyDisposition(want), fields...)
	}
}

func TestResolveReplyRoundTrip(t *testing.T) {
	want := &ResolveReply{
		Root:       Item{ItemID: 11, ItemGeneration: 13, StableIdentity: [16]byte{1}},
		RootAttr:   Attr{Item: Item{ItemID: 11, ItemGeneration: 13, StableIdentity: [16]byte{1}}, Kind: ItemKindDirectory},
		VolumeID:   "vol-17",
		VolumeName: "Shared",
		Capabilities: Capabilities{
			MaxNameBytes: 255, PreferredIOSize: 1 << 20,
		},
	}

	decoded := roundTripBody(t, want)
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("resolve reply round trip:\n got  %#v\n want %#v", decoded, want)
	}

	encoded := marshalResolveReply(want)
	assertWireFields(t, encoded, 1, 2, 3, 5, 6)
}

func TestItemStableIdentityWireIsExact(t *testing.T) {
	want := Item{ItemID: 7, ItemGeneration: 9, StableIdentity: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	got, err := parseItemField(wireBytes, marshalItem(&want))
	if err != nil || got != want {
		t.Fatalf("stable item round trip = %#v, %v; want %#v", got, err, want)
	}
	assertWireField(t, marshalItem(&want), 3, wireBytes)
	if _, err := parseItemField(wireBytes, appendBytesField(nil, 3, []byte{1, 2, 3})); err != ErrMalformed {
		t.Fatalf("short stable identity = %v, want ErrMalformed", err)
	}
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
