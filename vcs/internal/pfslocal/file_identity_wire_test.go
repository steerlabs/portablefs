package pfslocal

import (
	"bytes"
	"reflect"
	"testing"
)

// fileIdentityGoldenEnvelopes are the minor-16 frames shared with the Swift
// suite. They pin Attr.file_id/parent_file_id on a live owning Attr and on a
// non-owning entry snapshot, and both EnumerateEntries bodies at their exact
// envelope field numbers.
func fileIdentityGoldenEnvelopes() map[string]*Envelope {
	root := Item{ItemID: 1, ItemGeneration: 9, StableIdentity: [16]byte(bytes.Repeat([]byte{0x20}, 16))}
	return map[string]*Envelope{
		"attr_file_ids.hex": {RequestID: 59, PublicationAckRequired: true, OperationID: 4, Body: &LookupReply{Attr: Attr{
			Item: Item{ItemID: 23, ItemGeneration: 9, StableIdentity: [16]byte(bytes.Repeat([]byte{0x44}, 16))},
			Kind: ItemKindFile, Mode: 0o644, Nlink: 2, UID: 501, GID: 20, Size: 4097,
			MtimeMs: 31, CtimeMs: 37, AtimeMs: 41, BirthtimeMs: 43,
			Parent: &root, AllocSize: 8192, FileID: 1<<62 + 5, ParentFileID: 1,
		}}},
		"enumerate_entries_request.hex": {RequestID: 61, OperationID: 5, Body: &EnumerateEntriesRequest{
			Dir: root, Cookie: 1<<63 + 3, MaxEntries: 64, WantAttrs: true, Handle: 7,
		}},
		"enumerate_entries_reply.hex": {RequestID: 61, PublicationAckRequired: true, OperationID: 5, Body: &EnumerateEntriesReply{
			Entries: []DirEntry{
				{Name: []byte("a"), Cookie: 1<<63 + 4, Attr: Attr{
					Kind: ItemKindFile, Mode: 0o644, Nlink: 2, UID: 501, GID: 20, Size: 3,
					MtimeMs: 31, CtimeMs: 37, AtimeMs: 41, BirthtimeMs: 43, AllocSize: 4096,
					FileID: 1234, ParentFileID: 1,
				}},
				{Name: []byte{0xff, 'b'}, Attr: Attr{Kind: ItemKindDirectory, FileID: 5678, ParentFileID: 1}},
			},
			DirVersion: 77,
		}},
	}
}

func TestFileIdentityGoldenFramesRoundTripExactly(t *testing.T) {
	for name, env := range fileIdentityGoldenEnvelopes() {
		t.Run(name, func(t *testing.T) {
			frame, err := EncodeFrame(env)
			if err != nil {
				t.Fatal(err)
			}
			if golden := readGolden(t, name); !bytes.Equal(frame, golden) {
				t.Fatalf("frame\n got %x\nwant %x", frame, golden)
			}
			decoded, err := ReadFrame(bytes.NewReader(frame))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, env) {
				t.Fatalf("round trip:\n got  %#v\n want %#v", decoded, env)
			}
		})
	}
}

// The minor-16 fields are canonical proto3 scalars: zero is omitted, so every
// pre-16 Attr frame keeps its exact bytes and the older goldens stay valid.
func TestAttrFileIdentityFieldsAreCanonicalAndAdditive(t *testing.T) {
	for _, test := range []struct {
		name   string
		attr   Attr
		suffix []byte
	}{
		{name: "absent", attr: Attr{Kind: ItemKindFile}},
		{name: "file-id-only", attr: Attr{Kind: ItemKindFile, FileID: 2}, suffix: []byte{0x80, 0x01, 0x02}},
		{name: "parent-only", attr: Attr{Kind: ItemKindFile, ParentFileID: 1}, suffix: []byte{0x88, 0x01, 0x01}},
		{name: "both", attr: Attr{Kind: ItemKindFile, FileID: 300, ParentFileID: 1}, suffix: []byte{0x80, 0x01, 0xac, 0x02, 0x88, 0x01, 0x01}},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := marshalAttr(&Attr{Kind: ItemKindFile})
			encoded := marshalAttr(&test.attr)
			if !bytes.Equal(encoded, append(base, test.suffix...)) {
				t.Fatalf("attr encoding = %x, want %x%x", encoded, base, test.suffix)
			}
			decoded, err := parseAttrField(wireBytes, encoded)
			if err != nil || !reflect.DeepEqual(decoded, test.attr) {
				t.Fatalf("attr decode = (%#v, %v), want %#v", decoded, err, test.attr)
			}
		})
	}
}

// The non-owning listing has its own envelope slots. The frozen item-owning
// EnumerateRequest keeps field 13 and its meaning; a decoder must never
// confuse the two, because the daemon serves one and refuses the other.
func TestEnumerateEntriesUsesDistinctEnvelopeFields(t *testing.T) {
	for _, test := range []struct {
		body  any
		field byte
	}{
		{body: &EnumerateEntriesRequest{Cookie: 1, MaxEntries: 2, Handle: 3}, field: 40},
		{body: &EnumerateEntriesReply{NextCookie: 1, DirVersion: 2}, field: 88},
		{body: &EnumerateRequest{Cookie: 1, MaxEntries: 2, Handle: 3}, field: 13},
		{body: &EnumerateReply{NextCookie: 1, DirVersion: 2}, field: 63},
	} {
		encoded, err := MarshalEnvelope(&Envelope{Body: test.body})
		if err != nil {
			t.Fatal(err)
		}
		num, wt, _, err := consumeTag(encoded)
		if err != nil || num != int(test.field) || wt != wireBytes {
			t.Fatalf("%T encoded at field %d (wire type %d, err %v), want %d", test.body, num, wt, err, test.field)
		}
		decoded, err := UnmarshalEnvelope(encoded)
		if err != nil || !reflect.DeepEqual(decoded.Body, test.body) {
			t.Fatalf("%T decoded as %#v (%v)", test.body, decoded.Body, err)
		}
	}
}
