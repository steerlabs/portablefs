package pfslocal

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "pfslocal", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGoldenHelloRequestFrame(t *testing.T) {
	env := &Envelope{RequestID: 1, Body: &Hello{ProtocolMajor: 1, ClientName: "swift", ClientVersion: "1.0"}}
	got, err := EncodeFrame(env)
	if err != nil {
		t.Fatal(err)
	}
	if want := readGolden(t, "hello_request.hex"); !bytes.Equal(got, want) {
		t.Fatalf("hello request frame\n got %x\nwant %x", got, want)
	}
	dec, err := ReadFrame(bytes.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	hello, ok := dec.Body.(*Hello)
	if !ok || dec.RequestID != 1 || hello.ProtocolMajor != 1 || hello.ClientName != "swift" || hello.ClientVersion != "1.0" {
		t.Fatalf("decoded hello = %#v %#v", dec, dec.Body)
	}
}

func TestGoldenHelloReplyFrame(t *testing.T) {
	env := &Envelope{RequestID: 1, Body: &HelloReply{ProtocolMajor: 1, DaemonVersion: "portablefsd-test"}}
	got, err := EncodeFrame(env)
	if err != nil {
		t.Fatal(err)
	}
	if want := readGolden(t, "hello_reply.hex"); !bytes.Equal(got, want) {
		t.Fatalf("hello reply frame\n got %x\nwant %x", got, want)
	}
	dec, err := ReadFrame(bytes.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	rep, ok := dec.Body.(*HelloReply)
	if !ok || dec.RequestID != 1 || rep.ProtocolMajor != 1 || rep.DaemonVersion != "portablefsd-test" {
		t.Fatalf("decoded reply = %#v %#v", dec, dec.Body)
	}
}

func TestFramingRejectsOversized(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(MaxFrameBytes+1))
	if _, err := ReadFrame(bytes.NewReader(hdr[:])); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame oversized err=%v", err)
	}
}

func TestStreamMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Envelope{RequestID: 2, Body: &OpenReply{Handle: 99}}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, &Envelope{
		RequestID: 1,
		Body:      &CloseReply{Retired: true, CloseErrno: 5},
	}); err != nil {
		t.Fatal(err)
	}
	first, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != 2 || second.RequestID != 1 {
		t.Fatalf("stream order ids = %d, %d", first.RequestID, second.RequestID)
	}
	closeReply, ok := second.Body.(*CloseReply)
	if !ok || !closeReply.Retired || closeReply.CloseErrno != 5 {
		t.Fatalf("decoded close reply = %#v", second.Body)
	}
}

func TestPublicationAckRequirementRoundTrip(t *testing.T) {
	env := &Envelope{
		RequestID:              42,
		PublicationAckRequired: true,
		Body:                   &GetAttrReply{},
	}
	frame, err := EncodeFrame(env)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RequestID != 42 || !decoded.PublicationAckRequired {
		t.Fatalf("decoded envelope = %#v", decoded)
	}
}

func TestExactObjectHandlesRoundTrip(t *testing.T) {
	mode := uint32(0o600)
	size := uint64(17)
	mtime := int64(23)
	atime := int64(29)
	item := Item{ItemID: 31, ItemGeneration: 37}
	requests := []any{
		&GetAttrRequest{Item: item, Handle: 41},
		&SetAttrRequest{
			Item: item, Handle: 43, Mode: &mode, Size: &size,
			MtimeMs: &mtime, AtimeMs: &atime,
		},
		&XattrGetRequest{Item: item, Name: "user.key", Handle: 47},
		&XattrSetRequest{
			Item: item, Name: "user.key", Value: []byte("value"),
			CreateOnly: true, Handle: 53,
		},
		&XattrListRequest{Item: item, Handle: 59},
		&XattrRemoveRequest{Item: item, Name: "user.key", Handle: 61},
	}
	for _, request := range requests {
		frame, err := EncodeFrame(&Envelope{RequestID: 1, Body: request})
		if err != nil {
			t.Fatalf("%T encode: %v", request, err)
		}
		decoded, err := ReadFrame(bytes.NewReader(frame))
		if err != nil {
			t.Fatalf("%T decode: %v", request, err)
		}
		if !reflect.DeepEqual(decoded.Body, request) {
			t.Fatalf("%T round trip:\n got  %#v\n want %#v", request, decoded.Body, request)
		}
	}
}

func TestAttrParentAndFlagsRoundTrip(t *testing.T) {
	parent := Item{ItemID: 17, ItemGeneration: 19}
	want := &GetAttrReply{Attr: Attr{
		Item:           Item{ItemID: 23, ItemGeneration: 29},
		Kind:           ItemKindFile,
		Mode:           0o640,
		Nlink:          2,
		UID:            501,
		GID:            20,
		Size:           4097,
		MtimeMs:        31,
		CtimeMs:        37,
		AtimeMs:        41,
		BirthtimeMs:    43,
		ContentVersion: 47,
		Parent:         &parent,
		Flags:          0x00008000,
		AllocSize:      8192,
	}}
	frame, err := EncodeFrame(&Envelope{RequestID: 53, Body: want})
	if err != nil {
		t.Fatal(err)
	}
	if golden := readGolden(t, "attr_parent_flags.hex"); !bytes.Equal(frame, golden) {
		t.Fatalf("attr frame\n got %x\nwant %x", frame, golden)
	}
	decoded, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.RequestID != 53 || !reflect.DeepEqual(decoded.Body, want) {
		t.Fatalf("attr round trip:\n got  %#v\n want %#v", decoded.Body, want)
	}
}

// TestAppendIntentRoundTrip pins the O_APPEND intent on the wire. Without it
// the daemon can only ever see a frontend-computed absolute offset, which is
// what let two machines' appends land on the same byte range.
func TestAppendIntentRoundTrip(t *testing.T) {
	item := Item{ItemID: 7, ItemGeneration: 11}
	for _, tc := range []struct {
		name string
		body any
		want func(any) bool
	}{
		{"open", &OpenRequest{Item: item, Mode: OpenModeWrite, Append: true},
			func(b any) bool { r := b.(*OpenRequest); return r.Append && r.Mode == OpenModeWrite && r.Item == item }},
		{"create", &CreateRequest{Name: []byte("log"), Mode: 0o644, Exclusive: true, Append: true},
			func(b any) bool { r := b.(*CreateRequest); return r.Append && r.Exclusive }},
		{"write", &WriteRequest{Handle: 5, Data: []byte("rec\n"), Append: true},
			func(b any) bool {
				r := b.(*WriteRequest)
				return r.Append && r.Offset == 0 && string(r.Data) == "rec\n"
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := EncodeFrame(&Envelope{RequestID: 3, Body: tc.body})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := ReadFrame(bytes.NewReader(frame))
			if err != nil {
				t.Fatal(err)
			}
			if !tc.want(decoded.Body) {
				t.Fatalf("append intent lost across the wire: %#v", decoded.Body)
			}
		})
	}
}

// TestAppendIntentDefaultsOffForOlderFrontends keeps the added fields
// backward compatible: a frame minted without them decodes as a positional
// write, exactly as before.
func TestAppendIntentDefaultsOffForOlderFrontends(t *testing.T) {
	frame, err := EncodeFrame(&Envelope{RequestID: 4, Body: &WriteRequest{Handle: 9, Offset: 64, Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	w := decoded.Body.(*WriteRequest)
	if w.Append || w.Offset != 64 {
		t.Fatalf("legacy positional write changed meaning: %#v", w)
	}
}

// TestFlagIntentRoundTrip pins the chflags(2) group on the wire. The intent is
// a separate bool because 0 is a legal flag word (clear everything): a value
// alone could never distinguish "clear" from "no change".
func TestFlagIntentRoundTrip(t *testing.T) {
	item := Item{ItemID: 7, ItemGeneration: 11}
	mode := uint32(0o600)
	for _, tc := range []struct {
		name string
		req  SetAttrRequest
	}{
		{"set", SetAttrRequest{Item: item, SetFlags: true, Flags: 0x8000_0002}},
		{"clear", SetAttrRequest{Item: item, SetFlags: true, Flags: 0}},
		{"with-mode", SetAttrRequest{Item: item, Mode: &mode, SetFlags: true, Flags: 0x2}},
		{"absent", SetAttrRequest{Item: item, Mode: &mode}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.req
			frame, err := EncodeFrame(&Envelope{RequestID: 3, Body: &body})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := ReadFrame(bytes.NewReader(frame))
			if err != nil {
				t.Fatal(err)
			}
			got := decoded.Body.(*SetAttrRequest)
			if got.SetFlags != tc.req.SetFlags || got.Flags != tc.req.Flags {
				t.Fatalf("flag intent lost across the wire: setFlags=%v flags=%#x, want %v/%#x",
					got.SetFlags, got.Flags, tc.req.SetFlags, tc.req.Flags)
			}
			if got.Item != item {
				t.Fatalf("item = %+v", got.Item)
			}
		})
	}
}

// TestFlagFieldsDefaultOffForOlderFrontends keeps the added fields backward
// compatible without a protocol-minor bump: a frame minted without them decodes
// as a setattr that changes no flags, exactly as before. Same rule the O_APPEND
// intent fields follow.
func TestFlagFieldsDefaultOffForOlderFrontends(t *testing.T) {
	mode := uint32(0o644)
	frame, err := EncodeFrame(&Envelope{
		RequestID: 4,
		Body:      &SetAttrRequest{Item: Item{ItemID: 9, ItemGeneration: 2}, Mode: &mode},
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	s := decoded.Body.(*SetAttrRequest)
	if s.SetFlags || s.Flags != 0 || s.Mode == nil || *s.Mode != 0o644 {
		t.Fatalf("legacy setattr changed meaning: %#v", s)
	}
}

// TestCapabilitiesFlagsSupportedRoundTrip: the resolve reply carries TWO
// independent flag facts, and they must survive the wire independently.
// FlagsSupported describes the attached authority's durable storage;
// FlagsUnderstood describes whether the daemon parses set_flags at all. The
// interesting combination is the one the graft regression turned on —
// understood=true with supported=false — so every pairing is exercised.
func TestCapabilitiesFlagsSupportedRoundTrip(t *testing.T) {
	for _, want := range []Capabilities{
		{FlagsSupported: false, FlagsUnderstood: false},
		{FlagsSupported: false, FlagsUnderstood: true},
		{FlagsSupported: true, FlagsUnderstood: false},
		{FlagsSupported: true, FlagsUnderstood: true},
	} {
		reply := &ResolveReply{
			Root:     Item{ItemID: 1, ItemGeneration: 1},
			VolumeID: "vol",
			Capabilities: Capabilities{
				Symlinks: true, HardLinks: true, Xattrs: true, CaseSensitive: true,
				MaxNameBytes: 255, PreferredIOSize: 1 << 20,
				FlagsSupported:  want.FlagsSupported,
				FlagsUnderstood: want.FlagsUnderstood,
			},
		}
		frame, err := EncodeFrame(&Envelope{RequestID: 5, Body: reply})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ReadFrame(bytes.NewReader(frame))
		if err != nil {
			t.Fatal(err)
		}
		got := decoded.Body.(*ResolveReply)
		if got.Capabilities.FlagsSupported != want.FlagsSupported {
			t.Fatalf("flagsSupported = %v, want %v", got.Capabilities.FlagsSupported, want.FlagsSupported)
		}
		if got.Capabilities.FlagsUnderstood != want.FlagsUnderstood {
			t.Fatalf("flagsUnderstood = %v, want %v", got.Capabilities.FlagsUnderstood, want.FlagsUnderstood)
		}
		if got.Capabilities.PreferredIOSize != 1<<20 || !got.Capabilities.Xattrs {
			t.Fatalf("neighbouring capability fields disturbed: %+v", got.Capabilities)
		}
	}
}

// TestCapabilitiesFlagsUnderstoodAbsentDecodesFalse: flags_understood is an
// APPENDED field, so a resolve reply produced by a daemon that predates it
// carries no field 9 at all. It must decode false — that is precisely the
// signal "this daemon would silently discard a forwarded set_flags", and a
// default of true would hand the frontend a licence to forward into a
// silent no-op.
func TestCapabilitiesFlagsUnderstoodAbsentDecodesFalse(t *testing.T) {
	// The capabilities an older daemon emits: every field it knew about, and
	// literally no field 9 on the wire — a false bool is not encoded at all,
	// so leaving FlagsUnderstood unset reproduces those bytes exactly.
	old := Capabilities{
		Symlinks: true, Xattrs: true, CaseSensitive: true,
		MaxNameBytes: 255, PreferredIOSize: 1 << 20, FlagsSupported: true,
	}
	encoded := marshalCapabilities(&old)
	if err := scan(encoded, func(num int, _ int, _ []byte) error {
		if num == 9 {
			t.Fatalf("a false flags_understood put field 9 on the wire: % x", encoded)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reply := &ResolveReply{
		Root: Item{ItemID: 1, ItemGeneration: 1}, VolumeID: "vol", Capabilities: old,
	}
	frame, err := EncodeFrame(&Envelope{RequestID: 7, Body: reply})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Body.(*ResolveReply)
	if got.Capabilities.FlagsUnderstood {
		t.Fatal("an absent flags_understood decoded true; a pre-flags daemon would be forwarded to")
	}
	if !got.Capabilities.FlagsSupported || !got.Capabilities.Xattrs {
		t.Fatalf("the fields the old daemon DID send were lost: %+v", got.Capabilities)
	}
}
