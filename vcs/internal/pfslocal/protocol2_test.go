package pfslocal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func currentResolve() *ResolveReply {
	root := Item{ItemID: 1, ItemGeneration: 9, StableIdentity: [16]byte{0x20}}
	return &ResolveReply{Root: root, RootAttr: Attr{Item: root, Kind: ItemKindDirectory, FileID: 1}, VolumeID: "volume", VolumeName: "Shared", Capabilities: Capabilities{MaxNameBytes: 255, PreferredIOSize: 1 << 20}}
}

func TestGoldenResolveContract(t *testing.T) {
	env := &Envelope{RequestID: 2, Body: currentResolve()}
	frame, err := EncodeFrame(env)
	if err != nil {
		t.Fatal(err)
	}
	if want := golden(t, "resolve_contract.hex", frame); !bytes.Equal(frame, want) {
		t.Fatalf("frame=%x want=%x", frame, want)
	}
	decoded, err := ReadFrame(bytes.NewReader(frame))
	if err != nil || !reflect.DeepEqual(decoded, env) {
		t.Fatalf("roundtrip=%#v: %v", decoded, err)
	}
}

func TestProtocol2RequiresExactPairAndPositiveDeadline(t *testing.T) {
	for _, version := range [][2]uint32{{0, 0}, {1, 0}, {3, 0}, {2, 1}, {2, math.MaxUint32}} {
		for _, reply := range []bool{false, true} {
			raw := appendU32(nil, 1, version[0])
			raw = appendU32(raw, 2, version[1])
			field := 10
			if reply {
				raw = appendU32(raw, 4, 60000)
				field = 60
			}
			if _, err := UnmarshalEnvelope(appendMsg(nil, field, raw)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("accepted version=%v reply=%t: %v", version, reply, err)
			}
		}
	}
	for _, deadline := range []uint32{0, 1, math.MaxUint32} {
		_, err := MarshalEnvelope(&Envelope{Body: &HelloReply{ProtocolMajor: ProtocolMajor, ProtocolMinor: ProtocolMinor, RequestDeadlineMs: deadline}})
		if (err == nil) != (deadline > 0) {
			t.Fatalf("deadline=%d: %v", deadline, err)
		}
	}
}

func TestProtocol2RejectsUnknownAndMalformedGrammar(t *testing.T) {
	for _, name := range []string{".pfslocal.v1.Envelope", ".pfslocal.v1.ResolveReply", ".pfslocal.v1.Capabilities", ".pfslocal.v1.Event"} {
		state := localWireState{}
		if err := validateLocalMessage(appendMsg(nil, 500, nil), name, 0, false, &state); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted unknown field in %s: %v", name, err)
		}
	}
	for _, raw := range [][]byte{
		appendMsg(nil, 10, appendU64Present(nil, 1, 1<<32+ProtocolMajor)),
		appendMsg(nil, 10, appendBytesField(appendU32(nil, 1, ProtocolMajor), 3, []byte{255})),
		appendMsg(nil, 91, appendMsg(nil, 2, appendU32(nil, 1, 2))),
		appendVarint(nil, uint64(1<<29)<<3),

		{8, 1, 8, 1, 0x8a, 2, 0}, // duplicate scalar
		{0x8a, 2, 0, 0x92, 2, 0}, // duplicate body
		{0x8a, 2, 0, 8, 1},       // unordered
		{0x88, 0, 1, 0x8a, 2, 0}, // overlong tag
		{8, 0x81, 0, 0x8a, 2, 0}, // overlong scalar
		{0x8a, 2, 0x80, 0},       // overlong length
		{0x10, 2, 0x8a, 2, 0},    // invalid bool
		{0x8a, 2, 1},             // truncated payload
	} {
		if _, err := UnmarshalEnvelope(raw); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted %x: %v", raw, err)
		}
	}
}

func TestProtocol2RequiresResolveAndOwningIdentity(t *testing.T) {
	for _, change := range []func(*ResolveReply){
		func(r *ResolveReply) { r.Root.StableIdentity = [16]byte{} },
		func(r *ResolveReply) { r.Root.ItemID = 0 },
		func(r *ResolveReply) { r.Root.ItemGeneration = 0 },
	} {
		r := currentResolve()
		change(r)
		if _, err := MarshalEnvelope(&Envelope{Body: r}); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted incomplete resolve: %v", err)
		}
	}
	encoded := marshalResolveReply(currentResolve())
	if _, err := UnmarshalEnvelope(appendMsg(nil, 61, encoded)); err != nil {
		t.Fatal(err)
	}
	// The root and its attributes are both required, independently of limits.
	for _, field := range []int{1, 2} {
		var incomplete []byte
		if err := scan(encoded, func(n, wt int, raw []byte) error {
			if n != field {
				incomplete = appendVarint(incomplete, uint64(n<<3|wt))
				incomplete = append(incomplete, raw...)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalEnvelope(appendMsg(nil, 61, incomplete)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted missing Resolve field %d: %v", field, err)
		}
	}
}

func TestProtocol2BoundsListingAndPreservesNonOwningEntries(t *testing.T) {
	for _, count := range []int{4096, 4097} {
		entries := make([]DirEntry, count)
		for i := range entries {
			entries[i] = DirEntry{Name: []byte("x"), Attr: Attr{Kind: ItemKindFile, FileID: uint64(i + 2)}}
		}
		_, err := MarshalEnvelope(&Envelope{Body: &EnumerateEntriesReply{Entries: entries}})
		if (err == nil) != (count == 4096) {
			t.Fatalf("count=%d: %v", count, err)
		}
	}
	entry := DirEntry{Name: []byte{0xff}, Attr: Attr{Kind: ItemKindFile, Item: currentResolve().Root}}
	if _, err := MarshalEnvelope(&Envelope{Body: &EnumerateEntriesReply{Entries: []DirEntry{entry}}}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("accepted owning entry: %v", err)
	}
}

type shortFrameWriter struct{ bytes.Buffer }

func (w *shortFrameWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}
func TestFrameCompletesShortHeaderAndPayloadWrites(t *testing.T) {
	env := &Envelope{RequestID: 3, Body: &CloseReply{Retired: true}}
	writer := &shortFrameWriter{}
	if err := WriteFrame(writer, env); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(&writer.Buffer)
	if err != nil || !reflect.DeepEqual(decoded, env) {
		t.Fatalf("roundtrip=%v: %v", decoded, err)
	}
}

func TestLocalGrammarGeneratedFromCurrentSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "pfslocal", "pfslocal.proto"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != localSchemaSHA256 {
		t.Fatal("regenerate the local grammar table from pfslocal.proto")
	}
}

type zeroFrameWriter struct{}

func (zeroFrameWriter) Write([]byte) (int, error) { return 0, nil }
func TestProtocol2RefusesNilBodiesAndZeroProgressWrites(t *testing.T) {
	for _, env := range []*Envelope{nil, {}, {Body: (*Hello)(nil)}} {
		if _, err := MarshalEnvelope(env); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted missing body: %v", err)
		}
	}
	if err := WriteFrame(zeroFrameWriter{}, &Envelope{Body: &CloseReply{}}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress writer: %v", err)
	}
	want := &CloseReply{Retired: true, CloseErrno: -5}
	if got := roundTripBody(t, want); !reflect.DeepEqual(got, want) {
		t.Fatalf("signed close errno: %#v", got)
	}
}
