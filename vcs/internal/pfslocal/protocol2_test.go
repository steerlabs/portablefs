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
	return &ResolveReply{Root: root, RootAttr: Attr{Item: root, Kind: ItemKindDirectory, FileID: 1}, VolumeID: "volume", VolumeName: "Shared", Capabilities: Capabilities{Symlinks: true, HardLinks: true, Xattrs: true, CaseSensitive: true, MaxNameBytes: 255, PreferredIOSize: 1 << 20}, V3Coherence: &V3CoherenceContract{AuthorityEpoch: bytes.Repeat([]byte{0xa1}, 16), SessionID: bytes.Repeat([]byte{0xb2}, 16), CachePolicy: CachePolicy, LivenessIntervalMillis: 5000}}
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

func TestProtocol2RejectsRemovedAndMalformedGrammar(t *testing.T) {
	for _, field := range []int{4, 5, 13, 31, 37, 63, 81, 86, 92} {
		if _, err := UnmarshalEnvelope(appendMsg(nil, field, nil)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted envelope field %d: %v", field, err)
		}
	}
	for _, test := range []struct {
		body  int
		field int
	}{
		{61, 4}, {61, 8}, {85, 1}, {91, 1}, {91, 3},
	} {
		if _, err := UnmarshalEnvelope(appendMsg(nil, test.body, appendMsg(nil, test.field, nil))); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted body %d field %d: %v", test.body, test.field, err)
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

func TestProtocol2RequiresCompleteContractAndOwningIdentity(t *testing.T) {
	for _, change := range []func(*ResolveReply){
		func(r *ResolveReply) { r.V3Coherence = nil },
		func(r *ResolveReply) { r.V3Coherence.AuthorityEpoch = nil },
		func(r *ResolveReply) { r.V3Coherence.SessionID = make([]byte, 16) },
		func(r *ResolveReply) { r.V3Coherence.CachePolicy = "unknown" },
		func(r *ResolveReply) { r.V3Coherence.LivenessIntervalMillis = 0 },
		func(r *ResolveReply) { r.V3Coherence.LivenessIntervalMillis = math.MaxUint64 },
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
	// Deletions are also rejected inside a valid enclosing contract/capabilities.
	for _, test := range []struct {
		name   string
		fields []int
	}{
		{".pfslocal.v1.V3CoherenceContract", []int{1, 5, 6}},
		{".pfslocal.v1.Capabilities", []int{8, 9}},
	} {
		for _, field := range test.fields {
			state := localWireState{}
			if err := validateLocalMessage(appendU64Present(nil, field, 1), test.name, 0, false, &state); !errors.Is(err, ErrMalformed) {
				t.Fatalf("accepted %s field %d", test.name, field)
			}
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
