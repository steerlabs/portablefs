package ctlrec

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func pfc1SampleSnapshot() Payload {
	return Payload{Kind: KindSnapshot, Snapshot: &Snapshot{
		AsOfLSN: 42,
		Sessions: []SessionState{{
			SessionID: "sess-a", Generation: 2, Owner: "owner-a",
			TokenHash: bytes.Repeat([]byte{0x11}, 32), Slots: 8, ExpiresMs: 1700000001000,
			SlotStates: []SlotState{
				{Slot: 0, SlotSeq: 3, ReqHash: bytes.Repeat([]byte{0x22}, 32), Status: -2, Count: 7, Version: 9, Offset: 4096, Ino: 12},
				{Slot: 1, SlotSeq: 1, ReqHash: bytes.Repeat([]byte{0x33}, 32), OrphanIno: 77},
			},
			Expired: true,
		}},
		Watermarks: []FlushWatermark{{SessionID: "sess-a", Epoch: 2, Through: 19}},
		Orphans: []OrphanState{{
			Ino: 55, Name: "deleted.tmp", Kind: "file", Mode: 0o600,
			MtimeMs: 1700000002000, CtimeMs: 1700000002000, AtimeMs: 1700000002001,
			UID: 501, GID: 20,
			Source: SourceState{
				BlobDigest: "sha256:0011", BlobSize: 8, BlobCompression: "zstd", BlobPacked: true,
				Chunks: []ChunkState{{Digest: "sha256:aa", Size: 4, Offset: 0}, {Digest: "sha256:bb", Size: 4, Offset: 4}},
				Size:   8,
			},
			Blocks: []DirtyBlock{{Index: 0, Data: []byte{1, 2, 3}}, {Index: 2, Data: []byte{4}}},
			Size:   9, Born: true, Truncated: true,
		}},
	}}
}

// pfc1Goldens freeze the canonical bytes of every payload kind. Drift here
// means the codec is no longer PFC1.
var pfc1Goldens = []struct {
	name string
	p    Payload
	hex  string
}{
	{
		name: "session",
		p: Payload{Kind: KindSession, Session: &Session{
			SessionID: "sess-1", Generation: 4, Owner: "owner-1",
			TokenHash: bytes.Repeat([]byte{0xaa}, 32), Slots: 16,
			AtMs: 1700000000000, ExpiresMs: 1700000000500,
		}},
		hex: "50464331080112450a06736573732d3110041a076f776e65722d312220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa28103080a0abfef96238e8a7abfef962",
	},
	{
		name: "session-expire-forced",
		p:    Payload{Kind: KindSessionExpire, SessionExpire: &SessionExpire{SessionID: "sess-1", Generation: 4, AtMs: 1700000000700, Force: true}},
		hex:  "5046433108021a130a06736573732d31100418f8aaabfef9622001",
	},
	{
		name: "flush-watermark",
		p:    Payload{Kind: KindFlushWatermark, FlushWatermark: &FlushWatermark{SessionID: "sess-1", Epoch: 3, Through: 88}},
		hex:  "504643310803220c0a06736573732d3110031858",
	},
	{
		name: "outcome-negative-status",
		p: Payload{Kind: KindOutcome, Outcome: &Outcome{
			SessionID: "sess-1", Generation: 4, Slot: 3, SlotSeq: 21,
			ReqHash: bytes.Repeat([]byte{0xcd}, 32), Status: -13,
		}},
		hex: "50464331080532320a06736573732d311004180320152a20cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd3019",
	},
	{
		name: "session-renew",
		p: Payload{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
			SessionID: "sess-1", Generation: 4, TokenHash: bytes.Repeat([]byte{0xee}, 32), ExpiresMs: 1700000009000,
		}},
		hex: "5046433108063a330a06736573732d3110041a20eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee20d0acacfef962",
	},
}

func TestPFC1Goldens(t *testing.T) {
	for _, g := range pfc1Goldens {
		got, err := EncodePFC1(g.p)
		if err != nil {
			t.Fatalf("%s: encode: %v", g.name, err)
		}
		if hex.EncodeToString(got) != g.hex {
			t.Fatalf("%s: golden drift\n got %s\nwant %s", g.name, hex.EncodeToString(got), g.hex)
		}
		raw, err := hex.DecodeString(g.hex)
		if err != nil {
			t.Fatalf("%s: fixture: %v", g.name, err)
		}
		dec, err := DecodePFC1(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", g.name, err)
		}
		if !reflect.DeepEqual(dec, g.p) {
			t.Fatalf("%s: decoded payload differs\n got %+v\nwant %+v", g.name, dec, g.p)
		}
	}
}

func TestPFC1SnapshotRoundTrip(t *testing.T) {
	p := pfc1SampleSnapshot()
	enc, err := EncodePFC1(p)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodePFC1(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dec, p) {
		t.Fatalf("snapshot round trip mismatch\n got %#v\nwant %#v", dec, p)
	}
	re, err := EncodePFC1(dec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(re, enc) {
		t.Fatal("snapshot re-encode is not byte identical")
	}
	// The gob codec must accept the identical value space (cross-codec parity).
	gobEnc, err := Encode(p)
	if err != nil {
		t.Fatalf("gob encode of the same payload: %v", err)
	}
	gobDec, err := Decode(gobEnc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalizeGob(gobDec), p) {
		t.Fatal("gob and pfc1 decode to different values")
	}
}

// normalizeGob maps gob's empty-slice/nil differences onto the canonical form.
func normalizeGob(p Payload) Payload {
	if p.Snapshot != nil {
		s := p.Snapshot
		if len(s.Sessions) == 0 {
			s.Sessions = nil
		}
		if len(s.Watermarks) == 0 {
			s.Watermarks = nil
		}
		if len(s.Orphans) == 0 {
			s.Orphans = nil
		}
		for i := range s.Orphans {
			if len(s.Orphans[i].Blocks) == 0 {
				s.Orphans[i].Blocks = nil
			}
			if len(s.Orphans[i].Source.Chunks) == 0 {
				s.Orphans[i].Source.Chunks = nil
			}
		}
		for i := range s.Sessions {
			if len(s.Sessions[i].SlotStates) == 0 {
				s.Sessions[i].SlotStates = nil
			}
		}
	}
	return p
}

func randHash(rng *rand.Rand) []byte {
	b := make([]byte, 32)
	rng.Read(b)
	return b
}

func randPFC1Payload(rng *rand.Rand) Payload {
	id := "s" + strings.Repeat("x", 1+rng.Intn(20))
	switch rng.Intn(6) {
	case 0:
		return Payload{Kind: KindSession, Session: &Session{
			SessionID: id, Generation: rng.Uint64(), Owner: "o",
			TokenHash: randHash(rng), Slots: 1 + rng.Uint32()%4096,
			AtMs: rng.Int63(), ExpiresMs: 0,
		}}
	case 1:
		return Payload{Kind: KindSessionExpire, SessionExpire: &SessionExpire{
			SessionID: id, Generation: rng.Uint64(), AtMs: rng.Int63(), Force: rng.Intn(2) == 0,
		}}
	case 2:
		return Payload{Kind: KindFlushWatermark, FlushWatermark: &FlushWatermark{
			SessionID: id, Epoch: rng.Uint64(), Through: rng.Uint64(),
		}}
	case 3:
		return Payload{Kind: KindOutcome, Outcome: &Outcome{
			SessionID: id, Generation: rng.Uint64(), Slot: rng.Uint32() % 64,
			SlotSeq: 1 + rng.Uint64()%1000, ReqHash: randHash(rng), Status: int32(rng.Int31() - rng.Int31()),
		}}
	case 4:
		return Payload{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
			SessionID: id, Generation: rng.Uint64(), TokenHash: randHash(rng), ExpiresMs: 1 + rng.Int63(),
		}}
	default:
		slots := uint32(4 + rng.Intn(8))
		var slotStates []SlotState
		for i := 0; i < rng.Intn(3); i++ {
			slotStates = append(slotStates, SlotState{
				Slot: uint32(i), SlotSeq: 1 + rng.Uint64()%99, ReqHash: randHash(rng),
				Status: int32(rng.Intn(5) - 2), Count: int32(rng.Intn(9)), Version: rng.Uint64(),
				Offset: rng.Int63() - rng.Int63(), Ino: rng.Uint64(), OrphanIno: rng.Uint64(),
			})
		}
		return Payload{Kind: KindSnapshot, Snapshot: &Snapshot{
			AsOfLSN: rng.Uint64(),
			Sessions: []SessionState{{
				SessionID: id, Generation: 1 + rng.Uint64()%9, Owner: "o",
				TokenHash: randHash(rng), Slots: slots, ExpiresMs: rng.Int63(),
				SlotStates: slotStates, Expired: rng.Intn(2) == 0,
			}},
			Watermarks: []FlushWatermark{{SessionID: id, Epoch: rng.Uint64(), Through: rng.Uint64()}},
		}}
	}
}

func normalizePFC1(p Payload) Payload {
	if p.Snapshot != nil {
		for i := range p.Snapshot.Sessions {
			if len(p.Snapshot.Sessions[i].SlotStates) == 0 {
				p.Snapshot.Sessions[i].SlotStates = nil
			}
		}
	}
	return p
}

func TestPFC1RoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 3000; i++ {
		p := randPFC1Payload(rng)
		enc, err := EncodePFC1(p)
		if err != nil {
			t.Fatalf("iter %d: encode: %v (%+v)", i, err, p)
		}
		dec, err := DecodePFC1(enc)
		if err != nil {
			t.Fatalf("iter %d: decode: %v", i, err)
		}
		if !reflect.DeepEqual(dec, normalizePFC1(p)) {
			t.Fatalf("iter %d: round trip mismatch\n got %+v\nwant %+v", i, dec, p)
		}
		re, err := EncodePFC1(dec)
		if err != nil {
			t.Fatalf("iter %d: re-encode: %v", i, err)
		}
		if !bytes.Equal(re, enc) {
			t.Fatalf("iter %d: re-encode is not byte identical", i)
		}
	}
}

func TestPFC1RejectsMalformed(t *testing.T) {
	valid, err := EncodePFC1(Payload{Kind: KindFlushWatermark, FlushWatermark: &FlushWatermark{SessionID: "s", Epoch: 1, Through: 2}})
	if err != nil {
		t.Fatal(err)
	}
	magic := PFC1Magic[:]
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"wrong-magic", append([]byte("PFR1"), valid[4:]...)},
		{"trailing", append(append([]byte{}, valid...), 0x00)},
		{"kind-zero", append(append([]byte{}, magic...), 0x08, 0x00)},
		{"kind-unknown", append(append([]byte{}, magic...), 0x08, 0x09)},
		{"kind-without-arm", append(append([]byte{}, magic...), 0x08, 0x03)},
		{"two-arms", append(append([]byte{}, magic...), 0x08, 0x03, 0x22, 0x03, 0x0a, 0x01, 0x73, 0x3a, 0x03, 0x0a, 0x01, 0x73)},
		{"arm-kind-mismatch", append(append([]byte{}, magic...), 0x08, 0x01, 0x22, 0x03, 0x0a, 0x01, 0x73)},
		{"unknown-field", append(append([]byte{}, magic...), 0x08, 0x03, 0x22, 0x03, 0x0a, 0x01, 0x73, 0x40, 0x01)},
		{"gob-payload", []byte{0x02, 0x01, 0x02, 0x03}},
	}
	for _, c := range cases {
		if _, err := DecodePFC1(c.payload); err == nil {
			t.Fatalf("%s: decode accepted malformed payload", c.name)
		}
	}
}

func TestPFC1SizeBound(t *testing.T) {
	// A snapshot with ~7 MiB of dirty block data must be rejected by the 6 MiB
	// PFC1 payload bound (validatePayload allows up to 32 MiB inline for the
	// legacy gob path, so this exercises the PFC1-specific ceiling).
	blocks := make([]DirtyBlock, 0, 7)
	for i := 0; i < 7; i++ {
		blocks = append(blocks, DirtyBlock{Index: int64(i), Data: bytes.Repeat([]byte{0xaa}, 1<<20)})
	}
	p := Payload{Kind: KindSnapshot, Snapshot: &Snapshot{
		AsOfLSN: 9,
		Orphans: []OrphanState{{Ino: 3, Kind: "file", Blocks: blocks, Size: 7 << 20}},
	}}
	if _, err := EncodePFC1(p); err == nil {
		t.Fatal("7 MiB snapshot must exceed the PFC1 bound")
	}
	p.Snapshot.Orphans[0].Blocks = blocks[:4]
	if _, err := EncodePFC1(p); err != nil {
		t.Fatalf("4 MiB snapshot must encode: %v", err)
	}
}

func FuzzPFC1Decode(f *testing.F) {
	for _, g := range pfc1Goldens {
		raw, err := hex.DecodeString(g.hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	snap, err := EncodePFC1(pfc1SampleSnapshot())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(snap)
	f.Fuzz(func(t *testing.T, payload []byte) {
		p, err := DecodePFC1(payload)
		if err != nil {
			return
		}
		re, err := EncodePFC1(p)
		if err != nil {
			t.Fatalf("accepted payload does not re-encode: %v", err)
		}
		if !bytes.Equal(re, payload) {
			t.Fatalf("accepted payload is not canonical:\n in %x\nout %x", payload, re)
		}
	})
}
