package wal

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

// pfr1Golden freezes the byte encoding of representative records. If any of
// these change, the codec is no longer PFR1 — a new codec name is required.
// Fixtures were captured from the initial frozen implementation and are
// deliberately spelled as literal hex.
var pfr1Goldens = []struct {
	name string
	rec  Record
	hex  string
}{
	{
		name: "create",
		rec:  Record{Seq: 7, Op: OpCreate, Path: "a/b.txt", Mode: 0o644, TsMs: 1700000000000},
		hex:  "50465231080710011a07612f622e74787438a403900180a0abfef962",
	},
	{
		name: "write-with-data",
		rec:  Record{Seq: 8, Op: OpWrite, Path: "a/b.txt", Offset: 5, Data: []byte{0xde, 0xad, 0xbe, 0xef}},
		hex:  "50465231080810021a07612f622e747874280a4a04deadbeef",
	},
	{
		name: "rename",
		rec:  Record{Seq: 9, Op: OpRename, Path: "old", NewPath: "new"},
		hex:  "50465231080910061a036f6c6422036e6577",
	},
	{
		name: "chtimes-negative-atime",
		rec:  Record{Seq: 10, Op: OpChtimes, Path: "f", MtimeMs: -1, AtimeMs: -2, ChtimesSetAtime: true},
		hex:  "50465231080a10091a0166500158036001",
	},
	{
		name: "mkdir-inos",
		rec:  Record{Seq: 11, Op: OpMkdir, Path: "d/e", Mode: 0o755, Inos: []uint64{12, 13}},
		hex:  "50465231080b10041a03642f6538ed038201020c0d",
	},
	{
		name: "enveloped-write",
		rec: Record{
			Seq: 12, Op: OpWrite, Path: "f", Offset: 0, Data: []byte("hi"),
			Env: &Envelope{SessionID: "sess-1", Generation: 3, Slot: 2, SlotSeq: 9, ReqHash: bytes.Repeat([]byte{0xab}, 32)},
		},
		hex: "50465231080c10021a01664a026869ba01300a06736573732d311003180220092a20abababababababababababababababababababababababababababababababab",
	},
	{
		name: "batch",
		rec: Record{
			Seq: 13, Op: OpBatch,
			Mutations: []Record{
				{Seq: 1, Op: OpCreate, Path: "x", Mode: 0o600},
				{Seq: 2, Op: OpWrite, Path: "x", Data: []byte("d")},
			},
		},
		hex: "50465231080d100ec2010a080110011a0178388003c2010a080210021a01784a0164",
	},
	{
		name: "control",
		rec:  Record{Seq: 14, Op: OpControl, Data: []byte{0x02, 0x01, 0x02}},
		hex:  "50465231080e100d4a03020102",
	},
	{
		name: "reap-lease-cutoff",
		rec:  Record{Seq: 15, Op: OpReap, Ino: 42, ReapIfLeaseExpiresByMs: 1700000000001},
		hex:  "50465231080f100c782ab00182a0abfef962",
	},
	{
		name: "excl-create",
		rec:  Record{Seq: 16, Op: OpCreate, Path: "x.lock", Mode: 0o600, Excl: true},
		hex:  "50465231081010011a06782e6c6f636b388003c80101",
	},
	{
		name: "excl-mkdir-leaf-ino",
		rec:  Record{Seq: 17, Op: OpMkdir, Path: "d/e/f", Mode: 0o755, Ino: 44, Excl: true},
		hex:  "50465231081110041a05642f652f6638ed03782cc80101",
	},
	{
		name: "rename-no-replace",
		rec:  Record{Seq: 18, Op: OpRename, Path: "a", NewPath: "b", RenameNoReplace: true},
		hex:  "50465231081210061a0161220162d00101",
	},
	{
		name: "link",
		rec:  Record{Seq: 19, Op: OpLink, Path: "src", NewPath: "dst", Ino: 42},
		hex:  "504652310813100f1a037372632203647374782a",
	},
	{
		name: "setxattr",
		rec:  Record{Seq: 20, Op: OpSetxattr, Path: "f", Ino: 42, XattrName: "user.test", Data: []byte("v1")},
		hex:  "50465231081410101a01664a027631782ada0109757365722e74657374",
	},
	{
		name: "setxattr-create-only",
		rec:  Record{Seq: 23, Op: OpSetxattr, Path: "f", XattrName: "user.once", Data: []byte("v"), XattrFlags: XattrCreate},
		hex:  "50465231081710101a01664a0176da0109757365722e6f6e6365e00101",
	},
	{
		name: "setxattr-empty-value",
		rec:  Record{Seq: 22, Op: OpSetxattr, Path: "f", XattrName: "user.empty"},
		hex:  "50465231081610101a0166da010a757365722e656d707479",
	},
	{
		name: "removexattr",
		rec:  Record{Seq: 21, Op: OpRemovexattr, Path: "f", XattrName: "user.test"},
		hex:  "50465231081510111a0166da0109757365722e74657374",
	},
	{
		name: "chtimes-atime-only",
		rec: Record{
			Seq: 24, Op: OpChtimes, Path: "f", AtimeMs: -2,
			ChtimesSetAtime: true, ChtimesKeepMtime: true,
		},
		hex: "50465231081810091a016658036001e80101",
	},
}

func TestPFR1Goldens(t *testing.T) {
	for _, g := range pfr1Goldens {
		got, err := EncodePFR1(&g.rec)
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
		dec, err := DecodePFR1(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", g.name, err)
		}
		if !reflect.DeepEqual(dec, g.rec) {
			t.Fatalf("%s: decoded record differs\n got %+v\nwant %+v", g.name, dec, g.rec)
		}
	}
}

// randomPFR1Record builds an arbitrary VALID record (bounded).
func randomPFR1Record(rng *rand.Rand, allowBatch bool) Record {
	ops := []Op{OpCreate, OpWrite, OpTruncate, OpMkdir, OpRemove, OpRename, OpSymlink, OpChmod, OpChtimes, OpChown, OpOrphan, OpReap, OpControl, OpLink, OpSetxattr, OpRemovexattr}
	r := Record{Seq: rng.Uint64() >> 1, Op: ops[rng.Intn(len(ops))]}
	if allowBatch && rng.Intn(6) == 0 {
		r.Op = OpBatch
		n := 1 + rng.Intn(4)
		for i := 0; i < n; i++ {
			r.Mutations = append(r.Mutations, randomPFR1Record(rng, false))
		}
		return r
	}
	if rng.Intn(2) == 0 {
		r.Path = randPath(rng)
	}
	if r.Op == OpRename || r.Op == OpLink {
		r.Path, r.NewPath = randPath(rng), randPath(rng)
	}
	if r.Op == OpSymlink {
		r.Target = randPath(rng)
	}
	if r.Op == OpWrite || r.Op == OpControl {
		r.Data = randBytes(rng, 1+rng.Intn(64))
		r.Offset = rng.Int63() - rng.Int63()
	}
	if r.Op == OpSetxattr || r.Op == OpRemovexattr {
		r.XattrName = "user." + randToken(rng, 1+rng.Intn(24))
		if r.Op == OpSetxattr && rng.Intn(2) == 0 {
			r.Data = randBytes(rng, rng.Intn(96))
		}
		if r.Op == OpSetxattr && rng.Intn(3) == 0 {
			if rng.Intn(2) == 0 {
				r.XattrFlags = XattrCreate
			} else {
				r.XattrFlags = XattrReplace
			}
		}
	}
	if rng.Intn(3) == 0 {
		r.Mode = rng.Uint32() & 0o7777
		r.MtimeMs = rng.Int63() - rng.Int63()
		r.AtimeMs = rng.Int63() - rng.Int63()
		r.TsMs = rng.Int63()
		r.ChtimesSetAtime = rng.Intn(2) == 0
		r.ChtimesKeepMtime = rng.Intn(2) == 0
		r.UID = rng.Uint32()
		r.GID = rng.Uint32()
		r.ChownSetUID = rng.Intn(2) == 0
		r.ChownSetGID = rng.Intn(2) == 0
		r.Append = rng.Intn(2) == 0
		r.OrphanTarget = rng.Intn(2) == 0
		r.Size = rng.Int63()
		r.Ino = rng.Uint64()
		r.ReapIfLeaseExpiresByMs = rng.Int63()
	}
	if r.Op == OpMkdir && rng.Intn(2) == 0 {
		n := 1 + rng.Intn(5)
		for i := 0; i < n; i++ {
			r.Inos = append(r.Inos, rng.Uint64()|1)
		}
	}
	// Conditional-operation flags (frozen fields 25/26): excl only on
	// create/mkdir/symlink (an excl mkdir carries its leaf identity in Ino,
	// never Inos), rename_no_replace only on rename.
	switch r.Op {
	case OpCreate, OpSymlink:
		r.Excl = rng.Intn(3) == 0
	case OpMkdir:
		if rng.Intn(3) == 0 {
			r.Excl = true
			r.Inos = nil
		}
	case OpRename:
		r.RenameNoReplace = rng.Intn(3) == 0
	}
	if rng.Intn(4) == 0 {
		r.Env = &Envelope{
			SessionID:  "s" + randToken(rng, 1+rng.Intn(24)),
			Generation: rng.Uint64(),
			Slot:       rng.Uint32(),
			SlotSeq:    rng.Uint64(),
			ReqHash:    randBytes(rng, 32),
		}
	}
	return r
}

func randPath(rng *rand.Rand) string {
	segs := 1 + rng.Intn(4)
	parts := make([]string, segs)
	for i := range parts {
		parts[i] = randToken(rng, 1+rng.Intn(12))
	}
	return strings.Join(parts, "/")
}

func randToken(rng *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_ü漢"
	runes := []rune(alphabet)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(runes[rng.Intn(len(runes))])
	}
	return b.String()
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// normalizePFR1 maps a record onto its canonical in-memory shape (empty
// slices/strings become nil/zero) so DeepEqual matches decode output.
func normalizePFR1(r Record) Record {
	if len(r.Data) == 0 {
		r.Data = nil
	}
	if len(r.Inos) == 0 {
		r.Inos = nil
	}
	if len(r.Mutations) == 0 {
		r.Mutations = nil
	} else {
		for i := range r.Mutations {
			r.Mutations[i] = normalizePFR1(r.Mutations[i])
		}
	}
	return r
}

func TestPFR1RoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 4000; i++ {
		rec := randomPFR1Record(rng, true)
		enc, err := EncodePFR1(&rec)
		if err != nil {
			t.Fatalf("iter %d: encode: %v (%+v)", i, err, rec)
		}
		dec, err := DecodePFR1(enc)
		if err != nil {
			t.Fatalf("iter %d: decode: %v", i, err)
		}
		if !reflect.DeepEqual(dec, normalizePFR1(rec)) {
			t.Fatalf("iter %d: round trip mismatch\n got %+v\nwant %+v", i, dec, normalizePFR1(rec))
		}
		re, err := EncodePFR1(&dec)
		if err != nil {
			t.Fatalf("iter %d: re-encode: %v", i, err)
		}
		if !bytes.Equal(re, enc) {
			t.Fatalf("iter %d: re-encode is not byte identical", i)
		}
	}
}

func TestPFR1RejectsMalformed(t *testing.T) {
	valid, err := EncodePFR1(&Record{Seq: 3, Op: OpCreate, Path: "p", Mode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	body := valid[4:]

	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"short-magic", []byte("PFR")},
		{"wrong-magic", append([]byte("PFC1"), body...)},
		{"trailing-byte", append(append([]byte{}, valid...), 0x00)},
		{"trailing-valid-field", append(append([]byte{}, valid...), 0x08, 0x01)},                       // second seq after path: out of order
		{"unknown-field", append(append([]byte{}, PFR1Magic[:]...), 0xC8, 0x02, 0x01)},                 // field 41 varint
		{"wire-type-3", append(append([]byte{}, PFR1Magic[:]...), 0x0B)},                               // field 1 wt 3
		{"explicit-zero-seq", append(append([]byte{}, PFR1Magic[:]...), 0x08, 0x00, 0x10, 0x01)},       // seq=0 explicit
		{"bool-zero", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0x60, 0x00)},               // chtimes_set_atime=0
		{"bool-two", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0x60, 0x02)},                // bool=2
		{"nonminimal-varint", append(append([]byte{}, PFR1Magic[:]...), 0x08, 0x81, 0x00, 0x10, 0x01)}, // seq=1 over-long
		{"empty-string", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0x1A, 0x00)},            // path=""
		{"bad-utf8", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0x1A, 0x01, 0xFF)},
		{"nul-in-path", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0x1A, 0x01, 0x00)},
		{"op-zero", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x00)},
		{"op-unknown", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x12)}, // op 18 > OpRemovexattr(17): appended-op fencing
		// A setxattr without its name is structurally invalid (op 16 alone).
		{"setxattr-missing-name", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x10)},
		// xattr_name (field 27, tag 0xDA 0x01) is only legal on setxattr/removexattr.
		{"xattrname-on-create", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0xDA, 0x01, 0x01, 0x61)},
		// removexattr must carry no data (field 9, tag 0x4A).
		{"removexattr-with-data", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x11, 0x4A, 0x01, 0x76, 0xDA, 0x01, 0x01, 0x61)},
		{"duplicate-field", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0x10, 0x01)},
		{"misordered-fields", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0x08, 0x01)},
		{"truncated-length", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0x1A, 0x05, 0x61)},
		{"env-empty", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0xBA, 0x01, 0x00)},
		// excl (field 25, tag 0xC8 0x01) is only legal on create/mkdir/symlink.
		{"excl-on-write", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x02, 0xC8, 0x01, 0x01)},
		// rename_no_replace (field 26, tag 0xD0 0x01) is only legal on rename.
		{"noreplace-on-create", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0xD0, 0x01, 0x01)},
		// xattr_flags (field 28, tag 0xE0 0x01) is only legal on setxattr.
		{"xattrflags-on-create", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x01, 0xE0, 0x01, 0x01)},
		// Both create and replace at once is contradictory.
		{"xattrflags-both", append(append([]byte{}, PFR1Magic[:]...), 0x10, 0x10, 0xDA, 0x01, 0x01, 0x61, 0xE0, 0x01, 0x03)},
	}
	for _, c := range cases {
		if _, err := DecodePFR1(c.payload); err == nil {
			t.Fatalf("%s: decode accepted malformed payload", c.name)
		}
	}

	// Encode-side structural rules for the conditional-operation flags.
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpWrite, Path: "f", Data: []byte("d"), Excl: true}); err == nil {
		t.Fatal("encode accepted excl on a write")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpMkdir, Path: "d", Mode: 0o755, Excl: true, Inos: []uint64{7}}); err == nil {
		t.Fatal("encode accepted an exclusive mkdir with a component ino list")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpCreate, Path: "f", Mode: 0o644, RenameNoReplace: true}); err == nil {
		t.Fatal("encode accepted rename_no_replace on a create")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpCreate, Path: "f", Mode: 0o644, XattrName: "user.x"}); err == nil {
		t.Fatal("encode accepted xattr_name on a create")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpSetxattr, Path: "f", Data: []byte("v")}); err == nil {
		t.Fatal("encode accepted a setxattr without a name")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpRemovexattr, Path: "f", XattrName: "user.x", Data: []byte("v")}); err == nil {
		t.Fatal("encode accepted a removexattr carrying data")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpCreate, Path: "f", XattrFlags: XattrCreate}); err == nil {
		t.Fatal("encode accepted xattr flags on a create")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpSetxattr, Path: "f", XattrName: "user.x", XattrFlags: XattrFlagMask}); err == nil {
		t.Fatal("encode accepted mutually exclusive xattr flags together")
	}
}

func TestPFR1NestedBatchProhibited(t *testing.T) {
	inner := Record{Seq: 1, Op: OpBatch, Mutations: []Record{{Op: OpCreate, Path: "x", Mode: 0o600}}}
	outer := Record{Seq: 2, Op: OpBatch, Mutations: []Record{inner}}
	if _, err := EncodePFR1(&outer); err == nil {
		t.Fatal("encode accepted a nested batch")
	}
	// Hand-craft the wire form of a nested batch and confirm decode rejects it.
	leafLeaf, err := appendPFR1Record(nil, &Record{Op: OpCreate, Path: "x", Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	var innerBody []byte
	innerBody = pfwire.AppendUint(innerBody, 2, uint64(OpBatch))
	innerBody = pfwire.AppendBytes(innerBody, 24, leafLeaf)
	var outerBody []byte
	outerBody = pfwire.AppendUint(outerBody, 2, uint64(OpBatch))
	outerBody = pfwire.AppendBytes(outerBody, 24, innerBody)
	payload := append(append([]byte{}, PFR1Magic[:]...), outerBody...)
	if _, err := DecodePFR1(payload); err == nil {
		t.Fatal("decode accepted a nested batch")
	}
}

func TestPFR1Bounds(t *testing.T) {
	longPath := strings.Repeat("a", MaxPFR1PathBytes)
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpCreate, Path: longPath, Mode: 1}); err != nil {
		t.Fatalf("max path must encode: %v", err)
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpCreate, Path: longPath + "a", Mode: 1}); err == nil {
		t.Fatal("max+1 path must be rejected")
	}

	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpWrite, Path: "f", Data: make([]byte, MaxPFR1DataBytes+1)}); err == nil {
		t.Fatal("max+1 data must be rejected")
	}

	muts := make([]Record, MaxPFR1BatchMutations+1)
	for i := range muts {
		muts[i] = Record{Op: OpRemove, Path: "x"}
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpBatch, Mutations: muts}); err == nil {
		t.Fatal("max+1 batch mutations must be rejected")
	}

	inos := make([]uint64, MaxPFR1Inos+1)
	for i := range inos {
		inos[i] = uint64(i + 2)
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpMkdir, Path: "d", Mode: 1, Inos: inos}); err == nil {
		t.Fatal("max+1 inos must be rejected")
	}

	// Xattr bounds are enforced AT ENCODE, below the general data ceiling.
	maxName := strings.Repeat("n", MaxPFR1XattrNameBytes)
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpSetxattr, Path: "f", XattrName: maxName, Data: make([]byte, MaxPFR1XattrValueBytes)}); err != nil {
		t.Fatalf("max xattr name+value must encode: %v", err)
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpSetxattr, Path: "f", XattrName: maxName + "n", Data: []byte("v")}); err == nil {
		t.Fatal("max+1 xattr name must be rejected")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpSetxattr, Path: "f", XattrName: "user.x", Data: make([]byte, MaxPFR1XattrValueBytes+1)}); err == nil {
		t.Fatal("max+1 xattr value must be rejected at encode")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpRemovexattr, Path: "f", XattrName: maxName + "n"}); err == nil {
		t.Fatal("max+1 removexattr name must be rejected")
	}

	// Whole-record bound: a batch of 1 MiB writes crossing 8 MiB total.
	big := make([]Record, 0, 9)
	for i := 0; i < 9; i++ {
		big = append(big, Record{Op: OpWrite, Path: "f", Offset: int64(i) << 20, Data: make([]byte, 1<<20)})
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpBatch, Mutations: big}); err == nil {
		t.Fatal("9 MiB batch must exceed the 8 MiB record bound")
	}
	if _, err := EncodePFR1(&Record{Seq: 1, Op: OpBatch, Mutations: big[:7]}); err != nil {
		t.Fatalf("7 MiB batch must encode: %v", err)
	}
}

func TestPFR1ZigzagExtremes(t *testing.T) {
	rec := Record{
		Seq: 1, Op: OpChtimes, Path: "f",
		MtimeMs: math.MinInt64, AtimeMs: math.MaxInt64,
		Offset: math.MinInt64, Size: math.MaxInt64,
		TsMs: math.MinInt64, ReapIfLeaseExpiresByMs: math.MaxInt64,
	}
	enc, err := EncodePFR1(&rec)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodePFR1(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dec, rec) {
		t.Fatalf("extremes mismatch: %+v vs %+v", dec, rec)
	}
}

func TestPFR1SizeEstimateBoundsEveryRecordField(t *testing.T) {
	rec := Record{
		Seq: math.MaxUint64, Op: OpSetxattr,
		Path: "path", NewPath: "new-path",
		Offset: math.MinInt64, Size: math.MaxInt64, Mode: math.MaxUint32,
		Target: "target", Data: []byte("value"),
		MtimeMs: math.MinInt64, AtimeMs: math.MaxInt64,
		ChtimesSetAtime: true, ChtimesKeepMtime: true,
		UID: math.MaxUint32, GID: math.MaxUint32, Ino: math.MaxUint64,
		Inos:         []uint64{math.MaxUint64, math.MaxUint64},
		OrphanTarget: true, TsMs: math.MinInt64,
		ChownSetUID: true, ChownSetGID: true, Append: true,
		ReapIfLeaseExpiresByMs: math.MaxInt64,
		Env: &Envelope{
			SessionID: "estimate", Generation: math.MaxUint64,
			Slot: math.MaxUint32, SlotSeq: math.MaxUint64,
			ReqHash: bytes.Repeat([]byte{0xff}, PFR1ReqHashBytes),
		},
		XattrName: "user.estimate", XattrFlags: XattrCreate,
	}
	encoded, err := EncodePFR1(&rec)
	if err != nil {
		t.Fatal(err)
	}
	if estimate := PFR1SizeEstimate(rec); estimate < len(encoded) {
		t.Fatalf("PFR1SizeEstimate=%d, encoded=%d", estimate, len(encoded))
	}
}

func FuzzPFR1Decode(f *testing.F) {
	for _, g := range pfr1Goldens {
		raw, err := hex.DecodeString(g.hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte("PFR1"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		rec, err := DecodePFR1(payload)
		if err != nil {
			return
		}
		re, err := EncodePFR1(&rec)
		if err != nil {
			t.Fatalf("accepted payload does not re-encode: %v", err)
		}
		if !bytes.Equal(re, payload) {
			t.Fatalf("accepted payload is not canonical:\n in %x\nout %x", payload, re)
		}
	})
}
