package pfj3

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func hash32(b byte) (h [32]byte) {
	for i := range h {
		h[i] = b
	}
	return
}

func factID(b byte) (id [pfc2.FactIDBytes]byte) {
	for i := range id {
		id[i] = b
	}
	return
}

func sessionRef() pfc2.SessionRef {
	return pfc2.SessionRef{SessionID: "pfs-0a1b2c", Generation: 1}
}

func openControl() pfc2.Record {
	return pfc2.Record{Kind: pfc2.KindSessionOpen, SessionOpen: &pfc2.SessionOpen{
		Session: sessionRef(), Owner: "host-a", TokenHash: hash32(0xab), Slots: 64,
		Fact:        pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: factID(0x1f), DbMs: 1_700_000_000_000},
		ExpiresDbMs: 1_700_000_090_000,
	}}
}

func renewControl() pfc2.Record {
	return pfc2.Record{Kind: pfc2.KindSessionRenew, SessionRenew: &pfc2.SessionRenew{
		Session: sessionRef(), TokenHash: hash32(0xab),
		Fact:        pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: factID(0x2f), DbMs: 1_700_000_060_000},
		ExpiresDbMs: 1_700_000_150_000,
	}}
}

func flushControl(through uint64) pfc2.Record {
	return pfc2.Record{Kind: pfc2.KindFlushAdvance, FlushAdvance: &pfc2.FlushAdvance{
		Session: sessionRef(), WritebackID: "wb-1", CheckoutPath: "proj/data",
		CheckoutEpoch: "12", Through: through, Digest: hash32(0xcd),
	}}
}

func writeTree(lsn uint64) *wal.Record {
	return &wal.Record{Seq: lsn, Op: wal.OpWrite, Path: "a/b.txt", Offset: 5, Data: []byte{0xde, 0xad}}
}

func batchTree(lsn uint64) *wal.Record {
	return &wal.Record{Seq: lsn, Op: wal.OpBatch, Mutations: []wal.Record{
		{Seq: 1, Op: wal.OpCreate, Path: "x", Mode: 0o600},
		{Seq: 2, Op: wal.OpWrite, Path: "x", Data: []byte("d")},
	}}
}

// pfj3Goldens freezes the byte encoding of representative entries, including
// the fixed preamble (outer LSN, fact count, manifest digest, ordered fact
// manifest). If any of these change, the codec is no longer PFJ3 — a new
// codec name is required.
var pfj3Goldens = []struct {
	name  string
	entry JournalEntry
	hex   string
}{
	{
		name:  "tree-only",
		entry: JournalEntry{LSN: 7, Tree: writeTree(7)},
		hex: "50464a3300000000000000070000a5c62a1a3a0c2dff8a08a44bea8f4f22357bb3b71247a36d20052e70b033829708" +
			"07121750465231080710021a07612f622e747874280a4a02dead",
	},
	{
		name:  "control-only-open-fact",
		entry: JournalEntry{LSN: 9, Controls: []pfc2.Record{openControl()}},
		hex: "50464a33000000000000000900013e4daf26bfcd06defd3ec9773badf5e25a21fc1c51b7ab1c95b025074a81d722" +
			"0000010a7066732d30613162326300000000000000011f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f0000018bcfe56800" +
			"08091a6850464332080112600a0e0a0a7066732d30613162326310011206686f73742d611a20" +
			"abababababababababababababababababababababababababababababababab20402a1b08011210" +
			"1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1880a0abfef96230a09eb6fef962",
	},
	{
		name: "flush-batch-row",
		entry: JournalEntry{
			LSN: 12, Tree: batchTree(12),
			Controls: []pfc2.Record{flushControl(512)},
		},
		hex: "50464a33000000000000000c0000a5c62a1a3a0c2dff8a08a44bea8f4f22357bb3b71247a36d20052e70b033829708" +
			"0c122250465231080c100ec2010a080110011a0178388003c2010a080210021a01784a0164" +
			"1a525046433208063a4a0a0e0a0a7066732d3061316232631001120477622d311a0970726f6a2f64617461220231322880043220" +
			"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
	},
}

func TestGoldens(t *testing.T) {
	for _, g := range pfj3Goldens {
		got, err := Encode(&g.entry)
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
		dec, err := Decode(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", g.name, err)
		}
		if !reflect.DeepEqual(dec, g.entry) {
			t.Fatalf("%s: decoded entry differs\n got %+v\nwant %+v", g.name, dec, g.entry)
		}
		re, err := Encode(&dec)
		if err != nil || !bytes.Equal(re, raw) {
			t.Fatalf("%s: re-encode is not byte identical (%v)", g.name, err)
		}
	}
}

func TestPreambleLayout(t *testing.T) {
	// The manifest must be parseable with fixed offsets (the SQL append
	// transaction has no pfwire decoder): verify the frozen layout directly.
	entry := JournalEntry{LSN: 9, Controls: []pfc2.Record{openControl()}}
	enc, err := Encode(&entry)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint64(enc[4:12]); got != 9 {
		t.Fatalf("preamble LSN = %d", got)
	}
	if got := binary.BigEndian.Uint16(enc[12:14]); got != 1 {
		t.Fatalf("preamble fact count = %d", got)
	}
	off := 4 + preambleFixedBytes
	if got := binary.BigEndian.Uint16(enc[off : off+2]); got != 0 {
		t.Fatalf("entry control index = %d", got)
	}
	if enc[off+2] != byte(FactPurposeSessionOpen) {
		t.Fatalf("entry purpose = %d", enc[off+2])
	}
	idLen := int(enc[off+3])
	if string(enc[off+4:off+4+idLen]) != "pfs-0a1b2c" {
		t.Fatalf("entry session id = %q", enc[off+4:off+4+idLen])
	}
	if got := binary.BigEndian.Uint64(enc[off+4+idLen : off+12+idLen]); got != 1 {
		t.Fatalf("entry session generation = %d", got)
	}
	if !bytes.Equal(enc[off+12+idLen:off+28+idLen], bytes.Repeat([]byte{0x1f}, 16)) {
		t.Fatal("entry fact id bytes differ")
	}
	if got := binary.BigEndian.Uint64(enc[off+28+idLen : off+36+idLen]); got != 1_700_000_000_000 {
		t.Fatalf("entry db ms = %d", got)
	}
}

func TestValidateRules(t *testing.T) {
	cases := []struct {
		name  string
		entry JournalEntry
	}{
		{"empty", JournalEntry{LSN: 1}},
		{"lsn-mismatch", JournalEntry{LSN: 5, Tree: writeTree(6)}},
		{"opcontrol-tree", JournalEntry{LSN: 3, Tree: &wal.Record{Seq: 3, Op: wal.OpControl, Data: []byte{1}}}},
		{"opcontrol-batch-leaf", JournalEntry{LSN: 4, Tree: &wal.Record{
			Seq: 4, Op: wal.OpBatch, Mutations: []wal.Record{
				{Seq: 1, Op: wal.OpCreate, Path: "x", Mode: 0o600},
				{Seq: 2, Op: wal.OpControl, Data: []byte{1}},
			},
		}}},
		{"too-many-controls", JournalEntry{LSN: 2, Controls: func() []pfc2.Record {
			out := make([]pfc2.Record, MaxControls+1)
			for i := range out {
				out[i] = flushControl(uint64(i + 1))
			}
			return out
		}()}},
		{"invalid-control", JournalEntry{LSN: 2, Controls: []pfc2.Record{{Kind: pfc2.KindSessionOpen}}}},
	}
	for _, c := range cases {
		if err := c.entry.Validate(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: validate: %v", c.name, err)
		}
		if _, err := Encode(&c.entry); err == nil {
			t.Errorf("%s: encode accepted an invalid entry", c.name)
		}
	}

	// Batch trees are allowed; LSN 0 (fresh generation head) is legal.
	ok := JournalEntry{LSN: 0, Tree: batchTree(0)}
	enc, err := Encode(&ok)
	if err != nil {
		t.Fatalf("lsn-0 batch: %v", err)
	}
	dec, err := Decode(enc)
	if err != nil || dec.LSN != 0 || dec.Tree == nil {
		t.Fatalf("lsn-0 round trip: %+v %v", dec, err)
	}
}

// corruptPreamble re-encodes a valid entry and applies mut to its bytes.
func corruptPreamble(t *testing.T, entry JournalEntry, mut func(payload []byte) []byte) []byte {
	t.Helper()
	enc, err := Encode(&entry)
	if err != nil {
		t.Fatal(err)
	}
	return mut(append([]byte(nil), enc...))
}

func TestDecodeRejectsMalformed(t *testing.T) {
	valid, err := Encode(&JournalEntry{LSN: 7, Tree: writeTree(7)})
	if err != nil {
		t.Fatal(err)
	}
	// A minimal valid preamble for hand-built bodies (LSN 7, no facts).
	preamble7 := valid[4 : 4+preambleFixedBytes]
	withPreamble := func(lsn uint64, b ...byte) []byte {
		out := append([]byte{}, Magic[:]...)
		var u64 [8]byte
		binary.BigEndian.PutUint64(u64[:], lsn)
		out = append(out, u64[:]...)
		out = append(out, 0, 0)
		d := manifestDigest(0, nil)
		out = append(out, d[:]...)
		return append(out, b...)
	}
	_ = preamble7

	// A structurally valid PFC2 control whose bytes we can corrupt.
	controlBytes, err := pfc2.Encode(func() *pfc2.Record { r := flushControl(1); return &r }())
	if err != nil {
		t.Fatal(err)
	}
	nonCanonicalControl := append([]byte{}, controlBytes...)
	nonCanonicalControl[0] = 'X' // break the PFC2 magic

	treeBytes, err := wal.EncodePFR1(writeTree(7))
	if err != nil {
		t.Fatal(err)
	}

	factEntry := JournalEntry{LSN: 9, Controls: []pfc2.Record{openControl()}}

	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"short-magic", []byte("PFJ")},
		{"wrong-magic", append([]byte("PFR1"), valid[4:]...)},
		{"truncated-preamble", valid[:10]},
		{"trailing-byte", append(append([]byte{}, valid...), 0x00)},
		{"unknown-field", withPreamble(0, 0x20, 0x01)},
		{"duplicate-lsn", withPreamble(7, 0x08, 0x07, 0x08, 0x07)},
		{"explicit-zero-lsn", withPreamble(0, 0x08, 0x00)},
		{"preamble-body-lsn-mismatch", corruptPreamble(t, JournalEntry{LSN: 7, Tree: writeTree(7)}, func(p []byte) []byte {
			binary.BigEndian.PutUint64(p[4:12], 8)
			return p
		})},
		{"manifest-digest-corrupt", corruptPreamble(t, factEntry, func(p []byte) []byte {
			p[14] ^= 0x01
			return p
		})},
		{"manifest-fact-id-corrupt", corruptPreamble(t, factEntry, func(p []byte) []byte {
			// Flip a fact-id byte inside the manifest entry: the digest no
			// longer matches (and if it did, the controls would not).
			p[4+preambleFixedBytes+12+10] ^= 0x01
			return p
		})},
		{"manifest-count-overflow", corruptPreamble(t, factEntry, func(p []byte) []byte {
			binary.BigEndian.PutUint16(p[12:14], MaxFacts+1)
			return p
		})},
		{"fabricated-fact-on-factless-controls", corruptPreamble(t, JournalEntry{LSN: 1, Controls: []pfc2.Record{flushControl(1)}}, func(p []byte) []byte {
			// Splice the open-fact manifest in front of a fact-less body:
			// count/digest/entries are internally consistent, but the decoded
			// controls imply an EMPTY manifest.
			factEnc, err := Encode(&factEntry)
			if err != nil {
				t.Fatal(err)
			}
			factPreambleEnd := 4 + preambleFixedBytes + (factEntryFixedBytes + len("pfs-0a1b2c"))
			out := append([]byte{}, factEnc[:factPreambleEnd]...)
			binary.BigEndian.PutUint64(out[4:12], 1) // keep the outer LSN of the host body
			return append(out, p[4+preambleFixedBytes:]...)
		})},
		{"omitted-fact-manifest", corruptPreamble(t, factEntry, func(p []byte) []byte {
			// Replace the one-entry manifest with an internally consistent
			// EMPTY manifest: the decoded open control still freezes a fact.
			out := append([]byte{}, p[:12]...)
			out = append(out, 0, 0)
			d := manifestDigest(0, nil)
			out = append(out, d[:]...)
			entryLen := factEntryFixedBytes + len("pfs-0a1b2c")
			return append(out, p[4+preambleFixedBytes+entryLen:]...)
		})},
		{"duplicate-tree", func() []byte {
			var b []byte
			b = pfwire.AppendUint(b, 1, 7)
			b = pfwire.AppendBytes(b, 2, treeBytes)
			b = pfwire.AppendBytes(b, 2, treeBytes)
			return withPreamble(7, b...)
		}()},
		{"controls-before-tree", func() []byte {
			var b []byte
			b = pfwire.AppendUint(b, 1, 7)
			b = pfwire.AppendBytes(b, 3, controlBytes)
			b = pfwire.AppendBytes(b, 2, treeBytes)
			return withPreamble(7, b...)
		}()},
		{"non-canonical-control", func() []byte {
			var b []byte
			b = pfwire.AppendUint(b, 1, 1)
			b = pfwire.AppendBytes(b, 3, nonCanonicalControl)
			return withPreamble(1, b...)
		}()},
		{"tree-lsn-mismatch", func() []byte {
			var b []byte
			b = pfwire.AppendUint(b, 1, 8) // tree says 7
			b = pfwire.AppendBytes(b, 2, treeBytes)
			return withPreamble(8, b...)
		}()},
		{"tree-opcontrol", func() []byte {
			ctl, err := wal.EncodePFR1(&wal.Record{Seq: 7, Op: wal.OpControl, Data: []byte{1, 2}})
			if err != nil {
				t.Fatal(err)
			}
			var b []byte
			b = pfwire.AppendUint(b, 1, 7)
			b = pfwire.AppendBytes(b, 2, ctl)
			return withPreamble(7, b...)
		}()},
		{"oversized-entry", make([]byte, MaxEntryBytes+1)},
		{"control-length-exceeds-bound", func() []byte {
			// Declares a control longer than 64 KiB: rejected by the bound
			// check on the length prefix BEFORE the bytes are consumed.
			var b []byte
			b = pfwire.AppendUint(b, 1, 1)
			b = pfwire.AppendTag(b, 3, pfwire.TypeBytes)
			b = pfwire.AppendVarint(b, uint64(MaxControlBytes+1))
			return withPreamble(1, append(b, make([]byte, 1024)...)...)
		}()},
	}
	for _, c := range cases {
		if _, err := Decode(c.payload); err == nil {
			t.Errorf("%s: decode accepted malformed payload", c.name)
		} else if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: rejection is not typed ErrMalformed: %v", c.name, err)
		}
	}
}

// TestManifestBindingRejectsTampering covers the exact fact-binding matrix:
// reorder, cross-session, wrong purpose, wrong time, wrong control index —
// each rebuilt as an internally consistent preamble (digest recomputed) so
// only the controls-congruence check can catch it.
func TestManifestBindingRejectsTampering(t *testing.T) {
	entry := JournalEntry{LSN: 3, Controls: []pfc2.Record{openControl(), renewControl()}}
	enc, err := Encode(&entry)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := entry.FactManifest()
	if err != nil || len(manifest) != 2 {
		t.Fatalf("manifest: %v %d", err, len(manifest))
	}
	rebuild := func(refs []FactRef) []byte {
		var entries []byte
		for _, ref := range refs {
			var aerr error
			entries, aerr = appendFactEntry(entries, ref)
			if aerr != nil {
				t.Fatal(aerr)
			}
		}
		d := manifestDigest(len(refs), entries)
		out := append([]byte{}, enc[:12]...)
		var u16 [2]byte
		binary.BigEndian.PutUint16(u16[:], uint16(len(refs)))
		out = append(out, u16[:]...)
		out = append(out, d[:]...)
		out = append(out, entries...)
		// The original manifest region ends where the body begins.
		pre, perr := parsePreamble(enc)
		if perr != nil {
			t.Fatal(perr)
		}
		return append(out, enc[pre.bodyOffset:]...)
	}

	reordered := []FactRef{manifest[1], manifest[0]}
	crossSession := []FactRef{manifest[0], manifest[1]}
	crossSession[1].Session.SessionID = "pfs-other"
	wrongPurpose := []FactRef{manifest[0], manifest[1]}
	wrongPurpose[1].Purpose = FactPurposeSessionExpiry
	wrongTime := []FactRef{manifest[0], manifest[1]}
	wrongTime[1].DbMs++
	wrongIndex := []FactRef{manifest[0], manifest[1]}
	wrongIndex[1].ControlIndex = 0
	extra := []FactRef{manifest[0], manifest[1], manifest[1]}

	for _, c := range []struct {
		name string
		refs []FactRef
	}{
		{"reordered", reordered},
		{"cross-session", crossSession},
		{"wrong-purpose", wrongPurpose},
		{"wrong-time", wrongTime},
		{"wrong-control-index", wrongIndex},
		{"extra-fact", extra},
	} {
		if _, err := Decode(rebuild(c.refs)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: tampered manifest accepted (%v)", c.name, err)
		}
	}
	// The untampered rebuild round-trips (the rebuild helper is faithful).
	if _, err := Decode(rebuild(manifest)); err != nil {
		t.Fatalf("faithful rebuild rejected: %v", err)
	}
}

func TestBoundsBeforeAllocation(t *testing.T) {
	// 129 valid controls: encode must refuse before building anything big.
	controls := make([]pfc2.Record, MaxControls+1)
	for i := range controls {
		controls[i] = flushControl(uint64(i + 1))
	}
	if _, err := Encode(&JournalEntry{LSN: 1, Controls: controls}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("129 controls: %v", err)
	}
	// 128 valid controls fit.
	if _, err := Encode(&JournalEntry{LSN: 1, Controls: controls[:MaxControls]}); err != nil {
		t.Fatalf("128 controls rejected: %v", err)
	}
	// An entry crossing 8 MiB total is refused even when each arm is legal.
	big := &wal.Record{Seq: 1, Op: wal.OpBatch}
	for i := 0; i < 9; i++ {
		big.Mutations = append(big.Mutations, wal.Record{
			Op: wal.OpWrite, Path: "f", Offset: int64(i) << 20, Data: make([]byte, 1<<20),
		})
	}
	if _, err := Encode(&JournalEntry{LSN: 1, Tree: big}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("9 MiB tree: %v", err)
	}
}

func TestFromLegacyRecord(t *testing.T) {
	rec := wal.Record{Seq: 42, Op: wal.OpWrite, Path: "f", Data: []byte("hi")}
	entry := FromLegacyRecord(rec)
	if entry.LSN != 42 || entry.Tree == nil || len(entry.Controls) != 0 {
		t.Fatalf("legacy adapter: %+v", entry)
	}
	if !reflect.DeepEqual(*entry.Tree, rec) {
		t.Fatal("legacy adapter altered the record")
	}
	// Legacy OpControl records stay tree records: their payloads belong to
	// the legacy control codec, never to PFC2.
	ctl := wal.Record{Seq: 43, Op: wal.OpControl, Data: []byte{2, 1}}
	entry = FromLegacyRecord(ctl)
	if entry.Tree == nil || !entry.Tree.Op.IsControl() {
		t.Fatalf("legacy control adapter: %+v", entry)
	}
}

func TestDigestCoversMagic(t *testing.T) {
	enc, err := Encode(&JournalEntry{LSN: 7, Tree: writeTree(7)})
	if err != nil {
		t.Fatal(err)
	}
	if Digest(enc) == Digest(enc[4:]) {
		t.Fatal("digest does not cover the magic")
	}
	// The chain unit is the exact whole bytes: any single-byte flip changes
	// the chain digest.
	flipped := append([]byte{}, enc...)
	flipped[len(flipped)-1] ^= 0x01
	if wal.ChainDigestBytes([32]byte{}, enc) == wal.ChainDigestBytes([32]byte{}, flipped) {
		t.Fatal("chain digest ignores payload bytes")
	}
}

func TestRecordSizeEstimateFitsRow(t *testing.T) {
	// A full flush batch (write-back pattern): 128-control ceiling plus a
	// large batch stays under the row bound with the frozen limits.
	tree := &wal.Record{Seq: 5, Op: wal.OpBatch}
	for i := 0; i < 64; i++ {
		tree.Mutations = append(tree.Mutations, wal.Record{
			Op: wal.OpWrite, Path: strings.Repeat("p", 64), Offset: int64(i) << 16, Data: make([]byte, 1<<15),
		})
	}
	entry := JournalEntry{LSN: 5, Tree: tree, Controls: []pfc2.Record{flushControl(64)}}
	enc, err := Encode(&entry)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) > MaxEntryBytes {
		t.Fatalf("flush row exceeds bound: %d", len(enc))
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Tree == nil || len(dec.Controls) != 1 || dec.Controls[0].FlushAdvance.Through != 64 {
		t.Fatalf("flush row round trip: %+v", dec)
	}
}

func FuzzDecode(f *testing.F) {
	for _, g := range pfj3Goldens {
		raw, err := hex.DecodeString(g.hex)
		if err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte("PFJ3"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		entry, err := Decode(payload)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("rejection is not typed: %v", err)
			}
			return
		}
		re, err := Encode(&entry)
		if err != nil {
			t.Fatalf("accepted entry does not re-encode: %v", err)
		}
		if !bytes.Equal(re, payload) {
			t.Fatalf("accepted entry is not canonical:\n in %x\nout %x", payload, re)
		}
	})
}
