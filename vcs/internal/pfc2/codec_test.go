package pfc2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

func hash32(b byte) (h [32]byte) {
	for i := range h {
		h[i] = b
	}
	return
}

func hashID(b byte) (id [FactIDBytes]byte) {
	for i := range id {
		id[i] = b
	}
	return
}

func ref(id string, gen uint64) SessionRef { return SessionRef{SessionID: id, Generation: gen} }

func key(id string, gen uint64, slot uint32, seq uint64, hb byte) ExactKey {
	return ExactKey{Session: ref(id, gen), Slot: slot, SlotSeq: seq, RequestHash: hash32(hb)}
}

// lockRec builds a structurally valid LockChange (fingerprint filled in).
func lockRec(k ExactKey, ino, lockOwner uint64, op LockOp, start, length uint64) Record {
	l := &LockChange{Key: k, Ino: ino, KernelLockOwner: lockOwner, Op: op, Start: start, Length: length}
	l.Key.RequestHash = l.RequestHash()
	return Record{Kind: KindLockChange, LockChange: l}
}

// checkoutRec builds a structurally valid CheckoutChange (fingerprint filled in).
func checkoutRec(k ExactKey, op CheckoutOp, path string, epoch Epoch, digest [32]byte) Record {
	c := &CheckoutChange{Key: k, Op: op, Path: path, Epoch: epoch, RecalledDigest: digest}
	c.Key.RequestHash = c.RequestHash()
	return Record{Kind: KindCheckoutChange, CheckoutChange: c}
}

type goldenRecord struct {
	name string
	rec  Record
	hex  string
}

// goldenRecords freezes the byte encoding of representative records covering
// every kind. If any of these change, the codec is no longer PFC2 — a new
// codec name is required. Fixtures were captured from the initial frozen
// implementation and are deliberately spelled as literal hex.
func goldenRecords() []goldenRecord {
	factOf := func(b byte, dbMs int64) TimeFact {
		var id [FactIDBytes]byte
		for i := range id {
			id[i] = b
		}
		return TimeFact{Source: TimeSourceDB, FactID: id, DbMs: dbMs}
	}
	return []goldenRecord{
		{
			name: "session-open",
			rec: Record{Kind: KindSessionOpen, SessionOpen: &SessionOpen{
				Session: ref("pfs-0a1b2c", 1), Owner: "host-a:mount-7", TokenHash: hash32(0xab),
				Slots: 64, Fact: factOf(0x1f, 1_700_000_000_000), ExpiresDbMs: 1_700_000_090_000,
			}},
			hex: "50464332080112680a0e0a0a7066732d3061316232631001120e686f73742d613a6d6f756e742d371a20abababababababababababababababababababababababababababababababab20402a1b080112101f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1880a0abfef96230a09eb6fef962",
		},
		{
			name: "session-renew",
			rec: Record{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
				Session: ref("pfs-0a1b2c", 1), TokenHash: hash32(0xab),
				Fact: factOf(0x2f, 1_700_000_060_000), ExpiresDbMs: 1_700_000_180_000,
			}},
			hex: "5046433208021a560a0e0a0a7066732d30613162326310011220abababababababababababababababababababababababababababababababab1a1b080112102f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f18c0c9b2fef96220c09cc1fef962",
		},
		{
			name: "session-terminal-expire",
			rec: Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{
				Session: ref("pfs-0a1b2c", 1), Reason: TerminalExpire,
				ObservedDeadlineDbMs: 1_700_000_180_000,
				DecisionFact:         factOf(0x3f, 1_700_000_180_250),
			}},
			hex: "50464332080322360a0e0a0a7066732d3061316232631001100218c09cc1fef962221b080112103f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f18b4a0c1fef962",
		},
		{
			name: "session-terminal-close",
			rec: Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{
				Session: ref("pfs-0a1b2c", 2), Reason: TerminalClose,
			}},
			hex: "50464332080322120a0e0a0a7066732d30613162326310021001",
		},
		{
			name: "exact-outcome-rejection",
			rec: Record{Kind: KindExactOutcome, ExactOutcome: &ExactOutcome{
				Key:     key("pfs-0a1b2c", 1, 3, 9, 0xcd),
				Outcome: Outcome{Status: 17, Count: -1, Offset: 4096, Ino: 42, OrphanIno: 7},
			}},
			hex: "5046433208042a450a360a0e0a0a7066732d3061316232631001100318092220cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd120b08221001188040202a2807",
		},
		{
			name: "exact-outcome-zero",
			rec: Record{Kind: KindExactOutcome, ExactOutcome: &ExactOutcome{
				Key: key("pfs-0a1b2c", 1, 0, 1, 0xcd),
			}},
			hex: "5046433208042a360a340a0e0a0a7066732d306131623263100118012220cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
		},
		{
			name: "outcome-floor",
			rec: Record{Kind: KindOutcomeFloor, OutcomeFloor: &OutcomeFloor{
				Session: ref("pfs-0a1b2c", 1), Slot: 3, Through: 9,
			}},
			hex: "50464332080532140a0e0a0a7066732d306131623263100110031809",
		},
		{
			name: "flush-advance",
			rec: Record{Kind: KindFlushAdvance, FlushAdvance: &FlushAdvance{
				Session: ref("pfs-0a1b2c", 1), WritebackID: "wb-1",
				CheckoutPath: "proj/data", CheckoutEpoch: "12", Through: 512,
			}},
			hex: "5046433208063a280a0e0a0a7066732d3061316232631001120477622d311a0970726f6a2f6461746122023132288004",
		},
		{
			name: "lock-set-write-eof",
			rec:  lockRec(key("pfs-0a1b2c", 1, 2, 4, 0), 42, 0xdeadbeef, LockSetWrite, 4096, 0),
			hex:  "50464332080742450a360a0e0a0a7066732d306131623263100110021804222067c6d5a9c617d437d6f0f489e8b8f9d10c436261382b50c075101ee7d3d1651d182a20effdb6f50d2802308020",
		},
		{
			name: "lock-unlock-partial",
			rec:  lockRec(key("pfs-0a1b2c", 1, 2, 5, 0), 42, 0xdeadbeef, LockUnlock, 4096, 8192),
			hex:  "50464332080742480a360a0e0a0a7066732d30613162326310011002180522209f7dbab996c98a918e5ba3bed9f240c557cc03106d4f2425006dbd0f46f3ca7b182a20effdb6f50d2803308020388040",
		},
		{
			name: "checkout-grant",
			rec:  checkoutRec(key("pfs-0a1b2c", 1, 1, 2, 0), CheckoutGrant, "proj/data", "12", [32]byte{}),
			hex:  "5046433208084a490a360a0e0a0a7066732d3061316232631001100118022220768b4311ee00f7036365fa7292cf93b6a13e185e11b2298c2aba77dbb9c856c71801220970726f6a2f646174612a023132",
		},
		{
			name: "checkout-release",
			rec:  checkoutRec(key("pfs-0a1b2c", 1, 1, 3, 0), CheckoutRelease, "proj/data", "12", [32]byte{}),
			hex:  "5046433208084a490a360a0e0a0a7066732d30613162326310011001180322208be2397ffe9683e03a5acd152065c92e9ff954bb5240579d4d1090d13f80655e1802220970726f6a2f646174612a023132",
		},
		{
			name: "checkout-force-transfer",
			rec:  checkoutRec(key("pfs-9f8e7d", 3, 0, 1, 0), CheckoutForceTransfer, "proj/data", "13", hash32(0x5a)),
			hex:  "5046433208084a690a340a0e0a0a7066732d396638653764100318012220768b4311ee00f7036365fa7292cf93b6a13e185e11b2298c2aba77dbb9c856c71803220970726f6a2f646174612a02313332205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
		},
		{
			name: "open-pin",
			rec: Record{Kind: KindOpenPinChange, OpenPinChange: &OpenPinChange{
				Session: ref("pfs-0a1b2c", 1), Ino: 42,
			}},
			hex: "50464332080952120a0e0a0a7066732d3061316232631001102a",
		},
		{
			name: "open-unpin",
			rec: Record{Kind: KindOpenPinChange, OpenPinChange: &OpenPinChange{
				Session: ref("pfs-0a1b2c", 1), Ino: 42, Unpin: true,
			}},
			hex: "50464332080952140a0e0a0a7066732d3061316232631001102a1801",
		},
	}
}

func TestGoldens(t *testing.T) {
	for _, g := range goldenRecords() {
		got, err := Encode(&g.rec)
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
		if !reflect.DeepEqual(dec, g.rec) {
			t.Fatalf("%s: decoded record differs\n got %+v\nwant %+v", g.name, dec, g.rec)
		}
		re, err := Encode(&dec)
		if err != nil {
			t.Fatalf("%s: re-encode: %v", g.name, err)
		}
		if !bytes.Equal(re, raw) {
			t.Fatalf("%s: re-encode is not byte identical", g.name)
		}
	}
}

func TestDigestCoversMagic(t *testing.T) {
	rec := goldenRecords()[0].rec
	enc, err := Encode(&rec)
	if err != nil {
		t.Fatal(err)
	}
	full := Digest(enc)
	bodyOnly := Digest(enc[4:])
	if full == bodyOnly {
		t.Fatal("digest does not cover the magic")
	}
}

// ─── malformed wire corpus ──────────────────────────────────────────────────

func TestDecodeRejectsMalformed(t *testing.T) {
	valid, err := Encode(&Record{Kind: KindOutcomeFloor, OutcomeFloor: &OutcomeFloor{
		Session: ref("s", 1), Slot: 1, Through: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	body := valid[4:]

	withMagic := func(b ...byte) []byte { return append(append([]byte{}, Magic[:]...), b...) }
	// A floor arm body used to build kind-mismatch payloads.
	floorArm := func() []byte {
		var arm []byte
		arm = pfwire.AppendBytes(arm, 1, appendSessionRef(nil, ref("s", 1)))
		arm = pfwire.AppendUint(arm, 2, 1)
		arm = pfwire.AppendUint(arm, 3, 1)
		return arm
	}

	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"short-magic", []byte("PFC")},
		{"wrong-magic", append([]byte("PFC1"), body...)},
		{"trailing-byte", append(append([]byte{}, valid...), 0x00)},
		{"unknown-field", withMagic(0x58, 0x01)},               // field 11 varint
		{"wire-type-5", withMagic(0x0D)},                       // field 1 wt 5
		{"kind-zero", withMagic(0x08, 0x00)},                   // explicit default kind
		{"kind-unknown", withMagic(0x08, 0x0A)},                // kind 10
		{"kind-without-arm", withMagic(0x08, 0x05)},            // kind 5, no arm
		{"nonminimal-varint", withMagic(0x08, 0x85, 0x00)},     // kind 5 over-long
		{"duplicate-field", withMagic(0x08, 0x05, 0x08, 0x05)}, // kind twice
		{"empty-arm", withMagic(0x08, 0x05, 0x32, 0x00)},       // zero-length arm body
		{"arm-kind-mismatch", func() []byte { // kind 4 (exact outcome) with the floor arm (field 6)
			var b []byte
			b = pfwire.AppendUint(b, 1, 4)
			b = pfwire.AppendBytes(b, 6, floorArm())
			return withMagic(b...)
		}()},
		{"oversized", make([]byte, MaxRecordBytes+1)},
	}
	for _, c := range cases {
		if _, err := Decode(c.payload); err == nil {
			t.Fatalf("%s: decode accepted malformed payload", c.name)
		}
	}
}

// buildOpenArm hand-crafts a session-open record body; mut edits the arm
// builder inputs so tests can produce near-canonical malformed payloads.
type openArmParts struct {
	tokenHash []byte // nil = omit the field
	fact      []byte // nil = omit the field
	factID    []byte // nil = omit inside the fact
	source    uint64
	dbMs      int64
}

func buildOpenPayload(p openArmParts) []byte {
	if p.fact == nil && (p.factID != nil || p.source != 0 || p.dbMs != 0) {
		var f []byte
		f = pfwire.AppendUint(f, 1, p.source)
		f = pfwire.AppendBytes(f, 2, p.factID)
		f = pfwire.AppendSint(f, 3, p.dbMs)
		p.fact = f
	}
	var sess []byte
	sess = pfwire.AppendBytes(sess, 1, appendSessionRef(nil, ref("s", 1)))
	sess = pfwire.AppendBytes(sess, 3, p.tokenHash)
	sess = pfwire.AppendUint(sess, 4, 8)
	sess = pfwire.AppendBytes(sess, 5, p.fact)
	sess = pfwire.AppendSint(sess, 6, 2000)
	var b []byte
	b = pfwire.AppendUint(b, 1, uint64(KindSessionOpen))
	b = pfwire.AppendBytes(b, 2, sess)
	return append(append([]byte{}, Magic[:]...), b...)
}

func TestDecodeRejectsBadFixedFieldShapes(t *testing.T) {
	goodToken := bytes.Repeat([]byte{0xab}, 32)
	goodID := bytes.Repeat([]byte{0x01}, 16)
	cases := []struct {
		name string
		p    openArmParts
	}{
		{"token-hash-31", openArmParts{tokenHash: bytes.Repeat([]byte{0xab}, 31), source: 1, factID: goodID, dbMs: 1000}},
		{"token-hash-33", openArmParts{tokenHash: bytes.Repeat([]byte{0xab}, 33), source: 1, factID: goodID, dbMs: 1000}},
		{"missing-token-hash", openArmParts{source: 1, factID: goodID, dbMs: 1000}},
		{"missing-fact", openArmParts{tokenHash: goodToken}},
		{"missing-fact-id", openArmParts{tokenHash: goodToken, source: 1, dbMs: 1000}},
		{"fact-id-15", openArmParts{tokenHash: goodToken, source: 1, factID: bytes.Repeat([]byte{1}, 15), dbMs: 1000}},
		{"fact-id-17", openArmParts{tokenHash: goodToken, source: 1, factID: bytes.Repeat([]byte{1}, 17), dbMs: 1000}},
		{"unknown-fact-source", openArmParts{tokenHash: goodToken, source: 2, factID: goodID, dbMs: 1000}},
	}
	for _, c := range cases {
		if _, err := Decode(buildOpenPayload(c.p)); err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: not typed malformed: %v", c.name, err)
		}
	}
	// REQUIRED cryptographic identifiers reject the all-zero value even when
	// the wire field is present: absence is modeled by the missing field
	// (cases above), and a present zero can only be a fabricated or damaged
	// identity — never a legal credential digest or database-minted fact id.
	zeroToken := buildOpenPayload(openArmParts{tokenHash: make([]byte, 32), source: 1, factID: goodID, dbMs: 1000})
	if _, err := Decode(zeroToken); !errors.Is(err, ErrMalformed) {
		t.Fatalf("present all-zero token hash: %v", err)
	}
	zeroFact := buildOpenPayload(openArmParts{tokenHash: goodToken, source: 1, factID: make([]byte, 16), dbMs: 1000})
	if _, err := Decode(zeroFact); !errors.Is(err, ErrMalformed) {
		t.Fatalf("present all-zero fact id: %v", err)
	}
}

func TestDecodeRejectsMissingRequestHash(t *testing.T) {
	var k []byte
	k = pfwire.AppendBytes(k, 1, appendSessionRef(nil, ref("s", 1)))
	k = pfwire.AppendUint(k, 3, 1) // slot_seq without request_hash
	var arm []byte
	arm = pfwire.AppendBytes(arm, 1, k)
	var b []byte
	b = pfwire.AppendUint(b, 1, uint64(KindExactOutcome))
	b = pfwire.AppendBytes(b, 5, arm)
	if _, err := Decode(append(append([]byte{}, Magic[:]...), b...)); err == nil {
		t.Fatal("missing request hash accepted")
	}
}

func TestDecodeRejectsDecisionFactPresenceMismatch(t *testing.T) {
	// Close with a decision fact.
	var f []byte
	f = pfwire.AppendUint(f, 1, uint64(TimeSourceDB))
	f = pfwire.AppendBytes(f, 2, bytes.Repeat([]byte{1}, 16))
	f = pfwire.AppendSint(f, 3, 1000)
	var arm []byte
	arm = pfwire.AppendBytes(arm, 1, appendSessionRef(nil, ref("s", 1)))
	arm = pfwire.AppendUint(arm, 2, uint64(TerminalClose))
	arm = pfwire.AppendBytes(arm, 4, f)
	var b []byte
	b = pfwire.AppendUint(b, 1, uint64(KindSessionTerminal))
	b = pfwire.AppendBytes(b, 4, arm)
	if _, err := Decode(append(append([]byte{}, Magic[:]...), b...)); err == nil {
		t.Fatal("close with decision fact accepted")
	}
	// Expire without one.
	arm = nil
	arm = pfwire.AppendBytes(arm, 1, appendSessionRef(nil, ref("s", 1)))
	arm = pfwire.AppendUint(arm, 2, uint64(TerminalExpire))
	arm = pfwire.AppendSint(arm, 3, 1000)
	b = nil
	b = pfwire.AppendUint(b, 1, uint64(KindSessionTerminal))
	b = pfwire.AppendBytes(b, 4, arm)
	if _, err := Decode(append(append([]byte{}, Magic[:]...), b...)); err == nil {
		t.Fatal("expire without decision fact accepted")
	}
}

func TestDecodeRejectsDigestPresenceMismatch(t *testing.T) {
	// Grant with a recalled digest present.
	grant := checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "p", "1", [32]byte{})
	var arm []byte
	c := grant.CheckoutChange
	arm = pfwire.AppendBytes(arm, 1, appendExactKey(nil, &c.Key))
	arm = pfwire.AppendUint(arm, 3, uint64(CheckoutGrant))
	arm = pfwire.AppendString(arm, 4, c.Path)
	arm = pfwire.AppendString(arm, 5, string(c.Epoch))
	arm = pfwire.AppendBytes(arm, 6, bytes.Repeat([]byte{0x5a}, 32))
	var b []byte
	b = pfwire.AppendUint(b, 1, uint64(KindCheckoutChange))
	b = pfwire.AppendBytes(b, 9, arm)
	if _, err := Decode(append(append([]byte{}, Magic[:]...), b...)); err == nil {
		t.Fatal("grant with recalled digest accepted")
	}

	// Force transfer without a digest.
	transfer := checkoutRec(key("s", 1, 0, 1, 0), CheckoutForceTransfer, "p", "1", hash32(1))
	c = transfer.CheckoutChange
	arm = nil
	arm = pfwire.AppendBytes(arm, 1, appendExactKey(nil, &c.Key))
	arm = pfwire.AppendUint(arm, 3, uint64(CheckoutForceTransfer))
	arm = pfwire.AppendString(arm, 4, c.Path)
	arm = pfwire.AppendString(arm, 5, string(c.Epoch))
	b = nil
	b = pfwire.AppendUint(b, 1, uint64(KindCheckoutChange))
	b = pfwire.AppendBytes(b, 9, arm)
	if _, err := Decode(append(append([]byte{}, Magic[:]...), b...)); err == nil {
		t.Fatal("force transfer without recalled digest accepted")
	}
}

// ─── structural validation ──────────────────────────────────────────────────

func TestValidateRejects(t *testing.T) {
	goodFact := TimeFact{Source: TimeSourceDB, FactID: hashID(0x11), DbMs: 1000}
	openRec := func(mut func(*SessionOpen)) Record {
		s := &SessionOpen{
			Session: ref("s", 1), TokenHash: hash32(1), Slots: 8,
			Fact: goodFact, ExpiresDbMs: 2000,
		}
		mut(s)
		return Record{Kind: KindSessionOpen, SessionOpen: s}
	}
	renewRec := func(mut func(*SessionRenew)) Record {
		s := &SessionRenew{
			Session: ref("s", 1), TokenHash: hash32(1),
			Fact: goodFact, ExpiresDbMs: 2000,
		}
		mut(s)
		return Record{Kind: KindSessionRenew, SessionRenew: s}
	}
	lockValid := lockRec(key("s", 1, 0, 1, 0), 1, 1, LockSetRead, 0, 1)

	cases := []struct {
		name string
		rec  Record
	}{
		{"no-arm", Record{Kind: KindSessionOpen}},
		{"two-arms", Record{Kind: KindSessionOpen,
			SessionOpen:  &SessionOpen{Session: ref("s", 1), TokenHash: hash32(1), Slots: 1, Fact: goodFact, ExpiresDbMs: 2000},
			OutcomeFloor: &OutcomeFloor{Session: ref("s", 1), Through: 1}}},
		{"empty-session-id", openRec(func(s *SessionOpen) { s.Session.SessionID = "" })},
		{"bad-alphabet-session-id", openRec(func(s *SessionOpen) { s.Session.SessionID = "a b" })},
		{"slash-session-id", openRec(func(s *SessionOpen) { s.Session.SessionID = "a/b" })},
		{"oversized-session-id", openRec(func(s *SessionOpen) { s.Session.SessionID = strings.Repeat("a", 129) })},
		{"zero-generation", openRec(func(s *SessionOpen) { s.Session.Generation = 0 })},
		{"zero-slots", openRec(func(s *SessionOpen) { s.Slots = 0 })},
		{"oversized-slots", openRec(func(s *SessionOpen) { s.Slots = MaxSlots + 1 })},
		{"missing-fact-source", openRec(func(s *SessionOpen) { s.Fact.Source = 0 })},
		{"unknown-fact-source", openRec(func(s *SessionOpen) { s.Fact.Source = 3 })},
		{"zero-issued", openRec(func(s *SessionOpen) { s.Fact.DbMs = 0 })},
		{"negative-issued", openRec(func(s *SessionOpen) { s.Fact.DbMs = -5; s.ExpiresDbMs = 5 })},
		{"issued-past-year-9999", openRec(func(s *SessionOpen) { s.Fact.DbMs = MaxDbTimeMs + 1; s.ExpiresDbMs = MaxDbTimeMs + 2 })},
		{"expiry-before-issue", openRec(func(s *SessionOpen) { s.ExpiresDbMs = 999 })},
		{"expiry-equals-issue", openRec(func(s *SessionOpen) { s.ExpiresDbMs = s.Fact.DbMs })},
		{"expiry-overflow-int64", openRec(func(s *SessionOpen) { s.ExpiresDbMs = math.MaxInt64 })},
		{"lease-span-implausible", openRec(func(s *SessionOpen) { s.ExpiresDbMs = s.Fact.DbMs + MaxSessionLeaseMs + 1 })},
		{"oversized-owner", openRec(func(s *SessionOpen) { s.Owner = strings.Repeat("o", MaxOwnerBytes+1) })},
		{"nul-owner", openRec(func(s *SessionOpen) { s.Owner = "a\x00b" })},
		{"renew-missing-fact-source", renewRec(func(s *SessionRenew) { s.Fact.Source = 0 })},
		{"renew-zero-minted", renewRec(func(s *SessionRenew) { s.Fact.DbMs = 0 })},
		{"renew-deadline-before-minted", renewRec(func(s *SessionRenew) { s.ExpiresDbMs = 999 })},
		{"renew-span-implausible", renewRec(func(s *SessionRenew) { s.ExpiresDbMs = s.Fact.DbMs + MaxSessionLeaseMs + 1 })},
		{"terminal-unknown-reason", Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{Session: ref("s", 1), Reason: 9}}},
		{"terminal-expire-without-deadline", Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{Session: ref("s", 1), Reason: TerminalExpire, DecisionFact: TimeFact{Source: TimeSourceDB, DbMs: 5}}}},
		{"terminal-expire-without-decision", Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{Session: ref("s", 1), Reason: TerminalExpire, ObservedDeadlineDbMs: 5}}},
		{"terminal-expire-decided-before-deadline", Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{Session: ref("s", 1), Reason: TerminalExpire, ObservedDeadlineDbMs: 10, DecisionFact: TimeFact{Source: TimeSourceDB, DbMs: 9}}}},
		{"terminal-expire-implausible-deadline", Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{Session: ref("s", 1), Reason: TerminalExpire, ObservedDeadlineDbMs: MaxDbTimeMs + 1, DecisionFact: TimeFact{Source: TimeSourceDB, DbMs: MaxDbTimeMs + 2}}}},
		{"terminal-close-with-deadline", Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{Session: ref("s", 1), Reason: TerminalClose, ObservedDeadlineDbMs: 5}}},
		{"terminal-close-with-decision", Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{Session: ref("s", 1), Reason: TerminalClose, DecisionFact: TimeFact{Source: TimeSourceDB, FactID: hashID(1), DbMs: 5}}}},
		{"outcome-zero-slot-seq", Record{Kind: KindExactOutcome, ExactOutcome: &ExactOutcome{Key: ExactKey{Session: ref("s", 1), RequestHash: hash32(1)}}}},
		{"outcome-slot-out-of-bound", Record{Kind: KindExactOutcome, ExactOutcome: &ExactOutcome{Key: ExactKey{Session: ref("s", 1), Slot: MaxSlots, SlotSeq: 1, RequestHash: hash32(1)}}}},
		{"floor-zero-through", Record{Kind: KindOutcomeFloor, OutcomeFloor: &OutcomeFloor{Session: ref("s", 1), Slot: 0}}},
		{"flush-empty-writeback", Record{Kind: KindFlushAdvance, FlushAdvance: &FlushAdvance{Session: ref("s", 1), CheckoutPath: "p", CheckoutEpoch: "1", Through: 1}}},
		{"flush-bad-epoch", Record{Kind: KindFlushAdvance, FlushAdvance: &FlushAdvance{Session: ref("s", 1), WritebackID: "w", CheckoutPath: "p", CheckoutEpoch: "01", Through: 1}}},
		{"flush-zero-through", Record{Kind: KindFlushAdvance, FlushAdvance: &FlushAdvance{Session: ref("s", 1), WritebackID: "w", CheckoutPath: "p", CheckoutEpoch: "1"}}},
		{"lock-zero-ino", func() Record {
			r := lockRec(key("s", 1, 0, 1, 0), 1, 1, LockSetRead, 0, 1)
			r.LockChange.Ino = 0
			r.LockChange.Key.RequestHash = r.LockChange.RequestHash()
			return r
		}()},
		{"lock-bad-op", func() Record {
			r := lockValid
			l := *r.LockChange
			l.Op = 4
			l.Key.RequestHash = l.RequestHash()
			return Record{Kind: KindLockChange, LockChange: &l}
		}()},
		{"lock-range-overflow", func() Record {
			l := &LockChange{Key: key("s", 1, 0, 1, 0), Ino: 1, Op: LockSetRead, Start: math.MaxUint64, Length: 2}
			l.Key.RequestHash = l.RequestHash()
			return Record{Kind: KindLockChange, LockChange: l}
		}()},
		{"lock-nonzero-outcome", func() Record {
			l := &LockChange{Key: key("s", 1, 0, 1, 0), Ino: 1, Op: LockSetRead, Outcome: Outcome{Status: 11}}
			l.Key.RequestHash = l.RequestHash()
			return Record{Kind: KindLockChange, LockChange: l}
		}()},
		{"lock-fingerprint-mismatch", func() Record {
			r := lockRec(key("s", 1, 0, 1, 0), 1, 1, LockSetRead, 0, 1)
			r.LockChange.Key.RequestHash = hash32(0x11)
			return r
		}()},
		{"checkout-bad-path-absolute", checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "/abs", "1", [32]byte{})},
		{"checkout-bad-path-dotdot", checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "a/../b", "1", [32]byte{})},
		{"checkout-bad-path-empty-seg", checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "a//b", "1", [32]byte{})},
		{"checkout-trailing-slash", checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "a/", "1", [32]byte{})},
		{"checkout-epoch-zero", checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "a", "0", [32]byte{})},
		{"checkout-epoch-overflow", checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "a", "9223372036854775808", [32]byte{})},
		{"checkout-grant-with-digest", func() Record {
			r := checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "a", "1", [32]byte{})
			r.CheckoutChange.RecalledDigest = hash32(2)
			return r
		}()},
		{"checkout-fingerprint-mismatch", func() Record {
			r := checkoutRec(key("s", 1, 0, 1, 0), CheckoutGrant, "a", "1", [32]byte{})
			r.CheckoutChange.Key.RequestHash = hash32(0x11)
			return r
		}()},
		{"pin-zero-ino", Record{Kind: KindOpenPinChange, OpenPinChange: &OpenPinChange{Session: ref("s", 1)}}},
	}
	for _, c := range cases {
		if err := c.rec.Validate(); err == nil {
			t.Errorf("%s: validate accepted an invalid record", c.name)
		} else if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error root is not ErrMalformed: %v", c.name, err)
		}
		if _, err := Encode(&c.rec); err == nil {
			t.Errorf("%s: encode accepted an invalid record", c.name)
		}
	}
}

// TestAllZeroRequiredIdentifiersAreRejected locks the value rule on top of
// field-level presence: REQUIRED cryptographic identifiers — token hashes,
// exact request hashes, recalled-conflict digests, database fact ids — reject
// the all-zero value even when the wire field is present. Optional absence is
// modeled explicitly by the missing field or the declaring op/kind, never by
// accepting a zero required value.
func TestAllZeroRequiredIdentifiersAreRejected(t *testing.T) {
	goodFact := TimeFact{Source: TimeSourceDB, FactID: hashID(0x11), DbMs: 1000}
	rejected := []struct {
		name string
		rec  Record
	}{
		{"zero-token-hash-open", Record{Kind: KindSessionOpen, SessionOpen: &SessionOpen{
			Session: ref("s", 1), TokenHash: [32]byte{}, Slots: 1, Fact: goodFact, ExpiresDbMs: 2000,
		}}},
		{"zero-fact-id-open", Record{Kind: KindSessionOpen, SessionOpen: &SessionOpen{
			Session: ref("s", 1), TokenHash: hash32(1), Slots: 1,
			Fact: TimeFact{Source: TimeSourceDB, FactID: [FactIDBytes]byte{}, DbMs: 1000}, ExpiresDbMs: 2000,
		}}},
		{"zero-token-hash-renew", Record{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
			Session: ref("s", 1), TokenHash: [32]byte{}, Fact: goodFact, ExpiresDbMs: 2000,
		}}},
		{"zero-fact-id-renew", Record{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
			Session: ref("s", 1), TokenHash: hash32(1),
			Fact: TimeFact{Source: TimeSourceDB, FactID: [FactIDBytes]byte{}, DbMs: 1000}, ExpiresDbMs: 2000,
		}}},
		{"zero-request-hash", Record{Kind: KindExactOutcome, ExactOutcome: &ExactOutcome{
			Key: ExactKey{Session: ref("s", 1), SlotSeq: 1, RequestHash: [32]byte{}},
		}}},
		{"zero-recall-digest", checkoutRec(key("s", 1, 0, 1, 0), CheckoutForceTransfer, "a", "1", [32]byte{})},
		{"zero-decision-fact-id", Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{
			Session: ref("s", 1), Reason: TerminalExpire, ObservedDeadlineDbMs: 10,
			DecisionFact: TimeFact{Source: TimeSourceDB, FactID: [FactIDBytes]byte{}, DbMs: 11},
		}}},
	}
	for _, c := range rejected {
		if err := c.rec.Validate(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: validate did not reject the all-zero identifier: %v", c.name, err)
		}
		if _, err := Encode(&c.rec); err == nil {
			t.Errorf("%s: encode accepted an all-zero required identifier", c.name)
		}
	}
}

func TestCanonicalPathBounds(t *testing.T) {
	seg := strings.Repeat("a", MaxNameBytes)
	long := seg
	for len(long) < MaxPathBytes-MaxNameBytes-1 {
		long += "/" + seg
	}
	if err := ValidateCanonicalPath(long); err != nil {
		t.Fatalf("long canonical path rejected: %v", err)
	}
	if err := ValidateCanonicalPath(strings.Repeat("a/", MaxPathBytes/2) + "a"); err == nil {
		t.Fatal("over-length path accepted")
	}
	if err := ValidateCanonicalPath(seg + "b"); err == nil {
		t.Fatal("oversized segment accepted")
	}
	if err := ValidateCanonicalPath("a/\xff/b"); err == nil {
		t.Fatal("invalid UTF-8 path accepted")
	}
}

// ─── random round-trip property ─────────────────────────────────────────────

const idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"

func randID(rng *rand.Rand, max int) string {
	n := 1 + rng.Intn(max)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(idAlphabet[rng.Intn(len(idAlphabet))])
	}
	return b.String()
}

func randRef(rng *rand.Rand) SessionRef {
	return SessionRef{SessionID: randID(rng, 24), Generation: rng.Uint64()>>1 + 1}
}

func randHash(rng *rand.Rand) (h [32]byte) {
	for {
		rng.Read(h[:])
		if h != ([32]byte{}) {
			return
		}
	}
}

func randPath(rng *rand.Rand) string {
	segs := 1 + rng.Intn(4)
	parts := make([]string, segs)
	for i := range parts {
		seg := randID(rng, 12)
		if seg == "." || seg == ".." {
			seg = "x" + seg // "." and ".." segments are not canonical
		}
		parts[i] = seg
	}
	return strings.Join(parts, "/")
}

func randEpoch(rng *rand.Rand) Epoch {
	digits := 1 + rng.Intn(18)
	var b strings.Builder
	b.WriteByte(byte('1' + rng.Intn(9)))
	for i := 1; i < digits; i++ {
		b.WriteByte(byte('0' + rng.Intn(10)))
	}
	return Epoch(b.String())
}

func randKey(rng *rand.Rand) ExactKey {
	return ExactKey{
		Session: randRef(rng), Slot: uint32(rng.Intn(MaxSlots)),
		SlotSeq: rng.Uint64()>>1 + 1, RequestHash: randHash(rng),
	}
}

func randOutcome(rng *rand.Rand) Outcome {
	if rng.Intn(3) == 0 {
		return Outcome{}
	}
	return Outcome{
		Status: int32(rng.Intn(200) - 100), Count: int32(rng.Intn(1 << 20)),
		Offset: rng.Int63() - rng.Int63(), Ino: rng.Uint64(), OrphanIno: rng.Uint64(),
	}
}

func randFactID(rng *rand.Rand) (id [FactIDBytes]byte) {
	for {
		rng.Read(id[:])
		if id != ([FactIDBytes]byte{}) {
			return
		}
	}
}

func randFact(rng *rand.Rand, dbMs int64) TimeFact {
	return TimeFact{Source: TimeSourceDB, FactID: randFactID(rng), DbMs: dbMs}
}

func randRecord(rng *rand.Rand) Record {
	switch 1 + Kind(rng.Intn(9)) {
	case KindSessionOpen:
		issued := 1 + rng.Int63n(MaxDbTimeMs-MaxSessionLeaseMs)
		return Record{Kind: KindSessionOpen, SessionOpen: &SessionOpen{
			Session: randRef(rng), Owner: randID(rng, 32), TokenHash: randHash(rng),
			Slots: uint32(1 + rng.Intn(MaxSlots)), Fact: randFact(rng, issued),
			ExpiresDbMs: issued + 1 + rng.Int63n(MaxSessionLeaseMs-1),
		}}
	case KindSessionRenew:
		minted := 1 + rng.Int63n(MaxDbTimeMs-MaxSessionLeaseMs)
		return Record{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
			Session: randRef(rng), TokenHash: randHash(rng), Fact: randFact(rng, minted),
			ExpiresDbMs: minted + 1 + rng.Int63n(MaxSessionLeaseMs-1),
		}}
	case KindSessionTerminal:
		reason := TerminalReason(1 + rng.Intn(5))
		term := &SessionTerminal{Session: randRef(rng), Reason: reason}
		if reason == TerminalExpire {
			term.ObservedDeadlineDbMs = 1 + rng.Int63n(1<<40)
			term.DecisionFact = randFact(rng, term.ObservedDeadlineDbMs+rng.Int63n(1<<20))
		}
		return Record{Kind: KindSessionTerminal, SessionTerminal: term}
	case KindExactOutcome:
		return Record{Kind: KindExactOutcome, ExactOutcome: &ExactOutcome{
			Key: randKey(rng), Outcome: randOutcome(rng),
		}}
	case KindOutcomeFloor:
		return Record{Kind: KindOutcomeFloor, OutcomeFloor: &OutcomeFloor{
			Session: randRef(rng), Slot: uint32(rng.Intn(MaxSlots)), Through: rng.Uint64()>>1 + 1,
		}}
	case KindFlushAdvance:
		return Record{Kind: KindFlushAdvance, FlushAdvance: &FlushAdvance{
			Session: randRef(rng), WritebackID: randID(rng, 16),
			CheckoutPath: randPath(rng), CheckoutEpoch: randEpoch(rng), Through: rng.Uint64()>>1 + 1,
		}}
	case KindLockChange:
		op := LockOp(1 + rng.Intn(3))
		start := rng.Uint64() >> 1
		var length uint64
		if rng.Intn(3) != 0 {
			length = 1 + rng.Uint64()%(math.MaxUint64-start)
		}
		return lockRec(randKey(rng), rng.Uint64()>>1+1, rng.Uint64(), op, start, length)
	case KindCheckoutChange:
		op := CheckoutOp(1 + rng.Intn(3))
		var digest [32]byte
		if op == CheckoutForceTransfer {
			digest = randHash(rng)
		}
		return checkoutRec(randKey(rng), op, randPath(rng), randEpoch(rng), digest)
	default:
		return Record{Kind: KindOpenPinChange, OpenPinChange: &OpenPinChange{
			Session: randRef(rng), Ino: rng.Uint64()>>1 + 1, Unpin: rng.Intn(2) == 0,
		}}
	}
}

func TestRoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 4000; i++ {
		rec := randRecord(rng)
		enc, err := Encode(&rec)
		if err != nil {
			t.Fatalf("iter %d: encode: %v (%+v)", i, err, rec)
		}
		dec, err := Decode(enc)
		if err != nil {
			t.Fatalf("iter %d: decode: %v", i, err)
		}
		if !reflect.DeepEqual(dec, rec) {
			t.Fatalf("iter %d: round trip mismatch\n got %+v\nwant %+v", i, dec, rec)
		}
		re, err := Encode(&dec)
		if err != nil {
			t.Fatalf("iter %d: re-encode: %v", i, err)
		}
		if !bytes.Equal(re, enc) {
			t.Fatalf("iter %d: re-encode is not byte identical", i)
		}
	}
}

func TestZigzagExtremes(t *testing.T) {
	rec := Record{Kind: KindExactOutcome, ExactOutcome: &ExactOutcome{
		Key: key("s", math.MaxUint64, MaxSlots-1, math.MaxUint64, 0x01),
		Outcome: Outcome{
			Status: math.MinInt32, Count: math.MaxInt32,
			Offset: math.MinInt64, Ino: math.MaxUint64, OrphanIno: math.MaxUint64,
		},
	}}
	enc, err := Encode(&rec)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dec, rec) {
		t.Fatalf("extremes mismatch: %+v vs %+v", dec, rec)
	}
}

func TestRecordSizeBound(t *testing.T) {
	// The largest legal record (4096-byte path plus framing) stays far below
	// the 64 KiB envelope; nothing legal can exceed it.
	rec := checkoutRec(
		key(strings.Repeat("s", MaxSessionIDBytes), math.MaxUint64, MaxSlots-1, math.MaxUint64, 0),
		CheckoutForceTransfer,
		strings.Repeat("a", MaxNameBytes)+"/"+strings.Repeat("b", MaxNameBytes),
		Epoch(EpochBound), hash32(0x77),
	)
	enc, err := Encode(&rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) > MaxRecordBytes {
		t.Fatalf("legal record exceeds envelope: %d", len(enc))
	}
}
