package pfc2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

type goldenEntry struct {
	name  string
	entry Entry
	value string // canonical encoded value, hex
	key   string // canonical sort key, hex
}

// goldenEntries freezes the CONTROL_LEAF entry encoding and key derivation.
func goldenEntries() []goldenEntry {
	return []goldenEntry{
		{
			name: "session",
			entry: Entry{Kind: EntrySession, Session: &SessionEntryValue{
				Session: ref("pfs-0a1b2c", 1), Owner: "host-a", TokenHash: hash32(0xab), Slots: 64,
				TimeSource: TimeSourceDB, IssuedDbMs: 1_700_000_000_000, ExpiresDbMs: 1_700_000_090_000,
			}},
			value: "0801124c0a0e0a0a7066732d30613162326310011206686f73742d611a20abababababababababababababababababababababababababababababababab204028013080a0abfef96238a09eb6fef962",
			key:   "017066732d30613162326300",
		},
		{
			name: "tombstone",
			entry: Entry{Kind: EntryTombstone, Tombstone: &TombstoneEntryValue{
				Session: ref("pfs-dead", 3), Reason: TerminalSupersede,
			}},
			value: "08021a100a0c0a087066732d6465616410031003",
			key:   "017066732d6465616400",
		},
		{
			name: "slot-with-latest",
			entry: Entry{Kind: EntrySlot, Slot: &SlotEntryValue{
				Session: ref("pfs-0a1b2c", 1), Slot: 5, NextSeq: 4, RetiredThrough: 2,
				HasLatest: true, LatestSeq: 3, LatestHash: hash32(0xcd),
				LatestOutcome: Outcome{Status: 17},
			}},
			value: "0803223e0a0e0a0a7066732d306131623263100110051804200228033220cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd3a020822",
			key:   "037066732d3061316232630000000005",
		},
		{
			name: "slot-floored",
			entry: Entry{Kind: EntrySlot, Slot: &SlotEntryValue{
				Session: ref("pfs-0a1b2c", 1), Slot: 6, NextSeq: 4, RetiredThrough: 3,
			}},
			value: "080322160a0e0a0a7066732d3061316232631001100618042003",
			key:   "037066732d3061316232630000000006",
		},
		{
			name: "lock-eof",
			entry: Entry{Kind: EntryLock, Lock: &LockEntryValue{
				Ino: 42, Owner: LockOwner{Session: ref("pfs-0a1b2c", 1), KernelLockOwner: 7},
				Start: 4096, Length: 0, Write: true,
			}},
			value: "08042a19082a120e0a0a7066732d306131623263100118072080203001",
			key:   "04000000000000002a7066732d30613162326300000000000000000100000000000000070000000000001000",
		},
		{
			name: "checkout",
			entry: Entry{Kind: EntryCheckout, Checkout: &CheckoutEntryValue{
				Path: "proj/data", Holder: ref("pfs-0a1b2c", 1), Epoch: "12",
			}},
			value: "0805321f0a0970726f6a2f64617461120e0a0a7066732d30613162326310011a023132",
			key:   "0570726f6a2f6461746100",
		},
		{
			name:  "pin",
			entry: Entry{Kind: EntryPin, Pin: &PinEntryValue{Session: ref("pfs-0a1b2c", 1), Ino: 42}},
			value: "08063a120a0e0a0a7066732d3061316232631001102a",
			key:   "06000000000000002a7066732d306131623263000000000000000001",
		},
		{
			name: "flush",
			entry: Entry{Kind: EntryFlush, Flush: &FlushEntryValue{
				Session: ref("pfs-0a1b2c", 1), WritebackID: "wb-1", CheckoutPath: "proj/data",
				CheckoutEpoch: "12", Through: 512,
			}},
			value: "080742280a0e0a0a7066732d3061316232631001120477622d311a0970726f6a2f6461746122023132288004",
			key:   "077066732d30613162326300000000000000000177622d310070726f6a2f64617461003132",
		},
	}
}

// goldenProjectionState builds a deterministic state exercising every entry
// kind, used for the frozen projection digest.
func goldenProjectionState(t *testing.T) *State {
	t.Helper()
	st := NewState()
	mustApply(t, st, openAt("pfs-a", 1, t0))
	mustApply(t, st, openAt("pfs-b", 1, t0))
	mustApply(t, st, openAt("pfs-c", 1, t0+5))
	mustApply(t, st, closeRec("pfs-c", 1))
	var sa seqCounter
	mustApply(t, st, outcomeRec(key("pfs-a", 1, 0, sa.take(0), 0x11), Outcome{Status: 0, Count: 7}))
	mustApply(t, st, outcomeRec(key("pfs-a", 1, 0, sa.take(0), 0x12), Outcome{Status: 17}))
	mustApply(t, st, outcomeRec(key("pfs-a", 1, 3, sa.take(3), 0x13), Outcome{Ino: 99}))
	mustApply(t, st, floorRec("pfs-a", 1, 3, 1))
	mustApply(t, st, ptr(lockRec(key("pfs-a", 1, 1, sa.take(1), 0), 42, 7, LockSetWrite, 4096, 0)))
	mustApply(t, st, ptr(lockRec(key("pfs-a", 1, 1, sa.take(1), 0), 42, 7, LockSetRead, 0, 100)))
	mustApply(t, st, ptr(checkoutRec(key("pfs-a", 1, 2, sa.take(2), 0), CheckoutGrant, "proj/data", "1", [32]byte{})))
	mustApply(t, st, flushRec("pfs-a", 1, "wb-1", "proj/data", "1", 512))
	mustApply(t, st, pinRec("pfs-a", 1, 42, false))
	mustApply(t, st, pinRec("pfs-b", 1, 42, false))
	mustApply(t, st, pinRec("pfs-b", 1, 43, false))
	return st
}

// goldenProjectionDigest freezes the projection digest of the state above.
// A checkout grant's durable slot outcome now carries the granted epoch
// (Outcome.Offset), so the frozen digest reflects that.
const goldenProjectionDigest = "9c092d372eca4efe41a9ff1a028bc19d4b457bc1e86255bc603653d807dbde22"

func TestEntryGoldens(t *testing.T) {
	for _, g := range goldenEntries() {
		enc, err := EncodeEntry(&g.entry)
		if err != nil {
			t.Fatalf("%s: encode: %v", g.name, err)
		}
		if hex.EncodeToString(enc) != g.value {
			t.Fatalf("%s: value golden drift\n got %s\nwant %s", g.name, hex.EncodeToString(enc), g.value)
		}
		if hex.EncodeToString(g.entry.Key()) != g.key {
			t.Fatalf("%s: key golden drift\n got %s\nwant %s", g.name, hex.EncodeToString(g.entry.Key()), g.key)
		}
		dec, err := DecodeEntry(enc)
		if err != nil {
			t.Fatalf("%s: decode: %v", g.name, err)
		}
		if !reflect.DeepEqual(dec, g.entry) {
			t.Fatalf("%s: decoded entry differs\n got %+v\nwant %+v", g.name, dec, g.entry)
		}
		re, err := EncodeEntry(&dec)
		if err != nil {
			t.Fatalf("%s: re-encode: %v", g.name, err)
		}
		if !bytes.Equal(re, enc) {
			t.Fatalf("%s: re-encode is not byte identical", g.name)
		}
	}
}

func TestProjectionDigestGolden(t *testing.T) {
	p := goldenProjectionState(t).Project()
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) != goldenProjectionDigest {
		t.Fatalf("projection digest drift\n got %s\nwant %s", hex.EncodeToString(digest[:]), goldenProjectionDigest)
	}
}

func TestProjectionRoundTrip(t *testing.T) {
	st := goldenProjectionState(t)
	p := st.Project()

	// Keys strictly ascending.
	for i := 1; i < len(p.Entries); i++ {
		if bytes.Compare(p.Entries[i-1].Key(), p.Entries[i].Key()) >= 0 {
			t.Fatalf("entries not strictly sorted at %d", i)
		}
	}

	rebuilt, err := Rebuild(p)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := rebuilt.Project().Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("Project -> Rebuild -> Project is not identical")
	}
	if rebuilt.NextCheckoutEpoch() != st.NextCheckoutEpoch() || rebuilt.DbTimeFloorMs() != st.DbTimeFloorMs() {
		t.Fatal("root scalars differ after rebuild")
	}
	if rebuilt.Counts() != st.Counts() {
		t.Fatalf("counts differ: %+v vs %+v", rebuilt.Counts(), st.Counts())
	}

	// The rebuilt state keeps REDUCING identically: apply the same suffix to
	// both and compare digests.
	suffix := []*Record{
		renewAt("pfs-a", 1, t0+50_000),
		pinRec("pfs-b", 1, 43, true),
		flushRec("pfs-a", 1, "wb-1", "proj/data", "1", 600),
	}
	for _, r := range suffix {
		mustApply(t, st, r)
		mustApply(t, rebuilt, r)
	}
	if stateDigest(t, st) != stateDigest(t, rebuilt) {
		t.Fatal("post-rebuild reduction diverged")
	}

	// Empty state round trip.
	empty := NewState().Project()
	if len(empty.Entries) != 0 || empty.NextCheckoutEpoch != FirstEpoch || empty.DbTimeFloorMs != 0 {
		t.Fatalf("empty projection %+v", empty)
	}
	if _, err := Rebuild(empty); err != nil {
		t.Fatal(err)
	}
}

func TestProjectionPagination(t *testing.T) {
	p := goldenProjectionState(t).Project()
	pages, err := PaginateEntries(p.Entries, 3, LeafTargetBytes)
	if err != nil {
		t.Fatal(err)
	}
	var total int
	for _, page := range pages {
		if len(page) == 0 || len(page) > 3 {
			t.Fatalf("page size %d", len(page))
		}
		total += len(page)
	}
	if total != len(p.Entries) {
		t.Fatalf("pagination lost entries: %d vs %d", total, len(p.Entries))
	}
	// Byte-bound splitting.
	pages, err = PaginateEntries(p.Entries, MaxLeafEntries, 96)
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range pages {
		var b int
		for i := range page {
			enc, err := EncodeEntry(&page[i])
			if err != nil {
				t.Fatal(err)
			}
			b += len(enc) + len(page[i].Key())
		}
		if len(page) > 1 && b > 96 {
			t.Fatalf("page exceeds byte bound: %d", b)
		}
	}
	if _, err := PaginateEntries(p.Entries, 0, 10); !errors.Is(err, ErrMalformed) {
		t.Fatal("zero entry bound accepted")
	}
	if _, err := PaginateEntries(p.Entries, MaxLeafEntries, 4); !errors.Is(err, ErrMalformed) {
		t.Fatal("unfittable entry accepted")
	}
}

// cloneProjection deep-copies a projection so corruption tests can mutate it.
func cloneProjection(t *testing.T, p *Projection) *Projection {
	t.Helper()
	out := &Projection{
		Schema: p.Schema, Features: p.Features,
		NextCheckoutEpoch: p.NextCheckoutEpoch, DbTimeFloorMs: p.DbTimeFloorMs,
		Counts: p.Counts,
	}
	for i := range p.Entries {
		enc, err := EncodeEntry(&p.Entries[i])
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecodeEntry(enc)
		if err != nil {
			t.Fatal(err)
		}
		out.Entries = append(out.Entries, dec)
	}
	return out
}

func sessionEntryOf(t *testing.T, p *Projection, id string) *SessionEntryValue {
	t.Helper()
	for i := range p.Entries {
		if p.Entries[i].Kind == EntrySession && p.Entries[i].Session.Session.SessionID == id {
			return p.Entries[i].Session
		}
	}
	t.Fatalf("no session entry %q", id)
	return nil
}

func TestRebuildRejectsCorruption(t *testing.T) {
	base := goldenProjectionState(t).Project()

	mutate := func(name string, root error, mut func(p *Projection)) {
		p := cloneProjection(t, base)
		mut(p)
		if _, err := Rebuild(p); !errors.Is(err, root) {
			t.Errorf("%s: got %v, want root %v", name, err, root)
		}
	}

	mutate("unsupported-schema", ErrIntegrity, func(p *Projection) { p.Schema = 2 })
	mutate("unknown-features", ErrIntegrity, func(p *Projection) { p.Features = 1 })
	mutate("bad-epoch", ErrMalformed, func(p *Projection) { p.NextCheckoutEpoch = "007" })
	mutate("count-mismatch", ErrIntegrity, func(p *Projection) { p.Counts.Pins++ })
	mutate("unsorted", ErrIntegrity, func(p *Projection) {
		p.Entries[0], p.Entries[1] = p.Entries[1], p.Entries[0]
	})
	mutate("duplicate-entry", ErrIntegrity, func(p *Projection) {
		p.Entries[1] = p.Entries[0]
	})
	mutate("slot-for-tombstoned-session", ErrIntegrity, func(p *Projection) {
		for i := range p.Entries {
			if p.Entries[i].Kind == EntrySlot {
				p.Entries[i].Slot.Session = ref("pfs-c", 1) // tombstone
				return
			}
		}
	})
	mutate("lock-for-unknown-session", ErrIntegrity, func(p *Projection) {
		for i := range p.Entries {
			if p.Entries[i].Kind == EntryLock {
				p.Entries[i].Lock.Owner.Session = ref("ghost", 1)
				return
			}
		}
	})
	mutate("checkout-epoch-at-next", ErrIntegrity, func(p *Projection) {
		for i := range p.Entries {
			if p.Entries[i].Kind == EntryCheckout {
				p.Entries[i].Checkout.Epoch = p.NextCheckoutEpoch
				return
			}
		}
	})
	mutate("flush-without-grant", ErrIntegrity, func(p *Projection) {
		for i := range p.Entries {
			if p.Entries[i].Kind == EntryFlush {
				p.Entries[i].Flush.CheckoutEpoch = "9"
				return
			}
		}
	})
	mutate("slot-outside-window", ErrIntegrity, func(p *Projection) {
		for i := range p.Entries {
			if p.Entries[i].Kind == EntrySlot {
				p.Entries[i].Slot.Slot = MaxSlots - 1
				return
			}
		}
	})
	mutate("denormalized-locks", ErrIntegrity, func(p *Projection) {
		// Split one EOF write lock into two adjacent same-type intervals:
		// semantically equal coverage, but not the canonical merged form.
		for i := range p.Entries {
			if p.Entries[i].Kind == EntryLock && p.Entries[i].Lock.Length == 0 {
				l := *p.Entries[i].Lock
				first := l
				first.Length = 100
				second := l
				second.Start = l.Start + 100
				second.Length = 0
				p.Entries[i].Lock = &first
				extra := Entry{Kind: EntryLock, Lock: &second}
				p.Entries = append(p.Entries, Entry{})
				copy(p.Entries[i+2:], p.Entries[i+1:])
				p.Entries[i+1] = extra
				p.Counts.Locks++
				return
			}
		}
		t.Fatal("no EOF lock entry to denormalize")
	})

	// Overlapping checkouts (ancestor + descendant).
	p := cloneProjection(t, base)
	var checkout CheckoutEntryValue
	for i := range p.Entries {
		if p.Entries[i].Kind == EntryCheckout {
			checkout = *p.Entries[i].Checkout
			break
		}
	}
	child := checkout
	child.Path = checkout.Path + "/sub"
	child.Epoch = "3"
	insertEntrySorted(p, Entry{Kind: EntryCheckout, Checkout: &child})
	p.Counts.Checkouts++
	if _, err := Rebuild(p); !errors.Is(err, ErrIntegrity) {
		t.Errorf("overlapping checkouts: %v", err)
	}

	// Duplicate checkout epochs across paths.
	p = cloneProjection(t, base)
	sibling := checkout
	sibling.Path = "zz-elsewhere"
	insertEntrySorted(p, Entry{Kind: EntryCheckout, Checkout: &sibling})
	p.Counts.Checkouts++
	if _, err := Rebuild(p); !errors.Is(err, ErrIntegrity) {
		t.Errorf("duplicate epochs: %v", err)
	}
}

func insertEntrySorted(p *Projection, e Entry) {
	k := e.Key()
	for i := range p.Entries {
		if bytes.Compare(p.Entries[i].Key(), k) > 0 {
			p.Entries = append(p.Entries, Entry{})
			copy(p.Entries[i+1:], p.Entries[i:])
			p.Entries[i] = e
			return
		}
	}
	p.Entries = append(p.Entries, e)
}

func TestEntryValidateRejects(t *testing.T) {
	cases := []struct {
		name  string
		entry Entry
	}{
		{"no-arm", Entry{Kind: EntrySession}},
		{"slot-nextseq-1", Entry{Kind: EntrySlot, Slot: &SlotEntryValue{Session: ref("s", 1), NextSeq: 1}}},
		{"slot-latest-wrong-seq", Entry{Kind: EntrySlot, Slot: &SlotEntryValue{
			Session: ref("s", 1), NextSeq: 4, RetiredThrough: 2, HasLatest: true, LatestSeq: 2, LatestHash: hash32(1),
		}}},
		{"slot-floor-contradicts-latest", Entry{Kind: EntrySlot, Slot: &SlotEntryValue{
			Session: ref("s", 1), NextSeq: 4, RetiredThrough: 3, HasLatest: true, LatestSeq: 3, LatestHash: hash32(1),
		}}},
		{"slot-floor-wrong-without-latest", Entry{Kind: EntrySlot, Slot: &SlotEntryValue{
			Session: ref("s", 1), NextSeq: 4, RetiredThrough: 2,
		}}},
		{"lock-zero-ino", Entry{Kind: EntryLock, Lock: &LockEntryValue{Owner: LockOwner{Session: ref("s", 1)}}}},
		{"lock-overflow", Entry{Kind: EntryLock, Lock: &LockEntryValue{
			Ino: 1, Owner: LockOwner{Session: ref("s", 1)}, Start: LockRangeEOF, Length: 2,
		}}},
		{"checkout-bad-path", Entry{Kind: EntryCheckout, Checkout: &CheckoutEntryValue{Path: "/abs", Holder: ref("s", 1), Epoch: "1"}}},
		{"session-implausible-times", Entry{Kind: EntrySession, Session: &SessionEntryValue{
			Session: ref("s", 1), TokenHash: hash32(1), Slots: 1, TimeSource: TimeSourceDB,
			IssuedDbMs: MaxDbTimeMs + 1, ExpiresDbMs: MaxDbTimeMs + 2,
		}}},
		{"session-unknown-source", Entry{Kind: EntrySession, Session: &SessionEntryValue{
			Session: ref("s", 1), TokenHash: hash32(1), Slots: 1, TimeSource: 0,
			IssuedDbMs: 1, ExpiresDbMs: 2,
		}}},
		{"tombstone-bad-reason", Entry{Kind: EntryTombstone, Tombstone: &TombstoneEntryValue{Session: ref("s", 1), Reason: 0}}},
		{"flush-zero-through", Entry{Kind: EntryFlush, Flush: &FlushEntryValue{
			Session: ref("s", 1), WritebackID: "w", CheckoutPath: "p", CheckoutEpoch: "1",
		}}},
		{"pin-zero-ino", Entry{Kind: EntryPin, Pin: &PinEntryValue{Session: ref("s", 1)}}},
	}
	for _, c := range cases {
		if err := c.entry.Validate(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", c.name, err)
		}
		if _, err := EncodeEntry(&c.entry); err == nil {
			t.Errorf("%s: encode accepted an invalid entry", c.name)
		}
	}
}

func TestDecodeEntryRejectsMalformed(t *testing.T) {
	valid, err := EncodeEntry(&Entry{Kind: EntryPin, Pin: &PinEntryValue{Session: ref("s", 1), Ino: 1}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"trailing", append(append([]byte{}, valid...), 0x00)},
		{"kind-only", []byte{0x08, 0x07}},
		{"unknown-kind", []byte{0x08, 0x08}},
		{"oversized", make([]byte, MaxEntryBytes+1)},
		{"over-length-path", func() []byte {
			// Checkout entry whose path field exceeds MaxPathBytes.
			long := strings.Repeat("a", MaxPathBytes+1)
			var arm []byte
			arm = pfwire.AppendString(arm, 1, long)
			var body []byte
			body = pfwire.AppendUint(body, 1, uint64(EntryCheckout))
			body = pfwire.AppendBytes(body, 6, arm)
			return body
		}()},
	}
	for _, c := range cases {
		if _, err := DecodeEntry(c.payload); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
