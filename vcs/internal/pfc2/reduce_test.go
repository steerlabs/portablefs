package pfc2

import (
	"errors"
	"reflect"
	"testing"
)

const (
	t0  = int64(1_700_000_000_000) // base database time for tests
	ttl = int64(90_000)            // 90s lease TTL
)

// fid builds a deterministic NON-ZERO admission-fact identity for tests.
func fid(b byte) (id [FactIDBytes]byte) {
	for i := range id {
		id[i] = b
	}
	id[FactIDBytes-1] = 0xA5 // required identifiers are never all-zero
	return
}

// fact builds a deterministic issued admission fact for tests. The identity
// is derived from the time so distinct mints get distinct ids, and is never
// the forbidden all-zero value.
func fact(dbMs int64) TimeFact {
	var id [FactIDBytes]byte
	for i := 0; i < 8; i++ {
		id[i] = byte(uint64(dbMs) >> (8 * i))
		id[8+i] = ^id[i]
	}
	id[FactIDBytes-1] |= 0x01
	return TimeFact{Source: TimeSourceDB, FactID: id, DbMs: dbMs}
}

func openAt(id string, gen uint64, issuedDbMs int64) *Record {
	return &Record{Kind: KindSessionOpen, SessionOpen: &SessionOpen{
		Session: ref(id, gen), Owner: "owner-" + id, TokenHash: hash32(byte(gen)),
		Slots: 8, Fact: fact(issuedDbMs), ExpiresDbMs: issuedDbMs + ttl,
	}}
}

func renewAt(id string, gen uint64, mintedDbMs int64) *Record {
	return &Record{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
		Session: ref(id, gen), TokenHash: hash32(byte(gen)),
		Fact: fact(mintedDbMs), ExpiresDbMs: mintedDbMs + ttl,
	}}
}

func closeRec(id string, gen uint64) *Record {
	return &Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{
		Session: ref(id, gen), Reason: TerminalClose,
	}}
}

func expireAt(id string, gen uint64, observed, decided int64) *Record {
	return &Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{
		Session: ref(id, gen), Reason: TerminalExpire,
		ObservedDeadlineDbMs: observed, DecisionFact: fact(decided),
	}}
}

func outcomeRec(k ExactKey, out Outcome) *Record {
	return &Record{Kind: KindExactOutcome, ExactOutcome: &ExactOutcome{Key: k, Outcome: out}}
}

func floorRec(id string, gen uint64, slot uint32, through uint64) *Record {
	return &Record{Kind: KindOutcomeFloor, OutcomeFloor: &OutcomeFloor{
		Session: ref(id, gen), Slot: slot, Through: through,
	}}
}

func pinRec(id string, gen, ino uint64, unpin bool) *Record {
	return &Record{Kind: KindOpenPinChange, OpenPinChange: &OpenPinChange{
		Session: ref(id, gen), Ino: ino, Unpin: unpin,
	}}
}

func flushRec(id string, gen uint64, wb, path string, epoch Epoch, through uint64) *Record {
	return &Record{Kind: KindFlushAdvance, FlushAdvance: &FlushAdvance{
		Session: ref(id, gen), WritebackID: wb, CheckoutPath: path,
		CheckoutEpoch: epoch, Through: through,
	}}
}

func mustApply(t *testing.T, st *State, r *Record) ApplyResult {
	t.Helper()
	res, err := st.Apply(r)
	if err != nil {
		t.Fatalf("apply %v: %v", r.Kind, err)
	}
	return res
}

func wantErr(t *testing.T, st *State, r *Record, root error) {
	t.Helper()
	if _, err := st.Apply(r); !errors.Is(err, root) {
		t.Fatalf("apply %v: got %v, want root %v", r.Kind, err, root)
	}
	if err := st.Check(r); !errors.Is(err, root) {
		t.Fatalf("check %v: got %v, want root %v", r.Kind, err, root)
	}
}

func stateDigest(t *testing.T, st *State) [32]byte {
	t.Helper()
	d, err := st.Project().Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return d
}

// seq tracks per-slot sequences for building lock/checkout records in tests.
type seqCounter struct{ next map[uint32]uint64 }

func (c *seqCounter) take(slot uint32) uint64 {
	if c.next == nil {
		c.next = map[uint32]uint64{}
	}
	if c.next[slot] == 0 {
		c.next[slot] = 1
	}
	v := c.next[slot]
	c.next[slot]++
	return v
}

func TestSessionOpenLifecycle(t *testing.T) {
	st := NewState()
	open := openAt("m1", 1, t0)
	if res := mustApply(t, st, open); res.NoOp || res.SupersededGeneration != 0 {
		t.Fatalf("open result %+v", res)
	}
	info, ok := st.Session("m1")
	if !ok || info.Terminal || info.Ref.Generation != 1 || info.ExpiresDbMs != t0+ttl ||
		info.TimeSource != TimeSourceDB || info.IssuedDbMs != t0 {
		t.Fatalf("session view %+v", info)
	}
	if st.DbTimeFloorMs() != t0 {
		t.Fatalf("floor %d", st.DbTimeFloorMs())
	}

	// Byte-identical re-send is an idempotent no-op.
	if res := mustApply(t, st, open); !res.NoOp {
		t.Fatalf("identical re-send result %+v", res)
	}
	// Same generation, different tuple: credential conflict.
	changed := openAt("m1", 1, t0)
	changed.SessionOpen.Owner = "intruder"
	wantErr(t, st, changed, ErrFence)
	// Different times are a different tuple too.
	reminted := openAt("m1", 1, t0+5)
	wantErr(t, st, reminted, ErrFence)
	// The one-time fact identity is NOT part of the retained tuple (facts are
	// consumed at append and not projected), so a same-tuple open differing
	// only by fact id resolves as the idempotent no-op — identically before
	// and after a projection rebuild.
	refreshedFact := openAt("m1", 1, t0)
	refreshedFact.SessionOpen.Fact.FactID = fid(0xEE)
	if res := mustApply(t, st, refreshedFact); !res.NoOp {
		t.Fatalf("fact-id-only difference result %+v", res)
	}

	// Lower generation than the durable one: stale.
	mustApply(t, st, openAt("m1", 2, t0+10))
	wantErr(t, st, openAt("m1", 1, t0+20), ErrFence)
}

func TestSessionOpenSupersede(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, pinRec("m1", 1, 42, false))

	res := mustApply(t, st, openAt("m1", 2, t0+100))
	if res.SupersededGeneration != 1 {
		t.Fatalf("superseded %+v", res)
	}
	if !reflect.DeepEqual(res.NewlyUnpinnedInos, []uint64{42}) {
		t.Fatalf("released pins %+v", res.NewlyUnpinnedInos)
	}
	info, _ := st.Session("m1")
	if info.Terminal || info.Ref.Generation != 2 {
		t.Fatalf("session after supersede %+v", info)
	}
	// The superseded generation is fenced forever.
	wantErr(t, st, openAt("m1", 1, t0+200), ErrFence)
	wantErr(t, st, renewAt("m1", 1, t0+200), ErrFence)
	if got := st.CheckExact(key("m1", 1, 0, 1, 0x01)); got.Disposition != ExactSessionUnknown {
		t.Fatalf("stale generation disposition %v", got.Disposition)
	}
}

func TestSessionRenewSemantics(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))

	mustApply(t, st, renewAt("m1", 1, t0+30_000))
	info, _ := st.Session("m1")
	if info.ExpiresDbMs != t0+30_000+ttl {
		t.Fatalf("deadline %d", info.ExpiresDbMs)
	}
	if st.DbTimeFloorMs() != t0+30_000 {
		t.Fatalf("floor %d", st.DbTimeFloorMs())
	}

	// Wrong token: fence.
	bad := renewAt("m1", 1, t0+31_000)
	bad.SessionRenew.TokenHash = hash32(0xEE)
	wantErr(t, st, bad, ErrFence)
	// Unknown generation: fence.
	wantErr(t, st, renewAt("m1", 9, t0+31_000), ErrFence)

	// Backward minted time (old-authority straggler / skewed wall clock).
	wantErr(t, st, renewAt("m1", 1, t0+29_999), ErrIntegrity)

	// Non-advancing deadline: stale renew replay.
	stale := renewAt("m1", 1, t0+30_000)
	stale.SessionRenew.ExpiresDbMs = t0 + 30_000 + 1 // advances minted floor? no: equal minted, tiny deadline
	wantErr(t, st, stale, ErrIntegrity)

	// A renewal minted at/past the durable deadline lost to expiry.
	late := renewAt("m1", 1, t0+30_000+ttl)
	wantErr(t, st, late, ErrFence)
}

func TestConditionalExpiryOrdering(t *testing.T) {
	// Expiry ordered first permanently fences the generation.
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, pinRec("m1", 1, 7, false))
	res := mustApply(t, st, expireAt("m1", 1, t0+ttl, t0+ttl+250))
	if res.NoOp || !reflect.DeepEqual(res.NewlyUnpinnedInos, []uint64{7}) {
		t.Fatalf("expiry result %+v", res)
	}
	info, _ := st.Session("m1")
	if !info.Terminal || info.Reason != TerminalExpire {
		t.Fatalf("session %+v", info)
	}
	if st.DbTimeFloorMs() != t0+ttl+250 {
		t.Fatalf("floor %d", st.DbTimeFloorMs())
	}
	// The fenced renewal that lost the race is corrupt at apply.
	wantErr(t, st, renewAt("m1", 1, t0+ttl+300), ErrFence)

	// Renewal ordered first invalidates the conditional expiry: no-op, but
	// the decision time still advances the floor.
	st = NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, renewAt("m1", 1, t0+60_000))
	res = mustApply(t, st, expireAt("m1", 1, t0+ttl, t0+ttl+250))
	if !res.NoOp {
		t.Fatalf("invalidated expiry result %+v", res)
	}
	if info, _ := st.Session("m1"); info.Terminal {
		t.Fatal("renewed session was expired")
	}
	if st.DbTimeFloorMs() != t0+ttl+250 {
		t.Fatalf("floor after no-op expiry %d", st.DbTimeFloorMs())
	}

	// Observing a deadline LATER than the durable one was never durable:
	// corruption (durable is t0+60000+ttl after the renewal above).
	wantErr(t, st, expireAt("m1", 1, t0+200_000, t0+200_001), ErrIntegrity)

	// A decision time before its observed deadline is structurally malformed.
	wantErr(t, st, expireAt("m1", 1, t0+60_000+ttl, t0+60_000+ttl-1), ErrMalformed)

	// A decision time behind the durable floor is corruption even when it is
	// structurally consistent: a later admission (another session's open)
	// proved the database clock was already past it, so the stale decision
	// can only be an old authority's straggler or a smuggled host clock.
	st2 := NewState()
	mustApply(t, st2, openAt("m2", 1, t0)) // m2 deadline t0+ttl
	mustApply(t, st2, openAt("m4", 1, t0+95_000))
	wantErr(t, st2, expireAt("m2", 1, t0+ttl, t0+ttl+1), ErrIntegrity)
	// The same expiry decided at a fresh database time applies.
	res = mustApply(t, st2, expireAt("m2", 1, t0+ttl, t0+95_001))
	if res.NoOp {
		t.Fatalf("fresh expiry result %+v", res)
	}
}

func TestSessionOpenFloorRejectsBackwardTimes(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	// A second mount opened by an authority whose wall clock is behind the
	// database floor: rejected, the time cannot be database-minted.
	wantErr(t, st, openAt("m2", 1, t0-1), ErrIntegrity)
	// Equal-time admissions are fine (same-millisecond commits).
	mustApply(t, st, openAt("m3", 1, t0))
}

func TestTerminalReleasesEverything(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, openAt("m2", 1, t0))
	var seq1, seq2 seqCounter

	// m1: a lock, a checkout, a flush watermark, two pins.
	mustApply(t, st, ptr(lockRec(key("m1", 1, 0, seq1.take(0), 0), 10, 1, LockSetWrite, 0, 64)))
	mustApply(t, st, ptr(checkoutRec(key("m1", 1, 1, seq1.take(1), 0), CheckoutGrant, "proj/a", "1", [32]byte{})))
	mustApply(t, st, flushRec("m1", 1, "wb", "proj/a", "1", 5))
	mustApply(t, st, pinRec("m1", 1, 100, false))
	mustApply(t, st, pinRec("m1", 1, 101, false))
	// m2 shares a pin on 101 and holds its own (non-overlapping) lock.
	mustApply(t, st, pinRec("m2", 1, 101, false))
	mustApply(t, st, ptr(lockRec(key("m2", 1, 0, seq2.take(0), 0), 10, 2, LockSetRead, 100, 50)))

	res := mustApply(t, st, closeRec("m1", 1))
	if !reflect.DeepEqual(res.NewlyUnpinnedInos, []uint64{100}) {
		t.Fatalf("released %+v (101 is still pinned by m2)", res.NewlyUnpinnedInos)
	}
	if locks := st.HeldLocks(10); len(locks) != 1 || locks[0].Owner.Session != ref("m2", 1) {
		t.Fatalf("locks after terminal %+v", locks)
	}
	if _, ok := st.CheckoutAt("proj/a"); ok {
		t.Fatal("checkout survived terminal")
	}
	if _, ok := st.FlushThrough(ref("m1", 1), "wb", "proj/a", "1"); ok {
		t.Fatal("flush ledger survived terminal")
	}
	if st.HasPin(ref("m1", 1), 101) || !st.HasPin(ref("m2", 1), 101) {
		t.Fatal("pin state wrong after terminal")
	}
	// m2's own coordination state survives untouched: its slot outcome (from
	// the lock grant), its lock interval, and its pin on 101.
	c := st.Counts()
	want := Counts{LiveSessions: 1, Tombstones: 1, SlotStates: 1, LockIntervals: 1, OpenPins: 1}
	if c != want {
		t.Fatalf("counts %+v, want %+v", c, want)
	}
	// Slot outcomes are retired; the tombstone still fences the identity.
	if got := st.CheckExact(key("m1", 1, 0, 1, 0)); got.Disposition != ExactSessionUnknown {
		t.Fatalf("disposition %v", got.Disposition)
	}
	wantErr(t, st, closeRec("m1", 1), ErrFence) // double terminal

	// Tombstone discard requires every session terminal.
	if err := st.DiscardTombstonesAtGenerationRetirement(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("discard with live sessions: %v", err)
	}
	mustApply(t, st, closeRec("m2", 1))
	if err := st.DiscardTombstonesAtGenerationRetirement(); err != nil {
		t.Fatalf("discard: %v", err)
	}
	if st.Counts().Tombstones != 0 {
		t.Fatal("tombstones not discarded")
	}
}

func ptr(r Record) *Record { return &r }

func TestExactOutcomeFloors(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	k1 := key("m1", 1, 2, 1, 0x11)
	k2 := key("m1", 1, 2, 2, 0x22)

	// A gap before any outcome.
	wantErr(t, st, outcomeRec(key("m1", 1, 2, 2, 0x22), Outcome{Status: 5}), ErrIntegrity)
	// Slot outside the granted window.
	wantErr(t, st, outcomeRec(key("m1", 1, 8, 1, 0x11), Outcome{}), ErrIntegrity)

	if got := st.CheckExact(k1); got.Disposition != ExactAdmit {
		t.Fatalf("admit disposition %v", got.Disposition)
	}
	out1 := Outcome{Status: 0, Count: 42, Ino: 9}
	mustApply(t, st, outcomeRec(k1, out1))

	// Replay: same identity, same bytes returns the exact stored outcome.
	if got := st.CheckExact(k1); got.Disposition != ExactReplay || got.Outcome != out1 {
		t.Fatalf("replay %+v", got)
	}
	// Changed bytes at the occupied identity: conflict (caller fences).
	if got := st.CheckExact(key("m1", 1, 2, 1, 0x99)); got.Disposition != ExactConflict {
		t.Fatalf("conflict disposition %v", got.Disposition)
	}
	// Duplicate at APPLY is journal corruption, identical bytes or not.
	wantErr(t, st, outcomeRec(k1, out1), ErrIntegrity)

	// Admitting seq 2 implicitly retires seq 1's details.
	mustApply(t, st, outcomeRec(k2, Outcome{Status: 17}))
	if got := st.CheckExact(k1); got.Disposition != ExactRetired {
		t.Fatalf("retired disposition %v", got.Disposition)
	}
	view, _ := st.Slot(ref("m1", 1), 2)
	if view.NextSeq != 3 || view.RetiredThrough != 1 || !view.HasLatest || view.LatestSeq != 2 {
		t.Fatalf("slot view %+v", view)
	}
	// Future gap.
	if got := st.CheckExact(key("m1", 1, 2, 9, 0x11)); got.Disposition != ExactGap {
		t.Fatalf("gap disposition %v", got.Disposition)
	}

	// Floor acknowledges the idle latest outcome.
	wantErr(t, st, floorRec("m1", 1, 2, 1), ErrIntegrity) // already retired
	wantErr(t, st, floorRec("m1", 1, 2, 3), ErrIntegrity) // never admitted
	mustApply(t, st, floorRec("m1", 1, 2, 2))
	view, _ = st.Slot(ref("m1", 1), 2)
	if view.HasLatest || view.RetiredThrough != 2 || view.NextSeq != 3 {
		t.Fatalf("floored slot view %+v", view)
	}
	if got := st.CheckExact(k2); got.Disposition != ExactRetired {
		t.Fatalf("post-floor disposition %v", got.Disposition)
	}
	// Floor with no latest: corruption.
	wantErr(t, st, floorRec("m1", 1, 2, 2), ErrIntegrity)
	// Sequence 3 still admits after the floor.
	mustApply(t, st, outcomeRec(key("m1", 1, 2, 3, 0x33), Outcome{}))
}

func TestRecordExternalOutcomeMatchesExactOutcome(t *testing.T) {
	a, b := NewState(), NewState()
	open := openAt("m1", 1, t0)
	mustApply(t, a, open)
	mustApply(t, b, open)

	k := key("m1", 1, 1, 1, 0x44)
	out := Outcome{Status: 0, Count: 7, Offset: 4096}
	mustApply(t, a, outcomeRec(k, out))
	if err := b.RecordExternalOutcome(k, out); err != nil {
		t.Fatalf("external outcome: %v", err)
	}
	if stateDigest(t, a) != stateDigest(t, b) {
		t.Fatal("PFR1-carried outcome and ExactOutcome record disagree")
	}
	// Gap and fence semantics match too.
	if err := b.RecordExternalOutcome(key("m1", 1, 1, 3, 0x55), out); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("external gap: %v", err)
	}
	if err := b.RecordExternalOutcome(key("m9", 1, 1, 1, 0x55), out); !errors.Is(err, ErrFence) {
		t.Fatalf("external unknown session: %v", err)
	}
}

func TestLockChangeSemantics(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, openAt("m2", 1, t0))
	var s1, s2 seqCounter

	// m1 takes a write lock on the whole file.
	mustApply(t, st, ptr(lockRec(key("m1", 1, 0, s1.take(0), 0), 10, 1, LockSetWrite, 0, 0)))
	// A conflicting grant record is corruption (admission records EAGAIN as
	// an ExactOutcome instead of journaling a LockChange). The failed record
	// consumes no slot sequence.
	wantErr(t, st, ptr(lockRec(key("m2", 1, 0, 1, 0), 10, 7, LockSetRead, 5, 10)), ErrIntegrity)
	// The query layer sees the conflict for F_GETLK / setlk admission.
	if h, conflict := st.LockConflict(10, LockOwner{Session: ref("m2", 1), KernelLockOwner: 7}, 5, 10, false); !conflict || !h.Write {
		t.Fatalf("conflict query %+v %v", h, conflict)
	}

	// m1 downgrades the middle, m2 can then read-lock it.
	mustApply(t, st, ptr(lockRec(key("m1", 1, 0, s1.take(0), 0), 10, 1, LockSetRead, 100, 100)))
	mustApply(t, st, ptr(lockRec(key("m2", 1, 0, s2.take(0), 0), 10, 7, LockSetRead, 150, 10)))
	// Unlock of a sub-range splits.
	mustApply(t, st, ptr(lockRec(key("m1", 1, 0, s1.take(0), 0), 10, 1, LockUnlock, 0, 50)))
	locks := st.HeldLocks(10)
	want := []HeldLock{
		{Owner: LockOwner{Session: ref("m1", 1), KernelLockOwner: 1}, Start: 50, End: 99, Write: true},
		{Owner: LockOwner{Session: ref("m1", 1), KernelLockOwner: 1}, Start: 100, End: 199, Write: false},
		{Owner: LockOwner{Session: ref("m2", 1), KernelLockOwner: 7}, Start: 150, End: 159, Write: false},
		{Owner: LockOwner{Session: ref("m1", 1), KernelLockOwner: 1}, Start: 200, End: LockRangeEOF, Write: true},
	}
	if !reflect.DeepEqual(locks, want) {
		t.Fatalf("lock table:\n got %+v\nwant %+v", locks, want)
	}

	// Unlock covering nothing still consumes the identity (definite success).
	before := st.Counts().LockIntervals
	mustApply(t, st, ptr(lockRec(key("m2", 1, 1, s2.take(1), 0), 999, 7, LockUnlock, 0, 0)))
	if st.Counts().LockIntervals != before {
		t.Fatal("no-op unlock changed lock state")
	}
	// Its identity replays.
	rl := lockRec(key("m2", 1, 1, 1, 0), 999, 7, LockUnlock, 0, 0)
	if got := st.CheckExact(rl.LockChange.Key); got.Disposition != ExactReplay {
		t.Fatalf("unlock replay disposition %v", got.Disposition)
	}
}

func TestCheckoutSemantics(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, openAt("m2", 1, t0))
	var s1, s2 seqCounter

	// Grant must carry the server-controlled next epoch.
	wantErr(t, st, ptr(checkoutRec(key("m1", 1, 0, 1, 0), CheckoutGrant, "proj/a", "5", [32]byte{})), ErrIntegrity)
	mustApply(t, st, ptr(checkoutRec(key("m1", 1, 0, s1.take(0), 0), CheckoutGrant, "proj/a", st.NextCheckoutEpoch(), [32]byte{})))
	if st.NextCheckoutEpoch() != "2" {
		t.Fatalf("next epoch %s", st.NextCheckoutEpoch())
	}
	// Overlapping grants (equal, ancestor, descendant) are corruption at
	// apply; sibling-with-common-prefix strings are NOT overlap.
	wantErr(t, st, ptr(checkoutRec(key("m2", 1, 0, 1, 0), CheckoutGrant, "proj/a", "2", [32]byte{})), ErrIntegrity)
	wantErr(t, st, ptr(checkoutRec(key("m2", 1, 0, 1, 0), CheckoutGrant, "proj/a/sub", "2", [32]byte{})), ErrIntegrity)
	wantErr(t, st, ptr(checkoutRec(key("m2", 1, 0, 1, 0), CheckoutGrant, "proj", "2", [32]byte{})), ErrIntegrity)
	mustApply(t, st, ptr(checkoutRec(key("m2", 1, 0, s2.take(0), 0), CheckoutGrant, "proj/a.tmp", "2", [32]byte{})))

	// Release must name the exact epoch and holder.
	wantErr(t, st, ptr(checkoutRec(key("m2", 1, 0, s2.next[0], 0), CheckoutRelease, "proj/a", "1", [32]byte{})), ErrFence)
	wantErr(t, st, ptr(checkoutRec(key("m1", 1, 0, s1.next[0], 0), CheckoutRelease, "proj/a", "9", [32]byte{})), ErrFence)
	mustApply(t, st, flushRec("m1", 1, "wb", "proj/a", "1", 10))
	mustApply(t, st, ptr(checkoutRec(key("m1", 1, 0, s1.take(0), 0), CheckoutRelease, "proj/a", "1", [32]byte{})))
	if _, ok := st.CheckoutAt("proj/a"); ok {
		t.Fatal("checkout survived release")
	}
	if _, ok := st.FlushThrough(ref("m1", 1), "wb", "proj/a", "1"); ok {
		t.Fatal("release did not invalidate the flush ledger")
	}
}

func TestCheckoutForceTransfer(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("holderA", 1, t0))
	mustApply(t, st, openAt("holderC", 1, t0))
	mustApply(t, st, openAt("contender", 1, t0))
	var sa, sc, sx seqCounter

	mustApply(t, st, ptr(checkoutRec(key("holderA", 1, 0, sa.take(0), 0), CheckoutGrant, "proj/x", "1", [32]byte{})))
	mustApply(t, st, flushRec("holderA", 1, "wb", "proj/x", "1", 3))

	// The recall captured holder A's grant.
	recall := st.RecallDigestAt("proj/x/deep")

	// Before the transfer lands, A releases and C grabs a fresh grant.
	mustApply(t, st, ptr(checkoutRec(key("holderA", 1, 0, sa.take(0), 0), CheckoutRelease, "proj/x", "1", [32]byte{})))
	mustApply(t, st, ptr(checkoutRec(key("holderC", 1, 0, sc.take(0), 0), CheckoutGrant, "proj/x", "2", [32]byte{})))

	// The stale transfer (recall digest of {A}) cannot revoke fresh holder C.
	// The rejected record consumes no slot sequence.
	stale := checkoutRec(key("contender", 1, 0, 1, 0), CheckoutForceTransfer, "proj/x/deep", st.NextCheckoutEpoch(), recall)
	wantErr(t, st, &stale, ErrIntegrity)

	// A fresh recall against the CURRENT conflict set transfers atomically.
	fresh := st.RecallDigestAt("proj/x/deep")
	res := mustApply(t, st, ptr(checkoutRec(key("contender", 1, 0, sx.take(0), 0), CheckoutForceTransfer, "proj/x/deep", st.NextCheckoutEpoch(), fresh)))
	if res.NoOp {
		t.Fatalf("transfer result %+v", res)
	}
	if _, ok := st.CheckoutAt("proj/x"); ok {
		t.Fatal("conflicting grant survived force transfer")
	}
	got, ok := st.CheckoutAt("proj/x/deep")
	if !ok || got.Holder != ref("contender", 1) || got.Epoch != "3" {
		t.Fatalf("transferred grant %+v", got)
	}
	// Transfer with no conflicts must be an ordinary grant instead.
	empty := st.RecallDigestAt("elsewhere")
	wantErr(t, st, ptr(checkoutRec(key("contender", 1, 1, 1, 0), CheckoutForceTransfer, "elsewhere", st.NextCheckoutEpoch(), empty)), ErrIntegrity)
}

func TestFlushAdvanceSemantics(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, openAt("m2", 1, t0))
	var s1 seqCounter
	mustApply(t, st, ptr(checkoutRec(key("m1", 1, 0, s1.take(0), 0), CheckoutGrant, "proj/a", "1", [32]byte{})))

	// Flush against a path with no matching grant/epoch/holder: stale.
	wantErr(t, st, flushRec("m1", 1, "wb", "proj/a", "9", 5), ErrFence)
	wantErr(t, st, flushRec("m2", 1, "wb", "proj/a", "1", 5), ErrFence)
	wantErr(t, st, flushRec("m1", 1, "wb", "proj/b", "1", 5), ErrFence)

	mustApply(t, st, flushRec("m1", 1, "wb", "proj/a", "1", 5))
	// Strictly monotonic per identity.
	wantErr(t, st, flushRec("m1", 1, "wb", "proj/a", "1", 5), ErrIntegrity)
	wantErr(t, st, flushRec("m1", 1, "wb", "proj/a", "1", 4), ErrIntegrity)
	mustApply(t, st, flushRec("m1", 1, "wb", "proj/a", "1", 6))
	// Independent write-back domains.
	mustApply(t, st, flushRec("m1", 1, "wb2", "proj/a", "1", 1))

	// Release, re-grant under a NEW epoch to the same session: the old
	// epoch's delayed flush is stale forever.
	mustApply(t, st, ptr(checkoutRec(key("m1", 1, 0, s1.take(0), 0), CheckoutRelease, "proj/a", "1", [32]byte{})))
	mustApply(t, st, ptr(checkoutRec(key("m1", 1, 0, s1.take(0), 0), CheckoutGrant, "proj/a", "2", [32]byte{})))
	wantErr(t, st, flushRec("m1", 1, "wb", "proj/a", "1", 7), ErrFence)
	// The new epoch's ledger starts fresh.
	mustApply(t, st, flushRec("m1", 1, "wb", "proj/a", "2", 1))
}

func TestOpenPinSemantics(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, openAt("m2", 1, t0))

	mustApply(t, st, pinRec("m1", 1, 42, false))
	wantErr(t, st, pinRec("m1", 1, 42, false), ErrIntegrity) // double pin
	mustApply(t, st, pinRec("m2", 1, 42, false))

	res := mustApply(t, st, pinRec("m1", 1, 42, true))
	if len(res.NewlyUnpinnedInos) != 0 {
		t.Fatalf("m2 still pins 42: %+v", res)
	}
	res = mustApply(t, st, pinRec("m2", 1, 42, true))
	if !reflect.DeepEqual(res.NewlyUnpinnedInos, []uint64{42}) {
		t.Fatalf("last unpin %+v", res)
	}
	wantErr(t, st, pinRec("m2", 1, 42, true), ErrIntegrity) // unpin without pin
	if holders := st.PinHolders(42); len(holders) != 0 {
		t.Fatalf("holders %+v", holders)
	}
}

func TestBatchAtomicRollback(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, pinRec("m1", 1, 7, false))
	before := stateDigest(t, st)

	// A batch that fails midway must leave no trace: the terminal releases
	// coordination state, then a corrupt record aborts everything.
	_, err := st.ApplyBatch([]*Record{
		closeRec("m1", 1),
		openAt("m2", 1, t0+1),
		pinRec("m2", 1, 8, false),
		pinRec("m2", 1, 8, false), // duplicate pin: fails
	})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("batch error %v", err)
	}
	if got := stateDigest(t, st); got != before {
		t.Fatal("failed batch left residue")
	}
	if info, ok := st.Session("m1"); !ok || info.Terminal {
		t.Fatal("rollback did not restore the live session")
	}
	if !st.HasPin(ref("m1", 1), 7) {
		t.Fatal("rollback did not restore the pin")
	}

	// The same batch without the corrupt tail commits atomically.
	results, err := st.ApplyBatch([]*Record{
		closeRec("m1", 1),
		openAt("m2", 1, t0+1),
		pinRec("m2", 1, 8, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(results[0].NewlyUnpinnedInos, []uint64{7}) {
		t.Fatalf("terminal in batch %+v", results[0])
	}
	if _, err := st.ApplyBatch(nil); !errors.Is(err, ErrMalformed) {
		t.Fatal("empty batch accepted")
	}
}

func TestTxnComposesPFR1FlushBatch(t *testing.T) {
	// The write-back pattern: user PFR1 records (external outcomes) plus the
	// FlushAdvance in ONE atomic transaction.
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	var s1 seqCounter
	mustApply(t, st, ptr(checkoutRec(key("m1", 1, 0, s1.take(0), 0), CheckoutGrant, "proj/a", "1", [32]byte{})))
	before := stateDigest(t, st)

	tx := st.Begin()
	if err := tx.RecordExternalOutcome(key("m1", 1, 3, 1, 0x61), Outcome{Count: 128}); err != nil {
		t.Fatal(err)
	}
	if err := tx.RecordExternalOutcome(key("m1", 1, 3, 2, 0x62), Outcome{Count: 64}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Apply(flushRec("m1", 1, "wb", "proj/a", "1", 2)); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	if got := stateDigest(t, st); got != before {
		t.Fatal("rolled-back txn left residue")
	}

	tx = st.Begin()
	for i, h := range []byte{0x61, 0x62} {
		if err := tx.RecordExternalOutcome(key("m1", 1, 3, uint64(i+1), h), Outcome{Count: int32(128 >> i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Apply(flushRec("m1", 1, "wb", "proj/a", "1", 2)); err != nil {
		t.Fatal(err)
	}
	tx.Commit()
	if through, ok := st.FlushThrough(ref("m1", 1), "wb", "proj/a", "1"); !ok || through != 2 {
		t.Fatalf("flush through %d %v", through, ok)
	}
	if got := st.CheckExact(key("m1", 1, 3, 2, 0x62)); got.Disposition != ExactReplay || got.Outcome.Count != 64 {
		t.Fatalf("replayed PFR1 outcome %+v", got)
	}
}

func TestCheckIsPureAndMatchesApply(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	before := stateDigest(t, st)

	good := pinRec("m1", 1, 5, false)
	if err := st.Check(good); err != nil {
		t.Fatalf("check: %v", err)
	}
	if got := stateDigest(t, st); got != before {
		t.Fatal("check mutated state")
	}
	// Check inside a transaction sees staged state.
	tx := st.Begin()
	if _, err := tx.Apply(good); err != nil {
		t.Fatal(err)
	}
	if err := tx.Check(pinRec("m1", 1, 5, false)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("staged duplicate pin: %v", err)
	}
	tx.Rollback()
}
