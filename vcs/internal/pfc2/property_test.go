package pfc2

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"testing"
)

// driver generates random VALID record sequences by steering candidates with
// state queries and using State.Check as the admission oracle, exactly like a
// live authority: only records that pass the dry-run are journaled.
type driver struct {
	rng   *rand.Rand
	st    *State
	dbNow int64
	nextG map[string]uint64 // next generation per session id
	log   [][]byte          // canonical encoded journal
}

func newDriver(seed int64) *driver {
	return &driver{
		rng: rand.New(rand.NewSource(seed)), st: NewState(),
		dbNow: t0, nextG: map[string]uint64{},
	}
}

func (d *driver) mint() int64 {
	d.dbNow += d.rng.Int63n(2_000) // db time never regresses; may stall
	return d.dbNow
}

func (d *driver) liveSessions() []SessionInfo {
	var out []SessionInfo
	for id := range d.st.sessions {
		if info, ok := d.st.Session(id); ok && !info.Terminal {
			out = append(out, info)
		}
	}
	// Deterministic order for the rng-driven pick.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Ref.SessionID > out[j].Ref.SessionID; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func (d *driver) pickLive() (SessionInfo, bool) {
	live := d.liveSessions()
	if len(live) == 0 {
		return SessionInfo{}, false
	}
	return live[d.rng.Intn(len(live))], true
}

// nextKey builds the next admissible exact key for a random slot.
func (d *driver) nextKey(info SessionInfo, slot uint32) (ExactKey, bool) {
	view, ok := d.st.Slot(info.Ref, slot)
	if !ok {
		return ExactKey{}, false
	}
	return ExactKey{Session: info.Ref, Slot: slot, SlotSeq: view.NextSeq, RequestHash: randHash(d.rng)}, true
}

// candidate builds one random record against current state. It may still be
// invalid (the oracle filters).
func (d *driver) candidate() *Record {
	switch d.rng.Intn(20) {
	case 0, 1: // open a new session (or re-send / supersede)
		id := fmt.Sprintf("pfs-%d", d.rng.Intn(6))
		gen := d.nextG[id] + 1
		issued := d.mint()
		return &Record{Kind: KindSessionOpen, SessionOpen: &SessionOpen{
			Session: ref(id, gen), Owner: "o-" + id, TokenHash: hash32(byte(gen)),
			Slots: 4, Fact: randFact(d.rng, issued), ExpiresDbMs: issued + ttl,
		}}
	case 2: // renew
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		minted := d.mint()
		return &Record{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
			Session: info.Ref, TokenHash: hash32(byte(info.Ref.Generation)),
			Fact: randFact(d.rng, minted), ExpiresDbMs: minted + ttl,
		}}
	case 3: // close or admin fence
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		reason := TerminalClose
		if d.rng.Intn(2) == 0 {
			reason = TerminalAdminFence
		}
		return &Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{Session: info.Ref, Reason: reason}}
	case 4: // conditional expiry (sometimes against a stale observed deadline)
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		observed := info.ExpiresDbMs
		if d.rng.Intn(3) == 0 {
			observed -= int64(d.rng.Intn(int(ttl))) // stale observation: must not fence
		}
		decided := observed + int64(d.rng.Intn(5_000))
		if decided < d.dbNow {
			decided = d.dbNow
		}
		d.dbNow = decided
		return expireAt(info.Ref.SessionID, info.Ref.Generation, observed, decided)
	case 5, 6, 7, 8: // exact outcome
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		k, ok := d.nextKey(info, uint32(d.rng.Intn(int(info.Slots))))
		if !ok {
			return nil
		}
		return outcomeRec(k, randOutcome(d.rng))
	case 9: // outcome floor
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		slot := uint32(d.rng.Intn(int(info.Slots)))
		view, ok := d.st.Slot(info.Ref, slot)
		if !ok || !view.HasLatest {
			return nil
		}
		return floorRec(info.Ref.SessionID, info.Ref.Generation, slot, view.LatestSeq)
	case 10, 11, 12: // lock change
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		k, ok := d.nextKey(info, 0)
		if !ok {
			return nil
		}
		ino := uint64(1 + d.rng.Intn(4))
		op := LockOp(1 + d.rng.Intn(3))
		start := uint64(d.rng.Intn(300))
		length := uint64(d.rng.Intn(100))
		owner := LockOwner{Session: info.Ref, KernelLockOwner: uint64(d.rng.Intn(2))}
		if op != LockUnlock {
			if _, conflict := d.st.LockConflict(ino, owner, start, length, op == LockSetWrite); conflict {
				return nil // admission would answer EAGAIN without journaling a LockChange
			}
		}
		r := lockRec(k, ino, owner.KernelLockOwner, op, start, length)
		return &r
	case 13, 14: // checkout grant (plain or delegation)
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		k, ok := d.nextKey(info, 1)
		if !ok {
			return nil
		}
		path := fmt.Sprintf("dir%d/leaf%d", d.rng.Intn(3), d.rng.Intn(4))
		if len(d.st.OverlappingCheckouts(path)) != 0 {
			return nil // EBUSY at admission
		}
		if d.rng.Intn(2) == 0 {
			r := delegationRec(k, path, d.st.NextCheckoutEpoch(), "wb"+info.Ref.SessionID)
			return &r
		}
		r := checkoutRec(k, CheckoutGrant, path, d.st.NextCheckoutEpoch(), [32]byte{})
		return &r
	case 15: // checkout release, force transfer, rebind, or discard
		path := fmt.Sprintf("dir%d/leaf%d", d.rng.Intn(3), d.rng.Intn(4))
		if g, held := d.st.CheckoutAt(path); held && g.Recovery {
			// A recovery scope resolves by rebind (to a live session) or by
			// the audited discard; both ride keyless records.
			if info, ok := d.pickLive(); ok && d.rng.Intn(2) == 0 {
				return rebindRec(path, g.Epoch, g.WritebackID, info.Ref)
			}
			return discardRec(path, g.Epoch, g.WritebackID)
		}
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		k, ok := d.nextKey(info, 1)
		if !ok {
			return nil
		}
		if g, held := d.st.CheckoutAt(path); held && g.Holder == info.Ref && d.rng.Intn(2) == 0 {
			r := checkoutRec(k, CheckoutRelease, path, g.Epoch, [32]byte{})
			return &r
		}
		conflicts := d.st.OverlappingCheckouts(path)
		if len(conflicts) == 0 {
			return nil
		}
		for _, c := range conflicts {
			if c.WritebackID != "" {
				return nil // delegations are never force-transferred
			}
		}
		r := checkoutRec(k, CheckoutForceTransfer, path, d.st.NextCheckoutEpoch(), RecallDigest(conflicts))
		return &r
	case 16, 17: // pin
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		ino := uint64(1 + d.rng.Intn(6))
		return pinRec(info.Ref.SessionID, info.Ref.Generation, ino, d.st.HasPin(info.Ref, ino))
	default: // flush advance under a held delegation
		info, ok := d.pickLive()
		if !ok {
			return nil
		}
		var grant CheckoutView
		found := false
		for _, path := range []string{"dir0/leaf0", "dir0/leaf1", "dir1/leaf0", "dir1/leaf1", "dir2/leaf2"} {
			if g, held := d.st.CheckoutAt(path); held && g.Holder == info.Ref && g.WritebackID != "" && !g.Recovery {
				grant, found = g, true
				break
			}
		}
		if !found {
			return nil
		}
		through := uint64(0)
		if view, ok := d.st.StreamState(grant.WritebackID); ok {
			through = view.Through
		}
		return flushRec(info.Ref.SessionID, info.Ref.Generation, grant.WritebackID, grant.Path, grant.Epoch, through+1+uint64(d.rng.Intn(8)))
	}
}

// step generates, admits, journals, and applies one record; returns false if
// no valid candidate emerged this round.
func (d *driver) step(t *testing.T) bool {
	t.Helper()
	r := d.candidate()
	if r == nil {
		return false
	}
	if err := d.st.Check(r); err != nil {
		// The oracle rejected the candidate: admission would not journal it.
		// Apply must agree exactly.
		if _, aerr := d.st.Apply(r); aerr == nil || aerr.Error() != err.Error() {
			t.Fatalf("check/apply divergence for %v: check=%v apply=%v", r.Kind, err, aerr)
		}
		return false
	}
	enc, err := Encode(r)
	if err != nil {
		t.Fatalf("encode admitted record: %v", err)
	}
	res, err := d.st.Apply(r)
	if err != nil {
		t.Fatalf("apply admitted %v: %v", r.Kind, err)
	}
	if r.Kind == KindSessionOpen && !res.NoOp {
		d.nextG[r.SessionOpen.Session.SessionID] = r.SessionOpen.Session.Generation
	}
	d.log = append(d.log, enc)
	return true
}

func TestReplayEquivalenceProperty(t *testing.T) {
	for seed := int64(1); seed <= 6; seed++ {
		d := newDriver(seed)
		for i := 0; i < 1500; i++ {
			d.step(t)
		}
		want := stateDigest(t, d.st)

		// Cold replay of the exact journal bytes.
		replayed := NewState()
		for i, enc := range d.log {
			rec, err := Decode(enc)
			if err != nil {
				t.Fatalf("seed %d: decode journal record %d: %v", seed, i, err)
			}
			if _, err := replayed.Apply(&rec); err != nil {
				t.Fatalf("seed %d: replay record %d (%v): %v", seed, i, rec.Kind, err)
			}
			re, err := Encode(&rec)
			if err != nil || !bytes.Equal(re, enc) {
				t.Fatalf("seed %d: journal record %d is not re-encode exact", seed, i)
			}
		}
		if got := stateDigest(t, replayed); got != want {
			t.Fatalf("seed %d: replay diverged", seed)
		}

		// Restart-at-cut equivalence: project/rebuild at every prefix cut,
		// then replay the suffix into the recovered state.
		for _, cut := range []int{0, len(d.log) / 3, 2 * len(d.log) / 3, len(d.log)} {
			prefix := NewState()
			for i := 0; i < cut; i++ {
				rec, _ := Decode(d.log[i])
				if _, err := prefix.Apply(&rec); err != nil {
					t.Fatalf("seed %d: prefix apply %d: %v", seed, i, err)
				}
			}
			recovered, err := Rebuild(prefix.Project())
			if err != nil {
				t.Fatalf("seed %d cut %d: rebuild: %v", seed, cut, err)
			}
			for i := cut; i < len(d.log); i++ {
				rec, _ := Decode(d.log[i])
				if _, err := recovered.Apply(&rec); err != nil {
					t.Fatalf("seed %d cut %d: suffix apply %d (%v): %v", seed, cut, i, rec.Kind, err)
				}
			}
			if got := stateDigest(t, recovered); got != want {
				t.Fatalf("seed %d: cut-at-%d recovery diverged", seed, cut)
			}
		}
	}
}

func TestRollbackEqualityProperty(t *testing.T) {
	d := newDriver(42)
	for i := 0; i < 300; i++ {
		d.step(t)
	}
	rng := rand.New(rand.NewSource(7))
	for round := 0; round < 200; round++ {
		before := stateDigest(t, d.st)
		beforeCounts := d.st.Counts()
		// Candidates are generated BEFORE Begin: the driver steers them with
		// state queries, which must not run under the transaction's lock.
		var candidates []*Record
		for i := 0; i < 1+rng.Intn(6); i++ {
			if r := d.candidate(); r != nil {
				candidates = append(candidates, r)
			}
		}
		tx := d.st.Begin()
		staged := 0
		for _, r := range candidates {
			if err := tx.Check(r); err != nil {
				continue // earlier staged records invalidated this candidate
			}
			if _, err := tx.Apply(r); err != nil {
				t.Fatalf("round %d: staged apply after clean check: %v", round, err)
			}
			staged++
		}
		tx.Rollback()
		if got := stateDigest(t, d.st); got != before {
			t.Fatalf("round %d: rollback of %d staged records left residue", round, staged)
		}
		if d.st.Counts() != beforeCounts {
			t.Fatalf("round %d: rollback count drift", round)
		}
		// Keep the model moving between rounds.
		d.step(t)
	}
}

func TestDispositionStability(t *testing.T) {
	// Once an identity has a durable outcome, its classification is stable
	// across restart: Replay stays Replay with the identical outcome bytes;
	// Retired stays Retired; fenced generations stay fenced.
	d := newDriver(99)
	for i := 0; i < 800; i++ {
		d.step(t)
	}
	type probe struct {
		key  ExactKey
		want ExactCheck
	}
	var probes []probe
	for id := range d.st.sessions {
		info, _ := d.st.Session(id)
		if info.Terminal {
			// The tombstoned identity itself stays fenced after recovery.
			probes = append(probes, probe{key(id, info.Ref.Generation, 0, 1, 0x1), ExactCheck{Disposition: ExactSessionUnknown}})
			continue
		}
		for slot := uint32(0); slot < info.Slots; slot++ {
			view, _ := d.st.Slot(info.Ref, slot)
			if view.HasLatest {
				k := ExactKey{Session: info.Ref, Slot: slot, SlotSeq: view.LatestSeq, RequestHash: view.LatestHash}
				probes = append(probes, probe{k, d.st.CheckExact(k)})
			}
			if view.RetiredThrough > 0 {
				k := ExactKey{Session: info.Ref, Slot: slot, SlotSeq: view.RetiredThrough, RequestHash: hash32(0x77)}
				probes = append(probes, probe{k, ExactCheck{Disposition: ExactRetired}})
			}
		}
	}
	recovered, err := Rebuild(d.st.Project())
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range probes {
		if got := recovered.CheckExact(p.key); got != p.want {
			t.Fatalf("probe %d (%v): %+v != %+v", i, p.key, got, p.want)
		}
	}
}

func TestApplyErrorsAreTyped(t *testing.T) {
	// Every reducer rejection must carry exactly one typed root.
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	roots := []error{ErrMalformed, ErrCapacity, ErrIntegrity, ErrFence}
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 3000; i++ {
		rec := randRecord(rng)
		if _, err := st.Apply(&rec); err != nil {
			n := 0
			for _, root := range roots {
				if errors.Is(err, root) {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("error %v matches %d typed roots", err, n)
			}
		}
	}
}
