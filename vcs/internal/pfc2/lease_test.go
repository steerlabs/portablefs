package pfc2

import (
	"errors"
	"testing"
	"time"
)

func dbNow(ms int64) TimeFact { return fact(ms) }

func TestLeaseRecordBuilders(t *testing.T) {
	open, err := NewSessionOpenRecord(ref("m1", 1), "owner", hash32(1), 64, dbNow(t0), 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if o := open.SessionOpen; o.Fact.Source != TimeSourceDB || o.Fact.DbMs != t0 || o.ExpiresDbMs != t0+90_000 {
		t.Fatalf("open %+v", o)
	}
	renew, err := NewSessionRenewRecord(ref("m1", 1), hash32(1), dbNow(t0+30_000), 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r := renew.SessionRenew; r.Fact.DbMs != t0+30_000 || r.ExpiresDbMs != t0+120_000 {
		t.Fatalf("renew %+v", r)
	}
	expiry, err := NewSessionExpiryRecord(ref("m1", 1), t0+120_000, dbNow(t0+120_000))
	if err != nil {
		t.Fatal(err)
	}
	if e := expiry.SessionTerminal; e.Reason != TerminalExpire || e.ObservedDeadlineDbMs != t0+120_000 || e.DecisionFact.DbMs != t0+120_000 {
		t.Fatalf("expiry %+v", e)
	}

	// FactIDs surfaces exactly the frozen identities for append validation.
	if ids := open.FactIDs(); len(ids) != 1 || ids[0] != open.SessionOpen.Fact {
		t.Fatalf("open fact ids %+v", ids)
	}
	if ids := expiry.FactIDs(); len(ids) != 1 || ids[0] != expiry.SessionTerminal.DecisionFact {
		t.Fatalf("expiry fact ids %+v", ids)
	}
	if ids := closeRec("m1", 1).FactIDs(); len(ids) != 0 {
		t.Fatalf("close fact ids %+v", ids)
	}

	// End-to-end: builder-produced records drive the reducer.
	st := NewState()
	mustApply(t, st, open)
	mustApply(t, st, renew)
	res := mustApply(t, st, expiry)
	if res.NoOp {
		t.Fatalf("expiry no-op %+v", res)
	}
}

func TestLeaseBuilderRejections(t *testing.T) {
	// A "fact" claiming a non-database source is refused outright: host wall
	// clocks are not a source.
	hostClock := TimeFact{Source: 0, FactID: fid(1), DbMs: t0}
	if _, err := NewSessionOpenRecord(ref("m1", 1), "", hash32(1), 1, hostClock, time.Minute); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unsourced open: %v", err)
	}
	if _, err := NewSessionRenewRecord(ref("m1", 1), hash32(1), TimeFact{Source: 7, FactID: fid(1), DbMs: t0}, time.Minute); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unknown-source renew: %v", err)
	}
	// Implausible/overflowing/missing times.
	for _, bad := range []int64{0, -1, MaxDbTimeMs + 1} {
		if _, err := NewSessionOpenRecord(ref("m1", 1), "", hash32(1), 1, dbNow(bad), time.Minute); !errors.Is(err, ErrMalformed) {
			t.Fatalf("implausible mint %d: %v", bad, err)
		}
	}
	// TTL bounds.
	for _, ttl := range []time.Duration{0, -time.Second, 25 * time.Hour, 500 * time.Microsecond} {
		if _, err := NewSessionRenewRecord(ref("m1", 1), hash32(1), dbNow(t0), ttl); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ttl %v: %v", ttl, err)
		}
	}
	// A deadline that would leave the plausible domain.
	if _, err := NewSessionOpenRecord(ref("m1", 1), "", hash32(1), 1, dbNow(MaxDbTimeMs), time.Minute); !errors.Is(err, ErrMalformed) {
		t.Fatalf("deadline past domain: %v", err)
	}
	// An early local timer cannot mint an expiry: database time re-check
	// refuses a decision before the deadline.
	if _, err := NewSessionExpiryRecord(ref("m1", 1), t0+120_000, dbNow(t0+119_999)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("early expiry: %v", err)
	}
}

func TestRemainingLeaseProjection(t *testing.T) {
	// Remaining duration is measured purely in database time.
	d, err := RemainingLease(dbNow(t0), t0+90_000)
	if err != nil || d != 90*time.Second {
		t.Fatalf("remaining %v %v", d, err)
	}
	// An elapsed deadline clamps to zero (re-check immediately).
	if d, err = RemainingLease(dbNow(t0+90_000), t0+90_000); err != nil || d != 0 {
		t.Fatalf("elapsed remaining %v %v", d, err)
	}
	if _, err = RemainingLease(TimeFact{Source: 0, FactID: fid(1), DbMs: t0}, t0+1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unsourced now: %v", err)
	}
	if _, err = RemainingLease(dbNow(t0), -1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("implausible deadline: %v", err)
	}
	due, err := ExpiryDue(dbNow(t0+90_000), t0+90_000)
	if err != nil || !due {
		t.Fatalf("due %v %v", due, err)
	}
	due, err = ExpiryDue(dbNow(t0+89_999), t0+90_000)
	if err != nil || due {
		t.Fatalf("not yet due %v %v", due, err)
	}
}

// TestWallClockSkewVectors drives the old-authority/new-authority scenarios:
// host clocks disagree wildly with database time and with each other, and
// none of it may move durable lease state.
func TestWallClockSkewVectors(t *testing.T) {
	// Old authority ran with db time around t0. Its projection is adopted by
	// a NEW authority whose host wall clock is 2 hours BEHIND the database.
	// All its admissions still mint database time, so nothing regresses.
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	mustApply(t, st, renewAt("m1", 1, t0+60_000))
	p := st.Project()
	recovered, err := Rebuild(p)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.DbTimeFloorMs() != t0+60_000 {
		t.Fatalf("recovered floor %d", recovered.DbTimeFloorMs())
	}

	// Vector 1: the new authority's SKEWED HOST CLOCK is smuggled into a
	// renewal (host time = t0 - 2h). The floor rejects it: database time
	// cannot run backward.
	skewedHostMs := t0 - 2*time.Hour.Milliseconds()
	skewed := renewAt("m1", 1, skewedHostMs)
	if _, err := recovered.Apply(skewed); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("skewed host renewal: %v", err)
	}

	// Vector 2: an OLD authority's straggler expiry whose database re-check
	// happened before the recovered floor (it lost its lease long ago and
	// observed an ancient deadline) cannot fence anything: its decision time
	// is behind durable database history.
	if _, err := recovered.Apply(expireAt("m1", 1, t0+50_000, t0+59_999)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("straggler expiry: %v", err)
	}

	// Vector 3: correctly minted database times continue seamlessly on the
	// new authority even though its host clock is useless.
	mustApply(t, recovered, renewAt("m1", 1, t0+61_000))

	// Vector 4: a FAST host clock cannot expire a live lease early: expiry
	// carries database decision time, and building the record from a fresh
	// database fact below the deadline already refuses (see
	// TestLeaseBuilderRejections); a fabricated record decided "early" is
	// structurally malformed, and one decided at/past the deadline is the
	// legitimate expiry, not skew.
	fabricated := expireAt("m1", 1, t0+61_000+ttl, t0+61_000+ttl-30_000)
	if _, err := recovered.Apply(fabricated); !errors.Is(err, ErrMalformed) {
		t.Fatalf("fabricated early expiry: %v", err)
	}

	// Vector 5: the renewal-vs-expiry race across the restart boundary. The
	// sweeper observed the OLD deadline before the renewal above; its expiry
	// admission re-checks database time and the durable deadline no longer
	// matches: deterministic no-op, session stays live.
	res := mustApply(t, recovered, expireAt("m1", 1, t0+60_000+ttl, t0+61_000+ttl+5))
	if !res.NoOp {
		t.Fatalf("raced expiry fenced a renewed session: %+v", res)
	}
	if info, _ := recovered.Session("m1"); info.Terminal {
		t.Fatal("session lost to a stale expiry after recovery")
	}

	// Vector 6: after the true deadline passes in DATABASE time, expiry
	// fences regardless of any host clock.
	deadline := t0 + 61_000 + ttl
	res = mustApply(t, recovered, expireAt("m1", 1, deadline, deadline+40_000))
	if res.NoOp {
		t.Fatal("due expiry did not fence")
	}
}

// TestProjectionRejectsSkewedLeaseFacts covers corruption of the recovered
// control root: lease facts inconsistent with the recorded floor fail closed.
func TestProjectionRejectsSkewedLeaseFacts(t *testing.T) {
	st := NewState()
	mustApply(t, st, openAt("m1", 1, t0))
	base := st.Project()

	// Session issued after the floor: impossible (the open fed the floor).
	p := cloneProjection(t, base)
	sessionEntryOf(t, p, "m1").IssuedDbMs = t0 + 1
	p.DbTimeFloorMs = t0
	if _, err := Rebuild(p); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("issued-after-floor: %v", err)
	}

	// Deadline beyond anything mintable at the floor: implausible.
	p = cloneProjection(t, base)
	sessionEntryOf(t, p, "m1").ExpiresDbMs = t0 + MaxSessionLeaseMs + 1
	if _, err := Rebuild(p); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("deadline-beyond-floor: %v", err)
	}

	// Implausible floor itself.
	p = cloneProjection(t, base)
	p.DbTimeFloorMs = MaxDbTimeMs + 1
	if _, err := Rebuild(p); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("implausible floor: %v", err)
	}

	// Unknown time source in a session entry.
	p = cloneProjection(t, base)
	sessionEntryOf(t, p, "m1").TimeSource = 9
	if _, err := Rebuild(p); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unknown source: %v", err)
	}
}
