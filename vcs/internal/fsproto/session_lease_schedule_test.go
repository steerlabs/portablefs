package fsproto

// ── ROUND 17b: THE RESERVED LEASE TRANSPORT STILL HAD AN EXPIRY-SIZED HOLE ───
//
// Round 16 gave the renewal a transport of its own, and that part is sound. The
// SCHEDULE around it was not. For a 90s lease the loop woke every 30s, slept a
// full 30s BEFORE each attempt and another full 30s after a failed one, and the
// bound it advertised covered only the round trip — leaseConn's dial and auth
// happened outside it. The audit's worked example, reproduced by the first test
// below:
//
//	t=30   first attempt starts (one interval after establish)
//	t=45   ~15s spent dialing and authenticating (NOT inside the 30s bound)
//	t=75   30s round trip hits the bound and fails
//	t=105  the loop's next attempt — 15 seconds after the lease died at t=90
//
// Nothing renewed the lease and nothing tried again inside its lifetime. The
// authority swept the session terminal exactly on schedule, which is correct
// behaviour by the authority and a total failure by the client.
//
// These tests are deterministic: time is a virtual clock and the attempt
// latencies are injected. Nothing here races the wall clock.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// virtualLeaseClock is a single-goroutine virtual clock. The renewal loop is
// the only consumer, so "sleeping" is just advancing the clock and handing back
// an already-fired channel: the loop makes progress in zero real time and its
// schedule is fully determined.
type virtualLeaseClock struct {
	mu   sync.Mutex
	nowT time.Time
}

func newVirtualLeaseClock(start time.Time) *virtualLeaseClock {
	return &virtualLeaseClock{nowT: start}
}

func (v *virtualLeaseClock) now() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.nowT
}

func (v *virtualLeaseClock) advance(d time.Duration) {
	if d <= 0 {
		return
	}
	v.mu.Lock()
	v.nowT = v.nowT.Add(d)
	v.mu.Unlock()
}

func (v *virtualLeaseClock) after(d time.Duration) <-chan time.Time {
	v.advance(d)
	ch := make(chan time.Time, 1)
	ch <- v.now()
	return ch
}

func (v *virtualLeaseClock) clock() leaseClock {
	return leaseClock{now: v.now, after: v.after}
}

// leaseAttemptRecord is one attempt as the loop actually ran it.
type leaseAttemptRecord struct {
	start  time.Duration // relative to session establish
	end    time.Duration
	budget time.Duration
}

// leaseAttemptSim injects the audit's latencies into the loop's attempt hook.
//
// The model is deliberately CHARITABLE to the pre-fix code: it charges dial +
// auth + round trip against the one budget the loop advertises, which is what
// the fix guarantees and what the pre-fix code did NOT do (leaseConn dialed and
// authenticated before boundedRoundtrip and outside its bound). Even granted
// that, the pre-fix cadence alone loses the lease — so the schedule is the
// defect independently of the bound. That the real attempt bounds dial and auth
// too is proved separately, against a real transport, by
// TestLeaseRenewalAttemptBoundsDialAndAuthTogether.
type leaseAttemptSim struct {
	clk       *virtualLeaseClock
	start     time.Time
	dial      time.Duration
	roundtrip time.Duration
	// stopAfter ends the simulation: once the virtual clock passes it the
	// attempt reports a fence, which is the loop's terminal exit.
	stopAfter time.Duration

	attempts []leaseAttemptRecord
}

func (s *leaseAttemptSim) attempt(es *exactSession, budget time.Duration) (renewed, fenced bool) {
	began := s.clk.now()
	if began.Sub(s.start) > s.stopAfter {
		return false, true
	}
	spent := s.dial + s.roundtrip
	if spent > budget {
		spent = budget
	}
	s.clk.advance(spent)
	s.attempts = append(s.attempts, leaseAttemptRecord{
		start:  began.Sub(s.start),
		end:    s.clk.now().Sub(s.start),
		budget: budget,
	})
	// Every attempt in these tests FAILS. That is the interesting case: the
	// question is not whether a healthy renewal works, it is how many chances
	// the schedule gives a struggling one before the lease is gone.
	return false, false
}

func (s *leaseAttemptSim) timeline() string {
	var b strings.Builder
	for i, a := range s.attempts {
		fmt.Fprintf(&b, "\n  attempt %d: t=%v..%v (budget %v)", i+1, a.start, a.end, a.budget)
	}
	if b.Len() == 0 {
		return "\n  (no attempts at all)"
	}
	return b.String()
}

// completedBefore counts attempts that FINISHED strictly before d.
func (s *leaseAttemptSim) completedBefore(d time.Duration) int {
	n := 0
	for _, a := range s.attempts {
		if a.end < d {
			n++
		}
	}
	return n
}

// newLeaseScheduleSession builds a session with a confirmed 90s lease and no
// client attached to any authority: the loop under test is driven entirely
// through the injected clock and attempt hook.
func newLeaseScheduleSession(t *testing.T, ttl time.Duration, confirmedAt time.Time) (*Client, *exactSession) {
	t.Helper()
	es, err := newExactSession("owner", 4)
	if err != nil {
		t.Fatal(err)
	}
	es.noteLease(confirmedAt, ttl.Milliseconds())
	c := &Client{closed: make(chan struct{})}
	return c, es
}

// TestLeaseRenewalKeepsTwoAttemptsBeforeExpiry is the audit's worked example,
// deterministically. A 90s lease, a 15s dial+auth and a 30s round trip, every
// attempt failing: the question is how many bounded attempts finish strictly
// before the lease expires at t=90.
//
// Pre-fix the answer is ZERO — the first attempt ends at t=75 having renewed
// nothing, and the loop then sleeps a full cadence to t=105, fifteen seconds
// past the expiry it was supposed to protect.
func TestLeaseRenewalKeepsTwoAttemptsBeforeExpiry(t *testing.T) {
	const ttl = 90 * time.Second
	start := time.Unix(1_700_000_000, 0)
	clk := newVirtualLeaseClock(start)
	c, es := newLeaseScheduleSession(t, ttl, start)

	sim := &leaseAttemptSim{
		clk:       clk,
		start:     start,
		dial:      15 * time.Second,
		roundtrip: 30 * time.Second,
		stopAfter: ttl,
	}
	c.renewLoopWith(es, clk.clock(), sim.attempt)

	if got := sim.completedBefore(ttl); got < 2 {
		t.Fatalf("only %d renewal attempts finished strictly before the lease expired at %v; want >= 2.\n"+
			"A lease that gets fewer than two chances inside its own lifetime is one slow "+
			"round trip away from lapsing, and a lapsed session is fenced with acknowledged "+
			"data still in the kernel's dirty pages.%s",
			got, ttl, sim.timeline())
	}
	for i, a := range sim.attempts {
		if a.end <= a.start {
			continue
		}
		if a.budget <= 0 {
			t.Fatalf("attempt %d ran with a non-positive budget %v%s", i+1, a.budget, sim.timeline())
		}
	}
	t.Logf("renewal timeline (90s lease, 15s dial + 30s round trip, every attempt failing):%s", sim.timeline())
}

// TestLeaseRenewalNeverSleepsPastTheConfirmedExpiry pins the specific hole: no
// gap between the end of one attempt and the start of the next may cross the
// confirmed expiry while the window still had room for another attempt.
func TestLeaseRenewalNeverSleepsPastTheConfirmedExpiry(t *testing.T) {
	const ttl = 90 * time.Second
	start := time.Unix(1_700_000_000, 0)
	clk := newVirtualLeaseClock(start)
	c, es := newLeaseScheduleSession(t, ttl, start)

	sim := &leaseAttemptSim{
		clk:       clk,
		start:     start,
		dial:      15 * time.Second,
		roundtrip: 30 * time.Second,
		stopAfter: ttl,
	}
	c.renewLoopWith(es, clk.clock(), sim.attempt)

	last := time.Duration(0)
	for i, a := range sim.attempts {
		if last < ttl && a.start >= ttl {
			t.Fatalf("the renewal loop went quiet at t=%v and did not attempt again until t=%v, "+
				"past the lease's confirmed expiry at t=%v (attempt %d).\n"+
				"The schedule must be anchored on the confirmed expiry, not on loop iterations.%s",
				last, a.start, ttl, i+1, sim.timeline())
		}
		last = a.end
	}
}

// TestLeaseRenewalReschedulesFromTheConfirmedExpiry proves the anchor. A
// renewal that takes a long time to be confirmed must NOT push the next
// renewal out by that same delay: the next one is due relative to the expiry
// the authority just stated, so a slow round trip eats the client's slack, not
// the lease's.
func TestLeaseRenewalReschedulesFromTheConfirmedExpiry(t *testing.T) {
	const ttl = 90 * time.Second
	start := time.Unix(1_700_000_000, 0)
	clk := newVirtualLeaseClock(start)
	c, es := newLeaseScheduleSession(t, ttl, start)

	var starts []time.Duration
	attempts := 0
	attempt := func(es *exactSession, budget time.Duration) (bool, bool) {
		began := clk.now()
		starts = append(starts, began.Sub(start))
		attempts++
		if attempts > 4 {
			return false, true
		}
		// A slow but SUCCESSFUL renewal: 20s on the wire, then the authority
		// confirms a full fresh TTL measured from when we sent it.
		clk.advance(20 * time.Second)
		es.noteLease(began, ttl.Milliseconds())
		return true, false
	}
	c.renewLoopWith(es, clk.clock(), attempt)

	if len(starts) < 3 {
		t.Fatalf("expected at least 3 renewals, got %d: %v", len(starts), starts)
	}
	// Renewal i confirmed an expiry of starts[i] + ttl (the authority states a
	// REMAINING duration, anchored at send time). Renewal i+1 must begin no
	// later than half of that confirmed lease — otherwise the second half of
	// every lease is spent with fewer chances than the first, and the round
	// trip's cost has been charged to the lease instead of to our own slack.
	for i := 1; i < len(starts) && i <= 3; i++ {
		confirmedExpiry := starts[i-1] + ttl
		latest := confirmedExpiry - ttl/2
		if starts[i] > latest {
			t.Fatalf("renewal %d confirmed an expiry at t=%v but renewal %d did not start until "+
				"t=%v, past the halfway point t=%v.\n"+
				"The schedule is drifting with round-trip latency instead of being anchored on "+
				"the confirmed expiry.\nstarts: %v",
				i, confirmedExpiry, i+1, starts[i], latest, starts)
		}
	}
	t.Logf("renewal starts relative to establish: %v", starts)
}

// TestLeaseRenewalAttemptBoundsDialAndAuthTogether proves the second half of
// the fix against a REAL transport rather than a model: one attempt's budget
// covers dialing and authenticating as well as the round trip.
//
// The transport connects instantly and then never authenticates — the far side
// of the pipe is never read from or written to — so clientHandshake blocks.
// Pre-fix that cost dialHandshakeTimeout (5s) entirely OUTSIDE the bound the
// renewal loop advertised, which is how a "30s" attempt in the audit's timeline
// actually ran for 45.
func TestLeaseRenewalAttemptBoundsDialAndAuthTogether(t *testing.T) {
	const budget = 500 * time.Millisecond

	var mu sync.Mutex
	var parked []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range parked {
			_ = c.Close()
		}
	})
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	t.Cleanup(lifecycleCancel)
	c := &Client{
		addrs:           []string{"pipe"},
		closed:          make(chan struct{}),
		dedicated:       make(map[*conn]struct{}),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		transport: func(context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			mu.Lock()
			parked = append(parked, server)
			mu.Unlock()
			return client, nil
		},
	}
	es, err := newExactSession("owner", 4)
	if err != nil {
		t.Fatal(err)
	}

	began := time.Now()
	renewed, fenced := c.renewOnce(es, budget)
	elapsed := time.Since(began)

	if renewed || fenced {
		t.Fatalf("an attempt that never authenticated reported renewed=%v fenced=%v", renewed, fenced)
	}
	// Generous slack: the assertion is that the attempt is bounded by its OWN
	// budget rather than by dialHandshakeTimeout, and those differ by 4.5s.
	if limit := budget + 2*time.Second; elapsed > limit {
		t.Fatalf("one renewal attempt with a %v budget took %v (limit %v).\n"+
			"Dialing and authenticating the reserved transport are outside the attempt's "+
			"bound, so the loop's schedule is reasoning about a budget the attempt does "+
			"not actually honour.", budget, elapsed, limit)
	}
	if err := c.LeaseRenewalError(); err == nil {
		t.Fatal("a renewal attempt that never authenticated recorded no failure; " +
			"a silently swallowed transport/credential failure is exactly what made the " +
			"access-lease death invisible")
	}
	if es.isFenced() {
		t.Fatal("a failed renewal attempt fenced the session; only a definite ESTALE may")
	}
	t.Logf("bounded attempt returned in %v (budget %v), recorded: %v", elapsed, budget, c.LeaseRenewalError())
}
