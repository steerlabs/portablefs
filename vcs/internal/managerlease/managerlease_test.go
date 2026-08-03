package managerlease

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func testIdentity() Identity {
	return Identity{
		ManagerEpoch:        "7",
		ManagerRuntimeID:    "pfmgr_a",
		AuthorityInstanceID: "pfvcs_a",
		AuthorityRuntimeSeq: "3",
		AuthorityRuntimeID:  "pfrt_a",
	}
}

func baseFrame() Frame {
	return Frame{
		V:                   FrameVersion,
		Seq:                 1,
		ManagerEpoch:        "7",
		ManagerRuntimeID:    "pfmgr_a",
		AuthorityInstanceID: "pfvcs_a",
		AuthorityRuntimeSeq: "3",
		AuthorityRuntimeID:  "pfrt_a",
		DBTimeMs:            1_000_000,
		LeaseRemainingMs:    30_000,
	}
}

func encodeFrame(frame Frame) string {
	encoded, err := json.Marshal(frame)
	if err != nil {
		panic(err)
	}
	return string(encoded) + "\n"
}

func frameWithSeq(seq, remainingMs int64) string {
	frame := baseFrame()
	frame.Seq = seq
	frame.LeaseRemainingMs = remainingMs
	return encodeFrame(frame)
}

func validFrame(remainingMs int64) string { return frameWithSeq(1, remainingMs) }

// fakeProber returns scripted capability-bound lease facts (or errors), and
// records how many probes ran. Its default answer is a CURRENT claim with
// the exact test identity echo.
type fakeProber struct {
	mu     sync.Mutex
	facts  LeaseFacts
	err    error
	delay  time.Duration
	onCall func()
	probes int
}

func currentFacts(dbTimeMs, expiresAtDbMs int64) LeaseFacts {
	return LeaseFacts{
		Current:             true,
		DBTimeMs:            dbTimeMs,
		ExpiresAtDbMs:       expiresAtDbMs,
		ManagerEpoch:        "7",
		AuthorityRuntimeSeq: "3",
		AuthorityRuntimeID:  "pfrt_a",
	}
}

func newFakeProber(dbTimeMs, expiresAtDbMs int64) *fakeProber {
	return &fakeProber{facts: currentFacts(dbTimeMs, expiresAtDbMs)}
}

func (p *fakeProber) ProbeLeaseFacts(context.Context) (LeaseFacts, error) {
	p.mu.Lock()
	facts, err, hook := p.facts, p.err, p.onCall
	p.probes++
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return LeaseFacts{}, err
	}
	return facts, nil
}

func (p *fakeProber) set(facts LeaseFacts, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.facts = facts
	p.err = err
}

// fakeClock is an injectable child-local monotonic clock.
type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{at: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen in time", what)
	}
}

func expectNotClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s happened unexpectedly", what)
	default:
	}
}

// --- deadline grounding -----------------------------------------------------

// observeSettled observes a frame and waits for the grounding it triggers to
// complete. Grounding deliberately runs OFF the frame reader — the reader's
// only job is to keep the lease pipe drained, at pipe speed, no matter how
// slow the database is — so assertions about the armed deadline synchronize
// on the grounder here instead of relying on an inline probe.
func observeSettled(t *testing.T, g *Guard, frame Frame) error {
	t.Helper()
	_, settled := g.groundingSettled()
	if err := g.observe(frame); err != nil {
		return err
	}
	select {
	case <-settled:
	case <-time.After(5 * time.Second):
		t.Fatal("grounding did not settle")
	}
	return nil
}

// TestGroundedDeadlineUsesLeaseFactsNotFrame: the deadline is
// capturedLocal(pre-query) + (expiresAtDbMs − dbTimeMs) − guard, from the
// capability-bound lease-facts answer. The frame's own generous
// leaseRemainingMs is metadata: a buffered frame claiming 30s cannot extend
// past the database's true 10s remainder.
func TestGroundedDeadlineUsesLeaseFactsNotFrame(t *testing.T) {
	guard := NewGuard(testIdentity(), 100*time.Millisecond)
	clock := newFakeClock()
	guard.now = clock.now
	prober := newFakeProber(1_020_000, 1_030_000) // DB truth: 10s remain
	guard.SetProber(prober)

	frame := baseFrame() // frame CLAIMS 30s remaining — ignored for extension
	if err := guard.observe(frame); err != nil {
		t.Fatalf("observe: %v", err)
	}
	waitClosed(t, guard.FirstFrame(), "grounded first frame")

	wantDeadline := clock.now().Add(10*time.Second - 100*time.Millisecond)
	guard.mu.Lock()
	got := guard.deadlineAt
	guard.mu.Unlock()
	if !got.Equal(wantDeadline) {
		t.Fatalf("deadline = %v, want %v (lease-facts-grounded, not frame-anchored)", got, wantDeadline)
	}

	// The deadline check fences exactly at the grounded instant.
	clock.advance(10*time.Second - 100*time.Millisecond - time.Millisecond)
	guard.mu.Lock()
	guard.deadlineCheckLocked()
	guard.mu.Unlock()
	expectNotClosed(t, guard.Fenced(), "fence before the grounded deadline")
	clock.advance(time.Millisecond)
	guard.mu.Lock()
	guard.deadlineCheckLocked()
	guard.mu.Unlock()
	waitClosed(t, guard.Fenced(), "grounded deadline fence")
}

// TestQueryDelayShrinksTheProof: the local anchor is captured BEFORE the
// lease-facts query, so a slow query can only SHRINK the armed window (the
// clock advanced during the call), never stretch it by the response delay.
func TestQueryDelayShrinksTheProof(t *testing.T) {
	guard := NewGuard(testIdentity(), 100*time.Millisecond)
	clock := newFakeClock()
	guard.now = clock.now
	prober := newFakeProber(1_000_000, 1_010_000)             // 10s remain at DB time
	prober.onCall = func() { clock.advance(3 * time.Second) } // the query itself takes 3s
	guard.SetProber(prober)

	anchor := clock.now() // observe captures this BEFORE the query
	if err := observeSettled(t, guard, baseFrame()); err != nil {
		t.Fatalf("observe: %v", err)
	}
	wantDeadline := anchor.Add(10*time.Second - 100*time.Millisecond)
	guard.mu.Lock()
	got := guard.deadlineAt
	guard.mu.Unlock()
	if !got.Equal(wantDeadline) {
		t.Fatalf("deadline = %v, want %v (anchored at the PRE-query instant)", got, wantDeadline)
	}
	// Only 10s − 3s(query) − guard of real runway remains from "now".
	if runway := got.Sub(clock.now()); runway != 7*time.Second-100*time.Millisecond {
		t.Fatalf("remaining runway = %v, want %v", runway, 7*time.Second-100*time.Millisecond)
	}
}

// TestSupersededBeforePriorExpiryNeverExtends is the takeover hole this
// design closes: the manager is superseded BEFORE its previously reported
// expiry. A perfectly valid, fresh-looking frame (our epoch, next sequence)
// arrives after the takeover — but the capability-bound lease facts answer
// current=false, so NOTHING extends; the old deadline continues and expires
// on schedule.
func TestSupersededBeforePriorExpiryNeverExtends(t *testing.T) {
	guard := NewGuard(testIdentity(), 100*time.Millisecond)
	clock := newFakeClock()
	guard.now = clock.now
	prober := newFakeProber(1_000_000, 1_010_000) // 10s remain
	guard.SetProber(prober)
	if err := observeSettled(t, guard, baseFrame()); err != nil {
		t.Fatalf("observe: %v", err)
	}
	guard.mu.Lock()
	armed := guard.deadlineAt
	gen := guard.deadlineGen
	guard.mu.Unlock()

	// TAKEOVER at DB time 1_002_000 — well before the reported 1_010_000
	// expiry. The database now proves our binding is not current.
	prober.set(LeaseFacts{Current: false}, nil)
	clock.advance(2 * time.Second)
	// A valid old frame after the takeover (correct identity, next seq).
	second := baseFrame()
	second.Seq = 2
	if err := observeSettled(t, guard, second); err != nil {
		t.Fatalf("a valid frame after takeover must not fence by itself: %v", err)
	}
	guard.mu.Lock()
	if !guard.deadlineAt.Equal(armed) || guard.deadlineGen != gen {
		guard.mu.Unlock()
		t.Fatal("a superseded binding extended or re-armed the deadline")
	}
	guard.mu.Unlock()
	if guard.ProbeNotCurrent() != 1 {
		t.Fatalf("not-current probes = %d, want 1", guard.ProbeNotCurrent())
	}
	expectNotClosed(t, guard.Fenced(), "premature fence (the old deadline still runs)")

	// The OLD deadline expires on schedule and fences.
	clock.advance(8 * time.Second)
	guard.mu.Lock()
	guard.deadlineCheckLocked()
	guard.mu.Unlock()
	waitClosed(t, guard.Fenced(), "old-deadline fence after takeover")
}

// TestAmbiguousFactsNeverExtend: query errors (ACL revoked, timeout, network),
// nonsense times, and binding-echo mismatches leave the previously armed
// deadline exactly as it was — never extend, never fence by themselves.
func TestAmbiguousFactsNeverExtend(t *testing.T) {
	guard := NewGuard(testIdentity(), 100*time.Millisecond)
	clock := newFakeClock()
	guard.now = clock.now
	prober := newFakeProber(1_000_000, 1_030_000)
	guard.SetProber(prober)
	if err := observeSettled(t, guard, baseFrame()); err != nil {
		t.Fatalf("observe: %v", err)
	}
	guard.mu.Lock()
	armed := guard.deadlineAt
	gen := guard.deadlineGen
	guard.mu.Unlock()

	cases := []struct {
		name  string
		facts LeaseFacts
		err   error
	}{
		{name: "revoked/ACL-missing read", err: fmt.Errorf("permission denied for function authority_lease_facts")},
		{name: "timeout", err: context.DeadlineExceeded},
		{name: "unsafe dbTime", facts: LeaseFacts{Current: true, DBTimeMs: int64(1) << 60, ExpiresAtDbMs: int64(1)<<60 + 1, ManagerEpoch: "7", AuthorityRuntimeSeq: "3", AuthorityRuntimeID: "pfrt_a"}},
		{name: "expiry not after dbTime", facts: currentFacts(1_005_000, 1_005_000)},
		{name: "foreign epoch echo", facts: LeaseFacts{Current: true, DBTimeMs: 1_005_000, ExpiresAtDbMs: 1_035_000, ManagerEpoch: "8", AuthorityRuntimeSeq: "3", AuthorityRuntimeID: "pfrt_a"}},
		{name: "foreign runtime echo", facts: LeaseFacts{Current: true, DBTimeMs: 1_005_000, ExpiresAtDbMs: 1_035_000, ManagerEpoch: "7", AuthorityRuntimeSeq: "4", AuthorityRuntimeID: "pfrt_a"}},
	}
	for index, testCase := range cases {
		prober.set(testCase.facts, testCase.err)
		frame := baseFrame()
		frame.Seq = int64(index + 2)
		if err := observeSettled(t, guard, frame); err != nil {
			t.Fatalf("%s: observe must not fence: %v", testCase.name, err)
		}
		guard.mu.Lock()
		same := guard.deadlineAt.Equal(armed) && guard.deadlineGen == gen
		guard.mu.Unlock()
		if !same {
			t.Fatalf("%s: ambiguous facts extended or re-armed the deadline", testCase.name)
		}
	}
	if guard.ProbeFailures() != len(cases) {
		t.Fatalf("probe failures = %d, want %d", guard.ProbeFailures(), len(cases))
	}
	expectNotClosed(t, guard.Fenced(), "fence from ambiguous facts")
}

// TestNoProvisionalReadiness: before the journal seam exists, valid frames
// arm only a provisional FENCING deadline — FirstFrame stays closed, so
// serving can never begin on unverifiable facts — and the latest frame is
// queued (bounded to one) so it grounds the instant the seam is installed.
func TestNoProvisionalReadiness(t *testing.T) {
	guard := NewGuard(testIdentity(), 20*time.Millisecond)
	r, w := io.Pipe()
	go guard.Run(r)
	if _, err := io.WriteString(w, validFrame(80)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	expectNotClosed(t, guard.FirstFrame(), "serving release from an ungrounded frame")
	waitClosed(t, guard.Fenced(), "provisional deadline fence")
	_ = w.Close()
}

// TestQueuedFrameGroundsWhenSeamArrives: pre-seam frames are queued (latest
// only); SetProber grounds immediately and releases serving without waiting
// for another frame.
func TestQueuedFrameGroundsWhenSeamArrives(t *testing.T) {
	guard := NewGuard(testIdentity(), 100*time.Millisecond)
	clock := newFakeClock()
	guard.now = clock.now
	for seq := int64(1); seq <= 3; seq++ {
		frame := baseFrame()
		frame.Seq = seq
		if err := guard.observe(frame); err != nil {
			t.Fatalf("pre-seam observe %d: %v", seq, err)
		}
	}
	expectNotClosed(t, guard.FirstFrame(), "readiness before the seam exists")

	prober := newFakeProber(1_000_000, 1_030_000)
	guard.SetProber(prober)
	waitClosed(t, guard.FirstFrame(), "grounding of the queued frame")
	if prober.probes != 1 {
		t.Fatalf("probes = %d, want exactly 1 (one queued frame, not three)", prober.probes)
	}
	wantDeadline := clock.now().Add(30*time.Second - 100*time.Millisecond)
	guard.mu.Lock()
	got := guard.deadlineAt
	guard.mu.Unlock()
	if !got.Equal(wantDeadline) {
		t.Fatalf("deadline = %v, want %v", got, wantDeadline)
	}
}

// TestWallClockStepsAreIrrelevant: the guard consumes ONLY the injected
// monotonic clock; deadline arithmetic is pure differences of database
// times anchored at monotonic instants, so stepping any wall clock (here:
// wildly different DB wall values across probes) never manufactures or
// destroys local runway beyond the DB-computed remainder.
func TestWallClockStepsAreIrrelevant(t *testing.T) {
	guard := NewGuard(testIdentity(), 100*time.Millisecond)
	clock := newFakeClock()
	guard.now = clock.now
	// The database wall clock "steps backward" by a year between claims;
	// only (expires − dbTime) matters.
	prober := newFakeProber(999_999_999_999, 999_999_999_999+10_000)
	guard.SetProber(prober)
	if err := observeSettled(t, guard, baseFrame()); err != nil {
		t.Fatalf("observe: %v", err)
	}
	deadline1 := clock.now().Add(10*time.Second - 100*time.Millisecond)
	guard.mu.Lock()
	got := guard.deadlineAt
	guard.mu.Unlock()
	if !got.Equal(deadline1) {
		t.Fatalf("deadline = %v, want %v regardless of the DB wall value", got, deadline1)
	}
	// A later probe with a wall clock stepped FORWARD by a decade still only
	// contributes its remainder.
	prober.set(currentFacts(1_315_360_000_000_000, 1_315_360_000_000_000+20_000), nil)
	second := baseFrame()
	second.Seq = 2
	if err := observeSettled(t, guard, second); err != nil {
		t.Fatalf("observe: %v", err)
	}
	deadline2 := clock.now().Add(20*time.Second - 100*time.Millisecond)
	guard.mu.Lock()
	got = guard.deadlineAt
	guard.mu.Unlock()
	if !got.Equal(deadline2) {
		t.Fatalf("deadline = %v, want %v after a forward wall step", got, deadline2)
	}
}

// --- timer race (reusable AfterFunc) ----------------------------------------

// TestStaleTimerCallbackNeverFencesAfterValidFrame is the deterministic
// interleaving of the timer race: the timer callback for generation 1 is
// already "firing" (waiting on g.mu) while a fresh grounded frame re-arms
// the deadline to generation 2. When the stale callback finally runs, it
// must observe the LIVE deadline, re-arm, and not fence.
func TestStaleTimerCallbackNeverFencesAfterValidFrame(t *testing.T) {
	guard := NewGuard(testIdentity(), 100*time.Millisecond)
	clock := newFakeClock()
	guard.now = clock.now
	prober := newFakeProber(1_000_000, 1_010_000) // 10s remain
	guard.SetProber(prober)

	// Frame 1 arms deadline D1 (10s − guard from now).
	if err := observeSettled(t, guard, baseFrame()); err != nil {
		t.Fatalf("observe first: %v", err)
	}

	// Local time reaches D1 exactly — the gen-1 callback is now "due" and
	// would fence. Before it can run, a fresh frame lands and re-arms from
	// renewed lease facts (30s remain).
	clock.advance(10 * time.Second)
	prober.set(currentFacts(1_010_000, 1_040_000), nil)
	second := baseFrame()
	second.Seq = 2
	if err := observeSettled(t, guard, second); err != nil {
		t.Fatalf("observe second: %v", err)
	}

	// The STALE gen-1 callback finally acquires the lock. It must observe
	// the live deadline (30s out) and refuse to fence.
	guard.onDeadlineTimer()
	expectNotClosed(t, guard.Fenced(), "stale timer callback fenced after a valid frame")

	// And the live deadline still fences when it truly passes.
	clock.advance(30 * time.Second)
	guard.onDeadlineTimer()
	waitClosed(t, guard.Fenced(), "live deadline fence")
	if cause := guard.Cause(); cause == nil || !strings.Contains(cause.Error(), "deadline passed") {
		t.Fatalf("fence cause = %v", cause)
	}
}

// TestTimerCallbackGenerationBumpsPerArm: every arming bumps the generation,
// so tests and diagnostics can prove which arming a fence belongs to.
func TestTimerCallbackGenerationBumpsPerArm(t *testing.T) {
	guard := NewGuard(testIdentity(), 100*time.Millisecond)
	clock := newFakeClock()
	guard.now = clock.now
	prober := newFakeProber(1_000_000, 1_060_000)
	guard.SetProber(prober)
	for seq := int64(1); seq <= 3; seq++ {
		frame := baseFrame()
		frame.Seq = seq
		if err := observeSettled(t, guard, frame); err != nil {
			t.Fatalf("observe %d: %v", seq, err)
		}
	}
	guard.mu.Lock()
	gen := guard.deadlineGen
	guard.mu.Unlock()
	if gen != 3 {
		t.Fatalf("deadline generation = %d, want 3", gen)
	}
}

// TestConcurrentObserveAndTimerUnderRace hammers observe against manual
// timer callbacks (run with -race): no panic, no premature fence while
// frames stay fresh.
func TestConcurrentObserveAndTimerUnderRace(t *testing.T) {
	guard := NewGuard(testIdentity(), time.Millisecond)
	prober := newFakeProber(1_000_000, 1_060_000)
	guard.SetProber(prober)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for seq := int64(1); seq <= 200; seq++ {
			frame := baseFrame()
			frame.Seq = seq
			frame.LeaseRemainingMs = 60_000
			if err := guard.observe(frame); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		guard.onDeadlineTimer()
	}
	<-done
	expectNotClosed(t, guard.Fenced(), "fence while frames were fresh")
}

// --- pipe hygiene ------------------------------------------------------------

func TestForeignIdentityFrameFences(t *testing.T) {
	mutations := []func(*Frame){
		func(f *Frame) { f.ManagerEpoch = "8" },
		func(f *Frame) { f.ManagerRuntimeID = "pfmgr_other" },
		func(f *Frame) { f.AuthorityInstanceID = "pfvcs_other" },
		func(f *Frame) { f.AuthorityRuntimeSeq = "4" },
		func(f *Frame) { f.AuthorityRuntimeID = "pfrt_other" },
	}
	for i, mutate := range mutations {
		frame := baseFrame()
		mutate(&frame)
		guard := NewGuard(testIdentity(), 0)
		r, w := io.Pipe()
		go guard.Run(r)
		if _, err := io.WriteString(w, encodeFrame(frame)); err != nil {
			t.Fatal(err)
		}
		waitClosed(t, guard.Fenced(), fmt.Sprintf("mutation %d fence", i))
		expectNotClosed(t, guard.FirstFrame(), "first-frame release from a foreign frame")
		_ = w.Close()
	}
}

func TestNonIncreasingSequenceFences(t *testing.T) {
	cases := map[string][]string{
		"duplicate": {frameWithSeq(1, 60_000), frameWithSeq(1, 60_000)},
		"rewound":   {frameWithSeq(2, 60_000), frameWithSeq(1, 60_000)},
		"missing":   {frameWithSeq(0, 60_000)},
	}
	for name, frames := range cases {
		guard := NewGuard(testIdentity(), 0)
		prober := newFakeProber(1_000_000, 1_060_000)
		guard.SetProber(prober)
		r, w := io.Pipe()
		go guard.Run(r)
		go func() {
			for _, frame := range frames {
				if _, err := io.WriteString(w, frame); err != nil {
					return
				}
			}
		}()
		waitClosed(t, guard.Fenced(), name+" fence")
		if cause := guard.Cause(); cause == nil || !strings.Contains(cause.Error(), "sequence") {
			t.Fatalf("%s: fence cause = %v, want the sequence explanation", name, cause)
		}
		_ = w.Close()
	}
	// Strictly increasing (gaps allowed: superseded frames are discarded by
	// design) keeps the guard alive.
	guard := NewGuard(testIdentity(), 0)
	prober := newFakeProber(1_000_000, 1_060_000)
	guard.SetProber(prober)
	r, w := io.Pipe()
	go guard.Run(r)
	for _, seq := range []int64{1, 2, 7} {
		if _, err := io.WriteString(w, frameWithSeq(seq, 60_000)); err != nil {
			t.Fatal(err)
		}
	}
	waitClosed(t, guard.FirstFrame(), "first frame")
	time.Sleep(20 * time.Millisecond)
	expectNotClosed(t, guard.Fenced(), "fence on increasing sequences")
	_ = w.Close()
}

func TestMalformedAndOversizedFramesFence(t *testing.T) {
	cases := []string{
		"not-json\n",
		`{"v":1,"managerEpoch":"7","unknown":"field"}` + "\n",
		strings.Repeat("x", MaxFrameBytes+1) + "\n",
	}
	for i, payload := range cases {
		guard := NewGuard(testIdentity(), 0)
		r, w := io.Pipe()
		go guard.Run(r)
		go func() { _, _ = io.WriteString(w, payload) }()
		waitClosed(t, guard.Fenced(), fmt.Sprintf("case %d fence", i))
		_ = w.Close()
	}
}

func TestTruncatedFinalFrameFences(t *testing.T) {
	guard := NewGuard(testIdentity(), 0)
	r, w := io.Pipe()
	go guard.Run(r)
	if _, err := io.WriteString(w, `{"v":1,"managerEpo`); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	waitClosed(t, guard.Fenced(), "truncated-frame fence")
}

func TestWritePipeErrorFences(t *testing.T) {
	guard := NewGuard(testIdentity(), 0)
	prober := newFakeProber(1_000_000, 1_060_000)
	guard.SetProber(prober)
	r, w := io.Pipe()
	go guard.Run(r)
	if _, err := io.WriteString(w, validFrame(60_000)); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, guard.FirstFrame(), "first frame")
	_ = w.CloseWithError(fmt.Errorf("manager killed the pipe under backpressure"))
	waitClosed(t, guard.Fenced(), "pipe-error fence")
}

// --- strict wire validation ---------------------------------------------------

// TestParseFrameStrictWire is the adversarial table: duplicate keys anywhere,
// trailing JSON, non-canonical counters, unbounded ids, unsafe times, and
// out-of-range TTL/sequence are all rejected with no panic.
func TestParseFrameStrictWire(t *testing.T) {
	good := strings.TrimSuffix(encodeFrame(baseFrame()), "\n")
	if _, err := ParseFrame([]byte(good)); err != nil {
		t.Fatalf("canonical frame rejected: %v", err)
	}

	longID := strings.Repeat("a", maxIDBytes+1)
	cases := map[string]string{
		"duplicate key":         `{"v":1,"v":1,"seq":1,"managerEpoch":"7","managerRuntimeId":"pfmgr_a","authorityInstanceId":"pfvcs_a","authorityRuntimeSeq":"3","authorityRuntimeId":"pfrt_a","dbTimeMs":1000000,"leaseRemainingMs":30000}`,
		"trailing JSON":         good + `{}`,
		"trailing garbage":      good + ` x`,
		"array top level":       `[` + good + `]`,
		"unknown field":         strings.TrimSuffix(good, "}") + `,"extra":1}`,
		"float seq":             strings.Replace(good, `"seq":1`, `"seq":1.5`, 1),
		"zero seq":              strings.Replace(good, `"seq":1`, `"seq":0`, 1),
		"negative seq":          strings.Replace(good, `"seq":1`, `"seq":-1`, 1),
		"unsafe seq":            strings.Replace(good, `"seq":1`, `"seq":9007199254740993`, 1),
		"epoch leading zero":    strings.Replace(good, `"managerEpoch":"7"`, `"managerEpoch":"07"`, 1),
		"epoch zero":            strings.Replace(good, `"managerEpoch":"7"`, `"managerEpoch":"0"`, 1),
		"epoch not decimal":     strings.Replace(good, `"managerEpoch":"7"`, `"managerEpoch":"7a"`, 1),
		"epoch numeric":         strings.Replace(good, `"managerEpoch":"7"`, `"managerEpoch":7`, 1),
		"runtimeSeq empty":      strings.Replace(good, `"authorityRuntimeSeq":"3"`, `"authorityRuntimeSeq":""`, 1),
		"empty instance id":     strings.Replace(good, `"authorityInstanceId":"pfvcs_a"`, `"authorityInstanceId":""`, 1),
		"oversized runtime id":  strings.Replace(good, `"authorityRuntimeId":"pfrt_a"`, `"authorityRuntimeId":"`+longID+`"`, 1),
		"zero dbTimeMs":         strings.Replace(good, `"dbTimeMs":1000000`, `"dbTimeMs":0`, 1),
		"negative dbTimeMs":     strings.Replace(good, `"dbTimeMs":1000000`, `"dbTimeMs":-5`, 1),
		"unsafe dbTimeMs":       strings.Replace(good, `"dbTimeMs":1000000`, `"dbTimeMs":9007199254740993`, 1),
		"zero remaining":        strings.Replace(good, `"leaseRemainingMs":30000`, `"leaseRemainingMs":0`, 1),
		"oversized remaining":   strings.Replace(good, `"leaseRemainingMs":30000`, `"leaseRemainingMs":7300000000`, 1),
		"wrong version":         strings.Replace(good, `"v":1`, `"v":2`, 1),
		"string dbTimeMs":       strings.Replace(good, `"dbTimeMs":1000000`, `"dbTimeMs":"1000000"`, 1),
		"null frame":            `null`,
		"empty object":          `{}`,
		"nested duplicate keys": `{"v":1,"seq":1,"managerEpoch":"7","managerRuntimeId":"pfmgr_a","authorityInstanceId":"pfvcs_a","authorityRuntimeSeq":"3","authorityRuntimeId":"pfrt_a","dbTimeMs":{"a":1,"a":2},"leaseRemainingMs":30000}`,
	}
	for name, payload := range cases {
		if _, err := ParseFrame([]byte(payload)); err == nil {
			t.Fatalf("%s: %q must be rejected", name, payload)
		}
	}
}

// FuzzParseFrame: no input may panic; every accepted frame satisfies the
// wire invariants.
func FuzzParseFrame(f *testing.F) {
	f.Add(strings.TrimSuffix(encodeFrame(baseFrame()), "\n"))
	f.Add(`{"v":1,"seq":2,"managerEpoch":"9007199254740993"}`)
	f.Add(`{"v":1,"v":2}`)
	f.Add(`{}`)
	f.Add(`[]`)
	f.Add(`{"seq":`)
	f.Add(strings.Repeat("{", 5000))
	f.Fuzz(func(t *testing.T, line string) {
		frame, err := ParseFrame([]byte(line))
		if err != nil {
			return
		}
		if frame.V != FrameVersion || frame.Seq < 1 || frame.Seq > maxSafeMs {
			t.Fatalf("accepted frame violates version/sequence bounds: %+v", frame)
		}
		if !canonicalDecimalPattern.MatchString(frame.ManagerEpoch) ||
			!canonicalDecimalPattern.MatchString(frame.AuthorityRuntimeSeq) {
			t.Fatalf("accepted frame violates decimal canonicality: %+v", frame)
		}
		if frame.ManagerRuntimeID == "" || frame.AuthorityInstanceID == "" || frame.AuthorityRuntimeID == "" {
			t.Fatalf("accepted frame has empty ids: %+v", frame)
		}
		if frame.DBTimeMs < 1 || frame.DBTimeMs > maxSafeMs ||
			frame.LeaseRemainingMs < 1 || frame.LeaseRemainingMs > maxLeaseRemainingMs {
			t.Fatalf("accepted frame violates time bounds: %+v", frame)
		}
	})
}

// --- bootstrap ---------------------------------------------------------------

// shortWriter accepts at most n bytes per Write call.
type shortWriter struct {
	sink strings.Builder
	n    int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		p = p[:w.n]
	}
	return w.sink.Write(p)
}

func TestBootstrapFrameRoundTripsAndIsBounded(t *testing.T) {
	var sink strings.Builder
	frame := Bootstrap{
		AuthorityInstanceID: "pfvcs_a",
		VolumeID:            "vol_1",
		Branch:              "main",
		ManagerEpoch:        "7",
		AuthorityRuntimeSeq: "3",
		AuthorityRuntimeID:  "pfrt_a",
		FSAddr:              "127.0.0.1:50001",
		MetricsAddr:         "127.0.0.1:50002",
		JournalGenerationID: "pfgen_1",
		ProtocolVersion:     1,
		HAPolicyHash:        strings.Repeat("a", 64),
	}
	if err := EmitBootstrap(&sink, frame); err != nil {
		t.Fatalf("emit bootstrap: %v", err)
	}
	line := sink.String()
	if !strings.HasSuffix(line, "\n") || len(line) > MaxFrameBytes {
		t.Fatalf("bootstrap frame is unbounded or unterminated (%d bytes)", len(line))
	}
	var decoded Bootstrap
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	frame.V = FrameVersion
	if decoded != frame {
		t.Fatalf("bootstrap round trip mismatch:\n sent=%+v\n got=%+v", frame, decoded)
	}

	// Short writes must deliver the identical bytes.
	short := &shortWriter{n: 7}
	if err := EmitBootstrap(short, frame); err != nil {
		t.Fatalf("emit bootstrap over short writes: %v", err)
	}
	if short.sink.String() != line {
		t.Fatal("short writes corrupted the bootstrap frame")
	}

	oversized := frame
	oversized.JournalGenerationID = strings.Repeat("g", MaxFrameBytes)
	var refused strings.Builder
	if err := EmitBootstrap(&refused, oversized); err == nil || refused.Len() != 0 {
		t.Fatalf("oversized bootstrap must be refused before writing, err=%v written=%d", err, refused.Len())
	}
}

// --- the lease-facts probe budget (round 21c) -------------------------------

// budgetProber records the context deadline it was handed for each probe, so
// the DERIVED budget can be asserted directly instead of inferred from timing.
type budgetProber struct {
	mu      sync.Mutex
	facts   LeaseFacts
	budgets []time.Duration
}

func (p *budgetProber) ProbeLeaseFacts(ctx context.Context) (LeaseFacts, error) {
	deadline, ok := ctx.Deadline()
	p.mu.Lock()
	if ok {
		p.budgets = append(p.budgets, time.Until(deadline).Round(time.Second))
	} else {
		p.budgets = append(p.budgets, 0)
	}
	facts := p.facts
	p.mu.Unlock()
	return facts, nil
}

func (p *budgetProber) seen() []time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Duration(nil), p.budgets...)
}

// TestProbeBudgetIsDerivedFromTheArmedDeadline is the round-21c fix, one layer
// below the manager's own renewal. The budget used to be a flat 5 s, and on
// 2026-08-02 at 22:06:34 a child threw away a lease-facts answer to a
// WAL-saturated Postgres on that constant and fenced 13 s later — while the
// manager itself was healthy with 18.7 s of hard deadline left. A probe may
// now run for as long as the deadline it exists to extend: any less discards
// a proof that was still usable, any more cannot help because the guard has
// already fenced.
func TestProbeBudgetIsDerivedFromTheArmedDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	// Nothing armed yet: startup behaviour is deliberately unchanged from the
	// flat constant this replaces — the only unarmed probe is the very first
	// one, and its wait is bounded separately by firstLeaseFrameTimeout.
	if got := probeBudget(time.Time{}, now); got != unarmedProbeBudget {
		t.Fatalf("unarmed budget = %v, want %v", got, unarmedProbeBudget)
	}
	// The ordinary case: a 30 s claim minus a 2 s guard leaves 28 s, and the
	// probe gets all 28 — well past the constant it replaces.
	if got := probeBudget(now.Add(28*time.Second), now); got != 28*time.Second {
		t.Fatalf("armed budget = %v, want 28s", got)
	}
	if probeBudget(now.Add(28*time.Second), now) <= 5*time.Second {
		t.Fatal("the derived budget must exceed the flat 5s constant it replaces")
	}
	// A nearly-expired deadline still yields a usable, non-zero context.
	if got := probeBudget(now.Add(10*time.Millisecond), now); got != minProbeBudget {
		t.Fatalf("near-expiry budget = %v, want %v", got, minProbeBudget)
	}
	// An already-passed deadline never yields a negative context.
	if got := probeBudget(now.Add(-time.Hour), now); got != minProbeBudget {
		t.Fatalf("expired budget = %v, want %v", got, minProbeBudget)
	}
	// A pathologically long claim is clamped, so a wedged query cannot
	// occupy the single grounder indefinitely.
	if got := probeBudget(now.Add(time.Hour), now); got != maxProbeBudget {
		t.Fatalf("long-claim budget = %v, want %v", got, maxProbeBudget)
	}
}

// TestGroundingHandsTheProbeTheDerivedBudget proves the derivation reaches the
// actual query, not just the helper: the first probe (nothing armed) gets the
// cap, and the next one gets the window the previous grounding armed.
func TestGroundingHandsTheProbeTheDerivedBudget(t *testing.T) {
	guard := NewGuard(testIdentity(), 2*time.Second)
	clock := newFakeClock()
	guard.now = clock.now
	prober := &budgetProber{facts: currentFacts(1_000_000, 1_030_000)} // 30s remain
	guard.SetProber(prober)

	if err := observeSettled(t, guard, baseFrame()); err != nil {
		t.Fatalf("observe: %v", err)
	}
	next := baseFrame()
	next.Seq = 2
	if err := observeSettled(t, guard, next); err != nil {
		t.Fatalf("observe: %v", err)
	}

	budgets := prober.seen()
	if len(budgets) != 2 {
		t.Fatalf("probes = %d, want 2", len(budgets))
	}
	if budgets[0] != unarmedProbeBudget {
		t.Fatalf("first probe budget = %v, want %v (nothing armed yet)", budgets[0], unarmedProbeBudget)
	}
	// 30s of claim minus the 2s guard.
	if budgets[1] != 28*time.Second {
		t.Fatalf("second probe budget = %v, want 28s (the armed deadline)", budgets[1])
	}
}
