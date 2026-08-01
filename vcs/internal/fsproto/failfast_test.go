package fsproto

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/secure"
)

// fakeClock drives connHealth deterministically.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newFakeHealth() (*connHealth, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	h := newConnHealth()
	h.now = clk.now
	return h, clk
}

// TestFailFastEngagesAfterThresholdAndGrace pins the entry condition: N
// consecutive transport failures AND a streak that has persisted for the
// confirmation grace. Neither alone engages.
func TestFailFastEngagesAfterThresholdAndGrace(t *testing.T) {
	h, clk := newFakeHealth()

	// Three instant failures (fast ECONNREFUSED shape): threshold met but the
	// grace window has not elapsed — a brief restart must not engage.
	for i := 0; i < failFastThreshold; i++ {
		h.recordFailure()
	}
	if h.active() {
		t.Fatal("fail-fast engaged before the confirmation grace elapsed")
	}
	if err := h.gate(false); err != nil {
		t.Fatalf("gate before grace: %v", err)
	}

	// The outage persists past the grace: the next gate consultation engages
	// WITHOUT requiring another op to burn a deadline first.
	clk.advance(failFastGrace)
	if err := h.gate(false); !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("gate after threshold+grace: got %v, want ErrAuthorityUnreachable", err)
	}
	if !h.active() {
		t.Fatal("fail-fast should be engaged")
	}

	// Recovery-path connections stay exempt while engaged.
	if err := h.gate(true); err != nil {
		t.Fatalf("exempt gate must pass while engaged: %v", err)
	}
}

// TestFailFastExitsOnSuccess pins the automatic exit: one successful
// dial/round-trip clears the state entirely.
func TestFailFastExitsOnSuccess(t *testing.T) {
	h, clk := newFakeHealth()
	for i := 0; i < failFastThreshold; i++ {
		h.recordFailure()
	}
	clk.advance(failFastGrace)
	h.recordFailure()
	if !h.active() {
		t.Fatal("precondition: engaged")
	}

	h.recordSuccess()
	if h.active() {
		t.Fatal("a successful round-trip must exit fail-fast")
	}
	if err := h.gate(false); err != nil {
		t.Fatalf("gate after recovery: %v", err)
	}

	// The streak restarts from zero after a success: two fresh failures past
	// the grace must NOT engage (threshold not met).
	h.recordFailure()
	h.recordFailure()
	clk.advance(failFastGrace)
	if err := h.gate(false); err != nil {
		t.Fatalf("sub-threshold streak engaged fail-fast: %v", err)
	}
}

// TestFailFastStreakWindowResets pins that sporadic failures far apart (an
// idle mount with occasional blips and no intervening successes) never
// accumulate into an engage, while serial opTimeout-spaced failures do count
// as one streak.
func TestFailFastStreakWindowResets(t *testing.T) {
	h, clk := newFakeHealth()

	// Failures spread further apart than the streak window reset the count.
	for i := 0; i < 5; i++ {
		h.recordFailure()
		clk.advance(failFastStreakWindow + time.Second)
	}
	if h.active() {
		t.Fatal("sporadic failures beyond the streak window must not engage fail-fast")
	}

	// Serial black-hole failures land ~opTimeout apart, well inside the
	// window: they are exactly the streak fail-fast exists to catch.
	for i := 0; i < failFastThreshold; i++ {
		h.recordFailure()
		clk.advance(opTimeout)
	}
	if err := h.gate(false); !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("serial deadline-spaced failures must engage: got %v", err)
	}
}

// TestFailFastGateNeverEngagesOnStaleStreak pins that gate() judges a streak
// with the same staleness window recordFailure uses to extend one: three
// failures in a brief burst followed by a long idle gap (no ops, no
// successes — e.g. the subscribe stream's TCP conn survived a blip that
// killed three pooled-op round-trips) must NOT let the first op after the
// gap engage fail-fast and eat a spurious EIO without a single network
// attempt. The stale streak is reset instead, and a subsequent REAL outage
// still engages from a fresh streak.
func TestFailFastGateNeverEngagesOnStaleStreak(t *testing.T) {
	h, clk := newFakeHealth()

	// A brief burst: threshold met within the grace window, so nothing
	// engages at burst time.
	for i := 0; i < failFastThreshold; i++ {
		h.recordFailure()
	}
	if h.active() {
		t.Fatal("precondition: a sub-grace burst must not engage")
	}

	// A long idle gap with no traffic at all, then the next op arrives. The
	// grace measured to NOW has trivially elapsed; only streak staleness
	// distinguishes this stale history from a live outage.
	clk.advance(failFastStreakWindow + time.Minute)
	if err := h.gate(false); err != nil {
		t.Fatalf("gate engaged on a stale streak after an idle gap: %v", err)
	}
	if h.active() {
		t.Fatal("fail-fast must not be engaged by stale history")
	}

	// The reset must be a real reset: a fresh streak still engages normally.
	for i := 0; i < failFastThreshold; i++ {
		h.recordFailure()
		clk.advance(failFastGrace)
	}
	if err := h.gate(false); !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("a genuine fresh streak must still engage: got %v", err)
	}
}

// TestFailFastGatesRemoteOpsAndRecovers pins the WIRING: with fail-fast
// engaged on a real client, remote-bound ops (a read and the sync barrier)
// return ErrAuthorityUnreachable without burning their socket deadlines, and
// one successful round-trip restores normal service. (The mutation path rides
// the exact-once replay machinery, which has its own error surface; the
// read/barrier Do-paths are the deterministic gate-wiring proof.)
func TestFailFastGatesRemoteOpsAndRecovers(t *testing.T) {
	_, _, dial := startPipeAuthority(t)
	c := pipeClient(t, dial, "M-failfast")
	if live, err := c.EnsureExactSession(); err != nil || !live {
		t.Fatalf("session: live=%v err=%v", live, err)
	}
	if _, st, err := c.Create("ff.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	// Drive the shared health tracker to engaged deterministically via an
	// injected clock; the transport itself stays healthy so recovery can be
	// proven afterwards.
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	c.health.mu.Lock()
	c.health.now = clk.now
	c.health.onEngage = nil // no background prober: this test drives recovery itself
	c.health.mu.Unlock()
	for i := 0; i < failFastThreshold; i++ {
		c.health.recordFailure()
	}
	clk.advance(failFastGrace)
	if !c.FailFast() {
		_ = c.health.gate(false) // gate() evaluates lazily; consult it the way an op would
	}
	if !c.FailFast() {
		t.Fatal("precondition: fail-fast engaged")
	}

	// The read and the barrier fail fast (no socket-deadline burn).
	start := time.Now()
	if _, _, err := c.Getattr("ff.txt"); !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("gated read: %v, want ErrAuthorityUnreachable", err)
	}
	if err := c.Sync(); !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("gated sync barrier: %v, want ErrAuthorityUnreachable", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("gated ops took %v; they must fail fast, never burn the socket deadline", elapsed)
	}

	// One successful round-trip (the exempt recovery-conn shape) exits
	// fail-fast and restores service end to end.
	c.health.recordSuccess()
	if a, st, err := c.Getattr("ff.txt"); err != nil || st != OK || a == nil {
		t.Fatalf("read after recovery: attr=%v st=%d err=%v", a, st, err)
	}
	if c.FailFast() {
		t.Fatal("a successful round-trip must have cleared fail-fast")
	}
}

// TestFailFastAuthRejectionIsNotUnreachability pins that a DEFINITE auth
// rejection never feeds the fail-fast streak: the peer dialed and answered,
// so it is reachable — only the credential was refused. Without this, an idle
// mount's subscribe reconnect loop (rejected handshakes on an
// expired-but-renewable credential) would engage fail-fast and turn a mount
// whose pooled, already-authenticated connections still work into all-EIO.
func TestFailFastAuthRejectionIsNotUnreachability(t *testing.T) {
	h, clk := newFakeHealth()
	dial := func() (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			// The peer requires a different token: it answers the handshake
			// with the definite rejection byte (a REACHABLE peer's verdict).
			_ = secure.ServerHandshake(server, "expected-token")
			_ = server.Close()
		}()
		return client, nil
	}
	cn := &conn{transport: adaptLegacyTransport(dial), health: h, auth: func() installedCredential {
		return installedCredential{Credential: Credential{Token: "wrong-token"}}
	}}

	// Far more rejections than the threshold, spread past the grace: the
	// reconnect-loop shape that must NOT engage.
	for i := 0; i < failFastThreshold+2; i++ {
		err := cn.ensure()
		if !errors.Is(err, ErrSessionTokenRejected) {
			t.Fatalf("ensure against a rejecting peer: %v, want ErrSessionTokenRejected", err)
		}
		clk.advance(time.Second)
	}
	clk.advance(failFastGrace)
	if h.active() {
		t.Fatal("definite auth rejections engaged fail-fast; rejection is an answer from a reachable peer, not unreachability")
	}
	if err := h.gate(false); err != nil {
		t.Fatalf("gate after auth rejections must pass (pooled authenticated conns still work): %v", err)
	}

	// Contrast: genuine transport failures on the SAME tracker still engage.
	for i := 0; i < failFastThreshold; i++ {
		h.recordFailure()
	}
	clk.advance(failFastGrace)
	if err := h.gate(false); !errors.Is(err, ErrAuthorityUnreachable) {
		t.Fatalf("real transport failures must still engage: got %v", err)
	}
}

// TestFailFastNilHealthIsInert pins that health-less conns (constructed
// directly in tests) behave exactly as before.
func TestFailFastNilHealthIsInert(t *testing.T) {
	var h *connHealth
	h.recordFailure()
	h.recordSuccess()
	if h.active() {
		t.Fatal("nil health can never be active")
	}
	if err := h.gate(false); err != nil {
		t.Fatalf("nil health gate: %v", err)
	}
}
