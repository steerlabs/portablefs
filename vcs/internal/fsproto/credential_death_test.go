package fsproto

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/secure"
)

// TestCredentialDeathIsNotUnreachabilityAndStopsTheProbe is the round-4 live
// reproduction of the data plane's reachability lie.
//
// LIVE SHAPE: after the mount's ACCESS LEASE died, every data-plane operation
// surfaced `authority unreachable (fail-fast engaged after repeated transport
// failures)` — while a concurrent FRESH mount proved the authority perfectly
// healthy — and the reachability prober re-handshook with the SAME dead lease
// every two seconds for the life of the mount. 34-134 MiB of admitted backlog
// stranded for 30+ minutes with no parked-job engagement, because nothing in
// the mount ever reported a verdict an operator could act on.
//
// The two facts are different and the mount must not conflate them:
//
//	no answer at all       -> unreachable; the prober owns recovery.
//	an answer that REFUSES -> reachable, credential dead; only login +
//	                          remount can change it (the lease decision table).
//
// This test drives the second case through the real prober classification.
func TestCredentialDeathIsNotUnreachabilityAndStopsTheProbe(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "an-expired-lease")
	// The peer is REACHABLE throughout. It accepts the pool's construction
	// handshake and then — the lease having died — refuses every later one.
	var leaseAlive atomic.Bool
	leaseAlive.Store(true)
	dial := func() (net.Conn, error) {
		client, server := net.Pipe()
		accepted := leaseAlive.Load()
		go func() {
			expected := "the-only-valid-token"
			if accepted {
				expected = "an-expired-lease"
			}
			_ = secure.ServerHandshake(server, expected)
			_ = server.Close()
		}()
		return client, nil
	}
	c, err := DialWithTransport(1, dial)
	if err != nil {
		t.Fatalf("pipe client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	leaseAlive.Store(false)

	// Precondition: the transport breaker is engaged, exactly as it is after
	// the failure streak that precedes a lease death being noticed.
	clk := &fakeClock{t: time.Unix(1_900_000_000, 0)}
	c.health.mu.Lock()
	c.health.now = clk.now
	c.health.mu.Unlock()
	for i := 0; i < failFastThreshold; i++ {
		c.health.recordFailure()
	}
	clk.advance(failFastGrace)
	_ = c.health.gate(false)
	if !c.FailFast() {
		t.Fatal("precondition: fail-fast engaged")
	}

	if got := c.probeAuthority(); got != probeCredentialRejected {
		t.Fatalf(
			"probe against a REACHABLE authority refusing the credential "+
				"classified as %d, want probeCredentialRejected: reporting it "+
				"as unreachability is the live lie", got,
		)
	}

	// The prober must resolve it, not spin on it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.health.mu.Lock()
		c.health.probing = true
		c.health.mu.Unlock()
		c.runReachabilityProbe()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(
			"the reachability prober kept re-handshaking with a credential a " +
				"reachable authority had already refused; its lease cannot " +
				"recover and only login + remount can change the verdict",
		)
	}

	if c.FailFast() {
		t.Fatal(
			"the mount still claims the authority is UNREACHABLE after the " +
				"authority answered: a refusal is an answer, and the claim is false",
		)
	}
	if !c.CredentialRejected() {
		t.Fatal("the credential verdict was not latched, so nothing can surface it")
	}

	// Installing a fresh credential re-arms the probe: the verdict was about
	// the credential, not about the mount. It clears only once the installed
	// credential has actually been PROVED by a handshake — installation alone
	// proves nothing (see TestInvalidReplacementCredentialStaysRejected).
	c.SetAuthToken("the-only-valid-token")
	c.CredentialInstalled()
	if !waitFor(3*time.Second, func() bool { return !c.CredentialUnproven() }) {
		t.Fatal("the installed credential was never proved by a handshake: " +
			"installation must enter verification-pending and verify immediately")
	}
	if c.CredentialRejected() {
		t.Fatal("installing a VALID credential did not clear the previous " +
			"credential's verdict once its own handshake proved it")
	}
}

func waitFor(d time.Duration, ok func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ok()
}
