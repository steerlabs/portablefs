package fsproto

import (
	"sync/atomic"
	"testing"
	"time"
)

// The UNPROVEN credential state, and the boundary that ends it.
//
// A credential is unproven when no handshake has either accepted or refused
// it. Every install opens one (connHealth.installCredential), and exactly one
// production interleaving keeps it open indefinitely: the data-plane router or
// the authority closes the connection CLEANLY after reading the token frame
// and before answering the ack byte. That produces
//
//   - no ack 1, so nothing latches a credential verdict;
//   - no transport error, so nothing counts a failure, so the fail-fast
//     breaker never engages and the reachability prober never runs;
//   - one single verification handshake, which is where the story used to end.
//
// So the mount sat with an untested credential, reported itself perfectly
// healthy, and stayed that way for its whole life. These tests pin both halves
// of the fix: the state is HONEST (unproven is neither healthy nor dead) and it
// is BOUNDED (past the credential's own stated expiry it hardens to dead).

// TestCleanEOFBeforeAckLeavesTheCredentialUnprovenAndKeepsProbing drives the
// exact interleaving through the real router fake: a peer that hangs up after
// the token frame, forever.
//
// Two things must hold, and neither did.
//
// FIRST, the mount must not call the credential healthy. A clean EOF proves
// nothing in either direction (see ErrCredentialRefused): it must not latch a
// rejection — that told operators to fix a credential that was fine — and it
// must not be mistaken for verification either.
//
// SECOND, verification must actually keep trying. It used to be ONE probe:
// CredentialInstalled fired a single handshake, the clean EOF returned
// "unreachable" without engaging the breaker, and because runReachabilityProbe
// exits immediately when the breaker is not engaged, nothing re-offered the
// credential ever again. A router that is rolling for thirty seconds
// permanently poisoned the mount's credential state.
func TestCleanEOFBeforeAckLeavesTheCredentialUnprovenAndKeepsProbing(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")

	// The credential states a deadline far in the future: there IS a boundary
	// to converge inside, so verification is entitled to keep offering.
	expiresAt := time.Now().Add(time.Hour).UnixMilli()
	var token atomic.Value
	token.Store("tok-epoch1")
	cli, err := DialTLSCredential(router.addr(), 1, nil, func() Credential {
		tok, _ := token.Load().(string)
		return Credential{Token: tok, ExpiresAtMs: expiresAt}
	})
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if cli.CredentialUnproven() {
		t.Fatal("precondition: the pool's own construction handshake PROVED the " +
			"credential it dialed with; a healthy mount must not report an " +
			"unproven credential")
	}

	// From here the router reads the token frame and closes cleanly, with no
	// ack at all — a manager rolling, an authority shutting down mid-handshake.
	router.setCloseBeforeAck(true)
	// The router now refuses this token — but by hanging up rather than by
	// answering ack 1. On the wire the two are only distinguishable by the
	// MISSING ack, which is exactly what makes this state unresolvable.
	router.rotate("tok-epoch2")

	before := router.rejected.Load()
	// The credential is re-installed with its issuer's stated deadline intact:
	// that deadline is the boundary the verification loop converges inside.
	cli.InstallCredential(Credential{Token: "tok-epoch1", ExpiresAtMs: expiresAt})

	if !waitFor(3*time.Second, func() bool { return router.rejected.Load() > before }) {
		t.Fatal("installing a credential did not offer it to the authority at all")
	}
	// More than one offer: the credential is being RE-probed, not probed once
	// and abandoned. The peer answers nothing, so only repetition can ever
	// resolve this state.
	if !waitFor(3*credentialVerifyInterval+2*time.Second, func() bool {
		return router.rejected.Load() >= before+3
	}) {
		t.Fatalf("a clean-EOF-before-ack streak was probed %d time(s) and then "+
			"abandoned: nothing else in the mount re-offers the credential "+
			"(the breaker never engages on a clean EOF, so the reachability "+
			"prober never runs), so the credential stays untested forever",
			router.rejected.Load()-before)
	}

	if cli.CredentialRejected() {
		t.Fatal("a clean EOF before any ack is NOT a refusal: latching a dead " +
			"credential verdict on it sends the operator to re-authenticate a " +
			"credential nothing has found fault with")
	}
	if cli.FailFast() {
		t.Fatal("a clean EOF is not a transport failure and must not engage the " +
			"reachability breaker")
	}
	if !cli.CredentialUnproven() {
		t.Fatal("the credential was never accepted or refused by anyone, yet the " +
			"mount reports it as proven: an UNTESTED credential is not a healthy one")
	}
}

// TestUnprovenCredentialHardensAtItsOwnStatedExpiry pins the boundary.
//
// credPending carried no timestamp, no deadline and no TTL, so "we never found
// out" was a state with no exit. The exit is the credential's OWN stated
// expiry — the deadline its issuer already published, exactly the bound the
// lease keeper uses for unresolved renewals, and never a retry budget invented
// down here. Past it the lease is over by its own terms, so the unproven state
// resolves to the same definite verdict a refusal would have latched.
func TestUnprovenCredentialHardensAtItsOwnStatedExpiry(t *testing.T) {
	h, clk := newFakeHealth()
	expiresAt := clk.t.Add(10 * time.Minute)
	// The expiry travels with the generation it belongs to, exactly as the
	// client's published credential does.
	h.credExpiry = func() (int64, uint64) { return expiresAt.UnixMilli(), h.generation() }

	// A fresh install: unproven, and inside its stated life.
	h.installCredential(nil)
	if !h.credentialUnproven() {
		t.Fatal("precondition: an installed credential is unproven until a " +
			"handshake classifies it")
	}
	if h.credentialDead() {
		t.Fatal("an unproven credential inside its own stated life is not dead: " +
			"nobody has refused it and it has not run out")
	}

	// One second before the stated expiry it is still merely unproven.
	clk.advance(10*time.Minute - time.Second)
	if !h.credentialUnproven() || h.credentialDead() {
		t.Fatalf("hardened early: unproven=%v dead=%v", h.credentialUnproven(), h.credentialDead())
	}

	// At the stated expiry the credential is over by its issuer's own terms.
	clk.advance(time.Second)
	if !h.credentialDead() {
		t.Fatal("an unproven credential outlived the deadline its own issuer " +
			"stated for it and STILL reported as merely pending: the state had " +
			"no boundary at all, so a mount could sit in it forever")
	}
	if h.credentialUnproven() {
		t.Fatal("dead and unproven must be DISJOINT: they call for different " +
			"operator actions, and a mount reporting both says nothing at all")
	}

	// A handshake that proves the credential clears both, expiry or not: the
	// authority's answer outranks a deadline nobody consulted it about.
	h.recordHandshakeSuccess(h.generation())
	if h.credentialDead() || h.credentialUnproven() {
		t.Fatal("a completed handshake for the current generation must clear the " +
			"pending state, and with it the hardening that only applies to it")
	}
}

// TestUnprovenCredentialWithNoStatedExpiryNeverHardens is the compatibility
// half, and it is not a formality.
//
// ExpiresAtMs == 0 means "the issuer stated NO deadline" — it does not mean
// "expired at the unix epoch". Static --addr mounts, VCS_AUTH_TOKEN, embedders
// and every caller written before the field existed all land on zero. Reading
// that zero as a deadline would flip every one of them to credential-expired
// on the spot and send their operators to re-authenticate credentials that are
// perfectly good. Nothing may harden that nobody put a clock on.
func TestUnprovenCredentialWithNoStatedExpiryNeverHardens(t *testing.T) {
	h, clk := newFakeHealth()
	// The default: no credExpiry hook at all (an embedder-built health), which
	// must behave identically to a source that states zero.
	for _, expiry := range []func() (int64, uint64){nil, func() (int64, uint64) { return 0, h.generation() }} {
		h.credExpiry = expiry
		h.installCredential(nil)

		clk.advance(100 * 365 * 24 * time.Hour)
		if h.credentialDead() {
			t.Fatal("a credential whose issuer stated NO deadline hardened anyway: " +
				"a zero expiry was read as the unix epoch, so every pre-expiry " +
				"caller starts reporting a dead credential it has no reason to")
		}
		if !h.credentialUnproven() {
			t.Fatal("an unproven credential with no stated deadline stays unproven: " +
				"it is still untested, and there is no boundary to end it")
		}
	}
}

// TestCredentialVerificationWithNoStatedExpiryProbesExactlyOnce is the other
// half of the compatibility posture: the bounded re-probe loop exists BECAUSE
// there is a boundary to converge inside. Without a stated deadline there is
// none, so verification keeps its old single-probe shape rather than acquiring
// an open-ended retry loop invented at this layer — the same rule that stops
// the lease keeper from replaying past a lease's own expiry.
func TestCredentialVerificationWithNoStatedExpiryProbesExactlyOnce(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")

	var token atomic.Value
	token.Store("tok-epoch1")
	cli, err := DialTLSCredential(router.addr(), 1, nil, func() Credential {
		tok, _ := token.Load().(string)
		return Credential{Token: tok} // NO stated deadline.
	})
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()

	router.setCloseBeforeAck(true)
	// The router now refuses this token — but by hanging up rather than by
	// answering ack 1. On the wire the two are only distinguishable by the
	// MISSING ack, which is exactly what makes this state unresolvable.
	router.rotate("tok-epoch2")

	before := router.rejected.Load()
	// Re-installed with NO stated deadline: no boundary, so no loop.
	cli.InstallCredential(Credential{Token: "tok-epoch1"})
	if !waitFor(3*time.Second, func() bool { return router.rejected.Load() > before }) {
		t.Fatal("installing a credential did not offer it to the authority at all")
	}
	time.Sleep(2*credentialVerifyInterval + 500*time.Millisecond)
	if got := router.rejected.Load() - before; got != 1 {
		t.Fatalf("verification offered a deadline-less credential %d times: with "+
			"no stated expiry there is no boundary to converge inside, so this "+
			"must keep the old single-probe behaviour exactly", got)
	}
	if !cli.CredentialUnproven() {
		t.Fatal("the credential is still untested and must still say so")
	}
}
