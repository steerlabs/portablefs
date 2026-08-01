package fsproto

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/secure"
)

// credentialTestClient builds a client against a REACHABLE peer. It accepts the
// pool's construction handshake (the mount was healthy once) and then refuses
// every later one except accepted().
func credentialTestClient(t *testing.T, initial string, accepted func() string) *Client {
	t.Helper()
	var live atomic.Bool
	live.Store(true)
	dial := func() (net.Conn, error) {
		client, server := net.Pipe()
		expected := accepted()
		if live.Load() {
			expected = initial
		}
		go func() {
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
	live.Store(false)
	return c
}

// TestInvalidReplacementCredentialStaysRejected is the "healthy untested" lie.
//
// The credential verdict was one bool, and CredentialInstalled cleared it and
// then probed ONLY when the transport breaker happened to be engaged. So
// installing a SECOND INVALID credential moved the mount from
// credential-rejected to healthy with nothing having offered the replacement to
// anyone. Status reported a recovered mount; the next real operation found the
// truth.
//
// An installation is a new, UNPROVEN generation, and it is verified at once.
func TestInvalidReplacementCredentialStaysRejected(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "first-dead-token")
	c := credentialTestClient(t, "first-dead-token", func() string { return "the-only-valid-token" })

	// The pool's own handshake is refused: a rejection LATCHES wherever the
	// authority delivers it, not only in the prober.
	if err := c.probeAuthority(); err != probeCredentialRejected {
		t.Fatalf("probe = %d, want probeCredentialRejected", err)
	}
	if !c.CredentialRejected() {
		t.Fatal("a refused handshake did not latch the credential verdict")
	}

	// Install ANOTHER invalid credential.
	c.InstallCredential(Credential{Token: "second-dead-token"})
	if !waitFor(3*time.Second, func() bool { return !c.CredentialUnproven() }) {
		t.Fatal("the installed credential was never verified: installation " +
			"entered no verification at all, so the mount reports whatever the " +
			"previous verdict happened to be")
	}
	if !c.CredentialRejected() {
		t.Fatal("installing another INVALID credential reported the mount " +
			"HEALTHY and UNTESTED: clearing a verdict is not the same as proving " +
			"its replacement")
	}
}

// TestOrdinaryHandshakeRejectionLatchesTheVerdict pins that the rejection does
// not have to arrive on the prober's connection. Only the prober used to record
// one, so a mount whose ordinary pooled dials were being refused reported a
// perfectly healthy credential.
func TestOrdinaryHandshakeRejectionLatchesTheVerdict(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "dead-token")
	c := credentialTestClient(t, "dead-token", func() string { return "the-only-valid-token" })

	cn := &conn{
		addrs:     c.addrs,
		tls:       c.tls,
		auth:      c.credentialForHandshake,
		transport: c.transport,
		client:    c,
		health:    c.health,
	}
	if err := cn.ensure(); err == nil {
		t.Fatal("the ordinary pooled dial was not refused")
	}
	cn.reset()
	if !c.CredentialRejected() {
		t.Fatal("an ORDINARY handshake rejection was not recorded as a credential " +
			"rejection: only the prober's was, so a mount being refused on every " +
			"pooled dial reported a healthy credential")
	}
	if c.FailFast() {
		t.Fatal("a refusal is an ANSWER and must not trip the transport breaker")
	}
}

// TestRoundTripSuccessDoesNotProveTheCurrentCredential pins the third untruth:
// recordSuccess runs for every successful round trip, and a round trip travels
// an ALREADY-AUTHENTICATED connection whose handshake may predate the current
// credential entirely. Clearing the verdict there declared healthy a credential
// nothing had ever offered.
func TestRoundTripSuccessDoesNotProveTheCurrentCredential(t *testing.T) {
	h := newConnHealth()
	gen := h.generation()

	// The authority refuses the credential in use.
	h.recordCredentialRejected(gen)
	if !h.credentialDead() {
		t.Fatal("precondition: the verdict is latched")
	}

	// A round trip on a connection authenticated long ago succeeds.
	h.recordSuccess()
	if !h.credentialDead() {
		t.Fatal("a successful round trip on an already-authenticated connection " +
			"cleared the credential verdict without any handshake having offered " +
			"the current credential")
	}

	// A handshake for a STALE generation proves nothing about the current one.
	h.recordHandshakeSuccess(gen - 1)
	if !h.credentialDead() {
		t.Fatal("a handshake that offered a superseded credential cleared the " +
			"verdict for its successor")
	}

	// Only a handshake offering the CURRENT generation may clear it.
	h.recordHandshakeSuccess(h.generation())
	if h.credentialDead() {
		t.Fatal("a handshake offering the current credential did not clear it")
	}
}

// TestVerdictRacingAnInstallIsNotMisattributed pins that a handshake which
// started before an install cannot latch its verdict against the successor.
func TestVerdictRacingAnInstallIsNotMisattributed(t *testing.T) {
	h := newConnHealth()
	inFlight := h.generation()
	// The operator installs a fresh credential while that handshake is in the
	// air; it then comes back refused.
	h.installCredential(nil)
	h.recordCredentialRejected(inFlight)
	if h.credentialDead() {
		t.Fatal("a rejection of the PREVIOUS credential was attributed to the " +
			"credential installed while it was in flight")
	}
	if !h.credentialUnproven() {
		t.Fatal("the freshly installed credential must remain unproven")
	}
}
