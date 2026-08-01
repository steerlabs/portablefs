package fsproto

import (
	"testing"
	"time"
)

// TestVerdictIsNotCreditedToAGenerationTheHandshakeDidNotOffer pins the ONE
// SNAPSHOT rule.
//
// The generation used to be read from the health counter (ensureWithGate) and
// the token from the credential source (dialOnce) — two independent reads,
// microseconds apart, of state that changes together. A credential that arrived
// between them was therefore offered under its PREDECESSOR's generation tag,
// and the verdict it earned was filed against a credential nobody had ever
// presented. Installation writes the token before it bumps the counter, so the
// window was not hypothetical: it is the exact order SetAuthToken and the
// daemon's setCredential both produced.
//
// The rule is that a handshake carries ONE published (token, expiry,
// generation) value and its verdict names the generation IN that value. A
// credential that was never published names no generation at all (Gen 0) and
// can therefore speak for nothing.
func TestVerdictIsNotCreditedToAGenerationTheHandshakeDidNotOffer(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "T1")
	// The peer accepted "T1" for the pool's construction handshake and accepts
	// only "T2" from here on.
	c := credentialTestClient(t, "T1", func() string { return "T2" })

	// Open a fresh generation. It names the credential the client has published
	// — "T1" — and nothing has offered it since, so it is UNPROVEN.
	c.health.installCredential(nil)
	if !c.CredentialUnproven() {
		t.Fatal("precondition: a freshly installed generation is unproven")
	}

	// A handshake completes successfully while offering "T2": a credential that
	// reached the wire from outside the published value, which is exactly what
	// a separately-read counter cannot detect.
	cn := &conn{
		addrs:     c.addrs,
		tls:       c.tls,
		transport: c.transport,
		client:    c,
		health:    c.health,
		auth: func() installedCredential {
			return installedCredential{Credential: Credential{Token: "T2"}}
		},
	}
	if err := cn.ensure(); err != nil {
		t.Fatalf("the handshake offering T2 should have been accepted: %v", err)
	}
	cn.reset()

	if !c.CredentialUnproven() {
		t.Fatal("a handshake that offered a DIFFERENT credential was credited to " +
			"this generation: the generation is read separately from the token, so " +
			"a verdict can name a credential the handshake never presented")
	}
	if c.CredentialRejected() {
		t.Fatal("nothing refused anything")
	}
}

// TestHandshakeOfferingThePublishedCredentialProvesIt is the positive half. The
// one-snapshot rule must not make verdicts unclaimable: a handshake offering
// the credential the client actually published proves exactly that generation.
func TestHandshakeOfferingThePublishedCredentialProvesIt(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "T1")
	c := credentialTestClient(t, "T1", func() string { return "T2" })

	// One call publishes T2 AND opens the generation that names it.
	c.InstallCredential(Credential{Token: "T2"})

	cn := &conn{
		addrs:     c.addrs,
		tls:       c.tls,
		transport: c.transport,
		client:    c,
		health:    c.health,
		auth:      c.credentialForHandshake,
	}
	if err := cn.ensure(); err != nil {
		t.Fatalf("dial with the published credential: %v", err)
	}
	cn.reset()

	if c.CredentialUnproven() {
		t.Fatal("a handshake offering the PUBLISHED credential did not prove its " +
			"own generation")
	}
	if c.CredentialRejected() {
		t.Fatal("the peer accepted the credential")
	}
}

// TestInstallPublishesTokenExpiryAndGenerationTogether pins that the three
// facts move as one. Reading any of them without the others is what let a
// rotation change the token while the generation stood still (the FUSE lease
// path), and what let a hardening deadline belonging to one credential be
// applied to its successor.
func TestInstallPublishesTokenExpiryAndGenerationTogether(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "T1")
	c := credentialTestClient(t, "T1", func() string { return "T2" })

	before := c.credentialForHandshake()
	expiresAtMs := time.Now().Add(time.Hour).UnixMilli()
	c.InstallCredential(Credential{Token: "T2", ExpiresAtMs: expiresAtMs})

	after := c.credentialForHandshake()
	if after.Token != "T2" {
		t.Fatalf("published token = %q, want T2", after.Token)
	}
	if after.ExpiresAtMs != expiresAtMs {
		t.Fatalf("published expiry = %d, want %d", after.ExpiresAtMs, expiresAtMs)
	}
	if after.Gen != before.Gen+1 {
		t.Fatalf("one installation opened %d generations, want exactly 1",
			after.Gen-before.Gen)
	}
	if gotExpiry, gotGen := c.statedCredentialExpiry(); gotExpiry != expiresAtMs || gotGen != after.Gen {
		t.Fatalf("the hardening boundary read (%d, gen %d), want (%d, gen %d): an "+
			"expiry that does not travel with its own generation can be applied to "+
			"a credential its issuer never described",
			gotExpiry, gotGen, expiresAtMs, after.Gen)
	}
}
