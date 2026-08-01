package portablefsd

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The daemon's attach status is where a credential fault becomes something an
// operator can see: `portablefs mounts` and the extension read nothing else.
// Two of the three credential states had no coverage here at all — the
// REJECTED transition was written and never tested, and the UNPROVEN state was
// not surfaced by any code path, so a mount whose credential nobody had ever
// accepted or refused reported itself perfectly live.

// credentialStatusAttach starts a real attach against a real authority with a
// working credential. Every test below then breaks exactly one thing about the
// credential and reads the status the operator would read.
func credentialStatusAttach(t *testing.T, key string) *attach {
	t.Helper()
	// The authority requires a token, so a wrong one earns a REAL ack-1
	// refusal from a REACHABLE peer — the only thing entitled to latch the
	// terminal credential verdict.
	t.Setenv("VCS_AUTH_TOKEN", "good-credential")
	authority := serveAuthority(t)
	a := newAttach("att-"+key, key, ensureAttachRequest{
		VolumeID:           "vol-" + key,
		Branch:             "main",
		MountPath:          "/Volumes/" + key,
		AuthorityURL:       authority,
		DataPlaneTransport: "plaintext",
		AuthToken:          "good-credential",
	}, privateTestDir(t))
	if err := a.start(context.Background()); err != nil {
		t.Fatalf("start attach: %v", err)
	}
	t.Cleanup(func() { _, _ = a.detach(context.Background(), true) })

	// PRECONDITION, and a regression guard in its own right. A healthy mount
	// must report NO credential fault. It did not always: clientcore dialed
	// the pool with the credential source and then installed the very same
	// source again afterwards, opening a fresh generation that the completed
	// construction handshakes had already proved and that nothing would ever
	// prove again. Every mount alive was permanently "unproven", which is
	// precisely why the state could not be surfaced to anyone.
	st := a.status()
	if st.Credential != "" {
		t.Fatalf("a freshly attached, working mount reports credential=%q: an "+
			"honest mount reports no credential fault at all", st.Credential)
	}
	if st.State == "degraded" {
		t.Fatalf("a freshly attached, working mount is degraded: %s", st.LastError)
	}
	return a
}

// TestDaemonStatusReportsRejectedCredentialAsDegraded covers the transition
// that registry.status() has always performed and that nothing tested: a
// REACHABLE authority answering ack 1 makes the attach degraded, with the
// login-and-remount remedy, and now names the fault so a program can branch on
// it instead of parsing prose.
func TestDaemonStatusReportsRejectedCredentialAsDegraded(t *testing.T) {
	a := credentialStatusAttach(t, "CredentialRejected")

	// A dead credential, offered for real and refused for real. ONE call: the
	// credential setter is the installation — it opens the generation and
	// verifies it. It used to need a second, separate notification to make the
	// installation real, and calling both bumped the generation twice.
	a.setCredential("revoked-credential", 0)

	if !waitForStatus(3*time.Second, a, func(st attachStatus) bool {
		return st.Credential == credentialStateRejected
	}) {
		t.Fatalf("a credential a reachable authority REFUSED is not reported as "+
			"rejected: state=%q credential=%q lastError=%q",
			a.status().State, a.status().Credential, a.status().LastError)
	}
	st := a.status()
	if st.State != "degraded" {
		t.Fatalf("state = %q, want degraded", st.State)
	}
	if !strings.Contains(st.LastError, "portablefs login") {
		t.Fatalf("a proven-dead credential must carry the one remedy that works: %q", st.LastError)
	}
}

// TestDaemonStatusReportsUnprovenCredentialAsDegradedPendingVerification is
// the state that had no word at all.
//
// A credential that has been installed and that NO handshake has accepted or
// refused is untested. The mount used to report it as live, because nothing
// consulted CredentialUnproven — the predicate existed with zero non-test
// callers — and because the interleaving that produces it (a peer closing
// cleanly before the ack) latches no verdict and trips no breaker. Status must
// say so, and must say it SEPARATELY from rejection: the remedies differ, and
// telling someone to log in again fixes nothing when the authority never
// answered in the first place.
func TestDaemonStatusReportsUnprovenCredentialAsDegradedPendingVerification(t *testing.T) {
	a := credentialStatusAttach(t, "CredentialUnproven")

	// A renewal installs a new generation. Until a handshake offers it and the
	// authority answers, it is UNPROVEN — and its issuer says it is good for
	// another hour, so it has not run out either.
	a.setCredential("renewed-credential", time.Now().Add(time.Hour).UnixMilli())

	st := a.status()
	if st.Credential != credentialStatePendingVerification {
		t.Fatalf("an installed credential that NOTHING has accepted or refused is "+
			"reported as credential=%q: an untested credential is not a healthy "+
			"one, and a mount must not claim to be recovered on it", st.Credential)
	}
	if st.State != "degraded" {
		t.Fatalf("state = %q, want degraded: the mount is not known healthy", st.State)
	}
	if st.Credential == credentialStateRejected {
		t.Fatal("unproven must never be reported as rejected")
	}
	if !strings.Contains(st.LastError, "UNPROVEN") {
		t.Fatalf("the reason must say the credential is untested, not that it is "+
			"expired: %q", st.LastError)
	}
	if strings.Contains(st.LastError, "portablefs login") {
		t.Fatalf("an UNPROVEN credential must not send the operator to "+
			"re-authenticate: nothing has found fault with the credential, the "+
			"handshake is being torn down before the authority answers: %q", st.LastError)
	}
}

// TestDaemonStatusHardensAnUnprovenCredentialPastItsStatedExpiry is the
// boundary, seen from the operator's end.
//
// The unproven state had no timestamp, no deadline and no TTL: a mount could
// sit in it forever. The deadline existed one layer up the whole time — the
// access lease's own ExpiresAtMs — and simply never reached the data plane.
// Now it travels with the credential, and past it "we never found out"
// resolves to the same definite verdict a refusal would have latched.
func TestDaemonStatusHardensAnUnprovenCredentialPastItsStatedExpiry(t *testing.T) {
	a := credentialStatusAttach(t, "CredentialHardens")

	// Same untested credential — but its issuer says it stopped being valid an
	// hour ago. There is nothing left to verify.
	a.setCredential("stale-credential", time.Now().Add(-time.Hour).UnixMilli())

	st := a.status()
	if st.Credential != credentialStateRejected {
		t.Fatalf("an unproven credential past the deadline its OWN issuer stated "+
			"still reports credential=%q: the state has a boundary now, and past "+
			"it the mount owes the operator a definite answer", st.Credential)
	}
	if st.State != "degraded" {
		t.Fatalf("state = %q, want degraded", st.State)
	}
}

// TestDaemonStatusNeverHardensACredentialWithNoStatedExpiry is the
// compatibility posture at the daemon boundary.
//
// authTokenExpiresAtMs is additive and optional. An older CLI omits it, and
// direct --addr mounts never had a lease to state one. Those callers land on
// zero, zero means "no deadline was stated", and reading it as one would flip
// every one of them to a dead credential the moment they renewed.
func TestDaemonStatusNeverHardensACredentialWithNoStatedExpiry(t *testing.T) {
	a := credentialStatusAttach(t, "CredentialNoDeadline")

	// An older CLI: a credential and no statement about its lifetime.
	a.setCredential("credential-without-a-deadline", 0)

	st := a.status()
	if st.Credential == credentialStateRejected {
		t.Fatal("a credential whose issuer stated NO deadline was hardened into a " +
			"dead one: a zero expiry was read as the unix epoch, so every older " +
			"CLI starts reporting revoked credentials that are perfectly good")
	}
	if st.Credential != credentialStatePendingVerification {
		t.Fatalf("credential = %q: the credential is still untested, and saying so "+
			"is the honest answer even when nothing bounds it", st.Credential)
	}
}

func waitForStatus(d time.Duration, a *attach, ok func(attachStatus) bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok(a.status()) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ok(a.status())
}
