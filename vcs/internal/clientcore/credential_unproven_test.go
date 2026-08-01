package clientcore

import (
	"testing"
	"time"
)

// TestFreshlyDialedVolumeReportsNoCredentialFault pins the precondition that
// makes the UNPROVEN state reportable at all.
//
// Dial used to pass the credential source to the pool AND install it again
// afterwards. The pool's construction handshakes had already proved that exact
// source, but the second installation opened a NEW generation, and a new
// generation is unproven by definition. Nothing in a healthy, quiet mount goes
// on to re-handshake, so a perfectly good volume could report an untested
// credential — which is why surfacing the state to operators would have been
// pure noise. One installation, proved by the dial it configures.
func TestFreshlyDialedVolumeReportsNoCredentialFault(t *testing.T) {
	addr := serveCore(t)
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "credential-precondition",
		WALDir: t.TempDir(),
		CredentialSource: func() (string, int64) {
			return "", time.Now().Add(time.Hour).UnixMilli()
		},
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })

	if v.CredentialUnproven() {
		t.Fatal("a volume whose own construction handshakes accepted its credential " +
			"reports it as UNPROVEN: the source was installed a second time after " +
			"the dial that had already proved it, opening a generation nothing " +
			"would ever prove")
	}
	if v.CredentialExpired() {
		t.Fatal("a working credential must not report as expired")
	}
}

// TestVolumeSurfacesTheUnprovenCredentialSeparatelyFromTheExpiredOne pins that
// clientcore hands the frontend THREE distinct credential answers, not two.
//
// Before, a Volume could only say "expired" (a proven refusal) or nothing at
// all, and an untested credential fell into "nothing at all" — reported as a
// healthy mount. The two faults are not interchangeable: expired is answered
// by logging in again, unproven is answered by looking at whatever is tearing
// the handshake down before the authority replies.
func TestVolumeSurfacesTheUnprovenCredentialSeparatelyFromTheExpiredOne(t *testing.T) {
	addr := serveCore(t)
	expiresAtMs := time.Now().Add(time.Hour).UnixMilli()
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:            "credential-unproven",
		WALDir:           t.TempDir(),
		CredentialSource: func() (string, int64) { return "", expiresAtMs },
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })

	// A renewal opens a new generation. Nothing has offered it yet.
	v.RenewCredential("")
	if !v.CredentialUnproven() {
		t.Fatal("a renewed credential that no handshake has accepted or refused " +
			"is UNTESTED, and the volume must say so rather than let the mount " +
			"report itself recovered on it")
	}
	if v.CredentialExpired() {
		t.Fatal("an untested credential is not a proven-dead one: overloading the " +
			"expired word for both sends the operator to the wrong repair")
	}
}
