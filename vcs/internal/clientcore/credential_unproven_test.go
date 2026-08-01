package clientcore

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
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

// TestOneCredentialInstallationOpensExactlyOneGeneration pins the collapse.
//
// Installation used to be reachable through two methods that both bumped the
// generation counter — a token setter and a separate "credential installed"
// notification — and the daemon's rotation path called BOTH. One logical
// rotation therefore opened two generations. The first was published to nobody,
// superseded microseconds later, and unproven by construction: a generation no
// handshake could ever classify because it was gone before any dial read it.
//
// One installation, one generation, one verification.
func TestOneCredentialInstallationOpensExactlyOneGeneration(t *testing.T) {
	addr := serveCore(t)
	expiresAtMs := time.Now().Add(time.Hour).UnixMilli()
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:            "credential-generation",
		WALDir:           t.TempDir(),
		CredentialSource: func() (string, int64) { return "", expiresAtMs },
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })

	before := v.CredentialGeneration()
	v.InstallCredential("", expiresAtMs)
	if opened := v.CredentialGeneration() - before; opened != 1 {
		t.Fatalf("one credential installation opened %d generations, want exactly 1: "+
			"a rotation that bumps the counter twice publishes an intermediate "+
			"generation nothing will ever offer or prove", opened)
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
//
// The authority is deliberately made unanswerable before the rotation. It used
// to be enough to rotate against a live, accepting authority, because nothing
// verified an installed credential and the pending state simply persisted —
// which is the very bug this file's siblings exist to close. With installation
// now verifying, a live authority would ANSWER, and answering is the one thing
// that ends the unproven state. Testing "unproven" means testing what happens
// when nobody answers.
func TestVolumeSurfacesTheUnprovenCredentialSeparatelyFromTheExpiredOne(t *testing.T) {
	fs := newManagedTestFS(t, testBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := fsproto.NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()

	expiresAtMs := time.Now().Add(time.Hour).UnixMilli()
	v := dialCoreNoCleanup(t, ln.Addr().String(), Options{
		Owner:            "credential-unproven",
		WALDir:           t.TempDir(),
		CredentialSource: func() (string, int64) { return "", expiresAtMs },
	})
	t.Cleanup(func() { _, _ = v.CloseJournalDurable() })

	// From here the authority answers nothing at all: no ack, no refusal.
	cancel()
	_ = ln.Close()

	// A renewal opens a new generation, and no handshake can classify it.
	v.InstallCredential("rotated-and-unanswerable", expiresAtMs)

	if !v.CredentialUnproven() {
		t.Fatal("a renewed credential that no handshake has accepted or refused " +
			"is UNTESTED, and the volume must say so rather than let the mount " +
			"report itself recovered on it")
	}
	if v.CredentialExpired() {
		t.Fatal("an untested credential is not a proven-dead one: overloading the " +
			"expired word for both sends the operator to the wrong repair")
	}

	// It must STAY unproven while the authority stays silent: the verification
	// loop re-offers the credential, and a re-offer that gets no answer resolves
	// nothing in either direction.
	time.Sleep(300 * time.Millisecond)
	if !v.CredentialUnproven() || v.CredentialExpired() {
		t.Fatalf("after re-offering into silence: unproven=%v expired=%v; an "+
			"unanswered credential is neither proven nor dead",
			v.CredentialUnproven(), v.CredentialExpired())
	}
}
