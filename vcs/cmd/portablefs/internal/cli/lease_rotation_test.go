package cli

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// leaseRotationAuthority serves an authority that accepts exactly one
// data-plane token, so a mount offering any other credential is definitively
// REFUSED rather than quietly tolerated.
func leaseRotationAuthority(t *testing.T, token string) string {
	t.Helper()
	t.Setenv("VCS_AUTH_TOKEN", token)
	wfs := newManagedTestFS(t, noBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	go func() { _ = fsproto.NewServer(wfs, wfs).Serve(ctx, ln) }()
	return ln.Addr().String()
}

// TestFUSELeaseRotationOpensANewCredentialGenerationAndVerifiesIt is the FUSE
// half of the credential-health story, and it was the missing half.
//
// The FSKit strategy pushed every rotated lease credential across the daemon
// boundary, where it became a real installation: a new generation, opened and
// then proved by its own handshake. The FUSE strategy pushed nothing. Its lease
// keeper wrote the rotated token into the live token source and stopped there,
// so the data plane went on offering a NEW token under the OLD generation's
// tag: no generation was opened, no verification ran, the old generation stayed
// "verified" on evidence earned by a credential that had since been replaced,
// and — because a pending state was never entered — the credential's own stated
// expiry could never harden it either. A rotated-to-dead credential on a FUSE
// mount was therefore indistinguishable from a healthy one.
//
// The rotation must reach the data plane, and it must reach it as an
// INSTALLATION: one new generation, verified at once against the authority.
func TestFUSELeaseRotationOpensANewCredentialGenerationAndVerifiesIt(t *testing.T) {
	const good = "lease-token-1"
	addr := leaseRotationAuthority(t, good)

	expiresAtMs := time.Now().Add(time.Hour).UnixMilli()
	tokens := &sessionTokenSource{token: good, expiresAtMs: expiresAtMs}

	// Exactly the seam mountFUSE builds: the live lease source seeds the dial.
	seedToken, seedExpiry := tokens.get()
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr:             addr,
		Pool:             2,
		Owner:            "portablefs-lease-rotation-test",
		WALDir:           t.TempDir(),
		VolumeID:         "lease-rotation-test",
		CredentialSource: tokens.get,
	})
	if err != nil {
		t.Fatalf("dial authority: %v", err)
	}
	t.Cleanup(func() { _ = vol.Close() })
	tokens.bindDataPlane(vol, seedToken, seedExpiry)

	if vol.CredentialUnproven() || vol.CredentialExpired() {
		t.Fatal("precondition: the pool's construction handshake proved the seeded " +
			"lease credential")
	}
	before := vol.CredentialGeneration()

	// The lease keeper renews, and the authority has rotated underneath: the
	// replacement credential is one this authority refuses.
	keeper := newLeaseKeeper(nil, tokens, leaseState{
		AccessLeaseID: "lease-1",
		AccessToken:   good,
		ExpiresAtMs:   expiresAtMs,
	}, nil)
	keeper.applyUpdate(leaseState{
		AccessLeaseID: "lease-1",
		AccessToken:   "lease-token-2-which-this-authority-refuses",
		ExpiresAtMs:   time.Now().Add(2 * time.Hour).UnixMilli(),
	})

	if opened := vol.CredentialGeneration() - before; opened != 1 {
		t.Fatalf("a lease rotation opened %d credential generations, want exactly 1: "+
			"the FUSE keeper wrote the rotated token into the token source and told "+
			"the data plane nothing, so reconnects offered the new credential under "+
			"the old generation's tag and no verification ever ran", opened)
	}

	// Verification must actually run, and it must reach a verdict: the authority
	// is reachable and answers this credential with a refusal.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !vol.CredentialExpired() {
		time.Sleep(10 * time.Millisecond)
	}
	if !vol.CredentialExpired() {
		t.Fatalf("the rotated credential was never offered to the authority: "+
			"unproven=%v expired=%v. Installation must verify at once, or a mount "+
			"rotated onto a dead credential reports itself healthy until some "+
			"unrelated operation happens to discover the truth",
			vol.CredentialUnproven(), vol.CredentialExpired())
	}
	if vol.CredentialUnproven() {
		t.Fatal("a credential the authority definitively refused must not also " +
			"report as untested: the two verdicts call for different repairs")
	}
}

// TestLeaseRotationInstallsIntoEveryBoundDataPlane pins that the installation
// hangs off the keeper's own choke point rather than off a per-strategy hook.
//
// The FUSE branch simply forgot to store the strategy hook the FSKit branch
// stored, and nothing anywhere failed as a result. Binding the data plane to
// the credential SOURCE — which every strategy's keeper already writes through
// on every renewal — removes the whole class of bug: there is no per-strategy
// step left to forget.
func TestLeaseRotationInstallsIntoEveryBoundDataPlane(t *testing.T) {
	tokens := &sessionTokenSource{token: "t1", expiresAtMs: 111}
	var first, second recordingInstaller
	tokens.bindDataPlane(&first, "t1", 111)
	tokens.bindDataPlane(&second, "t1", 111)

	keeper := newLeaseKeeper(nil, tokens, leaseState{AccessToken: "t1", ExpiresAtMs: 111}, nil)
	keeper.applyUpdate(leaseState{AccessToken: "t2", ExpiresAtMs: 222})

	for name, got := range map[string][]installedPair{"first": first.installs, "second": second.installs} {
		if len(got) != 1 || got[0] != (installedPair{"t2", 222}) {
			t.Fatalf("%s data plane received %v, want exactly one install of "+
				"(t2, 222): a rotation that does not reach the data plane leaves it "+
				"offering a credential no generation describes", name, got)
		}
	}
}

// TestBindingADataPlaneDoesNotDisturbACurrentOne pins the precondition that
// keeps a healthy mount out of the unproven state: binding must not install a
// credential the data plane was already seeded with and has already proved.
// Installing one anyway would open a generation the completed construction
// handshake could no longer speak for, and nothing in a quiet mount would go on
// to prove it — the exact noise that made the unproven state unreportable.
func TestBindingADataPlaneDoesNotDisturbACurrentOne(t *testing.T) {
	tokens := &sessionTokenSource{token: "t1", expiresAtMs: 111}
	var current recordingInstaller
	tokens.bindDataPlane(&current, "t1", 111)
	if len(current.installs) != 0 {
		t.Fatalf("binding an already-current data plane installed %v", current.installs)
	}

	// A rotation that landed between the seed and the bind is NOT lost: the
	// data plane is holding a credential the lease has already replaced, and
	// nothing else would ever tell it.
	var stale recordingInstaller
	tokens.setToken("t2", 222)
	tokens.bindDataPlane(&stale, "t1", 111)
	if len(stale.installs) != 1 || stale.installs[0] != (installedPair{"t2", 222}) {
		t.Fatalf("binding a data plane seeded with a superseded credential "+
			"installed %v, want exactly one install of (t2, 222)", stale.installs)
	}
}

type installedPair struct {
	token       string
	expiresAtMs int64
}

type recordingInstaller struct{ installs []installedPair }

func (r *recordingInstaller) InstallCredential(token string, expiresAtMs int64) {
	r.installs = append(r.installs, installedPair{token, expiresAtMs})
}
