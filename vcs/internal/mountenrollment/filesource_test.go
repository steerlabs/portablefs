package mountenrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
)

const testSessionID = "c2Vzc2lvbi1pZC0xMjM0NQ"

type mintedCapability struct {
	key ed25519.PrivateKey
	t   *testing.T
}

func newMint(t *testing.T) *mintedCapability {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate capability key: %v", err)
	}
	return &mintedCapability{key: key, t: t}
}

// attach mints the capability a mount is started with: no session, no sequence.
func (mint *mintedCapability) attach(volumeID string, access []string, expires time.Time) []byte {
	mint.t.Helper()
	return mint.sign(volumecap.Claims{
		VolumeID: volumeID, Subject: "mount", Access: access, Nonce: "nonce",
		NotBefore: expires.Add(-time.Hour).Unix(), Expires: expires.Unix(),
		PeerSPKI: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
}

// grant mints what a credential manager rotates in: the same capability format,
// bound to one exact session and sequence.
func (mint *mintedCapability) grant(volumeID, sessionID string, sequence uint64, access []string, expires time.Time) []byte {
	mint.t.Helper()
	return mint.sign(volumecap.Claims{
		VolumeID: volumeID, Subject: "mount", Access: access, Nonce: "nonce",
		NotBefore: expires.Add(-time.Hour).Unix(), Expires: expires.Unix(),
		PeerSPKI:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		SessionID: sessionID, Sequence: sequence,
	})
}

func (mint *mintedCapability) sign(claims volumecap.Claims) []byte {
	mint.t.Helper()
	token, err := volumecap.Sign(mint.key, claims)
	if err != nil {
		mint.t.Fatalf("sign capability: %v", err)
	}
	return token
}

func rotate(t *testing.T, path string, token []byte) {
	t.Helper()
	// A credential manager replaces the file atomically; the mount must observe
	// whole credentials only.
	staging := path + ".next"
	if err := os.WriteFile(staging, token, 0o600); err != nil {
		t.Fatalf("write capability: %v", err)
	}
	if err := os.Chmod(staging, 0o600); err != nil {
		t.Fatalf("chmod capability: %v", err)
	}
	if err := os.Rename(staging, path); err != nil {
		t.Fatalf("rotate capability: %v", err)
	}
}

func newTestSource(t *testing.T, attach []byte) (*FileGrantSource, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.token")
	rotate(t, path, attach)
	source, err := NewFileGrantSource(path, attach, nil)
	if err != nil {
		t.Fatalf("NewFileGrantSource: %v", err)
	}
	return source, path
}

func TestFileGrantSourceReturnsTheRotatedCapabilityAndItsOwnDeadline(t *testing.T) {
	mint := newMint(t)
	expires := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	source, path := newTestSource(t, mint.attach("vol", []string{"read", "write"}, expires))
	renewed := mint.grant("vol", testSessionID, 1, []string{"read", "write"}, expires.Add(10*time.Minute))
	rotate(t, path, renewed)
	grant, err := source.Refresh(context.Background(), testSessionID, 1)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if grant.Capability != string(renewed) {
		t.Fatalf("capability = %q, want the rotated file's exact bytes", grant.Capability)
	}
	if grant.ExpiresUnix != expires.Add(10*time.Minute).Unix() {
		t.Fatalf("expires = %d, want the rotated capability's own expiry %d", grant.ExpiresUnix, expires.Add(10*time.Minute).Unix())
	}
	if grant.SessionID != testSessionID || grant.Sequence != 1 || grant.VolumeID != "vol" {
		t.Fatalf("grant identity = %q %d %q", grant.SessionID, grant.Sequence, grant.VolumeID)
	}
	if grant.ClientCertificatePEM != "" {
		t.Fatalf("file rotation carries no replacement certificate, got %q", grant.ClientCertificatePEM)
	}
}

func TestFileGrantSourceRefusesAnUnrotatedFileWithoutEndingTheMount(t *testing.T) {
	mint := newMint(t)
	expires := time.Now().Add(10 * time.Minute)
	source, _ := newTestSource(t, mint.attach("vol", []string{"read", "write"}, expires))
	_, err := source.Refresh(context.Background(), testSessionID, 1)
	if err == nil {
		t.Fatal("an attach capability is not a grant for sequence 1")
	}
	if !strings.Contains(err.Error(), "sequence 1") {
		t.Fatalf("error = %v, want it to name the sequence the credential manager must mint", err)
	}
	if errors.Is(err, ErrDefinitiveDenial) {
		t.Fatal("a missing rotation is retryable until the renewer's cutoff, not a definitive denial")
	}
}

func TestFileGrantSourceRetriesAMissingOrCorruptFileThenAcceptsTheRotation(t *testing.T) {
	mint := newMint(t)
	expires := time.Now().Add(10 * time.Minute)
	attach := mint.attach("vol", []string{"read"}, expires)
	source, path := newTestSource(t, attach)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove capability: %v", err)
	}
	if _, err := source.Refresh(context.Background(), testSessionID, 1); err == nil {
		t.Fatal("a missing capability file must fail")
	}
	rotate(t, path, []byte("v1.not-a-capability"))
	if _, err := source.Refresh(context.Background(), testSessionID, 1); err == nil {
		t.Fatal("a corrupt capability file must fail")
	}
	rotate(t, path, mint.grant("vol", testSessionID, 1, []string{"read"}, expires.Add(time.Minute)))
	if _, err := source.Refresh(context.Background(), testSessionID, 1); err != nil {
		t.Fatalf("Refresh after rotation: %v", err)
	}
}

func TestFileGrantSourcePresentsOneExactTokenPerSequence(t *testing.T) {
	mint := newMint(t)
	expires := time.Now().Add(10 * time.Minute)
	source, path := newTestSource(t, mint.attach("vol", []string{"read"}, expires))
	first := mint.grant("vol", testSessionID, 1, []string{"read"}, expires.Add(time.Minute))
	rotate(t, path, first)
	if _, err := source.Refresh(context.Background(), testSessionID, 1); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// A retry after a lost response must present the same bytes: the authority
	// fences a session that repeats a sequence with a different token.
	rotate(t, path, mint.grant("vol", testSessionID, 1, []string{"read"}, expires.Add(2*time.Minute)))
	grant, err := source.Refresh(context.Background(), testSessionID, 1)
	if err != nil {
		t.Fatalf("retry Refresh: %v", err)
	}
	if grant.Capability != string(first) {
		t.Fatal("a retried sequence presented different bytes than the first attempt")
	}
}

func TestFileGrantSourceAcceptsNarrowedAccessAndRefusesBroadenedAccess(t *testing.T) {
	mint := newMint(t)
	expires := time.Now().Add(10 * time.Minute)
	source, path := newTestSource(t, mint.attach("vol", []string{"write"}, expires))
	rotate(t, path, mint.grant("vol", testSessionID, 1, []string{"read"}, expires.Add(time.Minute)))
	grant, err := source.Refresh(context.Background(), testSessionID, 1)
	if err != nil {
		t.Fatalf("narrowing Refresh: %v", err)
	}
	if len(grant.Access) != 1 || grant.Access[0] != "read" {
		t.Fatalf("access = %v, want the narrowed access", grant.Access)
	}
	// The ceiling narrowed with the session: returning to write would now be a
	// broadening the authority fences.
	rotate(t, path, mint.grant("vol", testSessionID, 2, []string{"write"}, expires.Add(2*time.Minute)))
	_, err = source.Refresh(context.Background(), testSessionID, 2)
	if err == nil || !strings.Contains(err.Error(), "broadens") {
		t.Fatalf("error = %v, want a refusal to broaden access", err)
	}
}

func TestFileGrantSourceRefusesForeignExpiredAndWorldReadableCredentials(t *testing.T) {
	mint := newMint(t)
	expires := time.Now().Add(10 * time.Minute)
	source, path := newTestSource(t, mint.attach("vol", []string{"read"}, expires))
	for _, testCase := range []struct {
		name  string
		token []byte
		want  string
	}{
		{"other volume", mint.grant("other", testSessionID, 1, []string{"read"}, expires), "names volume"},
		{"other session", mint.grant("vol", "b3RoZXItc2Vzc2lvbi1pZDEy", 1, []string{"read"}, expires), "bound to session"},
		{"other sequence", mint.grant("vol", testSessionID, 7, []string{"read"}, expires), "sequence 7"},
		{"expired", mint.grant("vol", testSessionID, 1, []string{"read"}, time.Now().Add(-time.Second)), "already expired"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rotate(t, path, testCase.token)
			_, err := source.Refresh(context.Background(), testSessionID, 1)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to name %q", err, testCase.want)
			}
		})
	}
	rotate(t, path, mint.grant("vol", testSessionID, 1, []string{"read"}, expires))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod capability: %v", err)
	}
	if _, err := source.Refresh(context.Background(), testSessionID, 1); err == nil {
		t.Fatal("a credential readable by group and other must be refused")
	}
}

func TestFileGrantSourceRequiresAnUnboundAttachCapability(t *testing.T) {
	mint := newMint(t)
	expires := time.Now().Add(10 * time.Minute)
	path := filepath.Join(t.TempDir(), "access.token")
	bound := mint.grant("vol", testSessionID, 1, []string{"read"}, expires)
	rotate(t, path, bound)
	if _, err := NewFileGrantSource(path, bound, nil); err == nil {
		t.Fatal("a session-bound capability never attached a mount and cannot supply the access ceiling")
	}
	if _, err := NewFileGrantSource("", mint.attach("vol", []string{"read"}, expires), nil); err == nil {
		t.Fatal("a source without a file path must be refused")
	}
	if _, err := NewFileGrantSource(path, []byte("v1.garbage"), nil); err == nil {
		t.Fatal("an unparsable attach capability must be refused")
	}
}

// A mount whose credential file is never rotated must end itself while its
// installed authorization is still valid, which is the renewer's cutoff, not
// the authority's fence.
func TestFileGrantSourceFailsClosedThroughTheRenewerCutoff(t *testing.T) {
	mint := newMint(t)
	deadline := time.Now().Add(6 * time.Second)
	source, _ := newTestSource(t, mint.attach("vol", []string{"read"}, deadline))
	renewer := &Renewer{Source: source}
	installed := 0
	err := renewer.Run(context.Background(), testSessionID, deadline,
		func(context.Context, string, uint64, []byte) (time.Time, error) {
			installed++
			return time.Time{}, errors.New("unreachable: no grant was ever produced")
		})
	if err == nil || !strings.Contains(err.Error(), "safe cutoff") {
		t.Fatalf("err = %v, want the renewer's safe-cutoff refusal", err)
	}
	if installed != 0 {
		t.Fatalf("installed %d grants, want none: an unrotated file produces no grant to install", installed)
	}
	if remaining := time.Until(deadline); remaining <= 0 {
		t.Fatalf("renewal ended %s after the authorization deadline; it must end before it", -remaining)
	}
}
