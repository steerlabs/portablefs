package volumecap

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func testAuthorizer(t *testing.T, pub ed25519.PublicKey, now *time.Time) *Authorizer {
	t.Helper()
	return &Authorizer{
		PublicKey: pub, Now: func() time.Time { return *now },
		MaxLifetime: 15 * time.Minute, MaxRetainedNonces: 16,
	}
}

func TestVolumePeerExpiryAndAccessBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(10_000, 0)
	peer := [32]byte{1, 2, 3}
	claims := Claims{VolumeID: "volume-a", Subject: "agent-a", Access: []string{"write"}, NotBefore: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Minute).Unix(), PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "n-1"}
	token, err := Sign(priv, claims)
	if err != nil {
		t.Fatal(err)
	}
	a := testAuthorizer(t, pub, &now)
	authorization, err := a.Verify("volume-a", token, peer)
	if err != nil || authorization.Access != volumeserver.AccessRead|volumeserver.AccessWrite || !authorization.Deadline.Equal(time.Unix(claims.Expires, 0)) {
		t.Fatalf("Verify = %+v, %v", authorization, err)
	}
	if _, err := a.Verify("volume-b", token, peer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong volume = %v", err)
	}
	if _, err := a.Verify("volume-a", token, [32]byte{9}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong peer = %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := a.Verify("volume-a", token, peer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired = %v", err)
	}
}

func TestTamperedAndUnknownPermissionFailClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(20_000, 0)
	peer := [32]byte{4}
	claims := Claims{VolumeID: "v", Subject: "s", Access: []string{"root"}, NotBefore: now.Add(-time.Second).Unix(), Expires: now.Add(time.Minute).Unix(), PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "n"}
	token, _ := Sign(priv, claims)
	a := testAuthorizer(t, pub, &now)
	if _, err := a.Verify("v", token, peer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown access = %v", err)
	}
	token[len(token)-1] ^= 1
	if _, err := a.Verify("v", token, peer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered = %v", err)
	}
}

// Defect 5: Verify only required Expires > NotBefore, so a capability minted
// with an expiry in the year 3000 verified and became the session's absolute,
// non-renewable deadline. No keepalive limit, sweep, or lease expiry can revoke
// that, so "short-lived" has to be enforced here.
func TestAbsurdCapabilityLifetimeIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_700_000_000, 0)
	peer := [32]byte{7}
	spki := base64.RawURLEncoding.EncodeToString(peer[:])

	distantFuture := time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()
	for name, claims := range map[string]Claims{
		"year 3000 expiry": {VolumeID: "v", Subject: "s", Access: []string{"write"}, NotBefore: now.Add(-time.Minute).Unix(), Expires: distantFuture, PeerSPKI: spki, Nonce: "far"},
		"long window":      {VolumeID: "v", Subject: "s", Access: []string{"write"}, NotBefore: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Hour).Unix(), PeerSPKI: spki, Nonce: "hour"},
		"backdated window": {VolumeID: "v", Subject: "s", Access: []string{"read"}, NotBefore: now.Add(-24 * time.Hour).Unix(), Expires: now.Add(time.Minute).Unix(), PeerSPKI: spki, Nonce: "back"},
	} {
		token, err := Sign(priv, claims)
		if err != nil {
			t.Fatal(err)
		}
		a := testAuthorizer(t, pub, &now)
		if _, err := a.Verify("v", token, peer); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s = %v, want a refusal", name, err)
		}
	}

	within := Claims{VolumeID: "v", Subject: "s", Access: []string{"write"}, NotBefore: now.Add(-time.Minute).Unix(), Expires: now.Add(5 * time.Minute).Unix(), PeerSPKI: spki, Nonce: "ok"}
	token, err := Sign(priv, within)
	if err != nil {
		t.Fatal(err)
	}
	a := testAuthorizer(t, pub, &now)
	if _, err := a.Verify("v", token, peer); err != nil {
		t.Fatalf("a capability inside the enforced lifetime was refused: %v", err)
	}
}

// Defect 5: the nonce was required to be non-empty and then never used, so the
// documented replay protection did not exist. It is now load-bearing.
func TestCapabilityIsSingleUse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(30_000, 0)
	peer := [32]byte{5}
	spki := base64.RawURLEncoding.EncodeToString(peer[:])
	mint := func(nonce string, at time.Time) []byte {
		token, err := Sign(priv, Claims{VolumeID: "v", Subject: "s", Access: []string{"read"}, NotBefore: at.Add(-time.Second).Unix(), Expires: at.Add(time.Minute).Unix(), PeerSPKI: spki, Nonce: nonce})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	a := testAuthorizer(t, pub, &now)
	token := mint("single", now)
	if _, err := a.Verify("v", token, peer); err != nil {
		t.Fatalf("first use = %v", err)
	}
	if _, err := a.Verify("v", token, peer); !errors.Is(err, ErrReplayed) {
		t.Fatalf("second use = %v, want ErrReplayed", err)
	}
	if _, err := a.Verify("v", mint("fresh", now), peer); err != nil {
		t.Fatalf("a different nonce was refused: %v", err)
	}

	// Records drain on their own once the capability they protect has expired,
	// so retention is bounded by the enforced maximum lifetime.
	now = now.Add(2 * time.Minute)
	if _, err := a.Verify("v", mint("single", now), peer); err != nil {
		t.Fatalf("a nonce reissued after the original expired was refused: %v", err)
	}
	if len(a.spent.present) > 1 {
		t.Fatalf("expired single-use records were not drained: %d retained", len(a.spent.present))
	}
}

func TestSingleUseRecordsFailClosedWhenFull(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(40_000, 0)
	peer := [32]byte{6}
	spki := base64.RawURLEncoding.EncodeToString(peer[:])
	a := &Authorizer{PublicKey: pub, Now: func() time.Time { return now }, MaxLifetime: time.Minute, MaxRetainedNonces: 2}
	for i, nonce := range []string{"a", "b", "c"} {
		token, err := Sign(priv, Claims{VolumeID: "v", Subject: "s", Access: []string{"read"}, NotBefore: now.Add(-time.Second).Unix(), Expires: now.Add(30 * time.Second).Unix(), PeerSPKI: spki, Nonce: nonce})
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.Verify("v", token, peer)
		if i < 2 && err != nil {
			t.Fatalf("capability %d refused: %v", i, err)
		}
		if i == 2 && !errors.Is(err, ErrNoNonceCapacity) {
			t.Fatalf("capability beyond the record bound = %v, want ErrNoNonceCapacity", err)
		}
	}
}

func TestAuthorizerRequiresItsOwnBounds(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Unix(50_000, 0)
	peer := [32]byte{8}
	token, err := Sign(priv, Claims{VolumeID: "v", Subject: "s", Access: []string{"read"}, NotBefore: now.Add(-time.Second).Unix(), Expires: now.Add(time.Minute).Unix(), PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "n"})
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]*Authorizer{
		"no lifetime bound": {PublicKey: pub, Now: func() time.Time { return now }, MaxRetainedNonces: 4},
		"no nonce records":  {PublicKey: pub, Now: func() time.Time { return now }, MaxLifetime: time.Minute},
	} {
		if _, err := a.Verify("v", token, peer); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s = %v, want a refusal", name, err)
		}
	}
}
