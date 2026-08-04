package volumecap

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

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
	a := &Authorizer{PublicKey: pub, Now: func() time.Time { return now }}
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
	claims := Claims{VolumeID: "v", Subject: "s", Access: []string{"admin"}, NotBefore: now.Add(-time.Second).Unix(), Expires: now.Add(time.Minute).Unix(), PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "n"}
	token, _ := Sign(priv, claims)
	a := &Authorizer{PublicKey: pub, Now: func() time.Time { return now }}
	if _, err := a.Verify("v", token, peer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown access = %v", err)
	}
	token[len(token)-1] ^= 1
	if _, err := a.Verify("v", token, peer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered = %v", err)
	}
}
