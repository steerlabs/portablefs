package productauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestAuthorizationBindsEveryTenantAndClientDimension(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	peer := [32]byte{1, 2, 3}
	claims := Claims{
		Issuer: "opensteer", Audience: "portablefs-manager", AuthorizationDomain: "org-1",
		Owner: "user-1", Subject: "session-1", VolumeID: "volume-1", Access: []string{"write"},
		PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "nonce-1",
		NotBefore: now.Add(-time.Second).Unix(), Expires: now.Add(time.Minute).Unix(),
	}
	token, err := Sign(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	expected := Expectations{
		Issuer: claims.Issuer, Audience: claims.Audience, AuthorizationDomain: claims.AuthorizationDomain,
		Owner: claims.Owner, VolumeID: claims.VolumeID, PeerSPKI: peer,
		Now: now, MaxLifetime: 5 * time.Minute,
	}
	if verified, err := Verify(publicKey, token, expected); err != nil || verified.Claims.Subject != claims.Subject {
		t.Fatalf("Verify = %+v, %v", verified, err)
	}

	for name, mutate := range map[string]func(*Expectations){
		"issuer": func(value *Expectations) { value.Issuer = "other" },
		"domain": func(value *Expectations) { value.AuthorizationDomain = "org-2" },
		"owner":  func(value *Expectations) { value.Owner = "user-2" },
		"volume": func(value *Expectations) { value.VolumeID = "volume-2" },
		"peer":   func(value *Expectations) { value.PeerSPKI = [32]byte{9} },
	} {
		changed := expected
		mutate(&changed)
		if _, err := Verify(publicKey, token, changed); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s mismatch = %v, want ErrInvalid", name, err)
		}
	}
}

func TestAuthorizationRejectsBroadeningAndLongLifetime(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(2_000_000_000, 0)
	peer := [32]byte{4}
	claims := Claims{
		Issuer: "product", Audience: "portablefs-manager", AuthorizationDomain: "tenant", Owner: "owner",
		Subject: "subject", VolumeID: "volume", Access: []string{"read"},
		PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "nonce",
		NotBefore: now.Unix(), Expires: now.Add(time.Hour).Unix(),
	}
	token, _ := Sign(privateKey, claims)
	_, err := Verify(publicKey, token, Expectations{
		Issuer: claims.Issuer, Audience: claims.Audience, AuthorizationDomain: claims.AuthorizationDomain,
		Owner: claims.Owner, VolumeID: claims.VolumeID, PeerSPKI: peer, Now: now, MaxLifetime: 5 * time.Minute,
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("long authorization = %v, want ErrInvalid", err)
	}
	if Allows(claims.Access, []string{"write"}) {
		t.Fatal("read authorization broadened to write")
	}
	if !Allows([]string{"admin"}, []string{"write"}) {
		t.Fatal("admin authorization did not permit a narrower write grant")
	}
}
