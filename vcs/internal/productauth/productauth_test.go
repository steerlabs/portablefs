package productauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
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

func TestAuthorizationRequiresCompleteRenewalFenceClaims(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(2_000_000_000, 0)
	peer := [32]byte{4}
	base := Claims{
		Issuer: "product", Audience: "portablefs-manager", AuthorizationDomain: "tenant", Owner: "owner",
		Subject: "subject", VolumeID: "volume", Access: []string{"read"},
		PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "nonce",
		NotBefore: now.Unix(), Expires: now.Add(time.Minute).Unix(),
	}
	expected := Expectations{
		Issuer: base.Issuer, Audience: base.Audience, AuthorizationDomain: base.AuthorizationDomain,
		Owner: base.Owner, VolumeID: base.VolumeID, PeerSPKI: peer, Now: now, MaxLifetime: 5 * time.Minute,
	}
	for name, claims := range map[string]Claims{
		"scope only": {Issuer: base.Issuer, Audience: base.Audience, AuthorizationDomain: base.AuthorizationDomain, Owner: base.Owner, Subject: base.Subject, VolumeID: base.VolumeID, Access: base.Access, PeerSPKI: base.PeerSPKI, Nonce: base.Nonce, NotBefore: base.NotBefore, Expires: base.Expires, RenewalScope: "scope"},
		"epoch only": {Issuer: base.Issuer, Audience: base.Audience, AuthorizationDomain: base.AuthorizationDomain, Owner: base.Owner, Subject: base.Subject, VolumeID: base.VolumeID, Access: base.Access, PeerSPKI: base.PeerSPKI, Nonce: base.Nonce, NotBefore: base.NotBefore, Expires: base.Expires, RenewalEpoch: 1},
	} {
		t.Run(name, func(t *testing.T) {
			token, err := Sign(privateKey, claims)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(publicKey, token, expected); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify = %v, want ErrInvalid", err)
			}
		})
	}

	base.RenewalScope = "cloud-private-state:computer-1"
	base.RenewalEpoch = 7
	token, err := Sign(privateKey, base)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(publicKey, token, expected)
	if err != nil || verified.Claims.RenewalScope != base.RenewalScope || verified.Claims.RenewalEpoch != base.RenewalEpoch {
		t.Fatalf("scoped Verify = %+v, %v", verified, err)
	}
	expected.RenewalScope = base.RenewalScope
	expected.RenewalEpoch = base.RenewalEpoch
	if _, err := Verify(publicKey, token, expected); err != nil {
		t.Fatalf("matching renewal expectation: %v", err)
	}
	expected.RenewalEpoch++
	if _, err := Verify(publicKey, token, expected); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched renewal expectation = %v, want ErrInvalid", err)
	}
}

func TestAuthorizationSignatureCoversRenewalFenceClaims(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(2_000_000_000, 0)
	peer := [32]byte{4}
	claims := Claims{
		Issuer: "product", Audience: "portablefs-manager", AuthorizationDomain: "tenant", Owner: "owner",
		Subject: "subject", VolumeID: "volume", Access: []string{"read"},
		PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "nonce",
		NotBefore: now.Unix(), Expires: now.Add(time.Minute).Unix(),
		RenewalScope: "scope-a", RenewalEpoch: 7,
	}
	token, err := Sign(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	expected := Expectations{
		Issuer: claims.Issuer, Audience: claims.Audience, AuthorizationDomain: claims.AuthorizationDomain,
		Owner: claims.Owner, VolumeID: claims.VolumeID, PeerSPKI: peer, Now: now, MaxLifetime: 5 * time.Minute,
	}
	for name, replacement := range map[string]struct{ old, new string }{
		"scope": {`"renewal_scope":"scope-a"`, `"renewal_scope":"scope-b"`},
		"epoch": {`"renewal_epoch":7`, `"renewal_epoch":8`},
	} {
		t.Run(name, func(t *testing.T) {
			parts := strings.Split(string(token), ".")
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.Replace(payload, []byte(replacement.old), []byte(replacement.new), 1)
			if bytes.Equal(changed, payload) {
				t.Fatal("test did not alter the signed payload")
			}
			tampered := []byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString(changed) + "." + parts[2])
			if _, err := Verify(publicKey, tampered, expected); !errors.Is(err, ErrInvalid) {
				t.Fatalf("tampered Verify = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAuthorizationRenewalEpochBounds(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(2_000_000_000, 0)
	peer := [32]byte{4}
	base := Claims{
		Issuer: "product", Audience: "portablefs-manager", AuthorizationDomain: "tenant", Owner: "owner",
		Subject: "subject", VolumeID: "volume", Access: []string{"read"},
		PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "nonce",
		NotBefore: now.Unix(), Expires: now.Add(time.Minute).Unix(),
		RenewalScope: "cloud-private-state:clc_123e4567-e89b-12d3-a456-426614174000",
	}
	expected := Expectations{
		Issuer: base.Issuer, Audience: base.Audience, AuthorizationDomain: base.AuthorizationDomain,
		Owner: base.Owner, VolumeID: base.VolumeID, PeerSPKI: peer, Now: now, MaxLifetime: 5 * time.Minute,
	}
	for _, test := range []struct {
		name  string
		epoch uint64
		valid bool
	}{
		{name: "zero", epoch: 0},
		{name: "one", epoch: 1, valid: true},
		{name: "max", epoch: MaxRenewalEpoch, valid: true},
		{name: "max-plus-one", epoch: MaxRenewalEpoch + 1},
		{name: "uint64-max", epoch: ^uint64(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := base
			claims.RenewalEpoch = test.epoch
			token, err := Sign(privateKey, claims)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(publicKey, token, expected)
			if test.valid && err != nil {
				t.Fatalf("Verify epoch %d: %v", test.epoch, err)
			}
			if !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify epoch %d = %v, want ErrInvalid", test.epoch, err)
			}
		})
	}
}

func TestAuthorizationRenewalScopeSyntax(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(2_000_000_000, 0)
	peer := [32]byte{4}
	base := Claims{
		Issuer: "product", Audience: "portablefs-manager", AuthorizationDomain: "tenant", Owner: "owner",
		Subject: "subject", VolumeID: "volume", Access: []string{"read"},
		PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "nonce",
		NotBefore: now.Unix(), Expires: now.Add(time.Minute).Unix(), RenewalEpoch: 1,
	}
	expected := Expectations{
		Issuer: base.Issuer, Audience: base.Audience, AuthorizationDomain: base.AuthorizationDomain,
		Owner: base.Owner, VolumeID: base.VolumeID, PeerSPKI: peer, Now: now, MaxLifetime: 5 * time.Minute,
	}
	for _, test := range []struct {
		name  string
		scope string
		valid bool
	}{
		{name: "less-than", scope: "cloud-private-state:clc_<uuid"},
		{name: "greater-than", scope: "cloud-private-state:clc_>uuid"},
		{name: "ampersand", scope: "cloud-private-state:clc_&uuid"},
		{name: "control", scope: "cloud-private-state:clc_\n"},
		{name: "unicode", scope: "cloud-private-state:clc_é"},
		{name: "identifier", scope: "cloud-private-state:clc_123e4567-e89b-12d3-a456-426614174000", valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := base
			claims.RenewalScope = test.scope
			token, err := Sign(privateKey, claims)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(publicKey, token, expected)
			if test.valid && err != nil {
				t.Fatalf("Verify scope %q: %v", test.scope, err)
			}
			if !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify scope %q = %v, want ErrInvalid", test.scope, err)
			}
		})
	}
}
