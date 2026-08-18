// Package productauth verifies the product's independent authorization
// assertion. The product decides who may use a volume; the PortableFS manager
// and authority independently verify that decision before infrastructure
// credentials can authorize a mount.
package productauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const domain = "portablefs-product-authorization-v1\x00"

// MaxRenewalEpoch is the largest integer represented exactly by both Go and
// JavaScript peers.
const MaxRenewalEpoch uint64 = 9007199254740991

var ErrInvalid = errors.New("productauth: invalid authorization")

type Claims struct {
	Issuer              string   `json:"issuer"`
	Audience            string   `json:"audience"`
	AuthorizationDomain string   `json:"authorization_domain"`
	Owner               string   `json:"owner"`
	Subject             string   `json:"subject"`
	VolumeID            string   `json:"volume_id"`
	Access              []string `json:"access"`
	PeerSPKI            string   `json:"peer_spki_sha256"`
	Nonce               string   `json:"nonce"`
	NotBefore           int64    `json:"not_before"`
	Expires             int64    `json:"expires"`
	RenewalScope        string   `json:"renewal_scope,omitempty"`
	RenewalEpoch        uint64   `json:"renewal_epoch,omitempty"`
}

type Expectations struct {
	Issuer              string
	Audience            string
	AuthorizationDomain string
	Owner               string
	VolumeID            string
	PeerSPKI            [32]byte
	Now                 time.Time
	ClockSkew           time.Duration
	MaxLifetime         time.Duration
	RenewalScope        string
	RenewalEpoch        uint64
}

type Verified struct {
	Claims Claims
	Peer   [32]byte
}

func Sign(privateKey ed25519.PrivateKey, claims Claims) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, append([]byte(domain), payload...))
	return []byte("v1." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)), nil
}

func Verify(publicKey ed25519.PublicKey, token []byte, expected Expectations) (Verified, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(token) == 0 || len(token) > 8192 ||
		expected.Issuer == "" || expected.Audience == "" || expected.AuthorizationDomain == "" ||
		expected.Owner == "" || expected.VolumeID == "" || expected.Now.IsZero() ||
		expected.ClockSkew < 0 || expected.MaxLifetime <= 0 ||
		(expected.RenewalScope == "") != (expected.RenewalEpoch == 0) ||
		expected.RenewalEpoch > MaxRenewalEpoch ||
		expected.RenewalScope != "" && !ValidRenewalScope(expected.RenewalScope) {
		return Verified{}, ErrInvalid
	}
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return Verified{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 4096 {
		return Verified{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, append([]byte(domain), payload...), signature) {
		return Verified{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var claims Claims
	if err := decoder.Decode(&claims); err != nil {
		return Verified{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Verified{}, ErrInvalid
	}
	if claims.Issuer != expected.Issuer || claims.Audience != expected.Audience ||
		claims.AuthorizationDomain != expected.AuthorizationDomain || claims.Owner != expected.Owner ||
		claims.VolumeID != expected.VolumeID || claims.Subject == "" || claims.Nonce == "" ||
		claims.Expires <= claims.NotBefore || !validAccess(claims.Access) ||
		(claims.RenewalScope == "") != (claims.RenewalEpoch == 0) ||
		claims.RenewalEpoch > MaxRenewalEpoch ||
		claims.RenewalScope != "" && !ValidRenewalScope(claims.RenewalScope) ||
		expected.RenewalScope != "" &&
			(claims.RenewalScope != expected.RenewalScope || claims.RenewalEpoch != expected.RenewalEpoch) {
		return Verified{}, ErrInvalid
	}
	peerBytes, err := base64.RawURLEncoding.DecodeString(claims.PeerSPKI)
	if err != nil || len(peerBytes) != len(expected.PeerSPKI) ||
		subtle.ConstantTimeCompare(peerBytes, expected.PeerSPKI[:]) != 1 {
		return Verified{}, ErrInvalid
	}
	if expected.Now.Add(expected.ClockSkew).Unix() < claims.NotBefore ||
		expected.Now.Add(-expected.ClockSkew).Unix() >= claims.Expires {
		return Verified{}, ErrInvalid
	}
	maxSeconds := int64(expected.MaxLifetime / time.Second)
	if maxSeconds <= 0 || claims.Expires-claims.NotBefore > maxSeconds ||
		claims.Expires-expected.Now.Unix() > maxSeconds {
		return Verified{}, ErrInvalid
	}
	var peer [32]byte
	copy(peer[:], peerBytes)
	return Verified{Claims: claims, Peer: peer}, nil
}

func Allows(granted, requested []string) bool {
	grant := accessBits(granted)
	want := accessBits(requested)
	return grant != 0 && want != 0 && want&^grant == 0
}

func validAccess(access []string) bool {
	return accessBits(access) != 0
}

// ValidRenewalScope excludes JSON-escaped characters so encoded size remains
// proportional to raw size on both Go and TypeScript peers.
func ValidRenewalScope(value string) bool {
	if value == "" || len(value) > 200 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '.', '_', '-', ':', '/':
		default:
			return false
		}
	}
	return true
}

func accessBits(access []string) uint8 {
	var bits uint8
	for _, permission := range access {
		switch permission {
		case "read":
			bits |= 1
		case "write":
			bits |= 1 | 2
		case "admin":
			bits |= 1 | 2 | 4
		default:
			return 0
		}
	}
	return bits
}
