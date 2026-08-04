// Package volumecap verifies the control plane's short-lived, volume-scoped
// data-plane capabilities. Tokens are signed with Ed25519 and bound to the
// client's mutually authenticated TLS public key.
package volumecap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

const domain = "portablefs-volume-capability-v1\x00"

var ErrInvalid = errors.New("volumecap: invalid capability")

type Claims struct {
	VolumeID  string   `json:"volume_id"`
	Subject   string   `json:"subject"`
	Access    []string `json:"access"`
	NotBefore int64    `json:"not_before"`
	Expires   int64    `json:"expires"`
	PeerSPKI  string   `json:"peer_spki_sha256"`
	Nonce     string   `json:"nonce"`
}

type Authorizer struct {
	PublicKey ed25519.PublicKey
	Now       func() time.Time
	ClockSkew time.Duration
}

func (a *Authorizer) Authorize(ctx context.Context, volumeID string, token []byte) (volumeserver.Authorization, error) {
	peer, ok := authorityrpc.PeerIdentity(ctx)
	if !ok {
		return volumeserver.Authorization{}, ErrInvalid
	}
	return a.Verify(volumeID, token, peer)
}

func (a *Authorizer) Verify(volumeID string, token []byte, peer [32]byte) (volumeserver.Authorization, error) {
	if len(a.PublicKey) != ed25519.PublicKeySize || len(token) == 0 || len(token) > 8192 || volumeID == "" || a.ClockSkew < 0 {
		return volumeserver.Authorization{}, ErrInvalid
	}
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return volumeserver.Authorization{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 4096 {
		return volumeserver.Authorization{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(a.PublicKey, append([]byte(domain), payload...), signature) {
		return volumeserver.Authorization{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var claims Claims
	if err := dec.Decode(&claims); err != nil {
		return volumeserver.Authorization{}, ErrInvalid
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return volumeserver.Authorization{}, ErrInvalid
	}
	if claims.VolumeID != volumeID || claims.Subject == "" || claims.Nonce == "" || claims.Expires <= claims.NotBefore {
		return volumeserver.Authorization{}, ErrInvalid
	}
	boundPeer, err := base64.RawURLEncoding.DecodeString(claims.PeerSPKI)
	if err != nil || len(boundPeer) != len(peer) || subtle.ConstantTimeCompare(boundPeer, peer[:]) != 1 {
		return volumeserver.Authorization{}, ErrInvalid
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if now.Add(a.ClockSkew).Unix() < claims.NotBefore || now.Add(-a.ClockSkew).Unix() >= claims.Expires {
		return volumeserver.Authorization{}, ErrInvalid
	}
	var access volumeserver.Access
	for _, permission := range claims.Access {
		switch permission {
		case "read":
			access |= volumeserver.AccessRead
		case "write":
			access |= volumeserver.AccessRead | volumeserver.AccessWrite
		default:
			return volumeserver.Authorization{}, ErrInvalid
		}
	}
	if access&volumeserver.AccessRead == 0 {
		return volumeserver.Authorization{}, ErrInvalid
	}
	return volumeserver.Authorization{Access: access, Deadline: time.Unix(claims.Expires, 0)}, nil
}

// Sign is used by the control plane and tests. JSON bytes are signed exactly as
// encoded; verifiers never re-encode attacker-controlled claims.
func Sign(privateKey ed25519.PrivateKey, claims Claims) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 private key", ErrInvalid)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, append([]byte(domain), payload...))
	return []byte("v1." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)), nil
}
