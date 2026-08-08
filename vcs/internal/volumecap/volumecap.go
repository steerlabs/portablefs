// Package volumecap verifies the control plane's short-lived, volume-scoped
// data-plane capabilities. Tokens are signed with Ed25519, bound to the
// client's mutually authenticated TLS public key, bounded to a maximum
// lifetime this authority enforces itself, and accepted exactly once.
package volumecap

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

const domain = "portablefs-volume-capability-v1\x00"

var (
	ErrInvalid = errors.New("volumecap: invalid capability")
	// ErrReplayed is returned when a capability that was already spent is
	// presented again. It is a distinct condition from a malformed or expired
	// token and is never retryable with the same token.
	ErrReplayed = errors.New("volumecap: capability was already used")
	// ErrNoNonceCapacity is returned when the single-use record for a valid
	// capability cannot be retained. Accepting a capability whose reuse could
	// not be detected would silently remove replay protection, so this
	// authorizer refuses instead.
	ErrNoNonceCapacity = errors.New("volumecap: single-use capability records are full")
)

type Claims struct {
	VolumeID  string   `json:"volume_id"`
	Subject   string   `json:"subject"`
	Access    []string `json:"access"`
	NotBefore int64    `json:"not_before"`
	Expires   int64    `json:"expires"`
	PeerSPKI  string   `json:"peer_spki_sha256"`
	// Nonce makes each capability single use. The authorizer retains the
	// nonces it has accepted until they expire and refuses a second
	// presentation, so a captured token is not a reusable credential for the
	// remainder of its validity window.
	Nonce string `json:"nonce"`
}

type Authorizer struct {
	PublicKey ed25519.PublicKey
	Now       func() time.Time
	ClockSkew time.Duration
	// MaxLifetime is the longest validity window this authority will honour,
	// regardless of what the control plane signed. The verified expiry becomes
	// the session's absolute, non-renewable deadline, so without this bound one
	// minting mistake produces a capability nothing can revoke.
	MaxLifetime time.Duration
	// MaxRetainedNonces bounds the single-use records held at once. Retention
	// is bounded in time by MaxLifetime, so this bounds memory as a function of
	// the control plane's minting rate.
	MaxRetainedNonces int

	spent spentNonces
}

func (a *Authorizer) Authorize(ctx context.Context, volumeID string, token []byte) (volumeserver.Authorization, error) {
	peer, ok := authorityrpc.PeerIdentity(ctx)
	if !ok {
		return volumeserver.Authorization{}, ErrInvalid
	}
	return a.Verify(volumeID, token, peer)
}

func (a *Authorizer) Verify(volumeID string, token []byte, peer [32]byte) (volumeserver.Authorization, error) {
	if len(a.PublicKey) != ed25519.PublicKeySize || len(token) == 0 || len(token) > 8192 || volumeID == "" ||
		a.ClockSkew < 0 || a.MaxLifetime <= 0 || a.MaxRetainedNonces <= 0 {
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
	// "Short-lived" has to be a property this authority enforces, not a promise
	// the minting service makes. Both the declared window and the remaining
	// window are bounded: the first refuses a token minted with an absurd
	// expiry, the second refuses one whose not_before is far in the past.
	seconds := int64(a.MaxLifetime / time.Second)
	if seconds <= 0 || claims.Expires-claims.NotBefore > seconds || claims.Expires-now.Unix() > seconds {
		return volumeserver.Authorization{}, ErrInvalid
	}
	var access volumeserver.Access
	for _, permission := range claims.Access {
		switch permission {
		case "read":
			access |= volumeserver.AccessRead
		case "write":
			access |= volumeserver.AccessRead | volumeserver.AccessWrite
		case "admin":
			// Volume-wide configuration, not file contents. It implies write
			// because an administrator of a volume can necessarily also write
			// it, but write deliberately does not imply admin: changing
			// .portablefs/local-dirs changes what every other machine can see.
			access |= volumeserver.AccessRead | volumeserver.AccessWrite | volumeserver.AccessAdmin
		default:
			return volumeserver.Authorization{}, ErrInvalid
		}
	}
	if access&volumeserver.AccessRead == 0 {
		return volumeserver.Authorization{}, ErrInvalid
	}
	// Spending the nonce is the last step: a token is only consumed once it
	// would otherwise have been accepted, so a malformed or misdirected
	// presentation cannot burn a legitimate capability.
	if err := a.spent.spend(claims.Nonce, time.Unix(claims.Expires, 0), now, a.MaxRetainedNonces); err != nil {
		return volumeserver.Authorization{}, err
	}
	return volumeserver.Authorization{Access: access, Deadline: time.Unix(claims.Expires, 0)}, nil
}

// spentNonces retains accepted capability nonces until they expire. Expiry is
// bounded by the authorizer's maximum lifetime, so the set drains on its own.
type spentNonces struct {
	mu      sync.Mutex
	present map[string]struct{}
	expiry  nonceExpiryQueue
}

func (s *spentNonces) spend(nonce string, expires, now time.Time, limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.present == nil {
		s.present = make(map[string]struct{})
	}
	for len(s.expiry) != 0 && !now.Before(s.expiry[0].expires) {
		evicted := heap.Pop(&s.expiry).(nonceExpiry)
		delete(s.present, evicted.nonce)
	}
	if _, replayed := s.present[nonce]; replayed {
		return ErrReplayed
	}
	if len(s.present) >= limit {
		return ErrNoNonceCapacity
	}
	s.present[nonce] = struct{}{}
	heap.Push(&s.expiry, nonceExpiry{nonce: nonce, expires: expires})
	return nil
}

type nonceExpiry struct {
	nonce   string
	expires time.Time
}

type nonceExpiryQueue []nonceExpiry

func (q nonceExpiryQueue) Len() int           { return len(q) }
func (q nonceExpiryQueue) Less(i, j int) bool { return q[i].expires.Before(q[j].expires) }
func (q nonceExpiryQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *nonceExpiryQueue) Push(value any)    { *q = append(*q, value.(nonceExpiry)) }
func (q *nonceExpiryQueue) Pop() any {
	old := *q
	last := old[len(old)-1]
	*q = old[:len(old)-1]
	return last
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
