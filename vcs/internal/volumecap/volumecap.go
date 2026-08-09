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
	"crypto/sha256"
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
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
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
	// Hosted grants additionally bind the exact storage placement and
	// authority generation. A stale authority can verify only grants from its
	// own generation, even when it still has an otherwise trusted signing key.
	CellID              string `json:"cell_id,omitempty"`
	AuthorityID         string `json:"authority_id,omitempty"`
	AuthorityGeneration uint64 `json:"authority_generation,omitempty"`
	// ProductAuthorization is the product's independently signed decision.
	// The manager signs the infrastructure envelope around it; the authority
	// verifies both signatures and the pinned owner/domain/issuer.
	ProductAuthorization string `json:"product_authorization,omitempty"`
	// MountEnrollmentID names a durable, key-bound Manager authorization.
	// It is valid only for an in-session reauthorization; the authority trusts
	// the Manager's short-lived envelope instead of requiring the original
	// product decision to remain alive for the whole mount.
	MountEnrollmentID string `json:"mount_enrollment_id,omitempty"`
	// SessionID and Sequence are present only on an in-session
	// reauthorization. They make retrying the same signed token harmless and
	// make replay against any other session impossible.
	SessionID string `json:"session_id,omitempty"`
	Sequence  uint64 `json:"sequence,omitempty"`
}

type Authorizer struct {
	PublicKey ed25519.PublicKey
	// The following fields are all required together for a hosted authority.
	// Leaving all of them empty preserves the standalone, one-signature mode.
	ProductPublicKey    ed25519.PublicKey
	ProductIssuer       string
	ProductAudience     string
	AuthorizationDomain string
	Owner               string
	CellID              string
	AuthorityID         string
	AuthorityGeneration uint64
	Now                 func() time.Time
	ClockSkew           time.Duration
	// MaxLifetime is the longest validity window this authority will honour,
	// regardless of what the control plane signed. The verified expiry becomes
	// the initial session deadline or the exact reauthorization deadline, so
	// without this bound one minting mistake produces an excessively long grant.
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
	authorization, _, err := a.verify(volumeID, token, peer, volumeserver.SessionID{}, 0, true)
	return authorization, err
}

// Reauthorize verifies a retryable, session-bound grant. Unlike an attach
// capability it is not spent in the process-global nonce set: its exact
// session ID and monotonic sequence are the replay boundary, and the runtime
// retains the token digest for an idempotent lost-response retry.
func (a *Authorizer) Reauthorize(ctx context.Context, volumeID string, sessionID volumeserver.SessionID, sequence uint64, token []byte) (volumeserver.Authorization, [32]byte, error) {
	peer, ok := authorityrpc.PeerIdentity(ctx)
	if !ok || sessionID == (volumeserver.SessionID{}) || sequence == 0 {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	return a.VerifyReauthorization(volumeID, sessionID, sequence, token, peer)
}

// VerifyReauthorization is the explicit-peer form used by non-transport
// callers and conformance tests. Production RPC obtains peer only from the
// verified TLS connection and calls Reauthorize above.
func (a *Authorizer) VerifyReauthorization(volumeID string, sessionID volumeserver.SessionID, sequence uint64, token []byte, peer [32]byte) (volumeserver.Authorization, [32]byte, error) {
	if sessionID == (volumeserver.SessionID{}) || sequence == 0 {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	return a.verify(volumeID, token, peer, sessionID, sequence, false)
}

func (a *Authorizer) verify(volumeID string, token []byte, peer [32]byte, sessionID volumeserver.SessionID, sequence uint64, spend bool) (volumeserver.Authorization, [32]byte, error) {
	if len(a.PublicKey) != ed25519.PublicKeySize || len(token) == 0 || len(token) > 8192 || volumeID == "" ||
		a.ClockSkew < 0 || a.MaxLifetime <= 0 || a.MaxRetainedNonces <= 0 {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > 4096 {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(a.PublicKey, append([]byte(domain), payload...), signature) {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var claims Claims
	if err := dec.Decode(&claims); err != nil {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	if claims.VolumeID != volumeID || claims.Subject == "" || claims.Nonce == "" || claims.Expires <= claims.NotBefore {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	if spend {
		if claims.SessionID != "" || claims.Sequence != 0 {
			return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
		}
	} else if claims.SessionID != base64.RawURLEncoding.EncodeToString(sessionID[:]) || claims.Sequence != sequence {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	boundPeer, err := base64.RawURLEncoding.DecodeString(claims.PeerSPKI)
	if err != nil || len(boundPeer) != len(peer) || subtle.ConstantTimeCompare(boundPeer, peer[:]) != 1 {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if now.Add(a.ClockSkew).Unix() < claims.NotBefore || now.Add(-a.ClockSkew).Unix() >= claims.Expires {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	// "Short-lived" has to be a property this authority enforces, not a promise
	// the minting service makes. Both the declared window and the remaining
	// window are bounded: the first refuses a token minted with an absurd
	// expiry, the second refuses one whose not_before is far in the past.
	seconds := int64(a.MaxLifetime / time.Second)
	if seconds <= 0 || claims.Expires-claims.NotBefore > seconds || claims.Expires-now.Unix() > seconds {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
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
			return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
		}
	}
	if access&volumeserver.AccessRead == 0 {
		return volumeserver.Authorization{}, [32]byte{}, ErrInvalid
	}
	if err := a.verifyHosted(claims, peer, now); err != nil {
		return volumeserver.Authorization{}, [32]byte{}, err
	}
	// Spending the nonce is the last step: a token is only consumed once it
	// would otherwise have been accepted, so a malformed or misdirected
	// presentation cannot burn a legitimate capability.
	if spend {
		if err := a.spent.spend(claims.Nonce, time.Unix(claims.Expires, 0), now, a.MaxRetainedNonces); err != nil {
			return volumeserver.Authorization{}, [32]byte{}, err
		}
	}
	return volumeserver.Authorization{
		Access: access, Deadline: time.Unix(claims.Expires, 0), MountEnrollmentID: claims.MountEnrollmentID,
	}, sha256.Sum256(token), nil
}

func (a *Authorizer) verifyHosted(claims Claims, peer [32]byte, now time.Time) error {
	configured := len(a.ProductPublicKey) != 0 || a.ProductIssuer != "" || a.ProductAudience != "" ||
		a.AuthorizationDomain != "" || a.Owner != "" || a.CellID != "" ||
		a.AuthorityID != "" || a.AuthorityGeneration != 0
	if !configured {
		if claims.ProductAuthorization != "" || claims.MountEnrollmentID != "" || claims.CellID != "" || claims.AuthorityID != "" || claims.AuthorityGeneration != 0 {
			return ErrInvalid
		}
		return nil
	}
	if len(a.ProductPublicKey) != ed25519.PublicKeySize || a.ProductIssuer == "" || a.ProductAudience == "" ||
		a.AuthorizationDomain == "" || a.Owner == "" || a.CellID == "" || a.AuthorityID == "" ||
		a.AuthorityGeneration == 0 || claims.CellID != a.CellID || claims.AuthorityID != a.AuthorityID ||
		claims.AuthorityGeneration != a.AuthorityGeneration {
		return ErrInvalid
	}
	if claims.MountEnrollmentID != "" {
		if len(claims.MountEnrollmentID) > 256 || strings.TrimSpace(claims.MountEnrollmentID) != claims.MountEnrollmentID {
			return ErrInvalid
		}
		if claims.SessionID != "" {
			if claims.ProductAuthorization != "" || claims.Sequence == 0 {
				return ErrInvalid
			}
			return nil
		}
		// The initial enrollment-owned attach still carries and verifies the
		// product decision. Naming the enrollment here pins the sole issuer into
		// the authority session before sequence one is requested.
		if claims.Sequence != 0 || claims.ProductAuthorization == "" {
			return ErrInvalid
		}
	}
	if claims.ProductAuthorization == "" {
		return ErrInvalid
	}
	verified, err := productauth.Verify(a.ProductPublicKey, []byte(claims.ProductAuthorization), productauth.Expectations{
		Issuer: a.ProductIssuer, Audience: a.ProductAudience, AuthorizationDomain: a.AuthorizationDomain,
		Owner: a.Owner, VolumeID: claims.VolumeID, PeerSPKI: peer, Now: now,
		ClockSkew: a.ClockSkew, MaxLifetime: a.MaxLifetime,
	})
	if err != nil || verified.Claims.Subject != claims.Subject || !productauth.Allows(verified.Claims.Access, claims.Access) {
		return ErrInvalid
	}
	return nil
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
