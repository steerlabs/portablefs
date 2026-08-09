// Package cellplan defines the complete, signed desired state a manager sends
// to one storage cell. The cell agent and the privileged helper both verify the
// same envelope; neither accepts paths, commands, executable names, unit text,
// or environment variables from the network.
package cellplan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	Version          = 1
	MaxPayloadBytes  = 3 << 20
	MaxEnvelopeBytes = 4 << 20
	domain           = "portablefs-cell-plan-v1\x00"
)

var (
	ErrInvalid  = errors.New("cellplan: invalid plan")
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type VolumePhase string

const (
	PhaseProvision VolumePhase = "PROVISION"
	PhaseServe     VolumePhase = "SERVE"
	PhaseFence     VolumePhase = "FENCE"
	PhaseRetire    VolumePhase = "RETIRE"
)

type Plan struct {
	Version    uint32       `json:"version"`
	CellID     string       `json:"cell_id"`
	Generation uint64       `json:"generation"`
	IssuedAt   int64        `json:"issued_at"`
	ExpiresAt  int64        `json:"expires_at"`
	ReleaseID  string       `json:"release_id"`
	Volumes    []VolumePlan `json:"volumes"`
}

type VolumePlan struct {
	VolumeID             string      `json:"volume_id"`
	Phase                VolumePhase `json:"phase"`
	AuthorizationDomain  string      `json:"authorization_domain"`
	Owner                string      `json:"owner"`
	ProductIssuer        string      `json:"product_issuer"`
	ProductPublicKeyPEM  string      `json:"product_public_key_pem"`
	AuthorityID          string      `json:"authority_id"`
	AuthorityGeneration  uint64      `json:"authority_generation"`
	ProjectID            uint32      `json:"project_id"`
	ServiceUID           uint32      `json:"service_uid"`
	ServiceGID           uint32      `json:"service_gid"`
	ListenPort           uint16      `json:"listen_port"`
	QuotaBytes           uint64      `json:"quota_bytes"`
	QuotaInodes          uint64      `json:"quota_inodes"`
	AuthorityServerName  string      `json:"authority_server_name"`
	AuthorityCertificate string      `json:"authority_certificate_pem,omitempty"`
	AuthorityCAPEM       string      `json:"authority_ca_pem"`
	ClientCAPEM          string      `json:"client_ca_pem"`
	CapabilityPublicKey  string      `json:"capability_public_key_pem"`
	PriorStrictFenced    bool        `json:"prior_strict_mounts_fenced"`
}

type Envelope struct {
	Token string `json:"token"`
}

func Sign(privateKey ed25519.PrivateKey, plan Plan) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, ErrInvalid
	}
	if err := Validate(plan); err != nil {
		return Envelope{}, err
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		return Envelope{}, err
	}
	if len(payload) > MaxPayloadBytes {
		return Envelope{}, fmt.Errorf("%w: plan exceeds payload bound", ErrInvalid)
	}
	signature := ed25519.Sign(privateKey, append([]byte(domain), payload...))
	token := "v1." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(token) > MaxEnvelopeBytes {
		return Envelope{}, fmt.Errorf("%w: plan exceeds envelope bound", ErrInvalid)
	}
	return Envelope{Token: token}, nil
}

func Verify(publicKey ed25519.PublicKey, envelope Envelope, cellID string, now time.Time, clockSkew, maxLifetime time.Duration) (Plan, [32]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize || envelope.Token == "" || len(envelope.Token) > MaxEnvelopeBytes ||
		!uuidPattern.MatchString(cellID) || now.IsZero() || clockSkew < 0 || maxLifetime <= 0 {
		return Plan{}, [32]byte{}, ErrInvalid
	}
	parts := strings.Split(envelope.Token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return Plan{}, [32]byte{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return Plan{}, [32]byte{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, append([]byte(domain), payload...), signature) {
		return Plan{}, [32]byte{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, [32]byte{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Plan{}, [32]byte{}, ErrInvalid
	}
	if err := Validate(plan); err != nil || plan.CellID != cellID {
		return Plan{}, [32]byte{}, ErrInvalid
	}
	if now.Add(clockSkew).Unix() < plan.IssuedAt || now.Add(-clockSkew).Unix() >= plan.ExpiresAt ||
		plan.ExpiresAt-plan.IssuedAt > int64(maxLifetime/time.Second) {
		return Plan{}, [32]byte{}, ErrInvalid
	}
	return plan, sha256.Sum256(payload), nil
}

func Validate(plan Plan) error {
	if plan.Version != Version || !uuidPattern.MatchString(plan.CellID) || plan.Generation == 0 ||
		plan.IssuedAt <= 0 || plan.ExpiresAt <= plan.IssuedAt || !validText(plan.ReleaseID, 256) {
		return ErrInvalid
	}
	seenVolume := make(map[string]struct{}, len(plan.Volumes))
	seenProject := make(map[uint32]struct{}, len(plan.Volumes))
	seenUID := make(map[uint32]struct{}, len(plan.Volumes))
	seenPort := make(map[uint16]struct{}, len(plan.Volumes))
	for i := range plan.Volumes {
		volume := &plan.Volumes[i]
		if !uuidPattern.MatchString(volume.VolumeID) || !validText(volume.AuthorizationDomain, 256) || !validText(volume.Owner, 256) ||
			!validText(volume.ProductIssuer, 256) || volume.ProductPublicKeyPEM == "" || !validText(volume.AuthorityID, 253) ||
			volume.AuthorityGeneration == 0 || volume.ProjectID == 0 || volume.ServiceUID < 1000 ||
			volume.ServiceGID < 1000 || volume.ListenPort < 1024 || volume.QuotaBytes == 0 || volume.QuotaBytes%1024 != 0 || volume.QuotaInodes == 0 ||
			volume.AuthorityServerName == "" || volume.AuthorityCAPEM == "" || volume.ClientCAPEM == "" ||
			volume.CapabilityPublicKey == "" {
			return fmt.Errorf("%w: incomplete volume %q", ErrInvalid, volume.VolumeID)
		}
		switch volume.Phase {
		case PhaseProvision, PhaseFence, PhaseRetire:
		case PhaseServe:
			if volume.AuthorityCertificate == "" {
				return fmt.Errorf("%w: serving volume has no authority certificate", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: unknown volume phase", ErrInvalid)
		}
		if _, duplicate := seenVolume[volume.VolumeID]; duplicate {
			return fmt.Errorf("%w: duplicate volume", ErrInvalid)
		}
		if _, duplicate := seenProject[volume.ProjectID]; duplicate {
			return fmt.Errorf("%w: duplicate project ID", ErrInvalid)
		}
		if _, duplicate := seenUID[volume.ServiceUID]; duplicate {
			return fmt.Errorf("%w: duplicate service UID", ErrInvalid)
		}
		if _, duplicate := seenPort[volume.ListenPort]; duplicate {
			return fmt.Errorf("%w: duplicate listen port", ErrInvalid)
		}
		seenVolume[volume.VolumeID] = struct{}{}
		seenProject[volume.ProjectID] = struct{}{}
		seenUID[volume.ServiceUID] = struct{}{}
		seenPort[volume.ListenPort] = struct{}{}
	}
	if !slices.IsSortedFunc(plan.Volumes, func(a, b VolumePlan) int { return strings.Compare(a.VolumeID, b.VolumeID) }) {
		return fmt.Errorf("%w: volumes are not in canonical order", ErrInvalid)
	}
	return nil
}

func ValidID(value string) bool { return uuidPattern.MatchString(value) }

func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
