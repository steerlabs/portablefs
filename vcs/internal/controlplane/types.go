// Package controlplane is the product-neutral PortableFS hosted manager core.
// It owns placement and authorization state, never filesystem contents.
package controlplane

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

const (
	StateSchemaVersion                              = 1
	MaxVolumesPerCell                               = 256
	MaxActiveMountEnrollments                       = 2048
	MaxActiveMountEnrollmentsPerAuthorizationDomain = 512
	MaxActiveMountEnrollmentsPerVolume              = 256
	MaxRetainedMountEnrollments                     = 4096
)

var (
	ErrInvalid            = errors.New("controlplane: invalid request")
	ErrNotFound           = errors.New("controlplane: not found")
	ErrConflict           = errors.New("controlplane: conflict")
	ErrCapacity           = errors.New("controlplane: no cell has sufficient capacity")
	ErrEnrollmentCapacity = errors.New("controlplane: mount enrollment capacity reached")
	ErrIdempotencyReuse   = errors.New("controlplane: idempotency key reused for a different request")
	ErrQuarantined        = errors.New("controlplane: resource is quarantined")
	ErrEnrollmentEnded    = errors.New("controlplane: mount enrollment has ended")
)

type VolumeState string

const (
	VolumeProvisioning VolumeState = "PROVISIONING"
	VolumeReady        VolumeState = "READY"
	VolumeFencing      VolumeState = "FENCING"
	VolumeRetired      VolumeState = "RETIRED"
	VolumeQuarantined  VolumeState = "QUARANTINED"
)

type CellHealth string

const (
	CellUnknown     CellHealth = "UNKNOWN"
	CellHealthy     CellHealth = "HEALTHY"
	CellDegraded    CellHealth = "DEGRADED"
	CellQuarantined CellHealth = "QUARANTINED"
)

type State struct {
	SchemaVersion              uint32                               `json:"schema_version"`
	Cells                      map[string]Cell                      `json:"cells"`
	Volumes                    map[string]Volume                    `json:"volumes"`
	Receipts                   map[string]Receipt                   `json:"receipts"`
	AuthorizationNonces        map[string]AuthorizationNonce        `json:"authorization_nonces"`
	MountEnrollments           map[string]MountEnrollment           `json:"mount_enrollments,omitempty"`
	MountAuthorizationContexts map[string]MountAuthorizationContext `json:"mount_authorization_contexts,omitempty"`
}

type Cell struct {
	ID                 string     `json:"id"`
	AvailabilityZone   string     `json:"availability_zone"`
	AuthorityHost      string     `json:"authority_host"`
	AuthorityDNSZone   string     `json:"authority_dns_zone"`
	CapacityBytes      uint64     `json:"capacity_bytes"`
	CapacityInodes     uint64     `json:"capacity_inodes"`
	AllocatedBytes     uint64     `json:"allocated_bytes"`
	AllocatedInodes    uint64     `json:"allocated_inodes"`
	NextProjectID      uint32     `json:"next_project_id"`
	NextServiceUID     uint32     `json:"next_service_uid"`
	NextPort           uint16     `json:"next_port"`
	PlanGeneration     uint64     `json:"plan_generation"`
	PlanReleaseID      string     `json:"plan_release_id,omitempty"`
	PlanIssuedUnix     int64      `json:"plan_issued_unix"`
	PlanExpiresUnix    int64      `json:"plan_expires_unix"`
	LastObservedUnix   int64      `json:"last_observed_unix,omitempty"`
	LastManagerRelease string     `json:"last_manager_release,omitempty"`
	LastAgentRelease   string     `json:"last_agent_release,omitempty"`
	LastHelperRelease  string     `json:"last_helper_release,omitempty"`
	Health             CellHealth `json:"health"`
	QuarantineReason   string     `json:"quarantine_reason,omitempty"`
}

type Volume struct {
	ID                   string      `json:"id"`
	AuthorizationDomain  string      `json:"authorization_domain"`
	Owner                string      `json:"owner"`
	ProductIssuer        string      `json:"product_issuer"`
	ProductPublicKeyPEM  string      `json:"product_public_key_pem"`
	CellID               string      `json:"cell_id"`
	QuotaBytes           uint64      `json:"quota_bytes"`
	QuotaInodes          uint64      `json:"quota_inodes"`
	ProjectID            uint32      `json:"project_id"`
	ServiceUID           uint32      `json:"service_uid"`
	ServiceGID           uint32      `json:"service_gid"`
	ListenPort           uint16      `json:"listen_port"`
	AuthorityID          string      `json:"authority_id"`
	AuthorityServerName  string      `json:"authority_server_name"`
	AuthorityGeneration  uint64      `json:"authority_generation"`
	AuthorityCSRPEM      string      `json:"authority_csr_pem,omitempty"`
	AuthorityCertificate string      `json:"authority_certificate_pem,omitempty"`
	AuthorityCertExpires int64       `json:"authority_certificate_expires_unix,omitempty"`
	State                VolumeState `json:"state"`
	PriorStrictFenced    bool        `json:"prior_strict_mounts_fenced"`
	StrictFenceEvidence  string      `json:"strict_fence_evidence_sha256,omitempty"`
	LastObservedUnix     int64       `json:"last_observed_unix,omitempty"`
	QuarantineReason     string      `json:"quarantine_reason,omitempty"`
	CreatedUnix          int64       `json:"created_unix"`
	UpdatedUnix          int64       `json:"updated_unix"`
}

type Receipt struct {
	Operation   string          `json:"operation"`
	RequestHash string          `json:"request_sha256"`
	Response    json.RawMessage `json:"response"`
	CreatedUnix int64           `json:"created_unix"`
}

type AuthorizationNonce struct {
	RequestID   string `json:"request_id"`
	ExpiresUnix int64  `json:"expires_unix"`
}

type MountEnrollmentState string

const (
	MountEnrollmentActive  MountEnrollmentState = "ACTIVE"
	MountEnrollmentClosed  MountEnrollmentState = "CLOSED"
	MountEnrollmentRevoked MountEnrollmentState = "REVOKED"
)

// MountEnrollment is the durable Manager decision that lets one already-live
// mount obtain short-lived, session-bound grants without retaining or
// refreshing the product's original authorization. It is bound to the exact
// mount key, volume, access ceiling, and authority generation.
type MountEnrollment struct {
	ID                       string                    `json:"id"`
	VolumeID                 string                    `json:"volume_id"`
	Subject                  string                    `json:"subject"`
	Owner                    string                    `json:"owner"`
	Access                   []string                  `json:"access"`
	PeerSPKI                 string                    `json:"peer_spki_sha256"`
	AuthorizationDomain      string                    `json:"authorization_domain"`
	ProductIssuer            string                    `json:"product_issuer"`
	CellID                   string                    `json:"cell_id"`
	AuthorityID              string                    `json:"authority_id"`
	AuthorityGeneration      uint64                    `json:"authority_generation"`
	CreatedUnix              int64                     `json:"created_unix"`
	ExpiresUnix              int64                     `json:"expires_unix"`
	State                    MountEnrollmentState      `json:"state"`
	SessionID                string                    `json:"session_id,omitempty"`
	LastSequence             uint64                    `json:"last_sequence,omitempty"`
	LastRequestSHA256        string                    `json:"last_request_sha256,omitempty"`
	LastAuthorization        *MountAuthorizationReplay `json:"last_authorization,omitempty"`
	LastAuthorizationContext string                    `json:"last_authorization_context_sha256,omitempty"`
	UpdatedUnix              int64                     `json:"updated_unix"`
	TerminationReason        string                    `json:"termination_reason,omitempty"`
}

// MountAuthorizationReplay is the non-derivable portion of the exact current
// refresh response. Manager-wide infrastructure material is deduplicated in a
// MountAuthorizationContext, while volume/cell addressing is immutable for the
// enrollment's pinned authority generation and is reconstructed on replay.
type MountAuthorizationReplay struct {
	AuthorityEndpoint      string `json:"authority_endpoint"`
	AuthorityServerName    string `json:"authority_server_name"`
	ClientCertificatePEM   string `json:"client_certificate_pem"`
	Capability             string `json:"capability"`
	ExpiresUnix            int64  `json:"expires_unix"`
	CertificateExpiresUnix int64  `json:"certificate_expires_unix"`
	SessionID              string `json:"session_id"`
	Sequence               uint64 `json:"sequence"`
}

type MountAuthorizationContext struct {
	AuthorityCAPEM string `json:"authority_ca_pem"`
	ReleaseID      string `json:"release_id"`
}

type RegisterCellRequest struct {
	ID               string `json:"id"`
	AvailabilityZone string `json:"availability_zone"`
	AuthorityHost    string `json:"authority_host"`
	AuthorityDNSZone string `json:"authority_dns_zone"`
	CapacityBytes    uint64 `json:"capacity_bytes"`
	CapacityInodes   uint64 `json:"capacity_inodes"`
	FirstProjectID   uint32 `json:"first_project_id,omitempty"`
	FirstServiceUID  uint32 `json:"first_service_uid,omitempty"`
	FirstPort        uint16 `json:"first_port,omitempty"`
}

type CreateVolumeRequest struct {
	AuthorizationDomain string `json:"authorization_domain"`
	Owner               string `json:"owner"`
	ProductIssuer       string `json:"product_issuer"`
	QuotaBytes          uint64 `json:"quota_bytes"`
	QuotaInodes         uint64 `json:"quota_inodes"`
}

type RestartVolumeRequest struct {
	VolumeID string `json:"volume_id"`
	Reason   string `json:"reason"`
}

type ConfirmStrictFenceRequest struct {
	VolumeID       string `json:"volume_id"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type RetireVolumeRequest struct {
	VolumeID string `json:"volume_id"`
	Reason   string `json:"reason"`
}

type IssueMountRequest struct {
	VolumeID                 string   `json:"volume_id"`
	ProductAuthorization     string   `json:"product_authorization"`
	ClientCSRPEM             string   `json:"client_csr_pem"`
	Access                   []string `json:"access"`
	AutomaticReauthorization bool     `json:"automatic_reauthorization,omitempty"`
}

type ReauthorizeMountRequest struct {
	VolumeID             string   `json:"volume_id"`
	ProductAuthorization string   `json:"product_authorization"`
	ClientCSRPEM         string   `json:"client_csr_pem"`
	Access               []string `json:"access"`
	SessionID            string   `json:"session_id"`
	Sequence             uint64   `json:"sequence"`
}

type RefreshMountEnrollmentRequest struct {
	ClientCSRPEM string `json:"client_csr_pem"`
	SessionID    string `json:"session_id"`
	Sequence     uint64 `json:"sequence"`
}

type TerminateMountEnrollmentRequest struct {
	Reason string `json:"reason"`
}

type MountAuthorization struct {
	VolumeID                 string   `json:"volume_id"`
	AuthorityEndpoint        string   `json:"authority_endpoint"`
	AuthorityServerName      string   `json:"authority_server_name"`
	AuthorityCAPEM           string   `json:"authority_ca_pem"`
	ClientCertificatePEM     string   `json:"client_certificate_pem"`
	Capability               string   `json:"capability"`
	Access                   []string `json:"access"`
	ExpiresUnix              int64    `json:"expires_unix"`
	CertificateExpiresUnix   int64    `json:"certificate_expires_unix"`
	AuthorityGeneration      uint64   `json:"authority_generation"`
	SessionID                string   `json:"session_id,omitempty"`
	Sequence                 uint64   `json:"sequence,omitempty"`
	ReleaseID                string   `json:"release_id"`
	EnrollmentID             string   `json:"enrollment_id,omitempty"`
	EnrollmentCertificatePEM string   `json:"enrollment_certificate_pem,omitempty"`
	EnrollmentExpiresUnix    int64    `json:"enrollment_expires_unix,omitempty"`
}

type CellObservation struct {
	CellID           string              `json:"cell_id"`
	PlanGeneration   uint64              `json:"plan_generation"`
	ManagerReleaseID string              `json:"manager_release_id"`
	AgentReleaseID   string              `json:"agent_release_id"`
	HelperReleaseID  string              `json:"helper_release_id"`
	Volumes          []VolumeObservation `json:"volumes"`
	ObservedUnix     int64               `json:"observed_unix"`
}

type CellHeartbeat struct {
	CellID           string `json:"cell_id"`
	PlanGeneration   uint64 `json:"plan_generation"`
	ManagerReleaseID string `json:"manager_release_id"`
	AgentReleaseID   string `json:"agent_release_id"`
	HelperReleaseID  string `json:"helper_release_id"`
	ObservedUnix     int64  `json:"observed_unix"`
}

type VolumeObservation struct {
	VolumeID            string `json:"volume_id"`
	AuthorityGeneration uint64 `json:"authority_generation"`
	ProjectID           uint32 `json:"project_id"`
	ServiceUID          uint32 `json:"service_uid"`
	ServiceGID          uint32 `json:"service_gid"`
	ListenPort          uint16 `json:"listen_port"`
	Provisioned         bool   `json:"provisioned"`
	AuthorityRunning    bool   `json:"authority_running"`
	AuthorityAbsent     bool   `json:"authority_absent"`
	AuthorityCSRPEM     string `json:"authority_csr_pem,omitempty"`
	Error               string `json:"error,omitempty"`
}

type VolumeView struct {
	Volume
	AuthorityEndpoint string `json:"authority_endpoint"`
}

func NewState() State {
	return State{
		SchemaVersion: StateSchemaVersion, Cells: map[string]Cell{}, Volumes: map[string]Volume{}, Receipts: map[string]Receipt{},
		AuthorizationNonces: map[string]AuthorizationNonce{}, MountEnrollments: map[string]MountEnrollment{},
		MountAuthorizationContexts: map[string]MountAuthorizationContext{},
	}
}

func (state State) Validate() error {
	if state.SchemaVersion != StateSchemaVersion || state.Cells == nil || state.Volumes == nil || state.Receipts == nil || state.AuthorizationNonces == nil {
		return fmt.Errorf("%w: state schema", ErrInvalid)
	}
	if len(state.MountEnrollments) > MaxRetainedMountEnrollments {
		return fmt.Errorf("%w: mount enrollment capacity", ErrInvalid)
	}
	if len(state.MountAuthorizationContexts) > len(state.MountEnrollments) {
		return fmt.Errorf("%w: mount authorization context capacity", ErrInvalid)
	}
	projects := make(map[string]map[uint32]string)
	uids := make(map[string]map[uint32]string)
	ports := make(map[string]map[uint16]string)
	var allocatedBytes = make(map[string]uint64)
	var allocatedInodes = make(map[string]uint64)
	var volumeCounts = make(map[string]int)
	for id, cell := range state.Cells {
		if id != cell.ID || !cellplan.ValidID(id) || !validIdentity(cell.AvailabilityZone) ||
			net.ParseIP(cell.AuthorityHost) == nil && !validDNSName(cell.AuthorityHost) ||
			!validDNSName(cell.AuthorityDNSZone) || cell.CapacityBytes == 0 || cell.CapacityInodes == 0 ||
			cell.NextProjectID == 0 || cell.NextServiceUID < 1000 || cell.NextPort < 1024 || cell.PlanGeneration == 0 ||
			!validOptionalIdentity(cell.PlanReleaseID) ||
			!validOptionalIdentity(cell.LastManagerRelease) || !validOptionalIdentity(cell.LastAgentRelease) ||
			!validOptionalIdentity(cell.LastHelperRelease) || !validOptionalIdentity(cell.QuarantineReason) {
			return fmt.Errorf("%w: cell %q", ErrInvalid, id)
		}
		if cell.PlanIssuedUnix <= 0 || cell.PlanExpiresUnix <= cell.PlanIssuedUnix {
			return fmt.Errorf("%w: cell plan lifetime", ErrInvalid)
		}
		switch cell.Health {
		case CellUnknown, CellHealthy, CellDegraded, CellQuarantined:
		default:
			return fmt.Errorf("%w: cell health", ErrInvalid)
		}
		observedIdentity := cell.LastManagerRelease != "" || cell.LastAgentRelease != "" || cell.LastHelperRelease != ""
		if (cell.LastObservedUnix > 0) != observedIdentity || observedIdentity &&
			(cell.LastManagerRelease == "" || cell.LastAgentRelease == "" || cell.LastHelperRelease == "") {
			return fmt.Errorf("%w: cell observation identity", ErrInvalid)
		}
		projects[id] = map[uint32]string{}
		uids[id] = map[uint32]string{}
		ports[id] = map[uint16]string{}
	}
	for key, nonce := range state.AuthorizationNonces {
		if key == "" || !validIdentity(nonce.RequestID) || nonce.ExpiresUnix <= 0 {
			return fmt.Errorf("%w: authorization nonce", ErrInvalid)
		}
	}
	activeEnrollments := 0
	activeByAuthorizationDomain := make(map[string]int)
	activeByVolume := make(map[string]int)
	referencedAuthorizationContexts := make(map[string]struct{})
	for id, enrollment := range state.MountEnrollments {
		if id != enrollment.ID || !cellplan.ValidID(id) || !cellplan.ValidID(enrollment.VolumeID) ||
			!validIdentity(enrollment.Subject) || !validIdentity(enrollment.Owner) || !validAccess(enrollment.Access) || enrollment.PeerSPKI == "" ||
			!validIdentity(enrollment.AuthorizationDomain) || !validIdentity(enrollment.ProductIssuer) ||
			!cellplan.ValidID(enrollment.CellID) || !validDNSName(enrollment.AuthorityID) ||
			enrollment.AuthorityGeneration == 0 || enrollment.CreatedUnix <= 0 ||
			enrollment.ExpiresUnix <= enrollment.CreatedUnix || enrollment.UpdatedUnix < enrollment.CreatedUnix ||
			!validOptionalIdentity(enrollment.TerminationReason) {
			return fmt.Errorf("%w: mount enrollment %q", ErrInvalid, id)
		}
		peer, err := hex.DecodeString(enrollment.PeerSPKI)
		if err != nil || len(peer) != 32 || strings.ToLower(enrollment.PeerSPKI) != enrollment.PeerSPKI {
			return fmt.Errorf("%w: mount enrollment peer", ErrInvalid)
		}
		volume, ok := state.Volumes[enrollment.VolumeID]
		if !ok || volume.Owner != enrollment.Owner || volume.AuthorizationDomain != enrollment.AuthorizationDomain || volume.ProductIssuer != enrollment.ProductIssuer ||
			volume.CellID != enrollment.CellID || volume.AuthorityID != enrollment.AuthorityID {
			return fmt.Errorf("%w: mount enrollment volume binding", ErrInvalid)
		}
		switch enrollment.State {
		case MountEnrollmentActive:
			if enrollment.TerminationReason != "" {
				return fmt.Errorf("%w: active mount enrollment termination", ErrInvalid)
			}
			if volume.AuthorityGeneration != enrollment.AuthorityGeneration {
				return fmt.Errorf("%w: active mount enrollment authority generation", ErrInvalid)
			}
			activeEnrollments++
			activeByAuthorizationDomain[enrollment.AuthorizationDomain]++
			activeByVolume[enrollment.VolumeID]++
		case MountEnrollmentClosed, MountEnrollmentRevoked:
			if enrollment.TerminationReason == "" {
				return fmt.Errorf("%w: terminated mount enrollment reason", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: mount enrollment state", ErrInvalid)
		}
		if enrollment.SessionID == "" {
			if enrollment.LastSequence != 0 || enrollment.LastRequestSHA256 != "" || enrollment.LastAuthorization != nil || enrollment.LastAuthorizationContext != "" {
				return fmt.Errorf("%w: unbound mount enrollment sequence", ErrInvalid)
			}
		} else {
			session, err := base64.RawURLEncoding.DecodeString(enrollment.SessionID)
			if err != nil || len(session) != 16 || enrollment.LastSequence == 0 || !validSHA256Hex(enrollment.LastRequestSHA256) || enrollment.LastAuthorization == nil ||
				enrollment.LastAuthorization.SessionID != enrollment.SessionID || enrollment.LastAuthorization.Sequence != enrollment.LastSequence ||
				!validSHA256Hex(enrollment.LastAuthorizationContext) {
				return fmt.Errorf("%w: bound mount enrollment sequence", ErrInvalid)
			}
			if _, _, err := net.SplitHostPort(enrollment.LastAuthorization.AuthorityEndpoint); err != nil ||
				!validDNSName(enrollment.LastAuthorization.AuthorityServerName) ||
				enrollment.LastAuthorization.ClientCertificatePEM == "" || len(enrollment.LastAuthorization.ClientCertificatePEM) > 16<<10 ||
				enrollment.LastAuthorization.Capability == "" || len(enrollment.LastAuthorization.Capability) > 8192 ||
				enrollment.LastAuthorization.ExpiresUnix <= 0 || enrollment.LastAuthorization.CertificateExpiresUnix <= 0 {
				return fmt.Errorf("%w: mount authorization replay", ErrInvalid)
			}
			if _, ok := state.MountAuthorizationContexts[enrollment.LastAuthorizationContext]; !ok {
				return fmt.Errorf("%w: missing mount authorization context", ErrInvalid)
			}
			referencedAuthorizationContexts[enrollment.LastAuthorizationContext] = struct{}{}
		}
	}
	if activeEnrollments > MaxActiveMountEnrollments {
		return fmt.Errorf("%w: active mount enrollment capacity", ErrInvalid)
	}
	for _, count := range activeByAuthorizationDomain {
		if count > MaxActiveMountEnrollmentsPerAuthorizationDomain {
			return fmt.Errorf("%w: authorization-domain mount enrollment capacity", ErrInvalid)
		}
	}
	for _, count := range activeByVolume {
		if count > MaxActiveMountEnrollmentsPerVolume {
			return fmt.Errorf("%w: volume mount enrollment capacity", ErrInvalid)
		}
	}
	for id, context := range state.MountAuthorizationContexts {
		if _, referenced := referencedAuthorizationContexts[id]; !referenced || context.AuthorityCAPEM == "" || len(context.AuthorityCAPEM) > 4096 ||
			!validIdentity(context.ReleaseID) || mountAuthorizationContextID(context) != id {
			return fmt.Errorf("%w: mount authorization context", ErrInvalid)
		}
	}
	for id, receipt := range state.Receipts {
		if !validIdentity(id) || !validIdentity(receipt.Operation) || !validSHA256Hex(receipt.RequestHash) ||
			len(receipt.Response) == 0 || !json.Valid(receipt.Response) || receipt.CreatedUnix <= 0 {
			return fmt.Errorf("%w: idempotency receipt", ErrInvalid)
		}
	}
	for id, volume := range state.Volumes {
		cell, ok := state.Cells[volume.CellID]
		if id != volume.ID || !cellplan.ValidID(id) || !ok || !validIdentity(volume.AuthorizationDomain) || !validIdentity(volume.Owner) ||
			!validIdentity(volume.ProductIssuer) || volume.ProductPublicKeyPEM == "" || volume.QuotaBytes == 0 || volume.QuotaBytes%1024 != 0 || volume.QuotaInodes == 0 ||
			volume.ProjectID == 0 || volume.ServiceUID < 1000 || volume.ServiceGID < 1000 || volume.ListenPort < 1024 ||
			volume.ServiceGID != volume.ServiceUID || !validDNSName(volume.AuthorityID) || volume.AuthorityID != volume.AuthorityServerName ||
			!validDNSName(volume.AuthorityServerName) || volume.AuthorityGeneration == 0 || volume.CreatedUnix <= 0 ||
			volume.UpdatedUnix < volume.CreatedUnix || !validOptionalIdentity(volume.QuarantineReason) {
			return fmt.Errorf("%w: volume %q", ErrInvalid, id)
		}
		if (volume.AuthorityCertificate == "") != (volume.AuthorityCertExpires == 0) {
			return fmt.Errorf("%w: authority certificate lifetime", ErrInvalid)
		}
		if volume.AuthorityCertificate != "" && volume.AuthorityCSRPEM == "" ||
			volume.PriorStrictFenced != (volume.StrictFenceEvidence != "") ||
			volume.StrictFenceEvidence != "" && !validSHA256Hex(volume.StrictFenceEvidence) {
			return fmt.Errorf("%w: authority identity or fence evidence", ErrInvalid)
		}
		switch volume.State {
		case VolumeProvisioning, VolumeReady, VolumeFencing, VolumeRetired, VolumeQuarantined:
		default:
			return fmt.Errorf("%w: volume state", ErrInvalid)
		}
		if previous := projects[volume.CellID][volume.ProjectID]; previous != "" {
			return fmt.Errorf("%w: project ID shared by %s and %s", ErrInvalid, previous, id)
		}
		if previous := uids[volume.CellID][volume.ServiceUID]; previous != "" {
			return fmt.Errorf("%w: service UID shared by %s and %s", ErrInvalid, previous, id)
		}
		if previous := ports[volume.CellID][volume.ListenPort]; previous != "" {
			return fmt.Errorf("%w: port shared by %s and %s", ErrInvalid, previous, id)
		}
		projects[volume.CellID][volume.ProjectID] = id
		uids[volume.CellID][volume.ServiceUID] = id
		ports[volume.CellID][volume.ListenPort] = id
		allocatedBytes[volume.CellID] += volume.QuotaBytes
		allocatedInodes[volume.CellID] += volume.QuotaInodes
		volumeCounts[volume.CellID]++
		if volume.ProjectID >= cell.NextProjectID || volume.ServiceUID >= cell.NextServiceUID || volume.ListenPort >= cell.NextPort {
			return fmt.Errorf("%w: allocator reuse boundary", ErrInvalid)
		}
	}
	for id, cell := range state.Cells {
		if cell.AllocatedBytes != allocatedBytes[id] || cell.AllocatedInodes != allocatedInodes[id] ||
			cell.AllocatedBytes > cell.CapacityBytes || cell.AllocatedInodes > cell.CapacityInodes || volumeCounts[id] > MaxVolumesPerCell {
			return fmt.Errorf("%w: cell allocation accounting", ErrInvalid)
		}
	}
	return nil
}

func (state State) volumeView(volume Volume) VolumeView {
	cell := state.Cells[volume.CellID]
	return VolumeView{Volume: volume, AuthorityEndpoint: net.JoinHostPort(cell.AuthorityHost, fmt.Sprint(volume.ListenPort))}
}

func sortedCellIDs(cells map[string]Cell) []string {
	ids := make([]string, 0, len(cells))
	for id := range cells {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func validDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	return true
}

func validIdentity(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOptionalIdentity(value string) bool { return value == "" || validIdentity(value) }

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

func mountAuthorizationContextID(context MountAuthorizationContext) string {
	raw, err := json.Marshal(context)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func nowUnix(now func() time.Time) int64 { return now().UTC().Unix() }
