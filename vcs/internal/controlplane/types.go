// Package controlplane is the product-neutral PortableFS hosted manager core.
// It owns placement and authorization state, never filesystem contents.
package controlplane

import (
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
	StateSchemaVersion = 1
	MaxVolumesPerCell  = 256
)

var (
	ErrInvalid          = errors.New("controlplane: invalid request")
	ErrNotFound         = errors.New("controlplane: not found")
	ErrConflict         = errors.New("controlplane: conflict")
	ErrCapacity         = errors.New("controlplane: no cell has sufficient capacity")
	ErrIdempotencyReuse = errors.New("controlplane: idempotency key reused for a different request")
	ErrQuarantined      = errors.New("controlplane: resource is quarantined")
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
	SchemaVersion       uint32                        `json:"schema_version"`
	Cells               map[string]Cell               `json:"cells"`
	Volumes             map[string]Volume             `json:"volumes"`
	Receipts            map[string]Receipt            `json:"receipts"`
	AuthorizationNonces map[string]AuthorizationNonce `json:"authorization_nonces"`
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
	VolumeID             string   `json:"volume_id"`
	ProductAuthorization string   `json:"product_authorization"`
	ClientCSRPEM         string   `json:"client_csr_pem"`
	Access               []string `json:"access"`
}

type ReauthorizeMountRequest struct {
	VolumeID             string   `json:"volume_id"`
	ProductAuthorization string   `json:"product_authorization"`
	ClientCSRPEM         string   `json:"client_csr_pem"`
	Access               []string `json:"access"`
	SessionID            string   `json:"session_id"`
	Sequence             uint64   `json:"sequence"`
}

type MountAuthorization struct {
	VolumeID               string   `json:"volume_id"`
	AuthorityEndpoint      string   `json:"authority_endpoint"`
	AuthorityServerName    string   `json:"authority_server_name"`
	AuthorityCAPEM         string   `json:"authority_ca_pem"`
	ClientCertificatePEM   string   `json:"client_certificate_pem"`
	Capability             string   `json:"capability"`
	Access                 []string `json:"access"`
	ExpiresUnix            int64    `json:"expires_unix"`
	CertificateExpiresUnix int64    `json:"certificate_expires_unix"`
	AuthorityGeneration    uint64   `json:"authority_generation"`
	SessionID              string   `json:"session_id,omitempty"`
	Sequence               uint64   `json:"sequence,omitempty"`
	ReleaseID              string   `json:"release_id"`
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
	return State{SchemaVersion: StateSchemaVersion, Cells: map[string]Cell{}, Volumes: map[string]Volume{}, Receipts: map[string]Receipt{}, AuthorizationNonces: map[string]AuthorizationNonce{}}
}

func (state State) Validate() error {
	if state.SchemaVersion != StateSchemaVersion || state.Cells == nil || state.Volumes == nil || state.Receipts == nil || state.AuthorizationNonces == nil {
		return fmt.Errorf("%w: state schema", ErrInvalid)
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

func nowUnix(now func() time.Time) int64 { return now().UTC().Unix() }
