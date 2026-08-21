package controlplane

// These unexported v1 shapes and their validator exist only for offline
// migration reads. Runtime state is always schema v2.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
)

const legacyVolumeRetired VolumeState = "RETIRED"

type stateV1 struct {
	SchemaVersion              uint32                               `json:"schema_version"`
	Cells                      map[string]cellV1                    `json:"cells"`
	Volumes                    map[string]volumeV1                  `json:"volumes"`
	Receipts                   map[string]Receipt                   `json:"receipts"`
	AuthorizationNonces        map[string]AuthorizationNonce        `json:"authorization_nonces"`
	MountEnrollments           map[string]MountEnrollment           `json:"mount_enrollments,omitempty"`
	MountAuthorizationContexts map[string]MountAuthorizationContext `json:"mount_authorization_contexts,omitempty"`
	RenewalFences              map[string]uint64                    `json:"renewal_fences,omitempty"`
}

type cellV1 struct {
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

type volumeV1 struct {
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

func (state stateV1) Validate() error {
	if state.SchemaVersion != 1 || state.Cells == nil || state.Volumes == nil || state.Receipts == nil || state.AuthorizationNonces == nil ||
		len(state.MountEnrollments) > MaxRetainedMountEnrollments || len(state.RenewalFences) > MaxRenewalFences ||
		len(state.MountAuthorizationContexts) > len(state.MountEnrollments) {
		return fmt.Errorf("%w: v1 state schema", ErrInvalid)
	}
	projects := map[string]map[uint32]string{}
	uids := map[string]map[uint32]string{}
	ports := map[string]map[uint16]string{}
	allocatedBytes := map[string]uint64{}
	allocatedInodes := map[string]uint64{}
	volumeCounts := map[string]int{}
	for id, cell := range state.Cells {
		if id != cell.ID || !cellplan.ValidID(id) || !validIdentity(cell.AvailabilityZone) ||
			net.ParseIP(cell.AuthorityHost) == nil && !validDNSName(cell.AuthorityHost) || !validDNSName(cell.AuthorityDNSZone) ||
			cell.CapacityBytes == 0 || cell.CapacityInodes == 0 || cell.NextProjectID == 0 || cell.NextServiceUID < 1000 || cell.NextPort < 1024 ||
			cell.PlanGeneration == 0 || cell.PlanIssuedUnix <= 0 || cell.PlanExpiresUnix <= cell.PlanIssuedUnix ||
			!validOptionalIdentity(cell.PlanReleaseID) || !validOptionalIdentity(cell.LastManagerRelease) ||
			!validOptionalIdentity(cell.LastAgentRelease) || !validOptionalIdentity(cell.LastHelperRelease) || !validOptionalIdentity(cell.QuarantineReason) {
			return fmt.Errorf("%w: v1 cell %q", ErrInvalid, id)
		}
		switch cell.Health {
		case CellUnknown, CellHealthy, CellDegraded, CellQuarantined:
		default:
			return fmt.Errorf("%w: v1 cell health", ErrInvalid)
		}
		observed := cell.LastManagerRelease != "" || cell.LastAgentRelease != "" || cell.LastHelperRelease != ""
		if (cell.LastObservedUnix > 0) != observed || observed && (cell.LastManagerRelease == "" || cell.LastAgentRelease == "" || cell.LastHelperRelease == "") {
			return fmt.Errorf("%w: v1 cell observation", ErrInvalid)
		}
		projects[id], uids[id], ports[id] = map[uint32]string{}, map[uint32]string{}, map[uint16]string{}
	}
	for key, nonce := range state.AuthorizationNonces {
		if key == "" || !validIdentity(nonce.RequestID) || nonce.ExpiresUnix <= 0 {
			return fmt.Errorf("%w: v1 nonce", ErrInvalid)
		}
	}
	for key, epoch := range state.RenewalFences {
		issuer, scope, found := strings.Cut(key, "\x00")
		if !found || !validIdentity(issuer) || !validRenewalScope(scope) || epoch == 0 || epoch > productauth.MaxRenewalEpoch || renewalFenceKey(issuer, scope) != key {
			return fmt.Errorf("%w: v1 renewal fence", ErrInvalid)
		}
	}
	for id, volume := range state.Volumes {
		cell, ok := state.Cells[volume.CellID]
		if id != volume.ID || !cellplan.ValidID(id) || !ok || !validIdentity(volume.AuthorizationDomain) || !validIdentity(volume.Owner) ||
			!validIdentity(volume.ProductIssuer) || volume.ProductPublicKeyPEM == "" || volume.QuotaBytes == 0 || volume.QuotaBytes%1024 != 0 || volume.QuotaInodes == 0 ||
			volume.ProjectID == 0 || volume.ServiceUID < 1000 || volume.ServiceGID != volume.ServiceUID || volume.ListenPort < 1024 ||
			!validDNSName(volume.AuthorityID) || volume.AuthorityID != volume.AuthorityServerName || volume.AuthorityGeneration == 0 || volume.CreatedUnix <= 0 ||
			volume.UpdatedUnix < volume.CreatedUnix || !validOptionalIdentity(volume.QuarantineReason) ||
			(volume.AuthorityCertificate == "") != (volume.AuthorityCertExpires == 0) || volume.AuthorityCertificate != "" && volume.AuthorityCSRPEM == "" ||
			volume.PriorStrictFenced != (volume.StrictFenceEvidence != "") || volume.StrictFenceEvidence != "" && !validSHA256Hex(volume.StrictFenceEvidence) {
			return fmt.Errorf("%w: v1 volume %q", ErrInvalid, id)
		}
		switch volume.State {
		case VolumeProvisioning, VolumeReady, VolumeFencing, legacyVolumeRetired, VolumeQuarantined:
		default:
			return fmt.Errorf("%w: v1 volume state", ErrInvalid)
		}
		if projects[volume.CellID][volume.ProjectID] != "" || uids[volume.CellID][volume.ServiceUID] != "" || ports[volume.CellID][volume.ListenPort] != "" ||
			volume.ProjectID >= cell.NextProjectID || volume.ServiceUID >= cell.NextServiceUID || volume.ListenPort >= cell.NextPort {
			return fmt.Errorf("%w: v1 placement uniqueness", ErrInvalid)
		}
		projects[volume.CellID][volume.ProjectID], uids[volume.CellID][volume.ServiceUID], ports[volume.CellID][volume.ListenPort] = id, id, id
		allocatedBytes[volume.CellID] += volume.QuotaBytes
		allocatedInodes[volume.CellID] += volume.QuotaInodes
		volumeCounts[volume.CellID]++
	}
	for id, cell := range state.Cells {
		if cell.AllocatedBytes != allocatedBytes[id] || cell.AllocatedInodes != allocatedInodes[id] || cell.AllocatedBytes > cell.CapacityBytes ||
			cell.AllocatedInodes > cell.CapacityInodes || volumeCounts[id] > MaxVolumesPerCell {
			return fmt.Errorf("%w: v1 cell allocation", ErrInvalid)
		}
	}
	activeTotal := 0
	activeDomain := map[string]int{}
	activeVolume := map[string]int{}
	activeScopes := map[string]struct{}{}
	contexts := map[string]struct{}{}
	for id, enrollment := range state.MountEnrollments {
		volume, ok := state.Volumes[enrollment.VolumeID]
		if id != enrollment.ID || !cellplan.ValidID(id) || !cellplan.ValidID(enrollment.VolumeID) || !ok || !validIdentity(enrollment.Subject) ||
			!validIdentity(enrollment.Owner) || !validAccess(enrollment.Access) || enrollment.PeerSPKI == "" || !validIdentity(enrollment.AuthorizationDomain) ||
			!validIdentity(enrollment.ProductIssuer) || !cellplan.ValidID(enrollment.CellID) || !validDNSName(enrollment.AuthorityID) || enrollment.AuthorityGeneration == 0 ||
			enrollment.CreatedUnix <= 0 || enrollment.ExpiresUnix <= enrollment.CreatedUnix || enrollment.UpdatedUnix < enrollment.CreatedUnix ||
			volume.Owner != enrollment.Owner || volume.AuthorizationDomain != enrollment.AuthorizationDomain || volume.ProductIssuer != enrollment.ProductIssuer ||
			volume.CellID != enrollment.CellID || volume.AuthorityID != enrollment.AuthorityID || !validOptionalIdentity(enrollment.TerminationReason) ||
			(enrollment.RenewalScope == "") != (enrollment.RenewalEpoch == 0) || enrollment.RenewalEpoch > productauth.MaxRenewalEpoch ||
			enrollment.RenewalScope != "" && !validRenewalScope(enrollment.RenewalScope) {
			return fmt.Errorf("%w: v1 enrollment %q", ErrInvalid, id)
		}
		peer, err := hex.DecodeString(enrollment.PeerSPKI)
		if err != nil || len(peer) != 32 || strings.ToLower(enrollment.PeerSPKI) != enrollment.PeerSPKI {
			return fmt.Errorf("%w: v1 enrollment peer", ErrInvalid)
		}
		if enrollment.RenewalScope != "" {
			highWater, ok := state.RenewalFences[renewalFenceKey(enrollment.ProductIssuer, enrollment.RenewalScope)]
			if !ok || enrollment.RenewalEpoch > highWater || enrollment.State == MountEnrollmentActive && enrollment.RenewalEpoch < highWater {
				return fmt.Errorf("%w: v1 enrollment renewal fence", ErrInvalid)
			}
		}
		switch enrollment.State {
		case MountEnrollmentActive:
			if enrollment.TerminationReason != "" || volume.AuthorityGeneration != enrollment.AuthorityGeneration {
				return fmt.Errorf("%w: v1 active enrollment", ErrInvalid)
			}
			if enrollment.RenewalScope != "" {
				key := renewalFenceKey(enrollment.ProductIssuer, enrollment.RenewalScope)
				if _, duplicate := activeScopes[key]; duplicate {
					return fmt.Errorf("%w: v1 active renewal scope", ErrInvalid)
				}
				activeScopes[key] = struct{}{}
			}
			activeTotal++
			activeDomain[enrollment.AuthorizationDomain]++
			activeVolume[enrollment.VolumeID]++
		case MountEnrollmentClosed, MountEnrollmentRevoked:
			if enrollment.TerminationReason == "" {
				return fmt.Errorf("%w: v1 terminal enrollment", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: v1 enrollment state", ErrInvalid)
		}
		if enrollment.SessionID == "" {
			if enrollment.LastSequence != 0 || enrollment.LastRequestSHA256 != "" || enrollment.LastAuthorization != nil || enrollment.LastAuthorizationContext != "" {
				return fmt.Errorf("%w: v1 enrollment replay", ErrInvalid)
			}
		} else {
			session, err := base64.RawURLEncoding.DecodeString(enrollment.SessionID)
			if err != nil || len(session) != 16 || enrollment.LastSequence == 0 ||
				!validSHA256Hex(enrollment.LastRequestSHA256) || enrollment.LastAuthorization == nil ||
				enrollment.LastAuthorization.SessionID != enrollment.SessionID || enrollment.LastAuthorization.Sequence != enrollment.LastSequence ||
				!validSHA256Hex(enrollment.LastAuthorizationContext) {
				return fmt.Errorf("%w: v1 enrollment session", ErrInvalid)
			}
			if _, _, err := net.SplitHostPort(enrollment.LastAuthorization.AuthorityEndpoint); err != nil ||
				!validDNSName(enrollment.LastAuthorization.AuthorityServerName) ||
				enrollment.LastAuthorization.ClientCertificatePEM == "" || len(enrollment.LastAuthorization.ClientCertificatePEM) > 16<<10 ||
				enrollment.LastAuthorization.Capability == "" || len(enrollment.LastAuthorization.Capability) > 8192 ||
				enrollment.LastAuthorization.ExpiresUnix <= 0 || enrollment.LastAuthorization.CertificateExpiresUnix <= 0 {
				return fmt.Errorf("%w: v1 enrollment authorization replay", ErrInvalid)
			}
			if _, ok := state.MountAuthorizationContexts[enrollment.LastAuthorizationContext]; !ok {
				return fmt.Errorf("%w: v1 replay context", ErrInvalid)
			}
			contexts[enrollment.LastAuthorizationContext] = struct{}{}
		}
	}
	if activeTotal > MaxActiveMountEnrollments {
		return fmt.Errorf("%w: v1 enrollment capacity", ErrInvalid)
	}
	for _, count := range activeDomain {
		if count > MaxActiveMountEnrollmentsPerAuthorizationDomain {
			return fmt.Errorf("%w: v1 domain capacity", ErrInvalid)
		}
	}
	for _, count := range activeVolume {
		if count > MaxActiveMountEnrollmentsPerVolume {
			return fmt.Errorf("%w: v1 volume capacity", ErrInvalid)
		}
	}
	for id, context := range state.MountAuthorizationContexts {
		if _, ok := contexts[id]; !ok || context.AuthorityCAPEM == "" || len(context.AuthorityCAPEM) > 4096 || !validIdentity(context.ReleaseID) || mountAuthorizationContextID(context) != id {
			return fmt.Errorf("%w: v1 context", ErrInvalid)
		}
	}
	for id, receipt := range state.Receipts {
		if !validIdentity(id) || !validIdentity(receipt.Operation) || !validSHA256Hex(receipt.RequestHash) || len(receipt.Response) == 0 || !json.Valid(receipt.Response) || receipt.CreatedUnix <= 0 {
			return fmt.Errorf("%w: v1 receipt", ErrInvalid)
		}
	}
	return nil
}
