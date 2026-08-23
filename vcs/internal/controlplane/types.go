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
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
)

const (
	StateSchemaVersion                              = 2
	MaxVolumesPerCell                               = 256
	MaxActiveMountEnrollments                       = 2048
	MaxActiveMountEnrollmentsPerAuthorizationDomain = 512
	MaxActiveMountEnrollmentsPerVolume              = 256
	MaxRetainedMountEnrollments                     = 4096
	MaxRenewalFenceBatchEntries                     = 4096
	// MaxRenewalFences keeps the index comfortably below the 64 MiB serialized
	// state cap. Deletion waits for a future scope-retirement coordinator because
	// removing a high-water mark would re-admit lower generations.
	MaxRenewalFences         = 65536
	MaxOrphanedPlacements    = 4096
	MaxArchivePacks          = 1024
	MaxArchiveObjectKeyBytes = 512
	MaxArchiveRecordBytes    = 512 << 10
)

var (
	ErrInvalid  = errors.New("controlplane: invalid request")
	ErrNotFound = errors.New("controlplane: not found")
	ErrConflict = errors.New("controlplane: conflict")
	ErrCapacity = errors.New("controlplane: no cell has sufficient capacity")
	// ErrCellUnavailable is transient and carries no state change: a durable
	// cell can fit the placement, but its process-liveness or full-usage
	// evidence is not currently fresh enough for admission.
	ErrCellUnavailable         = errors.New("controlplane: cells with sufficient capacity are temporarily unavailable")
	ErrEnrollmentCapacity      = errors.New("controlplane: mount enrollment capacity reached")
	ErrRenewalFenceCapacity    = errors.New("controlplane: renewal fence capacity reached")
	ErrIdempotencyReuse        = errors.New("controlplane: idempotency key reused for a different request")
	ErrQuarantined             = errors.New("controlplane: resource is quarantined")
	ErrEnrollmentEnded         = errors.New("controlplane: mount enrollment has ended")
	ErrRenewalScopeFenced      = errors.New("renewal_scope_fenced")
	ErrArchiveStoreUnavailable = errors.New("controlplane: archive store unavailable")
	// ErrArchiveUnsupported means this deployment cannot perform the requested
	// archive-tier operation at all: the volume's cell advertises no archive
	// configuration, or the Manager itself runs without the archive component
	// (verifier, purger) the operation needs. It is a durable configuration
	// fact, not load and not a state race, so clients must surface it to an
	// operator rather than retry it as busy — which is why it is distinct from
	// both ErrArchiveStoreUnavailable (the store exists but is unreachable
	// right now) and ErrConflict (the volume is not in an eligible state).
	ErrArchiveUnsupported = errors.New("controlplane: archiving is not supported by this deployment")
	// ErrBusy is transient and carries no state change: the request was refused
	// only because a per-cell archive/restore concurrency cap is currently full,
	// so an unchanged retry on a later sweep is the correct response. It is
	// deliberately distinct from ErrCapacity, which means the fleet cannot hold
	// the volume at all.
	ErrBusy = errors.New("controlplane: cell archive or restore concurrency is saturated")
)

type VolumeState string

const (
	VolumeProvisioning VolumeState = "PROVISIONING"
	VolumeReady        VolumeState = "READY"
	VolumeFencing      VolumeState = "FENCING"
	VolumeQuarantined  VolumeState = "QUARANTINED"
	VolumeArchiving    VolumeState = "ARCHIVING"
	VolumeArchived     VolumeState = "ARCHIVED"
	VolumeRestoring    VolumeState = "RESTORING"
	VolumeDestroying   VolumeState = "DESTROYING"
	VolumeDestroyed    VolumeState = "DESTROYED"
)

const (
	PoolProduct = "product"
	PoolSystem  = "system"
	PoolTest    = "test"
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
	RenewalFences              map[string]uint64                    `json:"renewal_fences,omitempty"`
	OrphanedPlacements         []OrphanedPlacement                  `json:"orphaned_placements,omitempty"`
}

type Cell struct {
	ID               string `json:"id"`
	AvailabilityZone string `json:"availability_zone"`
	AuthorityHost    string `json:"authority_host"`
	AuthorityDNSZone string `json:"authority_dns_zone"`
	CapacityBytes    uint64 `json:"capacity_bytes"`
	CapacityInodes   uint64 `json:"capacity_inodes"`
	Pool             string `json:"pool"`
	Decommissioning  bool   `json:"decommissioning,omitempty"`
	Abandoned        bool   `json:"abandoned,omitempty"`
	NextProjectID    uint32 `json:"next_project_id"`
	NextServiceUID   uint32 `json:"next_service_uid"`
	NextPort         uint16 `json:"next_port"`
	// Last* values are inclusive immutable lifetime bounds. Next* may equal
	// Last*+1 only after the final identity has been consumed.
	LastProjectID      uint32     `json:"last_project_id,omitempty"`
	LastServiceUID     uint32     `json:"last_service_uid,omitempty"`
	LastPort           uint16     `json:"last_port,omitempty"`
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
	// These arrays remain in the durable schema so strict decoding accepts
	// schema-v2 snapshots written before plan negotiation was removed.
	PlanVersions        []uint32 `json:"plan_versions,omitempty"`
	HelperPlanVersions  []uint32 `json:"helper_plan_versions,omitempty"`
	HelperStateVersions []uint32 `json:"helper_state_versions,omitempty"`
	// ArchiveConfigured is the cell's own report that its helper holds readable
	// archive-store credentials. A cell without them can neither export nor
	// hydrate, so archive and restore work is never placed on one. Absent in
	// persisted state it decodes false, which refuses that work until the cell
	// reports otherwise.
	ArchiveConfigured bool `json:"archive_configured,omitempty"`
	// RegistrationSHA256 pins the exact normalized registration declaration.
	// Convergent PUT may then return the live Cell without replaying initial
	// capacity or allocator values over state that has advanced since creation.
	RegistrationSHA256 string `json:"registration_sha256,omitempty"`
}

func cellAllocatorBounded(cell Cell) bool {
	return cell.LastProjectID != 0 && cell.LastServiceUID != 0 && cell.LastPort != 0
}

type Volume struct {
	ID                      string         `json:"id"`
	AuthorizationDomain     string         `json:"authorization_domain"`
	Owner                   string         `json:"owner"`
	ProductIssuer           string         `json:"product_issuer"`
	ProductPublicKeyPEM     string         `json:"product_public_key_pem"`
	QuotaBytes              uint64         `json:"quota_bytes"`
	QuotaInodes             uint64         `json:"quota_inodes"`
	AuthorityEpoch          uint64         `json:"authority_generation"`
	PlacementSequence       uint64         `json:"placement_sequence"`
	State                   VolumeState    `json:"state"`
	Pool                    string         `json:"pool"`
	Placement               *Placement     `json:"placement,omitempty"`
	Archive                 *ArchiveRecord `json:"archive,omitempty"`
	PendingSeal             *ArchiveRecord `json:"pending_seal,omitempty"`
	ArchiveCycleStep        string         `json:"archive_cycle_step,omitempty"`
	ArchiveAttempt          string         `json:"archive_attempt,omitempty"`
	RestoreStep             string         `json:"restore_step,omitempty"`
	RestoreProgressPermille uint32         `json:"restore_progress_permille,omitempty"`
	RestoreState            string         `json:"restore_state,omitempty"`
	RestoreConvergedUnix    int64          `json:"restore_converged_unix,omitempty"`
	WakeRequested           bool           `json:"wake_requested,omitempty"`
	DeletionRequested       bool           `json:"deletion_requested,omitempty"`
	DestroyedUnix           int64          `json:"destroyed_unix,omitempty"`
	QuarantineReason        string         `json:"quarantine_reason,omitempty"`
	CreatedUnix             int64          `json:"created_unix"`
	UpdatedUnix             int64          `json:"updated_unix"`
}

type Placement struct {
	CellID                  string `json:"cell_id"`
	Sequence                uint64 `json:"sequence"`
	ProjectID               uint32 `json:"project_id"`
	ServiceUID              uint32 `json:"service_uid"`
	ServiceGID              uint32 `json:"service_gid"`
	ListenPort              uint16 `json:"listen_port"`
	AuthorityID             string `json:"authority_id"`
	AuthorityServerName     string `json:"authority_server_name"`
	AuthorityCSRPEM         string `json:"authority_csr_pem,omitempty"`
	AuthorityCertificatePEM string `json:"authority_certificate_pem,omitempty"`
	AuthorityCertExpires    int64  `json:"authority_certificate_expires_unix,omitempty"`
	PriorStrictFenced       bool   `json:"prior_strict_mounts_fenced"`
	StrictFenceEvidence     string `json:"strict_fence_evidence_sha256,omitempty"`
	CreatedUnix             int64  `json:"created_unix"`
	LastObservedUnix        int64  `json:"last_observed_unix,omitempty"`
	UsedBytes               uint64 `json:"used_bytes,omitempty"`
	UsedInodes              uint64 `json:"used_inodes,omitempty"`
	UsedObservedUnix        int64  `json:"used_observed_unix,omitempty"`
	PendingBytes            uint64 `json:"pending_bytes,omitempty"`
	PendingInodes           uint64 `json:"pending_inodes,omitempty"`
	DestroyProofSHA256      string `json:"destroy_proof_sha256,omitempty"`
}

type ObjectRef struct {
	Key       string `json:"key"`
	SizeBytes uint64 `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	CRC64NVME string `json:"crc64nvme,omitempty"`
}

type ArchiveRecord struct {
	FormatVersion        uint32      `json:"format_version"`
	ChunkSizeBytes       uint32      `json:"chunk_size_bytes"`
	Attempt              string      `json:"attempt"`
	SealedEpoch          uint64      `json:"sealed_epoch"`
	SealedUnix           int64       `json:"sealed_unix"`
	Manifest             ObjectRef   `json:"manifest"`
	Packs                []ObjectRef `json:"packs"`
	RootDigest           string      `json:"root_digest_sha256"`
	LogicalBytes         uint64      `json:"logical_bytes"`
	LogicalInodes        uint64      `json:"logical_inodes"`
	SealedAllocatedBytes uint64      `json:"sealed_allocated_bytes"`
	SealedInodes         uint64      `json:"sealed_inodes"`
	KeyVersion           string      `json:"key_version"`
	// SealedMeasured* is the placement's last measured usage at the moment the
	// verified seal committed. Zero means unmeasured and stays valid: records
	// sealed before this field existed decode zero, and restore admission takes
	// the maximum of it and the archive's own sizing.
	SealedMeasuredBytes  uint64 `json:"sealed_measured_bytes,omitempty"`
	SealedMeasuredInodes uint64 `json:"sealed_measured_inodes,omitempty"`
}

type OrphanedPlacement struct {
	VolumeID     string                 `json:"volume_id"`
	CellID       string                 `json:"cell_id"`
	Placement    OrphanedPlacementTuple `json:"placement"`
	Epoch        uint64                 `json:"authority_generation"`
	RecordedUnix int64                  `json:"recorded_unix"`
	Reason       string                 `json:"reason"`
}

type OrphanedPlacementTuple struct {
	Sequence            uint64 `json:"sequence"`
	ProjectID           uint32 `json:"project_id"`
	ServiceUID          uint32 `json:"service_uid"`
	ServiceGID          uint32 `json:"service_gid"`
	ListenPort          uint16 `json:"listen_port"`
	AuthorityID         string `json:"authority_id"`
	AuthorityServerName string `json:"authority_server_name"`
	DestroyProofSHA256  string `json:"destroy_proof_sha256,omitempty"`
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
	MountEnrollmentExpired MountEnrollmentState = "EXPIRED"
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
	RenewalScope             string                    `json:"renewal_scope,omitempty"`
	RenewalEpoch             uint64                    `json:"renewal_epoch,omitempty"`
}

type MountEnrollmentRevocationOutcome string

const (
	MountEnrollmentRevocationRevoked MountEnrollmentRevocationOutcome = "REVOKED"
	MountEnrollmentRevocationClosed  MountEnrollmentRevocationOutcome = "CLOSED"
	MountEnrollmentRevocationExpired MountEnrollmentRevocationOutcome = "EXPIRED"
	MountEnrollmentRevocationAbsent  MountEnrollmentRevocationOutcome = "ABSENT"
)

type MountEnrollmentRevocation struct {
	VolumeID     string                           `json:"volume_id"`
	EnrollmentID string                           `json:"enrollment_id"`
	Outcome      MountEnrollmentRevocationOutcome `json:"outcome"`
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
	Pool             string `json:"pool"`
	FirstProjectID   uint32 `json:"first_project_id,omitempty"`
	FirstServiceUID  uint32 `json:"first_service_uid,omitempty"`
	FirstPort        uint16 `json:"first_port,omitempty"`
	LastProjectID    uint32 `json:"last_project_id"`
	LastServiceUID   uint32 `json:"last_service_uid"`
	LastPort         uint16 `json:"last_port"`
}

type CreateVolumeRequest struct {
	AuthorizationDomain string `json:"authorization_domain"`
	Owner               string `json:"owner"`
	ProductIssuer       string `json:"product_issuer"`
	QuotaBytes          uint64 `json:"quota_bytes"`
	QuotaInodes         uint64 `json:"quota_inodes"`
	Pool                string `json:"pool,omitempty"`
}

type ArchiveVolumeRequest struct {
	VolumeID string `json:"volume_id"`
}
type WakeVolumeRequest struct {
	VolumeID string `json:"volume_id"`
}
type DestroyVolumeRequest struct {
	VolumeID string `json:"volume_id"`
	Reason   string `json:"reason"`
}
type UpdateCellCapacityRequest struct {
	CapacityBytes  uint64 `json:"capacity_bytes"`
	CapacityInodes uint64 `json:"capacity_inodes"`
}
type DecommissionCellRequest struct {
	Reason string `json:"reason"`
}
type AbandonCellRequest struct {
	Reason string `json:"reason"`
}

type RestartVolumeRequest struct {
	VolumeID string `json:"volume_id"`
	Reason   string `json:"reason"`
}

type ConfirmStrictFenceRequest struct {
	VolumeID       string `json:"volume_id"`
	EvidenceSHA256 string `json:"evidence_sha256"`
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

type RenewalFence struct {
	Scope string `json:"scope"`
	Epoch uint64 `json:"epoch"`
}

type AdvanceRenewalFencesRequest struct {
	Reason string         `json:"reason"`
	Fences []RenewalFence `json:"fences"`
}

type AdvanceRenewalFencesResponse struct {
	Fences []RenewalFence `json:"fences"`
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
}

type CellObservation struct {
	CellID            string              `json:"cell_id"`
	PlanGeneration    uint64              `json:"plan_generation"`
	ManagerReleaseID  string              `json:"manager_release_id"`
	AgentReleaseID    string              `json:"agent_release_id"`
	HelperReleaseID   string              `json:"helper_release_id"`
	Volumes           []VolumeObservation `json:"volumes"`
	ObservedUnix      int64               `json:"observed_unix"`
	ArchiveConfigured bool                `json:"archive_configured,omitempty"`
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
	VolumeID                string                    `json:"volume_id"`
	AuthorityGeneration     uint64                    `json:"authority_generation"`
	ProjectID               uint32                    `json:"project_id"`
	ServiceUID              uint32                    `json:"service_uid"`
	ServiceGID              uint32                    `json:"service_gid"`
	ListenPort              uint16                    `json:"listen_port"`
	Provisioned             bool                      `json:"provisioned"`
	AuthorityRunning        bool                      `json:"authority_running"`
	AuthorityAbsent         bool                      `json:"authority_absent"`
	AuthorityCSRPEM         string                    `json:"authority_csr_pem,omitempty"`
	Error                   string                    `json:"error,omitempty"`
	UsedBytes               uint64                    `json:"used_bytes,omitempty"`
	UsedInodes              uint64                    `json:"used_inodes,omitempty"`
	QuiesceProven           bool                      `json:"quiesce_proven,omitempty"`
	ArchiveSealed           *ArchiveSealedObservation `json:"archive_sealed,omitempty"`
	DestroyProofSHA256      string                    `json:"destroy_proof_sha256,omitempty"`
	Released                bool                      `json:"released,omitempty"`
	RestoreNamespaceReady   bool                      `json:"restore_namespace_ready,omitempty"`
	RestoreConverged        bool                      `json:"restore_converged,omitempty"`
	RestoreProgressPermille uint32                    `json:"restore_progress_permille,omitempty"`
	RestoreState            string                    `json:"restore_state,omitempty"`
}

type ArchiveSealedObservation struct {
	Attempt              string      `json:"attempt"`
	Manifest             ObjectRef   `json:"manifest"`
	Packs                []ObjectRef `json:"packs"`
	RootDigest           string      `json:"root_digest_sha256"`
	LogicalBytes         uint64      `json:"logical_bytes"`
	LogicalInodes        uint64      `json:"logical_inodes"`
	SealedAllocatedBytes uint64      `json:"sealed_allocated_bytes"`
	SealedInodes         uint64      `json:"sealed_inodes"`
	FormatVersion        uint32      `json:"format_version"`
	ChunkSizeBytes       uint32      `json:"chunk_size_bytes"`
	KeyVersion           string      `json:"key_version"`
}

type PoolCapacity struct {
	Pool               string `json:"pool"`
	CapacityBytes      uint64 `json:"capacity_bytes"`
	CapacityInodes     uint64 `json:"capacity_inodes"`
	MeasuredUsedBytes  uint64 `json:"measured_used_bytes"`
	MeasuredUsedInodes uint64 `json:"measured_used_inodes"`
	PendingBytes       uint64 `json:"pending_bytes"`
	PendingInodes      uint64 `json:"pending_inodes"`
	Placements         uint64 `json:"placements"`
	ArchivedVolumes    uint64 `json:"archived_volumes"`
	CreateAdmissible   bool   `json:"create_admissible"`
	RestoreAdmissible  bool   `json:"restore_admissible"`
	// CreateStatus and RestoreStatus preserve the two historical booleans while
	// distinguishing transient cell unavailability from durable headroom
	// exhaustion. They are the result of probing the standard provision floor.
	CreateStatus  AdmissionStatus `json:"create_status"`
	RestoreStatus AdmissionStatus `json:"restore_status"`
}

type AdmissionStatus string

const (
	AdmissionAdmissible      AdmissionStatus = "ADMISSIBLE"
	AdmissionCellUnavailable AdmissionStatus = "CELL_UNAVAILABLE"
	AdmissionCapacity        AdmissionStatus = "CAPACITY_EXHAUSTED"
	AdmissionBusy            AdmissionStatus = "BUSY"
)

type CapacityReport struct {
	Pools []PoolCapacity `json:"pools"`
}

type CellList struct {
	Cells []Cell `json:"cells"`
}

type VolumeList struct {
	Volumes []VolumeView `json:"volumes"`
}

// ArchiveSummaryView is the product-facing projection of a sealed archive:
// the identities a product needs (to address archived Files reads and display
// totals) and nothing else. Object keys, pack inventories, and digests are
// Manager-internal — the product holds no archive-store access and a large
// volume's pack list would bloat every volume poll.
type ArchiveSummaryView struct {
	SealedEpoch   uint64 `json:"sealed_epoch"`
	Attempt       string `json:"attempt"`
	LogicalBytes  uint64 `json:"logical_bytes"`
	LogicalInodes uint64 `json:"logical_inodes"`
	SealedUnix    int64  `json:"sealed_unix"`
}

type VolumeView struct {
	Volume
	AuthorityEndpoint string              `json:"authority_endpoint"`
	ArchiveSummary    *ArchiveSummaryView `json:"archive_summary,omitempty"`
}

func NewState() State {
	return State{
		SchemaVersion: StateSchemaVersion, Cells: map[string]Cell{}, Volumes: map[string]Volume{}, Receipts: map[string]Receipt{},
		AuthorizationNonces: map[string]AuthorizationNonce{}, MountEnrollments: map[string]MountEnrollment{},
		MountAuthorizationContexts: map[string]MountAuthorizationContext{}, RenewalFences: map[string]uint64{},
		OrphanedPlacements: []OrphanedPlacement{},
	}
}

func (state State) Validate() error {
	if state.SchemaVersion != StateSchemaVersion || state.Cells == nil || state.Volumes == nil || state.Receipts == nil || state.AuthorizationNonces == nil {
		return fmt.Errorf("%w: state schema", ErrInvalid)
	}
	if len(state.MountEnrollments) > MaxRetainedMountEnrollments {
		return fmt.Errorf("%w: mount enrollment capacity", ErrInvalid)
	}
	if len(state.RenewalFences) > MaxRenewalFences {
		return fmt.Errorf("%w: renewal fence capacity", ErrInvalid)
	}
	if len(state.MountAuthorizationContexts) > len(state.MountEnrollments) {
		return fmt.Errorf("%w: mount authorization context capacity", ErrInvalid)
	}
	projects := make(map[string]map[uint32]string)
	uids := make(map[string]map[uint32]string)
	ports := make(map[string]map[uint16]string)
	var volumeCounts = make(map[string]int)
	for id, cell := range state.Cells {
		boundedAllocators := cell.LastProjectID != 0 || cell.LastServiceUID != 0 || cell.LastPort != 0
		if id != cell.ID || !cellplan.ValidID(id) || !validIdentity(cell.AvailabilityZone) ||
			net.ParseIP(cell.AuthorityHost) == nil && !validDNSName(cell.AuthorityHost) ||
			!validDNSName(cell.AuthorityDNSZone) || cell.CapacityBytes == 0 || cell.CapacityInodes == 0 ||
			cell.NextProjectID == 0 || cell.NextServiceUID < 1000 || cell.NextPort < 1024 || cell.PlanGeneration == 0 ||
			!validPool(cell.Pool) ||
			!validOptionalIdentity(cell.PlanReleaseID) ||
			!validOptionalIdentity(cell.LastManagerRelease) || !validOptionalIdentity(cell.LastAgentRelease) ||
			!validOptionalIdentity(cell.LastHelperRelease) || !validOptionalIdentity(cell.QuarantineReason) ||
			cell.RegistrationSHA256 != "" && !validSHA256Hex(cell.RegistrationSHA256) {
			return fmt.Errorf("%w: cell %q", ErrInvalid, id)
		}
		if boundedAllocators != cellAllocatorBounded(cell) ||
			cellAllocatorBounded(cell) && cell.RegistrationSHA256 == "" ||
			cellAllocatorBounded(cell) && (cell.LastProjectID == ^uint32(0) || cell.LastServiceUID == ^uint32(0) || cell.LastPort == ^uint16(0) ||
				cell.NextProjectID > cell.LastProjectID+1 || cell.NextServiceUID > cell.LastServiceUID+1 || cell.NextPort > cell.LastPort+1) {
			return fmt.Errorf("%w: cell allocator bounds", ErrInvalid)
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
		// Archive capability is a reported observation, never an assumption: it
		// can only be set on a cell that has actually reported.
		if cell.ArchiveConfigured && !observedIdentity {
			return fmt.Errorf("%w: cell archive capability without observation", ErrInvalid)
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
	for key, epoch := range state.RenewalFences {
		issuer, scope, found := strings.Cut(key, "\x00")
		if !found || !validIdentity(issuer) || !validRenewalScope(scope) || epoch == 0 || epoch > productauth.MaxRenewalEpoch || renewalFenceKey(issuer, scope) != key {
			return fmt.Errorf("%w: renewal fence", ErrInvalid)
		}
	}
	activeEnrollments := 0
	activeByAuthorizationDomain := make(map[string]int)
	activeByVolume := make(map[string]int)
	activeRenewalScopeVolumes := make(map[string]struct{})
	referencedAuthorizationContexts := make(map[string]struct{})
	for id, enrollment := range state.MountEnrollments {
		if id != enrollment.ID || !cellplan.ValidID(id) || !cellplan.ValidID(enrollment.VolumeID) ||
			!validIdentity(enrollment.Subject) || !validIdentity(enrollment.Owner) || !validAccess(enrollment.Access) || enrollment.PeerSPKI == "" ||
			!validIdentity(enrollment.AuthorizationDomain) || !validIdentity(enrollment.ProductIssuer) ||
			enrollment.CreatedUnix <= 0 ||
			enrollment.ExpiresUnix <= enrollment.CreatedUnix || enrollment.UpdatedUnix < enrollment.CreatedUnix ||
			!validOptionalIdentity(enrollment.TerminationReason) ||
			(enrollment.RenewalScope == "") != (enrollment.RenewalEpoch == 0) ||
			enrollment.RenewalEpoch > productauth.MaxRenewalEpoch ||
			enrollment.RenewalScope != "" && !validRenewalScope(enrollment.RenewalScope) {
			return fmt.Errorf("%w: mount enrollment %q", ErrInvalid, id)
		}
		peer, err := hex.DecodeString(enrollment.PeerSPKI)
		if err != nil || len(peer) != 32 || strings.ToLower(enrollment.PeerSPKI) != enrollment.PeerSPKI {
			return fmt.Errorf("%w: mount enrollment peer", ErrInvalid)
		}
		volume, ok := state.Volumes[enrollment.VolumeID]
		if !ok || volume.Owner != enrollment.Owner || volume.AuthorizationDomain != enrollment.AuthorizationDomain || volume.ProductIssuer != enrollment.ProductIssuer {
			return fmt.Errorf("%w: mount enrollment volume binding", ErrInvalid)
		}
		if enrollment.RenewalScope != "" {
			highWater, ok := state.RenewalFences[renewalFenceKey(enrollment.ProductIssuer, enrollment.RenewalScope)]
			if !ok || enrollment.RenewalEpoch > highWater || enrollment.State == MountEnrollmentActive && enrollment.RenewalEpoch < highWater {
				return fmt.Errorf("%w: mount enrollment renewal fence", ErrInvalid)
			}
		}
		switch enrollment.State {
		case MountEnrollmentActive:
			if enrollment.TerminationReason != "" {
				return fmt.Errorf("%w: active mount enrollment termination", ErrInvalid)
			}
			if enrollment.RenewalScope != "" {
				key := renewalFenceKey(enrollment.ProductIssuer, enrollment.RenewalScope) + "\x00" + enrollment.VolumeID
				if _, exists := activeRenewalScopeVolumes[key]; exists {
					return fmt.Errorf("%w: active mount enrollment renewal scope and volume", ErrInvalid)
				}
				activeRenewalScopeVolumes[key] = struct{}{}
			}
			if volume.Placement == nil || !cellplan.ValidID(enrollment.CellID) || !validDNSName(enrollment.AuthorityID) || enrollment.AuthorityGeneration == 0 ||
				volume.Placement.CellID != enrollment.CellID || volume.Placement.AuthorityID != enrollment.AuthorityID || volume.AuthorityEpoch != enrollment.AuthorityGeneration {
				return fmt.Errorf("%w: active mount enrollment placement binding", ErrInvalid)
			}
			activeEnrollments++
			activeByAuthorizationDomain[enrollment.AuthorizationDomain]++
			activeByVolume[enrollment.VolumeID]++
		case MountEnrollmentClosed, MountEnrollmentRevoked, MountEnrollmentExpired:
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
		if err := validateVolume(id, volume, state.Cells); err != nil {
			return err
		}
		if volume.Placement == nil {
			continue
		}
		placement := volume.Placement
		cell := state.Cells[placement.CellID]
		if previous := projects[placement.CellID][placement.ProjectID]; previous != "" {
			return fmt.Errorf("%w: project ID shared by %s and %s", ErrInvalid, previous, id)
		}
		if previous := uids[placement.CellID][placement.ServiceUID]; previous != "" {
			return fmt.Errorf("%w: service UID shared by %s and %s", ErrInvalid, previous, id)
		}
		if previous := ports[placement.CellID][placement.ListenPort]; previous != "" {
			return fmt.Errorf("%w: port shared by %s and %s", ErrInvalid, previous, id)
		}
		projects[placement.CellID][placement.ProjectID] = id
		uids[placement.CellID][placement.ServiceUID] = id
		ports[placement.CellID][placement.ListenPort] = id
		volumeCounts[placement.CellID]++
		if placement.ProjectID >= cell.NextProjectID || placement.ServiceUID >= cell.NextServiceUID || placement.ListenPort >= cell.NextPort ||
			cellAllocatorBounded(cell) && (placement.ProjectID > cell.LastProjectID || placement.ServiceUID > cell.LastServiceUID || placement.ListenPort > cell.LastPort) {
			return fmt.Errorf("%w: allocator reuse boundary", ErrInvalid)
		}
	}
	for id := range state.Cells {
		if volumeCounts[id] > MaxVolumesPerCell {
			return fmt.Errorf("%w: cell placement count", ErrInvalid)
		}
	}
	if len(state.OrphanedPlacements) > MaxOrphanedPlacements {
		return fmt.Errorf("%w: orphaned placement capacity", ErrInvalid)
	}
	for _, orphan := range state.OrphanedPlacements {
		if !cellplan.ValidID(orphan.VolumeID) || !cellplan.ValidID(orphan.CellID) || orphan.Epoch == 0 || orphan.RecordedUnix <= 0 ||
			!validIdentity(orphan.Reason) || orphan.Placement.Sequence == 0 || orphan.Placement.ProjectID == 0 || orphan.Placement.ServiceUID < 1000 ||
			orphan.Placement.ServiceGID != orphan.Placement.ServiceUID || orphan.Placement.ListenPort < 1024 ||
			!validDNSName(orphan.Placement.AuthorityID) || orphan.Placement.AuthorityID != orphan.Placement.AuthorityServerName ||
			orphan.Placement.DestroyProofSHA256 != "" && !validSHA256Hex(orphan.Placement.DestroyProofSHA256) {
			return fmt.Errorf("%w: orphaned placement", ErrInvalid)
		}
		cell, ok := state.Cells[orphan.CellID]
		if !ok {
			return fmt.Errorf("%w: orphaned placement cell", ErrInvalid)
		}
		if cellAllocatorBounded(cell) &&
			(orphan.Placement.ProjectID > cell.LastProjectID || orphan.Placement.ServiceUID > cell.LastServiceUID || orphan.Placement.ListenPort > cell.LastPort) {
			return fmt.Errorf("%w: orphaned placement allocator boundary", ErrInvalid)
		}
		want := "v-" + strings.ReplaceAll(orphan.VolumeID, "-", "") + "." + cell.AuthorityDNSZone
		if orphan.Placement.Sequence >= 2 {
			want = fmt.Sprintf("v-%s-p%d.%s", strings.ReplaceAll(orphan.VolumeID, "-", ""), orphan.Placement.Sequence, cell.AuthorityDNSZone)
		}
		if orphan.Placement.AuthorityServerName != want {
			return fmt.Errorf("%w: orphaned placement endpoint", ErrInvalid)
		}
	}
	return nil
}

func validateVolume(id string, volume Volume, cells map[string]Cell) error {
	if id != volume.ID || !cellplan.ValidID(id) || !validIdentity(volume.AuthorizationDomain) || !validIdentity(volume.Owner) ||
		!validIdentity(volume.ProductIssuer) || volume.ProductPublicKeyPEM == "" || volume.QuotaBytes == 0 || volume.QuotaBytes%1024 != 0 ||
		volume.QuotaInodes == 0 || volume.AuthorityEpoch == 0 || volume.PlacementSequence == 0 || !validPool(volume.Pool) ||
		volume.CreatedUnix <= 0 || volume.UpdatedUnix < volume.CreatedUnix || !validOptionalIdentity(volume.QuarantineReason) ||
		volume.RestoreProgressPermille > 1000 || volume.RestoreState != "" && volume.RestoreState != "blocked" && volume.RestoreState != "corrupt" {
		return fmt.Errorf("%w: volume %q", ErrInvalid, id)
	}
	if volume.Placement != nil {
		if err := validatePlacement(id, volume.PlacementSequence, *volume.Placement, cells, true); err != nil {
			return err
		}
	} else if volume.State != VolumeArchived && volume.State != VolumeDestroyed && !(volume.State == VolumeDestroying && volume.ArchiveCycleStep == "purging-archive") {
		return fmt.Errorf("%w: placement-free volume state", ErrInvalid)
	}
	if volume.Archive != nil {
		if err := volume.Archive.Validate(); err != nil {
			return err
		}
	}
	if volume.PendingSeal != nil {
		if err := volume.PendingSeal.Validate(); err != nil {
			return err
		}
	}
	switch volume.State {
	case VolumeProvisioning, VolumeReady, VolumeFencing, VolumeQuarantined:
		if volume.Placement == nil || volume.ArchiveCycleStep != "" || volume.ArchiveAttempt != "" || volume.PendingSeal != nil ||
			volume.RestoreStep != "" || volume.WakeRequested || volume.DeletionRequested || volume.DestroyedUnix != 0 {
			return fmt.Errorf("%w: ordinary volume cursor", ErrInvalid)
		}
		if volume.State != VolumeQuarantined && volume.Archive != nil && volume.Archive.SealedEpoch >= volume.AuthorityEpoch {
			return fmt.Errorf("%w: checkpoint epoch", ErrInvalid)
		}
	case VolumeArchiving:
		if volume.Placement == nil || !cellplan.ValidID(volume.ArchiveAttempt) || volume.RestoreStep != "" ||
			volume.DeletionRequested || volume.DestroyedUnix != 0 {
			return fmt.Errorf("%w: archiving shape", ErrInvalid)
		}
		if volume.Archive != nil && volume.Archive.SealedEpoch >= volume.AuthorityEpoch {
			return fmt.Errorf("%w: archiving checkpoint epoch", ErrInvalid)
		}
		switch volume.ArchiveCycleStep {
		case "quiescing", "exporting":
			if volume.PendingSeal != nil {
				return fmt.Errorf("%w: premature pending seal", ErrInvalid)
			}
		case "verifying":
			if volume.PendingSeal == nil || volume.PendingSeal.Attempt != volume.ArchiveAttempt || volume.PendingSeal.SealedEpoch != volume.AuthorityEpoch {
				return fmt.Errorf("%w: pending seal binding", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: archiving cursor", ErrInvalid)
		}
	case VolumeArchived:
		if volume.Archive == nil || volume.ArchiveAttempt != "" || volume.PendingSeal != nil || volume.RestoreStep != "" ||
			volume.DeletionRequested || volume.DestroyedUnix != 0 || volume.Archive.SealedEpoch != volume.AuthorityEpoch {
			return fmt.Errorf("%w: archived shape", ErrInvalid)
		}
		switch volume.ArchiveCycleStep {
		case "sealed":
			if volume.Placement == nil || volume.Placement.DestroyProofSHA256 != "" {
				return fmt.Errorf("%w: sealed placement", ErrInvalid)
			}
		case "destroyed":
			if volume.Placement == nil || !validSHA256Hex(volume.Placement.DestroyProofSHA256) {
				return fmt.Errorf("%w: destroyed placement", ErrInvalid)
			}
		case "released":
			if volume.Placement != nil {
				return fmt.Errorf("%w: released placement", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: archived cursor", ErrInvalid)
		}
	case VolumeRestoring:
		if volume.Placement == nil || volume.Archive == nil || volume.ArchiveCycleStep != "released" || volume.ArchiveAttempt != "" ||
			volume.PendingSeal != nil || volume.DestroyedUnix != 0 || volume.DeletionRequested || volume.Archive.SealedEpoch >= volume.AuthorityEpoch {
			return fmt.Errorf("%w: restoring shape", ErrInvalid)
		}
		switch volume.RestoreStep {
		case "restoring-namespace", "serving-restore":
		default:
			return fmt.Errorf("%w: restoring cursor", ErrInvalid)
		}
	case VolumeDestroying:
		if !volume.DeletionRequested || volume.WakeRequested || volume.ArchiveAttempt != "" || volume.PendingSeal != nil || volume.RestoreStep != "" || volume.DestroyedUnix != 0 {
			return fmt.Errorf("%w: destroying shape", ErrInvalid)
		}
		switch volume.ArchiveCycleStep {
		case "quiescing":
			if volume.Placement == nil || volume.Archive != nil {
				return fmt.Errorf("%w: destroying quiesce", ErrInvalid)
			}
		case "destroying":
			if volume.Placement == nil || volume.Archive != nil || volume.Placement.DestroyProofSHA256 != "" {
				return fmt.Errorf("%w: destroying host data", ErrInvalid)
			}
		case "destroyed":
			if volume.Placement == nil || volume.Archive != nil || !validSHA256Hex(volume.Placement.DestroyProofSHA256) {
				return fmt.Errorf("%w: destroying proof", ErrInvalid)
			}
		case "purging-archive":
			if volume.Placement != nil || volume.Archive == nil || volume.Archive.SealedEpoch != volume.AuthorityEpoch {
				return fmt.Errorf("%w: archive purge", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: destroying cursor", ErrInvalid)
		}
	case VolumeDestroyed:
		if volume.Placement != nil || volume.Archive != nil || volume.PendingSeal != nil || volume.ArchiveAttempt != "" || volume.RestoreStep != "" ||
			volume.ArchiveCycleStep != "" || volume.DestroyedUnix <= 0 || !volume.DeletionRequested {
			return fmt.Errorf("%w: destroyed shape", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: volume state", ErrInvalid)
	}
	return nil
}

func validatePlacement(volumeID string, sequence uint64, placement Placement, cells map[string]Cell, enforceSequence bool) error {
	cell, ok := cells[placement.CellID]
	if !ok || !cellplan.ValidID(placement.CellID) || placement.Sequence == 0 || enforceSequence && placement.Sequence != sequence ||
		placement.ProjectID == 0 || placement.ServiceUID < 1000 || placement.ServiceGID != placement.ServiceUID || placement.ListenPort < 1024 ||
		placement.AuthorityID == "" || placement.AuthorityID != placement.AuthorityServerName || !validDNSName(placement.AuthorityServerName) || placement.CreatedUnix <= 0 ||
		(placement.AuthorityCertificatePEM == "") != (placement.AuthorityCertExpires == 0) || placement.AuthorityCertificatePEM != "" && placement.AuthorityCSRPEM == "" ||
		placement.PriorStrictFenced != (placement.StrictFenceEvidence != "") || placement.StrictFenceEvidence != "" && !validSHA256Hex(placement.StrictFenceEvidence) ||
		placement.DestroyProofSHA256 != "" && !validSHA256Hex(placement.DestroyProofSHA256) ||
		placement.UsedObservedUnix == 0 && (placement.UsedBytes != 0 || placement.UsedInodes != 0) {
		return fmt.Errorf("%w: placement for volume %q", ErrInvalid, volumeID)
	}
	compactID := strings.ReplaceAll(volumeID, "-", "")
	want := "v-" + compactID + "." + cell.AuthorityDNSZone
	if placement.Sequence >= 2 {
		want = fmt.Sprintf("v-%s-p%d.%s", compactID, placement.Sequence, cell.AuthorityDNSZone)
	}
	if placement.AuthorityServerName != want {
		return fmt.Errorf("%w: placement endpoint name", ErrInvalid)
	}
	return nil
}

func (record ArchiveRecord) Validate() error {
	if record.FormatVersion == 0 || record.ChunkSizeBytes == 0 || !cellplan.ValidID(record.Attempt) || record.SealedEpoch == 0 || record.SealedUnix <= 0 ||
		len(record.Packs) == 0 || len(record.Packs) > MaxArchivePacks || !validSHA256Hex(record.RootDigest) ||
		record.SealedAllocatedBytes == 0 || record.SealedInodes == 0 || !validIdentity(record.KeyVersion) {
		return fmt.Errorf("%w: archive record", ErrInvalid)
	}
	if err := validateObjectRef(record.Manifest); err != nil {
		return err
	}
	for _, pack := range record.Packs {
		if err := validateObjectRef(pack); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > MaxArchiveRecordBytes {
		return fmt.Errorf("%w: archive record size", ErrInvalid)
	}
	return nil
}

func validateObjectRef(ref ObjectRef) error {
	if ref.Key == "" || len(ref.Key) > MaxArchiveObjectKeyBytes || !utf8.ValidString(ref.Key) || strings.ContainsRune(ref.Key, 0) || ref.SizeBytes == 0 ||
		!validSHA256Hex(ref.SHA256) || ref.CRC64NVME != "" && !validIdentity(ref.CRC64NVME) {
		return fmt.Errorf("%w: archive object reference", ErrInvalid)
	}
	return nil
}

func validPool(pool string) bool {
	return pool == PoolProduct || pool == PoolSystem || pool == PoolTest
}

func (state State) volumeView(volume Volume) VolumeView {
	// The product view never carries the full archive record or a pending
	// seal: those are Manager-internal (object keys, pack inventories). The
	// compact summary carries exactly the identities archived Files reads
	// need plus display totals.
	var summary *ArchiveSummaryView
	if volume.Archive != nil {
		summary = &ArchiveSummaryView{
			SealedEpoch: volume.Archive.SealedEpoch, Attempt: volume.Archive.Attempt,
			LogicalBytes: volume.Archive.LogicalBytes, LogicalInodes: volume.Archive.LogicalInodes,
			SealedUnix: volume.Archive.SealedUnix,
		}
	}
	volume.Archive = nil
	volume.PendingSeal = nil
	view := VolumeView{Volume: volume, ArchiveSummary: summary}
	if volume.Placement != nil {
		cell := state.Cells[volume.Placement.CellID]
		view.AuthorityEndpoint = net.JoinHostPort(cell.AuthorityHost, fmt.Sprint(volume.Placement.ListenPort))
	}
	return view
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

func validRenewalScope(value string) bool { return productauth.ValidRenewalScope(value) }

func renewalFenceKey(productIssuer, scope string) string { return productIssuer + "\x00" + scope }

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
