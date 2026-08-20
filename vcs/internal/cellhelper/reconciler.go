// Package cellhelper is the narrow privileged reconciliation boundary on one
// Linux storage cell. It consumes only a manager-signed cell plan and calls a
// closed host interface; network input can never select paths or commands.
package cellhelper

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

var ErrInvalid = errors.New("cellhelper: invalid reconciliation")

type Host interface {
	Apply(context.Context, cellplan.VolumePlan, Assignment) (controlplane.VolumeObservation, HostUpdate)
	Observe(context.Context, cellplan.VolumePlan, Assignment) (controlplane.VolumeObservation, HostUpdate)
}

// HostUpdate contains only facts produced by a completed host operation that
// must become durable before the corresponding observation can leave the
// helper. A host failure returns no update; partial work is retried from local
// facts on the next pass.
type HostUpdate struct {
	LastQuiesceNonce string
	ArchiveSealed    *controlplane.ArchiveSealedObservation
	DestroyProof     *DestroyProof
}

type Assignment struct {
	VolumeID            string                                 `json:"volume_id"`
	AuthorizationDomain string                                 `json:"authorization_domain"`
	Owner               string                                 `json:"owner"`
	ProductIssuer       string                                 `json:"product_issuer"`
	ProductPublicKeyPEM string                                 `json:"product_public_key_pem"`
	CellID              string                                 `json:"cell_id"`
	PlacementSequence   uint64                                 `json:"placement_sequence"`
	ProjectID           uint32                                 `json:"project_id"`
	ServiceUID          uint32                                 `json:"service_uid"`
	ServiceGID          uint32                                 `json:"service_gid"`
	ListenPort          uint16                                 `json:"listen_port"`
	QuotaBytes          uint64                                 `json:"quota_bytes"`
	QuotaInodes         uint64                                 `json:"quota_inodes"`
	AppliedQuotaBytes   uint64                                 `json:"applied_quota_bytes"`
	AppliedQuotaInodes  uint64                                 `json:"applied_quota_inodes"`
	AuthorityID         string                                 `json:"authority_id"`
	AuthorityServerName string                                 `json:"authority_server_name"`
	AuthorityGeneration uint64                                 `json:"authority_generation"`
	LastPhase           cellplan.VolumePhase                   `json:"last_phase"`
	AuthorityAbsent     bool                                   `json:"authority_absent"`
	ArchiveSealed       *controlplane.ArchiveSealedObservation `json:"archive_sealed,omitempty"`
	DestroyProof        *DestroyProof                          `json:"destroy_proof,omitempty"`
	LastQuiesceNonce    string                                 `json:"last_quiesce_nonce,omitempty"`
	Applied             bool                                   `json:"applied"`
	AppliedPlanHash     string                                 `json:"applied_plan_sha256,omitempty"`
}

// DestroyProof retains both the canonical postcondition record and its hash.
// Keeping only the hash would make RELEASE replayable but would discard the
// local evidence the hash is supposed to name.
type DestroyProof struct {
	Record DestroyRecord `json:"record"`
	SHA256 string        `json:"sha256"`
}

type DestroyRecord struct {
	AuthorityEpoch      uint64                `json:"authority_epoch"`
	AuthorityID         string                `json:"authority_id"`
	AuthorityServerName string                `json:"authority_server_name"`
	CellID              string                `json:"cell_id"`
	ListenPort          uint16                `json:"listen_port"`
	PlacementSequence   uint64                `json:"placement_sequence"`
	Postconditions      DestroyPostconditions `json:"postconditions"`
	ProjectID           uint32                `json:"project_id"`
	ServiceGID          uint32                `json:"service_gid"`
	ServiceUID          uint32                `json:"service_uid"`
	VolumeID            string                `json:"volume_id"`
}

type DestroyPostconditions struct {
	ConfigRootAbsent   bool `json:"config_root_absent"`
	DropInsAbsent      bool `json:"dropins_absent"`
	QuotaCleared       bool `json:"quota_cleared"`
	StateRootAbsent    bool `json:"state_root_absent"`
	SysusersConfAbsent bool `json:"sysusers_conf_absent"`
	TreeAbsent         bool `json:"tree_absent"`
}

type Tombstone struct {
	VolumeID           string `json:"volume_id"`
	PlacementSequence  uint64 `json:"placement_sequence"`
	AuthorityEpoch     uint64 `json:"authority_epoch"`
	DestroyProofSHA256 string `json:"destroy_proof_sha256"`
}

type State struct {
	Version            uint32                `json:"version"`
	CellID             string                `json:"cell_id"`
	PlanVersionApplied uint32                `json:"plan_version_applied"`
	PlanGeneration     uint64                `json:"plan_generation"`
	PlanHash           string                `json:"plan_sha256"`
	Assignments        map[string]Assignment `json:"assignments"`
	Tombstones         map[string]Tombstone  `json:"tombstones"`
}

type Reconciler struct {
	CellID        string
	PlanPublicKey ed25519.PublicKey
	ClockSkew     time.Duration
	PlanLifetime  time.Duration
	ReleaseID     string
	Now           func() time.Time
	StatePath     string
	Host          Host
}

func (reconciler *Reconciler) Reconcile(ctx context.Context, envelope cellplan.Envelope) (controlplane.CellObservation, error) {
	if reconciler.Host == nil || reconciler.StatePath == "" || !cellplan.ValidID(reconciler.CellID) ||
		len(reconciler.PlanPublicKey) != ed25519.PublicKeySize || reconciler.ClockSkew < 0 || reconciler.PlanLifetime <= 0 || reconciler.ReleaseID == "" {
		return controlplane.CellObservation{}, ErrInvalid
	}
	now := time.Now().UTC()
	if reconciler.Now != nil {
		now = reconciler.Now().UTC()
	}
	plan, digest, err := cellplan.Verify(reconciler.PlanPublicKey, envelope, reconciler.CellID, now, reconciler.ClockSkew, reconciler.PlanLifetime)
	if err != nil {
		return controlplane.CellObservation{}, err
	}
	state, err := loadState(reconciler.StatePath, reconciler.CellID)
	if err != nil {
		return controlplane.CellObservation{}, err
	}
	digestHex := hex.EncodeToString(digest[:])
	if plan.Generation < state.PlanGeneration || plan.Generation == state.PlanGeneration && state.PlanHash != "" && state.PlanHash != digestHex {
		return controlplane.CellObservation{}, errors.New("cellhelper: stale or equivocated plan generation")
	}
	if plan.Version == cellplan.Version {
		state.Version = helperStateVersion
		state.PlanVersionApplied = cellplan.Version
	}
	if err := validatePlanTransition(plan, state, reconciler.CellID); err != nil {
		return controlplane.CellObservation{}, err
	}

	observation := controlplane.CellObservation{
		CellID: reconciler.CellID, PlanGeneration: plan.Generation, ManagerReleaseID: plan.ReleaseID,
		HelperReleaseID: reconciler.ReleaseID, ObservedUnix: now.Unix(),
		HelperPlanVersions:  []uint32{cellplan.VersionV1, cellplan.Version},
		HelperStateVersions: []uint32{helperStateVersionV1, helperStateVersion},
	}
	for _, volume := range plan.Volumes {
		if volume.Phase == cellplan.PhaseRelease {
			observed, err := applyRelease(volume, &state)
			if err != nil {
				return controlplane.CellObservation{}, err
			}
			setObservationIdentity(&observed, volume)
			observation.Volumes = append(observation.Volumes, observed)
			continue
		}
		volumeBytes, err := json.Marshal(volume)
		if err != nil {
			return controlplane.CellObservation{}, err
		}
		volumeDigest := sha256.Sum256(volumeBytes)
		volumeDigestHex := hex.EncodeToString(volumeDigest[:])
		previous := state.Assignments[volume.VolumeID]
		if previous.VolumeID == "" {
			previous = assignmentFromPlan(volume, reconciler.CellID)
		}

		var observed controlplane.VolumeObservation
		var update HostUpdate
		switch {
		case volume.Phase == cellplan.PhaseArchive && previous.ArchiveSealed != nil:
			sealed := cloneArchiveSealed(previous.ArchiveSealed)
			observed = controlplane.VolumeObservation{Provisioned: true, AuthorityAbsent: true, QuiesceProven: true, ArchiveSealed: sealed}
		case volume.Phase == cellplan.PhaseDestroy && previous.DestroyProof != nil:
			observed = controlplane.VolumeObservation{AuthorityAbsent: true, DestroyProofSHA256: previous.DestroyProof.SHA256}
		default:
			effective := effectiveVolumePlan(plan, volume)
			if previous.Applied && previous.AppliedPlanHash == volumeDigestHex {
				observed, update = reconciler.Host.Observe(ctx, effective, previous)
			} else {
				observed, update = reconciler.Host.Apply(ctx, effective, previous)
			}
		}
		setObservationIdentity(&observed, volume)
		assignment := assignmentAfterObservation(previous, volume, reconciler.CellID, plan.Version, observed, update, volumeDigestHex)
		state.Assignments[volume.VolumeID] = assignment
		observation.Volumes = append(observation.Volumes, observed)
	}
	state.PlanGeneration = plan.Generation
	state.PlanHash = digestHex
	if err := saveState(reconciler.StatePath, state); err != nil {
		return controlplane.CellObservation{}, err
	}
	return observation, nil
}

func validatePlanTransition(plan cellplan.Plan, state State, cellID string) error {
	present := make(map[string]struct{}, len(plan.Volumes))
	for _, volume := range plan.Volumes {
		present[volume.VolumeID] = struct{}{}
		previous, exists := state.Assignments[volume.VolumeID]
		if exists {
			if err := immutableAssignmentMatches(previous, volume, cellID); err != nil {
				return err
			}
			if volume.AuthorityGeneration < previous.AuthorityGeneration || volume.AuthorityGeneration > previous.AuthorityGeneration+1 {
				return errors.New("cellhelper: authority generation is stale or skipped")
			}
			if volume.AuthorityGeneration == previous.AuthorityGeneration+1 &&
				!((previous.LastPhase == cellplan.PhaseFence || previous.LastPhase == cellplan.PhaseArchive) && previous.AuthorityAbsent) {
				return errors.New("cellhelper: replacement authority lacks local process-absence proof")
			}
			continue
		}
		if volume.Phase == cellplan.PhaseRelease {
			continue
		}
		sequence := placementSequence(volume)
		if tombstone, ok := state.Tombstones[volume.VolumeID]; ok && sequence <= tombstone.PlacementSequence {
			return errors.New("cellhelper: new assignment does not advance its released placement sequence")
		}
	}
	for volumeID := range state.Assignments {
		if _, ok := present[volumeID]; !ok {
			if _, released := state.Tombstones[volumeID]; !released {
				return fmt.Errorf("cellhelper: signed plan removed durable assignment %s instead of retiring it", volumeID)
			}
		}
	}
	return nil
}

func applyRelease(volume cellplan.VolumePlan, state *State) (controlplane.VolumeObservation, error) {
	proof := volume.ReleaseProof
	if proof == nil {
		return controlplane.VolumeObservation{}, errors.New("cellhelper: release plan has no proof")
	}
	if assignment, ok := state.Assignments[volume.VolumeID]; ok {
		if assignment.DestroyProof == nil || proof.PlacementSequence != assignment.PlacementSequence ||
			proof.AuthorityEpoch != assignment.AuthorityGeneration || proof.DestroyProofSHA256 != assignment.DestroyProof.SHA256 {
			return controlplane.VolumeObservation{}, errors.New("cellhelper: release proof does not match the current assignment")
		}
		state.Tombstones[volume.VolumeID] = Tombstone{VolumeID: volume.VolumeID, PlacementSequence: proof.PlacementSequence,
			AuthorityEpoch: proof.AuthorityEpoch, DestroyProofSHA256: proof.DestroyProofSHA256}
		delete(state.Assignments, volume.VolumeID)
		return controlplane.VolumeObservation{AuthorityAbsent: true, Released: true}, nil
	}
	tombstone, ok := state.Tombstones[volume.VolumeID]
	if !ok || proof.PlacementSequence != tombstone.PlacementSequence || proof.AuthorityEpoch != tombstone.AuthorityEpoch ||
		proof.DestroyProofSHA256 != tombstone.DestroyProofSHA256 {
		return controlplane.VolumeObservation{}, errors.New("cellhelper: release proof does not match the current tombstone")
	}
	return controlplane.VolumeObservation{AuthorityAbsent: true, Released: true}, nil
}

func assignmentAfterObservation(previous Assignment, volume cellplan.VolumePlan, cellID string, planVersion uint32, observed controlplane.VolumeObservation, update HostUpdate, digest string) Assignment {
	assignment := previous
	if assignment.VolumeID == "" {
		assignment = assignmentFromPlan(volume, cellID)
	}
	assignment.QuotaBytes, assignment.QuotaInodes = volume.QuotaBytes, volume.QuotaInodes
	assignment.AuthorityGeneration = volume.AuthorityGeneration
	assignment.LastPhase = volume.Phase
	assignment.AuthorityAbsent = observed.AuthorityAbsent
	if update.LastQuiesceNonce != "" {
		assignment.LastQuiesceNonce = update.LastQuiesceNonce
	}
	if update.ArchiveSealed != nil {
		assignment.ArchiveSealed = cloneArchiveSealed(update.ArchiveSealed)
	}
	if update.DestroyProof != nil {
		copy := *update.DestroyProof
		assignment.DestroyProof = &copy
	}
	quotaSucceeded := observed.Provisioned || planVersion == cellplan.VersionV1
	if observed.Error == "" && quotaSucceeded &&
		(volume.Phase == cellplan.PhaseProvision || volume.Phase == cellplan.PhaseServe || volume.Phase == cellplan.PhaseRestore) {
		assignment.AppliedQuotaBytes, assignment.AppliedQuotaInodes = volume.QuotaBytes, volume.QuotaInodes
	}
	assignment.Applied = phaseApplied(volume.Phase, observed)
	assignment.AppliedPlanHash = ""
	if assignment.Applied {
		assignment.AppliedPlanHash = digest
	}
	return assignment
}

func phaseApplied(phase cellplan.VolumePhase, observed controlplane.VolumeObservation) bool {
	if observed.Error != "" {
		return false
	}
	switch phase {
	case cellplan.PhaseArchive:
		return observed.ArchiveSealed != nil
	case cellplan.PhaseRestore:
		return observed.RestoreNamespaceReady && observed.AuthorityRunning
	case cellplan.PhaseDestroy:
		return observed.DestroyProofSHA256 != ""
	default:
		return true
	}
}

func effectiveVolumePlan(plan cellplan.Plan, volume cellplan.VolumePlan) cellplan.VolumePlan {
	if plan.Version == cellplan.Version {
		volume.AuthorityCAPEM = plan.AuthorityCAPEM
		volume.ClientCAPEM = plan.ClientCAPEM
		volume.CapabilityPublicKey = plan.CapabilityPublicKey
	}
	return volume
}

func setObservationIdentity(observed *controlplane.VolumeObservation, volume cellplan.VolumePlan) {
	observed.VolumeID = volume.VolumeID
	observed.AuthorityGeneration = volume.AuthorityGeneration
	observed.ProjectID = volume.ProjectID
	observed.ServiceUID = volume.ServiceUID
	observed.ServiceGID = volume.ServiceGID
	observed.ListenPort = volume.ListenPort
}

func assignmentFromPlan(volume cellplan.VolumePlan, cellID string) Assignment {
	return Assignment{
		VolumeID: volume.VolumeID, AuthorizationDomain: volume.AuthorizationDomain, Owner: volume.Owner,
		ProductIssuer: volume.ProductIssuer, ProductPublicKeyPEM: volume.ProductPublicKeyPEM,
		CellID: cellID, PlacementSequence: placementSequence(volume), ProjectID: volume.ProjectID,
		ServiceUID: volume.ServiceUID, ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort,
		QuotaBytes: volume.QuotaBytes, QuotaInodes: volume.QuotaInodes, AuthorityID: volume.AuthorityID,
		AuthorityServerName: volume.AuthorityServerName, AuthorityGeneration: volume.AuthorityGeneration, LastPhase: volume.Phase,
	}
}

func placementSequence(volume cellplan.VolumePlan) uint64 {
	if volume.PlacementSequence == 0 {
		return 1
	}
	return volume.PlacementSequence
}

func immutableAssignmentMatches(previous Assignment, volume cellplan.VolumePlan, cellID string) error {
	if previous.VolumeID != volume.VolumeID || previous.AuthorizationDomain != volume.AuthorizationDomain ||
		previous.Owner != volume.Owner || previous.ProductIssuer != volume.ProductIssuer || previous.ProductPublicKeyPEM != volume.ProductPublicKeyPEM || previous.CellID != cellID ||
		previous.PlacementSequence != placementSequence(volume) || previous.ProjectID != volume.ProjectID || previous.ServiceUID != volume.ServiceUID ||
		previous.ServiceGID != volume.ServiceGID || previous.ListenPort != volume.ListenPort ||
		previous.AuthorityID != volume.AuthorityID || previous.AuthorityServerName != volume.AuthorityServerName {
		return errors.New("cellhelper: signed plan attempted to change an immutable volume assignment")
	}
	if volume.QuotaBytes < previous.QuotaBytes || volume.QuotaInodes < previous.QuotaInodes {
		return errors.New("cellhelper: signed plan attempted to lower a volume quota")
	}
	return nil
}

func cloneArchiveSealed(value *controlplane.ArchiveSealedObservation) *controlplane.ArchiveSealedObservation {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Packs = append([]controlplane.ObjectRef(nil), value.Packs...)
	return &copy
}
