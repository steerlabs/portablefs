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
	Apply(context.Context, cellplan.VolumePlan, Assignment) controlplane.VolumeObservation
	Observe(context.Context, cellplan.VolumePlan, Assignment) controlplane.VolumeObservation
}

type Assignment struct {
	VolumeID             string               `json:"volume_id"`
	AuthorizationDomain  string               `json:"authorization_domain"`
	Owner                string               `json:"owner"`
	ProductIssuer        string               `json:"product_issuer"`
	ProductPublicKeyPEM  string               `json:"product_public_key_pem"`
	CellID               string               `json:"cell_id"`
	ProjectID            uint32               `json:"project_id"`
	ServiceUID           uint32               `json:"service_uid"`
	ServiceGID           uint32               `json:"service_gid"`
	ListenPort           uint16               `json:"listen_port"`
	QuotaBytes           uint64               `json:"quota_bytes"`
	QuotaInodes          uint64               `json:"quota_inodes"`
	AuthorityID          string               `json:"authority_id"`
	AuthorityServerName  string               `json:"authority_server_name"`
	AuthorityGeneration  uint64               `json:"authority_generation"`
	LastPhase            cellplan.VolumePhase `json:"last_phase"`
	AuthorityAbsent      bool                 `json:"authority_absent"`
	QuotaApplied         bool                 `json:"quota_applied"`
	Applied              bool                 `json:"applied"`
	AppliedPlanHash      string               `json:"applied_plan_sha256,omitempty"`
	AppliedHelperRelease string               `json:"applied_helper_release,omitempty"`
}

type State struct {
	Version        uint32                `json:"version"`
	CellID         string                `json:"cell_id"`
	PlanGeneration uint64                `json:"plan_generation"`
	PlanHash       string                `json:"plan_sha256"`
	Assignments    map[string]Assignment `json:"assignments"`
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
	present := make(map[string]struct{}, len(plan.Volumes))
	for _, volume := range plan.Volumes {
		present[volume.VolumeID] = struct{}{}
		previous, exists := state.Assignments[volume.VolumeID]
		if exists {
			if err := immutableAssignmentMatches(previous, volume, reconciler.CellID); err != nil {
				return controlplane.CellObservation{}, err
			}
			if volume.AuthorityGeneration < previous.AuthorityGeneration || volume.AuthorityGeneration > previous.AuthorityGeneration+1 {
				return controlplane.CellObservation{}, errors.New("cellhelper: authority generation is stale or skipped")
			}
			if volume.AuthorityGeneration == previous.AuthorityGeneration+1 &&
				(previous.LastPhase != cellplan.PhaseFence || !previous.AuthorityAbsent) {
				return controlplane.CellObservation{}, errors.New("cellhelper: replacement authority lacks local process-absence proof")
			}
		} else {
			previous = assignmentFromPlan(volume, reconciler.CellID)
		}
	}
	for volumeID := range state.Assignments {
		if _, ok := present[volumeID]; !ok {
			return controlplane.CellObservation{}, fmt.Errorf("cellhelper: signed plan removed durable assignment %s instead of retiring it", volumeID)
		}
	}

	observation := controlplane.CellObservation{
		CellID: reconciler.CellID, PlanGeneration: plan.Generation, ManagerReleaseID: plan.ReleaseID,
		HelperReleaseID: reconciler.ReleaseID, ObservedUnix: now.Unix(),
	}
	for _, volume := range plan.Volumes {
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
		observed := controlplane.VolumeObservation{}
		if previous.Applied && previous.AppliedPlanHash == volumeDigestHex && previous.AppliedHelperRelease == reconciler.ReleaseID {
			observed = reconciler.Host.Observe(ctx, volume, previous)
		} else {
			observed = reconciler.Host.Apply(ctx, volume, previous)
		}
		observed.VolumeID = volume.VolumeID
		observed.AuthorityGeneration = volume.AuthorityGeneration
		observed.ProjectID = volume.ProjectID
		observed.ServiceUID = volume.ServiceUID
		observed.ServiceGID = volume.ServiceGID
		observed.ListenPort = volume.ListenPort
		observation.Volumes = append(observation.Volumes, observed)
		assignment := assignmentFromPlan(volume, reconciler.CellID)
		assignment.LastPhase = volume.Phase
		assignment.AuthorityAbsent = observed.AuthorityAbsent
		assignment.QuotaApplied = previous.QuotaApplied || observed.Error == "" &&
			(volume.Phase == cellplan.PhaseProvision || volume.Phase == cellplan.PhaseServe)
		assignment.Applied = observed.Error == ""
		if assignment.Applied {
			assignment.AppliedPlanHash = volumeDigestHex
			assignment.AppliedHelperRelease = reconciler.ReleaseID
		}
		state.Assignments[volume.VolumeID] = assignment
	}
	state.PlanGeneration = plan.Generation
	state.PlanHash = digestHex
	if err := saveState(reconciler.StatePath, state); err != nil {
		return controlplane.CellObservation{}, err
	}
	return observation, nil
}

func assignmentFromPlan(volume cellplan.VolumePlan, cellID string) Assignment {
	return Assignment{
		VolumeID: volume.VolumeID, AuthorizationDomain: volume.AuthorizationDomain, Owner: volume.Owner,
		ProductIssuer: volume.ProductIssuer, ProductPublicKeyPEM: volume.ProductPublicKeyPEM,
		CellID: cellID, ProjectID: volume.ProjectID,
		ServiceUID: volume.ServiceUID, ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort,
		QuotaBytes: volume.QuotaBytes, QuotaInodes: volume.QuotaInodes, AuthorityID: volume.AuthorityID,
		AuthorityServerName: volume.AuthorityServerName, AuthorityGeneration: volume.AuthorityGeneration, LastPhase: volume.Phase,
	}
}

func immutableAssignmentMatches(previous Assignment, volume cellplan.VolumePlan, cellID string) error {
	if previous.VolumeID != volume.VolumeID || previous.AuthorizationDomain != volume.AuthorizationDomain ||
		previous.Owner != volume.Owner || previous.ProductIssuer != volume.ProductIssuer || previous.ProductPublicKeyPEM != volume.ProductPublicKeyPEM || previous.CellID != cellID ||
		previous.ProjectID != volume.ProjectID || previous.ServiceUID != volume.ServiceUID || previous.ServiceGID != volume.ServiceGID ||
		previous.ListenPort != volume.ListenPort || previous.QuotaBytes != volume.QuotaBytes || previous.QuotaInodes != volume.QuotaInodes ||
		previous.AuthorityID != volume.AuthorityID || previous.AuthorityServerName != volume.AuthorityServerName {
		return errors.New("cellhelper: signed plan attempted to change an immutable volume assignment")
	}
	return nil
}
