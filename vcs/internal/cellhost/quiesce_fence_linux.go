//go:build linux

package cellhost

import (
	"context"
	"errors"

	"github.com/steerlabs/portablefs/vcs/internal/cellhelper"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

// applyQuiesceFence performs the authority-owned empty-membership handshake
// before using the ordinary process fence. Archive and destructive quiesce use
// this one implementation; restart fencing deliberately does not.
func (host *Host) applyQuiesceFence(ctx context.Context, plan cellplan.VolumePlan, previous cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	observed := controlplane.VolumeObservation{Provisioned: host.volumeExists(plan.VolumeID)}
	nonce := previous.LastQuiesceNonce
	if previous.LastPhase != plan.Phase {
		nonce = ""
	}
	if nonce == "" {
		if !host.unitActive(ctx, authorityServiceUnit(plan.VolumeID)) {
			observed.Error = "cellhost: cannot establish quiesce proof because the authority is absent"
			return observed, cellhelper.HostUpdate{}
		}
		fresh, err := host.WriteQuiesceRequest(plan.VolumeID, plan.ServiceGID)
		if err != nil {
			observed.Error = err.Error()
			return observed, cellhelper.HostUpdate{}
		}
		observed.AuthorityRunning = true
		return observed, cellhelper.HostUpdate{LastQuiesceNonce: fresh}
	}
	proof, err := host.ReadQuiesceProof(plan.VolumeID)
	if errors.Is(err, ErrQuiesceProofAbsent) {
		observed.AuthorityRunning = host.unitActive(ctx, authorityServiceUnit(plan.VolumeID))
		if !observed.AuthorityRunning {
			observed.Error = "cellhost: authority disappeared before writing its quiesce proof"
		}
		return observed, cellhelper.HostUpdate{}
	}
	if err != nil || !proof.Proves(plan.VolumeID, plan.AuthorityGeneration, nonce) {
		if err == nil {
			err = errors.New("cellhost: quiesce proof does not match the current request")
		}
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if !host.unitActive(ctx, authorityServiceUnit(plan.VolumeID)) {
		return host.observeQuiesceFence(ctx, plan, previous), cellhelper.HostUpdate{}
	}
	absent, err := host.fence(ctx, plan.VolumeID)
	if err != nil || !absent {
		if err == nil {
			err = errors.New("cellhost: authority remained present after quiesce fence")
		}
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	empty, err := host.StrictMembershipEmpty(plan.VolumeID)
	if err != nil || !empty {
		if err == nil {
			err = errors.New("cellhost: strict membership disagrees with the quiesce proof")
		}
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	proofAfter, err := host.ReadQuiesceProof(plan.VolumeID)
	if err != nil || !proofAfter.Proves(plan.VolumeID, plan.AuthorityGeneration, nonce) {
		if err == nil {
			err = errors.New("cellhost: quiesce proof changed across the authority fence")
		}
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	observed.AuthorityAbsent, observed.QuiesceProven = true, true
	return observed, cellhelper.HostUpdate{}
}

func (host *Host) observeQuiesceFence(ctx context.Context, plan cellplan.VolumePlan, previous cellhelper.Assignment) controlplane.VolumeObservation {
	observed := controlplane.VolumeObservation{Provisioned: host.volumeExists(plan.VolumeID)}
	absent, err := host.authorityAbsent(ctx, plan.VolumeID)
	if err != nil || !absent {
		if err == nil {
			err = errors.New("cellhost: authority is present after quiesce")
		}
		observed.Error = err.Error()
		return observed
	}
	proof, err := host.ReadQuiesceProof(plan.VolumeID)
	if err != nil || !proof.Proves(plan.VolumeID, plan.AuthorityGeneration, previous.LastQuiesceNonce) {
		if err == nil {
			err = errors.New("cellhost: matching quiesce proof is absent after fence")
		}
		observed.Error = err.Error()
		return observed
	}
	empty, err := host.StrictMembershipEmpty(plan.VolumeID)
	if err != nil || !empty {
		if err == nil {
			err = errors.New("cellhost: strict membership is not empty after quiesce")
		}
		observed.Error = err.Error()
		return observed
	}
	observed.AuthorityAbsent, observed.QuiesceProven = true, true
	return observed
}
