package portablefsd

import (
	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
	"github.com/steerlabs/portablefs/vcs/internal/pathcomponent"
)

const (
	v3MaxCompleteDirs  = 1024
	v3MaxCompleteNames = 16384
	v3MaxCompleteBytes = 1 << 20
)

// Membership owns no child capabilities or identities. Permission ordering
// survives certificate disposal in the directory record, including ABA.
type v3DirectoryCertificate struct {
	names map[string]struct{}
	bytes int
}

// All helpers in this file require d.mu. There is no independent cache owner.
func (d *v3DataPlane) dropCompletenessLocked(dir *v3ItemRecord, reason lantrace.CertDrop) {
	if c := dir.complete; c != nil {
		d.completeDirs--
		d.completeNames -= len(c.names)
		d.completeBytes -= c.bytes
		dir.complete = nil
	}
	dir.certificateDrop = reason
	dir.search = lantrace.SearchUnknown
}

func (d *v3DataPlane) permissionChangedLocked(dir *v3ItemRecord, cut uint64) {
	dir.permissionCut = max(dir.permissionCut, cut)
	d.dropCompletenessLocked(dir, lantrace.CertDropPermissionCut)
	d.forgetNamesLocked(dir)
	dir.watermark = max(dir.watermark, cut)
}

// Validate before applying this MKDIR's own PostState/cold floor. Equal cuts
// cannot seed again: a replay must never erase members learned since creation.
func (d *v3DataPlane) mkdirSeedEligibleLocked(effect *v3MutationEffect) bool {
	dir, w := effect.mkdir, effect.mkdirWitness
	if dir == nil || w == nil || d.itemsByID[dir.item.ItemID] != dir {
		return false
	}
	// Exact replay of creation is not a new observation of the directory's
	// contents or permissions. Preserve knowledge maintained since that cut.
	if previous := dir.mkdirWitness; dir.complete != nil && previous != nil && *previous == *w {
		return false
	}
	dir.mkdirWitness = w
	switch {
	case w.identity != dir.item.StableIdentity || w.snapshot != effect.snapshot:
		d.dropCompletenessLocked(dir, lantrace.CertDropNamespaceCut)
	case w.snapshot <= dir.permissionCut:
		d.dropCompletenessLocked(dir, lantrace.CertDropPermissionCut)
	case w.snapshot <= dir.watermark || w.snapshot < dir.snapshot:
		// An exact duplicate can keep existing knowledge, but cannot re-seed it.
		if dir.complete == nil {
			d.dropCompletenessLocked(dir, lantrace.CertDropNamespaceCut)
		}
	case w.snapshot <= d.coldFloor:
		if dir.complete == nil {
			d.dropCompletenessLocked(dir, lantrace.CertDropColdCut)
		}
	default:
		return true
	}
	return false
}

func (d *v3DataPlane) seedMkdirLocked(dir *v3ItemRecord) {
	if !dir.valid || dir.complete != nil {
		return
	}
	if d.completeDirs == v3MaxCompleteDirs {
		d.dropCompletenessLocked(dir, lantrace.CertDropCapacity)
		return
	}
	dir.complete = &v3DirectoryCertificate{names: make(map[string]struct{})}
	dir.certificateDrop = ""
	dir.watermark = max(dir.watermark, dir.mkdirWitness.snapshot)
	dir.permissionCut = max(dir.permissionCut, dir.mkdirWitness.snapshot)
	dir.search = lantrace.SearchDenied
	if dir.mkdirWitness.searchPermitted {
		dir.search = lantrace.SearchPermitted
	}
	d.completeDirs++
}

// Complete validated effects are the only membership writer. Compute the
// whole outcome before accounting, so rename at capacity can remove and add
// atomically. At most four objects/two coordinates occur in a wire outcome.
func (d *v3DataPlane) applyCompletenessLocked(effect *v3MutationEffect) {
	parents := make(map[*v3ItemRecord]struct{}, 2)
	for _, n := range effect.names {
		parents[n.parent] = struct{}{}
	}
	for _, o := range effect.objects {
		if o.roles&(v3PostStateRoleParent|v3PostStateRoleOldParent|v3PostStateRoleNewParent) != 0 {
			if dir := d.itemsByIdentity[o.identity]; dir != nil {
				parents[dir] = struct{}{}
			}
		}
	}
	deltaNames, deltaBytes := 0, 0
	invalid := false
	for dir := range parents {
		if dir == nil || dir.complete == nil {
			continue
		}
		valid, touched := effect.namesComplete && effect.snapshot >= dir.watermark, false
		for i, n := range effect.names {
			if n.parent != dir {
				continue
			}
			touched = true
			if !pathcomponent.ValidName([]byte(n.name)) {
				valid = false
			}
			for _, previous := range effect.names[:i] {
				if previous.parent == dir && previous.name == n.name &&
					(previous.bound != n.bound || previous.identity != n.identity) {
					valid = false
				}
			}
			_, present := dir.complete.names[n.name]
			if effect.snapshot == dir.watermark && present != n.bound {
				valid = false
			}
		}
		invalid = invalid || !valid || !touched
	}
	if invalid {
		for dir := range parents {
			if dir != nil && dir.complete != nil {
				d.dropCompletenessLocked(dir, lantrace.CertDropNamespaceCut)
			}
		}
		return
	}
	// Deduplicate a same-coordinate rename's identical post-binding.
	for i, n := range effect.names {
		if n.parent == nil || n.parent.complete == nil {
			continue
		}
		duplicate := false
		for _, previous := range effect.names[:i] {
			duplicate = duplicate || previous.parent == n.parent && previous.name == n.name
		}
		if duplicate {
			continue
		}
		_, present := n.parent.complete.names[n.name]
		if n.bound && !present {
			deltaNames++
			deltaBytes += len(n.name)
		} else if !n.bound && present {
			deltaNames--
			deltaBytes -= len(n.name)
		}
	}
	if d.completeNames+deltaNames > v3MaxCompleteNames || d.completeBytes+deltaBytes > v3MaxCompleteBytes {
		for dir := range parents {
			if dir != nil && dir.complete != nil {
				d.dropCompletenessLocked(dir, lantrace.CertDropCapacity)
			}
		}
		return
	}
	for _, n := range effect.names {
		if n.parent == nil || n.parent.complete == nil {
			continue
		}
		c := n.parent.complete
		_, present := c.names[n.name]
		if n.bound && !present {
			c.names[n.name] = struct{}{}
			c.bytes += len(n.name)
		} else if !n.bound && present {
			delete(c.names, n.name)
			c.bytes -= len(n.name)
		}
	}
	d.completeNames += deltaNames
	d.completeBytes += deltaBytes
}
