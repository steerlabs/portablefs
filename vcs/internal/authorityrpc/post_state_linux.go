//go:build linux

package authorityrpc

import (
	"bytes"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

const objectVersionCapacity = 65536
const maxMutationObjects = 4

type postStateSnapshot struct {
	identity [16]byte
	attr     xfsstore.Attr
	roles    uint32
	changed  bool
}

// mutationChanges belongs to one apply, including newly created identities.
// It is never retained by the handler or reconstructed from version equality.
type mutationChanges struct {
	identities [maxMutationObjects][16]byte
	count      int
}

func (c *mutationChanges) contains(identity [16]byte) bool {
	for _, i := range c.identities[:c.count] {
		if i == identity {
			return true
		}
	}
	return false
}
func (c *mutationChanges) add(identity [16]byte) {
	if c.contains(identity) {
		return
	}
	if identity == ([16]byte{}) || c.count == len(c.identities) {
		panic("authorityrpc: invalid atomic changed-identity set")
	}
	c.identities[c.count] = identity
	c.count++
}

// mutationPostState merges aliases before canonical ordering. Versions here are
// provisional; commit samples the complete tuple while the storage turn stays
// held. The explicit changed set follows this outcome through that commit.
func (h *VolumeHandler) mutationPostState(changed *mutationChanges, sequence uint64, snapshots ...postStateSnapshot) *authoritypb.PostState {
	if sequence == 0 || len(snapshots) == 0 {
		return nil
	}
	merged := make(map[[16]byte]postStateSnapshot, len(snapshots))
	for _, s := range snapshots {
		if prior, ok := merged[s.identity]; ok {
			s.roles |= prior.roles
			s.changed = s.changed || prior.changed
		}
		merged[s.identity] = s
	}
	if len(merged) > maxMutationObjects {
		panic("authorityrpc: atomic PostState exceeds fixed object bound")
	}
	ordered := make([]postStateSnapshot, 0, len(merged))
	*changed = mutationChanges{}
	for _, s := range merged {
		ordered = append(ordered, s)
		if s.changed {
			changed.add(s.identity)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i].identity[:], ordered[j].identity[:]) < 0 })
	objects := make([]*authoritypb.ObjectPostState, 0, len(ordered))
	for _, s := range ordered {
		objects = append(objects, &authoritypb.ObjectPostState{StableIdentity: bytes.Clone(s.identity[:]), ObjectVersion: sequence, Attr: attrProto(s.attr), Roles: s.roles})
	}
	return &authoritypb.PostState{VisibilitySequence: sequence, SnapshotSequence: sequence, Objects: objects}
}

// Called only under coherenceCommitMu. Compaction creates no logical commit;
// unchanged objects conservatively advance to the floor on their next sample.
func (h *VolumeHandler) finalizeMutationPostState(committed uint64, state *authoritypb.PostState, changed *mutationChanges) map[string]uint64 {
	cap := h.objectVersionLimit
	if cap == 0 {
		cap = objectVersionCapacity
	}
	if cap < maxMutationObjects || cap > objectVersionCapacity {
		panic("authorityrpc: invalid object-version capacity")
	}
	if h.objectVersionFloor == 0 {
		h.objectVersionFloor = 1
	}
	if h.objectVersions == nil {
		h.objectVersions = make(map[[16]byte]uint64)
	}
	added := 0
	for _, identity := range changed.identities[:changed.count] {
		if _, ok := h.objectVersions[identity]; !ok {
			added++
		}
	}
	if len(h.objectVersions)+added > cap {
		// The caller has not allocated this mutation's sequence yet in the map;
		// every covered entry belongs to the previous committed cut.
		h.objectVersionFloor = max(h.objectVersionFloor, committed-1)
		clear(h.objectVersions)
	}
	for _, identity := range changed.identities[:changed.count] {
		h.objectVersions[identity] = committed
	}
	if state == nil {
		return nil
	}
	versions := make(map[string]uint64, len(state.GetObjects()))
	for _, object := range state.GetObjects() {
		var identity [16]byte
		copy(identity[:], object.GetStableIdentity())
		version := max(h.objectVersionFloor, h.objectVersions[identity])
		object.ObjectVersion = version
		versions[string(identity[:])] = version
	}
	state.VisibilitySequence, state.SnapshotSequence = committed, committed
	return versions
}

// sampleVersions captures sequence, floor and every requested entry under one
// commit cut. Callers still hold storage/hydration guards around their attrs.
func (h *VolumeHandler) sampleVersions(identities ...[16]byte) (uint64, []uint64) {
	h.coherenceCommitMu.Lock()
	defer h.coherenceCommitMu.Unlock()
	versions := make([]uint64, len(identities))
	for i, identity := range identities {
		versions[i] = max(uint64(1), h.objectVersionFloor, h.objectVersions[identity])
	}
	return h.coherenceVersion, versions
}
