//go:build linux

package authorityrpc

import (
	"bytes"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type postStateSnapshot struct {
	identity [16]byte
	attr     xfsstore.Attr
	roles    uint32
	changed  bool
}

// mutationPostState assigns versions and canonicalizes duplicate identities as
// one operation. Roles are ORed before sorting, so hard-link aliases and a
// same-parent rename cannot produce duplicate records on the wire.
func (h *VolumeHandler) mutationPostState(sequence uint64, snapshots ...postStateSnapshot) *authoritypb.PostState {
	if sequence == 0 || len(snapshots) == 0 {
		return nil
	}
	merged := make(map[[16]byte]postStateSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		if prior, ok := merged[snapshot.identity]; ok {
			prior.roles |= snapshot.roles
			prior.changed = prior.changed || snapshot.changed
			// All descriptions of one stable identity must have sampled the same
			// post-state. Validation at the storage boundary catches disagreement;
			// retain the latest supplied value here only to keep this constructor
			// deterministic for test doubles.
			prior.attr = snapshot.attr
			merged[snapshot.identity] = prior
			continue
		}
		merged[snapshot.identity] = snapshot
	}
	ordered := make([]postStateSnapshot, 0, len(merged))
	for _, snapshot := range merged {
		ordered = append(ordered, snapshot)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i].identity[:], ordered[j].identity[:]) < 0
	})

	h.postStateMu.Lock()
	if h.objectVersions == nil {
		h.objectVersions = make(map[[16]byte]uint64)
	}
	objects := make([]*authoritypb.ObjectPostState, 0, len(ordered))
	for _, snapshot := range ordered {
		version := h.objectVersions[snapshot.identity]
		if version == 0 {
			// COMPLETE(1) is the epoch's explicit empty-history baseline.
			version = 1
		}
		if snapshot.changed {
			version = sequence
			h.objectVersions[snapshot.identity] = sequence
		}
		objects = append(objects, &authoritypb.ObjectPostState{
			StableIdentity: append([]byte(nil), snapshot.identity[:]...),
			ObjectVersion:  version,
			Attr:           attrProto(snapshot.attr),
			Roles:          snapshot.roles,
		})
	}
	h.postStateMu.Unlock()
	return &authoritypb.PostState{VisibilitySequence: sequence, SnapshotSequence: sequence, Objects: objects}
}

func (h *VolumeHandler) sampledObjectVersion(identity [16]byte, snapshot uint64) uint64 {
	h.postStateMu.Lock()
	defer h.postStateMu.Unlock()
	version := h.objectVersions[identity]
	if version == 0 {
		version = 1
	}
	// A future version here is an authority ordering defect. Preserve it so the
	// consumer's mandatory version<=snapshot validation fences the session;
	// clamping would fabricate a coherent-looking stamp for incoherent state.
	return version
}
