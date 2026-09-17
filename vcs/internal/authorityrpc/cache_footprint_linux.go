//go:build linux

package authorityrpc

import (
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func (h *VolumeHandler) coherenceCacheToken(id volumeserver.SessionID) (volumeserver.SubscriptionToken, error) {
	profile, err := h.sessionFrontendProfile(id)
	if err != nil {
		return volumeserver.SubscriptionToken{}, err
	}
	if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER {
		return volumeserver.SubscriptionToken{}, nil
	}
	return h.coherenceToken(id)
}
func (h *VolumeHandler) admitCoherenceCache(token volumeserver.SubscriptionToken, a volumeserver.CacheAdmission) error {
	if token == (volumeserver.SubscriptionToken{}) {
		return nil
	}
	return h.Coherence.AdmitCache(token, a)
}

func sourceCacheAdmission(gate volumeserver.SourcePublicationGate, resp *authoritypb.Response) volumeserver.CacheAdmission {
	var a volumeserver.CacheAdmission
	for _, target := range gate.Targets {
		if target.ParentIdentity != ([16]byte{}) {
			a.Directories = append(a.Directories, target.ParentIdentity)
		}
		if target.Attributes {
			a.Attributes = append(a.Attributes, target.Identity)
		}
		if target.Data {
			a.Data = append(a.Data, target.Identity)
		}
		if target.BoundAttributes {
			a.Attributes = append(a.Attributes, target.BoundIdentities...)
		}
		if target.BoundData {
			a.Data = append(a.Data, target.BoundIdentities...)
		}
	}
	for _, object := range resp.GetPostState().GetObjects() {
		if len(object.GetStableIdentity()) != 16 {
			continue
		}
		var id [16]byte
		copy(id[:], object.GetStableIdentity())
		a.Attributes = append(a.Attributes, id)
		// MKDIR's physical reply can establish an empty-directory proof without
		// any subsequent LOOKUP or READDIR. Conservatively cover all directory
		// post-state objects, including the parent of a namespace mutation.
		if object.GetAttr().GetKind() == authoritypb.Attr_DIRECTORY {
			a.Directories = append(a.Directories, id)
		}
	}
	return a
}
