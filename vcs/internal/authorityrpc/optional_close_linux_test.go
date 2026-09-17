//go:build linux

package authorityrpc

import (
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"testing"
)

func TestActivationAdvertisesCloseBatchOnlyToLinux(t *testing.T) {
	h, _, _ := newWriteHarness(t)
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR, authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER} {
		reply := h.newActivationReply(&sessionResources{profile: profile}, xfsstore.Attr{Kind: xfsstore.KindDirectory}, [16]byte{1}, volumeserver.VisibilityCursor{})
		if got := hasFeatures(reply.Features, []string{batchedCloseFeature}); got != (profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES) {
			t.Fatalf("profile %v advertised=%v", profile, got)
		}
	}
}
