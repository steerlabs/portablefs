package authorityrpc

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type fskitFeatureTestHandler struct {
	clientTestHandler
	omit string
}

func (h fskitFeatureTestHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	reply := h.clientTestHandler.Handle(ctx, req)
	if hello := reply.GetHello(); hello != nil {
		hello.Features, _ = helloFeatures(authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR)
		hello.Features = append(hello.Features, fskitDirectWriteFeature)
		hello.MaxFskitWriteBytes = RequiredFskitWriteBytes
		hello.Features = slices.DeleteFunc(hello.Features, func(feature string) bool { return feature == h.omit })
	}
	if active := reply.GetActivate(); active != nil {
		active.Features, _ = advertisedActivateFeatures(authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR)
		// The current FSKit client also requires the optional FSKit CloseBatch
		// admission; an authority that serves it advertises it here.
		if !slices.Contains(active.Features, batchedCloseFeature) {
			active.Features = append(active.Features, batchedCloseFeature)
		}
		active.Features = slices.DeleteFunc(active.Features, func(feature string) bool { return feature == h.omit })
		active.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR
		active.FskitRepairCursor = &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE}
	}
	return reply
}
func TestFskitClientRequiresAdditiveWriteAndDurabilityFeatures(t *testing.T) {
	for _, omit := range []string{"", fskitDirectWriteFeature, fskitDurableMutationsFeature, fskitFragmentedWriteFeature, batchedCloseFeature} {
		t.Run("omit_"+omit, func(t *testing.T) {
			handler := fskitFeatureTestHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 4}, omit: omit}
			address, tls, stop := startTestServer(t, handler, 4, time.Minute)
			defer stop()
			cfg := coherentTestClientConfig(address, tls, "fskit", 4, 4)
			cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR
			cfg.FskitCachedNameCapacity = 16
			cfg.FskitRepairBudget = time.Second
			cfg.FskitNamespaceRepair = authoritypb.NamespaceRepair_NAMESPACE_REPAIR_CALLBACK_SERIALIZED
			client, err := DialClient(t.Context(), cfg)
			if omit == "" {
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if _, max := client.IOLimits(); max != 1<<20 {
					t.Fatalf("max write=%d", max)
				}
				if !client.SupportsBatchedClose() {
					t.Fatal("negotiated FSKit session does not report batched close")
				}
			} else {
				if err == nil {
					client.Close()
					t.Fatalf("accepted missing %s", omit)
				}
				if omit != fskitFragmentedWriteFeature && !strings.Contains(err.Error(), omit) {
					t.Fatalf("refusal=%v", err)
				}
			}
		})
	}
}

func TestLinuxClientDoesNotRequireFSKitWriteAndDurabilityFeatures(t *testing.T) {
	handler := clientTestHandler{epoch: make([]byte, 16), maxInFlight: 4}
	address, tls, stop := startTestServer(t, handler, 4, time.Minute)
	defer stop()
	cfg := coherentTestClientConfig(address, tls, "linux", 4, 4)
	cfg.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES
	client, err := DialClient(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
}
