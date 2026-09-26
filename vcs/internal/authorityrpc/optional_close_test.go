package authorityrpc

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type optionalCloseHandler struct {
	clientTestHandler
	enabled bool
}

func (h *optionalCloseHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := h.clientTestHandler.Handle(ctx, req)
	if active := response.GetActivate(); active != nil && h.enabled {
		active.Features = append(active.Features, batchedCloseFeature)
	}
	return response
}
func TestCloseBatchCapabilityIsOptionalAtActivation(t *testing.T) {
	minimum, _ := activateFeatures(authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES)
	if hasFeatures(minimum, []string{batchedCloseFeature}) {
		t.Fatal("CloseBatch changed frozen protocol minimum")
	}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "old peer", true: "batch peer"}[enabled], func(t *testing.T) {
			h := &optionalCloseHandler{clientTestHandler: clientTestHandler{epoch: make([]byte, 16), maxInFlight: 3}, enabled: enabled}
			address, tls, stop := startTestServer(t, h, 3, time.Minute)
			defer stop()
			c, err := DialClient(t.Context(), coherentTestClientConfig(address, tls, "volume", 3, 3))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.SupportsBatchedClose() != enabled {
				t.Fatal("optional advertisement not retained")
			}
		})
	}
}
