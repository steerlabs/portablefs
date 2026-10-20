package authorityrpc

import (
	"context"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// The profile alone establishes all FSKit semantics.
type fskitProfileTestHandler struct{ clientTestHandler }

func (h fskitProfileTestHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := h.clientTestHandler.Handle(ctx, req)
	if active := response.GetActivate(); active != nil {
		active.FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE
	}
	return response
}
