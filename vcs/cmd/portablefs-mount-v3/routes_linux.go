//go:build linux

package main

import (
	"context"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
)

// attachWithRoutes attaches this mount and returns the routing it was admitted
// with. The one-capability adopt-and-retry protocol is shared with the
// `portablefs mount` frontend; see mountv3.AttachWithRoutes for why there is
// exactly one attach, and at most one more.
func attachWithRoutes(ctx context.Context, attach authorityrpc.ClientConfig, adopt bool) (*authorityrpc.Client, localroutes.RuleSet, error) {
	return mountv3.AttachWithRoutes(ctx, attach, adopt)
}
