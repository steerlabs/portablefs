//go:build linux

package main

import (
	"context"
	"errors"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
)

// stringList collects a repeatable command-line flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value must not be empty")
	}
	*l = append(*l, value)
	return nil
}

// attachWithRoutes attaches this mount and returns the routing it was admitted
// with. The one-capability adopt-and-retry protocol is shared with the
// `portablefs mount` frontend; see mountv3.AttachWithRoutes for why there is
// exactly one attach, and at most one more.
func attachWithRoutes(ctx context.Context, attach authorityrpc.ClientConfig, adopt bool) (*authorityrpc.Client, localroutes.RuleSet, error) {
	return mountv3.AttachWithRoutes(ctx, attach, adopt)
}
