//go:build !darwin

package cli

import (
	"context"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/workspacehost"
)

func (e *cmdEnv) requestWorkspace(context.Context, workspacehost.Request) (workspacehost.Reply, error) {
	return workspacehost.Reply{}, fmt.Errorf("Linux Workspace requires an Apple-silicon Mac with macOS 26 or later")
}
