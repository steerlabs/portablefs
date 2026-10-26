//go:build darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/workspacehost"
)

func (e *cmdEnv) requestWorkspace(ctx context.Context, request workspacehost.Request) (workspacehost.Reply, error) {
	executable, err := os.Executable()
	if err != nil {
		return workspacehost.Reply{}, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return workspacehost.Reply{}, err
	}
	app := filepath.Dir(filepath.Dir(filepath.Dir(executable)))
	if executable != filepath.Join(app, "Contents", "Helpers", "portablefs") || filepath.Ext(app) != ".app" {
		return workspacehost.Reply{}, errors.New("workspace requires the CLI embedded in the signed PortableFS app")
	}
	if out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", app).CombinedOutput(); err != nil {
		return workspacehost.Reply{}, fmt.Errorf("authenticate workspace owning release: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	service := filepath.Join(app, "Contents", "Library", "LaunchAgents", "PortableFSWorkspaceService.app")
	peer := filepath.Join(service, "Contents", "MacOS", "portablefs-workspace-service")
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "-dv", "--verbose=4", service).CombinedOutput()
	if err != nil {
		return workspacehost.Reply{}, fmt.Errorf("inspect workspace service identity: %w", err)
	}
	hash, err := exactCodesignField(string(out), "CDHash")
	if err != nil {
		return workspacehost.Reply{}, err
	}
	state, err := e.mountLifecycleStateDir()
	if err != nil {
		return workspacehost.Reply{}, err
	}
	socket := filepath.Join(state, "workspace", workspacehost.SocketName)
	if request.Operation == "start" || request.Operation == "mount" {
		cmd := exec.CommandContext(ctx, filepath.Join(app, "Contents", "MacOS", macOSAppExecutable), "--workspace-service-register")
		if out, err := cmd.CombinedOutput(); err != nil {
			return workspacehost.Reply{}, fmt.Errorf("%s: %s", workspacehost.Approval, strings.TrimSpace(string(out)))
		}
		// Registration can return before launchd publishes the endpoint. Each dial
		// reauthenticates the exact signed execution; no old socket is adopted.
		for {
			reply, err := workspacehost.Exchange(ctx, socket, peer, hash, request)
			if err == nil {
				return reply, nil
			}
			if _, inspect := os.Lstat(socket); inspect == nil {
				return workspacehost.Reply{}, err
			}
			select {
			case <-ctx.Done():
				return workspacehost.Reply{}, fmt.Errorf("start workspace service: %w", ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	if _, err := os.Lstat(socket); errors.Is(err, os.ErrNotExist) && request.Operation == "status" {
		// Do not register/start anything to inspect state. Absence of a listener is
		// not an empty-resource proof; retained durable state requires service repair.
		if _, stateErr := os.Lstat(filepath.Join(state, "workspace", "desired.json")); errors.Is(stateErr, os.ErrNotExist) {
			return workspacehost.Reply{Version: 1, State: "stopped", Message: "Linux Workspace: Stopped", Volumes: []workspacehost.Volume{}}, nil
		}
	}
	return workspacehost.Exchange(ctx, socket, peer, hash, request)
}
