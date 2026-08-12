//go:build darwin

package portablefsd

import (
	"fmt"
	"path/filepath"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/appgroupcontainer"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
)

func prepareRuntimeConfig(cfg *Config) error {
	home, err := accountpath.Home()
	if err != nil {
		return fmt.Errorf("portablefsd: resolve canonical account home: %w", err)
	}
	expectedState := filepath.Join(home, ".local", "state", "portablefs", "portablefsd")
	if filepath.Clean(cfg.StateDir) != expectedState {
		return fmt.Errorf(
			"portablefsd: state directory %q does not match canonical account state %q",
			cfg.StateDir,
			expectedState,
		)
	}
	container, err := appgroupcontainer.Resolve(fskitidentity.AppGroup)
	if err != nil {
		return fmt.Errorf("portablefsd: resolve signed FSKit app-group container: %w", err)
	}
	return applyDarwinSocketRoots(
		cfg,
		filepath.Join(container, "portablefsd"),
		expectedState,
	)
}

func applyDarwinSocketRoots(cfg *Config, frontendRoot, stateRoot string) error {
	wantFrontend := filepath.Join(frontendRoot, "pfs.sock")
	wantControl := filepath.Join(stateRoot, "control.sock")
	if cfg.FrontendSocket == "" {
		cfg.FrontendSocket = wantFrontend
	}
	if cfg.ControlSocket == "" {
		cfg.ControlSocket = wantControl
	}
	if filepath.Clean(cfg.FrontendSocket) != wantFrontend {
		return fmt.Errorf("portablefsd: frontend socket %q is outside the resolved signed app-group identity", cfg.FrontendSocket)
	}
	if filepath.Clean(cfg.ControlSocket) != wantControl {
		return fmt.Errorf("portablefsd: control socket %q is outside canonical account state", cfg.ControlSocket)
	}
	return nil
}
