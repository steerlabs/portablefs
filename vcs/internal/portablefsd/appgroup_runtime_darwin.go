//go:build darwin

package portablefsd

import (
	"fmt"
	"io"
	"log"
	"path/filepath"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/appgroupcontainer"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

// DaemonLogPath is the account-private log the launchd-managed daemon owns. It
// sits beside the daemon's state directory, not inside it, so rotating or
// removing the log can never disturb the sockets and singleton locks the state
// directory holds.
func DaemonLogPath(stateDir string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(stateDir)), "portablefsd.log")
}

// openDaemonLog gives the daemon its own log file.
//
// Under launchd there is nowhere else for a diagnostic to go. When the CLI
// still spawned portablefsd it handed the child an already-open descriptor for
// this exact path, so the daemon inherited a log without ever opening one. The
// move to an SMAppService-managed agent removed that spawner, and its plist
// sets no StandardErrorPath, so every log.Printf — including the terminal cause
// of a failed coherence stream, which is recorded at the one point that always
// holds it — was written to a discarded stderr. A mount could fail with no
// evidence anywhere on the machine.
//
// Failing closed is the right posture: the daemon cannot report a later
// failure if it has no log, and a daemon that cannot be diagnosed is the exact
// condition this restores. The check is also not a new fragility — the same
// directory already has to admit the control socket and the state singleton,
// so a machine that refuses this file could not have served a mount anyway.
func openDaemonLog(cfg *Config) (io.Closer, error) {
	file, err := privatepath.OpenFileAppend(DaemonLogPath(cfg.StateDir))
	if err != nil {
		return nil, fmt.Errorf("portablefsd: open daemon log: %w", err)
	}
	log.SetOutput(file)
	return file, nil
}

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
