package portablefsd

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
)

func ParseFlags(version string) (Config, bool, bool) {
	var cfg Config
	cfg.Version = version
	cfg.ExecutableSHA256, _ = daemonctl.CurrentExecutableSHA256()
	home, _ := accountpath.Home()
	defaultState := filepath.Join(home, ".local", "state", "portablefs", "portablefsd")
	if home == "" {
		defaultState = filepath.Join(os.TempDir(), "portablefsd")
	}
	defaultFrontendSocket := filepath.Join(defaultState, "pfs.sock")
	defaultControlSocket := filepath.Join(defaultState, "control.sock")
	if runtime.GOOS == "darwin" {
		// Main resolves the frontend through Foundation and pins control under
		// canonical account state after handling the side-effect-free -version
		// and -identity-json commands. An empty frontend can never become a
		// synthesized Data Vault path.
		defaultFrontendSocket = ""
		defaultControlSocket = ""
	}
	flag.StringVar(&cfg.FrontendSocket, "frontend-socket", defaultFrontendSocket, "pfslocal frontend Unix socket")
	flag.StringVar(&cfg.ControlSocket, "control-socket", defaultControlSocket, "portablefsd control Unix socket")
	flag.StringVar(&cfg.StateDir, "state-dir", defaultState, "portablefsd per-user state directory")
	flag.StringVar(&cfg.MountLogDir, "mount-log-dir", "", "private per-mount log directory (defaults beside -state-dir)")
	showVersion := flag.Bool("version", false, "print version and exit")
	showIdentity := flag.Bool("identity-json", false, "print the stamped FSKit identity as JSON and exit")
	flag.Parse()
	if cfg.MountLogDir == "" {
		cfg.MountLogDir = defaultMountLogDir(cfg.StateDir)
	}
	return cfg, *showVersion, *showIdentity
}

func defaultMountLogDir(stateDir string) string {
	return filepath.Join(filepath.Dir(stateDir), "mounts")
}
