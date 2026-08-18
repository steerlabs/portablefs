package portablefsd

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
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
	defaultSocketDir := defaultState
	if runtime.GOOS == "darwin" && home != "" {
		defaultSocketDir = filepath.Join(home, "Library", "Group Containers", fskitidentity.AppGroup, "portablefsd")
	}
	flag.StringVar(&cfg.FrontendSocket, "frontend-socket", filepath.Join(defaultSocketDir, "pfs.sock"), "pfslocal frontend Unix socket")
	flag.StringVar(&cfg.ControlSocket, "control-socket", filepath.Join(defaultSocketDir, "control.sock"), "portablefsd control Unix socket")
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
