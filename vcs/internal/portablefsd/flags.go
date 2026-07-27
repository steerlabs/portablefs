package portablefsd

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
)

// AppGroup is the macOS app-group container shared with the FSKit extension
// (PFSAppGroupIdentifier in the extension Info.plist). The sandboxed
// extension may only connect(2) to unix sockets inside app-group container
// paths, so on darwin the daemon's sockets default to that container — a
// daemon serving sockets anywhere else is unreachable from the extension.
const AppGroup = "B47U2LLKHW.pfsoss"

func ParseFlags(version string) (Config, bool) {
	var cfg Config
	cfg.Version = version
	home, _ := os.UserHomeDir()
	defaultState := filepath.Join(home, "Library", "Application Support", "PortableFS", "portablefsd")
	if home == "" {
		defaultState = filepath.Join(os.TempDir(), "portablefsd")
	}
	defaultSocketDir := defaultState
	if runtime.GOOS == "darwin" && home != "" {
		defaultSocketDir = filepath.Join(home, "Library", "Group Containers", AppGroup, "portablefsd")
	}
	flag.StringVar(&cfg.FrontendSocket, "frontend-socket", filepath.Join(defaultSocketDir, "pfs.sock"), "pfslocal frontend Unix socket")
	flag.StringVar(&cfg.ControlSocket, "control-socket", filepath.Join(defaultSocketDir, "control.sock"), "portablefsd control Unix socket")
	flag.StringVar(&cfg.StateDir, "state-dir", defaultState, "portablefsd per-user state directory")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	return cfg, *showVersion
}
