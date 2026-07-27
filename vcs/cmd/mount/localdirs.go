package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
)

// Machine-local dirs (grafts) for the raw mount client, configured through
// env knobs like every other cmd/mount option (new variables, additive per
// COMPATIBILITY.md; unset means no grafts, exactly the previous behavior):
//
//	PORTABLEFS_LOCAL_DIRS        comma-separated workspace-relative dirs to
//	                             serve from machine-local disk (for example
//	                             "node_modules,agent-app/node_modules")
//	PORTABLEFS_LOCAL_DIRS_STATE  state base for the backing store; default
//	                             $XDG_STATE_HOME/portablefs or
//	                             ~/.local/state/portablefs
//
// Backing lives at <state>/local/<storageID(addr,"",mountpoint)>/, the same
// layout convention portablefsd and the portablefs CLI use. The volume's
// .portablefs/local-dirs declaration file is unioned in at mount time.
//
// grafts is nil when no local dirs are configured; every graft check below
// nil-checks first, so the non-graft hot path is unchanged.
var grafts *localdirs.Grafts

// localDirsStateBase resolves the default state base for graft backing.
func localDirsStateBase(getenv func(string) string) string {
	if explicit := getenv("PORTABLEFS_LOCAL_DIRS_STATE"); explicit != "" {
		return explicit
	}
	if base := getenv("XDG_STATE_HOME"); base != "" {
		return filepath.Join(base, "portablefs")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Last resort: keep the backing near the WAL scratch area.
		return filepath.Join(os.TempDir(), "portablefs-state")
	}
	return filepath.Join(home, ".local", "state", "portablefs")
}

// setupLocalDirs builds the mount's graft set from the environment plus the
// volume's declaration file. Returns nil (no grafts) when nothing is
// configured anywhere.
func setupLocalDirs(vol *clientcore.Volume, addr, mountpoint string, logf func(string, ...any)) (*localdirs.Grafts, error) {
	var envDirs []string
	if v := os.Getenv("PORTABLEFS_LOCAL_DIRS"); v != "" {
		envDirs = strings.Split(v, ",")
	}
	volDirs := localdirs.ReadVolumeConfig(context.Background(), vol, logf)
	dirs, err := localdirs.Normalize(append(append([]string(nil), envDirs...), volDirs...))
	if err != nil {
		return nil, err
	}
	if len(dirs) == 0 {
		return nil, nil
	}
	backing := localdirs.BackingRoot(localDirsStateBase(os.Getenv), addr, "", mountpoint)
	g, err := localdirs.New(backing, dirs, nil)
	if err != nil {
		return nil, err
	}
	logf("machine-local dirs: %s (backing %s)", strings.Join(dirs, ", "), backing)
	return g, nil
}
