package cli

import (
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// Caller holds product lifecycle exclusion. Absence of this durable name is
// the only cross-release empty-resource witness; its contents are never read.
func requireWorkspaceResourcesAbsent(stateDir string) error {
	path := filepath.Join(stateDir, "workspace")
	directory, err := privatepath.OpenExistingDir(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("workspace resource witness directory: %w", err)
	}
	defer directory.Close()
	var entry unix.Stat_t
	if err = unix.Fstatat(int(directory.Fd()), "resources.present", &entry, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return fmt.Errorf("workspace resources remain or absence is unverified; cleanly stop Linux Workspace before updating: %v", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("persist empty workspace resource witness: %w", err)
	}
	var opened, named unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &opened) != nil || unix.Lstat(path, &named) != nil || opened.Dev != named.Dev || opened.Ino != named.Ino {
		return fmt.Errorf("workspace resource witness directory changed")
	}
	return nil
}
