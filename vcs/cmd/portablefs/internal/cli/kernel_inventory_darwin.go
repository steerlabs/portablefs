//go:build darwin

package cli

import (
	"fmt"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

func portableFSKernelInventory() ([]string, error) {
	mounts, err := darwinMountTable()
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, mount := range mounts {
		if mount.fsType != "portablefs" {
			continue
		}
		ref, ok := strings.CutPrefix(mount.source, "pfs://")
		if !ok || !mountid.ValidAttachRef(ref) {
			return nil, fmt.Errorf("PortableFS kernel mount at %s has invalid attach source %q", mount.path, mount.source)
		}
		paths = append(paths, mount.path)
	}
	return paths, nil
}
