//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

// Managed children keep the normal CLI record with their exact incarnation's
// cleanup owner. Discover that same record from the kernel source, without
// another registry or a pathname operation through the mounted filesystem.
func platformManagedMountStates() ([]mountState, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var states []mountState
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		entry, ok := parseLinuxMountInfoEntry(scanner.Text())
		instance := strings.TrimPrefix(entry.source, "portablefs:")
		if !ok || entry.fsType != "fuse.portablefs" || !mountid.ValidMountInstance(instance) || filepath.Dir(entry.mountPoint) != "/workspaces" {
			continue
		}
		st, err := readMountState(filepath.Join("/data/workspace-clients", instance), entry.mountPoint)
		if os.IsNotExist(err) || os.IsPermission(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read managed mount inventory: %w", err)
		}
		if st != nil && st.MountInstanceID == instance {
			states = append(states, *st)
		}
	}
	return states, scanner.Err()
}
