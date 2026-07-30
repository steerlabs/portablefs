//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
)

func portableFSKernelInventory() ([]string, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("read Linux kernel mount inventory: %w", err)
	}
	defer file.Close()
	var paths []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		path, fsType, source, ok := parseLinuxMountInfoLine(scanner.Text())
		if !ok || fsType != "fuse.portablefs" {
			continue
		}
		if source == "portablefs" {
			return nil, fmt.Errorf("legacy PortableFS mount at %s has no unique mount instance identity", path)
		}
		id, ok := strings.CutPrefix(source, "portablefs:")
		if !ok || !mountid.ValidMountInstance(id) {
			return nil, fmt.Errorf("PortableFS mount at %s has invalid source identity %q", path, source)
		}
		paths = append(paths, path)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan Linux kernel mount inventory: %w", err)
	}
	return paths, nil
}
